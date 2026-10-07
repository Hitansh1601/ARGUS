"""ARGUS Windows guard: score live windows -> alert + quarantine.

Windows 10+ only, admin assumed. Default is dry-run (log only);
pass --enforce to actually kill/quarantine/delete persistence.

Actions:
- kill suspicious PIDs (psutil)
- quarantine files: move to quarantine/ + .quarantined marker
- remove persistence Run values (winreg) when persistence_key_count > 0
- append feedback row to feedback.db for nightly retrain
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import socket
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
from xgboost import XGBClassifier

try:
    from src.collector_windows import collect_snapshot
    from src.feature_engineering import build_features
    from src.risk_engine import calculate_risk_score, explain_risk
    from src.argus_alert import print_alert, collect_evidence
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.collector_windows import collect_snapshot
    from src.feature_engineering import build_features
    from src.risk_engine import calculate_risk_score, explain_risk
    from src.argus_alert import print_alert, collect_evidence

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE = BASE_DIR / "models" / "argus_xgboost.json"
QUARANTINE_DIR = BASE_DIR / "quarantine"
FEEDBACK_DB = BASE_DIR / "feedback.db"
LIVE_FEATURES = BASE_DIR / "data" / "live" / "live_features.csv"


def persist_live_windows(feats, live_path=LIVE_FEATURES):
    """Append scored live windows for nightly retrain. Dedups on run_id+window_id."""
    try:
        import pandas as pd
    except ImportError:
        return 0
    cols = [c for c in feats.columns if c != "threat_probability"]
    snap = feats[cols].copy()
    live_path.parent.mkdir(parents=True, exist_ok=True)
    if live_path.exists():
        try:
            prev = pd.read_csv(live_path, usecols=["run_id", "window_id"])
            keys = set(zip(prev["run_id"].astype(str), prev["window_id"].astype(int)))
            snap = snap[~snap.apply(
                lambda r: (str(r["run_id"]), int(r["window_id"])) in keys, axis=1)]
        except Exception:
            pass
    if snap.empty:
        return 0
    header = not live_path.exists()
    snap.to_csv(live_path, mode="a", index=False, header=header)
    return len(snap)


def model_hash():
    h = hashlib.sha256()
    h.update(MODEL_FILE.read_bytes())
    return h.hexdigest()[:16]


def load_model():
    if not MODEL_FILE.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_FILE}. Run tasks.ps1 train first.")
    m = XGBClassifier()
    m.load_model(MODEL_FILE)
    return m


def ensure_feedback_db():
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(FEEDBACK_DB)
    con.execute(
        """CREATE TABLE IF NOT EXISTS feedback(
        ts TEXT, host_id TEXT, run_id TEXT, window_id INTEGER,
        probability REAL, risk REAL, severity TEXT,
        label INTEGER, model_hash TEXT)"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS persistence_backup(
        ts TEXT, hive TEXT, subkey TEXT, name TEXT, value TEXT,
        sha256 TEXT)"""
    )
    con.commit()
    con.close()


def backup_persistence_value(hive: str, sub: str, name: str, value: str):
    ensure_feedback_db()
    h = hashlib.sha256((value or "").encode("utf-8", "ignore")).hexdigest()
    con = sqlite3.connect(FEEDBACK_DB)
    con.execute(
        "INSERT INTO persistence_backup VALUES(?,?,?,?,?,?)",
        (datetime.utcnow().isoformat(), hive, sub, name, value, h),
    )
    con.commit()
    con.close()
    # Also append human-readable .reg restore snippet
    try:
        snippet = (
            f"Windows Registry Editor Version 5.00\n"
            f"[{hive}\\{sub}]\n"
            f"\"{name}\"=\"{value.replace(chr(34), chr(39))}\"\n"
        )
        with open(QUARANTINE_DIR / "persistence_backup.reg", "a",
                  encoding="utf-8") as f:
            f.write(f"; {datetime.utcnow().isoformat()} {hive}\\{sub} : {name}\n")
            f.write(snippet + "\n")
    except Exception:
        pass
    return h


def quarantine_file(path: str, dry_run=True):
    if not path or path == "None":
        return None
    # Strip quotes/args: "C:\a\b.exe" /MINIMIZED -> C:\a\b.exe
    cleaned = path.strip().strip('"').strip("'")
    if cleaned.lower().startswith('"'):
        cleaned = cleaned.strip('"')
    # Take exe/script prefix up to known extension
    import re
    m = re.match(r'(.+?\.(?:exe|vbe|vbs|js|jse|ps1|bat|dll|lnk))\b',
                 cleaned, re.IGNORECASE)
    if m:
        cleaned = m.group(1)
    else:
        cleaned = cleaned.split(" /")[0].split(" --")[0].strip().strip('"')
    src = Path(cleaned)
    if not src.exists() or not src.is_file():
        return None
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        h = hashlib.sha256(src.read_bytes()).hexdigest()[:16]
    except Exception:
        h = "nohash"
    dst = QUARANTINE_DIR / (src.name + f".{h}.quarantined")
    if dry_run:
        return f"WOULD quarantine {src} -> {dst}"
    try:
        shutil.move(str(src), str(dst))
        return f"Quarantined {src} -> {dst}"
    except Exception as e:
        return f"Quarantine failed for {src}: {e}"


def kill_suspicious_processes(df_events, dry_run=True):
    """Kill processes whose basename is in LOLBins and parent is Office."""
    try:
        import psutil
    except ImportError:
        return ["psutil missing, skip kill"]
    suspicious = {"powershell.exe", "pwsh.exe", "powershell_ise.exe",
                  "cmd.exe", "mshta.exe", "rundll32.exe", "wscript.exe",
                  "cscript.exe", "certutil.exe", "bitsadmin.exe"}
    office = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
    actions = []
    for _, r in df_events.iterrows():
        proc = str(r.get("process_name") or "").lower().split("\\")[-1]
        parent = str(r.get("parent_process") or "").lower().split("\\")[-1]
        pid = r.get("process_id")
        if proc in suspicious and parent in office and pid:
            try:
                p = psutil.Process(int(pid))
                if dry_run:
                    actions.append(f"WOULD kill {proc} pid={pid} parent={parent}")
                else:
                    p.terminate()
                    actions.append(f"Killed {proc} pid={pid}")
            except Exception as e:
                actions.append(f"Kill failed pid={pid}: {e}")
    if not actions:
        actions.append("No Office-spawned LOLBins to kill")
    return actions


ALLOWLIST_SUBSTRINGS = (
    "onedrive.exe", "discord", "steam.exe", "overwolf",
    "ea desktop", "opera", "nvidia", "docker desktop",
    "riotclient", "upwork", "adobe", "epicgameslauncher",
    "microsoft\\edge", "msedge.exe", "tomcat",
    "pi network", "honeygain", "grass.exe", "grammarly",
    "bluestacks", "loom.exe", "aro desktop",
)

SUSPICIOUS_PERSISTENCE_HINTS = (
    ".vbe", ".vbs", ".js", ".jse", ".ps1", ".bat",
    "appdata/roaming", "appdata/local/temp", "/temp/", "roaming",
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "rundll32", "certutil", "bitsadmin",
    "windows updates service",
)


def persistence_verdict(value: str) -> str:
    v = (value or "").lower()
    for good in ALLOWLIST_SUBSTRINGS:
        if good in v:
            return "allow"
    for bad in SUSPICIOUS_PERSISTENCE_HINTS:
        if bad in v:
            return "suspicious"
    return "review"


def remove_persistence(dry_run=True, allow_review=False):
    """Remove only SUSPICIOUS Run values. Backs up before delete + quarantines target file."""
    try:
        import winreg
    except ImportError:
        return ["winreg unavailable (not Windows?), skip"]
    actions = []
    hives = [(winreg.HKEY_CURRENT_USER, "HKCU")]
    try:
        hives.append((winreg.HKEY_LOCAL_MACHINE, "HKLM"))
    except Exception:
        pass
    for sub in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"]:
        for root, label in hives:
            try:
                with winreg.OpenKey(root, sub, 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as k:
                    # Snapshot first to avoid index-shift on delete
                    vals = []
                    i = 0
                    while True:
                        try:
                            vals.append(winreg.EnumValue(k, i))
                            i += 1
                        except OSError:
                            break
                    for name, val, _typ in vals:
                        verdict = persistence_verdict(str(val))
                        if verdict == "allow":
                            continue
                        if verdict == "review" and not allow_review:
                            actions.append(f"REVIEW (skip) {label}\\{sub} : {name}={val}")
                            continue
                        if dry_run:
                            actions.append(f"WOULD remove [{verdict}] {label}\\{sub} : {name}={val}")
                            q = quarantine_file(str(val), dry_run=True)
                            if q:
                                actions.append(f"  {q}")
                        else:
                            backup_persistence_value(label, sub, name, str(val))
                            q = quarantine_file(str(val), dry_run=False)
                            if q:
                                actions.append(f"[guard] {q}")
                            try:
                                # Re-open for write (snapshot key is read-consistent)
                                with winreg.OpenKey(root, sub, 0, winreg.KEY_WRITE) as kw:
                                    winreg.DeleteValue(kw, name)
                                actions.append(f"Removed [{verdict}] {label}\\{sub} : {name} (backed up)")
                            except FileNotFoundError:
                                actions.append(f"Already removed {label}\\{sub} : {name}")
            except FileNotFoundError:
                continue
            except PermissionError as e:
                actions.append(f"Need admin for {label}\\{sub}: {e}")
            except Exception as e:
                actions.append(f"Reg error {label}\\{sub}: {e}")
    if not actions:
        actions.append("No persistence values found")
    return actions


def score_events(events):
    df_raw = pd.DataFrame(events)
    if df_raw.empty:
        return None, None, None
    feats = build_features(df_raw)
    model = load_model()
    meta = ["label", "scenario", "dominant_phase", "run_id", "host_id", "window_id"]
    X = feats.drop(columns=meta, errors="ignore").select_dtypes(include=["number"]).fillna(0)
    probs = model.predict_proba(X.astype(float))[:, 1]
    feats["threat_probability"] = probs
    out = []
    for idx, row in feats.iterrows():
        score, sev = calculate_risk_score(row, float(row["threat_probability"]))
        out.append((idx, float(row["threat_probability"]), score, sev))
    out.sort(key=lambda x: x[2], reverse=True)
    return feats, out, df_raw


def guard_once(enforce=False, top_n=3):
    dry_run = not enforce
    host = socket.gethostname().upper()
    run = f"LIVE-{datetime.now():%Y%m%d-%H%M%S}"
    print(f"[ARGUS] Collecting live snapshot on {host} (admin={'yes' if not dry_run else 'dry-run'})...")
    events = collect_snapshot(host_id=host, run_id=run, window_id=0)
    print(f"[ARGUS] {len(events)} events collected")
    if not events:
        print("[ARGUS] No events (psutil/winreg missing?). Nothing to score.")
        return {"events": 0}
    feats, ranked, df_raw = score_events(events)
    if feats is None:
        return {"events": 0}
    ensure_feedback_db()
    try:
        n = persist_live_windows(feats)
        if n:
            print(f"[ARGUS] Persisted {n} live windows -> {LIVE_FEATURES}")
    except Exception as e:
        print(f"[ARGUS] Live persist skipped: {e}")
    mh = model_hash() if MODEL_FILE.exists() else "none"
    con = sqlite3.connect(FEEDBACK_DB)
    shown = 0
    for idx, prob, score, sev in ranked[:top_n]:
        if sev in ("LOW",):
            continue
        row = feats.loc[idx]
        print_alert(row, prob, score, sev, ascii_only=False)
        print(f"[explain] {explain_risk(row)}")
        # Actions on HIGH/CRITICAL
        if sev in ("HIGH", "CRITICAL"):
            for a in kill_suspicious_processes(df_raw, dry_run=dry_run):
                print(f"[guard] {a}")
            # Quarantine top file_path in window
            win_events = df_raw[
                (df_raw["run_id"] == row["run_id"]) &
                (df_raw["window_id"] == row["window_id"])
            ]
            for fp in win_events["file_path"].dropna().unique()[:2]:
                print(f"[guard] {quarantine_file(str(fp), dry_run=dry_run)}")
            if float(row.get("persistence_key_count", 0)) > 0:
                for a in remove_persistence(dry_run=dry_run):
                    print(f"[guard] {a}")
        con.execute(
            "INSERT INTO feedback VALUES(?,?,?,?,?,?,?,?,?)",
            (datetime.utcnow().isoformat(), str(row.get("host_id")),
             str(row.get("run_id")), int(row.get("window_id", 0)),
             prob, score, sev, None, mh),
        )
        shown += 1
    con.commit()
    con.close()
    print(f"[ARGUS] {shown} alerts shown. Feedback saved to {FEEDBACK_DB}")
    return {"events": len(events), "alerts": shown}


def main():
    ap = argparse.ArgumentParser(description="ARGUS Windows guard (Win10+, admin)")
    ap.add_argument("--enforce", action="store_true",
                    help="Actually kill/quarantine/delete (default dry-run)")
    ap.add_argument("--once", action="store_true", help="Single snapshot (default)")
    ap.add_argument("--top-n", type=int, default=3)
    args = ap.parse_args()
    guard_once(enforce=args.enforce, top_n=args.top_n)


if __name__ == "__main__":
    main()
