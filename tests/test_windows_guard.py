"""Windows-only guard tests: evasion resistance + dry-run actions."""
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.feature_engineering import build_features


def _row(ts, **kw):
    base = {
        "timestamp": ts.isoformat(),
        "host_id": "WIN-TEST-001",
        "run_id": "R-0001",
        "window_id": 0,
        "event_type": "process_create",
        "process_name": "chrome.exe",
        "parent_process": "explorer.exe",
        "tree_depth": 2,
        "file_path": None,
        "entropy_before": 4.0,
        "entropy_after": 4.05,
        "entropy_delta": 0.05,
        "registry_key": None,
        "registry_action": None,
        "destination_ip": None,
        "destination_port": None,
        "bytes_sent": 0,
        "bytes_received": 0,
        "auth_result": None,
        "label": 0,
        "scenario": "live_host",
        "attack_phase": "BENIGN",
    }
    base.update(kw)
    return base


def test_pwsh_variants_detected():
    ts = datetime(2026, 9, 29, 10, 0, 0)
    for name in ["pwsh.exe", "POWERSHELL_ISE.EXE",
                 r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]:
        df = pd.DataFrame([_row(ts, process_name=name)])
        feats = build_features(df)
        assert feats.iloc[0]["powershell_count"] == 1, name


def test_persistence_case_insensitive_runonce():
    ts = datetime(2026, 9, 29, 10, 0, 0)
    for key in ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "hkcu\\software\\microsoft\\windows\\currentversion\\run"]:
        df = pd.DataFrame([_row(
            ts, event_type="registry_modify", registry_key=key,
            registry_action="MODIFY", label=1,
            scenario="persistence_attack", attack_phase="PERSISTENCE")])
        feats = build_features(df)
        assert feats.iloc[0]["persistence_key_count"] == 1, key


def test_office_lolbin_parent_child():
    ts = datetime(2026, 9, 29, 10, 0, 0)
    df = pd.DataFrame([_row(ts, process_name="mshta.exe",
                             parent_process="WINWORD.EXE")])
    feats = build_features(df)
    assert feats.iloc[0]["suspicious_parent_child_count"] == 1


def test_entropy_file_only():
    # Process-only window must not get file entropy; file window must.
    ts = datetime(2026, 9, 29, 10, 0, 0)
    df = pd.DataFrame([_row(ts)])
    feats = build_features(df)
    assert feats.iloc[0]["entropy_mean"] == 0
    assert feats.iloc[0]["entropy_delta_mean"] == 0
    rows = [_row(ts + timedelta(seconds=i), event_type="file_write",
                 file_path=f"C:\\a\\{i}.txt",
                 entropy_after=6.5, entropy_delta=2.5) for i in range(5)]
    feats2 = build_features(pd.DataFrame(rows))
    assert feats2.iloc[0]["entropy_mean"] > 6.0
    assert feats2.iloc[0]["high_entropy_write_count"] == 5


def test_network_interval_excludes_single():
    ts = datetime(2026, 9, 29, 10, 0, 0)
    df = pd.DataFrame([_row(ts, event_type="network_connection",
                             destination_ip="1.1.1.1",
                             destination_port=443, bytes_sent=100)])
    feats = build_features(df)
    assert feats.iloc[0]["average_network_interval"] == 0


def test_guard_dry_run():
    from src.guard import quarantine_file, kill_suspicious_processes
    # Missing file -> None, no crash
    assert quarantine_file(r"C:\nonexistent_argus_test.txt", dry_run=True) is None
    df = pd.DataFrame([{
        "process_name": "powershell.exe", "parent_process": "winword.exe",
        "process_id": 9999999}])
    out = kill_suspicious_processes(df, dry_run=True)
    assert isinstance(out, list)


def test_collector_snapshot_schema():
    from src.collector_windows import collect_snapshot
    evs = collect_snapshot(host_id="WIN-TEST", run_id="LIVE-TEST", window_id=0)
    # May be empty on CI without psutil, but if present check schema
    for e in evs[:5]:
        for k in ["event_id", "timestamp", "host_id", "run_id",
                  "window_id", "event_type", "label", "scenario"]:
            assert k in e


def test_etw_sources_graceful():
    # No Sysmon/audit on CI or this box -> must return list, never raise
    from src.collector_windows import collect_sysmon_events, collect_4688_events
    assert isinstance(collect_sysmon_events(), list)
    assert isinstance(collect_4688_events(), list)


def test_live_persist_dedups(tmp_path):
    import pandas as pd
    from src.guard import persist_live_windows
    lp = tmp_path / "live.csv"
    df = pd.DataFrame([
        {"run_id": "R1", "window_id": 0, "label": 0, "scenario": "live_host"},
        {"run_id": "R1", "window_id": 1, "label": 0, "scenario": "live_host"},
    ])
    assert persist_live_windows(df, lp) == 2
    assert persist_live_windows(df, lp) == 0  # dup run+window skipped


def test_labeled_live_merge(tmp_path):
    import sqlite3
    import pandas as pd
    from src.retrain import load_labeled_live
    lp = tmp_path / "live.csv"
    db = tmp_path / "fb.db"
    pd.DataFrame([
        {"run_id": "L1", "window_id": 0, "label": 0, "scenario": "live_host"},
        {"run_id": "L2", "window_id": 0, "label": 0, "scenario": "live_host"},
    ]).to_csv(lp, index=False)
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE feedback(run_id TEXT, window_id INTEGER, label INTEGER)")
    con.execute("INSERT INTO feedback VALUES(?, ?, ?)", ("L1", 0, 1))
    con.commit()
    con.close()
    m = load_labeled_live(lp, db)
    assert m is not None and len(m) == 1
    assert int(m.iloc[0]["label"]) == 1
