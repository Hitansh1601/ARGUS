"""ARGUS alerting: batch / live / watch scoring over windowed features.

Fixes the old `from risk_engine import ...` brittleness and the
single-demo-only behavior.

Examples:
    python src/argus_alert.py --top 3
    python src/argus_alert.py --scenario ransomware_like --limit 5 --threshold 0.3
    python src/argus_alert.py --live --threshold 0.5 --limit 20
    python src/argus_alert.py --watch data/processed/argus_features.csv --interval 5
    python src/argus_alert.py --top 3 --json
    python -m src.argus_alert --top 3
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import pandas as pd
from xgboost import XGBClassifier

# --- robust import: works as script, as module, and from repo root ---
try:
    from src.risk_engine import calculate_risk_score
except ImportError:  # pragma: no cover
    try:
        from risk_engine import calculate_risk_score
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from risk_engine import calculate_risk_score

try:
    from src.config import load_config
except ImportError:  # pragma: no cover
    try:
        from config import load_config
    except ImportError:
        load_config = None  # optional; defaults below

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("argus.alert")

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA = BASE_DIR / "data" / "processed" / "argus_features.csv"
DEFAULT_MODEL = BASE_DIR / "models" / "argus_xgboost.json"

METADATA_COLUMNS = ["label", "scenario", "dominant_phase", "run_id", "host_id", "window_id"]


def resolve_paths(args, cfg: dict | None):
    cfg = cfg or {}
    data = Path(args.data) if args.data else Path(cfg.get("data", {}).get("features", str(DEFAULT_DATA)))
    model = Path(args.model) if args.model else Path(cfg.get("data", {}).get("model", str(DEFAULT_MODEL)))
    # allow relative paths in config
    if not data.is_absolute():
        data = BASE_DIR / data
    if not model.is_absolute():
        model = BASE_DIR / model
    threshold = args.threshold if args.threshold is not None else float(cfg.get("alerting", {}).get("threshold", 0.5))
    return data, model, threshold


def load_model(model_path: Path) -> XGBClassifier:
    if not model_path.exists():
        raise FileNotFoundError(f"Trained ARGUS model not found: {model_path} (run src/train_model.py first)")
    model = XGBClassifier()
    model.load_model(model_path)
    return model


def load_features(data_path: Path) -> pd.DataFrame:
    if not data_path.exists():
        raise FileNotFoundError(f"Feature dataset not found: {data_path} (run src/feature_engineering.py first)")
    return pd.read_csv(data_path)


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    X = df.drop(columns=METADATA_COLUMNS, errors="ignore")
    X = X.select_dtypes(include=["number"])
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0).astype(float)
    return X


def score_all(model: XGBClassifier, df: pd.DataFrame) -> pd.DataFrame:
    # Schema gate: fail fast if the CSV predates the model (missing inputs).
    try:
        from src.schema import check_frame, expected_features
    except ImportError:  # script-run fallback
        from schema import check_frame, expected_features
    cols = check_frame(df, expected_features(), source="features CSV")
    X = feature_matrix(df)[cols]
    proba = model.predict_proba(X)[:, 1]
    out = df.copy()
    out["_proba"] = proba
    risks = [calculate_risk_score(row, float(p)) for _, row, p in
             [(i, r, p) for (i, r), p in zip(out.iterrows(), proba)]]
    out["_risk"] = [r[0] for r in risks]
    out["_severity"] = [r[1] for r in risks]
    # keep original index for stable selection
    out["_idx"] = out.index
    return out


def collect_evidence(row):
    """Return evidence strings -- kept in parity with risk_engine WEIGHTS."""
    evidence = []

    if row.get("powershell_count", 0) > 0:
        evidence.append("PowerShell execution")

    if row.get("cmd_count", 0) > 0:
        evidence.append("Command shell execution")

    if row.get("suspicious_parent_child_count", 0) > 0:
        evidence.append("Suspicious process relationship")

    if row.get("file_write_velocity", 0) > 1:
        evidence.append(
            f"High file-write velocity "
            f"({row['file_write_velocity']:.2f}/sec)"
        )

    if row.get("high_entropy_write_count", 0) > 5:
        evidence.append(
            f"High-entropy writes "
            f"({int(row['high_entropy_write_count'])})"
        )

    if row.get("entropy_delta_mean", 0) > 1:
        evidence.append(
            f"Significant entropy increase "
            f"({row['entropy_delta_mean']:.2f})"
        )

    if row.get("persistence_key_count", 0) > 0:
        evidence.append("Registry persistence activity")

    if row.get("network_connection_count", 0) > 5:
        evidence.append("Elevated network activity")

    if row.get("failed_login_count", 0) > 3:
        evidence.append(
            "Multiple failed authentication attempts"
        )

    if not evidence:
        evidence.append(
            "No strong behavioral indicators"
        )
    return evidence


def print_alert(row, probability, risk_score, severity):
    # ASCII borders on purpose: Windows cp1252 consoles crash on box-drawing chars.
    bar = "+" + "-" * 68 + "+"
    print()
    print(bar)
    print("|" + "ARGUS SECURITY ALERT".center(68) + "|")
    print("+" + "-" * 68 + "+")
    print(f"| Host             : {str(row['host_id']):<46}|")
    print(f"| Run              : {str(row['run_id']):<46}|")
    print(f"| Window           : {str(row['window_id']):<46}|")
    print(f"| Scenario         : {str(row['scenario']):<46}|")
    print("|" + " " * 68 + "|")
    print(f"| Threat Probability : {probability * 100:>7.2f}%" + " " * 43 + "|")
    print(f"| Risk Score         : {risk_score:>7.2f}/100" + " " * 45 + "|")
    print(f"| Severity           : {severity:<46}|")
    print("|" + " " * 68 + "|")
    print("| Evidence:".ljust(69) + "|")
    evidence = collect_evidence(row)
    for item in evidence:
        print(f"|  * {item:<64}|")
    print("|" + " " * 68 + "|")
    print(f"| Attack Phase      : {str(row['dominant_phase']):<46}|")
    print(bar)


def emit_json(rows: pd.DataFrame):
    records = []
    for _, r in rows.iterrows():
        records.append({
            "host_id": str(r["host_id"]), "run_id": str(r["run_id"]),
            "window_id": int(r["window_id"]), "scenario": str(r["scenario"]),
            "threat_probability": round(float(r["_proba"]), 4),
            "risk_score": float(r["_risk"]), "severity": str(r["_severity"]),
            "label": int(r["label"]) if "label" in r else None,
        })
    print(json.dumps(records, indent=2))


def dedup_hits(hits: pd.DataFrame) -> pd.DataFrame:
    """Collapse to one row per (run_id, scenario, severity), keeping the
    highest-risk window and counting how many it stands for."""
    if hits.empty:
        return hits
    out = (hits.sort_values(["_risk", "_proba"], ascending=False)
           .groupby(["run_id", "scenario", "_severity"], as_index=False)
           .first())
    counts = hits.groupby(["run_id", "scenario", "_severity"]).size()
    out["_dupes"] = out.set_index(
        ["run_id", "scenario", "_severity"]).index.map(counts).to_numpy()
    return out.sort_values(["_risk", "_proba"], ascending=False).reset_index(drop=True)


def pick_batch(scored: pd.DataFrame, scenario: str | None, limit: int, threshold: float,
               dedup: bool = False) -> pd.DataFrame:
    pool = scored
    if scenario:
        pool = pool[pool["scenario"] == scenario]
        if pool.empty:
            raise RuntimeError(f"No windows with scenario={scenario!r}")
    # above-threshold first, ranked by risk then proba
    above = pool[pool["_proba"] >= threshold].sort_values(["_risk", "_proba"], ascending=False)
    if len(above) >= limit:
        rows = above.head(limit)
        return dedup_hits(rows) if dedup else rows
    # backfill with highest-risk windows so demo never prints nothing
    rest = pool.sort_values(["_risk", "_proba"], ascending=False)
    rows = rest.head(limit)
    return dedup_hits(rows) if dedup else rows


def run_batch(scored: pd.DataFrame, scenario: str | None, top: int, limit: int,
              threshold: float, as_json: bool, dedup: bool = False):
    n = top or limit
    rows = pick_batch(scored, scenario, n, threshold, dedup=dedup)
    if as_json:
        emit_json(rows)
        return len(rows)
    for _, row in rows.iterrows():
        if "_dupes" in rows.columns and int(row["_dupes"]) > 1:
            print(f"(+{int(row['_dupes']) - 1} similar alert(s) collapsed)")
        print_alert(row, float(row["_proba"]), float(row["_risk"]), str(row["_severity"]))
    log.info("Displayed %d alert(s) (threshold=%.2f%s%s)", len(rows), threshold,
             f", scenario={scenario}" if scenario else "",
             ", deduped" if dedup else "")
    return len(rows)


def run_live(scored: pd.DataFrame, threshold: float, limit: int, as_json: bool,
             delay: float = 0.0, dedup: bool = False):
    ordered = scored.sort_values(["run_id", "window_id"]).reset_index(drop=True)
    hits = ordered[ordered["_proba"] >= threshold].head(limit)
    if dedup:
        hits = dedup_hits(hits)
    log.info("Live replay: %d/%d windows above %.2f", len(hits), len(ordered), threshold)
    if as_json:
        emit_json(hits)
        return len(hits)
    for _, row in hits.iterrows():
        print_alert(row, float(row["_proba"]), float(row["_risk"]), str(row["_severity"]))
        if delay > 0:
            time.sleep(delay)
    if len(hits) == 0:
        log.warning("No windows above threshold %.2f -- try --threshold 0.1 or --top N", threshold)
    return len(hits)


def run_watch(data_path: Path, model: XGBClassifier, threshold: float, interval: int):
    log.info("Watching %s every %ds (Ctrl+C to stop)...", data_path, interval)
    seen = set()
    try:
        while True:
            df = load_features(data_path)
            scored = score_all(model, df)
            new_hits = scored[(scored["_proba"] >= threshold) & (~scored["_idx"].isin(seen))]
            for _, row in new_hits.iterrows():
                print_alert(row, float(row["_proba"]), float(row["_risk"]), str(row["_severity"]))
                seen.add(row["_idx"])
            log.info("tick: %d windows, %d new alerts (total seen %d)",
                     len(scored), len(new_hits), len(seen))
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("Watch stopped.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ARGUS alerting: batch / live / watch")
    p.add_argument("--data", default=None, help="features CSV (default data/processed/argus_features.csv)")
    p.add_argument("--model", default=None, help="model JSON (default models/argus_xgboost.json)")
    p.add_argument("--threshold", type=float, default=None, help="alert threshold (default 0.5 or config)")
    p.add_argument("--scenario", default=None, help="filter, e.g. ransomware_like")
    p.add_argument("--top", type=int, default=0, help="show top-N by risk (batch mode)")
    p.add_argument("--limit", type=int, default=3, help="max alerts to display (default 3)")
    p.add_argument("--live", action="store_true", help="replay windows in time order, only above threshold")
    p.add_argument("--watch", default=None, metavar="CSV",
                   help="poll CSV for new rows and alert (uses --interval)")
    p.add_argument("--interval", type=int, default=5, help="watch poll seconds (default 5)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON instead of boxes")
    p.add_argument("--delay", type=float, default=0.0, help="sleep between live alerts (demo pacing)")
    p.add_argument("--dedup", action="store_true",
                   help="collapse repeats to one alert per run/scenario/severity")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    cfg = load_config() if load_config else None
    data_path, model_path, threshold = resolve_paths(args, cfg)
    log.info("Loading model %s + features %s", model_path, data_path)
    model = load_model(model_path)

    if args.watch:
        run_watch(Path(args.watch), model, threshold, args.interval)
        return 0

    df = load_features(data_path)
    scored = score_all(model, df)

    if args.live:
        run_live(scored, threshold, args.limit, args.json, args.delay, args.dedup)
    else:
        # default preserves old demo: top ransomware_like window when no flags
        scenario = args.scenario
        top = args.top or args.limit
        if not args.scenario and args.top == 0 and args.limit == 3:
            # legacy single-alert demo path, but show 1 not 3 to match old script
            scenario = "ransomware_like"
            top = 1
            rows = pick_batch(scored, scenario, top, threshold=0.0)
            # old script picked max file_write_velocity; keep that tiebreak
            rows = rows.sort_values("file_write_velocity", ascending=False).head(1)
            if args.json:
                emit_json(rows)
            else:
                for _, row in rows.iterrows():
                    print_alert(row, float(row["_proba"]), float(row["_risk"]), str(row["_severity"]))
            return 0
        run_batch(scored, scenario, top, args.limit, threshold, args.json, args.dedup)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
