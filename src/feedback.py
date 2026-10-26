"""Analyst feedback loop (light): label scored windows, export for review.

The SOC half of the product: an analyst confirms or corrects alerts and the
labels accumulate in results/feedback.csv for the next retrain / audit.
Read-only w.r.t. the model — labeling never retrains by itself.

Usage:
    python src/feedback.py label --run DEMO-0001 --window 1 --label 1 --note "ransomware drill"
    python src/feedback.py list
    python src/feedback.py stats
    python src/feedback.py label --run X --window 0 --label 0   # confirm benign
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FEATURES = BASE_DIR / "data" / "processed" / "argus_features.csv"
DEFAULT_FEEDBACK = BASE_DIR / "results" / "feedback.csv"

COLUMNS = ["timestamp", "run_id", "window_id", "host_id", "scenario",
           "threat_probability", "risk_score", "severity",
           "analyst_label", "note"]


def _load_feedback(path: Path) -> pd.DataFrame:
    if path.exists():
        return pd.read_csv(path)
    return pd.DataFrame(columns=COLUMNS)


def label(run_id: str, window_id: int, analyst_label: int,
          note: str = "", features_path: Path = DEFAULT_FEATURES,
          feedback_path: Path = DEFAULT_FEEDBACK) -> dict:
    if analyst_label not in (0, 1):
        raise ValueError("label must be 0 (benign) or 1 (malicious)")
    if not features_path.exists():
        raise FileNotFoundError(f"Missing {features_path}")
    df = pd.read_csv(features_path)
    match = df[(df["run_id"] == run_id) & (df["window_id"] == int(window_id))]
    if match.empty:
        raise ValueError(f"No window run_id={run_id} window_id={window_id} in {features_path}")
    row = match.iloc[0]
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_id": run_id, "window_id": int(window_id),
        "host_id": str(row.get("host_id", "")),
        "scenario": str(row.get("scenario", "")),
        "threat_probability": "",
        "risk_score": "",
        "severity": "",
        "analyst_label": int(analyst_label), "note": note,
    }
    fb = _load_feedback(feedback_path)
    fb = pd.concat([fb, pd.DataFrame([entry])], ignore_index=True)
    feedback_path.parent.mkdir(parents=True, exist_ok=True)
    fb.to_csv(feedback_path, index=False)
    return entry


def stats(feedback_path: Path = DEFAULT_FEEDBACK) -> dict:
    fb = _load_feedback(feedback_path)
    if fb.empty:
        return {"n": 0, "malicious": 0, "benign": 0, "scenarios": {}}
    return {"n": int(len(fb)), "malicious": int((fb["analyst_label"] == 1).sum()),
            "benign": int((fb["analyst_label"] == 0).sum()),
            "scenarios": fb["scenario"].value_counts().to_dict()}


def main(argv=None):
    ap = argparse.ArgumentParser(description="ARGUS analyst feedback")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("label", help="record an analyst label for a window")
    p.add_argument("--run", required=True)
    p.add_argument("--window", type=int, required=True)
    p.add_argument("--label", type=int, choices=[0, 1], required=True)
    p.add_argument("--note", default="")
    p.add_argument("--features", default=str(DEFAULT_FEATURES))
    p.add_argument("--file", default=str(DEFAULT_FEEDBACK))
    sub.add_parser("list", help="print labeled rows").add_argument(
        "--file", default=str(DEFAULT_FEEDBACK))
    sub.add_parser("stats", help="label counts").add_argument(
        "--file", default=str(DEFAULT_FEEDBACK))
    args = ap.parse_args(argv)
    if args.cmd == "label":
        e = label(args.run, args.window, args.label, args.note,
                  Path(args.features), Path(args.file))
        print(f"Labeled {e['run_id']} w{e['window_id']} ({e['scenario']}) = {e['analyst_label']}")
    elif args.cmd == "list":
        fb = _load_feedback(Path(args.file))
        print(fb.to_string(index=False) if not fb.empty else "(no labels yet)")
    elif args.cmd == "stats":
        print(stats(Path(args.file)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
