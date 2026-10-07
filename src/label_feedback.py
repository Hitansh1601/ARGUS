"""Push labeled feedback CSV into feedback.db (guard -> retrain loop).
Usage:
  python src/label_feedback.py results/feedback_review.csv
  python src/label_feedback.py results/feedback_review.csv --default 0
CSV needs: run_id,window_id,label (label 0/1). Empty labels skipped unless --default given.
Updates feedback.db rows matching run_id+window_id; inserts if missing.
"""
from __future__ import annotations
import argparse
import sqlite3
import sys
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
FEEDBACK_DB = BASE_DIR / "feedback.db"


def main():
    ap = argparse.ArgumentParser(description="Push CSV labels into feedback.db")
    ap.add_argument("csv", type=str, help="Labeled CSV with run_id,window_id,label")
    ap.add_argument("--default", type=int, default=None, choices=[0, 1],
                    help="Fill empty labels with this (e.g. 0 for benign dev box)")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"Not found: {csv_path}")
        return 1
    df = pd.read_csv(csv_path)
    if "label" not in df.columns or "run_id" not in df.columns or "window_id" not in df.columns:
        print(f"CSV needs run_id,window_id,label, got {list(df.columns)}")
        return 1
    if args.default is not None:
        df["label"] = df["label"].fillna(args.default)
    df = df.dropna(subset=["label"])
    if df.empty:
        print("No labeled rows (fill label 0/1 or pass --default 0/1).")
        return 0
    df["label"] = df["label"].astype(int).clip(0, 1)
    df["window_id"] = df["window_id"].astype(int)

    if not FEEDBACK_DB.exists():
        print(f"No {FEEDBACK_DB}, run guard first.")
        return 1
    con = sqlite3.connect(FEEDBACK_DB)
    updated, inserted = 0, 0
    for _, r in df.iterrows():
        cur = con.execute(
            "UPDATE feedback SET label=? WHERE run_id=? AND window_id=?",
            (int(r["label"]), str(r["run_id"]), int(r["window_id"])))
        if cur.rowcount:
            updated += cur.rowcount
        else:
            con.execute(
                "INSERT INTO feedback(ts,host_id,run_id,window_id,probability,risk,severity,label,model_hash)"
                " VALUES(datetime('now'),?,?,?,?,?,?,?,?)",
                (str(r.get("host_id", "")), str(r["run_id"]), int(r["window_id"]),
                 float(r.get("probability", 0) or 0), float(r.get("risk", 0) or 0),
                 str(r.get("severity", "")), int(r["label"]), "manual"))
            inserted += 1
    con.commit()
    con.close()
    print(f"Pushed {len(df)} labels: {updated} updated, {inserted} inserted -> {FEEDBACK_DB}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
