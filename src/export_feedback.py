"""Export guard feedback for labeling -> results/feedback_review.csv
Run: python src/export_feedback.py
Output columns: host_id,run_id,window_id,probability,risk,severity,label
Fill label 0/1, then pass to retrain via --label-feedback, or UPDATE feedback.db directly.
"""
from __future__ import annotations
from pathlib import Path
import sqlite3
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
FEEDBACK_DB = BASE_DIR / "feedback.db"
RESULTS_DIR = BASE_DIR / "results"

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if not FEEDBACK_DB.exists():
        print(f"No {FEEDBACK_DB}, nothing to export.")
        return 0
    con = sqlite3.connect(FEEDBACK_DB)
    try:
        import pandas as pd
        df = pd.read_sql_query(
            "SELECT host_id,run_id,window_id,probability,risk,severity,label "
            "FROM feedback ORDER BY rowid DESC LIMIT 500", con)
    finally:
        con.close()
    if df.empty:
        print("feedback.db empty.")
        return 0
    out = RESULTS_DIR / "feedback_review.csv"
    # Only export unlabeled for review; keep labeled in db
    todo = df[df["label"].isna()]
    export = todo if not todo.empty else df.head(20)
    export.to_csv(out, index=False)
    print(f"Exported {len(export)} rows -> {out}")
    print("Label them (0 benign / 1 malicious), then either:")
    print(f"  python src/retrain.py --label-feedback {out}")
    print("  or UPDATE feedback.db SET label=.. to auto-pickup nightly.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
