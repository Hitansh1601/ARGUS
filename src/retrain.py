"""Nightly self-learning retrain (recommended v1).

Flow:
  feedback.db (guard.py) -> labels -> merge with data/processed/argus_features.csv
  -> train_and_evaluate -> drift gate vs tests/golden/baseline_metrics.json
  -> version models/argus_xgboost.<ts>.json + update argus_xgboost.json on pass.

Run: python src/retrain.py [--label-feedback path.csv]
feedback CSV columns: host_id,run_id,window_id,label (0/1)
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

try:
    from src.train_model import train_and_evaluate
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.train_model import train_and_evaluate

BASE_DIR = Path(__file__).resolve().parent.parent
FEATURES_CSV = BASE_DIR / "data" / "processed" / "argus_features.csv"
LIVE_FEATURES = BASE_DIR / "data" / "live" / "live_features.csv"
MODEL_FILE = BASE_DIR / "models" / "argus_xgboost.json"
GOLDEN = BASE_DIR / "tests" / "golden" / "baseline_metrics.json"
FEEDBACK_DB = BASE_DIR / "feedback.db"
RESULTS_DIR = BASE_DIR / "results"


def load_feedback_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    need = {"run_id", "window_id", "label"}
    if not need.issubset(df.columns):
        raise ValueError(f"feedback CSV needs {need}, got {list(df.columns)}")
    return df


def apply_feedback(base: pd.DataFrame, fb: pd.DataFrame) -> pd.DataFrame:
    """Override label where feedback matches run_id+window_id."""
    base = base.copy()
    fb = fb.copy()
    fb["window_id"] = fb["window_id"].astype(int)
    base["window_id"] = base["window_id"].astype(int)
    key = ["run_id", "window_id"]
    base = base.merge(fb[key + ["label"]].rename(columns={"label": "fb_label"}),
                      on=key, how="left")
    mask = base["fb_label"].notna()
    base.loc[mask, "label"] = base.loc[mask, "fb_label"].astype(int)
    base = base.drop(columns=["fb_label"])
    print(f"Applied {int(mask.sum())} feedback labels")
    return base


def load_labeled_live(live_path=LIVE_FEATURES, db=FEEDBACK_DB):
    """Labeled live windows: live_features.csv joined to feedback.db labels."""
    if not live_path.exists() or not db.exists():
        return None
    live = pd.read_csv(live_path)
    if live.empty:
        return None
    con = sqlite3.connect(db)
    try:
        labels = pd.read_sql_query(
            "SELECT run_id, window_id, label FROM feedback WHERE label IS NOT NULL",
            con)
    finally:
        con.close()
    if labels.empty:
        return None
    labels["window_id"] = labels["window_id"].astype(int)
    live["window_id"] = live["window_id"].astype(int)
    m = live.merge(labels, on=["run_id", "window_id"], how="inner",
                   suffixes=("", "_fb"))
    if m.empty:
        return None
    m["label"] = m["label_fb"].astype(int)
    m = m.drop(columns=["label_fb"])
    # Align to base columns, live-only extras dropped
    return m


def load_db_feedback() -> pd.DataFrame | None:
    if not FEEDBACK_DB.exists():
        return None
    con = sqlite3.connect(FEEDBACK_DB)
    try:
        df = pd.read_sql_query(
            "SELECT run_id, window_id, label FROM feedback WHERE label IS NOT NULL",
            con)
    except Exception:
        return None
    finally:
        con.close()
    if df.empty:
        return None
    return df


def main():
    ap = argparse.ArgumentParser(description="ARGUS nightly retrain")
    ap.add_argument("--label-feedback", type=str, default=None,
                    help="CSV with run_id,window_id,label overrides")
    ap.add_argument("--no-plots", action="store_true", default=True)
    args = ap.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "models").mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(FEATURES_CSV)
    print(f"Base windows: {len(df)}")

    if args.label_feedback:
        fb = load_feedback_csv(Path(args.label_feedback))
        df = apply_feedback(df, fb)
    db_fb = load_db_feedback()
    if db_fb is not None:
        df = apply_feedback(df, db_fb)
    live = load_labeled_live()
    if live is not None:
        keep = [c for c in df.columns if c in live.columns]
        live = live[keep]
        df = pd.concat([df, live], ignore_index=True)
        print(f"Merged {len(live)} labeled live windows (total {len(df)})")

    model, metrics, _ = train_and_evaluate(df)
    print(f"P={metrics['precision']:.4f} R={metrics['recall']:.4f} "
          f"F1={metrics['f1']:.4f} AUC={metrics['roc_auc']:.4f}")

    # Drift gate vs golden
    if GOLDEN.exists():
        g = json.loads(GOLDEN.read_text())
        ok = True
        for k in ["precision", "recall", "f1", "roc_auc"]:
            if metrics[k] < 0.90 or metrics[k] < g.get(k, 0.9) - 0.05:
                print(f"GATE FAIL {k}={metrics[k]:.4f} (golden {g.get(k):.4f})")
                ok = False
        if not ok:
            print("Retrain rejected by gate, model NOT updated.")
            return metrics

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    versioned = MODEL_FILE.parent / f"argus_xgboost.{ts}.json"
    model.save_model(versioned)
    shutil.copy(versioned, MODEL_FILE)
    with open(RESULTS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved {MODEL_FILE} (versioned {versioned.name})")
    return metrics


if __name__ == "__main__":
    main()
