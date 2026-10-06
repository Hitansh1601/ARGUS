"""Task 4: real-data validation — CIC-MalMem-2022 baseline vs synthetic ARGUS model.

Same binary task (Benign=0 / Malicious=1) but DIFFERENT feature spaces,
so this is a side-by-side comparison, not a direct transfer test.
Proves the baseline reproduces on real memory features and documents
exactly what blocks reuse of the synthetic model on real telemetry.

Usage:
    python src/validate_real.py [--sample 20000] [--no-download]
    python src/validate_real.py --sample 0   # full dataset
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (classification_report, confusion_matrix, roc_auc_score,
                             roc_curve, precision_score, recall_score, f1_score)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("argus.real")

BASE_DIR = Path(__file__).resolve().parent.parent
CACHE = BASE_DIR / "data" / "raw" / "MalMem2022.csv"
RESULTS = BASE_DIR / "results"
RESULTS.mkdir(parents=True, exist_ok=True)
DATA_URL = "https://huggingface.co/datasets/bvk/CIC-MalMem-2022/resolve/main/MalMem2022.csv"


def load_cic(sample: int, no_download: bool) -> pd.DataFrame:
    if CACHE.exists():
        log.info("Loading cached %s", CACHE)
        df = pd.read_csv(CACHE)
    elif no_download:
        raise FileNotFoundError(f"No cached {CACHE} and --no-download set.")
    else:
        log.info("Downloading CIC-MalMem-2022 (may take ~1 min)…")
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        df = pd.read_csv(DATA_URL)
        df.to_csv(CACHE, index=False)
        log.info("Cached %d rows to %s", len(df), CACHE)
    log.info("CIC rows=%d cols=%d", len(df), len(df.columns))
    if sample and sample > 0 and len(df) > sample:
        df = df.sample(sample, random_state=42).reset_index(drop=True)
        log.info("Sampled %d rows for speed", len(df))
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0, help="0 = full dataset, else N rows")
    ap.add_argument("--no-download", action="store_true")
    args = ap.parse_args()

    df = load_cic(args.sample, args.no_download)

    # label detect (same rule as argus_baseline.py)
    label_col = next((c for c in df.columns if c.strip().lower() in ("class", "category", "label")), None)
    if label_col is None:
        raise ValueError(f"No label col in {list(df.columns)}")
    log.info("Label col=%r values=%s", label_col, df[label_col].unique()[:8].tolist())
    y = df[label_col].apply(lambda x: 0 if str(x).strip().lower().startswith("benign") else 1)
    log.info("Class balance: %s", y.value_counts().to_dict())

    drop = [label_col, "binary_label", "Category", "Class", "Filename"]
    X = df.drop(columns=[c for c in drop if c in df.columns], errors="ignore")
    X = X.select_dtypes(include=[np.number])
    log.info("Real feature matrix: %d x %d (e.g. %s…)", *X.shape, list(X.columns[:5]))

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                          eval_metric="logloss", random_state=42, n_jobs=1, tree_method="hist")
    log.info("Training real-data XGBoost…")
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    proba = model.predict_proba(Xte)[:, 1]
    metrics = {
        "n_rows": int(len(df)), "n_features": int(X.shape[1]),
        "label_col": label_col,
        "precision": float(precision_score(yte, pred)),
        "recall": float(recall_score(yte, pred)),
        "f1": float(f1_score(yte, pred)),
        "roc_auc": float(roc_auc_score(yte, proba)),
        "tn": int(confusion_matrix(yte, pred)[0, 0]), "fp": int(confusion_matrix(yte, pred)[0, 1]),
        "fn": int(confusion_matrix(yte, pred)[1, 0]), "tp": int(confusion_matrix(yte, pred)[1, 1]),
        "classification_report": classification_report(yte, pred),
        "real_features": list(X.columns),
    }
    log.info("REAL: P=%.4f R=%.4f F1=%.4f AUC=%.4f", metrics["precision"], metrics["recall"],
             metrics["f1"], metrics["roc_auc"])

    # plots
    cm = confusion_matrix(yte, pred)
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Benign", "Malicious"], yticklabels=["Benign", "Malicious"])
    plt.xlabel("Predicted"); plt.ylabel("Actual"); plt.title("CIC-MalMem-2022 — Confusion Matrix")
    plt.tight_layout(); plt.savefig(RESULTS / "real_confusion_matrix.png", dpi=150); plt.close()
    fpr, tpr, _ = roc_curve(yte, proba)
    plt.figure(figsize=(5, 4))
    plt.plot(fpr, tpr, label=f"AUC={metrics['roc_auc']:.3f}")
    plt.plot([0, 1], [0, 1], "--", color="gray")
    plt.xlabel("FPR"); plt.ylabel("TPR"); plt.title("CIC-MalMem-2022 — ROC")
    plt.legend(); plt.tight_layout(); plt.savefig(RESULTS / "real_roc_curve.png", dpi=150); plt.close()

    # synthetic side
    synth, synth_features = {}, []
    gj = RESULTS / "generalization_report.json"
    if gj.exists():
        synth = json.loads(gj.read_text())["standard_group_split"]
    fi = RESULTS / "feature_importance.csv"
    if fi.exists():
        synth_features = pd.read_csv(fi)["feature"].tolist()
    else:
        ap2 = BASE_DIR / "data" / "processed" / "argus_features.csv"
        if ap2.exists():
            synth_features = [c for c in pd.read_csv(ap2, nrows=0).columns
                              if c not in ("label", "scenario", "dominant_phase", "run_id", "host_id", "window_id")]

    overlap = sorted(set(metrics["real_features"]) & set(synth_features))
    report = {
        "real_cic_malmem": {k: v for k, v in metrics.items() if k != "real_features"},
        "real_n_features": metrics["n_features"],
        "synthetic_standard": synth.get("at_0.5", synth),
        "synthetic_auc": synth.get("auc"),
        "feature_overlap": overlap,
        "n_overlap": len(overlap),
        "conclusion": (
            "Both models score ~1.0 on their own test sets, but feature spaces are "
            "disjoint (memory-forensics counters vs 30-s endpoint window behaviors; "
            f"overlap={len(overlap)}). No direct transfer is possible without a unified "
            "features_v2 schema mapping both sources to shared primitives "
            "(process rarity, entropy velocity, persistence, C2 cadence)."
        ),
    }
    (RESULTS / "real_validation_report.json").write_text(json.dumps(report, indent=2))

    s = synth.get("at_0.5", {}) if isinstance(synth, dict) else {}
    md = [
        "# Real-data validation (Task 4): CIC-MalMem-2022 vs synthetic ARGUS",
        "",
        f"Real rows={metrics['n_rows']}, features={metrics['n_features']}, label={label_col}.",
        f"Real: P={metrics['precision']:.4f} R={metrics['recall']:.4f} "
        f"F1={metrics['f1']:.4f} AUC={metrics['roc_auc']:.4f} "
        f"(TN={metrics['tn']} FP={metrics['fp']} FN={metrics['fn']} TP={metrics['tp']})",
        "",
        f"Synthetic (standard split): AUC={synth.get('auc', float('nan')):.4f}, "
        f"F1@0.5={(s.get('f1', float('nan')) if isinstance(s, dict) else float('nan')):.4f} "
        f"(see generalization_report.md for LOSO collapse).",
        "",
        "## Why no direct transfer",
        "",
        f"- CIC features ({metrics['n_features']}): memory-forensics counters "
        f"(`pslist.*`, `dlllist.*`, `handles.*`, …).",
        f"- ARGUS features ({len(synth_features)}): windowed behaviors "
        f"(`powershell_count`, `file_write_velocity`, `entropy_delta_mean`, …).",
        f"- Shared column names: {overlap if overlap else 'none'}.",
        "- Same label semantics (Benign vs rest) but different sensors, "
        "different time granularity, different adversaries.",
        "",
        "## What is needed for a unified claim",
        "",
        "1. `features_v2` schema with shared primitives present in both sources.",
        "2. Joint training (or domain adaptation) + LOSO-across-datasets eval.",
        "3. Persist the tuned threshold; 0.5 is uncalibrated across domains.",
        "",
        "Plots: `results/real_confusion_matrix.png`, `results/real_roc_curve.png`.",
        "Numbers: `results/real_validation_report.json`.",
    ]
    (RESULTS / "real_validation_report.md").write_text("\n".join(md) + "\n")
    log.info("Wrote real_validation_report.{json,md}, real_confusion_matrix.png, real_roc_curve.png")


if __name__ == "__main__":
    main()
