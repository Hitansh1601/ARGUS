"""ARGUS generalization evaluation (Task 1).

Answers: does the model generalize to unseen attack styles,
what threshold is best, and does benign_high_entropy cause FPs?

Protocols:
  A) Standard group-aware split (reference, same as train_model.py)
  B) Leave-one-attack-scenario-out (LOSO): train on all other scenarios,
     test on held-out attack + held-out benign windows.
  C) Threshold sweep on protocol A test set.
  D) benign_high_entropy vs benign_normal FPR breakdown.

Usage:
    python src/evaluate_generalization.py
    python src/evaluate_generalization.py --thresholds 0.05 0.95 0.05
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
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("argus.eval")

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "data" / "processed" / "argus_features.csv"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

METADATA_COLS = ["label", "scenario", "dominant_phase", "run_id", "host_id", "window_id"]
ATTACK_SCENARIOS = ["powershell_attack", "persistence_attack", "ransomware_like",
                    "multi_stage_attack", "brute_force_attack", "c2_heavy_attack"]
BENIGN_SCENARIOS = ["benign_normal", "benign_high_entropy"]

MODEL_KWARGS = dict(
    n_estimators=250,
    max_depth=5,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.9,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=1,  # NOTE: n_jobs>1 is ~100x slower on Windows/OpenMP here
    tree_method="hist",
)


def features_labels(df: pd.DataFrame):
    try:
        from src.schema import check_frame, expected_features
    except ImportError:  # script-run fallback
        from schema import check_frame, expected_features
    cols = check_frame(df, expected_features(), source="features CSV")
    X = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    y = df["label"].astype(int)
    return X, y


def make_model():
    return XGBClassifier(**MODEL_KWARGS)


def metrics_at_threshold(y_true, proba, thr: float) -> dict:
    pred = (proba >= thr).astype(int)
    return {
        "threshold": round(float(thr), 4),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "tn": int(confusion_matrix(y_true, pred, labels=[0, 1])[0, 0]),
        "fp": int(confusion_matrix(y_true, pred, labels=[0, 1])[0, 1]),
        "fn": int(confusion_matrix(y_true, pred, labels=[0, 1])[1, 0]),
        "tp": int(confusion_matrix(y_true, pred, labels=[0, 1])[1, 1]),
        "fpr": float(np.mean(pred[y_true == 0] == 1)) if int((y_true == 0).sum()) else 0.0,
    }


def protocol_standard(df: pd.DataFrame):
    """Group-by-run split, same as train_model.py."""
    X, y = features_labels(df)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    tr, te = next(gss.split(X, y, groups=df["run_id"]))
    model = make_model()
    model.fit(X.iloc[tr], y.iloc[tr])
    proba = model.predict_proba(X.iloc[te])[:, 1]
    y_te = y.iloc[te].to_numpy()
    auc = float(roc_auc_score(y_te, proba))
    m50 = metrics_at_threshold(y_te, proba, 0.5)
    return model, {"auc": auc, "at_0.5": m50, "n_train": int(len(tr)), "n_test": int(len(te))}, (y_te, proba)


def protocol_loso(df: pd.DataFrame, held_out: str):
    """Train on everything except `held_out` attack; test on held_out + benign holdout.

    Benign holdout: 30% of benign run_ids (group-aware) so FPR is measurable
    and no run leaks between train and test.
    """
    benign = df[df["scenario"].isin(BENIGN_SCENARIOS)]
    attack_held = df[df["scenario"] == held_out]
    attack_rest = df[df["scenario"].isin([s for s in ATTACK_SCENARIOS if s != held_out])]

    # benign group split: 70% train, 30% test
    Xb = benign.drop(columns=METADATA_COLS, errors="ignore").select_dtypes(include=["number"])
    gss = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=42)
    b_tr_idx, b_te_idx = next(gss.split(Xb, benign["label"], groups=benign["run_id"]))
    benign_train = benign.iloc[b_tr_idx]
    benign_test = benign.iloc[b_te_idx]

    train_df = pd.concat([attack_rest, benign_train], ignore_index=True)
    test_df = pd.concat([attack_held, benign_test], ignore_index=True)

    X_tr, y_tr = features_labels(train_df)
    X_te, y_te_s = features_labels(test_df)
    y_te = y_te_s.to_numpy()

    model = make_model()
    model.fit(X_tr, y_tr)
    proba = model.predict_proba(X_te)[:, 1]
    m50 = metrics_at_threshold(y_te, proba, 0.5)
    try:
        auc = float(roc_auc_score(y_te, proba))
    except ValueError:
        auc = float("nan")  # single-class test set (shouldn't happen here)
    return {
        "held_out": held_out,
        "n_train": int(len(train_df)),
        "n_test": int(len(test_df)),
        "n_test_attack": int(len(attack_held)),
        "n_test_benign": int(len(benign_test)),
        "auc": auc,
        "at_0.5": m50,
    }, (y_te, proba, test_df)


def threshold_sweep(y_true, proba, lo=0.05, hi=0.95, step=0.05):
    thrs = np.arange(lo, hi + 1e-9, step)
    rows = [metrics_at_threshold(y_true, proba, float(t)) for t in thrs]
    best_f1 = max(rows, key=lambda r: r["f1"])
    # Youden's J = TPR - FPR
    for r in rows:
        tp, fn, fp, tn = r["tp"], r["fn"], r["fp"], r["tn"]
        r["youden_j"] = float((tp / (tp + fn) if (tp + fn) else 0.0) - (fp / (fp + tn) if (fp + tn) else 0.0))
    best_youden = max(rows, key=lambda r: r["youden_j"])
    return rows, best_f1, best_youden


def benign_breakdown(y_te, proba, test_df, thresholds=(0.5,)):
    out = {}
    df = test_df.copy()
    df["_proba"] = proba
    df["_y"] = y_te
    for scen in BENIGN_SCENARIOS + ["benign_all"]:
        sub = df[df["scenario"].isin(BENIGN_SCENARIOS)] if scen == "benign_all" else df[df["scenario"] == scen]
        if len(sub) == 0:
            continue
        entry = {"n": int(len(sub))}
        for thr in thresholds:
            pred = (sub["_proba"].to_numpy() >= thr).astype(int)
            entry[f"fpr@{thr:g}"] = float(pred.mean())  # all are label 0
            entry[f"fp@{thr:g}"] = int(pred.sum())
        out[scen] = entry
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--thresholds", nargs=3, type=float, default=[0.05, 0.95, 0.05],
                    metavar=("LO", "HI", "STEP"))
    args = ap.parse_args()
    lo, hi, step = args.thresholds

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Missing {INPUT_FILE}. Run simulator + feature_engineering first.")
    df = pd.read_csv(INPUT_FILE)
    log.info("Loaded %d windows, scenarios=%s", len(df), df["scenario"].value_counts().to_dict())

    # A) standard
    _, std, (y_std, p_std) = protocol_standard(df)
    log.info("Standard split: AUC=%.4f F1@0.5=%.4f", std["auc"], std["at_0.5"]["f1"])

    # C) threshold sweep on standard test set
    sweep, best_f1, best_youden = threshold_sweep(y_std, p_std, lo, hi, step)
    log.info("Best F1: %.4f @ thr=%.2f | Best Youden: %.4f @ thr=%.2f",
             best_f1["f1"], best_f1["threshold"], best_youden["youden_j"], best_youden["threshold"])

    # B) LOSO for each attack
    loso = []
    fprs_bhe = {}
    loso_sweeps = {}
    for scen in ATTACK_SCENARIOS:
        res, (y_te, p_te, test_df) = protocol_loso(df, scen)
        sweep_loso, best_loso, _ = threshold_sweep(y_te, p_te, 0.01, 0.99, 0.02)
        res["best_thresh_f1"] = best_loso
        loso_sweeps[scen] = sweep_loso
        loso.append(res)
        bd = benign_breakdown(y_te, p_te, test_df, thresholds=(0.5, float(best_f1["threshold"])))
        fprs_bhe[scen] = bd
        log.info("LOSO %-18s AUC=%.4f F1@0.5=%.4f R@0.5=%.4f bestF1=%.4f@%.2f (test n=%d)",
                 scen, res["auc"], res["at_0.5"]["f1"], res["at_0.5"]["recall"],
                 best_loso["f1"], best_loso["threshold"], res["n_test"])

    # D) benign breakdown on standard test set too
    # reconstruct standard test frame for breakdown
    X_all, y_all = features_labels(df)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    _, te_idx = next(gss.split(X_all, y_all, groups=df["run_id"]))
    std_test_df = df.iloc[te_idx]
    benign_std = benign_breakdown(y_std, p_std, std_test_df, thresholds=(0.5, float(best_f1["threshold"])))

    # Data-driven conclusion (no hardcoded story: with 6 scenarios the
    # model had zero transfer; with 8 it generalizes -- report what ran).
    min_f1 = min(r["at_0.5"]["f1"] for r in loso) if loso else 0.0
    if min_f1 >= 0.90:
        verdict = (
            f"LOSO passes: every held-out attack is detected at the default "
            f"0.5 threshold (worst F1@0.5={min_f1:.4f}). Scenario diversity "
            f"(8 scenarios incl. brute-force auth and C2 beacons) forced the "
            f"model onto shared behavioral features instead of disjoint "
            f"indicators. Keep the LOSO gate in CI to catch regressions."
        )
    else:
        weak = [r["held_out"] for r in loso if r["at_0.5"]["f1"] < 0.90]
        verdict = (
            "Standard split is strong but LOSO fails for: "
            + ", ".join(weak) + ". The model memorizes scenario-specific "
            "indicators and does not transfer. Next fix: shared behavioral "
            "features + anomaly head."
        )
    report = {
        "standard_group_split": std,
        "threshold_sweep": sweep,
        "best_f1": best_f1,
        "best_youden": best_youden,
        "loso": loso,
        "benign_fpr_standard_test": benign_std,
        "benign_fpr_loso": fprs_bhe,
        "conclusion": verdict,
    }
    with open(RESULTS_DIR / "generalization_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # --- plots ---
    # 1) threshold curve
    thrs = [r["threshold"] for r in sweep]
    plt.figure(figsize=(8, 5))
    plt.plot(thrs, [r["precision"] for r in sweep], marker="o", label="Precision")
    plt.plot(thrs, [r["recall"] for r in sweep], marker="o", label="Recall")
    plt.plot(thrs, [r["f1"] for r in sweep], marker="o", label="F1")
    plt.axvline(best_f1["threshold"], linestyle="--", color="gray",
                label=f'best F1 @{best_f1["threshold"]:.2f}')
    plt.xlabel("Threshold"); plt.ylabel("Score"); plt.title("ARGUS threshold tuning (standard split)")
    plt.legend(); plt.tight_layout()
    plt.savefig(RESULTS_DIR / "threshold_tuning.png", dpi=180)
    plt.close()

    # 2) LOSO F1 bar
    plt.figure(figsize=(8, 5))
    names = [r["held_out"] for r in loso]
    f1s = [r["at_0.5"]["f1"] for r in loso]
    recs = [r["at_0.5"]["recall"] for r in loso]
    x = np.arange(len(names))
    plt.bar(x - 0.2, f1s, 0.4, label="F1@0.5")
    plt.bar(x + 0.2, recs, 0.4, label="Recall@0.5")
    plt.xticks(x, [n.replace("_", "\n") for n in names], fontsize=8)
    plt.ylim(0, 1.05); plt.ylabel("Score"); plt.title("Leave-one-attack-out generalization")
    plt.legend(); plt.tight_layout()
    plt.savefig(RESULTS_DIR / "loso_f1.png", dpi=180)
    plt.close()

    # --- markdown summary ---
    lines = ["# ARGUS generalization report", ""]
    lines.append(f"Standard group split: AUC={std['auc']:.4f}, "
                 f"P={std['at_0.5']['precision']:.4f} R={std['at_0.5']['recall']:.4f} "
                 f"F1={std['at_0.5']['f1']:.4f} @0.5 (train={std['n_train']}, test={std['n_test']})")
    lines.append(f"Best threshold by F1: {best_f1['threshold']:.2f} "
                 f"(P={best_f1['precision']:.4f} R={best_f1['recall']:.4f} F1={best_f1['f1']:.4f})")
    lines.append(f"Best threshold by Youden J: {best_youden['threshold']:.2f} (J={best_youden['youden_j']:.4f})")
    lines.append("")
    lines.append("## Leave-one-attack-out (test = held-out attack + 30% benign holdout)")
    lines.append("")
    lines.append("| held-out | AUC | P@0.5 | R@0.5 | F1@0.5 | bestF1 | bestThr | n_test |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in loso:
        m = r["at_0.5"]
        b = r.get("best_thresh_f1", {})
        lines.append(f"| {r['held_out']} | {r['auc']:.4f} | {m['precision']:.4f} | "
                     f"{m['recall']:.4f} | {m['f1']:.4f} | {b.get('f1', 0):.4f} | "
                     f"{b.get('threshold', 0):.2f} | {r['n_test']} |")
    lines.append("")
    lines.append(f"> {verdict}")
    lines.append("")
    lines.append("")
    lines.append("## Benign FPR (standard test set)")
    lines.append("")
    for k, v in benign_std.items():
        keys = sorted([kk for kk in v if kk.startswith("fpr")])
        lines.append(f"- {k} (n={v['n']}): " + ", ".join(f"{kk}={v[kk]:.4f}" for kk in keys))
    lines.append("")
    lines.append("## Benign FPR inside each LOSO test set")
    lines.append("")
    for scen, bd in fprs_bhe.items():
        lines.append(f"### held-out={scen}")
        for k, v in bd.items():
            keys = sorted([kk for kk in v if kk.startswith("fpr")])
            lines.append(f"- {k} (n={v['n']}): " + ", ".join(f"{kk}={v[kk]:.4f}" for kk in keys))
    (RESULTS_DIR / "generalization_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    log.info("Wrote generalization_report.json/.md, threshold_tuning.png, loso_f1.png")


if __name__ == "__main__":
    main()
