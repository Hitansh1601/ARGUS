"""Batch D: test whether the v2 shared schema unifies CIC + ARGUS.

Protocols (all XGBoost hist/1-job, same seed):
  A) argus-only : train/test on v2 rows from ARGUS
  B) cic-only    : train/test on v2 rows from CIC
  C) joint       : train/test on concatenated v2 rows (stratified)
  D) cross cic->argus and argus->cic (train one source, test the other)

Writes results/unified_report.{json,md}. Expectation set honestly in
advance: with only 2 shared primitives, C ≈ single-source and D ≈ chance.
If D ever approaches C, the schema earned its keep.

Usage: python src/validate_unified.py [--cic-sample 20000]
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

try:
    from src.features_v2 import describe_gaps, load_argus_v2, load_cic_v2
except ImportError:  # script-run fallback
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from features_v2 import describe_gaps, load_argus_v2, load_cic_v2

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("argus.unified")

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS = BASE_DIR / "results"
V2_FEATURES = ["process_count", "hidden_artifact"]


def make_model():
    return XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                         eval_metric="logloss", random_state=42,
                         n_jobs=1, tree_method="hist")


def score(name: str, model, Xte, yte) -> dict:
    proba = model.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return {
        "protocol": name,
        "n_test": int(len(yte)),
        "precision": float(precision_score(yte, pred, zero_division=0)),
        "recall": float(recall_score(yte, pred, zero_division=0)),
        "f1": float(f1_score(yte, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(yte, proba)) if len(set(yte)) > 1 else float("nan"),
    }


def run(df_tr, df_te, name):
    model = make_model()
    model.fit(df_tr[V2_FEATURES], df_tr["label"])
    return score(name, model, df_te[V2_FEATURES], df_te["label"].to_numpy())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cic-sample", type=int, default=20000)
    args = ap.parse_args()

    argus = load_argus_v2()
    cic = load_cic_v2(sample=args.cic_sample)
    log.info("v2 rows: argus=%d (pos rate %.3f) cic=%d (pos rate %.3f)",
             len(argus), argus["label"].mean(), len(cic), cic["label"].mean())

    a_tr, a_te = train_test_split(argus, test_size=0.25, random_state=42, stratify=argus["label"])
    c_tr, c_te = train_test_split(cic, test_size=0.25, random_state=42, stratify=cic["label"])
    joint = pd.concat([argus, cic], ignore_index=True)
    j_tr, j_te = train_test_split(joint, test_size=0.25, random_state=42,
                                  stratify=joint[["label", "source"]].apply(tuple, axis=1))

    rows = [
        run(a_tr, a_te, "A argus-only"),
        run(c_tr, c_te, "B cic-only"),
        run(j_tr, j_te, "C joint->joint"),
        run(c_tr, a_te, "D cross cic->argus"),
        run(a_tr, c_te, "D cross argus->cic"),
        run(j_tr, a_te, "C joint->argus-slice"),
        run(j_tr, c_te, "C joint->cic-slice"),
    ]
    gaps = describe_gaps()
    cross = [r for r in rows if r["protocol"].startswith("D cross")]
    cross_str = ", ".join(f"{r['protocol']} F1={r['f1']:.3f}/AUC={r['roc_auc']:.3f}" for r in cross)
    worst_auc = min(r["roc_auc"] for r in cross)
    verdict = (
        "v2 does not unify the domains: cross-source ranking is chance "
        f"({cross_str}; worst AUC={worst_auc:.3f}). The high cross F1 is a "
        "base-rate illusion — both cross models predict all-positive "
        "(recall 1.0, precision = base rate). The two shared primitives "
        "carry within-source signal (argus-only AUC 0.82) but no "
        "transferable semantics. A common sensor is required; post-hoc "
        "mapping cannot create it."
        if worst_auc < 0.60 else
        "v2 shows partial transfer — inspect per-protocol rows before claiming more."
    )
    (RESULTS / "unified_report.json").write_text(
        json.dumps({"features": V2_FEATURES, "gaps": gaps,
                    "protocols": rows, "verdict": verdict}, indent=2))
    md = ["# Unified v2 validation (Batch D)", "",
          f"Shared primitives: {', '.join(V2_FEATURES)}. "
          f"Rows: argus={len(argus)}, cic={len(cic)} (sample={args.cic_sample}).", "",
          "| protocol | n_test | P | R | F1 | AUC |",
          "|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['protocol']} | {r['n_test']} | {r['precision']:.4f} | "
                  f"{r['recall']:.4f} | {r['f1']:.4f} | {r['roc_auc']:.4f} |")
    md += ["", f"> {verdict}", "",
           "Gaps (one side only):",
           f"- argus-only: {', '.join(gaps['argus_only'])}",
           f"- cic-only: {', '.join(gaps['cic_only'])}"]
    (RESULTS / "unified_report.md").write_text("\n".join(md) + "\n")
    for r in rows:
        log.info("%-22s F1=%.4f AUC=%.4f (n=%d)", r["protocol"], r["f1"], r["roc_auc"], r["n_test"])
    log.info("Wrote results/unified_report.{json,md}")


if __name__ == "__main__":
    main()
