"""Safe demo: 'malicious-similar' sample WITHOUT any virus/malware.

Builds 3 telemetry windows from real feature distributions already in
data/processed/argus_features.csv and scores them with the trained model:
  w0 demo_benign            -> expect LOW  (~0% threat)
  w1 demo_ransomware_like   -> expect CRITICAL (mass file_rename + entropy jump)
  w2 demo_powershell_attack -> expect CRITICAL (powershell + cmd + suspect parent)

Nothing executes, encrypts, or touches real processes. Pure CSV-level demo
for reviewer presentations.

Usage: python demo/malicious_similar_demo.py [--json]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from argus_alert import load_model, score_all

BASE_MODEL = ROOT / "models" / "argus_xgboost.json"
BASE_FEATS = ROOT / "data" / "processed" / "argus_features.csv"


def build_demo() -> pd.DataFrame:
    df = pd.read_csv(BASE_FEATS)
    b = df[df["scenario"] == "benign_normal"].iloc[0].copy()
    r = df[df["scenario"] == "ransomware_like"].iloc[0].copy()
    p = df[df["scenario"] == "powershell_attack"].iloc[0].copy()
    for row, wid, sc in [(b, 0, "demo_benign"),
                         (r, 1, "demo_ransomware_like"),
                         (p, 2, "demo_powershell_attack")]:
        row["run_id"] = "DEMO-0001"
        row["host_id"] = "DEMO-HOST"
        row["window_id"] = wid
        row["scenario"] = sc
        row["dominant_phase"] = {"demo_benign": "BENIGN",
                                 "demo_ransomware_like": "IMPACT",
                                 "demo_powershell_attack": "EXECUTION"}[sc]
    return pd.DataFrame([b, r, p])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    model = load_model(BASE_MODEL)
    demo = build_demo()
    scored = score_all(model, demo)

    print("SAFE DEMO SAMPLE (no virus, no process touched)")
    print("=" * 70)
    for _, row in scored.iterrows():
        print(f"window {int(row['window_id'])} {row['scenario']:<24}"
              f"threat={float(row['_proba']) * 100:6.2f}%  "
              f"risk={float(row['_risk']):6.2f}  {row['_severity']}"
              f"  [label={int(row['label'])}]")
        if "ransomware" in str(row["scenario"]):
            print(f"   signals: file_write={int(row['file_write_count'])}, "
                  f"rename={int(row['file_rename_count'])}, "
                  f"entropy_delta={float(row['entropy_delta_mean']):.2f}")
        if "powershell" in str(row["scenario"]):
            print(f"   signals: powershell={int(row['powershell_count'])}, "
                  f"cmd={int(row['cmd_count'])}, "
                  f"suspicious_parent_child={int(row['suspicious_parent_child_count'])}")
    print("=" * 70)

    ok = (
        float(scored.iloc[0]["_proba"]) < 0.5
        and float(scored.iloc[1]["_proba"]) >= 0.5
        and float(scored.iloc[2]["_proba"]) >= 0.5
    )
    print("RESULT:", "PASS -- benign LOW, both malicious-pattern windows CRITICAL"
          if ok else "FAIL -- unexpected scores (model/threshold changed?)")

    if args.json:
        import json
        print(json.dumps([
            {"window": int(r["window_id"]), "scenario": str(r["scenario"]),
             "threat": round(float(r["_proba"]), 4),
             "risk": float(r["_risk"]), "severity": str(r["_severity"])}
            for _, r in scored.iterrows()], indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
