# ARGUS — Reviewer Presentation Runbook (~8 min)

All commands run from repo root (`C:\Users\DELL\ARGUS`).
Everything below was verified passing.

## Tabs to keep open

1. `simulator/generator.py:14` — 6 scenarios
2. `src/feature_engineering.py:39` — `build_features()`, 30 window features
3. `src/train_model.py:154` — XGBoost block (`hist`, `n_jobs=1`)
4. `src/risk_engine.py:1` — probability → 0–100 + LOW/MED/HIGH/CRITICAL
5. `src/argus_alert.py:102,158,221` — alert box, `pick_batch`, CLI
6. `demo/malicious_similar_demo.py:1` — safe sample, no virus
7. `results/dashboard.html` (browser)
8. `results/generalization_report.md`, `results/real_validation_report.md`

## 0. Pre-check (30s)

```powershell
python -m pytest -q
```

Expect: `14 passed`.

## 1. Train (60s)

```powershell
python src/train_model.py
```

Expect: `Precision/Recall/F1/AUC 1.0`, 540 test windows.
Show: `results/argus_confusion_matrix.png`, `results/argus_roc_curve.png`,
`results/feature_importance.csv` (powershell 0.36, event_count 0.25, file_rename 0.21).

Say: "Group-by-run split, no leakage."

## 2. Safe malicious-similar demo (30s) — the implementation proof

```powershell
python demo/malicious_similar_demo.py
python demo/malicious_similar_demo.py --json
```

Expect:

- w0 `demo_benign` → ~0.2% / LOW
- w1 `demo_ransomware_like` → ~99.8% / CRITICAL (writes, renames, entropy jump)
- w2 `demo_powershell_attack` → ~99.9% / CRITICAL (powershell + cmd + suspect parent)
- `RESULT: PASS`

Say: "No virus, no real processes touched — pure telemetry patterns.
Detects malicious processes via process-tree signals and ransomware
behavior via rename + entropy."

## 3. SOC view (60s)

```powershell
python src/argus_alert.py --top 2
python src/argus_alert.py --top 1 --json
python src/argus_alert.py --live --limit 2 --threshold 0.5
```

Expect: CRITICAL boxes, same data as JSON, `Live replay: 2/2160 above 0.50`.

## 4. Dashboard (30s)

```powershell
python src/dashboard.py
```

Then open `results/dashboard.html` (offline, embedded plots).

## 5. Honest limits (60s) — show saved reports, do NOT re-run

Do NOT run live (slow):

- `python src/evaluate_generalization.py` — 5 trainings
- `python src/validate_real.py` — 58,596 rows

Instead open:

- `results/generalization_report.md` — standard split 1.0, but LOSO
  F1@0.5 = 0.0 on all held-out attacks; ransomware AUC 0.26 (inverted).
  Benign FPR 0.0 → the gap is false negatives on novel attacks, not FPs.
- `results/real_validation_report.md` — CIC-MalMem P 0.9998 / R 1.0 /
  F1 0.9999, but 0 shared columns with ARGUS features → side-by-side
  only, needs `features_v2`.
- `results/threshold_tuning.png`, `results/loso_f1.png`,
  `results/real_confusion_matrix.png`.

Say: "Perfect on seen patterns, fails on unseen styles — disjoint
indicators. Fix: shared primitives + anomaly head."

## If asked for code paths

`simulator/generator.py:14` → `src/feature_engineering.py:39` →
`src/train_model.py:154` → `src/argus_alert.py:102` + `:158`.
