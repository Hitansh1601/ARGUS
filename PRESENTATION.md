# ARGUS — Reviewer Presentation Runbook (~8 min)

All commands run from repo root (`C:\Users\DELL\ARGUS`).
Everything below was verified passing.

## Tabs to keep open

1. `simulator/generator.py:14` — 8 scenarios
2. `src/feature_engineering.py:39` — `build_features()`, 16 model features (14 dead pruned) + `validate_schema()`
3. `src/train_model.py:82` — `train_and_evaluate()` testable core (`hist`, `n_jobs=1`) + `metrics.json`
4. `src/risk_engine.py:1` — WEIGHTS table + `explain_risk()` → 0–100 + LOW/MED/HIGH/CRITICAL
5. `src/argus_alert.py` — `collect_evidence()`, alert box, `pick_batch`, batch/live/watch/JSON CLI
6. `demo/malicious_similar_demo.py:1` — safe sample, no virus
7. `results/dashboard.html` (browser)
8. `results/generalization_report.md`, `results/real_validation_report.md`

## 0. Pre-check (30s)

```powershell
python -m pytest -q
```

Expect: `38+ passed` fast (`pytest -m "not e2e"`), e2e on demand (`pytest -m e2e`).

## 1. Train (60s)

```powershell
python src/train_model.py
```

Expect: `Precision 1.0 / Recall 1.0 / F1 1.0 / AUC 1.0`, 720 test windows.
Show: `results/argus_confusion_matrix.png`, `results/metrics.json` (CI gate),
`results/feature_importance.csv` (event_count 0.27, file_modify 0.25, file_rename 0.14).

Say: "Group-by-run split, no leakage. `train_and_evaluate()` is unit-testable."

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

Expect: CRITICAL boxes, same data as JSON, `Live replay` over 2880 windows.

## 4. Dashboard (30s)

```powershell
python src/dashboard.py
```

Then open `results/dashboard.html` (offline, embedded plots).

## 5. Generalization — the headline result (60s)

Open `results/generalization_report.md`:

- Standard split: AUC 1.0, F1 1.0.
- LOSO: **all 6 held-out attacks detected at 0.5** (F1 1.0 on all 6 folds).
  With the old 6-scenario simulator this was F1 = 0.0 everywhere — adding
  auth-heavy and C2-heavy scenarios forced shared-feature learning.
  Protected by the LOSO gate test (`test_generalization_contract.py`).
- Benign FPR 0.0.

Open `results/real_validation_report.md`: CIC-MalMem F1 0.9999, but 0 shared
columns with ARGUS features. Open `results/unified_report.md` (Batch D):
only 2 primitives shared; cross-source AUC 0.50 both ways while cross F1
looks high (0.83/0.67) — base-rate illusion (all-positive, recall 1.0).
Takeaway line: "Report AUC, not F1, for transfer claims."

Do NOT re-run live on stage: `evaluate_generalization.py` (7 trainings),
`validate_real.py` full (58,596 rows) — show the saved reports.

Say: "Diversity fixed transfer. Dead weight pruned since: 30 → 16 model
features (gain-0.0 out), rules untouched, all gates still green."

## If asked for code paths

`simulator/generator.py:14` → `src/feature_engineering.py:39` →
`src/train_model.py:154` → `src/argus_alert.py:102` + `:158`.
