# ARGUS — Behavioral Malware Detection (synthetic endpoint telemetry)

ARGUS detects malicious endpoint behavior from 30-second telemetry windows.
Pipeline: synthetic telemetry → windowed features → XGBoost → risk score → console alert.

> Status: standard split P 0.998 / R 1.0 / F1 0.999 / AUC 1.0, and — after
> adding auth-heavy (`brute_force_attack`) and network-heavy (`c2_heavy_attack`)
> scenarios — **LOSO now passes for all 6 held-out attacks** (worst F1@0.5 =
> 0.9958). Scenario diversity forced the model onto shared behavioral features.
> `benign_high_entropy` FPR is 0.0. See `results/generalization_report.md`.
> Guard/collector live-enforcement stack deliberately **not** merged (Windows-only
> + admin); see Limitations.

## Quickstart (Windows / Python 3.13)

```powershell
pip install -r requirements.txt

# 1. Generate synthetic telemetry (8 scenarios x 60 runs x 6 windows)
python simulator/generator.py

# 2. Build windowed features (validates schema, 30 features)
python src/feature_engineering.py

# 3. Train + evaluate (group-by-run split, no leakage; saves metrics.json)
python src/train_model.py
# fast variant without PNGs (for tests): python src/train_model.py --no-plots

# Windows shortcut for 1–3 + more: .\tasks.ps1 data / features / train
# (Makefile mirrors the same targets for compat)

# 4. Generalization stress test — standard split, LOSO (6 folds), threshold sweep, benign FPR
python src/evaluate_generalization.py

# 5. Fire a demo alert
python src/argus_alert.py --top 3

# 6. Live / watch mode (Task 3)
python src/argus_alert.py --live --threshold 0.5 --limit 20
python src/argus_alert.py --watch data/processed/argus_features.csv --interval 5

# 7. Static dashboard (Task 5)
python src/dashboard.py
# open results/dashboard.html

# 8. Tests (fast unit + slow e2e marked separately)
pytest -q
pytest -m "not e2e" -q   # fast (<30s)
pytest -m e2e -q         # full regen + train gate
```

## How it works

```
simulator/generator.py
  benign_normal, benign_high_entropy (label 0)
  powershell_attack, persistence_attack, ransomware_like, multi_stage_attack (label 1)
  brute_force_attack (4-6 FAILURE + 1 SUCCESS logins), c2_heavy_attack (8-12 beacons)
  -> data/raw/synthetic/all_synthetic_telemetry.jsonl (~74.5k events, 2880 windows)

src/feature_engineering.py
  30 numeric window features: process / file+entropy / registry / network / auth / diversity
  (validates schema; persistence regex fixed: CurrentVersion\Run now fires)
  -> data/processed/argus_features.csv (2880 rows x 36 cols)

src/train_model.py (XGBoost 250 trees, depth 5, lr 0.05, hist, n_jobs=1)
  train_and_evaluate() testable core; GroupShuffleSplit by run_id (25% test)
  -> results/metrics.json (CI gate + golden), results/argus_*.png, models/argus_xgboost.json

src/risk_engine.py: WEIGHTS table + explain_risk() -> 0-100 + LOW/MEDIUM/HIGH/CRITICAL
src/argus_alert.py: collect_evidence() in parity with WEIGHTS; batch/live/watch, JSON optional
src/evaluate_generalization.py: LOSO (6 folds) + threshold sweep + benign breakdown
```

Why `n_jobs=1, tree_method="hist"`? On this Windows/OpenMP box `n_jobs>1`
is ~100x slower (47 s for 50 trees vs 0.14 s). Pinned in `train_model.py` and eval.

## Results (8 scenarios, 2880 windows: 2160 malicious / 720 benign)

### Standard group split (seen scenarios)

| metric | value |
|---|---|
| AUC | 1.0000 |
| Precision / Recall / F1 @0.5 | 0.9980 / 1.0000 / 0.9990 |
| Confusion | TN 221, FP 1, FN 0, TP 498 (test 720) |
| `metrics.json` | machine-readable gate for CI (`tests/golden/baseline_metrics.json`) |

Top features (`results/feature_importance.csv`):
`event_count 0.27`, `file_modify_count 0.25`, `file_rename_count 0.14`,
`file_write_velocity 0.13`, `file_write_count 0.11`.
Still 0.0: `persistence_key_count` (regex fixed, 874 hits in telemetry — the
model just doesn't need it), `network_connection_count`, `failed_login_count`,
… — the model generalizes via shared features (`event_count`,
`signal_diversity`), not the scenario-specific ones.

### Leave-one-attack-out (train without one attack, test on it + benign holdout)

| held-out | AUC | P@0.5 | R@0.5 | F1@0.5 | best F1 (tuned) | best thr |
|---|---|---|---|---|---|---|
| powershell_attack | 1.00 | 1.0 | 1.0 | 1.00 | 1.00 | 0.03 |
| persistence_attack | 1.00 | 1.0 | 1.0 | 1.00 | 1.00 | 0.01 |
| ransomware_like | 1.00 | 1.0 | 0.9917 | 0.9958 | 1.00 | 0.03 |
| multi_stage_attack | 1.00 | 0.9959 | 1.0 | 0.9979 | 0.9979 | 0.05 |
| brute_force_attack | 1.00 | 1.0 | 1.0 | 1.00 | 1.00 | 0.03 |
| c2_heavy_attack | 1.00 | 1.0 | 1.0 | 1.00 | 1.00 | 0.03 |

History worth stating in review: with 6 scenarios this table was 0.0 F1
everywhere (disjoint indicators, nothing shared to transfer). Adding
auth-heavy and C2-heavy scenarios forced shared-feature learning and fixed
it — protected now by the LOSO gate in `tests/test_generalization_contract.py`.

### Benign false-positive check

Standard test set FPR 0.0 for `benign_normal` and `benign_high_entropy`.
Compression/backup-like high entropy is **not** the problem.

### Real-data baseline (`argus_baseline.py`, CIC-MalMem-2022)

Root `confusion_matrix.png`: TN 5859, FP 1, FN 0, TP 5860 — same story on real
memory features: near-perfect because the two tasks use **different feature
spaces** (CIC memory counters vs ARGUS 30 window features). There is no direct
transfer without a feature map; see `results/real_validation_report.md`
for the side-by-side and what is needed to unify.

### Unified v2: can a shared schema transfer? (`src/features_v2.py`, Batch D)

Only 2 primitives are honestly measurable on both sides (`process_count`,
`hidden_artifact`); everything else is a documented one-side-only gap.
Joint/cross-source experiment (`results/unified_report.md`):

| protocol | F1 | AUC |
|---|---|---|
| argus-only | 0.89 | 0.82 |
| cic-only | 0.54 | 0.70 |
| cross cic→argus | 0.83 | **0.50** |
| cross argus→cic | 0.67 | **0.50** |

Cross-source ranking is exactly chance (AUC 0.50 both ways); the high cross
F1 is a base-rate illusion (all-positive predictions, recall 1.0). Lesson
for review: **report AUC, not F1, for transfer claims** — and post-hoc
mapping cannot substitute for a common sensor.

## Project structure

```
argus_baseline.py              CIC-MalMem baseline (real data)
simulator/generator.py         synthetic telemetry generator (8 scenarios)
src/feature_engineering.py     windowed feature builder (+validate_schema)
src/train_model.py             train_and_evaluate() core + CLI + metrics.json
src/risk_engine.py             WEIGHTS table + explain_risk() -> 0-100 score
src/argus_alert.py             batch / live / watch alerting + collect_evidence()
src/evaluate_generalization.py LOSO (6 folds) + threshold + benign FPR
src/validate_real.py           real-data side-by-side
src/config.py + config.yaml    central paths/hyperparams/thresholds
src/dashboard.py               static HTML dashboard generator
src/features_v2.py             shared CIC<->ARGUS schema (2 primitives + gaps)
src/validate_unified.py        joint/cross-source experiment -> unified_report.*
demo/malicious_similar_demo.py safe reviewer demo (no virus)
Makefile + tasks.ps1           Windows-friendly task runners
pytest.ini + tests/golden/     e2e markers + metric gate
tests/                         40+ tests: features, risk, alert, generator, train, LOSO gate
data/raw/synthetic/            generator output (8 jsonl + combined)
data/processed/argus_features.csv  (2880 rows)
models/argus_xgboost.json
results/                       confusion, ROC, importance, threshold_tuning, loso_f1,
                               metrics.json, generalization_report.{json,md},
                               real_validation_report.{json,md}
```

## Configuration

`config.yaml` is the single source for input/output paths, model hyperparams,
and alert thresholds. `src/config.py` loads it with a stdlib fallback if PyYAML
is missing. `train_model.py` / `evaluate_generalization.py` still carry inline
defaults so they run even without the config file.

## Limitations → roadmap

1. **Dead features that stay dead** (`persistence_key_count`,
   `network_connection_count`, `failed_login_count` at 0.0 even though the
   telemetry now contains 874 persistence hits, brute-force logins, C2
   beacons). LOSO passes anyway via shared features, but these signals are
   wasted. Fix: prune them or reweight the simulator so they carry unique
   information (Batch C remainder).
2. **Calibration**: default 0.5 holds (tuned 0.05–0.10 gives the same F1 here);
   threshold stays in `config.yaml: alerting.threshold` and `metrics.json`.
3. **Real telemetry**: unified CIC-MalMem and ARGUS windows behind one
   `features_v2` schema before claiming real-world performance — DONE as a
   quantified negative (`src/features_v2.py`, `results/unified_report.md`):
   cross-source AUC 0.50 both ways. Next step needs a common sensor, not
   more mapping.
4. **Live enforcement deliberately deferred**: the `argus-improvements`
   guard/collector/nightly-retrain stack (`src/guard.py`,
   `src/collector_windows.py`, Sysmon XML) is Windows-only + admin-gated.
   Adopt only on a Windows admin review box.
5. **Ops**: dashboard is static HTML; next is streaming ingest
   (watch dir) + alert dedup + analyst feedback loop.
