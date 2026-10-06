# ARGUS — Behavioral Malware Detection (synthetic endpoint telemetry)

ARGUS detects malicious endpoint behavior from 30-second telemetry windows.
Pipeline: synthetic telemetry → windowed features → XGBoost → risk score → console alert.

> Status: works perfectly on **seen** scenarios (AUC 1.0), **fails on unseen attack styles**
> (LOSO F1@0.5 = 0.0 for all held-out attacks). See `results/generalization_report.md`.
> `benign_high_entropy` does **not** cause false positives (FPR 0.0). The gap is
> false *negatives* on novel attacks, not FPs.

## Quickstart (Windows / Python 3.13)

```powershell
pip install -r requirements.txt

# 1. Generate synthetic telemetry (6 scenarios x 60 runs x 6 windows)
python simulator/generator.py

# 2. Build windowed features
python src/feature_engineering.py

# 3. Train + evaluate (group-by-run split, no leakage)
python src/train_model.py

# 4. Generalization stress test (Task 1) — standard split, LOSO, threshold sweep, benign FPR
python src/evaluate_generalization.py

# 5. Fire a demo alert
python src/argus_alert.py --top 3

# 6. Live / watch mode (Task 3)
python src/argus_alert.py --live --threshold 0.5 --limit 20
python src/argus_alert.py --watch data/processed/argus_features.csv --interval 5

# 7. Static dashboard (Task 5)
python src/dashboard.py
# open results/dashboard.html

# 8. Tests + lint-ish check
pytest -q
```

## How it works

```
simulator/generator.py
  benign_normal, benign_high_entropy (label 0)
  powershell_attack, persistence_attack, ransomware_like, multi_stage_attack (label 1)
  -> data/raw/synthetic/all_synthetic_telemetry.jsonl (52 MB, ~2.1k windows)

src/feature_engineering.py
  30 numeric window features: process / file+entropy / registry / network / auth / diversity
  -> data/processed/argus_features.csv (2160 rows x 36 cols)

src/train_model.py (XGBoost 250 trees, depth 5, lr 0.05, hist, n_jobs=1)
  GroupShuffleSplit by run_id (25% test) -> results/argus_*.png, models/argus_xgboost.json

src/risk_engine.py: p*60 + behavioral bonuses -> 0-100 + LOW/MEDIUM/HIGH/CRITICAL
src/argus_alert.py: loads model, scores windows, prints alerts (batch/live/watch, JSON optional)
src/evaluate_generalization.py: LOSO + threshold sweep + benign breakdown
```

Why `n_jobs=1, tree_method="hist"`? On this Windows/OpenMP box `n_jobs>1`
is ~100x slower (47 s for 50 trees vs 0.14 s). Pinned in `train_model.py` and eval.

## Results (reproduced 2026-10-06, 2160 windows: 1320 malicious / 840 benign)

### Standard group split (seen scenarios)

| metric | value |
|---|---|
| AUC | 1.0000 |
| Precision / Recall / F1 @0.5 | 1.0 / 1.0 / 1.0 |
| Confusion | TN 232, FP 0, FN 0, TP 308 |
| Threshold sweep | every threshold 0.05–0.95 gives F1 1.0 (too separable) |

Top features (`results/feature_importance.csv`):
`powershell_count 0.36`, `event_count 0.25`, `file_rename_count 0.21`,
`process_tree_depth 0.07`, `file_modify_count 0.06`.
13/30 features have 0.0 importance (`persistence_key_count`,
`network_connection_count`, `failed_login_count`, …) — simulator artifacts.

### Leave-one-attack-out (train without one attack, test on it + 30% benign holdout)

| held-out | AUC | P@0.5 | R@0.5 | F1@0.5 | best F1 (tuned) | best thr |
|---|---|---|---|---|---|---|
| powershell_attack | 0.81 | 0.0 | 0.0 | 0.0 | 0.67 | 0.01 |
| persistence_attack | 1.00 | 0.0 | 0.0 | 0.0 | 1.00 | 0.01 |
| ransomware_like | 0.26 | 0.0 | 0.0 | 0.0 | 0.00 | — |
| multi_stage_attack | 1.00 | 0.0 | 0.0 | 0.0 | 0.00 | — |

Reading: at the default 0.5 threshold the model misses **every** unseen attack.
Lowering the threshold rescues `persistence_attack` (ranking is perfect, just
miscalibrated) and partly `powershell_attack`, but `ransomware_like` ranks
*inverted* (AUC 0.26) — no threshold fixes it. Each attack uses disjoint
indicators, so there is nothing shared to transfer.

### Benign false-positive check

Standard test set: `benign_normal` FPR 0.0 (n=130), `benign_high_entropy`
FPR 0.0 (n=102), at both 0.05 and 0.5. Compression/backup-like high entropy
is **not** the problem.

### Real-data baseline (`argus_baseline.py`, CIC-MalMem-2022)

Root `confusion_matrix.png`: TN 5859, FP 1, FN 0, TP 5860 — same story on real
memory features: near-perfect because the two tasks use **different feature
spaces** (CIC memory counters vs ARGUS 30 window features). There is no direct
transfer without a feature map; see `results/real_validation_report.md`
(Task 4) for the side-by-side and what is needed to unify.

## Project structure

```
argus_baseline.py              CIC-MalMem baseline (real data)
simulator/generator.py         synthetic telemetry generator
src/feature_engineering.py     windowed feature builder
src/train_model.py             XGBoost training + plots
src/risk_engine.py             p -> 0-100 risk + severity
src/argus_alert.py             batch / live / watch alerting (argparse, JSON)
src/evaluate_generalization.py LOSO + threshold + benign FPR
src/validate_real.py           real-data side-by-side (Task 4)
src/config.py + config.yaml    central paths/hyperparams/thresholds
src/dashboard.py               static HTML dashboard generator
dashboard/                     (generated) results/dashboard.html
tests/                         pytest: features, risk, alert-import, generalization contract
data/raw/synthetic/            generator output (gitignored if large)
data/processed/argus_features.csv
models/argus_xgboost.json
results/                       confusion, ROC, importance, threshold_tuning, loso_f1,
                               generalization_report.{json,md}, real_validation_report.md
```

## Configuration

`config.yaml` is the single source for input/output paths, model hyperparams,
and alert thresholds. `src/config.py` loads it with a stdlib fallback if PyYAML
is missing. `train_model.py` / `evaluate_generalization.py` still carry inline
defaults so they run even without the config file.

## Limitations → roadmap

1. **No cross-attack generalization** (proven above). Fix: shared behavioral
   primitives (entropy velocity, rarity, graph features) + anomaly/OOD head +
   leave-one-scenario-out in CI with a minimum-recall gate.
2. **Dead features** (13919 zeros). Prune or make simulator emit overlapping
   signals (e.g. persistence + network in the same run).
3. **Calibration**: default 0.5 is arbitrary; persist a tuned threshold
   (`results/generalization_report.json: best_f1`) into `config.yaml`.
4. **Real telemetry**: unify CIC-MalMem and ARGUS windows behind one
   `features_v2` schema before claiming real-world performance.
5. **Ops**: current dashboard is static HTML; next is streaming ingest
   (watch dir / Kafka) + alert dedup + analyst feedback loop.
