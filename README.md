# ARGUS — Windows-only self-learning guard

Synthetic + live endpoint-detection: **simulator → features → XGBoost → risk engine → guard (alert + quarantine)**, plus nightly retrain. Windows 10+ only, admin assumed.

## Quickstart (Windows PowerShell, admin)

```powershell
python -m pip install -r requirements.txt
.\tasks.ps1 data; .\tasks.ps1 features; .\tasks.ps1 train; .\tasks.ps1 alert
# fast tests (<30s)
.\tasks.ps1 test-fast
# full regen e2e (74k events, 2880 windows, ~2-5 min)
.\tasks.ps1 test-e2e
# live guard (dry-run lists actions, --enforce to act)
python -m src.guard --once
python -m src.guard --once --enforce
# nightly self-learn
python src/retrain.py
```

Run order:
1. `python simulator/generator.py` — 8 scenarios × 60 runs × 6 windows (30s) → `data/raw/synthetic/*.jsonl` + `all_synthetic_telemetry.jsonl` (74,524 events). Use `.\tasks.ps1 data`.
2. `python src/feature_engineering.py` — windowed 30-feature matrix → `data/processed/argus_features.csv` (2880 rows). Use `.\tasks.ps1 features`.
3. `python src/train_model.py [--no-plots] [--test-size 0.25] [--seed 42]` — GroupShuffleSplit by `run_id`, XGBoost (250, depth 5) → `models/argus_xgboost.json`, `results/metrics.json`, PNGs. Use `.\tasks.ps1 train`.
4. `python -m src.argus_alert [--scenario ransomware_like] [--top-n 1]` — demo SOC alert. Use `.\tasks.ps1 alert`.
5. `python -m src.guard --once [--enforce]` — live ETW/EventLog + psutil snapshot → quarantine + feedback.db. Needs admin.
6. `python src/retrain.py [--label-feedback labels.csv]` — nightly retrain with drift gate.
7. `python argus_baseline.py` — side-branch on real CIC-MalMem-2022 (`MalMem2022.csv` from HuggingFace `bvk/CIC-MalMem-2022` / Kaggle / UNB) → root `confusion_matrix.png`, `roc_curve.png`, `shap_summary.png`.

## Structure

- `simulator/generator.py` — scenarios: `benign_normal`, `benign_high_entropy`, `powershell_attack`, `persistence_attack`, `ransomware_like`, `multi_stage_attack` (kill-chain 0-1 benign, 2 exec, 3 persist, 4 C2, 5 impact), `brute_force_attack` (4-6 FAILURE + SUCCESS), `c2_heavy_attack` (8-12 beacons). Fixed: multi-stage windows now keep `scenario=multi_stage_attack` (was leaking to `ransomware_like`/`benign_*`); persistence regex fixed (`CurrentVersion\Run` single-backslash).
- `src/feature_engineering.py` — 30 features (`WINDOW_SECONDS=30`, `HIGH_ENTROPY_DELTA_THRESHOLD=1.0`, `validate_schema()`). See `src/` for full list.
- `src/train_model.py` — `train_and_evaluate()` testable core, `metrics.json` for CI gates. Current: P 0.998 / R 1.0 / F1 0.999 / AUC 1.0.
- `src/risk_engine.py` — `PROB_WEIGHT=60` + `WEIGHTS` table + `THRESHOLDS` (75/50/25), `explain_risk()`.
- `src/argus_alert.py` — `collect_evidence()` in parity with risk weights (incl. high-entropy writes), `select_suspicious()`, robust imports (`python -m src.argus_alert` from root or `python src/argus_alert.py`).
- `src/collector_windows.py` — live ETW/EventLog + psutil + Run keys → same schema as generator (Win10+, admin).
- `src/guard.py` — score → kill Office-spawned LOLBins, quarantine files, remove SUSPICIOUS Run values only (allowlist + review), log to `feedback.db`.
- `src/retrain.py` — nightly retrain with feedback overrides + drift gate vs golden.
- `data/`, `models/argus_xgboost.json`, `results/` (argus_* PNGs + `feature_importance.csv` + `metrics.json`).

## Tests

- `python -m pytest -m "not e2e"` — 33 unit/integration (schema, velocity, persistence case-insensitive, pwsh variants, entropy file-only, guard dry-run, collector).
- `python -m pytest -m e2e` — full `generator.main()` regen + leakage check + train gate (≥0.90, within 0.05 of `tests/golden/baseline_metrics.json`).
- `python -m pytest` — all 36.

## Known gaps / next

- Model still near-perfect (1.0 AUC); 11 features (network/auth/registry) at 0.0 importance — need harder negatives where those alone distinguish.
- No hyperparameter search; thresholds uncalibrated; `argus_baseline.py` still standalone (no shared utils).
