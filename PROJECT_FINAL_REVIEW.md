# PROJECT FINAL REVIEW — ARGUS

Behavioral malware detection on synthetic endpoint telemetry:
**simulator → 30 window features → XGBoost → 0–100 risk score → SOC alert**,
plus a real-data baseline (CIC-MalMem-2022) and a unification experiment.
44 files changed vs upstream `origin/main` (+5231 / -1051), 47 tests green.

## 1. How to show it (3 commands)

```powershell
.\tasks.ps1 review
# = fast tests (44 pass) -> safe demo (PASS) -> dashboard rebuild

python demo/malicious_similar_demo.py
# w0 benign 0.08% LOW / w1 ransomware-like 99.74% CRITICAL / w2 powershell 99.82% CRITICAL

start results/dashboard.html
# all metrics, plots, protocol tables, git changelog — offline, one file
```

Full pipeline: `.\tasks.ps1 data features train eval validate dashboard`
Slow/optional: `pytest -m e2e` (full regen + train gate).

## 2. What was built, by batch

**A — Hygiene.** Committed the reviewer runbook (`PRESENTATION.md`) and the
safe demo (`demo/malicious_similar_demo.py` — pure telemetry replay, no virus,
no processes touched). `.gitignore` covers caches, live/self-learn artifacts,
`MalMem2022.csv`. Kept the 52 MB telemetry tracked (already in upstream
history; untracking would force a regen with no benefit).

**B — Merged upstream safe improvements** (from `d721425`, skipping the
Windows-only guard/collector stack): 2 new attack scenarios
(`brute_force_attack`, `c2_heavy_attack` → 8×360 windows, 74,524 events),
multi-stage relabel fix, `CurrentVersion\Run` regex fix (0 → 874 persistence
hits), `train_and_evaluate()` testable core + `metrics.json` CI gate +
golden file, WEIGHTS table + `explain_risk()`, `collect_evidence()` parity in
alerts (incl. the missing high-entropy-writes item), Makefile + `tasks.ps1` +
`pytest.ini` (e2e markers) + Windows CI. Kept our config wiring and the
`hist`/`n_jobs=1` fix (`n_jobs>1` is ~100× slower on this box).

**C — Generalization, with a reversal.** With 6 scenarios LOSO failed at
F1 = 0.0 on every held-out attack (disjoint indicators). After Batch B's
diversity, LOSO passes all 6 folds at the default 0.5 (F1 1.0 on all 6 folds) —
the model moved onto shared features. Protected by a LOSO recall gate test;
verdict text in the report is now data-driven, not hardcoded.

**D — features_v2 unification experiment.** Only 2 primitives are honestly
measurable on both CIC and ARGUS (`process_count`, `hidden_artifact`).
7-protocol result: argus-only AUC 0.82, cross-source AUC **0.50 both ways**
while cross F1 looks high (0.83/0.67) — a base-rate illusion
(all-positive, recall 1.0). Lesson: **report AUC, not F1, for transfer
claims**; post-hoc mapping cannot replace a common sensor.

**Final polish (this pass).** One-command `review` target; ASCII-safe +
explicit-UTF-8 report writes (console showed `?` for em-dashes); deterministic
telemetry regen (seeded event IDs replace `uuid4` - re-running the generator
is byte-identical, e2e leaves a clean tree); dashboard changelog section
(this page lists recent commits); 30 → 16 model-feature prune with gates
re-verified; schema gate + analyst feedback CLI; this file.

## 3. Current numbers

| check | result |
|---|---|
| standard split (720 test) | P 1.0 / R 1.0 / F1 1.0 / AUC 1.0 |
| LOSO worst fold | none -- all 6 folds F1 1.0 |
| benign FPR | 0.0 |
| CIC-MalMem (full 58,596 rows) | P 0.9998 / R 1.0 / F1 0.9999 / AUC 1.0 |
| unified cross-source | AUC 0.50 / 0.50 (chance) |
| tests | 47 passed (44 fast + 3 e2e) |
| demo | PASS (LOW / CRITICAL / CRITICAL) |

## 4. Key files

`simulator/generator.py`, `src/feature_engineering.py` (+`validate_schema`),
`src/train_model.py` (`train_and_evaluate`, `metrics.json`), `src/risk_engine.py`
(WEIGHTS), `src/argus_alert.py` (batch/live/watch/JSON), `src/evaluate_generalization.py`
(6-fold LOSO), `src/validate_real.py`, `src/features_v2.py` + `src/validate_unified.py`,
`src/config.py` + `config.yaml`, `src/dashboard.py`, `demo/malicious_similar_demo.py`,
`results/` (metrics, 3 reports, plots), `tests/` (+`golden/`), `Makefile`, `tasks.ps1`.

## 5. Deferred / future work

- Live-enforcement stack (`src/guard.py`, `src/collector_windows.py`, Sysmon XML,
  nightly retrain) from `origin/argus-improvements`: Windows-only + admin-gated,
  adopt only on a Windows admin box.
- Dead features still at 0.0 importance (`persistence_key_count`,
  `network_connection_count`, `failed_login_count`): prune or reweight simulator.
- Real `features_v2` unification needs a common sensor (EDR on both sides).
- Streaming ingest + alert dedup + analyst feedback loop.

## 6. Verification

- `python -m pytest -q` → 47 passed (13.99s)
- `python demo/malicious_similar_demo.py` → RESULT: PASS
- `python src/dashboard.py` → `results/dashboard.html` (this file's data source)
- Commits on this line: `a7c9686` (Tasks 1–5) → `2df9fc2` (runbook+demo) →
  `841d316` (Batch B) → `b9f44a6` (Batches C+D) → this review pass.
