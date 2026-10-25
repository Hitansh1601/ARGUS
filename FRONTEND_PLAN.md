# FRONTEND PLAN — ARGUS review UI

Status: designed + implemented locally in `frontend/` (**not pushed** —
held back for review; see "Push policy" below). This file describes what
the frontend looks like, the build plan, and how it is built.

## 1. What it should look like

One Streamlit app, wide layout, sidebar + 8 tabs. Read-only: it loads the
trained model and saved results, never retrains, never touches processes.

- **Sidebar (always visible):** alert-threshold slider (0.05–0.95),
  top-N slider, scenario multi-select, data/model path caption.
- **Overview:** P/R/F1/AUC metric cards from `results/metrics.json`,
  confusion-matrix + ROC plots side by side, top-15 feature bar chart
  from `results/feature_importance.csv`.
- **Alerts:** filtered alert table (host/run/window/scenario/probability/
  risk/severity), CSV + JSON download buttons, per-alert drill-down with
  metric cards and the evidence list (`collect_evidence()`).
- **Kill chain:** run selector → window-by-window threat-probability bars
  plus phase table (benign → execution → persistence → C2 → impact).
  Best demo run: any `MULTI_STAGE_ATTACK` run.
- **Playground:** preset selector (Benign / Ransomware / PowerShell /
  Brute-force / C2) + 10 sliders over key telemetry signals → instant
  threat probability, risk score, severity, and triggered evidence.
  Pure numeric simulation; best "the model works" moment.
- **Safe demo:** button runs `demo/malicious_similar_demo.py` in-app
  (LOW / CRITICAL / CRITICAL + PASS banner).
- **Generalization:** standard-split numbers, 6-fold LOSO table, verdict,
  LOSO-F1 + threshold-sweep plots.
- **Real data:** CIC-MalMem-2022 metrics + plots, disjoint-space disclaimer.
- **Unified v2:** 7-protocol cross-source table + the AUC verdict
  (cross-source AUC 0.50 both ways; report AUC, not F1, for transfer).

## 2. Plan (phases)

- [x] Phase 1 (built, local): 6 tabs — Overview, Alerts, Safe demo,
      Generalization, Real data, Unified v2. Verified headless, zero
      exceptions, live metrics match the trained model.
- [x] Phase 2 (built, local): Kill-chain timeline, what-if Playground,
      CSV/JSON export. Interactions verified headless (run switch,
      ransomware preset → 99.74% / CRITICAL).
- [ ] Phase 3 (proposed): analyst TP/FP feedback → `results/feedback_review.csv`;
      SHAP per-alert explanations; batch CSV scoring upload; watch-mode status.
      Build only on approval.

## 3. How it is built

- `frontend/app.py` (~300 lines): page config, cached loaders
  (`st.cache_resource` for the XGBoost model, `st.cache_data` for features
  and scored frames), one `with` block per tab. No new ML code — it reuses
  `src/argus_alert.py` (`load_model`, `score_all`, `collect_evidence`),
  `src/risk_engine.py`, and `demo/malicious_similar_demo.py` (`build_demo`).
- `frontend/requirements.txt`: `streamlit==1.66.0` only, kept separate so
  the core pipeline (`requirements.txt`) stays light.
- Verification: `streamlit.testing.v1.AppTest` full-script run —
  8 tabs render, widgets interact, no exceptions; plus live serve check
  (HTTP 200 on `/` and `/healthz`).
- Run: `pip install -r frontend/requirements.txt`,
  then `streamlit run frontend/app.py` → http://localhost:8501.
  One-command review remains `.\tasks.ps1 review` (tests + demo + dashboard).

## 4. Push policy

`frontend/` is intentionally **unpushed**. Push to `main` covers this plan
file plus all previously committed backend work (pipeline, eval, v2,
docs, tests). Push the implementation only after explicit approval.
