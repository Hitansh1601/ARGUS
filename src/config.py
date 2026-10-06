"""Central config loader with stdlib fallback (PyYAML optional)."""
from __future__ import annotations

from pathlib import Path

_DEFAULTS = {
    "data": {
        "synthetic": "data/raw/synthetic/all_synthetic_telemetry.jsonl",
        "features": "data/processed/argus_features.csv",
        "model": "models/argus_xgboost.json",
        "results_dir": "results",
    },
    "model": {
        "n_estimators": 250, "max_depth": 5, "learning_rate": 0.05,
        "subsample": 0.9, "colsample_bytree": 0.9,
        "objective": "binary:logistic", "eval_metric": "logloss",
        "random_state": 42, "n_jobs": 1, "tree_method": "hist",
    },
    "alerting": {"threshold": 0.5},
    "eval": {"test_size": 0.25, "benign_holdout": 0.30, "random_state": 42},
}

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


def _deep_merge(base: dict, over: dict) -> dict:
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | Path | None = None) -> dict:
    p = Path(path) if path else CONFIG_PATH
    if not p.exists():
        return {k: dict(v) for k, v in _DEFAULTS.items()}
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(p.read_text()) or {}
    except ImportError:
        data = {}
    except Exception:
        data = {}
    return _deep_merge(_DEFAULTS, data)
