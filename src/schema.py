"""Model-feature schema gate: fail fast on training-serving skew.

The model was trained on exactly metrics.json:feature_names. If the scoring
CSV lacks any of them (stale features file, pruned-schema mismatch, renamed
column), XGBoost would either crash obscurely or silently mis-score. check()
turns that into one clear error. Extra columns (metadata, rule-side signals)
are allowed — they are simply not model inputs.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_METRICS = BASE_DIR / "results" / "metrics.json"


def expected_features(metrics_path: str | Path = DEFAULT_METRICS) -> list[str]:
    p = Path(metrics_path)
    if not p.exists():
        raise FileNotFoundError(
            f"Missing {p}. Run src/train_model.py first (it writes metrics.json).")
    names = json.loads(p.read_text(encoding="utf-8")).get("feature_names", [])
    if not names:
        raise ValueError(f"{p} has no feature_names list.")
    return list(names)


def check_frame(df: pd.DataFrame, expected: list[str] | None = None,
                source: str = "features") -> list[str]:
    """Return the ordered model-input columns, or raise a clear ValueError."""
    expected = expected if expected is not None else expected_features()
    missing = [c for c in expected if c not in df.columns]
    if missing:
        raise ValueError(
            f"{source}: {len(missing)} model feature(s) missing: {missing}. "
            "Regenerate with src/feature_engineering.py matching the trained model, "
            "or retrain with src/train_model.py.")
    return expected
