"""Train e2e: full feature CSV -> train_and_evaluate (slower)."""
import json
import sys
from pathlib import Path

import pandas as pd
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))


@pytest.mark.e2e
def test_train_metrics_gate():
    from src.train_model import train_and_evaluate
    df = pd.read_csv(BASE_DIR / "data" / "processed" / "argus_features.csv")
    _, metrics, _ = train_and_evaluate(df)
    # Baseline was perfect 1.0; allow small dip after generator fix + new scenarios.
    for k in ["precision", "recall", "f1", "roc_auc"]:
        assert metrics[k] >= 0.90, f"{k}={metrics[k]} below gate"
    assert len(metrics["feature_names"]) == 30
    # Compare to golden if present.
    golden = BASE_DIR / "tests" / "golden" / "baseline_metrics.json"
    if golden.exists():
        g = json.loads(golden.read_text())
        for k in ["precision", "recall", "f1", "roc_auc"]:
            assert metrics[k] >= g.get(k, 0.9) - 0.05
