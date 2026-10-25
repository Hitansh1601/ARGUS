"""Smoke tests: imports, files, model load."""
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent


def test_required_files_exist():
    assert (BASE_DIR / "requirements.txt").exists()
    assert (BASE_DIR / "simulator" / "generator.py").exists()
    assert (BASE_DIR / "src" / "feature_engineering.py").exists()
    assert (BASE_DIR / "src" / "train_model.py").exists()
    assert (BASE_DIR / "src" / "risk_engine.py").exists()
    assert (BASE_DIR / "src" / "argus_alert.py").exists()


def test_model_loads():
    from xgboost import XGBClassifier
    model_path = BASE_DIR / "models" / "argus_xgboost.json"
    assert model_path.exists(), "Run src/train_model.py first"
    m = XGBClassifier()
    m.load_model(model_path)
    assert m.n_features_in_ == 30


def test_feature_csv_shape():
    csv = BASE_DIR / "data" / "processed" / "argus_features.csv"
    assert csv.exists()
    df = pd.read_csv(csv)
    # 6 windows per run; runs = rows/6. Accept old (360 runs) or new (480 runs).
    assert len(df) % 6 == 0
    assert len(df) >= 2160
    assert "label" in df.columns and "scenario" in df.columns
