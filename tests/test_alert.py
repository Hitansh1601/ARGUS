"""Alert module must import both ways and helpers must behave."""
import pandas as pd


def test_import_as_package_and_script():
    import src.argus_alert as pkg
    assert hasattr(pkg, "pick_batch")
    assert hasattr(pkg, "feature_matrix")
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "argus_alert_script", Path("src/argus_alert.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "main")


def test_feature_matrix_is_float():
    from argus_alert import feature_matrix
    df = pd.DataFrame({
        "label": [0, 1], "scenario": ["a", "b"], "dominant_phase": ["BENIGN", "X"],
        "run_id": ["R1", "R2"], "host_id": ["H1", "H2"], "window_id": [0, 1],
        "event_count": [5, 50], "powershell_count": [0, 2],
        "note": ["x", "y"],  # non-numeric, must be dropped
    })
    X = feature_matrix(df)
    assert "note" not in X.columns
    assert all(str(t) in ("float64", "float32", "float") for t in X.dtypes.astype(str))


def test_pick_batch_limit_and_backfill():
    from argus_alert import pick_batch
    df = pd.DataFrame({
        "scenario": ["ransomware_like"] * 4,
        "_proba": [0.9, 0.8, 0.1, 0.05],
        "_risk": [90, 80, 10, 5],
    })
    top2 = pick_batch(df, "ransomware_like", limit=2, threshold=0.5)
    assert len(top2) == 2
    assert top2.iloc[0]["_risk"] == 90
    # threshold so high nothing passes -> backfill still returns `limit` rows
    bf = pick_batch(df, "ransomware_like", limit=3, threshold=0.999)
    assert len(bf) == 3


def test_load_model_missing_raises():
    from argus_alert import load_model
    from pathlib import Path
    try:
        load_model(Path("nonexistent_model.json"))
        assert False, "should raise"
    except FileNotFoundError:
        pass
