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

def test_evidence_parity_with_risk():
    from argus_alert import collect_evidence
    row = {
        "powershell_count": 1, "cmd_count": 1,
        "suspicious_parent_child_count": 1, "file_write_velocity": 2.0,
        "high_entropy_write_count": 10, "entropy_delta_mean": 2.0,
        "persistence_key_count": 1, "network_connection_count": 10,
        "failed_login_count": 5,
    }
    ev = collect_evidence(row)
    assert len(ev) == 9, f"expected 9 evidence items, got {ev}"
    assert any("High-entropy" in e for e in ev)


def test_evidence_empty():
    from argus_alert import collect_evidence
    assert collect_evidence({}) == ["No strong behavioral indicators"]


def _dupes_df():
    import pandas as pd
    return pd.DataFrame([
        {"run_id": "R1", "window_id": 0, "scenario": "ransomware_like",
         "_proba": 0.99, "_risk": 90.0, "_severity": "CRITICAL"},
        {"run_id": "R1", "window_id": 1, "scenario": "ransomware_like",
         "_proba": 0.98, "_risk": 85.0, "_severity": "CRITICAL"},
        {"run_id": "R2", "window_id": 0, "scenario": "brute_force_attack",
         "_proba": 0.97, "_risk": 70.0, "_severity": "HIGH"},
    ])


def test_dedup_collapses_same_run():
    from argus_alert import dedup_hits, pick_batch
    out = dedup_hits(_dupes_df())
    assert len(out) == 2  # R1 pair -> 1, R2 stays
    r1 = out[out["run_id"] == "R1"].iloc[0]
    assert r1["_dupes"] == 2 and r1["_risk"] == 90.0  # keeps hottest
    assert out[out["run_id"] == "R2"].iloc[0]["_dupes"] == 1


def test_pick_batch_dedup_flag():
    from argus_alert import pick_batch
    plain = pick_batch(_dupes_df(), None, limit=10, threshold=0.5)
    assert len(plain) == 3 and "_dupes" not in plain.columns
    dd = pick_batch(_dupes_df(), None, limit=10, threshold=0.5, dedup=True)
    assert len(dd) == 2 and dd["_dupes"].tolist() == [2, 1]
