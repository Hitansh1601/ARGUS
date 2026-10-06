import pandas as pd

from feature_engineering import build_features


def tiny_telemetry():
    rows = []
    base = {"run_id": "R1", "host_id": "H1", "scenario": "benign_normal",
            "label": 0, "attack_phase": "BENIGN", "process_name": "chrome.exe",
            "parent_process": "explorer.exe", "tree_depth": 2,
            "event_type": "process_create", "file_path": None,
            "entropy_before": 4.0, "entropy_after": 4.05, "entropy_delta": 0.05,
            "bytes_sent": 100, "bytes_received": 100, "connection_interval": 5,
            "registry_key": None, "registry_action": None,
            "destination_ip": "192.0.2.10", "destination_port": 443,
            "auth_result": "SUCCESS", "timestamp": "2026-09-29T10:00:01.000"}
    for wid in (0, 1):
        for i in range(3):
            r = dict(base)
            r.update({"window_id": wid, "timestamp": f"2026-09-29T10:00:{wid * 30 + i:02d}.000"})
            rows.append(r)
    # one malicious ransomware-ish window
    for i in range(5):
        r = dict(base)
        r.update({"window_id": 2, "scenario": "ransomware_like", "label": 1,
                  "attack_phase": "IMPACT", "event_type": "file_write",
                  "file_path": f"C:\\a\\f{i}.encrypted",
                  "entropy_delta": 2.0, "entropy_after": 7.0,
                  "timestamp": f"2026-09-29T10:01:{i:02d}.000"})
        rows.append(r)
    return pd.DataFrame(rows)


def test_build_features_shape_and_labels():
    feats = build_features(tiny_telemetry())
    assert len(feats) == 3  # windows 0,1,2
    assert set(feats["label"].tolist()) == {0, 1}
    for col in ("event_count", "file_write_count", "entropy_delta_mean",
                "signal_diversity", "scenario"):
        assert col in feats.columns
    mal = feats[feats["label"] == 1].iloc[0]
    assert mal["file_write_count"] >= 5
    assert mal["entropy_delta_mean"] > 1.0


def test_features_no_inf_nan():
    feats = build_features(tiny_telemetry())
    num = feats.select_dtypes(include=["number"])
    assert not num.isna().any().any()
    assert not (num == float("inf")).any().any()
