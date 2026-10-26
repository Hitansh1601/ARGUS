from datetime import datetime, timedelta

import pandas as pd
import pytest

from feature_engineering import build_features
from src.feature_engineering import (
    HIGH_ENTROPY_DELTA_THRESHOLD,
    WINDOW_SECONDS,
    validate_schema,
)


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
                "scenario"):
        assert col in feats.columns
    mal = feats[feats["label"] == 1].iloc[0]
    assert mal["file_write_count"] >= 5
    assert mal["entropy_delta_mean"] > 1.0


def test_features_no_inf_nan():
    feats = build_features(tiny_telemetry())
    num = feats.select_dtypes(include=["number"])
    assert not num.isna().any().any()
    assert not (num == float("inf")).any().any()


# --- Tests adopted from upstream (argus-improvements PR#1) ---


def _row(ts, run="R-0001", host="H-001", win=0, **kw):
    base = {
        "timestamp": ts.isoformat(),
        "host_id": host,
        "run_id": run,
        "window_id": win,
        "event_type": "process_create",
        "process_name": "chrome.exe",
        "parent_process": "explorer.exe",
        "tree_depth": 2,
        "file_path": None,
        "entropy_before": 4.0,
        "entropy_after": 4.05,
        "entropy_delta": 0.05,
        "registry_key": None,
        "registry_action": None,
        "destination_ip": None,
        "destination_port": None,
        "bytes_sent": 0,
        "bytes_received": 0,
        "auth_result": None,
        "label": 0,
        "scenario": "benign_normal",
        "attack_phase": "BENIGN",
    }
    base.update(kw)
    return base


def test_validate_schema():
    with pytest.raises(ValueError):
        validate_schema(pd.DataFrame([{"foo": 1}]))
    with pytest.raises(ValueError):
        validate_schema(pd.DataFrame(columns=["timestamp", "run_id",
                                              "host_id", "window_id"]))


def test_velocity_and_entropy_thresholds():
    ts = datetime(2026, 9, 29, 10, 0, 0)
    rows = []
    for i in range(60):  # 60 writes in one window -> velocity 2.0
        rows.append(_row(ts + timedelta(seconds=i % 30), event_type="file_write",
                         file_path=f"C:\\a\\{i}.txt",
                         entropy_delta=2.5, entropy_after=6.5))
    df = pd.DataFrame(rows)
    feats = build_features(df)
    assert len(feats) == 1
    assert feats.iloc[0]["file_write_velocity"] == pytest.approx(60 / WINDOW_SECONDS)
    assert feats.iloc[0]["high_entropy_write_count"] == 60
    assert HIGH_ENTROPY_DELTA_THRESHOLD == 1.0


def test_pruned_schema_drops_dead_features():
    # Raw registry/auth/network events still parse, but gain-0.0 columns are
    # pruned from the model input by design (see PRUNED_FEATURES). Rule-side
    # scoring (risk_engine, collect_evidence) still reads these signals.
    from feature_engineering import PRUNED_FEATURES
    ts = datetime(2026, 9, 29, 10, 0, 0)
    rows = [
        _row(ts, event_type="registry_modify", registry_key="HKCU\\a\\CurrentVersion\\Run",
             registry_action="MODIFY", label=1, scenario="persistence_attack",
             attack_phase="PERSISTENCE"),
        _row(ts + timedelta(seconds=5), event_type="network_connection",
             destination_ip="1.1.1.1", destination_port=443,
             bytes_sent=100, label=1, scenario="persistence_attack",
             attack_phase="PERSISTENCE"),
        _row(ts + timedelta(seconds=6), event_type="authentication",
             auth_result="FAILURE", label=1, scenario="persistence_attack",
             attack_phase="PERSISTENCE"),
    ]
    feats = build_features(pd.DataFrame(rows))
    assert feats.iloc[0]["label"] == 1
    assert feats.iloc[0]["event_count"] == 3
    for col in PRUNED_FEATURES:
        assert col not in feats.columns, f"{col} should be pruned"
    assert len(PRUNED_FEATURES) == 14


def test_suspicious_parent_child():
    # Parent-child signal lives on the rule side now (risk + evidence);
    # the model input keeps the process counts that matter.
    ts = datetime(2026, 9, 29, 10, 0, 0)
    df = pd.DataFrame([_row(ts, process_name="powershell.exe",
                             parent_process="WINWORD.EXE")])
    feats = build_features(df)
    assert feats.iloc[0]["powershell_count"] == 1
    assert "suspicious_parent_child_count" not in feats.columns
