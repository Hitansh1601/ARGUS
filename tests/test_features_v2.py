"""Schema tests for features_v2 (fast: synthetic frames only, no 58k load)."""
import pandas as pd

from features_v2 import (
    V2_COLUMNS,
    describe_gaps,
    extract_argus,
    extract_cic,
)


def _cic_row(**kw):
    base = {
        "pslist.nproc": 55, "psxview.not_in_pslist": 0,
        "psxview.not_in_eprocess_pool": 0, "malfind.ninjections": 0,
        "malfind.uniqueInjections": 0, "ldrmodules.not_in_mem": 0,
        "Class": "Benign",
    }
    base.update(kw)
    return base


def _argus_row(**kw):
    base = {
        "process_count": 3, "suspicious_parent_child_count": 0,
        "process_tree_depth": 2, "label": 0,
    }
    base.update(kw)
    return base


def test_cic_benign_no_artifact():
    v2 = extract_cic(pd.DataFrame([_cic_row()]))
    assert list(v2.columns) == V2_COLUMNS
    assert v2.iloc[0]["label"] == 0
    assert v2.iloc[0]["hidden_artifact"] == 0
    assert v2.iloc[0]["process_count"] == 55


def test_cic_malware_hidden_artifact():
    v2 = extract_cic(pd.DataFrame([
        _cic_row(Class="Malware"),  # no stealth indicators -> 0
        _cic_row(Class="Trojan", **{"psxview.not_in_pslist": 2}),
        _cic_row(Class="Ransomware", **{"ldrmodules.not_in_mem": 1}),
    ]))
    assert v2["label"].tolist() == [1, 1, 1]
    assert v2["hidden_artifact"].tolist() == [0, 1, 1]


def test_argus_mapping():
    v2 = extract_argus(pd.DataFrame([
        _argus_row(),
        _argus_row(suspicious_parent_child_count=1, label=1),
        _argus_row(process_tree_depth=5, label=1),
    ]))
    assert v2["label"].tolist() == [0, 1, 1]
    assert v2["hidden_artifact"].tolist() == [0, 1, 1]


def test_schema_no_nan_and_dtypes():
    v2 = extract_argus(pd.DataFrame([_argus_row()]))
    assert not v2.isna().any().any()
    assert set(v2["hidden_artifact"].unique()) <= {0, 1}
    assert set(v2["label"].unique()) <= {0, 1}
    assert set(v2["source"].unique()) == {"argus"}


def test_gaps_documented():
    gaps = describe_gaps()
    assert gaps["shared_primitives"] == ["process_count", "hidden_artifact"]
    assert "failed_login_count" in gaps["argus_only"]
    assert "malfind.ninjections" in gaps["cic_only"]
