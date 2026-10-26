"""Schema gate tests (fast, tmp files only)."""
import json

import pandas as pd
import pytest

from schema import check_frame, expected_features


def _metrics(tmp_path, names):
    p = tmp_path / "metrics.json"
    p.write_text(json.dumps({"feature_names": names}), encoding="utf-8")
    return p


def test_expected_features_loads(tmp_path):
    p = _metrics(tmp_path, ["a", "b"])
    assert expected_features(p) == ["a", "b"]


def test_expected_features_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        expected_features(tmp_path / "nope.json")


def test_check_frame_ok_and_ordered(tmp_path):
    p = _metrics(tmp_path, ["b", "a"])
    df = pd.DataFrame({"a": [1], "b": [2], "run_id": ["R"],
                       "label": [0]})  # extras allowed
    assert check_frame(df, expected_features(p)) == ["b", "a"]


def test_check_frame_missing_raises(tmp_path):
    p = _metrics(tmp_path, ["a", "b", "c"])
    df = pd.DataFrame({"a": [1], "b": [2]})
    with pytest.raises(ValueError, match="missing.*'c'|missing.*c"):
        check_frame(df, expected_features(p), source="unit-test")


def test_live_metrics_match_csv():
    # Repo-level contract: committed features CSV satisfies committed model.
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    df = pd.read_csv(root / "data" / "processed" / "argus_features.csv")
    assert check_frame(df, expected_features(root / "results" / "metrics.json"))
