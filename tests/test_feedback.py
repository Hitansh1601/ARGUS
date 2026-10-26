"""Analyst feedback tests (fast, tmp files only)."""
import pandas as pd

from feedback import label, stats


def _features(tmp_path):
    p = tmp_path / "features.csv"
    pd.DataFrame([
        {"run_id": "R1", "window_id": 0, "host_id": "H1",
         "scenario": "demo_benign", "label": 0},
        {"run_id": "R1", "window_id": 1, "host_id": "H1",
         "scenario": "demo_ransomware_like", "label": 1},
    ]).to_csv(p, index=False)
    return p


def test_label_roundtrip(tmp_path):
    fp = tmp_path / "feedback.csv"
    e = label("R1", 1, 1, note="drill", features_path=_features(tmp_path),
              feedback_path=fp)
    assert e["analyst_label"] == 1 and e["scenario"] == "demo_ransomware_like"
    fb = pd.read_csv(fp)
    assert len(fb) == 1 and fb.iloc[0]["note"] == "drill"


def test_label_bad_window_raises(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        label("NOPE", 9, 1, features_path=_features(tmp_path),
              feedback_path=tmp_path / "f.csv")


def test_stats_counts(tmp_path):
    fp = tmp_path / "feedback.csv"
    f = _features(tmp_path)
    label("R1", 0, 0, features_path=f, feedback_path=fp)
    label("R1", 1, 1, features_path=f, feedback_path=fp)
    s = stats(fp)
    assert s == {"n": 2, "malicious": 1, "benign": 1,
                 "scenarios": {"demo_benign": 1, "demo_ransomware_like": 1}}
