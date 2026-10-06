"""Contract for Task 1 outputs: structure + sane standard metrics.

Does NOT assert LOSO failure as a requirement (that would block fixing it);
it asserts the report exists, is complete, and the standard split is strong
while benign FPR stays low.
"""
import json
from pathlib import Path

R = Path("results")


def load():
    p = R / "generalization_report.json"
    assert p.exists(), "run src/evaluate_generalization.py first"
    return json.loads(p.read_text())


def test_report_structure():
    r = load()
    assert "standard_group_split" in r
    assert "loso" in r and len(r["loso"]) == 4
    assert "threshold_sweep" in r and len(r["threshold_sweep"]) > 5
    for entry in r["loso"]:
        assert "held_out" in entry and "at_0.5" in entry and "best_thresh_f1" in entry


def test_standard_split_strong():
    r = load()["standard_group_split"]
    assert r["auc"] >= 0.99
    assert r["at_0.5"]["f1"] >= 0.99


def test_benign_fpr_low():
    r = load()["benign_fpr_standard_test"]
    for scen in ("benign_normal", "benign_high_entropy", "benign_all"):
        assert scen in r
        assert r[scen]["fpr@0.5"] <= 0.01


def test_config_exists_and_sane():
    import sys
    sys.path.insert(0, "src")
    from config import load_config
    cfg = load_config("config.yaml")
    assert cfg["model"]["n_jobs"] == 1
    assert cfg["model"]["tree_method"] == "hist"
    assert 0 < cfg["alerting"]["threshold"] < 1
