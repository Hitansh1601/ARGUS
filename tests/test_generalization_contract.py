"""Contract for evaluation outputs: structure + sane standard metrics.

Does NOT assert LOSO failure as a requirement (that would block fixing it);
it asserts the report exists, is complete, and the standard split is strong
while benign FPR stays low. A separate gate requires every held-out attack
to be detected (recall the 6-scenario era, when this failed at F1=0.0).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from evaluate_generalization import ATTACK_SCENARIOS

R = Path("results")


def load():
    p = R / "generalization_report.json"
    assert p.exists(), "run src/evaluate_generalization.py first"
    return json.loads(p.read_text())


def test_report_structure():
    r = load()
    assert "standard_group_split" in r
    assert "loso" in r and len(r["loso"]) == len(ATTACK_SCENARIOS)
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


def test_loso_gate_no_unseen_attack_missed():
    # Regression gate for the generalization finding: every held-out
    # attack scenario must be detected at the default threshold.
    # (With 6 scenarios this failed at F1=0.0; 8-scenario diversity fixed it.)
    r = load()
    for entry in r["loso"]:
        assert entry["auc"] >= 0.90, f"{entry['held_out']} AUC={entry['auc']}"
        f1 = entry["at_0.5"]["f1"]
        assert f1 >= 0.90, f"{entry['held_out']} F1@0.5={f1}"
