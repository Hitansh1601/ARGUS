"""Table-driven risk engine tests."""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.risk_engine import PROB_WEIGHT, calculate_risk_score, explain_risk


def _row(**kw):
    base = {
        "powershell_count": 0, "cmd_count": 0,
        "suspicious_parent_child_count": 0, "file_write_velocity": 0,
        "high_entropy_write_count": 0, "entropy_delta_mean": 0,
        "persistence_key_count": 0, "network_connection_count": 0,
        "failed_login_count": 0,
    }
    base.update(kw)
    return base


def test_benign_low():
    score, sev = calculate_risk_score(_row(), 0.05)
    assert score == round(0.05 * PROB_WEIGHT, 2)
    assert sev == "LOW"


def test_ransomware_critical():
    row = _row(powershell_count=0, file_write_velocity=2.3,
               high_entropy_write_count=70, entropy_delta_mean=2.5)
    score, sev = calculate_risk_score(row, 0.98)
    # 58.8 + 5 + 8 + 8 = 79.8
    assert score == pytest_approx(79.8)
    assert sev == "CRITICAL"


def pytest_approx(x):
    return x  # tiny helper to keep style; equality is exact for these values


def test_each_rule_fires():
    cases = [
        ({"powershell_count": 1}, 8),
        ({"cmd_count": 1}, 5),
        ({"suspicious_parent_child_count": 1}, 10),
        ({"file_write_velocity": 1.1}, 5),
        ({"high_entropy_write_count": 6}, 8),
        ({"entropy_delta_mean": 1.1}, 8),
        ({"persistence_key_count": 1}, 10),
        ({"network_connection_count": 6}, 3),
        ({"failed_login_count": 4}, 5),
    ]
    for extra, w in cases:
        s, _ = calculate_risk_score(_row(**extra), 0.0)
        assert s == w, f"{extra} -> {s} != {w}"


def test_thresholds_not_firing_on_boundary():
    # Strict > : exactly at threshold must NOT fire.
    s, _ = calculate_risk_score(_row(file_write_velocity=1.0), 0.0)
    assert s == 0
    s, _ = calculate_risk_score(_row(high_entropy_write_count=5), 0.0)
    assert s == 0


def test_clipping_and_severity():
    s, sev = calculate_risk_score(_row(powershell_count=1), 1.0)
    assert sev in ("HIGH", "CRITICAL")
    s2, _ = calculate_risk_score(_row(), 5.0)  # prob clamped
    assert s2 <= 100


def test_explain():
    t = explain_risk(_row(powershell_count=2, persistence_key_count=1))
    assert len(t) == 2
