from risk_engine import calculate_risk_score


def benign_row():
    return {
        "powershell_count": 0, "cmd_count": 0, "suspicious_parent_child_count": 0,
        "file_write_velocity": 0.2, "high_entropy_write_count": 0,
        "entropy_delta_mean": 0.05, "persistence_key_count": 0,
        "network_connection_count": 2, "failed_login_count": 0,
    }


def test_benign_low_probability_is_low():
    score, sev = calculate_risk_score(benign_row(), 0.02)
    assert score < 25
    assert sev == "LOW"


def test_ransomware_signals_push_critical():
    row = benign_row()
    row.update({"file_write_velocity": 3.0, "high_entropy_write_count": 40,
                "entropy_delta_mean": 2.5})
    score, sev = calculate_risk_score(row, 0.99)
    assert score >= 75
    assert sev == "CRITICAL"


def test_severity_bands():
    row = benign_row()
    _, s0 = calculate_risk_score(row, 0.0)
    assert s0 == "LOW"
    # threat 0.5 alone = 30 -> MEDIUM
    _, s1 = calculate_risk_score(row, 0.5)
    assert s1 == "MEDIUM"
    # threat 1.0 alone = 60 -> HIGH (no bonuses)
    _, s2 = calculate_risk_score(row, 1.0)
    assert s2 == "HIGH"


def test_score_clamped_0_100():
    row = {"powershell_count": 5, "cmd_count": 5, "suspicious_parent_child_count": 5,
           "file_write_velocity": 99, "high_entropy_write_count": 99,
           "entropy_delta_mean": 9, "persistence_key_count": 9,
           "network_connection_count": 99, "failed_login_count": 99}
    score, _ = calculate_risk_score(row, 1.0)
    assert 0 <= score <= 100
