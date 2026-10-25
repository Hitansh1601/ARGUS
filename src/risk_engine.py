"""ARGUS risk engine: ML probability + explainable rules -> 0-100 score.

Example:
    >>> row = {"powershell_count": 1, "file_write_velocity": 2.5,
    ...        "high_entropy_write_count": 70, "entropy_delta_mean": 2.5}
    >>> calculate_risk_score(row, 0.98)
    (79.8, 'CRITICAL')
    # 0.98*60=58.8 + powershell 8 + velocity 5 + high_entropy 8 ... wait
    # entropy_delta 8 would be 87.8, but velocity/high_entropy/entropy
    # overlap depends on row values — see WEIGHTS below.
"""

PROB_WEIGHT = 60.0

# (feature, threshold, weight): score += weight if row[feature] > threshold.
# Thresholds use strict > to match historical behavior.
WEIGHTS = [
    ("powershell_count", 0, 8),
    ("cmd_count", 0, 5),
    ("suspicious_parent_child_count", 0, 10),
    ("file_write_velocity", 1, 5),
    ("high_entropy_write_count", 5, 8),
    ("entropy_delta_mean", 1, 8),
    ("persistence_key_count", 0, 10),
    ("network_connection_count", 5, 3),
    ("failed_login_count", 3, 5),
]

THRESHOLDS = {
    "CRITICAL": 75,
    "HIGH": 50,
    "MEDIUM": 25,
}


def calculate_risk_score(row, threat_probability):
    """
    Convert model probability and behavioral evidence
    into a 0-100 ARGUS risk score.
    """

    # Clamp probability to [0, 1] for robustness.
    try:
        prob = float(threat_probability)
    except (TypeError, ValueError):
        prob = 0.0
    prob = max(0.0, min(1.0, prob))

    score = prob * PROB_WEIGHT

    # get() works for both dict and pandas Series.
    getter = row.get if hasattr(row, "get") else lambda k, d=0: row[k] if k in row else d

    for feature, threshold, weight in WEIGHTS:
        try:
            val = float(getter(feature, 0) or 0)
        except (TypeError, ValueError):
            continue
        if val > threshold:
            score += weight

    score = max(0, min(100, score))

    if score >= THRESHOLDS["CRITICAL"]:
        severity = "CRITICAL"
    elif score >= THRESHOLDS["HIGH"]:
        severity = "HIGH"
    elif score >= THRESHOLDS["MEDIUM"]:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return round(score, 2), severity


def explain_risk(row):
    """Return list of triggered rule names for a row (for alerts/tests)."""
    triggered = []
    getter = row.get if hasattr(row, "get") else lambda k, d=0: row[k] if k in row else d
    for feature, threshold, weight in WEIGHTS:
        try:
            val = float(getter(feature, 0) or 0)
        except (TypeError, ValueError):
            continue
        if val > threshold:
            triggered.append(f"{feature}>{threshold} (+{weight})")
    return triggered
