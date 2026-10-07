from pathlib import Path
import argparse
import sys

import pandas as pd
from xgboost import XGBClassifier

# Robust import: works as `python -m src.argus_alert` (root) and
# `python src/argus_alert.py` (src cwd) and `pytest` (rootdir).
try:
    from src.risk_engine import calculate_risk_score
except ImportError:  # fallback when cwd == src/
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    try:
        from src.risk_engine import calculate_risk_score
    except ImportError:
        from risk_engine import calculate_risk_score


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "argus_features.csv"
)

MODEL_FILE = (
    BASE_DIR
    / "models"
    / "argus_xgboost.json"
)


def collect_evidence(row):
    """Return evidence strings — kept in parity with risk_engine WEIGHTS."""
    evidence = []

    if row.get("powershell_count", 0) > 0:
        evidence.append("PowerShell execution")

    if row.get("cmd_count", 0) > 0:
        evidence.append("Command shell execution")

    if row.get("suspicious_parent_child_count", 0) > 0:
        evidence.append("Suspicious process relationship")

    if row.get("file_write_velocity", 0) > 1:
        evidence.append(
            f"High file-write velocity "
            f"({row['file_write_velocity']:.2f}/sec)"
        )

    if row.get("high_entropy_write_count", 0) > 5:
        evidence.append(
            f"High-entropy writes "
            f"({int(row['high_entropy_write_count'])})"
        )

    if row.get("entropy_delta_mean", 0) > 1:
        evidence.append(
            f"Significant entropy increase "
            f"({row['entropy_delta_mean']:.2f})"
        )

    if row.get("persistence_key_count", 0) > 0:
        evidence.append("Registry persistence activity")

    if row.get("network_connection_count", 0) > 5:
        evidence.append("Elevated network activity")

    if row.get("failed_login_count", 0) > 3:
        evidence.append(
            "Multiple failed authentication attempts"
        )

    if not evidence:
        evidence.append(
            "No strong behavioral indicators"
        )
    return evidence


def _supports_unicode():
    try:
        import sys
        enc = (sys.stdout.encoding or "").lower()
        return "utf" in enc
    except Exception:
        return False


def _safe_str(row, key, default="-"):
    try:
        v = row.get(key, default) if hasattr(row, "get") else row[key]
    except Exception:
        return str(default)
    if v is None:
        return str(default)
    try:
        import math
        if isinstance(v, float) and math.isnan(v):
            return str(default)
    except Exception:
        pass
    s = str(v)
    return s if len(s) <= 46 else s[:43] + "..."


def print_alert(row, probability, risk_score, severity, ascii_only=False):
    use_unicode = (not ascii_only) and _supports_unicode()
    if use_unicode:
        TL, TR, ML, MR, BL, BR, H, V = "\u2554", "\u2557", "\u2560", "\u2563", "\u255a", "\u255d", "\u2550", "\u2551"
        bullet = "\u2022"
    else:
        TL, TR, ML, MR, BL, BR, H, V = "+", "+", "+", "+", "+", "+", "-", "|"
        bullet = "*"
    try:
        print()
        print(TL + H * 68 + TR)
        print(V + "ARGUS SECURITY ALERT".center(68) + V)
        print(ML + H * 68 + MR)
        print(f"{V} Host             : {_safe_str(row, 'host_id'):<46}{V}")
        print(f"{V} Run              : {_safe_str(row, 'run_id'):<46}{V}")
        print(f"{V} Window           : {_safe_str(row, 'window_id'):<46}{V}")
        print(f"{V} Scenario         : {_safe_str(row, 'scenario'):<46}{V}")
        print(V + " " * 68 + V)
        print(f"{V} Threat Probability : {float(probability) * 100:>7.2f}%" + " " * 43 + V)
        print(f"{V} Risk Score         : {float(risk_score):>7.2f}/100" + " " * 45 + V)
        print(f"{V} Severity           : {str(severity):<46}{V}")
        print(V + " " * 68 + V)
        print((V + " Evidence:").ljust(69) + V)
        evidence = collect_evidence(row)
        for item in evidence:
            s = str(item)
            if len(s) > 64:
                s = s[:61] + "..."
            print(f"{V}  {bullet} {s:<64}{V}")
        print(V + " " * 68 + V)
        print(f"{V} Attack Phase      : {_safe_str(row, 'dominant_phase'):<46}{V}")
        print(BL + H * 68 + BR)
    except UnicodeEncodeError:
        print_alert(row, probability, risk_score, severity, ascii_only=True)


def select_suspicious(df, scenario="ransomware_like", top_n=1):
    """Select top-N suspicious windows by file_write_velocity."""
    suspicious = df[
        df["scenario"] == scenario
    ]

    if suspicious.empty:
        suspicious = df[
            df["label"] == 1
        ]

    if suspicious.empty:
        raise RuntimeError(
            "No suspicious examples found."
        )

    # Keep the original dataframe index.
    # This is important when selecting the prediction row.
    ranked = suspicious.sort_values(
        "file_write_velocity",
        ascending=False
    )
    indices = list(ranked.index[:max(1, top_n)])
    return indices


def main(scenario="ransomware_like", top_n=1):

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            "Feature dataset not found."
        )

    if not MODEL_FILE.exists():
        raise FileNotFoundError(
            "Trained ARGUS model not found."
        )

    print()
    print("Loading ARGUS model...")

    model = XGBClassifier()

    model.load_model(
        MODEL_FILE
    )

    print("Loading telemetry features...")

    df = pd.read_csv(
        DATA_FILE
    )

    # -----------------------------------------------------
    # Select suspicious examples
    # -----------------------------------------------------

    indices = select_suspicious(df, scenario=scenario, top_n=top_n)
    selected_index = indices[0]

    row = df.loc[selected_index]

    # -----------------------------------------------------
    # Prepare model features
    # -----------------------------------------------------

    metadata_columns = [
        "label",
        "scenario",
        "dominant_phase",
        "run_id",
        "host_id",
        "window_id",
    ]

    X = df.drop(
        columns=metadata_columns,
        errors="ignore"
    )

    # Only numeric columns
    X = X.select_dtypes(
        include=["number"]
    )

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.fillna(0)

    # -----------------------------------------------------
    # IMPORTANT FIX
    # -----------------------------------------------------
    # Select the row directly from the numeric dataframe.
    # This preserves numeric dtypes and prevents XGBoost's
    # "DataFrame.dtypes must be int, float, bool or category"
    # error.

    X_row = X.loc[
        [selected_index]
    ].astype(float)

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------

    probability = model.predict_proba(
        X_row
    )[0][1]

    # -----------------------------------------------------
    # Risk score
    # -----------------------------------------------------

    risk_score, severity = calculate_risk_score(
        row,
        probability
    )

    # -----------------------------------------------------
    # Display alert
    # -----------------------------------------------------

    print_alert(
        row,
        probability,
        risk_score,
        severity
    )
    return {
        "probability": float(probability),
        "risk_score": risk_score,
        "severity": severity,
        "index": int(selected_index),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARGUS demo alert")
    parser.add_argument("--scenario", default="ransomware_like")
    parser.add_argument("--top-n", type=int, default=1)
    args = parser.parse_args()
    main(scenario=args.scenario, top_n=args.top_n)
