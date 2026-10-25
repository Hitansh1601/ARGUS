from pathlib import Path

import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "raw"
    / "synthetic"
    / "all_synthetic_telemetry.jsonl"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "argus_features.csv"
)

# Tunable constants (must stay in sync with simulator/generator.py
# and src/risk_engine.py).
WINDOW_SECONDS = 30
HIGH_ENTROPY_DELTA_THRESHOLD = 1.0

REQUIRED_COLUMNS = {"timestamp", "run_id", "host_id", "window_id"}


def validate_schema(df):
    """Fail fast with a helpful error if raw telemetry is malformed."""
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Input telemetry missing required columns: {sorted(missing)}. "
            "Did you run simulator/generator.py first?"
        )
    if df.empty:
        raise ValueError("Input telemetry is empty (0 rows).")
    return True


def safe_mode(series, default="BENIGN"):
    values = series.dropna()

    if values.empty:
        return default

    mode = values.mode()

    if mode.empty:
        return default

    return mode.iloc[0]


def build_features(df):
    validate_schema(df)
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Numeric conversions
    numeric_columns = [
        "entropy_before",
        "entropy_after",
        "entropy_delta",
        "bytes_sent",
        "bytes_received",
        "tree_depth",
        "connection_interval",
    ]

    for col in numeric_columns:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(
            df[col],
            errors="coerce"
        ).fillna(0)

    # Sorting is important for temporal calculations
    df = df.sort_values(
        ["run_id", "window_id", "timestamp"]
    ).reset_index(drop=True)

    group_columns = [
        "run_id",
        "host_id",
        "window_id",
    ]

    # -----------------------------------------------------
    # Process features
    # -----------------------------------------------------

    df["is_powershell"] = (
        df["process_name"]
        .fillna("")
        .str.lower()
        .eq("powershell.exe")
    )

    df["is_cmd"] = (
        df["process_name"]
        .fillna("")
        .str.lower()
        .eq("cmd.exe")
    )

    suspicious_children = [
        "powershell.exe",
        "cmd.exe",
    ]

    suspicious_parents = [
        "winword.exe",
        "excel.exe",
        "outlook.exe",
    ]

    df["suspicious_parent_child"] = (
        df["parent_process"]
        .fillna("")
        .str.lower()
        .isin(suspicious_parents)
        &
        df["process_name"]
        .fillna("")
        .str.lower()
        .isin(suspicious_children)
    )

    # -----------------------------------------------------
    # Network interval
    # -----------------------------------------------------

    network_mask = (
        df["event_type"] == "network_connection"
    )

    df["network_time_diff"] = (
        df.loc[network_mask]
        .groupby(group_columns)["timestamp"]
        .diff()
        .dt.total_seconds()
        .fillna(0)
    )

    # -----------------------------------------------------
    # Signal indicators
    # -----------------------------------------------------

    df["process_signal"] = (
        df["event_type"] == "process_create"
    ).astype(int)

    df["file_signal"] = (
        df["event_type"]
        .fillna("")
        .str.startswith("file_")
    ).astype(int)

    df["registry_signal"] = (
        df["event_type"] == "registry_modify"
    ).astype(int)

    df["network_signal"] = (
        df["event_type"] == "network_connection"
    ).astype(int)

    df["auth_signal"] = (
        df["event_type"] == "authentication"
    ).astype(int)

    # -----------------------------------------------------
    # Aggregation
    # -----------------------------------------------------

    grouped = df.groupby(group_columns)

    features = grouped.size().to_frame(
        "event_count"
    )

    features["process_count"] = grouped["process_signal"].sum()

    features["unique_process_count"] = grouped[
        "process_name"
    ].nunique()

    features["powershell_count"] = grouped[
        "is_powershell"
    ].sum()

    features["cmd_count"] = grouped[
        "is_cmd"
    ].sum()

    features["suspicious_parent_child_count"] = grouped[
        "suspicious_parent_child"
    ].sum()

    features["process_tree_depth"] = grouped[
        "tree_depth"
    ].max()

    # -----------------------------------------------------
    # File features
    # -----------------------------------------------------

    features["file_create_count"] = grouped[
        "event_type"
    ].apply(lambda x: (x == "file_create").sum())

    features["file_write_count"] = grouped[
        "event_type"
    ].apply(lambda x: (x == "file_write").sum())

    features["file_modify_count"] = grouped[
        "event_type"
    ].apply(lambda x: (x == "file_modify").sum())

    features["file_delete_count"] = grouped[
        "event_type"
    ].apply(lambda x: (x == "file_delete").sum())

    features["file_rename_count"] = grouped[
        "event_type"
    ].apply(lambda x: (x == "file_rename").sum())

    features["unique_files_modified"] = grouped[
        "file_path"
    ].nunique()

    features["file_write_velocity"] = (
        features["file_write_count"] / float(WINDOW_SECONDS)
    )

    features["entropy_mean"] = grouped[
        "entropy_after"
    ].mean()

    features["entropy_delta_mean"] = grouped[
        "entropy_delta"
    ].mean()

    features["high_entropy_write_count"] = grouped[
        "entropy_delta"
    ].apply(lambda x: (x > HIGH_ENTROPY_DELTA_THRESHOLD).sum())

    # -----------------------------------------------------
    # Registry features
    # -----------------------------------------------------

    features["registry_event_count"] = grouped[
        "registry_signal"
    ].sum()

    features["registry_modify_count"] = grouped[
        "registry_action"
    ].apply(
        lambda x: (
            x.fillna("").str.upper() == "MODIFY"
        ).sum()
    )

    features["persistence_key_count"] = grouped[
        "registry_key"
    ].apply(
        lambda x: x.fillna("").str.contains(
            r"CurrentVersion\Run",
            regex=False
        ).sum()
    )

    # -----------------------------------------------------
    # Network features
    # -----------------------------------------------------

    features["network_connection_count"] = grouped[
        "network_signal"
    ].sum()

    features["unique_destinations"] = grouped[
        "destination_ip"
    ].nunique()

    features["unique_ports"] = grouped[
        "destination_port"
    ].nunique()

    features["total_bytes_sent"] = grouped[
        "bytes_sent"
    ].sum()

    features["total_bytes_received"] = grouped[
        "bytes_received"
    ].sum()

    features["average_network_interval"] = grouped[
        "network_time_diff"
    ].mean()

    # -----------------------------------------------------
    # Authentication
    # -----------------------------------------------------

    features["auth_event_count"] = grouped[
        "auth_signal"
    ].sum()

    features["failed_login_count"] = grouped[
        "auth_result"
    ].apply(
        lambda x: (
            x.fillna("").str.upper() == "FAILURE"
        ).sum()
    )

    features["successful_login_count"] = grouped[
        "auth_result"
    ].apply(
        lambda x: (
            x.fillna("").str.upper() == "SUCCESS"
        ).sum()
    )

    # -----------------------------------------------------
    # Signal diversity
    # -----------------------------------------------------

    signal_matrix = grouped[
        [
            "process_signal",
            "file_signal",
            "registry_signal",
            "network_signal",
            "auth_signal",
        ]
    ].max()

    features["signal_diversity"] = signal_matrix.sum(axis=1)

    # -----------------------------------------------------
    # Labels / metadata
    # -----------------------------------------------------

    metadata = grouped.agg(
        label=("label", "max"),
        scenario=("scenario", safe_mode),
        dominant_phase=("attack_phase", safe_mode),
    )

    features = features.join(metadata)

    # -----------------------------------------------------
    # Cleanup
    # -----------------------------------------------------

    features = features.replace(
        [np.inf, -np.inf],
        np.nan
    )

    features = features.fillna(0)

    features = features.reset_index()

    return features


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found:\n{INPUT_FILE}\n"
            "Run simulator/generator.py first."
        )

    print("Loading synthetic telemetry...")

    df = pd.read_json(
        INPUT_FILE,
        lines=True
    )

    print(f"Raw events: {len(df):,}")

    features = build_features(df)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    features.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print()
    print("=" * 60)
    print("ARGUS FEATURE ENGINEERING")
    print("=" * 60)

    print(
        f"Feature windows : {len(features):,}"
    )

    print(
        f"Feature columns : {len(features.columns):,}"
    )

    print()
    print("Class distribution:")

    print(
        features["label"].value_counts()
    )

    print()
    print("Scenario distribution:")

    print(
        features["scenario"].value_counts()
    )

    print()
    print(f"Saved to:\n{OUTPUT_FILE}")

    print("=" * 60)


if __name__ == "__main__":
    main()