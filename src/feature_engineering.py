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

    # Windows-only: match by basename, case-insensitive, handles full paths
    # e.g. C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    def _basename(series):
        return (
            series.fillna("")
            .str.lower()
            .str.replace("/", "\\", regex=False)
            .str.split("\\")
            .str[-1]
        )

    _proc_base = _basename(df["process_name"])
    _parent_base = _basename(df["parent_process"])

    POWERSHELL_NAMES = {
        "powershell.exe",
        "powershell_ise.exe",
        "pwsh.exe",
    }

    CMD_NAMES = {
        "cmd.exe",
    }

    df["is_powershell"] = _proc_base.isin(POWERSHELL_NAMES)

    df["is_cmd"] = _proc_base.isin(CMD_NAMES)

    suspicious_children = [
        "powershell.exe",
        "powershell_ise.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "msiexec.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "regsvr32.exe",
    ]

    suspicious_parents = [
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "powerpnt.exe",
        "acrord32.exe",
        "iexplore.exe",
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
    ]

    df["suspicious_parent_child"] = (
        _parent_base.isin(suspicious_parents)
        &
        _proc_base.isin(suspicious_children)
    )

    # -----------------------------------------------------
    # Network interval
    # -----------------------------------------------------

    network_mask = (
        df["event_type"] == "network_connection"
    )

    # Keep NaN for non-network rows and first packet in window.
    # average_network_interval below excludes zeros so 1-beacon
    # windows don't look like C2 beacons.
    _net_diff = (
        df.loc[network_mask]
        .groupby(group_columns)["timestamp"]
        .diff()
        .dt.total_seconds()
    )
    df["network_time_diff"] = _net_diff.reindex(df.index)
    df["network_time_diff_for_avg"] = df["network_time_diff"].where(
        df["network_time_diff"] > 0
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

    # Entropy averaged over file events only. Non-file events have
    # entropy 0 after fillna and would drag benign windows down,
    # making separation artificially easy.
    df["entropy_after_file"] = df["entropy_after"].where(
        df["file_signal"] == 1
    )
    df["entropy_delta_file"] = df["entropy_delta"].where(
        df["file_signal"] == 1
    )

    features["entropy_mean"] = grouped[
        "entropy_after_file"
    ].mean()

    features["entropy_delta_mean"] = grouped[
        "entropy_delta_file"
    ].mean()

    # Count high-entropy file_write events only (not reads).
    df["is_high_entropy_write"] = (
        (df["event_type"] == "file_write")
        & (df["entropy_delta"] > HIGH_ENTROPY_DELTA_THRESHOLD)
    )
    features["high_entropy_write_count"] = grouped[
        "is_high_entropy_write"
    ].sum()

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

    # Case-insensitive. `currentversion\run` covers Run, RunOnce,
    # RunServices (all start with ...\Run).
    features["persistence_key_count"] = grouped[
        "registry_key"
    ].apply(
        lambda x: x.fillna("").str.lower().str.contains(
            r"currentversion\run",
            regex=False,
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

    # Exclude first-packet zeros: mean over >0 intervals only.
    # Windows with 0-1 beacons -> NaN -> filled to 0 later.
    features["average_network_interval"] = grouped[
        "network_time_diff_for_avg"
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