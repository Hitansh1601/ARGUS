import json
import random
import uuid
from pathlib import Path
from datetime import datetime, timedelta

SEED = 42
random.seed(SEED)

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "raw" / "synthetic"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SCENARIOS = [
    "benign_normal",
    "benign_high_entropy",
    "powershell_attack",
    "persistence_attack",
    "ransomware_like",
    "multi_stage_attack",
    "brute_force_attack",
    "c2_heavy_attack",
]

RUNS_PER_SCENARIO = 60
WINDOW_SECONDS = 30
# Thresholds shared with feature_engineering / risk_engine.
HIGH_ENTROPY_DELTA_THRESHOLD = 1.0


def iso_time(dt):
    return dt.isoformat(timespec="milliseconds")


def make_event(
    timestamp,
    host_id,
    run_id,
    window_id,
    event_type,
    label,
    scenario,
    attack_phase="BENIGN",
    **kwargs,
):
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": iso_time(timestamp),
        "host_id": host_id,
        "run_id": run_id,
        "window_id": window_id,

        "event_type": event_type,

        "process_name": None,
        "parent_process": None,
        "process_id": None,
        "parent_pid": None,
        "tree_depth": None,

        "file_path": None,
        "file_extension": None,
        "entropy_before": None,
        "entropy_after": None,
        "entropy_delta": None,

        "registry_key": None,
        "registry_action": None,

        "destination_ip": None,
        "destination_port": None,
        "protocol": None,
        "bytes_sent": 0,
        "bytes_received": 0,

        "username": "student",
        "auth_result": None,

        "source": "synthetic_endpoint_simulator",

        "label": label,
        "scenario": scenario,
        "attack_phase": attack_phase,
    }

    event.update(kwargs)
    return event


def process_event(
    timestamp,
    host,
    run_id,
    window_id,
    scenario,
    label,
    process,
    parent,
    depth,
    phase="BENIGN",
):
    return make_event(
        timestamp=timestamp,
        host_id=host,
        run_id=run_id,
        window_id=window_id,
        event_type="process_create",
        label=label,
        scenario=scenario,
        attack_phase=phase,
        process_name=process,
        parent_process=parent,
        process_id=random.randint(1000, 9000),
        parent_pid=random.randint(1000, 9000),
        tree_depth=depth,
    )


def file_event(
    timestamp,
    host,
    run_id,
    window_id,
    scenario,
    label,
    action,
    extension,
    phase="BENIGN",
    high_entropy=False,
):
    before = round(random.uniform(3.5, 6.2), 3)

    if high_entropy:
        after = round(before + random.uniform(0.5, 4.0), 3)
    else:
        after = round(before + random.uniform(0.01, 0.15), 3)

    delta = round(after - before, 3)

    stem = random.choice([
        "report",
        "document",
        "photo",
        "database",
        "backup",
        "presentation",
        "financial",
        "project",
    ])

    extension_map = {
        "txt": ".txt",
        "doc": ".docx",
        "jpg": ".jpg",
        "pdf": ".pdf",
        "zip": ".zip",
        "enc": ".encrypted",
        "bak": ".bak",
    }

    final_ext = extension_map.get(extension, ".dat")

    return make_event(
        timestamp=timestamp,
        host_id=host,
        run_id=run_id,
        window_id=window_id,
        event_type=f"file_{action}",
        label=label,
        scenario=scenario,
        attack_phase=phase,
        file_path=f"C:\\Users\\student\\Documents\\{stem}_{random.randint(1,9999)}{final_ext}",
        file_extension=final_ext,
        entropy_before=before,
        entropy_after=after,
        entropy_delta=delta,
    )


def network_event(
    timestamp,
    host,
    run_id,
    window_id,
    scenario,
    label,
    process,
    interval,
    phase="BENIGN",
):
    return make_event(
        timestamp=timestamp,
        host_id=host,
        run_id=run_id,
        window_id=window_id,
        event_type="network_connection",
        label=label,
        scenario=scenario,
        attack_phase=phase,
        process_name=process,
        destination_ip=random.choice([
            "192.0.2.10",
            "198.51.100.20",
            "203.0.113.30",
        ]),
        destination_port=random.choice([443, 80, 53]),
        protocol="TCP",
        bytes_sent=random.randint(200, 5000),
        bytes_received=random.randint(100, 5000),
        connection_interval=interval,
    )


def auth_event(
    timestamp,
    host,
    run_id,
    window_id,
    scenario,
    label,
    result,
    phase="BENIGN",
):
    return make_event(
        timestamp=timestamp,
        host_id=host,
        run_id=run_id,
        window_id=window_id,
        event_type="authentication",
        label=label,
        scenario=scenario,
        attack_phase=phase,
        auth_result=result,
    )


# ---------------------------------------------------------
# BENIGN NORMAL
# ---------------------------------------------------------

def generate_benign_normal(start, host, run_id, window_id):
    events = []
    base_offset = random.randint(0, 25)
    label = 0
    scenario = "benign_normal"

    processes = [
        ("chrome.exe", "explorer.exe", 2),
        ("WINWORD.EXE", "explorer.exe", 2),
        ("notepad.exe", "explorer.exe", 2),
        ("explorer.exe", "winlogon.exe", 1),
    ]

    for process, parent, depth in random.sample(
        processes, random.randint(2, 4)
    ):
        events.append(
            process_event(
                start + timedelta(seconds=base_offset),
                host,
                run_id,
                window_id,
                scenario,
                label,
                process,
                parent,
                depth,
            )
        )

    for _ in range(random.randint(4, 8)):
        events.append(
            file_event(
                start + timedelta(seconds=random.randint(1, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                action=random.choice(["create", "write", "modify"]),
                extension=random.choice(["txt", "doc", "jpg", "pdf"]),
            )
        )

    for _ in range(random.randint(2, 5)):
        events.append(
            network_event(
                start + timedelta(seconds=random.randint(1, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "chrome.exe",
                random.randint(3, 15),
            )
        )

    if window_id == 0:
        events.append(
            auth_event(
                start + timedelta(seconds=2),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "SUCCESS",
            )
        )

    return events


# ---------------------------------------------------------
# BENIGN HIGH ENTROPY
# ---------------------------------------------------------

def generate_benign_high_entropy(start, host, run_id, window_id):
    events = []
    label = 0
    scenario = "benign_high_entropy"

    process_name = random.choice([
        "7zFM.exe",
        "backupsvc.exe",
        "encoder.exe",
    ])

    events.append(
        process_event(
            start + timedelta(seconds=2),
            host,
            run_id,
            window_id,
            scenario,
            label,
            process_name,
            "explorer.exe",
            2,
        )
    )

    for _ in range(random.randint(25, 45)):
        events.append(
            file_event(
                start + timedelta(seconds=random.randint(1, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                action=random.choice(["read", "write", "modify"]),
                extension=random.choice(["zip", "bak", "dat"]),
                high_entropy=True,
            )
        )

    for _ in range(random.randint(1, 3)):
        events.append(
            network_event(
                start + timedelta(seconds=random.randint(1, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                process_name,
                random.randint(5, 20),
            )
        )

    return events


# ---------------------------------------------------------
# POWERSHELL ATTACK
# ---------------------------------------------------------

def generate_powershell(start, host, run_id, window_id):
    events = []
    label = 1
    scenario = "powershell_attack"
    phase = "EXECUTION"

    events.append(
        process_event(
            start + timedelta(seconds=2),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "WINWORD.EXE",
            "explorer.exe",
            2,
            phase,
        )
    )

    events.append(
        process_event(
            start + timedelta(seconds=5),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "powershell.exe",
            "WINWORD.EXE",
            3,
            phase,
        )
    )

    events.append(
        process_event(
            start + timedelta(seconds=8),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "cmd.exe",
            "powershell.exe",
            4,
            phase,
        )
    )

    for _ in range(random.randint(2, 5)):
        events.append(
            network_event(
                start + timedelta(seconds=random.randint(8, 28)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "powershell.exe",
                random.randint(5, 10),
                phase,
            )
        )

    for _ in range(random.randint(2, 5)):
        events.append(
            file_event(
                start + timedelta(seconds=random.randint(5, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "create",
                "txt",
                phase,
            )
        )

    return events


# ---------------------------------------------------------
# PERSISTENCE ATTACK
# ---------------------------------------------------------

def generate_persistence(start, host, run_id, window_id):
    events = []
    label = 1
    scenario = "persistence_attack"
    phase = "PERSISTENCE"

    events.append(
        process_event(
            start + timedelta(seconds=2),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "powershell.exe",
            "explorer.exe",
            2,
            phase,
        )
    )

    for _ in range(random.randint(1, 3)):
        events.append(
            make_event(
                timestamp=start + timedelta(seconds=random.randint(5, 20)),
                host_id=host,
                run_id=run_id,
                window_id=window_id,
                event_type="registry_modify",
                label=label,
                scenario=scenario,
                attack_phase=phase,
                process_name="powershell.exe",
                registry_key=(
                    "HKCU\\Software\\Microsoft\\Windows\\"
                    "CurrentVersion\\Run"
                ),
                registry_action="MODIFY",
            )
        )

    events.append(
        process_event(
            start + timedelta(seconds=22),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "taskhostw.exe",
            "explorer.exe",
            2,
            phase,
        )
    )

    for _ in range(random.randint(1, 3)):
        events.append(
            network_event(
                start + timedelta(seconds=random.randint(10, 28)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "taskhostw.exe",
                10,
                phase,
            )
        )

    return events


# ---------------------------------------------------------
# RANSOMWARE-LIKE SIMULATION
# ---------------------------------------------------------

def generate_ransomware(start, host, run_id, window_id, scenario_override=None):
    events = []
    label = 1
    scenario = scenario_override or "ransomware_like"
    phase = "IMPACT"

    events.append(
        process_event(
            start + timedelta(seconds=2),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "worker.exe",
            "explorer.exe",
            2,
            phase,
        )
    )

    for _ in range(random.randint(70, 110)):
        events.append(
            file_event(
                start + timedelta(seconds=random.randint(1, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                action=random.choice(["write", "modify", "rename"]),
                extension=random.choice(["enc", "doc", "jpg", "pdf"]),
                phase=phase,
                high_entropy=True,
            )
        )

    for _ in range(random.randint(2, 5)):
        events.append(
            network_event(
                start + timedelta(seconds=random.randint(3, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "worker.exe",
                10,
                phase,
            )
        )

    return events


# ---------------------------------------------------------
# MULTI-STAGE ATTACK
# ---------------------------------------------------------

def _relabel(events, scenario):
    for e in events:
        e["scenario"] = scenario
    return events


def generate_multi_stage(start, host, run_id, window_id):
    events = []
    target = "multi_stage_attack"

    # Window 0-1: normal activity (keep BENIGN phase, fix scenario label)
    if window_id < 2:
        return _relabel(generate_benign_normal(
            start,
            host,
            run_id,
            window_id
        ), target)

    # Window 2: execution
    if window_id == 2:
        return _relabel(generate_powershell(
            start,
            host,
            run_id,
            window_id
        ), target)

    # Window 3: persistence
    if window_id == 3:
        return _relabel(generate_persistence(
            start,
            host,
            run_id,
            window_id
        ), target)

    # Window 4: C2-like behavior
    if window_id == 4:
        events = []
        label = 1
        scenario = "multi_stage_attack"
        phase = "C2"

        events.append(
            process_event(
                start + timedelta(seconds=2),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "svchelper.exe",
                "powershell.exe",
                4,
                phase,
            )
        )

        for offset in [5, 15, 25]:
            events.append(
                network_event(
                    start + timedelta(seconds=offset),
                    host,
                    run_id,
                    window_id,
                    scenario,
                    label,
                    "svchelper.exe",
                    10,
                    phase,
                )
            )

        return events

    # Window 5: impact (preserve multi-stage scenario label)
    return generate_ransomware(
        start,
        host,
        run_id,
        window_id,
        scenario_override="multi_stage_attack",
    )


# ---------------------------------------------------------
# BRUTE-FORCE ATTACK (auth-heavy, gives failed_login signal)
# ---------------------------------------------------------

def generate_brute_force(start, host, run_id, window_id):
    events = []
    label = 1
    scenario = "brute_force_attack"
    phase = "ACCESS"

    events.append(
        process_event(
            start + timedelta(seconds=2),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "svchost.exe",
            "explorer.exe",
            2,
            phase,
        )
    )

    # 4-6 failed logins + 1 success (breach)
    for i in range(random.randint(4, 6)):
        events.append(
            auth_event(
                start + timedelta(seconds=3 + i * 3),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "FAILURE",
                phase,
            )
        )

    events.append(
        auth_event(
            start + timedelta(seconds=24),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "SUCCESS",
            phase,
        )
    )

    for _ in range(random.randint(1, 3)):
        events.append(
            network_event(
                start + timedelta(seconds=random.randint(5, 28)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "svchost.exe",
                random.randint(2, 6),
                phase,
            )
        )

    return events


# ---------------------------------------------------------
# C2-HEAVY ATTACK (network-heavy, gives network signal)
# ---------------------------------------------------------

def generate_c2_heavy(start, host, run_id, window_id):
    events = []
    label = 1
    scenario = "c2_heavy_attack"
    phase = "C2"

    events.append(
        process_event(
            start + timedelta(seconds=2),
            host,
            run_id,
            window_id,
            scenario,
            label,
            "svchelper.exe",
            "powershell.exe",
            4,
            phase,
        )
    )

    # 8-12 beacon connections across distinct ports
    for _ in range(random.randint(8, 12)):
        ts = start + timedelta(seconds=random.randint(1, 29))
        # Use network_event then override port for diversity
        ev = network_event(
            ts,
            host,
            run_id,
            window_id,
            scenario,
            label,
            "svchelper.exe",
            random.randint(8, 12),
            phase,
        )
        ev["destination_port"] = random.choice([443, 80, 53, 8080, 8443])
        ev["destination_ip"] = random.choice([
            "192.0.2.10",
            "198.51.100.20",
            "203.0.113.30",
            "198.51.100.99",
        ])
        events.append(ev)

    for _ in range(random.randint(1, 3)):
        events.append(
            file_event(
                start + timedelta(seconds=random.randint(5, 29)),
                host,
                run_id,
                window_id,
                scenario,
                label,
                "create",
                "txt",
                phase,
            )
        )

    return events


def generate_run(scenario, run_number):
    host_id = f"WIN-ARGUS-{run_number:03d}"
    run_id = f"{scenario.upper()}-{run_number:04d}"

    start = datetime(2026, 9, 29, 10, 0, 0) + timedelta(
        minutes=run_number
    )

    all_events = []

    for window_id in range(6):
        window_start = start + timedelta(
            seconds=window_id * WINDOW_SECONDS
        )

        if scenario == "benign_normal":
            events = generate_benign_normal(
                window_start, host_id, run_id, window_id
            )

        elif scenario == "benign_high_entropy":
            events = generate_benign_high_entropy(
                window_start, host_id, run_id, window_id
            )

        elif scenario == "powershell_attack":
            events = generate_powershell(
                window_start, host_id, run_id, window_id
            )

        elif scenario == "persistence_attack":
            events = generate_persistence(
                window_start, host_id, run_id, window_id
            )

        elif scenario == "ransomware_like":
            events = generate_ransomware(
                window_start, host_id, run_id, window_id
            )

        elif scenario == "multi_stage_attack":
            events = generate_multi_stage(
                window_start, host_id, run_id, window_id
            )

        elif scenario == "brute_force_attack":
            events = generate_brute_force(
                window_start, host_id, run_id, window_id
            )

        elif scenario == "c2_heavy_attack":
            events = generate_c2_heavy(
                window_start, host_id, run_id, window_id
            )

        else:
            events = []

        all_events.extend(events)

    return all_events


def main():
    combined_file = OUTPUT_DIR / "all_synthetic_telemetry.jsonl"

    total_events = 0

    with combined_file.open("w", encoding="utf-8") as combined:

        for scenario in SCENARIOS:
            scenario_file = OUTPUT_DIR / f"{scenario}.jsonl"

            with scenario_file.open("w", encoding="utf-8") as f:
                for run_number in range(1, RUNS_PER_SCENARIO + 1):
                    events = generate_run(
                        scenario,
                        run_number
                    )

                    for event in events:
                        line = json.dumps(event)

                        f.write(line + "\n")
                        combined.write(line + "\n")

                        total_events += 1

    print("=" * 60)
    print("ARGUS SYNTHETIC TELEMETRY GENERATOR")
    print("=" * 60)
    print(f"Scenarios              : {len(SCENARIOS)}")
    print(f"Runs per scenario     : {RUNS_PER_SCENARIO}")
    print(f"Window size            : {WINDOW_SECONDS} seconds")
    print(f"Total events           : {total_events}")
    print(f"Output directory       : {OUTPUT_DIR}")
    print()
    print("Generated files:")

    for scenario in SCENARIOS:
        print(f"  - {scenario}.jsonl")

    print("  - all_synthetic_telemetry.jsonl")
    print("=" * 60)


if __name__ == "__main__":
    main()