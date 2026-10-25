"""Fast unit tests for simulator/generator.py (no full regen)."""
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from simulator.generator import (
    SCENARIOS,
    file_event,
    generate_brute_force,
    generate_c2_heavy,
    generate_multi_stage,
    generate_ransomware,
    make_event,
)


def _ts():
    return datetime(2026, 9, 29, 10, 0, 0)


def test_make_event_schema():
    e = make_event(_ts(), "WIN-ARGUS-001", "X-0001", 0,
                   "process_create", 0, "benign_normal")
    for k in ["event_id", "timestamp", "host_id", "run_id", "window_id",
              "event_type", "process_name", "file_path", "entropy_delta",
              "registry_key", "destination_ip", "label", "scenario",
              "attack_phase"]:
        assert k in e


def test_file_event_entropy():
    low = file_event(_ts(), "h", "r", 0, "benign_normal", 0,
                     "write", "txt", high_entropy=False)
    high = file_event(_ts(), "h", "r", 0, "ransomware_like", 1,
                      "write", "enc", high_entropy=True)
    assert low["entropy_delta"] < 0.5
    assert high["entropy_delta"] > 0.5


def test_ransomware_override():
    evs = generate_ransomware(_ts(), "h", "r", 5,
                              scenario_override="multi_stage_attack")
    assert all(e["scenario"] == "multi_stage_attack" for e in evs)
    evs2 = generate_ransomware(_ts(), "h", "r", 5)
    assert all(e["scenario"] == "ransomware_like" for e in evs2)


def test_multi_stage_window5_keeps_scenario():
    evs = generate_multi_stage(_ts(), "h", "r", 5)
    assert len(evs) > 50
    assert all(e["scenario"] == "multi_stage_attack" for e in evs)
    assert all(e["label"] == 1 for e in evs)


def test_multi_stage_windows_dispatch():
    assert all(e["label"] == 0 for e in generate_multi_stage(_ts(), "h", "r", 0))
    assert all(e["label"] == 0 for e in generate_multi_stage(_ts(), "h", "r", 1))
    w2 = generate_multi_stage(_ts(), "h", "r", 2)
    assert any(e["process_name"] == "powershell.exe" for e in w2)
    w4 = generate_multi_stage(_ts(), "h", "r", 4)
    assert w4[0]["scenario"] == "multi_stage_attack"


def test_brute_force_has_failures():
    evs = generate_brute_force(_ts(), "h", "r", 0)
    fails = [e for e in evs if e["auth_result"] == "FAILURE"]
    succ = [e for e in evs if e["auth_result"] == "SUCCESS"]
    assert len(fails) >= 4
    assert len(succ) == 1
    assert all(e["scenario"] == "brute_force_attack" for e in evs)


def test_c2_heavy_network_volume():
    evs = generate_c2_heavy(_ts(), "h", "r", 0)
    nets = [e for e in evs if e["event_type"] == "network_connection"]
    assert 8 <= len(nets) <= 12
    assert len({n["destination_port"] for n in nets}) >= 2


def test_scenarios_include_new():
    assert "brute_force_attack" in SCENARIOS
    assert "c2_heavy_attack" in SCENARIOS
    assert len(SCENARIOS) == 8
