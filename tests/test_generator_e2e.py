"""Full-regen e2e: runs generator.main() (slow, ~50M I/O)."""
import json
import sys
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

OUTPUT_DIR = BASE_DIR / "data" / "raw" / "synthetic"


@pytest.mark.e2e
def test_full_regeneration():
    from simulator.generator import SCENARIOS, main
    main()
    assert (OUTPUT_DIR / "all_synthetic_telemetry.jsonl").exists()
    total = 0
    for sc in SCENARIOS:
        p = OUTPUT_DIR / f"{sc}.jsonl"
        assert p.exists(), f"missing {sc}.jsonl"
        n = sum(1 for _ in p.open())
        assert n > 0, f"{sc} empty"
        total += n
    combined = sum(1 for _ in (OUTPUT_DIR / "all_synthetic_telemetry.jsonl").open())
    assert combined == total


@pytest.mark.e2e
def test_multi_stage_no_leakage_after_regen():
    # Window-5 of multi_stage must NOT be labeled ransomware_like.
    from collections import Counter
    path = OUTPUT_DIR / "multi_stage_attack.jsonl"
    if not path.exists():
        pytest.skip("run test_full_regeneration first")
    c = Counter()
    for line in path.open():
        e = json.loads(line)
        if e["window_id"] == 5:
            c[e["scenario"]] += 1
    assert c.get("ransomware_like", 0) == 0, f"leakage: {c}"
    assert c.get("multi_stage_attack", 0) > 0
