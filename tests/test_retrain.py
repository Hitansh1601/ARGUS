"""Retrain-loop tests: feedback merge + golden metric gate (fast, no training)."""
import json

import pandas as pd

from train_model import check_gate, merge_feedback


def _df():
    return pd.DataFrame([
        {"run_id": "R1", "window_id": 0, "label": 0},
        {"run_id": "R1", "window_id": 1, "label": 0},
        {"run_id": "R2", "window_id": 0, "label": 1},
    ])


def _fb(rows):
    return pd.DataFrame(rows, columns=["run_id", "window_id", "analyst_label"])


def test_merge_overrides_and_counts_flips():
    out, info = merge_feedback(_df(), _fb([
        {"run_id": "R1", "window_id": 1, "analyst_label": 1},  # benign -> mal
        {"run_id": "R2", "window_id": 0, "analyst_label": 1},  # no change
        {"run_id": "RX", "window_id": 9, "analyst_label": 1},  # unknown
    ]))
    assert out["label"].tolist() == [0, 1, 1]
    assert info == {"overridden": 2, "missing": 1, "flipped": 1}


def test_merge_empty_feedback_noop():
    out, info = merge_feedback(_df(), _fb([]))
    assert out["label"].tolist() == [0, 0, 1]
    assert info["overridden"] == 0 and info["missing"] == 0


def test_gate_passes_and_missing_golden_passes(tmp_path):
    good = {"precision": 1.0, "recall": 1.0, "f1": 1.0, "roc_auc": 1.0}
    g = tmp_path / "golden.json"
    g.write_text(json.dumps(good), encoding="utf-8")
    assert check_gate(good, golden_path=g) == []
    assert check_gate(good, golden_path=tmp_path / "absent.json") == []


def test_gate_fails_degraded(tmp_path):
    g = tmp_path / "golden.json"
    g.write_text(json.dumps({"precision": 1.0, "recall": 1.0,
                             "f1": 1.0, "roc_auc": 1.0}), encoding="utf-8")
    bad = {"precision": 0.5, "recall": 1.0, "f1": 0.67, "roc_auc": 0.9}
    failed = check_gate(bad, golden_path=g)
    assert "precision" in failed and "f1" in failed
    assert "recall" not in failed
