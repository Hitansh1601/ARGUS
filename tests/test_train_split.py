"""Group-aware split: same run never in train+test."""
import sys
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from sklearn.model_selection import GroupShuffleSplit


def test_group_split_no_leakage():
    csv = BASE_DIR / "data" / "processed" / "argus_features.csv"
    df = pd.read_csv(csv)
    X = df.drop(columns=["label", "scenario", "dominant_phase",
                         "run_id", "host_id", "window_id"], errors="ignore")
    y = df["label"]
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    tr, te = next(splitter.split(X, y, groups=df["run_id"]))
    assert set(df.iloc[tr]["run_id"]).isdisjoint(set(df.iloc[te]["run_id"]))
    assert len(tr) + len(te) == len(df)
