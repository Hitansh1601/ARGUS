"""features_v2: one shared schema for CIC-MalMem-2022 snapshots + ARGUS windows.

Honest scope: the two sources share almost no sensors (memory-forensics
counters vs 30-s endpoint behaviors). v2 therefore defines the small set of
primitives measurable in BOTH, with explicit per-source extractor rules, and
documents everything else as a gap. The point of v2 is to make the
unification claim *testable* (see src/validate_unified.py) — not to pretend
post-hoc column renaming unifies the domains.

Shared primitives (v2.0):
  process_count   int    # processes observed (CIC pslist.nproc / ARGUS process_count)
  hidden_artifact 0/1    # stealth indicator:
                         #   CIC: psxview hidden sum > 0 OR malfind injections > 0
                         #        OR ldrmodules not_in_mem > 0
                         #   ARGUS: suspicious_parent_child_count > 0
                         #        OR process_tree_depth >= 4
  label           0/1    # 0 benign, 1 malicious (same rule both sides)
  source          str    # 'cic' | 'argus' (for per-source breakdowns)

Known gaps (measurable one side only, NOT in v2 — common sensor needed):
  file/entropy velocity, registry Run persistence, auth pressure,
  network beaconing (ARGUS-only); malfind injections detail, hidden
  process-table entries, driver/service anomalies (CIC-only).
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
CIC_CACHE = BASE_DIR / "data" / "raw" / "MalMem2022.csv"
ARGUS_FEATURES = BASE_DIR / "data" / "processed" / "argus_features.csv"

V2_COLUMNS = ["process_count", "hidden_artifact", "label", "source"]

CIC_PSXVIEW_COLS = [c for c in [
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool", "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
] ]

CIC_LDR_COLS = ["ldrmodules.not_in_mem"]


def extract_cic(df: pd.DataFrame) -> pd.DataFrame:
    """Map a CIC-MalMem frame (raw 58-col) to v2. Requires pslist + label col."""
    label_col = next((c for c in df.columns if c.strip().lower() in ("class", "category", "label")), None)
    if label_col is None:
        raise ValueError("CIC frame has no Class/Category/label column")
    if "pslist.nproc" not in df.columns:
        raise ValueError("CIC frame missing pslist.nproc")
    out = pd.DataFrame({
        "process_count": pd.to_numeric(df["pslist.nproc"], errors="coerce").fillna(0).astype(int),
        "hidden_artifact": 0,
        "label": df[label_col].apply(lambda x: 0 if str(x).strip().lower().startswith("benign") else 1).astype(int),
        "source": "cic",
    })
    hidden = pd.Series(0, index=df.index)
    for c in CIC_PSXVIEW_COLS + CIC_LDR_COLS + ["malfind.ninjections", "malfind.uniqueInjections"]:
        if c in df.columns:
            hidden = hidden | (pd.to_numeric(df[c], errors="coerce").fillna(0) > 0)
    out["hidden_artifact"] = hidden.astype(int)
    return out[V2_COLUMNS]


def extract_argus(df: pd.DataFrame) -> pd.DataFrame:
    """Map an ARGUS window-features frame to v2."""
    need = {"process_count", "suspicious_parent_child_count",
            "process_tree_depth", "label"}
    missing = need - set(df.columns)
    if missing:
        raise ValueError(f"ARGUS frame missing {sorted(missing)}")
    num = df[list(need - {"label"})].apply(pd.to_numeric, errors="coerce").fillna(0)
    out = pd.DataFrame({
        "process_count": num["process_count"].astype(int),
        "hidden_artifact": ((num["suspicious_parent_child_count"] > 0)
                            | (num["process_tree_depth"] >= 4)).astype(int),
        "label": df["label"].astype(int),
        "source": "argus",
    })
    return out[V2_COLUMNS]


def load_cic_v2(sample: int = 0) -> pd.DataFrame:
    if not CIC_CACHE.exists():
        raise FileNotFoundError(
            f"Missing {CIC_CACHE}. Run: python src/validate_real.py (caches download).")
    df = pd.read_csv(CIC_CACHE, usecols=lambda c: c != "Filename", low_memory=True)
    if sample and len(df) > sample:
        df = df.sample(sample, random_state=42).reset_index(drop=True)
    return extract_cic(df)


def load_argus_v2() -> pd.DataFrame:
    if not ARGUS_FEATURES.exists():
        raise FileNotFoundError(f"Missing {ARGUS_FEATURES}. Run src/feature_engineering.py first.")
    return extract_argus(pd.read_csv(ARGUS_FEATURES))


def describe_gaps() -> dict:
    return {
        "shared_primitives": ["process_count", "hidden_artifact"],
        "argus_only": ["file_write_velocity", "entropy_delta_mean",
                       "persistence_key_count", "failed_login_count",
                       "network_connection_count"],
        "cic_only": ["malfind.ninjections", "psxview.not_in_pslist",
                     "svcscan.kernel_drivers", "ldrmodules.not_in_mem"],
        "note": ("Unification beyond these two primitives needs a common "
                 "sensor (EDR telemetry on both sides), not post-hoc mapping."),
    }
