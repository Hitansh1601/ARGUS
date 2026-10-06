# Real-data validation (Task 4): CIC-MalMem-2022 vs synthetic ARGUS

Real rows=58596, features=55, label=Class.
Real: P=0.9998 R=1.0000 F1=0.9999 AUC=1.0000 (TN=5859 FP=1 FN=0 TP=5860)

Synthetic (standard split): AUC=1.0000, F1@0.5=1.0000 (see generalization_report.md for LOSO collapse).

## Why no direct transfer

- CIC features (55): memory-forensics counters (`pslist.*`, `dlllist.*`, `handles.*`, …).
- ARGUS features (30): windowed behaviors (`powershell_count`, `file_write_velocity`, `entropy_delta_mean`, …).
- Shared column names: none.
- Same label semantics (Benign vs rest) but different sensors, different time granularity, different adversaries.

## What is needed for a unified claim

1. `features_v2` schema with shared primitives present in both sources.
2. Joint training (or domain adaptation) + LOSO-across-datasets eval.
3. Persist the tuned threshold; 0.5 is uncalibrated across domains.

Plots: `results/real_confusion_matrix.png`, `results/real_roc_curve.png`.
Numbers: `results/real_validation_report.json`.
