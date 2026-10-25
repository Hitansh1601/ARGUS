# Real-data validation (Task 4): CIC-MalMem-2022 vs synthetic ARGUS

Real rows=20000, features=55, label=Class.
Real: P=1.0000 R=0.9995 F1=0.9998 AUC=1.0000 (TN=1994 FP=0 FN=1 TP=2005)

Synthetic (standard split): AUC=1.0000, F1@0.5=0.9990 (see generalization_report.md for LOSO collapse).

## Why no direct transfer

- CIC features (55): memory-forensics counters (`pslist.*`, `dlllist.*`, `handles.*`, ...).
- ARGUS features (30): windowed behaviors (`powershell_count`, `file_write_velocity`, `entropy_delta_mean`, ...).
- Shared column names: none.
- Same label semantics (Benign vs rest) but different sensors, different time granularity, different adversaries.

## What is needed for a unified claim

1. `features_v2` schema with shared primitives present in both sources.
2. Joint training (or domain adaptation) + LOSO-across-datasets eval.
3. Persist the tuned threshold; 0.5 is uncalibrated across domains.

Plots: `results/real_confusion_matrix.png`, `results/real_roc_curve.png`.
Numbers: `results/real_validation_report.json`.
