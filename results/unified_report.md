# Unified v2 validation (Batch D)

Shared primitives: process_count, hidden_artifact. Rows: argus=3240, cic=20000 (sample=20000).

| protocol | n_test | P | R | F1 | AUC |
|---|---|---|---|---|---|
| A argus-only | 810 | 0.8310 | 1.0000 | 0.9077 | 0.8278 |
| B cic-only | 5000 | 0.8431 | 0.4007 | 0.5432 | 0.6994 |
| C joint->joint | 5810 | 0.8330 | 0.5137 | 0.6355 | 0.7418 |
| D cross cic->argus | 810 | 0.7407 | 1.0000 | 0.8511 | 0.5000 |
| D cross argus->cic | 5000 | 0.5016 | 1.0000 | 0.6681 | 0.5000 |
| C joint->argus-slice | 810 | 0.8310 | 1.0000 | 0.9077 | 0.8278 |
| C joint->cic-slice | 5000 | 0.8437 | 0.4003 | 0.5430 | 0.7019 |

> v2 does not unify the domains: cross-source ranking is chance (D cross cic->argus F1=0.851/AUC=0.500, D cross argus->cic F1=0.668/AUC=0.500; worst AUC=0.500). The high cross F1 is a base-rate illusion -- both cross models predict all-positive (recall 1.0, precision = base rate). The two shared primitives carry within-source signal (argus-only AUC 0.82) but no transferable semantics. A common sensor is required; post-hoc mapping cannot create it.

Gaps (one side only):
- argus-only: file_write_velocity, entropy_delta_mean, persistence_key_count, failed_login_count, network_connection_count
- cic-only: malfind.ninjections, psxview.not_in_pslist, svcscan.kernel_drivers, ldrmodules.not_in_mem
