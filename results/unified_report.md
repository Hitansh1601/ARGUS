# Unified v2 validation (Batch D)

Shared primitives: process_count, hidden_artifact. Rows: argus=2880, cic=20000 (sample=20000).

| protocol | n_test | P | R | F1 | AUC |
|---|---|---|---|---|---|
| A argus-only | 720 | 0.8070 | 1.0000 | 0.8932 | 0.8244 |
| B cic-only | 5000 | 0.8431 | 0.4007 | 0.5432 | 0.6994 |
| C joint->joint | 5720 | 0.8217 | 0.4995 | 0.6213 | 0.7350 |
| D cross cic->argus | 720 | 0.7083 | 1.0000 | 0.8293 | 0.5000 |
| D cross argus->cic | 5000 | 0.5016 | 1.0000 | 0.6681 | 0.5000 |
| C joint->argus-slice | 720 | 0.8070 | 1.0000 | 0.8932 | 0.8244 |
| C joint->cic-slice | 5000 | 0.8404 | 0.4011 | 0.5430 | 0.7038 |

> v2 does not unify the domains: cross-source ranking is chance (D cross cic->argus F1=0.829/AUC=0.500, D cross argus->cic F1=0.668/AUC=0.500; worst AUC=0.500). The high cross F1 is a base-rate illusion — both cross models predict all-positive (recall 1.0, precision = base rate). The two shared primitives carry within-source signal (argus-only AUC 0.82) but no transferable semantics. A common sensor is required; post-hoc mapping cannot create it.

Gaps (one side only):
- argus-only: file_write_velocity, entropy_delta_mean, persistence_key_count, failed_login_count, network_connection_count
- cic-only: malfind.ninjections, psxview.not_in_pslist, svcscan.kernel_drivers, ldrmodules.not_in_mem
