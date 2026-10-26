# ARGUS generalization report

Standard group split: AUC=1.0000, P=1.0000 R=1.0000 F1=1.0000 @0.5 (train=2430, test=810)
Best threshold by F1: 0.05 (P=1.0000 R=1.0000 F1=1.0000)
Best threshold by Youden J: 0.05 (J=1.0000)

## Leave-one-attack-out (test = held-out attack + 30% benign holdout)

| held-out | AUC | P@0.5 | R@0.5 | F1@0.5 | bestF1 | bestThr | n_test |
|---|---|---|---|---|---|---|---|
| powershell_attack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.03 | 576 |
| persistence_attack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.03 | 576 |
| ransomware_like | 1.0000 | 1.0000 | 0.9833 | 0.9916 | 1.0000 | 0.03 | 576 |
| multi_stage_attack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.03 | 576 |
| brute_force_attack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.03 | 576 |
| c2_heavy_attack | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.03 | 576 |
| low_slow_exfil | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.03 | 576 |

> LOSO passes: every held-out attack is detected at the default 0.5 threshold (worst F1@0.5=0.9916). Scenario diversity (9 scenarios incl. auth-heavy, C2 and quiet low-and-slow attacks) forced the model onto shared behavioral features instead of disjoint indicators. Keep the LOSO gate in CI to catch regressions.


## Benign FPR (standard test set)

- benign_normal (n=120): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=84): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=204): fpr@0.05=0.0000, fpr@0.5=0.0000

## Benign FPR inside each LOSO test set

### held-out=powershell_attack
- benign_normal (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=114): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=216): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=persistence_attack
- benign_normal (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=114): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=216): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=ransomware_like
- benign_normal (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=114): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=216): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=multi_stage_attack
- benign_normal (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=114): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=216): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=brute_force_attack
- benign_normal (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=114): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=216): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=c2_heavy_attack
- benign_normal (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=114): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=216): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=low_slow_exfil
- benign_normal (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=114): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=216): fpr@0.05=0.0000, fpr@0.5=0.0000
