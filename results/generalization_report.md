# ARGUS generalization report

Standard group split: AUC=1.0000, P=1.0000 R=1.0000 F1=1.0000 @0.5 (train=1620, test=540)
Best threshold by F1: 0.05 (P=1.0000 R=1.0000 F1=1.0000)
Best threshold by Youden J: 0.05 (J=1.0000)

## Leave-one-attack-out (test = held-out attack + 30% benign holdout)

| held-out | AUC | P@0.5 | R@0.5 | F1@0.5 | bestF1 | bestThr | n_test |
|---|---|---|---|---|---|---|---|
| powershell_attack | 0.8103 | 0.0000 | 0.0000 | 0.0000 | 0.6656 | 0.01 | 668 |
| persistence_attack | 1.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.01 | 668 |
| ransomware_like | 0.2641 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.01 | 668 |
| multi_stage_attack | 1.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.01 | 308 |

> Conclusion: standard split is perfect but LOSO fails even at the best
> threshold. Each attack uses disjoint indicators, so the model cannot
> transfer. Next fix: shared behavioral features + anomaly head.


## Benign FPR (standard test set)

- benign_normal (n=130): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=102): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=232): fpr@0.05=0.0000, fpr@0.5=0.0000

## Benign FPR inside each LOSO test set

### held-out=powershell_attack
- benign_normal (n=140): fpr@0.05=0.0071, fpr@0.5=0.0071
- benign_high_entropy (n=108): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=248): fpr@0.05=0.0040, fpr@0.5=0.0040
### held-out=persistence_attack
- benign_normal (n=140): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=108): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=248): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=ransomware_like
- benign_normal (n=140): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=108): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=248): fpr@0.05=0.0000, fpr@0.5=0.0000
### held-out=multi_stage_attack
- benign_normal (n=140): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_high_entropy (n=108): fpr@0.05=0.0000, fpr@0.5=0.0000
- benign_all (n=248): fpr@0.05=0.0000, fpr@0.5=0.0000
