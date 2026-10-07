# ARGUS — Before / Done / Next

Branch `argus-improvements`, Windows 10+ only, admin assumed.
Model: P 0.998 / R 1.0 / F1 0.999 / AUC 1.0 · 39/39 tests green (36 fast + 3 e2e).

## BEFORE (upstream PR#1 @ d721425)

Synthetic EDR simulator → 30 features → XGBoost → risk engine → alert, plus baseline.
Review found:

- **Bugs:** entropy_mean averaged with zeros; network interval included first-packet 0;
  persistence match case-sensitive `Run` only; narrow PowerShell/parent lists;
  import-time `mkdir`s; Makefile assumed `python3`/`find`/`rm` (breaks Windows);
  CI on ubuntu; `numpy==2.5.2` pin needs Py3.12 (breaks Py3.11); alert box crashes
  on cp1252 consoles.
- **Detection gaps:** RunOnce/RunServices bypass; `pwsh.exe`/`powershell_ise`/full-path
  bypass; mshta/rundll32 etc. missed; risk weights double-count; low-and-slow evasion;
  `select_suspicious` velocity-only; model/file parsing DoS; remote CSV, no checksum;
  generated telemetry + models committed (55 MB push warnings).

## DONE (this branch, 4 commits)

**`8a19798` — Windows-only guard + self-learn foundation**
- `src/collector_windows.py`: live snapshot via psutil/winreg/win32evtlog.
- `src/guard.py`: score → kill / quarantine (hash-named) / Run-value removal with
  allowlist; every destructive op backs up first (`feedback.db` + `.reg`).
  Dry-run default, `--enforce` to act. Covers HKCU+HKLM Run/RunOnce.
- `src/retrain.py` + `src/export_feedback.py` + `src/label_feedback.py`:
  nightly retrain with metric gate, prune (7 models / 14 logs), CSV labeling loop.
- `tasks.ps1` (+ fixed Makefile): data/features/train/test/install-task/
  remove-task/export-feedback/label-feedback. CI → windows-latest, Py3.11.
- Fixes: basename LOLBin/parent matching, case-insensitive Run incl. RunOnce,
  file-only entropy, high-entropy-writes-only, network avg excludes zeros,
  unicode/ascii alert fallback, `requirements.txt` relaxed (+psutil/pywin32).
- Real catches on this box: dormant `Windows Updates Service.vbe` persistence
  (surgically removed, verified) + uTorrent (left alone).

**`dbb1afb` — self-learn loop closed + ETW sources**
- Guard persists live windows → `data/live/live_features.csv` (deduped);
  retrain merges labeled live rows (`load_labeled_live`).
- Collector: Sysmon Operational (1/3/13) + Security 4688 readers, best-effort capped.
- 3 new tests (ETW graceful, live dedup, labeled merge).

**`3bc56fa` — ETW enablement + repo hygiene**
- `scripts/sysmon-argus.xml` (validated minimal config) +
  `scripts/enable-auditing.ps1` (4688 + cmdline; needs admin — enabled ✅).
- Untracked generated telemetry/plots (kept features CSV + model: CI fast needs them).
- Nightly task re-registered as **SYSTEM /RL HIGHEST**, daily 02:00 —
  first privileged cycle exit 0, HKLM coverage confirmed.

**`9195dda` — speed + live-fire showcase**
- Generator `--runs/--workers` (deterministic seeds; serial default bit-compatible);
  training uses all CPU threads. Measured: 372k-event gen parallelized,
  14.4k-window train 0.24s CPU vs 0.31s RTX 2070S — CPU wins below ~1M rows.
- `scripts/showcase.ps1` (+`showcase_cleanup.py`): 5-phase contained attack demo —
  stage → CRITICAL 99.9% alert → surgical removal → verify → queue for learning.

## NEXT

1. **Labels:** 4+ rows waiting in `results/feedback_review.csv` (incl. 1 CRITICAL live
   row — rec: benign dev-box FP) → label, tonight's run trains on them.
2. **Sysmon install:** `sysmon64.exe -accepteula -i scripts\sysmon-argus.xml`
   (needs the binary + admin) to light up the Sysmon collector branch.
3. **Scale story:** push past 1M windows to show GPU crossover (disk/time heavy —
   on demand only).
4. **PR merge:** squash or keep 4-commit history into upstream PR#1 when ready.
