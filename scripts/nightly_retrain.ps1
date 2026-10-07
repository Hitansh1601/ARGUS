# ARGUS nightly retrain wrapper. Called by Task Scheduler at 02:00 daily.
# Does: export feedback for review -> run retrain.py -> prune old models/logs.
param(
  [string]$LabelCsv = ""
)
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Root -or -not (Test-Path "$Root\src\retrain.py")) {
  $Root = "C:\Users\piyus\Desktop\ARGUS-PR1"
}
Set-Location $Root
$Py = "C:\Users\piyus\AppData\Local\Programs\Python\Python311\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$Results = Join-Path $Root "results"
New-Item -ItemType Directory -Force -Path $Results | Out-Null
$Log = Join-Path $Results "retrain-$ts.log"

function Log($m) {
  $line = "$(Get-Date -Format o) $m"
  $line | Tee-Object -FilePath $Log -Append | Write-Output
}

Log "=== ARGUS nightly retrain start ==="
Log "Root=$Root Py=$Py"

# 1. Export unlabeled feedback for manual labeling
try {
  & $Py src/export_feedback.py 2>&1 | ForEach-Object { Log $_ }
} catch { Log "export_feedback failed: $_" }

# 2. Retrain (auto-picks labeled rows in feedback.db; optional CSV)
try {
  if ($LabelCsv -ne "" -and (Test-Path $LabelCsv)) {
    Log "Using label CSV: $LabelCsv"
    & $Py src/retrain.py --label-feedback "$LabelCsv" 2>&1 | ForEach-Object { Log $_ }
  } else {
    & $Py src/retrain.py 2>&1 | ForEach-Object { Log $_ }
  }
  Log "retrain exit=$LASTEXITCODE"
} catch { Log "retrain failed: $_" }

# 3. Prune: keep last 7 versioned models + last 14 logs
try {
  Get-ChildItem "$Root\models\argus_xgboost.*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 7 |
    ForEach-Object { Remove-Item $_.FullName -Force; Log "pruned model $($_.Name)" }
  Get-ChildItem "$Results\retrain-*.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 14 |
    ForEach-Object { Remove-Item $_.FullName -Force; Log "pruned log $($_.Name)" }
} catch { Log "prune failed: $_" }

Log "=== done ==="
