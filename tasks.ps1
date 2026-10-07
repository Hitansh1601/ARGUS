# ARGUS Windows tasks (PowerShell). Primary entrypoint on Windows 10+.
# Usage: .\tasks.ps1 data | .\tasks.ps1 features | .\tasks.ps1 train | .\tasks.ps1 alert
#        .\tasks.ps1 test-fast | .\tasks.ps1 test-e2e | .\tasks.ps1 guard
param(
  [Parameter(Position=0)]
  [ValidateSet('install','data','features','train','train-fast','alert','baseline','test','test-fast','test-e2e','clean','guard','retrain','export-feedback','label-feedback','install-task','remove-task')]
  [string]$Task = 'test-fast'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# Ensure console can render alert box on legacy cmd (chcp 65001 equivalent)
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

function Invoke-Py($Args) {
  python @Args
  if ($LASTEXITCODE -ne 0) { throw "python $($Args -join ' ') failed with $LASTEXITCODE" }
}

switch ($Task) {
  'install'    { Invoke-Py @('-m','pip','install','-r','requirements.txt') }
  'data'       { Invoke-Py @('simulator/generator.py') }
  'features'   { Invoke-Py @('src/feature_engineering.py') }
  'train'      { Invoke-Py @('src/train_model.py') }
  'train-fast' { Invoke-Py @('src/train_model.py','--no-plots') }
  'alert'      { Invoke-Py @('-m','src.argus_alert','--scenario','ransomware_like') }
  'baseline'   { Invoke-Py @('argus_baseline.py') }
  'test'       { Invoke-Py @('-m','pytest','-v') }
  'test-fast'  { Invoke-Py @('-m','pytest','-m','not e2e','-v') }
  'test-e2e'   { Invoke-Py @('-m','pytest','-m','e2e','-v') }
  'guard'      { Invoke-Py @('-m','src.guard','--once') }
  'retrain'    { Invoke-Py @('src/retrain.py') }
  'export-feedback' { Invoke-Py @('src/export_feedback.py') }
  'label-feedback' { Invoke-Py @('src/label_feedback.py','results/feedback_review.csv') }
  'install-task' {
    $Script = Join-Path $Root 'scripts\nightly_retrain.ps1'
    # Try admin-level first (sees HKLM Run), fall back to user-level
    schtasks /Create /TN 'ARGUS-Nightly-Retrain' /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script" /SC DAILY /ST 02:00 /RL HIGHEST /F
    if ($LASTEXITCODE -ne 0) {
      Write-Output "Admin install failed, trying user-level task..."
      schtasks /Create /TN 'ARGUS-Nightly-Retrain' /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script" /SC DAILY /ST 02:00 /F
      if ($LASTEXITCODE -ne 0) { throw "schtasks create failed." }
      Write-Output "Task installed (user-level, no HKLM). Re-run as Admin for full coverage."
    } else {
      Write-Output "Task ARGUS-Nightly-Retrain installed (02:00 daily, HIGHEST)."
    }
  }
  'remove-task' {
    schtasks /Delete /TN 'ARGUS-Nightly-Retrain' /F
  }
}
