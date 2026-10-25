# ARGUS Windows tasks (PowerShell). Primary entrypoint on Windows 10+.
# Usage: .\tasks.ps1 data | .\tasks.ps1 features | .\tasks.ps1 train | .\tasks.ps1 alert
#        .\tasks.ps1 test-fast | .\tasks.ps1 demo | .\tasks.ps1 dashboard
param(
  [Parameter(Position=0)]
  [ValidateSet('install','data','features','train','train-fast','alert','demo','dashboard','eval','validate','baseline','test','test-fast','test-e2e','review','clean')]
  [string]$Task = 'test-fast'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# Ensure console can render alert output on legacy cmd (chcp 65001 equivalent)
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
  'demo'       { Invoke-Py @('demo/malicious_similar_demo.py') }
  'dashboard'  { Invoke-Py @('src/dashboard.py') }
  'eval'       { Invoke-Py @('src/evaluate_generalization.py') }
  'validate'   { Invoke-Py @('src/validate_real.py','--sample','20000') }
  'baseline'   { Invoke-Py @('argus_baseline.py') }
  'test'       { Invoke-Py @('-m','pytest','-v') }
  'test-fast'  { Invoke-Py @('-m','pytest','-m','not e2e','-v') }
  'test-e2e'   { Invoke-Py @('-m','pytest','-m','e2e','-v') }
  'review'     { Invoke-Py @('-m','pytest','-m','not e2e','-q'); Invoke-Py @('demo/malicious_similar_demo.py'); Invoke-Py @('src/dashboard.py') }
  'clean'      { Invoke-Py @('-c','import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path(''.'').rglob(''__pycache__'')]; list(map(lambda p: p.unlink(missing_ok=True), pathlib.Path(''.'').rglob(''*.pyc'')))') }
}
