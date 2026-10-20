# ARGUS live-fire showcase. Stages a contained fake attack in %TEMP%\argus-demo,
# detects it (dry-run guard), surgically removes ONLY demo artifacts, verifies.
# Safe: nothing outside the demo dir + one HKCU Run value (backed up) is touched.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\showcase.ps1 [-NoPause]
param([switch]$NoPause)
$ErrorActionPreference = 'Stop'
$Py = "C:\Users\piyus\AppData\Local\Programs\Python\Python311\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
$demo = Join-Path $env:TEMP "argus-demo"

function Phase($t) {
  Write-Host ""
  Write-Host "=== $t ===" -ForegroundColor Cyan
  if (-not $NoPause) { Read-Host "Press Enter to continue" | Out-Null }
}

# --- PHASE 1: stage the attack ---
Phase "PHASE 1/5 - staging contained attack in $demo"
# clean stale sleepers from aborted runs (only our demo marker)
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -match 'Start-Sleep -Seconds 240' } | ForEach-Object {
    Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction SilentlyContinue | Out-Null
  }
Remove-Item $demo -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $demo | Out-Null
# high-entropy 'encrypted' files + ransom note
$rng = New-Object Random
1..5 | ForEach-Object {
  $b = New-Object byte[] 4096; $rng.NextBytes($b)
  [IO.File]::WriteAllBytes("$demo\doc$_.locked", $b)
}
"ALL YOUR FILES ARE ENCRYPTED. Send 1 BTC. -ARGUS-DEMO (harmless)" | Out-File "$demo\READ_ME.txt"
"'demo persistence stub (harmless)" | Out-File "$demo\demo-persist.vbe"
# encoded powershell sleeper spawned from cmd (suspicious parent + -enc)
$cmd = "Start-Sleep -Seconds 240"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
$sleeper = Start-Process cmd.exe -ArgumentList "/c powershell -NoProfile -EncodedCommand $enc" -PassThru
# demo persistence (HKCU only, backed up by guard before removal)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS Demo" /t REG_SZ /d "$demo\demo-persist.vbe" /f | Out-Null
Write-Host "staged: 5x .locked + ransom note + -enc sleeper (PID $($sleeper.Id)) + HKCU Run value"

# --- PHASE 2: detect ---
Phase "PHASE 2/5 - guard live scan (dry-run: detects, touches nothing)"
& $Py src/guard.py --once --top-n 3

# --- PHASE 3: surgical enforce on demo artifacts only ---
Phase "PHASE 3/5 - surgical removal (demo artifacts ONLY)"
& $Py scripts/showcase_cleanup.py $demo 2>&1 | Select-Object -Last 10
try { Stop-Process -Id $sleeper.Id -Force -ErrorAction SilentlyContinue } catch {}
Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {
  try { $_.CommandLine -match 'Start-Sleep' } catch { $false }
} | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "sleeper processes killed"

# --- PHASE 4: verify ---
Phase "PHASE 4/5 - verify clean"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS Demo" 2>&1 | Select-Object -First 2
$left = Get-ChildItem $demo -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
Write-Host "files left in demo dir: $left"
Get-ChildItem quarantine | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host

# --- PHASE 5: queue for learning ---
Phase "PHASE 5/5 - queue detection for nightly learning"
& $Py src/export_feedback.py 2>&1 | Select-Object -First 4

Write-Host ""
Write-Host "SHOWCASE COMPLETE: staged -> detected -> removed -> verified -> queued." -ForegroundColor Green
