# Enable process-creation auditing for ARGUS 4688 collector. MUST run elevated.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\enable-auditing.ps1
$ErrorActionPreference = 'Stop'

Write-Output "[1/2] Enabling Detailed Tracking / Process Creation auditing..."
auditpol /set /subcategory:"Process Creation" /success:enable
if ($LASTEXITCODE -ne 0) { throw "auditpol failed. Re-run as Administrator." }

Write-Output "[2/2] Enabling command-line in 4688 events..."
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
if ($LASTEXITCODE -ne 0) { throw "reg add failed. Re-run as Administrator." }

Write-Output "Done. Verify: auditpol /get /category:'Detailed Tracking'"
