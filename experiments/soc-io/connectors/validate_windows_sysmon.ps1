param(
    [switch]$RunBenignProcessTest
)

$ErrorActionPreference = "Stop"
$channel = "Microsoft-Windows-Sysmon/Operational"

if (-not $RunBenignProcessTest) {
    throw "Explicit opt-in required. Re-run with -RunBenignProcessTest on a dedicated test host."
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw "Python was not found on PATH."
}

$log = Get-WinEvent -ListLog $channel -ErrorAction Stop
if (-not $log.IsEnabled) {
    throw "The Sysmon Operational channel is disabled."
}
if ($log.RecordCount -lt 1) {
    Write-Warning "Sysmon channel has no retained records; a successful collection cannot be assumed."
}

Write-Host "Generating a benign, short-lived PowerShell process for Sysmon Event ID 1 validation..."
$marker = "SOCIO_SYSMON_VALIDATION"
$command = "Write-Output '$marker'; Start-Sleep -Seconds 1"
$childPowerShell = Join-Path $PSHOME "powershell.exe"
if (-not (Test-Path $childPowerShell)) {
    $childPowerShell = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
}
if (-not $childPowerShell -or -not (Test-Path $childPowerShell)) {
    throw "Could not locate a PowerShell executable to generate the benign test event."
}
& $childPowerShell -NoProfile -Command $command | Out-Null
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    throw "Benign child PowerShell process exited with code $LASTEXITCODE."
}

$connector = Join-Path $PSScriptRoot "windows_sysmon.py"
$output = Join-Path $env:TEMP ("soc-io-sysmon-validation-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff") + ".jsonl")
& $python.Source $connector --enable-local-read-only --since-minutes 5 --max-events 5000 --output $output
if ($LASTEXITCODE -ne 0) {
    throw "SOC-IO connector failed with exit code $LASTEXITCODE. See its error output."
}

$rows = @()
foreach ($line in Get-Content -LiteralPath $output) {
    if (-not [string]::IsNullOrWhiteSpace($line)) {
        $rows += $line | ConvertFrom-Json
    }
}
$match = $rows | Where-Object {
    $_.source -eq "windows-sysmon" -and
    $_.event_type -eq "process_start" -and
    $_.command_line -like "*$marker*"
} | Select-Object -First 1

if (-not $match) {
    Write-Host "Connector output: $output"
    throw "No matching Sysmon process-start event was found. Check Sysmon config, event ID 1 collection, permissions, and clock/window."
}

$result = [ordered]@{
    result = "PASS"
    connector = "windows-sysmon"
    host = $match.host
    source_event_id = $match.event_id
    event_time_utc = $match.timestamp
    output_path = $output
    rows_collected = $rows.Count
    matched_benign_test_event = $true
    network_access_by_connector = $false
    response_actions = $false
}
$result | ConvertTo-Json -Depth 4
Write-Host "Validation evidence saved to: $output"
