param(
    [switch]$RunBenignProcessTest
)

$ErrorActionPreference = "Stop"
$channel = "Microsoft-Windows-Sysmon/Operational"
$marker = "SOCIO_SYSMON_VALIDATION"
$summaryPath = $env:SOCIO_VALIDATION_SUMMARY_PATH
if ([string]::IsNullOrWhiteSpace($summaryPath)) {
    $summaryPath = Join-Path $env:TEMP ("soc-io-sysmon-summary-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff") + ".json")
}

$summary = [ordered]@{
    result = "FAIL"
    connector = "windows-sysmon"
    validation = "benign-process-start"
    stage = "preflight"
    completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    rows_collected = 0
    matched_benign_test_event = $false
    network_access_by_connector = $false
    response_actions = $false
    raw_event_file_retained = $false
}

try {
    if (-not $RunBenignProcessTest) {
        throw "Explicit opt-in required."
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
        throw "The Sysmon channel has no retained records."
    }

    $summary.stage = "generate-benign-event"
    Write-Host "Generating a benign, short-lived PowerShell process for Sysmon Event ID 1 validation..."
    $command = "Write-Output '$marker'; Start-Sleep -Seconds 1"
    $childPowerShell = Join-Path $PSHOME "powershell.exe"
    if (-not (Test-Path $childPowerShell)) {
        $childPowerShell = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    }
    if (-not $childPowerShell -or -not (Test-Path $childPowerShell)) {
        throw "Could not locate a PowerShell executable."
    }
    & $childPowerShell -NoProfile -Command $command | Out-Null
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "Benign child PowerShell process failed."
    }

    $summary.stage = "collect-local-sysmon"
    $connector = Join-Path $PSScriptRoot "windows_sysmon.py"
    $rawOutput = Join-Path $env:TEMP ("soc-io-sysmon-validation-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff") + ".jsonl")
    & $python.Source $connector --enable-local-read-only --since-minutes 5 --max-events 5000 --output $rawOutput
    if ($LASTEXITCODE -ne 0) {
        throw "SOC-IO collector returned a non-zero exit code."
    }

    $rows = @()
    foreach ($line in Get-Content -LiteralPath $rawOutput) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $rows += $line | ConvertFrom-Json
        }
    }
    $summary.rows_collected = $rows.Count

    $summary.stage = "verify-benign-event"
    $match = $rows | Where-Object {
        $_.source -eq "windows-sysmon" -and
        $_.event_type -eq "process_start" -and
        $_.command_line -like "*$marker*"
    } | Select-Object -First 1

    if (-not $match) {
        throw "No matching Sysmon process-start event was found."
    }

    $summary.result = "PASS"
    $summary.stage = "complete"
    $summary.matched_benign_test_event = $true
    $sysmonDetails = $match.message | ConvertFrom-Json
    $summary.source_event_id = $sysmonDetails.sysmon_event_id
    $summary.event_time_utc = $match.timestamp
    $summary.rows_collected = $rows.Count
    Write-Host "The benign process-start marker was observed in normalized collector output."
    Write-Host "Raw event JSONL remains local and is not included in the sanitized summary."
}
catch {
    # Retain a short, non-sensitive stage and generic failure reason only.
    $summary.failure_category = switch ($summary.stage) {
        "preflight" { "preflight-or-opt-in-failed" }
        "generate-benign-event" { "benign-event-generation-failed" }
        "collect-local-sysmon" { "collector-failed" }
        "verify-benign-event" { "expected-event-not-observed" }
        default { "validation-failed" }
    }
    Write-Error $_.Exception.Message
    throw
}
finally {
    $summary.completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    $summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding utf8
    Write-Host "Sanitized validation summary written to the configured summary path."
}
