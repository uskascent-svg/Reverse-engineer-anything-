# Validate real Windows / Sysmon collection in a dedicated lab

**This procedure has not been run by GitHub Actions.** CI runs on Linux and cannot
prove Windows Event Log permissions, Sysmon configuration, or real event coverage.
Run it on a dedicated Windows test machine where you are authorized to inspect logs.
Do not use a production endpoint for first validation.

## Prerequisites

- Windows 10/11 or a Windows Server test VM.
- PowerShell and Python 3.11+ on PATH.
- Sysmon installed and configured with the
  `Microsoft-Windows-Sysmon/Operational` channel enabled.
- A Sysmon configuration that records process creation (Event ID 1).
- The repository checked out at `feature/soc-io-proposal`.
- Permission to read the Sysmon Operational event channel.

The connector only reads local events. It does not install/configure Sysmon, reach
remote endpoints, read credentials, upload logs, or perform response actions.

## Optional GitHub Actions lab job

The SOC-IO workflow also has a manual `run_windows_sysmon_lab` input. It requires a
self-hosted runner registered to this repository with labels
`self-hosted`, `Windows`, `X64`, and `soc-io-sysmon-lab`, already provisioned
with Sysmon and appropriate local event-log read permissions. Configure that runner
only on a dedicated lab host, then use Actions → SOC-IO prototype checks → Run workflow
and explicitly enable the Windows lab input. Without that runner, the job will not run.
It uploads only a sanitized JSON summary artifact with 14-day retention; raw event JSONL stays in the runner user's TEMP directory and is never uploaded.

## Run the validation

Open PowerShell in `experiments/soc-io/connectors`. Review the script before running.
The explicit switch generates a benign short-lived child PowerShell process, then
runs the collector with the explicit `--enable-local-read-only` flag.

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
  Select-Object LogName, IsEnabled, RecordCount

python --version
.\validate_windows_sysmon.ps1 -RunBenignProcessTest
```

The script writes a uniquely named JSONL evidence file under the current user's
temporary directory. It passes only if the collected normalized records include
the benign `SOCIO_SYSMON_VALIDATION` process-start marker. Retain the summary and
output file according to your lab evidence-retention policy; review for any sensitive
command lines before sharing.

## Acceptance criteria

Record the following for the test report:

- Windows version, Sysmon version/config hash, test date, and operator.
- Sysmon channel enabled and event ID 1 observed in the local event log.
- Connector exit code 0; reported collection window and count.
- At least one normalized event with `source=windows-sysmon`,
  `event_type=process_start`, host, UTC timestamp, source record reference, and
  matching benign marker.
- No unexpected outbound network connections from the collector process.
- No event log writes, configuration changes, or response actions by the connector.
- Failure behavior tested with an invalid output path and with opt-in omitted.

A passing result validates only this machine, its current Sysmon configuration, and
the tested process-creation path. It does not establish coverage for every Sysmon
event ID, production reliability, detection precision/recall, multi-host collection,
or absence of threats. A zero-record query is not a healthy status.

## Troubleshooting

- **Channel not found:** install and configure Sysmon on the lab host; do not assume
  Windows Security logs are equivalent to Sysmon.
- **Channel disabled / zero records:** inspect the lab configuration and event retention.
- **No marker event:** verify Event ID 1 is enabled in the Sysmon configuration and
  the collection window includes the generated process.
- **Access denied:** use an appropriately authorized test account; do not broaden
  permissions beyond what is needed to read the event channel.
- **PowerShell or JSON parse failure:** retain the sanitized error and evidence file,
  fix the adapter, and rerun the test before treating collection as validated.
