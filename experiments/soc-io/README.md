# SOC-IO — isolated prototype

SOC-IO is an **experimental SOC engineering project** with an offline-first event triage prototype and one opt-in Windows/Sysmon local event-log adapter. It is not a production SIEM/SOC, has no multi-user service or persistent RBAC-backed case management yet, and has no trained or validated prediction model. It cannot guarantee 100% accuracy. Do not use it as
the sole basis for incident decisions.

This folder is intentionally isolated from REA's CLI/MCP and default package.
It does not change REA provider authority or run any response actions.

## Requirements

- Python 3.10+ (standard library only)
- A local JSONL file of normalized events

## Run the synthetic example

From the repository root:

```bash
python3 experiments/soc-io/soc_io.py experiments/soc-io/examples/events.jsonl
python3 experiments/soc-io/soc_io.py experiments/soc-io/examples/events.jsonl --json
python3 experiments/soc-io/soc_io.py experiments/soc-io/examples/events.jsonl --iocs experiments/soc-io/examples/iocs.json
python3 -m unittest discover -s experiments/soc-io -p 'test_*.py' -v
```

All included sample events and indicators are synthetic/documentation-only.
The IOC example uses reserved example IP ranges and an invalid example domain.

## Analyst dashboard

Open `experiments/soc-io/dashboard.html` in a browser. It is a standalone
local page with sample data, severity/status/search filters, alert evidence
details, local workflow status changes, and JSON export. Use **Load JSON report**
to load the engine's `--json` output. The page does not make network requests;
status edits remain in the current page session and are not written back to the
source report unless exported.


## Windows / Sysmon connector (early experimental adapter)

The connector at `experiments/soc-io/connectors/windows_sysmon.py` reads the
local `Microsoft-Windows-Sysmon/Operational` event channel through PowerShell's
read-only `Get-WinEvent` API and emits normalized JSONL records. It is a local
collector, not a remote agent or a multi-host deployment service.

**Nothing is collected unless the operator explicitly opts in.** Run from an
elevated or otherwise appropriately authorized Windows terminal only if the
account has permission to read the Sysmon channel:

```powershell
python experiments/soc-io/connectors/windows_sysmon.py --enable-local-read-only --since-minutes 60 --max-events 1000 --output .\sysmon-events.jsonl
```

- Requires Windows, PowerShell, and a configured Sysmon installation/channel.
- Uses a bounded lookback window (maximum 7 days) and hard cap of 20,000 records.
- Refuses to overwrite an existing output file; choose a new path per collection.
- Uses a fixed PowerShell query; operator-supplied values are passed as environment
  data, not interpolated into executable PowerShell.
- Does not contact a remote host, access credentials, modify event logs, or run
  response actions. The connector has no network or EDR/cloud integrations.
- Normalized events preserve host, source-local record ID, timestamp, Sysmon event
  type, and source payload fields in the message. Unknown Sysmon event IDs are
  retained as `sysmon_event`; this is not a complete Sysmon schema mapping.
- A zero-record query is not proof of a healthy endpoint or absence of threats.
  Check Sysmon installation, channel health, collection window, permissions, and
  ingestion errors independently.
- The adapter and its unit tests can be tested on non-Windows hosts, but a real
  collection requires Windows and a lab system with Sysmon configured. CI does
  not contact a Windows host and does not validate production event coverage.

The connector is **experimental and read-only**. It is not yet a service-managed
connector: no scheduling, durable checkpoints, multi-host orchestration, health
API, or tenant-aware ingestion store is implemented. Multi-user deployment also
requires a server-side identity provider, database-backed cases, authorization
on every API request, tenant isolation, audit history, and backup/restore tests.
See [the production readiness contract](../../docs/soc-io-production-readiness.md).

## Event schema

Each non-empty JSONL line is an object with required fields:

- `event_id`: source-local event identifier
- `timestamp`: ISO-8601 timestamp with timezone, e.g. `2026-10-17T08:00:00Z`
- `source`: source name
- `event_type`: normalized event category

Optional string fields: `host`, `user`, `outcome`, `src_ip`, `process`,
`command_line`, `file_hash`, `destination`, and `message`. This prototype
accepts already-normalized events; it does not collect logs from endpoints.

## Current detections

- **SOCIO-AUTH-001:** five or more failed authentication events for the same
  user and source IP within ten minutes.
- **SOCIO-AUTH-002:** a successful authentication following at least three
  failures for the same user/source IP within ten minutes.
- **SOCIO-PROC-001:** a PowerShell command line containing an encoded-command
  option.
- **SOCIO-PROC-002:** a process path under common temp/tmp/downloads locations.
- **SOCIO-IOC-001:** a match against a locally supplied IP/domain/hash list.

These are deterministic leads, not verdicts. The rules are intentionally
small and will produce false positives. Indicator matches are not independently
verified against a threat-intelligence service.

## Labeled evaluation

The event-level evaluation script computes precision, recall, F1, specificity,
false-positive rate, accuracy, confusion counts, and how many predicted event
IDs had no label. Labels are manually reviewed JSONL rows such as:

```json
{"event_id":"event-123","malicious":true}
{"event_id":"event-124","malicious":false}
```

Run it with separate, reviewed labels:

```bash
python3 experiments/soc-io/evaluate.py experiments/soc-io/examples/events.jsonl experiments/soc-io/examples/labels.jsonl
```

The included labels are synthetic demonstration data only. Event-level scoring
is a rough proxy for alert quality, especially for correlated alerts. For
credible results, use a broad, representative dataset, time-separated holdout
sets, independent labels, confidence intervals, and drift monitoring. Do not
tune and report on the same sample.

## Output and safety boundaries

Each alert includes its rule ID, evidence event IDs, entities, a transparent
priority-ordering heuristic, confidence label, rationale, and suggested manual
verification steps. The score is **not** a probability. Forecasting is marked
unavailable until a representative labeled dataset, baseline, time-based
backtesting, calibration, drift checks, and independent review exist.

- Reads local input only; no network requests or telemetry uploads.
- Never executes event commands or files.
- Does not kill processes, block IPs, disable accounts, quarantine files, or
  mutate endpoints.
- Rejects malformed events, enforces event/line/field size limits, and reports
  ingestion warnings.
- Missing or stale telemetry must never be interpreted as a clean bill of health.

## Before operational use

Add schema/version governance, source-specific adapters, stronger event identity,
allowlist expiry/audit, robust entity correlation, access controls and retention
controls, a case workflow, a broad labeled replay corpus, security tests, and
operational monitoring. Review REA's contribution scope before integrating this
capability into core CLI/MCP or official packages.
