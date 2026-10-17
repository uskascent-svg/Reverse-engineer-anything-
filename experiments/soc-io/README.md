# SOC-IO — isolated prototype

SOC-IO is an **experimental, offline-first event triage prototype**. It is not a
production SIEM/SOC, has no live telemetry connectors, and has no trained or
validated prediction model. It cannot guarantee 100% accuracy. Do not use it as
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
