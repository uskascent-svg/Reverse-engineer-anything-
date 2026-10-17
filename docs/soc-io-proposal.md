# SOC-IO: SOC analyst extension proposal

Status: **draft proposal with isolated offline prototype — not integrated, not validated, and not production-ready**

## Goal

SOC-IO is a proposed security-operations analyst that uses REA as a local investigation and reverse-engineering capability. It should help analysts detect suspicious behavior, correlate weak signals, prioritize incidents, explain its reasoning, and estimate near-term risk from observed telemetry.

**No system can guarantee 100% threat-prediction accuracy.** SOC-IO must report measured performance and uncertainty; it must never present a heuristic score as a calibrated probability or claim that an absence of alerts means a system is safe.

## Scope boundary

REA's documented product scope is general-purpose reverse engineering and evidence collection. A full SIEM/SOC platform is a significant new product area. Keep SOC-IO isolated as an optional experiment until a human maintainer explicitly approves the scope and architecture. Do not change REA's default CLI/MCP catalog, provider authority, setup behavior, package contents, or default network activity as part of this proposal.

The initial prototype should be offline-first and read-only. It must not execute response actions, modify endpoints, inject into processes, scan third-party systems, or upload telemetry to external services. Any future connectors or response integrations require a separate authority and privacy review.

## System architecture

1. **Telemetry adapters** — ingest normalized, timestamped events from explicitly configured sources. Initial fixture formats: JSONL and documented synthetic events. Future adapters may include Windows Security/Sysmon, Linux audit/journald, EDR, DNS/proxy/firewall, cloud audit logs, identity providers, and email security platforms.
2. **Normalization and provenance** — preserve source, event ID, event time, ingestion time, host/tenant identity, schema version, raw-evidence reference and parsing status. Never silently discard malformed or late events.
3. **Detection engine** — deterministic, versioned rules for known behaviors; ATT&CK technique tags where justified; allowlists with expiry and audit history; duplicate suppression and rule tests.
4. **Correlation engine** — link events by stable identities and bounded time windows (host, user, process, IP/domain, file hash, session). Track supporting and contradictory evidence; prevent one event from being counted repeatedly as independent evidence.
5. **Threat intelligence enrichment** — optional, explicitly configured local indicators and signed/imported feeds. Store feed provenance, observation time, expiry, confidence and false-positive context. An IOC match is a lead, not proof of compromise.
6. **Risk and forecast engine** — separate severity, evidence confidence, asset criticality and forecast probability. Forecasts must specify a horizon, population, base rate, model version, calibration status and uncertainty. Unknown or missing telemetry must lower coverage, not silently lower risk.
7. **Alert triage and case management** — explain why an alert fired, affected entities, timeline, evidence links, ATT&CK mapping, competing benign explanations, recommended verification steps, owner, status, SLA and audit trail.
8. **REA investigation bridge** — invoke existing REA capabilities only for an explicitly selected local artifact or target, using the least-authority provider and retaining REA Evidence references. Static analysis is preferred; any dynamic execution requires a separate explicit confirmation and isolation warning.
9. **Analyst interface** — alert queue, asset and identity context, event timeline, investigation graph, detection coverage, case notes, response checklist, model-health and data-freshness dashboards.
10. **Evaluation and governance** — replayable fixtures, historical backtesting with time-based splits, analyst feedback, rule/model versioning, drift monitoring, audit logs, retention controls and documented limitations.

## Minimum SOC capability matrix

| Capability | Initial requirement |
| --- | --- |
| Telemetry | Schema validation, timestamps, source health, data freshness, deduplication |
| Detection | Versioned rules, tests, severity, rationale, ATT&CK tags, false-positive handling |
| Correlation | Entity graph, event windows, evidence provenance, contradiction handling |
| Threat intel | IOC matching, expiry, source confidence, safe import and provenance |
| Triage | Priority, confidence, affected assets/users, timeline, next steps |
| Case management | Assignment, state transitions, notes, SLA, evidence and audit history |
| Response | Human-approved runbooks only; no autonomous containment in the first release |
| Prediction | Explicit horizon, calibrated probability, uncertainty, backtesting and drift checks |
| Security | RBAC, tenant boundaries, secrets handling, immutable audit trail, retention/deletion |
| Reliability | Bounded queues and parsing, idempotency, graceful partial failures, health checks |
| Validation | Unit/integration tests, synthetic attack chains, benign controls, replay and regression tests |
| Reporting | Detection coverage, false-positive rate, precision/recall, latency, telemetry gaps and model health |

## Risk model: never collapse everything into one unexplained number

Each alert should expose independent dimensions:

- **Severity**: potential business impact if the behavior is malicious.
- **Evidence confidence**: strength and quality of the observed evidence.
- **Asset criticality**: business importance of the affected system or identity.
- **Exploitability/exposure**: validated context that increases plausible impact.
- **Forecast probability**: only where a validated model estimates a defined outcome within a defined time horizon.
- **Coverage/freshness**: whether relevant data sources are present, current and healthy.

A deterministic priority may be used to order analyst work, but must be labelled as a heuristic. Do not label it “probability of attack” unless calibration has been measured on representative held-out data.

## Prediction and evaluation requirements

- Establish a baseline and label quality before fitting a model.
- Split evaluation data by time and, where applicable, environment/tenant to reduce leakage.
- Measure precision, recall, PR-AUC, false positives per endpoint/day, time-to-detect, Brier score and calibration error where applicable.
- Report confidence intervals, sample sizes, class prevalence, missing-data coverage and comparison with simple baselines.
- Include benign lookalikes, adversarially modified samples, delayed events, duplicated events, clock skew, feed expiry and telemetry outages.
- Use shadow mode before any operational reliance. Analyst feedback must be tracked with provenance and must not automatically convert unverified alerts into training truth.
- Define rollback thresholds and detect drift. If model health is degraded, fall back to transparent rules and mark forecasts unavailable.

## Security and privacy defaults

- Local-first; no external telemetry upload by default.
- Explicit source configuration and least-privilege credentials; never log secrets.
- Tenant isolation and role-based access if multi-user deployment is added.
- Encrypt data in transit and at rest when applicable; define retention, deletion and export controls.
- Treat event payloads, filenames, command lines, URLs and artifacts as untrusted input.
- Bound event size, archive depth, parsing time, queue growth and correlation windows.
- Preserve provenance and tamper-evident audit events.
- Do not auto-block IPs, kill processes, disable accounts, quarantine files or change firewall rules in the initial release.

## Delivery plan

### Phase 0 — scope and threat model
Human maintainer approves the product boundary, data sources, deployment model, privacy/retention rules and permitted actions.

### Phase 1 — offline deterministic prototype
Typed event schema, JSONL fixtures, rule engine, deduplication, explainable priority dimensions, correlation windows, alert records, unit tests and a CLI report. No network listeners or live response.

### Phase 2 — replay and evaluation
Synthetic benign/malicious scenarios, labeled replay harness, time-based validation, metrics and regression corpus.

### Phase 3 — analyst workflow
Case lifecycle, timeline, entity graph, analyst feedback, ATT&CK coverage and source-health dashboard.

### Phase 4 — opt-in integrations
Reviewed connectors for selected telemetry platforms and threat-intelligence sources. Add one connector at a time with least privilege and end-to-end tests.

### Phase 5 — forecast models
Only after adequate representative labels and a working baseline: calibrated forecasting, drift detection, model cards and shadow deployment. No claim of perfect accuracy.

### Phase 6 — controlled response
Separate proposal for human-approved playbooks, simulation/dry-run, authorization checks, rollback, audit and failure handling. Autonomous response is out of initial scope.

## Acceptance criteria before production claims

- No “100% accuracy” claim; every metric links to a reproducible evaluation set and method.
- All detections include provenance, rule/model version, timestamps and a human-readable explanation.
- Missing/stale telemetry is visible and cannot be interpreted as a clean bill of health.
- Unit, integration, replay, negative-control, security-boundary and performance tests pass.
- False-positive rates and detection latency are reported by source and scenario.
- No external data transfer or state-changing response without explicit configuration and authorization.
- Security review, privacy review, operator runbook and rollback plan are complete.

## Current state

This document began as a design proposal. An isolated experimental prototype now exists under `experiments/soc-io/`: local JSONL ingestion, bounded validation, deterministic rules for repeated authentication failures, success-after-failures, encoded PowerShell, processes launched from common staging paths, and matches against locally supplied IP/domain/hash indicators. It includes synthetic fixtures, a CLI/JSON report, and standard-library unit tests. No live ingestion connector, trained prediction model, dashboard, case-management workflow, or response capability exists. Local execution and tests could not be run in the current environment because GitHub DNS/network access failed; do not treat the prototype as validated or production-ready.
