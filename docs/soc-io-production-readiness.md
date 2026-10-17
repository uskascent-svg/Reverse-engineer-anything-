# SOC-IO production readiness and implementation contract

Status: **requirements and design contract; implementation incomplete**. An experimental opt-in local Windows/Sysmon adapter, a FastAPI OIDC-authenticated case API, a PostgreSQL case-store schema, and disposable PostgreSQL integration tests have been added. The Windows lab procedure is prepared but has not been run on a connected Windows host; the API still lacks real OIDC-provider integration tests and deployment hardening.  
Scope: isolated experiment under `experiments/soc-io/`. This document does not authorize merging SOC-IO into REA's core CLI/MCP or changing REA's default network behavior.

## Release gates

SOC-IO must not be described as production-ready until each applicable gate is implemented, tested, and reviewed. A configuration example or mock connector does not count as a working integration.

### Gate A — explicit, real telemetry connectors

Implement connectors as independently enabled adapters. All connectors are disabled unless the operator explicitly enables and configures them. No credential discovery, broad host scanning, or telemetry export by default.

Initial connector families:
- **Windows / Sysmon:** an early experimental adapter now queries the local Sysmon Operational channel with PowerShell `Get-WinEvent`, explicit `--enable-local-read-only` opt-in, bounded time/event limits, and JSONL output. It maps common event IDs and preserves host, source-local record ID, event time, and event payload. It is not a remote collector or service-managed connector; durable checkpoints, source health API, broader schema mapping, and a real Windows lab integration test remain outstanding. The remaining connector contract still requires ingestion time, channel/provider provenance, health, cursor recovery, and integration validation.
- **Linux:** consume configured journald or auditd sources; preserve boot ID, machine identity, audit serial/correlation IDs, original timestamps, and parser status.
- **Identity platforms:** vendor-specific, read-only API adapters with explicit tenant, endpoint, event categories, cursor/checkpoint, and scopes. Start with one provider only after its API contract and pagination/rate-limit behavior are tested.
- **Cloud audit logs:** provider-specific read-only collection (for example, AWS CloudTrail, Microsoft Entra/Azure activity, or Google Cloud Audit Logs), with explicit account/project/tenant and region/scope allowlists.
- **EDR:** vendor-specific API adapter with read-only alert/event permissions, explicit tenant and endpoint scope, documented rate limits, and no response permission in the ingest credential.

Connector contract:
1. Explicit configuration file and command-line override; reject unknown fields and invalid combinations.
2. Connector identity, enabled state, config version, source scope, credential reference (never secret value), checkpoint/cursor, last successful poll, last event time, lag, errors, and health state.
3. Secrets supplied through environment variables or a supported secret manager; never committed, echoed, or logged. No automatic credential discovery.
4. Least-privilege read-only permissions; separate credentials and approval boundary for any future response action.
5. Idempotent ingestion, bounded retries/backoff, rate-limit handling, pagination, checkpoint recovery, duplicate detection, late-arrival handling, and explicit partial-failure reporting.
6. Raw evidence retained only according to documented retention policy; normalized records retain provenance and a stable reference to source evidence.
7. Contract tests with recorded/synthetic fixtures and opt-in integration tests against a dedicated test tenant. Never call a live tenant in ordinary CI.
8. A connector is labelled **configured**, **connected**, or **healthy** only when the relevant check actually succeeded. An absent connector is **not configured**, not healthy.

No connector may silently upload collected telemetry to a third-party service. Network destinations must be documented and limited to the configured provider.

### Gate B — detections, hunting, correlation, ATT&CK

- Give every rule a stable ID, semantic version, description, author, data-source prerequisites, required fields, logic, severity rationale, false-positive notes, test fixtures, and changelog.
- Add ATT&CK technique/sub-technique identifiers only when the rule behavior supports the mapping. Record ATT&CK version and mapping rationale; avoid mapping solely by keyword.
- Expand detections in reviewed increments: authentication abuse and MFA anomalies; suspicious script/process execution; persistence via services/tasks/run keys/systemd; privilege changes; unusual remote execution; credential-access indicators; defense evasion; suspicious DNS/network activity; cloud control-plane changes; and EDR alert correlation.
- Include benign lookalikes and negative tests for each detection. Report prerequisites and blind spots when relevant telemetry is absent.
- Threat hunting must support bounded, read-only queries over collected events, time range, tenant/scope, saved queries, and exported results. Treat event text as untrusted data, never executable instructions.
- Correlate by stable host, user, process, session, IP/domain, hash, cloud resource, and identity IDs. Use bounded time windows and source-aware identity rules; retain edge provenance and supporting/contradicting evidence. Do not count repeated copies of the same source event as independent evidence.
- Surface telemetry coverage, freshness, parser failures, rule coverage, and event volume beside detection results.

### Gate C — persistent cases and access control

Use a supported transactional database for durable state. The in-memory HTML dashboard is only a prototype and must not be represented as persistent case management.

Minimum entities:
- Case: immutable ID, title, state, priority, owner, tenant, timestamps, linked alerts, assets, and disposition.
- Case event: append-only state transition and assignment history.
- Analyst note: author, timestamp, revision/deletion policy, and case linkage.
- Evidence reference: source, event ID, hash/reference, collected time, and access classification.
- Audit record: actor, action, target, timestamp, request/correlation ID, outcome, and relevant before/after metadata (never secrets).
- User/role/tenant: identity provider subject, assigned roles, tenant scope, and authorization policy.

Minimum roles: **viewer**, **analyst**, **incident lead**, and **administrator**. Enforce authorization server-side on every read/write; hiding UI controls is not access control. Deny by default, scope all data access by tenant, and test horizontal/vertical privilege escalation. Administrator privileges do not implicitly authorize response execution.

Audit history should be append-only and tamper-evident, with protected storage, controlled retention, and documented export. Case/note edits must not erase prior audit evidence. Add backups, restore tests, migrations, retention/deletion procedures, and encryption in transit/at rest for deployment.

### Gate D — representative evaluation and forecast governance

- Build a licensed, documented, privacy-reviewed dataset spanning Windows/Sysmon, Linux, identity, cloud, and EDR events; include benign operational traffic, rare events, false-positive lookalikes, missing fields, duplicate/delayed events, time skew, and outages.
- Labels need source, reviewer, timestamp, confidence, adjudication status, and label rationale. Separate uncertain/unreviewed labels from ground truth.
- Split by time before tuning. Prevent entity/session/incident leakage across train, validation, and holdout sets; where relevant, hold out tenants/environments as well.
- Compare against transparent rule-only and simple baseline methods. Report sample sizes, prevalence, confidence intervals, per-source/per-rule metrics, precision, recall, F1, PR-AUC where appropriate, false positives per endpoint/day, detection latency, and missing-telemetry coverage.
- Forecasts additionally require Brier score, calibration plots/error, base rate, a clearly defined outcome and horizon, model version, uncertainty, and subgroup/source analysis.
- Monitor data/schema drift, feature drift, calibration drift, source-health changes, and label delay. Define thresholds, alerting, rollback, and a safe fallback.
- Keep forecasting **unavailable** until a designated reviewer signs off on dataset representativeness, label quality, time-separated backtest results, calibration, and monitoring. Synthetic fixtures validate software behavior only; they do not establish detection efficacy.
- Analyst feedback is not ground truth by default. Track feedback provenance and require adjudication before using it as a training label.

### Gate E — separately reviewed human-approved response

Response is a separate security boundary and release. It is not enabled by connector credentials or analyst role alone.

Every proposed playbook must have:
- written threat model, scope, prerequisites, permitted targets, and explicit prohibited actions;
- dry-run/simulation mode and deterministic preview of the exact proposed changes;
- authenticated requester, separate approver where risk warrants, authorization re-check at execution time, and expiry of approvals;
- idempotency key, timeout, bounded retries, rate limits, cancellation, and rollback/compensating action where possible;
- pre/post-state capture, immutable audit record, result verification, failure handling, and a tested manual recovery path;
- integration tests against a dedicated lab tenant and independent security review.

Initial response candidates should be narrowly scoped and reversible. Do not automatically kill processes, disable identities, quarantine files, block network ranges, or alter firewall/cloud policy. Human approval must be explicit and tied to the exact target and action. If approval, audit, or verification fails, do not execute.

## Delivery order

1. **Foundation:** versioned normalized event schema, connector interface, health/coverage model, provenance, and security threat model.
2. **One real connector:** select one provider and deliver end-to-end read-only collection with integration tests, cursor recovery, rate-limit handling, and setup documentation. Do not claim all connector families are supported.
3. **Detection quality:** add rule metadata, ATT&CK mapping, negative fixtures, and bounded hunting/correlation.
4. **Service hardening:** reviewed migrations, real OIDC/JWKS integration tests, expanded authorization matrix, deployment hardening, audit protection, and backup/restore tests.
5. **Evaluation:** representative labeled replay corpus, time-separated backtests, reproducible metrics, and drift monitoring.
6. **Forecasting review:** only after Gate D passes; keep disabled until sign-off.
7. **Response review:** independent approval and lab validation under Gate E.

## Definition of done

A feature is done only when its code, documentation, tests, operational failure behavior, and security boundary agree. Roadmap text, sample data, UI mockups, or green CI on synthetic fixtures are not evidence that a production integration or detection has been validated.

## Decisions that must be explicit before provider work

- First connector to implement and the operator-controlled deployment target.
- Single-user local deployment versus multi-user/tenant service.
- Database and identity provider for persistent cases and RBAC.
- Approved dataset sources, licensing/privacy constraints, and retention policy.
- Which response actions, if any, are in scope for a later separate review.
