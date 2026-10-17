# SOC-IO deployment security review (preliminary)

**Status: NOT APPROVED for shared or production deployment.** This is a source-level
review of the experimental branch, not a penetration test, independent audit, or
proof of runtime configuration. It does not certify detection accuracy.

## Scope reviewed

- FastAPI authentication and tenant/role authorization.
- PostgreSQL schema, row-level security (RLS), case notes/events, and audit records.
- Windows/Sysmon local collector and its opt-in lab-validation path.
- CI test configuration and evidence retention boundaries.

## Positive controls present

- OIDC JWT verification pins the accepted algorithm to RS256 and validates issuer,
  audience, required claims, signature, and expiry with a small clock-skew allowance.
- Issuer and JWKS endpoints must be absolute HTTPS URLs; URL user-info and fragments
  are rejected.
- Tenant membership is independently checked after token validation; the `socio_users` table now also has RLS limited to identities with membership in the selected tenant.
- Query values are parameterized; dynamic update columns come from an allow-list.
- Case updates use version checks; request fields and list sizes are bounded.
- Viewers cannot mutate cases; analysts cannot assign cases or move cases into terminal
  states without an incident lead/admin. There are no forecast or response routes.
- The Sysmon collector is local, read-only, bounded, and opt-in. CI retains only the
  sanitized validation summary; raw event JSONL is not uploaded.

## Findings and required remediation

### Blocker — runtime validations not yet completed

- No dedicated Windows/Sysmon runner has executed the benign event test in this session.
- The local HTTPS JWKS suite tests the actual PyJWT/JWKS code path using an ephemeral
  test key, but the configured external identity provider has not been exercised.
- The PostgreSQL suite is useful integration coverage, including a tenant-scoped identity-row check, but is not a substitute for a broader database privilege and migration review.

**Required:** execute the manual Windows lab job and retain its sanitized artifact;
execute the service.test_oidc_provider test with a short-lived token from the selected staging
identity provider; retain only sanitized pass/fail metadata and never the token.

### High — deployment hardening is incomplete

No reviewed migration runner, managed secret integration, deployment-specific TLS
configuration, rate limiting, request tracing, structured security monitoring,
dependency vulnerability gate, tested backup/restore, or documented incident recovery
procedure is included.

**Required:** complete and review these controls before exposing the API beyond a
restricted development environment. Keep it bound to loopback until a deployment
design and TLS/network boundary are reviewed.

### High — database role and RLS boundary require operational enforcement

RLS policies rely on transaction-local custom settings set by the trusted API. A
database principal able to issue arbitrary SQL can set these values. RLS and history
triggers do not protect against database owners/superusers.

**Required:** use a dedicated non-owner, non-superuser role; grant only required
operations; do not expose arbitrary SQL; verify grants and FORCE ROW LEVEL SECURITY
in integration tests; separate migration credentials from runtime credentials; and
review the threat model for the database provider and privileged operators.

### Medium — authorization coverage needs expansion

The current tests cover core tenant isolation and selected role checks, but not the
complete endpoint/role matrix, concurrency races under load, account disable/revocation,
provider key rotation/cache behavior, or negative database privilege cases.

**Required:** expand the authorization matrix and test expired/revoked identities,
unknown key IDs, JWKS outages, key rotation, concurrent updates, and tenant isolation
for every read/write endpoint.

### Medium — audit immutability is operational, not cryptographic

Append-only triggers stop ordinary application updates/deletes but cannot prevent a
privileged database operator from changing the schema or underlying records.

**Required:** consider exporting audit events to a separately administered append-only
or WORM destination, define retention/access policy, and test alerting for audit
pipeline failure before shared use.

## Go/no-go criteria

Do not approve shared use until all of the following are evidenced:

1. Real Windows lab test passes and sanitized artifact is retained.
2. Real staging OIDC provider test passes; issuer, audience, signature, expiry, and
   failure cases are verified without exposing credentials.
3. Database grants, RLS, migrations, tenant isolation, and the full authorization
   matrix pass reviewed tests.
4. TLS/network restrictions, rate limits, secrets, dependency scanning, security
   logging, retention, backup/restore, and recovery are reviewed and tested.
5. An independent reviewer approves the deployment configuration and threat model.

No production accuracy claim, forecasting, or automated response action is enabled by
this change.
