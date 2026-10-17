# SOC-IO authenticated case API — experimental

This directory now contains an initial FastAPI case API, an OIDC bearer-token
validator, role guards, a PostgreSQL schema, and unit tests. It is an **experimental
foundation**, not a production-ready SOC service. Live Windows collection is a
separate local adapter; this API does not schedule or remotely control collectors.

## What is implemented

- OIDC JWT validation using issuer, audience, and a configured JWKS URL; RS256 only.
- Explicit tenant selection with `X-SOC-IO-Tenant`, followed by a database membership
  lookup using the validated token issuer and subject.
- Transaction-local PostgreSQL tenant/actor context for each request, compatible
  with the schema's tenant row-level security policies.
- API endpoints for case create/list/read/update, append-only notes, case event
  history, current identity/role, and restricted audit listing.
- Server-side role guards: viewers are read-only; analysts can create/update cases
  and add notes; incident leads and administrators can assign cases and view audit
  history. Administrator status does not grant any response-action capability.
- Parameterized values, bounded request fields/list sizes, allow-listed dynamic
  update column names, version checks for concurrent case updates, and audit rows.
- No forecast or response-action endpoints.

## Configure and run locally

Use a disposable development PostgreSQL database. Do not point this at a production
tenant during initial setup.

1. Install Python 3.11+ and PostgreSQL 15+.
2. Create a dedicated database role that is **not** a superuser, table owner, or
   role with permission to disable row-level security or alter history triggers.
3. Apply the schema as a trusted database migration/administrator:
   `psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f postgres_schema.sql`.
4. Install runtime dependencies:
   `python -m pip install -r requirements.txt`.
5. Configure these environment variables from your identity provider:
   - `DATABASE_URL`: PostgreSQL connection string for the restricted application role.
   - `SOCIO_OIDC_ISSUER`: exact issuer URL expected in JWT `iss`.
   - `SOCIO_OIDC_AUDIENCE`: API audience expected in JWT `aud`.
   - `SOCIO_OIDC_JWKS_URL`: trusted provider JWKS endpoint. Configure only a trusted
     HTTPS URL. The API allows RS256 signatures only.
6. Pre-provision `socio_users` and `socio_memberships` for each authorized identity.
   Store the exact validated `iss` and `sub` values, and assign one of
   `viewer`, `analyst`, `incident_lead`, or `administrator`. There is no public
   self-registration or first-user bootstrap endpoint.
7. Run from the `experiments/soc-io` directory:
   `uvicorn service.app:app --host 127.0.0.1 --port 8080`.

Do not expose this service directly to the internet. Use TLS termination, network
restrictions, managed secrets, dependency patching, rate limits, request logging,
and a reviewed deployment configuration before any shared environment. Never
commit credentials or production tokens.

## Request examples

A valid access token and a tenant UUID are both required:

```http
GET /api/me
Authorization: Bearer <OIDC_ACCESS_TOKEN>
X-SOC-IO-Tenant: <TENANT_UUID>
```

Create a case (analyst, incident lead, or administrator):

```http
POST /api/cases
Authorization: Bearer <OIDC_ACCESS_TOKEN>
X-SOC-IO-Tenant: <TENANT_UUID>
Content-Type: application/json

{"title":"Investigate Sysmon alert","summary":"Review process-start evidence","severity":"medium"}
```

Available endpoints are described by the local OpenAPI document at `/docs` when
running the service. The health endpoint is intentionally minimal and does not
claim database, identity-provider, or collector health.

## Validation

Run unit tests from the `experiments/soc-io` directory:

```sh
python -m pip install -r service/requirements.txt
python -m unittest discover -s . -p 'test_*.py' -v
```

The workflow runs PostgreSQL 16 integration tests against a disposable database and a local HTTPS JWKS integration suite that exercises actual RS256 signature validation, issuer/audience/expiry checks, wrong-signature rejection, and algorithm restrictions. The local HTTPS issuer uses a test-only key/certificate; it is not your selected identity provider. To test the real provider, configure the same issuer, audience, and HTTPS JWKS URL used by the deployment, supply a short-lived test access token as `SOCIO_OIDC_TEST_TOKEN`, and run `python -m unittest service.test_oidc_provider -v` from `experiments/soc-io`. Never put that token in source control or CI logs. External-provider validation is not complete until this test is run against your configured staging identity provider. Before shared deployment, also complete reviewed migrations, concurrent update tests, broader authorization matrix tests, database privilege checks, and backup/restore drills.

## Important limitations and review items

- The API uses a simple connection pool and does not yet include deployment-grade
  rate limiting, CSRF controls (needed if cookie-based auth is added), request tracing,
  structured operational metrics, or a formal migration runner.
- RLS relies on the trusted API setting transaction-local custom PostgreSQL settings.
  A database principal able to issue arbitrary SQL can set those values; use a tightly
  restricted role, parameterized queries, and a threat-model-reviewed database boundary.
- Append-only triggers prevent ordinary application updates/deletes but are not
  cryptographically tamper-proof against database owners/superusers.
- User provisioning, role administration endpoints, SSO setup UI, case attachment
  uploads, and notification delivery are not implemented.
- No real Windows lab validation has been performed by CI. The optional manual job retains only a sanitized JSON summary artifact (14-day retention); raw event JSONL stays on the lab host. Follow
  `../connectors/WINDOWS_SYSMON_VALIDATION.md` on a dedicated test host.
- No forecasting, threat-probability output, or automated response action is implemented.
