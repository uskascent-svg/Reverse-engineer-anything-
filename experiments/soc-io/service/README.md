# Multi-user service foundation (not a running service)

`postgres_schema.sql` is an initial PostgreSQL schema foundation for tenants,
external identity subjects, memberships, cases, append-only case events and notes,
evidence references, and audit events. It includes tenant-scoped row-level security
policies and append-only triggers for case history.

**This file alone does not provide a secure multi-user service.** No API server,
authentication middleware, authorization middleware, migration runner, session
management, deployment configuration, database role setup, or backup/restore
process is implemented here. Do not deploy this schema as a production service.

Before using it:
1. Choose and configure a supported OIDC identity provider. Validate issuer,
   audience, signature, expiry, and subject; never trust a client-supplied user ID.
2. Use a non-owner, non-superuser application DB role with narrowly granted
   permissions. The application must validate membership before setting
   transaction-local `soc_io.tenant_id` and `soc_io.actor_user_id`.
3. Set tenant context transaction-locally on every request and clear it by
   ending the transaction. Use parameterized SQL and a connection pool that
   cannot leak tenant context across requests.
4. Enforce role permissions in the server on every read/write. Viewer is read-only;
   analyst can work assigned cases according to policy; incident lead can assign
   and change case disposition; administrator manages memberships but cannot
   automatically authorize response actions.
5. Add tested migrations, CSRF protections where cookie auth is used, rate limits,
   request-size limits, secrets management, TLS, encryption at rest, backups,
   restore drills, retention/deletion procedures, and security tests for
   cross-tenant access and privilege escalation.
6. Treat RLS as defense in depth, not as a substitute for application authorization.
   A database role that can execute arbitrary SQL can set custom PostgreSQL settings;
   production design must account for that threat.
7. Restrict table ownership and trigger privileges. Append-only triggers deter
   application-level updates/deletes but are not cryptographically tamper-proof
   against database owners or administrators. Consider protected external audit
   storage and hash chaining after a threat-model review.
8. Validate the SQL against the exact supported PostgreSQL version in a disposable
   integration-test database before relying on it.

This foundation is deliberately separate from the standalone HTML dashboard.
The dashboard still stores status edits only in browser memory and is not connected
to this database.
