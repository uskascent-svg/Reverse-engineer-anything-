-- SOC-IO multi-user case-store foundation (PostgreSQL 15+).
-- This schema is NOT a complete service: API authentication, authorization,
-- migrations, connection security, backup/restore, and integration tests remain required.
-- The application must validate the authenticated user's tenant membership before
-- setting transaction-local soc_io.tenant_id and soc_io.actor_user_id.

CREATE TABLE IF NOT EXISTS socio_tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS socio_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    display_name text NOT NULL DEFAULT '' CHECK (length(display_name) <= 200),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS socio_memberships (
    tenant_id uuid NOT NULL REFERENCES socio_tenants(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES socio_users(id) ON DELETE RESTRICT,
    role text NOT NULL CHECK (role IN ('viewer', 'analyst', 'incident_lead', 'administrator')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS socio_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES socio_tenants(id) ON DELETE RESTRICT,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
    summary text NOT NULL DEFAULT '' CHECK (length(summary) <= 20000),
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    severity text NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    assigned_to uuid REFERENCES socio_users(id) ON DELETE RESTRICT,
    created_by uuid NOT NULL REFERENCES socio_users(id) ON DELETE RESTRICT,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS socio_case_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES socio_tenants(id) ON DELETE RESTRICT,
    case_id uuid NOT NULL,
    actor_user_id uuid NOT NULL REFERENCES socio_users(id) ON DELETE RESTRICT,
    event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 100),
    event_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, case_id) REFERENCES socio_cases(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS socio_case_notes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES socio_tenants(id) ON DELETE RESTRICT,
    case_id uuid NOT NULL,
    author_user_id uuid NOT NULL REFERENCES socio_users(id) ON DELETE RESTRICT,
    body text NOT NULL CHECK (length(body) BETWEEN 1 AND 50000),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, case_id) REFERENCES socio_cases(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS socio_case_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES socio_tenants(id) ON DELETE RESTRICT,
    case_id uuid NOT NULL,
    evidence_type text NOT NULL CHECK (length(evidence_type) BETWEEN 1 AND 100),
    source_name text NOT NULL CHECK (length(source_name) BETWEEN 1 AND 256),
    source_event_id text NOT NULL CHECK (length(source_event_id) BETWEEN 1 AND 512),
    content_sha256 char(64),
    reference_uri text NOT NULL CHECK (length(reference_uri) <= 4096),
    collected_at timestamptz NOT NULL DEFAULT now(),
    added_by uuid NOT NULL REFERENCES socio_users(id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, case_id) REFERENCES socio_cases(tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS socio_audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES socio_tenants(id) ON DELETE RESTRICT,
    actor_user_id uuid REFERENCES socio_users(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (length(action) BETWEEN 1 AND 200),
    target_type text NOT NULL CHECK (length(target_type) BETWEEN 1 AND 100),
    target_id text NOT NULL CHECK (length(target_id) <= 512),
    request_id text NOT NULL DEFAULT '' CHECK (length(request_id) <= 256),
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS socio_cases_tenant_status_idx ON socio_cases (tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS socio_case_events_timeline_idx ON socio_case_events (tenant_id, case_id, created_at);
CREATE INDEX IF NOT EXISTS socio_case_notes_timeline_idx ON socio_case_notes (tenant_id, case_id, created_at);
CREATE INDEX IF NOT EXISTS socio_case_evidence_lookup_idx ON socio_case_evidence (tenant_id, case_id, collected_at);
CREATE INDEX IF NOT EXISTS socio_audit_timeline_idx ON socio_audit_events (tenant_id, created_at DESC);

-- Defense in depth against accidental unscoped reads. The API must validate
-- membership before setting the transaction-local tenant ID. A shared DB role
-- that can issue arbitrary SQL can set custom GUCs; RLS is not a substitute for
-- a trusted API boundary, parameterized queries, or database role separation.
ALTER TABLE socio_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE socio_tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE socio_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE socio_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE socio_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE socio_cases FORCE ROW LEVEL SECURITY;
ALTER TABLE socio_case_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE socio_case_events FORCE ROW LEVEL SECURITY;
ALTER TABLE socio_case_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE socio_case_notes FORCE ROW LEVEL SECURITY;
ALTER TABLE socio_case_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE socio_case_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE socio_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE socio_audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS socio_tenants_scope ON socio_tenants;
CREATE POLICY socio_tenants_scope ON socio_tenants
    USING (id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS socio_memberships_tenant_scope ON socio_memberships;
CREATE POLICY socio_memberships_tenant_scope ON socio_memberships
    USING (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS socio_cases_tenant_scope ON socio_cases;
CREATE POLICY socio_cases_tenant_scope ON socio_cases
    USING (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS socio_case_events_tenant_scope ON socio_case_events;
CREATE POLICY socio_case_events_tenant_scope ON socio_case_events
    USING (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS socio_case_notes_tenant_scope ON socio_case_notes;
CREATE POLICY socio_case_notes_tenant_scope ON socio_case_notes
    USING (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS socio_case_evidence_tenant_scope ON socio_case_evidence;
CREATE POLICY socio_case_evidence_tenant_scope ON socio_case_evidence
    USING (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS socio_audit_events_tenant_scope ON socio_audit_events;
CREATE POLICY socio_audit_events_tenant_scope ON socio_audit_events
    USING (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('soc_io.tenant_id', true), '')::uuid);

-- Protect append-only evidence histories from accidental edits by application
-- code. DB owners/superusers remain privileged; production roles must not own
-- these tables or have trigger-management privileges.
CREATE OR REPLACE FUNCTION socio_reject_history_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'SOC-IO history tables are append-only';
END;
$$;

DROP TRIGGER IF EXISTS socio_case_events_append_only ON socio_case_events;
CREATE TRIGGER socio_case_events_append_only
    BEFORE UPDATE OR DELETE ON socio_case_events
    FOR EACH ROW EXECUTE FUNCTION socio_reject_history_mutation();
DROP TRIGGER IF EXISTS socio_case_notes_append_only ON socio_case_notes;
CREATE TRIGGER socio_case_notes_append_only
    BEFORE UPDATE OR DELETE ON socio_case_notes
    FOR EACH ROW EXECUTE FUNCTION socio_reject_history_mutation();
DROP TRIGGER IF EXISTS socio_audit_events_append_only ON socio_audit_events;
CREATE TRIGGER socio_audit_events_append_only
    BEFORE UPDATE OR DELETE ON socio_audit_events
    FOR EACH ROW EXECUTE FUNCTION socio_reject_history_mutation();
