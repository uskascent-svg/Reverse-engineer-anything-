import os
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import psycopg
from fastapi.testclient import TestClient

from service.app import app

ADMIN_DSN = os.getenv("SOCIO_TEST_ADMIN_DSN", "")


@unittest.skipUnless(ADMIN_DSN, "PostgreSQL integration tests require SOCIO_TEST_ADMIN_DSN")
class CaseApiPostgresIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_dsn = ADMIN_DSN
        cls.tenant_a = UUID("11111111-1111-4111-8111-111111111111")
        cls.tenant_b = UUID("22222222-2222-4222-8222-222222222222")
        cls.alice = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        cls.viewer = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        cls.lead = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        cls.bob = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

        with psycopg.connect(cls.admin_dsn, autocommit=True) as conn:
            # This suite recreates public schema and is intentionally restricted
            # to the disposable CI database; fail closed for any other target.
            if conn.info.dbname != "socio_test" or conn.info.host not in {"localhost", "127.0.0.1", "::1"}:
                raise RuntimeError(
                    "Destructive PostgreSQL integration tests require local database socio_test"
                )
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")
            schema = Path(__file__).with_name("postgres_schema.sql").read_text(encoding="utf-8")
            conn.execute(schema)
            conn.execute("DROP ROLE IF EXISTS socio_app")
            conn.execute("CREATE ROLE socio_app LOGIN PASSWORD 'socio-test-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
            conn.execute("GRANT CONNECT ON DATABASE socio_test TO socio_app")
            conn.execute("GRANT USAGE ON SCHEMA public TO socio_app")
            conn.execute("GRANT SELECT ON socio_tenants, socio_users, socio_memberships TO socio_app")
            conn.execute("GRANT SELECT, INSERT, UPDATE ON socio_cases TO socio_app")
            conn.execute("GRANT SELECT, INSERT ON socio_case_events, socio_case_notes, socio_case_evidence, socio_audit_events TO socio_app")
            conn.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO socio_app")

            conn.execute("INSERT INTO socio_tenants (id, name) VALUES (%s, 'Tenant A'), (%s, 'Tenant B')",
                         (cls.tenant_a, cls.tenant_b))
            conn.execute(
                "INSERT INTO socio_users (id, issuer, subject, display_name) VALUES "
                "(%s, 'https://issuer.test', 'alice', 'Alice Analyst'), "
                "(%s, 'https://issuer.test', 'viewer', 'Read Only'), "
                "(%s, 'https://issuer.test', 'lead', 'Incident Lead'), "
                "(%s, 'https://issuer.test', 'bob', 'Tenant B Analyst')",
                (cls.alice, cls.viewer, cls.lead, cls.bob),
            )
            conn.execute(
                "INSERT INTO socio_memberships (tenant_id, user_id, role) VALUES "
                "(%s, %s, 'analyst'), (%s, %s, 'viewer'), (%s, %s, 'incident_lead'), (%s, %s, 'analyst')",
                (cls.tenant_a, cls.alice, cls.tenant_a, cls.viewer,
                 cls.tenant_a, cls.lead, cls.tenant_b, cls.bob),
            )
        cls.app_dsn = "postgresql://socio_app:socio-test-password@localhost:5432/socio_test"

    def request_as(self, subject, tenant, method, path, **kwargs):
        env = {
            "DATABASE_URL": self.app_dsn,
            "SOCIO_OIDC_ISSUER": "https://issuer.test",
            "SOCIO_OIDC_AUDIENCE": "soc-io-test",
            "SOCIO_OIDC_JWKS_URL": "https://issuer.test/.well-known/jwks.json",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("service.app.verify_token", side_effect=lambda token: {"sub": token}):
                with TestClient(app) as client:
                    headers = {
                        "Authorization": f"Bearer {subject}",
                        "X-SOC-IO-Tenant": str(tenant),
                        "X-Request-ID": "test-request",
                    }
                    return client.request(method, path, headers=headers, **kwargs)

    def test_persistent_case_note_events_and_audit(self):
        created = self.request_as(
            "alice", self.tenant_a, "POST", "/api/cases",
            json={"title": "Sysmon investigation", "summary": "Lab event", "severity": "medium"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        case = created.json()
        case_id = case["id"]

        blank_note = self.request_as(
            "alice", self.tenant_a, "POST", f"/api/cases/{case_id}/notes",
            json={"body": "   "},
        )
        self.assertEqual(blank_note.status_code, 422)

        note = self.request_as(
            "alice", self.tenant_a, "POST", f"/api/cases/{case_id}/notes",
            json={"body": "Review the process-start evidence."},
        )
        self.assertEqual(note.status_code, 201, note.text)
        self.assertEqual(note.json()["body"], "Review the process-start evidence.")

        read_back = self.request_as("alice", self.tenant_a, "GET", f"/api/cases/{case_id}")
        self.assertEqual(read_back.status_code, 200, read_back.text)
        self.assertEqual(read_back.json()["title"], "Sysmon investigation")

        notes = self.request_as("viewer", self.tenant_a, "GET", f"/api/cases/{case_id}/notes")
        self.assertEqual(notes.status_code, 200, notes.text)
        self.assertEqual(len(notes.json()), 1)

        audit = self.request_as("lead", self.tenant_a, "GET", "/api/audit")
        self.assertEqual(audit.status_code, 200, audit.text)
        self.assertTrue(any(item["action"] == "case.create" for item in audit.json()))

    def test_database_role_cannot_read_users_outside_selected_tenant(self):
        with psycopg.connect(self.app_dsn) as conn:
            with conn.transaction():
                conn.execute(
                    "SELECT set_config('soc_io.tenant_id', %s, true)",
                    (str(self.tenant_a),),
                )
                visible = conn.execute(
                    "SELECT id FROM socio_users WHERE id = %s",
                    (self.alice,),
                ).fetchall()
                hidden = conn.execute(
                    "SELECT id FROM socio_users WHERE id = %s",
                    (self.bob,),
                ).fetchall()
                self.assertEqual(len(visible), 1)
                self.assertEqual(hidden, [])

    def test_tenant_membership_is_required(self):
        response = self.request_as("alice", self.tenant_b, "GET", "/api/cases")
        self.assertEqual(response.status_code, 403)

    def test_viewer_cannot_create_case(self):
        response = self.request_as(
            "viewer", self.tenant_a, "POST", "/api/cases",
            json={"title": "Should be denied", "severity": "low"},
        )
        self.assertEqual(response.status_code, 403)

    def test_analyst_cannot_close_case_without_incident_lead(self):
        created = self.request_as(
            "alice", self.tenant_a, "POST", "/api/cases",
            json={"title": "Role test", "severity": "low"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        response = self.request_as(
            "alice", self.tenant_a, "PATCH", f"/api/cases/{created.json()['id']}",
            json={"status": "closed"},
        )
        self.assertEqual(response.status_code, 403)

    def test_cross_tenant_case_is_not_visible(self):
        created_b = self.request_as(
            "bob", self.tenant_b, "POST", "/api/cases",
            json={"title": "Tenant B case", "severity": "high"},
        )
        self.assertEqual(created_b.status_code, 201, created_b.text)
        response = self.request_as(
            "alice", self.tenant_a, "GET", f"/api/cases/{created_b.json()['id']}",
        )
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
