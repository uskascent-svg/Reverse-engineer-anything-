import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from service.app import (
    CASE_STATUSES,
    ROLES,
    CaseCreate,
    CaseUpdate,
    NoteCreate,
    app,
    oidc_settings,
    require_role,
    verify_token,
)


class ServiceSecurityTests(unittest.TestCase):
    def test_role_allowlist_is_explicit(self):
        self.assertEqual(ROLES, {"viewer", "analyst", "incident_lead", "administrator"})
        require_role("viewer", {"viewer"})
        with self.assertRaises(HTTPException) as denied:
            require_role("viewer", {"analyst", "incident_lead"})
        self.assertEqual(denied.exception.status_code, 403)

    def test_unknown_role_is_denied(self):
        with self.assertRaises(HTTPException):
            require_role("superuser", {"superuser"})

    def test_oidc_configuration_is_required(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "SOCIO_OIDC_ISSUER"):
                oidc_settings()

    def test_token_verification_fails_closed_without_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "SOCIO_OIDC_ISSUER"):
                verify_token("not-a-token")

    def test_jwks_url_must_use_https(self):
        with patch.dict(os.environ, {
            "SOCIO_OIDC_ISSUER": "https://issuer.example",
            "SOCIO_OIDC_AUDIENCE": "soc-io",
            "SOCIO_OIDC_JWKS_URL": "http://issuer.example/jwks",
        }, clear=True):
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                oidc_settings()

    def test_oidc_issuer_must_use_https(self):
        with patch.dict(os.environ, {
            "SOCIO_OIDC_ISSUER": "http://issuer.example",
            "SOCIO_OIDC_AUDIENCE": "soc-io",
            "SOCIO_OIDC_JWKS_URL": "https://issuer.example/jwks",
        }, clear=True):
            with self.assertRaisesRegex(RuntimeError, "issuer URL"):
                oidc_settings()

    def test_jwks_url_rejects_embedded_credentials(self):
        with patch.dict(os.environ, {
            "SOCIO_OIDC_ISSUER": "https://issuer.example",
            "SOCIO_OIDC_AUDIENCE": "soc-io",
            "SOCIO_OIDC_JWKS_URL": "https://user:password@issuer.example/jwks",
        }, clear=True):
            with self.assertRaisesRegex(RuntimeError, "HTTPS URL"):
                oidc_settings()

    def test_case_input_rejects_unknown_fields(self):
        with self.assertRaises(ValidationError):
            CaseCreate(title="Investigate alert", unreviewed_admin=True)

    def test_note_size_is_bounded(self):
        with self.assertRaises(ValidationError):
            NoteCreate(body="x" * 50001)

    def test_update_fields_are_allowlisted_by_model(self):
        with self.assertRaises(ValidationError):
            CaseUpdate(sql="DROP TABLE socio_cases")

    def test_case_statuses_are_closed_set(self):
        self.assertEqual(
            CASE_STATUSES,
            {"open", "investigating", "contained", "resolved", "closed"},
        )

    def test_api_has_no_forecast_or_response_routes(self):
        paths = {route.path for route in app.routes}
        self.assertFalse(any("forecast" in path.lower() for path in paths))
        self.assertFalse(any("response" in path.lower() for path in paths))
        self.assertIn("/api/cases", paths)
        self.assertIn("/api/audit", paths)


if __name__ == "__main__":
    unittest.main()
