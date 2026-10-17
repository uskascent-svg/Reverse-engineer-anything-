"""Optional smoke test against the configured real OIDC provider.

Supply a short-lived test access token via SOCIO_OIDC_TEST_TOKEN. Never print or
persist the token. This test is intentionally skipped when no test token is supplied.
"""
import os
import unittest

from fastapi import HTTPException

from service.app import oidc_settings, verify_token


@unittest.skipUnless(os.getenv("SOCIO_OIDC_TEST_TOKEN"), "No real-provider test token configured")
class ConfiguredOidcProviderSmokeTest(unittest.TestCase):
    def test_test_access_token_against_configured_provider_jwks(self):
        issuer, audience, _ = oidc_settings()
        claims = verify_token(os.environ["SOCIO_OIDC_TEST_TOKEN"])
        self.assertEqual(claims["iss"], issuer)
        token_audiences = claims["aud"]
        if isinstance(token_audiences, str):
            self.assertEqual(token_audiences, audience)
        else:
            self.assertIn(audience, token_audiences)
        self.assertTrue(claims.get("sub"))


if __name__ == "__main__":
    unittest.main()
