"""Integration tests exercise PyJWT/JWKS over real HTTPS, not a mocked verifier.

This is a local test issuer, not a substitute for staging tests against the selected
identity provider. A self-signed certificate is trusted only by this test process.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from service.app import verify_token


def b64url_int(value: int) -> str:
    import base64
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


class LocalJwksHandler(BaseHTTPRequestHandler):
    jwks_payload = b"{}"

    def do_GET(self):
        if self.path != "/jwks":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(self.jwks_payload)

    def log_message(self, fmt, *args):
        pass


class OidcJwksIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_numbers = cls.private_key.public_key().public_numbers()
        cls.kid = "soc-io-test-key-1"
        LocalJwksHandler.jwks_payload = json.dumps({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": cls.kid,
                "n": b64url_int(public_numbers.n),
                "e": b64url_int(public_numbers.e),
            }]
        }).encode()

        cls.tempdir = tempfile.TemporaryDirectory()
        cls.cert_path = Path(cls.tempdir.name) / "localhost-cert.pem"
        cls.key_path = Path(cls.tempdir.name) / "localhost-key.pem"
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(cls.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.private_key, hashes.SHA256())
        )
        cls.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        cls.key_path.write_bytes(cls.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalJwksHandler)
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert_path), str(cls.key_path))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.jwks_url = f"https://localhost:{cls.server.server_port}/jwks"
        cls.env = {
            "SOCIO_OIDC_ISSUER": "https://issuer.soc-io.test",
            "SOCIO_OIDC_AUDIENCE": "soc-io-test-api",
            "SOCIO_OIDC_JWKS_URL": cls.jwks_url,
        }

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        cls.tempdir.cleanup()

    def make_token(self, **overrides):
        now = datetime.now(timezone.utc)
        claims = {
            "iss": self.env["SOCIO_OIDC_ISSUER"],
            "aud": self.env["SOCIO_OIDC_AUDIENCE"],
            "sub": "integration-test-user",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        }
        claims.update(overrides)
        return jwt.encode(
            claims, self.private_key, algorithm="RS256",
            headers={"kid": self.kid, "typ": "JWT"},
        )

    def verify(self, token):
        import ssl
        trusted_context = lambda: ssl.create_default_context(cafile=str(self.cert_path))
        with patch.dict(os.environ, self.env, clear=False):
            # PyJWKClient uses urllib, so trust this test-only certificate through
            # Python's HTTPS context rather than a requests-specific CA setting.
            with patch("ssl._create_default_https_context", side_effect=trusted_context):
                return verify_token(token)

    def test_valid_signed_token_is_verified_via_https_jwks(self):
        claims = self.verify(self.make_token())
        self.assertEqual(claims["sub"], "integration-test-user")
        self.assertEqual(claims["iss"], self.env["SOCIO_OIDC_ISSUER"])
        self.assertEqual(claims["aud"], self.env["SOCIO_OIDC_AUDIENCE"])

    def test_wrong_issuer_is_rejected(self):
        with self.assertRaises(HTTPException) as caught:
            self.verify(self.make_token(iss="https://attacker.invalid"))
        self.assertEqual(caught.exception.status_code, 401)

    def test_wrong_audience_is_rejected(self):
        with self.assertRaises(HTTPException) as caught:
            self.verify(self.make_token(aud="other-api"))
        self.assertEqual(caught.exception.status_code, 401)

    def test_expired_token_is_rejected(self):
        with self.assertRaises(HTTPException) as caught:
            self.verify(self.make_token(
                iat=datetime.now(timezone.utc) - timedelta(hours=2),
                exp=datetime.now(timezone.utc) - timedelta(hours=1),
            ))
        self.assertEqual(caught.exception.status_code, 401)

    def test_wrong_signature_is_rejected(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        token = jwt.encode({
            "iss": self.env["SOCIO_OIDC_ISSUER"],
            "aud": self.env["SOCIO_OIDC_AUDIENCE"],
            "sub": "attacker",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        }, other_key, algorithm="RS256", headers={"kid": self.kid})
        with self.assertRaises(HTTPException) as caught:
            self.verify(token)
        self.assertEqual(caught.exception.status_code, 401)

    def test_algorithm_confusion_is_rejected(self):
        now = datetime.now(timezone.utc)
        token = jwt.encode({
            "iss": self.env["SOCIO_OIDC_ISSUER"],
            "aud": self.env["SOCIO_OIDC_AUDIENCE"],
            "sub": "attacker",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        }, "not-a-key", algorithm="HS256")
        with self.assertRaises(HTTPException) as caught:
            self.verify(token)
        self.assertEqual(caught.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
