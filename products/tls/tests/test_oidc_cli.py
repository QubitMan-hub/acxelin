"""A person enrols with the ID token their identity provider issued, through the installed commands."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from acxelin_core.pki import CA
from acxelin_core.pki.est import fingerprint

from support_tls import REASON
from test_enroll import free_port, wait_port

ISSUER, AUDIENCE = "https://idp.corp.example", "acxelin-enroll"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def number(n):
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


@unittest.skipIf(REASON, REASON)
class OidcEnrolTest(unittest.TestCase):
    def test_sign_in_token_to_certificate(self):
        key = rsa.generate_private_key(65537, 2048)
        pub = key.public_key().public_numbers()

        def token(**claims):
            now = int(time.time())
            body = {"iss": ISSUER, "aud": AUDIENCE, "email": "ana@corp.example", "email_verified": True, "exp": now + 600, "iat": now,
                    "groups": ["pki-users"], **claims}
            signing = f"{b64(json.dumps({'alg': 'RS256', 'kid': 'k'}).encode())}.{b64(json.dumps(body).encode())}"
            return f"{signing}.{b64(key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256()))}"

        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ca = CA.init(d / "pki", "Root")
            est_dir, _ = ca.issue("ca.internal", "server", ["127.0.0.1"], out=d / "est")
            (d / "keys.json").write_text(json.dumps({"keys": [{"kty": "RSA", "kid": "k", "n": number(pub.n), "e": number(pub.e)}]}))
            run = lambda *a, **kw: subprocess.run([sys.executable, "-m", "acxelin_tls", *map(str, a)], capture_output=True, text=True, timeout=60, **kw)

            r = run("ca", "oidc", "--dir", d / "pki", "--issuer", "http://idp.corp.example", "--audience", AUDIENCE, "--jwks-file", d / "keys.json")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("https", r.stderr + r.stdout)
            r = run("ca", "oidc", "--dir", d / "pki", "--issuer", ISSUER, "--audience", AUDIENCE, "--jwks-file", d / "keys.json",
                    "--domain", "corp.example", "--group", "pki-users")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

            port = free_port()
            server = subprocess.Popen([sys.executable, "-m", "acxelin_tls", "ca", "serve", "--dir", str(d / "pki"), "--listen", f"127.0.0.1:{port}",
                                       "--cert", str(est_dir / "chain.pem"), "--key", str(est_dir / "key.pem")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(server.wait, 10)
            self.addCleanup(server.terminate)
            wait_port(port)
            enroll = ["ca", "enroll", f"https://127.0.0.1:{port}", "--oidc", "--ca-fingerprint", fingerprint(ca.cert), "--server-name", "ca.internal"]

            good = token()
            r = run(*enroll, "--cn", "ana@corp.example", "--out", d / "ana", env={**os.environ, "ACXELIN_TLS_OIDC_TOKEN": good})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((d / "ana" / "cert.pem").exists())
            self.assertNotIn(good, r.stdout + r.stderr)

            r = run(*enroll, "--cn", "ana@corp.example", "--out", d / "again", env={**os.environ, "ACXELIN_TLS_OIDC_TOKEN": good})
            self.assertNotEqual(r.returncode, 0, "a token works once")
            self.assertIn("already used", r.stderr + r.stdout)
            self.assertNotIn(good, r.stdout + r.stderr)

            bad = token(email="mallory@evil.example")
            r = run(*enroll, "--cn", "mallory@evil.example", "--out", d / "m", env={**os.environ, "ACXELIN_TLS_OIDC_TOKEN": bad})
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("domain", r.stderr + r.stdout)
            self.assertNotIn(bad, r.stdout + r.stderr)
            self.assertNotIn(bad, (d / "pki" / "est-audit.jsonl").read_text())

            env = {k: v for k, v in os.environ.items() if k != "ACXELIN_TLS_OIDC_TOKEN"}
            r = run(*enroll, "--cn", "ana@corp.example", "--out", d / "none", env=env, input="")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("ACXELIN_TLS_OIDC_TOKEN", r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main()
