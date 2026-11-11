import base64
import json
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from acxelin_core.pki import CA, CAError, est, oidc
from support import REASON

ISSUER = "https://idp.corp.example"
AUDIENCE = "acxelin-enroll"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def int_b64(n):
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class Idp:
    """A stand-in identity provider: signs ID tokens and publishes its keys as a JWKS."""

    def __init__(self, kid="k1", kind="RS256"):
        self.kid, self.kind = kid, kind
        self.key = rsa.generate_private_key(65537, 2048) if kind == "RS256" else ec.generate_private_key(ec.SECP256R1())

    def jwk(self):
        n = self.key.public_key().public_numbers()
        if self.kind == "RS256":
            return {"kty": "RSA", "kid": self.kid, "alg": "RS256", "use": "sig", "n": int_b64(n.n), "e": int_b64(n.e)}
        return {"kty": "EC", "kid": self.kid, "alg": "ES256", "crv": "P-256", "x": int_b64(n.x), "y": int_b64(n.y)}

    def jwks(self):
        return {"keys": [self.jwk()]}

    def sign(self, signing_input):
        if self.kind == "RS256":
            return self.key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        r, s = utils.decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def token(self, header=None, **claims):
        now = int(time.time())
        body = {"iss": ISSUER, "aud": AUDIENCE, "sub": "u-1", "email": "ana@corp.example", "email_verified": True,
                "iat": now, "exp": now + 600, "groups": ["pki-users"], **claims}
        body = {k: v for k, v in body.items() if v is not None}
        head = {"alg": self.kind, "typ": "JWT", "kid": self.kid, **(header or {})}
        signing = f"{b64(json.dumps(head).encode())}.{b64(json.dumps(body).encode())}"
        return f"{signing}.{b64(self.sign(signing.encode()))}"


def policy(idp, **over):
    return oidc.Policy(**{"issuer": ISSUER, "audience": AUDIENCE, "jwks": idp.jwks(), "name_claim": "email",
                          "domains": ["corp.example"], "groups_claim": "groups", "groups": ["pki-users"], **over})


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.idp = Idp()
        self.policy = policy(self.idp)

    def refused(self, token, pattern, pol=None):
        with self.assertRaisesRegex(CAError, pattern):
            oidc.verify(token, pol or self.policy)

    def test_a_good_token_gives_the_name_it_vouches_for(self):
        self.assertEqual(oidc.verify(self.idp.token(), self.policy)[0], "ana@corp.example")
        es = Idp(kind="ES256")
        self.assertEqual(oidc.verify(es.token(), policy(es))[0], "ana@corp.example")

    def test_a_token_from_another_issuer_or_for_another_service_is_refused(self):
        self.refused(self.idp.token(iss="https://evil.example"), "issuer")
        self.refused(self.idp.token(aud="some-other-app"), "audience")
        self.assertTrue(oidc.verify(self.idp.token(aud=["x", AUDIENCE]), self.policy))

    def test_time_is_checked_both_ways(self):
        now = int(time.time())
        self.refused(self.idp.token(exp=now - 600), "expired")
        self.refused(self.idp.token(nbf=now + 3600), "not valid yet")
        self.refused(self.idp.token(exp=None), "expiry")

    def test_a_forged_or_altered_token_is_refused(self):
        other = Idp()  # same kid, different key
        self.refused(other.token(), "signature")
        head, body, sig = self.idp.token().split(".")
        forged = json.loads(base64.urlsafe_b64decode(body + "=="))
        forged["email"] = "ceo@corp.example"
        self.refused(f"{head}.{b64(json.dumps(forged).encode())}.{sig}", "signature")
        self.refused(self.idp.token(header={"kid": "unknown"}), "no key")

    def test_only_rs256_and_es256_are_accepted(self):
        for alg in ("none", "HS256", "RS512", "PS256"):
            self.refused(self.idp.token(header={"alg": alg}), "algorithm")
        # key confusion: an HMAC token keyed with the public key's bytes must not verify
        import hmac
        signing = f"{b64(json.dumps({'alg': 'HS256', 'kid': 'k1'}).encode())}.{b64(json.dumps({'iss': ISSUER, 'aud': AUDIENCE, 'exp': int(time.time()) + 99, 'email': 'a@corp.example'}).encode())}"
        mac = hmac.new(json.dumps(self.idp.jwk()).encode(), signing.encode(), "sha256").digest()
        self.refused(f"{signing}.{b64(mac)}", "algorithm")
        self.refused("not.a.token", "token")
        self.refused("x" * 20000, "too long")

    def test_a_weak_key_in_the_key_set_is_refused(self):
        weak = Idp()
        weak.key = rsa.generate_private_key(65537, 1024)
        self.refused(weak.token(), "2048", policy(weak))

    def test_the_name_must_be_verified_and_from_an_allowed_domain_and_group(self):
        self.refused(self.idp.token(email_verified=False), "verified")
        self.refused(self.idp.token(email="mallory@evil.example"), "domain")
        self.refused(self.idp.token(email="ana@corp.example.evil.example"), "domain")
        self.refused(self.idp.token(groups=["interns"]), "group")
        self.refused(self.idp.token(groups=None), "group")
        self.refused(self.idp.token(email=None), "email")
        self.refused(self.idp.token(email="a" * 70 + "@corp.example"), "64")

    def test_the_configuration_is_checked_when_it_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            ca = CA.init(Path(d) / "pki", "Root")
            with self.assertRaisesRegex(CAError, "https"):
                oidc.configure(ca, "http://idp.example", AUDIENCE, jwks_url="https://idp.example/keys")
            with self.assertRaisesRegex(CAError, "exactly one"):
                oidc.configure(ca, ISSUER, AUDIENCE)
            with self.assertRaisesRegex(CAError, "https"):
                oidc.configure(ca, ISSUER, AUDIENCE, jwks_url="http://idp.example/keys")
            with self.assertRaisesRegex(CAError, "domain"):
                oidc.configure(ca, ISSUER, AUDIENCE, jwks_file="k.json", name_claim="sub", domains=["corp.example"])

    def test_keys_come_from_a_file_or_from_a_https_address_and_a_failed_fetch_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            ca = CA.init(Path(d) / "pki", "Root")
            keys = Path(d) / "keys.json"
            keys.write_text(json.dumps(self.idp.jwks()))
            oidc.configure(ca, ISSUER, AUDIENCE, jwks_file=str(keys), domains=["corp.example"], groups=["pki-users"])
            self.assertEqual(oidc.verify(self.idp.token(), oidc.load(ca.root))[0], "ana@corp.example")
            keys.write_text("not json")
            with self.assertRaisesRegex(CAError, "key set"):
                oidc.verify(self.idp.token(), oidc.load(ca.root))
            oidc.configure(ca, ISSUER, AUDIENCE, jwks_url="https://idp.corp.example/keys", domains=["corp.example"])
            pol = oidc.load(ca.root)
            calls = []
            pol.fetch = lambda url: calls.append(url) or json.dumps(self.idp.jwks()).encode()
            oidc.verify(self.idp.token(groups=None), pol)
            oidc.verify(self.idp.token(groups=None), pol)
            self.assertEqual(calls, ["https://idp.corp.example/keys"])  # kept for a few minutes
            fresh = oidc.load(ca.root)
            fresh.fetch = lambda url: (_ for _ in ()).throw(OSError("network down"))
            with self.assertRaisesRegex(CAError, "cannot fetch the identity provider's keys"):
                oidc.verify(self.idp.token(), fresh)


@unittest.skipIf(REASON, REASON)
class EnrolTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.idp = Idp()
        self.ca = CA.init(self.d / "pki", "Enrollment Root")
        keys = self.d / "keys.json"
        keys.write_text(json.dumps(self.idp.jwks()))
        oidc.configure(self.ca, ISSUER, AUDIENCE, jwks_file=str(keys), domains=["corp.example"], groups=["pki-users"])
        srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=self.d / "srv")
        self.server = est.serve(self.d / "pki", "127.0.0.1:0", srv / "chain.pem", srv / "key.pem")
        self.server.start()
        self.addCleanup(self.server.stop, 1)
        self.url = f"https://localhost:{self.server.port}"
        self.cafile = self.d / "pki" / "ca.crt"

    def enrol(self, token, cn="ana@corp.example", out="ana", **kw):
        return est.enroll(self.url, token, cn, [], self.d / out, self.cafile, oidc=True, **kw)

    def test_a_person_gets_a_client_certificate_for_the_name_the_provider_vouches_for(self):
        token = self.idp.token()
        cert = self.enrol(token)
        cert.verify_directly_issued_by(self.ca.cert)
        self.assertEqual(cert.subject.rfc4514_string(), "CN=ana@corp.example")
        rec = next(r for r in self.ca.records() if r.common_name == "ana@corp.example")
        self.assertEqual(rec.kind, "client")
        log = (self.d / "pki" / "est-audit.jsonl").read_text()
        self.assertIn('"oidc_enrolled"', log)
        for secret in (token, token.split(".")[2]):
            self.assertNotIn(secret, log)
            self.assertNotIn(secret, "".join(p.read_text(errors="ignore") for p in (self.d / "pki").glob("*.json*")))

    def test_a_token_works_once(self):
        token = self.idp.token()
        self.enrol(token)
        with self.assertRaisesRegex(CAError, "401.*already used"):
            self.enrol(token, out="again")
        self.assertFalse((self.d / "again" / "cert.pem").exists())

    def test_the_certificate_name_cannot_differ_from_the_person(self):
        with self.assertRaisesRegex(CAError, "403.*ana@corp.example"):
            self.enrol(self.idp.token(), cn="ceo@corp.example")
        self.assertEqual([r for r in self.ca.records() if r.kind == "client"], [])
        with self.assertRaisesRegex(CAError, "403"):
            est.enroll(self.url, self.idp.token(), "ana@corp.example", ["db.corp.example"], self.d / "x", self.cafile, oidc=True)

    def test_refusals_are_401_and_name_the_reason_without_the_token(self):
        for token, reason in ((self.idp.token(exp=int(time.time()) - 900), "expired"),
                              (self.idp.token(email="x@evil.example"), "domain"),
                              (Idp().token(), "signature")):
            with self.assertRaisesRegex(CAError, f"401.*{reason}") as caught:
                self.enrol(token, out="no")
            self.assertNotIn(token, str(caught.exception))
        log = (self.d / "pki" / "est-audit.jsonl").read_text()
        self.assertEqual(log.count('"enroll_refused"'), 3)

    def test_without_a_configuration_a_bearer_token_is_not_accepted(self):
        (self.d / "pki" / "oidc.json").unlink()
        with self.assertRaisesRegex(CAError, "401.*not set up"):
            self.enrol(self.idp.token())

    def test_a_classical_key_does_not_spend_the_token(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.serialization import Encoding
        import support
        token = self.idp.token()
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ana@corp.example")]))
               .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()))
        with self.assertRaisesRegex(CAError, "403.*ML-DSA"):
            est._call(self.url, support.client_context(self.cafile), "/simpleenroll", base64.encodebytes(csr.public_bytes(Encoding.DER)),
                      {"Content-Type": "application/pkcs10", "Authorization": f"Bearer {token}"}, "localhost")
        self.enrol(token)


if __name__ == "__main__":
    unittest.main()
