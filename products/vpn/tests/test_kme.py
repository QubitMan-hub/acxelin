"""The key server for existing gateways: two sites' servers agree a secret over post-quantum mutual TLS, a gateway at one site gets
keys over ETSI GS QKD 014 and the gateway at the other gets the same keys by ID, once each. Gateways that are not this site's,
keys asked for twice, unknown sites and secrets rotated out are refused."""
import datetime as dt
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acxelin_core import https, tls
from acxelin_core.pki import CA
from acxelin_vpn import kme, qkd
from support_vpn import REASON


def classical(folder, names):
    """A classical CA, like a firewall vendor's, with a server certificate for localhost and one client certificate per name."""
    now = dt.datetime.now(dt.timezone.utc)

    def make(cn, issuer_key=None, issuer=None, ca=False, san=None):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name).public_key(key.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        if ca:
            b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), critical=False)
        cert = b.sign(issuer_key or key, hashes.SHA256())
        return key, cert

    folder.mkdir(parents=True)
    ca_key, ca_cert = make("Firewall Vendor CA", ca=True)
    (folder / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    for cn in ["localhost", *names]:
        key, cert = make(cn, ca_key, ca_cert.subject, san=cn)
        (folder / f"{cn}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (folder / f"{cn}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return folder


@unittest.skipIf(REASON, REASON)
class KMETest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        ca = CA.init(self.d / "pki", "VPN Root")
        ca.crl()
        for n in ("kme-a", "kme-b"):
            ca.issue(n, "site", ["localhost"], out=self.d / n)
        self.fw = classical(self.d / "fw", ["fw-a", "fw-b", "fw-x"])
        b = self.server("kme-b", ["fw-b"], [kme.KMEPeer("kme-a", ["fw-a"])])
        self.a = self.server("kme-a", ["fw-a"], [kme.KMEPeer("kme-b", ["fw-b"], f"localhost:{b.keyring.port}")], start=False)
        self.b = b
        self.a.start()
        self.addCleanup(self.a.shutdown)
        self.addCleanup(self.b.shutdown)
        for _ in range(100):
            if self.a.secrets["kme-b"] and self.b.secrets["kme-a"]:
                break
            __import__("time").sleep(0.05)

    def server(self, name, saes, peers, start=True):
        cfg = kme.KMEConfig(name=name, listen="127.0.0.1:0", tls_cert=str(self.fw / "localhost.pem"), tls_key=str(self.fw / "localhost.key"),
                            sae_ca=str(self.fw / "ca.pem"), saes=saes, keyring_listen="127.0.0.1:0", cert=str(self.d / name / "chain.pem"),
                            key=str(self.d / name / "key.pem"), ca=str(self.d / "pki" / "ca.crt"), peers=peers,
                            crl=str(self.d / "pki" / "crl.pem")).validate()
        k = kme.KME(cfg)
        if start:
            k.start()
        return k

    def gateway(self, server, sae):
        return qkd.KME(f"https://localhost:{server.https.server_address[1]}", sae, str(self.fw / "ca.pem"), str(self.fw / f"{sae}.pem"),
                       str(self.fw / f"{sae}.key"))

    def call(self, server, sae, path, body=None):
        ctx = tls.client_context(qkd.KME_POLICY, str(self.fw / "ca.pem"), str(self.fw / f"{sae}.pem"), str(self.fw / f"{sae}.key"))
        with tls.connect("localhost", server.https.server_address[1], ctx, "localhost", 10) as conn:
            status, _, raw = https.request(conn, "POST" if body is not None else "GET", path, "localhost",
                                           json.dumps(body).encode() if body is not None else b"", {"Content-Type": "application/json"})
        return status, json.loads(raw)

    def test_two_sites_gateways_get_the_same_key_once_each(self):
        kid, key = self.gateway(self.a, "fw-a").new_key("fw-b")
        self.assertEqual(self.gateway(self.b, "fw-b").key("fw-a", kid), key)
        with self.assertRaisesRegex(qkd.QKDError, "400"):
            self.gateway(self.b, "fw-b").key("fw-a", kid)

    def test_several_keys_of_any_size_and_the_status_a_gateway_reads(self):
        status, got = self.call(self.a, "fw-a", "/api/v1/keys/fw-b/enc_keys", {"number": 3, "size": 512})
        self.assertEqual(status, 200)
        self.assertEqual([len(__import__("base64").b64decode(k["key"])) for k in got["keys"]], [64, 64, 64])
        status, back = self.call(self.b, "fw-b", "/api/v1/keys/fw-a/dec_keys", {"key_IDs": [{"key_ID": k["key_ID"]} for k in got["keys"]]})
        self.assertEqual((status, back["keys"]), (200, got["keys"]))
        status, s = self.call(self.a, "fw-a", "/api/v1/keys/fw-b/status")
        self.assertEqual((status, s["source_KME_ID"], s["target_KME_ID"], s["slave_SAE_ID"]), (200, "kme-a", "kme-b", "fw-b"))

    def test_a_gateway_that_speaks_only_tls_1_2_is_served(self):
        import http.client
        import ssl
        ctx = ssl.create_default_context(cafile=str(self.fw / "ca.pem"))
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(self.fw / "fw-a.pem"), str(self.fw / "fw-a.key"))
        c = http.client.HTTPSConnection("localhost", self.a.https.server_address[1], context=ctx, timeout=10)
        c.request("POST", "/api/v1/keys/fw-b/enc_keys", body=b'{"number": 1}', headers={"Content-Type": "application/json"})
        version = c.sock.version()
        r = c.getresponse()
        self.assertEqual((r.status, version), (200, "TLSv1.2"))
        self.assertEqual(len(json.loads(r.read())["keys"]), 1)

    def test_what_is_refused(self):
        self.assertEqual(self.call(self.a, "fw-x", "/api/v1/keys/fw-b/enc_keys", {})[0], 401, "a gateway of no site here")
        self.assertEqual(self.call(self.a, "fw-a", "/api/v1/keys/fw-q/enc_keys", {})[0], 400, "a gateway at no known site")
        self.assertEqual(self.call(self.a, "fw-a", "/api/v1/keys/fw-b/enc_keys", {"size": 100})[0], 400)
        self.assertEqual(self.call(self.a, "fw-a", "/api/v1/keys/fw-b/enc_keys", {"number": 99})[0], 400)
        kid, _ = self.gateway(self.a, "fw-a").new_key("fw-b")
        status, body = self.call(self.b, "fw-b", "/api/v1/keys/fw-a/dec_keys", {"key_IDs": [{"key_ID": kid}, {"key_ID": kid}]})
        self.assertEqual(status, 400, "the same key twice in one request")
        self.assertEqual(self.gateway(self.b, "fw-b").key("fw-a", kid) and 1, 1, "a refused request hands nothing out")

    def test_a_key_from_a_secret_rotated_out_is_gone(self):
        kid, _ = self.gateway(self.a, "fw-a").new_key("fw-b")
        for _ in range(kme.EPOCHS):
            self.a.agree(self.a.cfg.peers[0])
        with self.assertRaisesRegex(qkd.QKDError, "400"):
            self.gateway(self.b, "fw-b").key("fw-a", kid)

    def test_a_peer_with_another_name_gets_no_secret(self):
        impostor = kme.KMEPeer("kme-c", ["fw-b"], f"localhost:{self.b.keyring.port}")
        with self.assertRaisesRegex(tls.TLSError, "hostname mismatch|presented"):  # refused by the certificate check, or by the name check after it
            self.a.agree(impostor)

    def test_a_key_server_the_other_site_does_not_know_gets_no_secret(self):
        CA(self.d / "pki").issue("kme-c", "site", ["localhost"], out=self.d / "kme-c")
        stranger = self.server("kme-c", ["fw-x"], [kme.KMEPeer("kme-b", ["fw-b"], f"localhost:{self.b.keyring.port}")], start=False)
        with self.assertRaisesRegex(tls.TLSError, "refused"):
            stranger.agree(stranger.cfg.peers[0])
        self.assertNotIn("kme-c", self.b.secrets)


class ConfigTest(unittest.TestCase):
    def test_the_shipped_example_loads_and_mistakes_are_named(self):
        cfg = kme.load(Path(__file__).resolve().parents[1] / "config" / "kme.toml")
        self.assertEqual(cfg.peers[0].saes, ["fw-branch1"])
        base = dict(name="a", listen="0.0.0.0:8443", tls_cert="c", tls_key="k", sae_ca="s", saes=["fw-a"], keyring_listen="0.0.0.0:7445",
                    cert="c", key="k", ca="a")
        for bad, words in (({"saes": []}, "at least one"), ({"saes": ["fw a"]}, "SAE IDs"), ({"key_size": 100}, "multiple of 8"),
                           ({"peers": [kme.KMEPeer("b", ["fw-a"])]}, "one site only"), ({"rotate_minutes": 0}, "rotate_minutes")):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, words):
                kme.KMEConfig(**(base | bad)).validate()

    def test_a_key_id_names_its_epoch_and_length(self):
        kid = kme.key_id("a1b2c3d4e5f6", 32)
        self.assertEqual(kme.parse_id(kid), ("a1b2c3d4e5f6", 32))
        self.assertEqual(len(kid), 36)
        self.assertEqual(kme.parse_id("not-a-uuid"), (None, 0))


if __name__ == "__main__":
    unittest.main()
