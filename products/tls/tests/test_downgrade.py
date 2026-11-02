"""Downgrade and confusion: every pairing of server and client policy, plus attackers that offer only classical key exchange,
only TLS 1.2, the wrong ML-DSA size, or a certificate issued for the other role. Two post-quantum peers must never end up
classical, and strict or cnsa2 must refuse whatever they do not allow. Needs OpenSSL 3.5+."""
import datetime as dt
import ipaddress
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acxelin_core import tls
import support_tls
from acxelin_core.pki import CA, algorithm_of
from acxelin_tls.policies import CIPHERSUITES, PQC_GROUPS
from acxelin_core.openssl import Context
from support_tls import REASON


CLASSICAL = "X25519:secp256r1"
REFUSED = "refused"


@unittest.skipIf(REASON, REASON)
class DowngradeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.d = Path(cls.tmp.name)
        ca = CA.init(d / "pki", "Root")
        cls.cafile = str(d / "pki" / "ca.crt")
        cls.s65, _ = ca.issue("localhost", "server", ["127.0.0.1"], out=d / "s65")
        cls.s87, _ = ca.issue("localhost", "server", ["127.0.0.1"], algorithm="ML-DSA-87", out=d / "s87")
        cls.c65, _ = ca.issue("alice", "client", out=d / "c65")
        cls.c87, _ = ca.issue("bob", "client", algorithm="ML-DSA-87", out=d / "c87")
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        fb = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
              .not_valid_before(dt.datetime(2020, 1, 1)).not_valid_after(dt.datetime(2040, 1, 1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
              .sign(key, hashes.SHA256()))
        (d / "fb.crt").write_bytes(fb.public_bytes(serialization.Encoding.PEM))
        (d / 'both.crt').write_bytes((d / 'pki' / 'ca.crt').read_bytes() + fb.public_bytes(serialization.Encoding.PEM))
        (d / "fb.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.listeners = []

    @classmethod
    def tearDownClass(cls):
        for s in cls.listeners:
            s.close()
        cls.tmp.cleanup()

    def serve(self, ctx):
        s = socket.create_server(("127.0.0.1", 0))
        self.listeners.append(s)

        def run():
            while True:
                try:
                    c, _ = s.accept()
                except OSError:
                    return

                def one(c=c):
                    try:
                        conn = ctx.wrap(c, timeout=5)
                        conn.sendall(b"ok")
                        conn.close()
                    except Exception:
                        c.close()
                threading.Thread(target=one, daemon=True).start()
        threading.Thread(target=run, daemon=True).start()
        return s.getsockname()[1]

    def attempt(self, port, ctx):
        try:
            with tls.connect("127.0.0.1", port, ctx, "localhost", 5) as c:
                if c.recv(timeout=5) != b"ok":
                    return REFUSED
                return c.info()["group"], algorithm_of(c.peer_certificate().public_key())
        except (tls.TLSError, OSError):
            return REFUSED

    def tls12(self, port):
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname, c.verify_mode, c.maximum_version = False, ssl.CERT_NONE, ssl.TLSVersion.TLSv1_2
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, c.wrap_socket(raw):
                return "accepted"
        except (ssl.SSLError, OSError):
            return REFUSED

    def test_policy_matrix(self):
        s65, s87 = self.s65, self.s87
        servers = {"strict": support_tls.server_context(s65 / "chain.pem", s65 / "key.pem", policy_name="strict"),
                   "transition": support_tls.server_context(s65 / "chain.pem", s65 / "key.pem", policy_name="transition",
                                                    fallback=(str(self.d / "fb.crt"), str(self.d / "fb.key"))),
                   "cnsa2": support_tls.server_context(s87 / "chain.pem", s87 / "key.pem", policy_name="cnsa2"),
                   "classical": Context(True, CLASSICAL, None, CIPHERSUITES, str(s65 / "chain.pem"), str(s65 / "key.pem"))}
        clients = {"strict": support_tls.client_context(self.cafile, policy_name="strict"),
                   "transition": support_tls.client_context(self.d / "both.crt", policy_name="transition"),
                   "cnsa2": support_tls.client_context(self.cafile, policy_name="cnsa2"),
                   "classical": Context(False, CLASSICAL, None, CIPHERSUITES, ca=str(self.d / "both.crt"))}
        pq65, pq87, weak = ("X25519MLKEM768", "ML-DSA-65"), ("MLKEM1024", "ML-DSA-87"), ("x25519", "ML-DSA-65")
        expected = {
            ("strict", "strict"): pq65, ("strict", "transition"): pq65, ("strict", "cnsa2"): REFUSED, ("strict", "classical"): REFUSED,
            ("transition", "strict"): pq65, ("transition", "transition"): ("X25519MLKEM768", None), ("transition", "cnsa2"): REFUSED,
            ("transition", "classical"): ("x25519", None),
            ("cnsa2", "strict"): REFUSED, ("cnsa2", "transition"): REFUSED, ("cnsa2", "cnsa2"): pq87,  # only pure ML-KEM-1024 is CNSA 2.0
             ("cnsa2", "classical"): REFUSED,
            ("classical", "strict"): REFUSED, ("classical", "transition"): weak, ("classical", "cnsa2"): REFUSED,
            ("classical", "classical"): weak,
        }
        ports = {name: self.serve(ctx) for name, ctx in servers.items()}
        for (server, client), want in expected.items():
            with self.subTest(server=server, client=client):
                self.assertEqual(self.attempt(ports[server], clients[client]), want)
        for server, port in ports.items():
            with self.subTest(server=server, client="TLS 1.2"):
                self.assertEqual(self.tls12(port), REFUSED)

    def test_cnsa2_client_certificates_must_be_ml_dsa_87(self):
        port = self.serve(support_tls.server_context(self.s87 / "chain.pem", self.s87 / "key.pem", self.cafile, True, "cnsa2"))
        def client(name):  # offers what cnsa2 needs, so only the client certificate decides
            return Context(False, "MLKEM1024", "mldsa87", "TLS_AES_256_GCM_SHA384", str(self.d / name / "chain.pem"), str(self.d / name / "key.pem"), ca=str(self.cafile))
        ok, small = client("c87"), client("c65")
        self.assertEqual(self.attempt(port, ok), ("MLKEM1024", "ML-DSA-87"))
        self.assertEqual(self.attempt(port, small), REFUSED)

    def test_certificates_only_work_in_their_own_role(self):
        wrong_server = self.serve(support_tls.server_context(self.c65 / "chain.pem", self.c65 / "key.pem"))
        self.assertEqual(self.attempt(wrong_server, support_tls.client_context(self.cafile)), REFUSED)
        mtls = self.serve(support_tls.server_context(self.s65 / "chain.pem", self.s65 / "key.pem", self.cafile, True))
        self.assertEqual(self.attempt(mtls, support_tls.client_context(self.cafile, self.s65 / "chain.pem", self.s65 / "key.pem")), REFUSED)
        self.assertEqual(self.attempt(mtls, support_tls.client_context(self.cafile, self.c65 / "chain.pem", self.c65 / "key.pem")),
                         ("X25519MLKEM768", "ML-DSA-65"))

    def test_transition_fallback_is_trusted_by_a_dual_capability_browser_client(self):
        port = self.serve(support_tls.server_context(self.s65 / 'chain.pem', self.s65 / 'key.pem', policy_name='transition',
                                           fallback=(str(self.d / 'fb.crt'), str(self.d / 'fb.key'))))
        browser = Context(False, PQC_GROUPS, 'mldsa65:ecdsa_secp256r1_sha256', CIPHERSUITES, ca=str(self.d / 'fb.crt'))
        try:
            with tls.connect('127.0.0.1', port, browser, 'localhost') as conn:
                self.assertEqual(conn.recv(), b'ok')
                self.assertEqual(conn.group, 'X25519MLKEM768')
                self.assertEqual(conn.info()['peer_key'], '1.2.840.10045.2.1')
        finally:
            browser.close()
        strict = support_tls.client_context(self.cafile)
        try:
            self.assertEqual(self.attempt(port, strict), ('X25519MLKEM768', 'ML-DSA-65'))
        finally:
            strict.close()


if __name__ == "__main__":
    unittest.main()

