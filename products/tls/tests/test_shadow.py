"""Shadow mode: an edge that serves everyone as before and reports who `strict` would refuse, without logging anything sensitive."""
import json
import logging
import socket
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from acxelin_core import tls
from acxelin_core.pki import CA
from acxelin_tls import policies, shadow
from acxelin_tls.edge import Edge, Route, metrics_text, serve_metrics
from support_tls import REASON

CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
SECRET, NAME = b"SECRET-PAYLOAD-4711", "payroll.internal.example"


def ext(kind, body):
    return kind.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def hello(groups=(0x11EC, 0x001D), sigalgs=(0x0905, 0x0804), suites=(0x1302, 0x1301), sni=None):
    exts = ext(0x000A, (2 * len(groups)).to_bytes(2, "big") + b"".join(g.to_bytes(2, "big") for g in groups))
    exts += ext(0x000D, (2 * len(sigalgs)).to_bytes(2, "big") + b"".join(s.to_bytes(2, "big") for s in sigalgs))
    if sni:
        name = sni.encode()
        exts += ext(0, (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name)
    body = b"\x03\x03" + bytes(32) + b"\x00" + (2 * len(suites)).to_bytes(2, "big") + b"".join(s.to_bytes(2, "big") for s in suites)
    body += b"\x01\x00" + len(exts).to_bytes(2, "big") + exts
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class ParseTest(unittest.TestCase):
    def test_groups_and_signature_schemes_are_named(self):
        p = shadow.parse(hello(groups=(0x0A0A, 0x11EC, 0x001D, 0x1234), sigalgs=(0x0906, 0x0804, 0xABCD)))
        self.assertEqual(p["groups"], ["grease", "X25519MLKEM768", "x25519", "0x1234"])
        self.assertEqual(p["sigalgs"], ["mldsa87", "rsa_pss_rsae_sha256", "0xabcd"])

    def test_the_server_name_and_everything_else_in_the_hello_is_not_kept(self):
        p = shadow.parse(hello(sni=NAME))
        self.assertNotIn("payroll", repr(p))
        self.assertEqual(set(p), {"groups", "sigalgs", "suites"})

    def test_garbage_truncation_and_lying_lengths_give_nothing_and_never_raise(self):
        good = hello()
        junk = [b"", b"\x16\x03\x01", b"GET / HTTP/1.1\r\n\r\n", good[:20], good[:-3], good[:5] + b"\xff" * (len(good) - 5),
                good.replace(b"\x00\x0a\x00\x06", b"\x00\x0a\xff\xff", 1), b"\x16\x03\x01\x00\x04\x02\x00\x00\x00"]
        for data in junk:
            self.assertIsNone(shadow.parse(data), data[:12])

    def test_a_huge_list_is_cut_short_so_one_client_cannot_fill_the_log(self):
        p = shadow.parse(hello(groups=tuple(range(0x2000, 0x2000 + 3000)), sigalgs=tuple(range(0x2000, 0x2400))))
        self.assertLessEqual(len(p["groups"]), shadow.LIMIT + 1)
        self.assertLessEqual(len(p["sigalgs"]), shadow.LIMIT + 1)
        self.assertTrue(p["groups"][-1].startswith("+"))

    def test_strict_wants_a_post_quantum_group_and_a_signature_scheme_for_ml_dsa_certificates(self):
        self.assertEqual(shadow.reasons("strict", shadow.parse(hello())), [])
        classical = shadow.parse(hello(groups=(0x001D, 0x0017), sigalgs=(0x0905,)))
        self.assertEqual(shadow.reasons("strict", classical), ["no post-quantum key exchange offered"])
        blind = shadow.parse(hello(sigalgs=(0x0804, 0x0403)))
        self.assertEqual(shadow.reasons("strict", blind), ["cannot verify ML-DSA certificates"])
        both = shadow.parse(hello(groups=(0x001D,), sigalgs=(0x0804,)))
        self.assertEqual(len(shadow.reasons("strict", both)), 2)

    def test_cnsa2_wants_ml_kem_1024_ml_dsa_87_and_aes_256(self):
        ok = shadow.parse(hello(groups=(0x11ED,), sigalgs=(0x0906,), suites=(0x1302,)))
        self.assertEqual(shadow.reasons("cnsa2", ok), [])
        weaker = shadow.parse(hello(groups=(0x11EC,), sigalgs=(0x0905,), suites=(0x1301,)))
        self.assertEqual(len(shadow.reasons("cnsa2", weaker)), 3)


@unittest.skipIf(REASON, REASON)
class EdgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.ca = CA.init(d / "pki", "Shadow Root")
        cls.srv, _ = cls.ca.issue("localhost", "server", ["127.0.0.1", NAME], out=d / "srv")
        cls.cafile = str(d / "pki" / "ca.crt")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def upstream(self):
        srv = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(srv.close)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=lambda c=conn: (c.sendall(c.recv(4096)), c.close()), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1]

    def edge(self, **kw):
        route = Route("shadowed", "terminate", "127.0.0.1:0", f"127.0.0.1:{self.upstream()}", cert=str(self.srv / "chain.pem"),
                      key=str(self.srv / "key.pem"), **kw)
        e = Edge(route).start()
        self.addCleanup(e.stop, 1)
        return e

    def talk(self, edge, ctx):
        with tls.connect("127.0.0.1", edge.port, ctx, NAME, 5) as c:
            c.sendall(SECRET)
            return c.recv(timeout=5)

    def classical(self):
        return tls.Context(False, "X25519", None, CIPHERS, ca=self.cafile)

    def post_quantum(self):
        return tls.client_context(policies.policy("strict"), self.cafile)

    def test_strict_without_shadow_refuses_a_client_that_offers_only_classical_key_exchange(self):
        e = self.edge(policy="strict")
        with self.assertRaises(tls.TLSError):
            self.talk(e, self.classical())

    def test_shadow_serves_that_client_and_reports_who_it_was_and_what_it_offered(self):
        e = self.edge(policy="strict", shadow=True)
        with self.assertLogs("acxelin_tls.edge", "WARNING") as logs:
            self.assertEqual(self.talk(e, self.classical()), SECRET)
        text = "\n".join(logs.output)
        for want in ("127.0.0.1", "x25519", "strict", "would be refused", "no post-quantum key exchange offered"):
            self.assertIn(want, text)
        s = e.stats.snapshot()
        self.assertEqual((s.get("shadow_would_refuse"), s.get("shadow_ok", 0)), (1, 0))

    def test_nothing_sensitive_reaches_the_log(self):
        e = self.edge(policy="strict", shadow=True)
        with self.assertLogs("acxelin_tls.edge", "DEBUG") as logs:
            logging.getLogger("acxelin_tls.edge").debug("start")
            self.talk(e, self.classical())
            self.talk(e, self.post_quantum())
        text = "\n".join(logs.output)
        for secret in (SECRET.decode(), NAME, "BEGIN", str(self.srv)):
            self.assertNotIn(secret, text)

    def test_a_client_strict_would_accept_is_counted_and_not_reported(self):
        e = self.edge(policy="strict", shadow=True)
        with self.assertNoLogs("acxelin_tls.edge", "WARNING"):
            self.assertEqual(self.talk(e, self.post_quantum()), SECRET)
        s = e.stats.snapshot()
        self.assertEqual((s.get("shadow_ok"), s.get("shadow_would_refuse", 0)), (1, 0))

    def test_the_counters_reach_the_metrics_by_reason(self):
        e = self.edge(policy="strict", shadow=True)
        self.talk(e, self.classical())
        text = metrics_text([e])
        self.assertIn('event="shadow_would_refuse"', text)
        self.assertIn('event="shadow_would_refuse_no_post_quantum_key_exchange_offered"', text)

    def test_a_failure_while_reporting_never_stops_the_connection(self):
        e = self.edge(policy="strict", shadow=True)
        with mock.patch.object(shadow, "reasons", side_effect=RuntimeError("boom")), self.assertLogs("acxelin_tls.edge", "ERROR"):
            self.assertEqual(self.talk(e, self.classical()), SECRET)
        self.assertEqual(e.stats.snapshot().get("shadow_failed"), 1)

    def test_the_status_says_the_route_is_in_shadow_so_nobody_takes_it_for_enforcement(self):
        e = self.edge(policy="strict", shadow=True)
        httpd = serve_metrics("127.0.0.1:0", [e])
        self.addCleanup(httpd.shutdown)
        body = json.load(urllib.request.urlopen(f"http://127.0.0.1:{httpd.server_address[1]}/status"))
        self.assertTrue(body["shadowed"]["shadow"])


class RouteTest(unittest.TestCase):
    def route(self, **kw):
        return Route("r", "terminate", "127.0.0.1:0", "127.0.0.1:1", cert="c", key="k", **kw)

    def test_shadow_is_off_by_default(self):
        self.assertFalse(self.route().shadow)

    def test_shadow_only_makes_sense_for_a_policy_that_refuses_something(self):
        with self.assertRaisesRegex(ValueError, "shadow.*strict or cnsa2"):
            self.route(policy="transition", shadow=True).validate()
        self.route(policy="strict", shadow=True).validate()
        self.route(policy="cnsa2", shadow=True).validate()

    def test_shadow_is_for_terminate_routes_and_may_carry_a_fallback_certificate(self):
        with self.assertRaisesRegex(ValueError, "shadow.*terminate"):
            Route("r", "originate", "127.0.0.1:0", "127.0.0.1:1", ca="x", policy="strict", shadow=True).validate()
        self.route(policy="strict", shadow=True, fallback_cert="f", fallback_key="g").validate()
