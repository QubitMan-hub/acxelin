import datetime as dt
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.x509 import ocsp

import support
from acxelin_core import tls
from acxelin_core.pki import CA, CAError
from acxelin_core.pki import ocsp as acxelin_ocsp
from support import REASON


@unittest.skipIf(REASON, REASON)
class ResponseTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.ca = CA.init(self.d / "pki", "OCSP Root")
        out, self.rec = self.ca.issue("web.acme", "server", ["web.acme"], out=self.d / "web")
        self.cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())

    def test_a_valid_certificate_gets_a_signed_good_answer(self):
        der = acxelin_ocsp.respond(self.ca, self.cert, hours=24)
        r = ocsp.load_der_ocsp_response(der)
        self.assertEqual((r.response_status, r.certificate_status, r.serial_number), (ocsp.OCSPResponseStatus.SUCCESSFUL, ocsp.OCSPCertStatus.GOOD, self.cert.serial_number))
        self.assertEqual(r.next_update_utc - r.this_update_utc, dt.timedelta(hours=24))
        self.assertEqual(acxelin_ocsp.check(der, self.cert, self.ca.cert), ocsp.OCSPCertStatus.GOOD)

    def test_a_revoked_certificate_gets_a_revoked_answer_with_the_time_and_reason(self):
        self.ca.revoke(self.rec.serial, "keyCompromise")
        der = acxelin_ocsp.respond(self.ca, self.cert)
        r = ocsp.load_der_ocsp_response(der)
        self.assertEqual(r.certificate_status, ocsp.OCSPCertStatus.REVOKED)
        self.assertEqual(r.revocation_reason, x509.ReasonFlags.key_compromise)
        self.assertEqual(acxelin_ocsp.check(der, self.cert, self.ca.cert), ocsp.OCSPCertStatus.REVOKED)

    def test_only_this_cas_certificates_are_answered_for(self):
        other = CA.init(self.d / "other", "Other Root")
        out, _ = other.issue("stranger", "server", ["stranger"], out=self.d / "stranger")
        stranger = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        with self.assertRaisesRegex(CAError, "not issued by this CA"):
            acxelin_ocsp.respond(self.ca, stranger)
        with self.assertRaisesRegex(CAError, "between 1 and 168"):
            acxelin_ocsp.respond(self.ca, self.cert, hours=500)

    def test_a_staple_that_is_forged_stale_or_for_another_certificate_is_refused(self):
        der = acxelin_ocsp.respond(self.ca, self.cert)
        tampered = bytearray(der)
        tampered[-5] ^= 0x01
        with self.assertRaisesRegex(CAError, "signature"):
            acxelin_ocsp.check(bytes(tampered), self.cert, self.ca.cert)
        other = CA.init(self.d / "other", "Other Root")  # the same name, another key: signed by someone else
        fake = acxelin_ocsp.respond(other, self._issued_by(other))
        with self.assertRaisesRegex(CAError, "serial|signature|not issued"):
            acxelin_ocsp.check(fake, self.cert, self.ca.cert)
        out, _ = self.ca.issue("db.acme", "server", ["db.acme"], out=self.d / "db")
        second = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        with self.assertRaisesRegex(CAError, "another certificate"):
            acxelin_ocsp.check(acxelin_ocsp.respond(self.ca, second), self.cert, self.ca.cert)
        stale = ocsp.load_der_ocsp_response(der)
        late = stale.next_update_utc + dt.timedelta(minutes=1)
        with self.assertRaisesRegex(CAError, "out of date"):
            acxelin_ocsp.check(der, self.cert, self.ca.cert, now=late)
        early = stale.this_update_utc - dt.timedelta(hours=1)
        with self.assertRaisesRegex(CAError, "not valid yet"):
            acxelin_ocsp.check(der, self.cert, self.ca.cert, now=early)

    def _issued_by(self, ca):
        out, _ = ca.issue("web.acme", "server", ["web.acme"], out=self.d / "w2")
        return x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())

    def test_a_staple_file_is_followed_and_never_sent_stale(self):
        path = self.d / "staple.der"
        follow = acxelin_ocsp.StapleFile(path, self.ca.cert)
        self.assertIsNone(follow(), "no file, no staple")
        path.write_bytes(acxelin_ocsp.respond(self.ca, self.cert))
        first = follow()
        self.assertEqual(ocsp.load_der_ocsp_response(first).certificate_status, ocsp.OCSPCertStatus.GOOD)
        self.ca.revoke(self.rec.serial, "superseded")
        path.write_bytes(acxelin_ocsp.respond(self.ca, self.cert))
        os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 5))
        self.assertEqual(ocsp.load_der_ocsp_response(follow()).certificate_status, ocsp.OCSPCertStatus.REVOKED)
        path.write_bytes(b"not an ocsp response")
        os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 10))
        self.assertIsNone(follow())
        path.write_bytes(acxelin_ocsp.respond(self.ca, self.cert))
        os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 15))
        follow.clock = lambda: dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3)
        self.assertIsNone(follow(), "an expired answer is never stapled")
        self.assertIn("out of date", follow.problem)


@unittest.skipIf(REASON, REASON)
class StapleOverTlsTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.ca = CA.init(self.d / "pki", "OCSP Root")
        out, self.rec = self.ca.issue("localhost", "server", ["127.0.0.1"], out=self.d / "srv")
        self.out = out
        self.cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        self.staple = acxelin_ocsp.respond(self.ca, self.cert)

    def serve(self, provider):
        ctx = tls.server_context(support.PQ, self.out / "chain.pem", self.out / "key.pem")
        if provider:
            ctx.set_staple(provider)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        self.addCleanup(ctx.close)

        def run():
            for _ in range(2):
                try:
                    c, _ = listener.accept()
                    conn = ctx.wrap(c, None, 5)
                    conn.recv(10)
                    conn.close()
                except Exception:
                    pass
        threading.Thread(target=run, daemon=True).start()
        return listener.getsockname()[1]

    def fetch(self, port, want):
        ctx = tls.client_context(support.PQ, self.d / "pki" / "ca.crt")
        ctx.request_staple = want
        with tls.connect("127.0.0.1", port, ctx, "127.0.0.1") as conn:
            got = conn.staple
            conn.sendall(b"x")
            return got

    def test_a_client_that_asks_receives_the_staple_and_can_check_it(self):
        port = self.serve(lambda: self.staple)
        got = self.fetch(port, True)
        self.assertEqual(got, self.staple)
        self.assertEqual(acxelin_ocsp.check(got, self.cert, self.ca.cert), ocsp.OCSPCertStatus.GOOD)

    def test_nothing_is_stapled_to_a_client_that_did_not_ask_or_when_there_is_no_staple(self):
        port = self.serve(lambda: self.staple)
        self.assertIsNone(self.fetch(port, False))
        port = self.serve(lambda: None)
        self.assertIsNone(self.fetch(port, True))
        self.assertIsNone(self.fetch(self.serve(None), True))

    def test_a_provider_that_fails_does_not_break_the_handshake(self):
        def broken():
            raise RuntimeError("disk gone")
        self.assertIsNone(self.fetch(self.serve(broken), True))


if __name__ == "__main__":
    unittest.main()
