"""Bugs a correctness review reproduced in the CA and edge commands, each now fixed: a renewal written to a new folder, renewed
certificates still reported as expiring, doctor reading paths from the wrong folder, `connect --send` taking escapes literally,
an IPv6 error hiding a refusal, a CSR's certificate renewed with a key the CA made, and numbers that can only fail later."""
import contextlib
import io
import socket
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

from acxelin_core.http import explain
from acxelin_core.pki import CA, CAError

from acxelin_tls.cli import main
from support_tls import REASON


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main([str(a) for a in argv])
        except SystemExit as e:
            code = e.code
    return code, out.getvalue() + err.getvalue()


@unittest.skipIf(REASON, REASON)
class CATest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.ca = CA.init(self.d / "pki", "Root")

    def test_renew_without_out_replaces_the_certificate_in_its_folder(self):
        out, rec = self.ca.issue("web.example", "server", out=self.d / "web")
        before = (out / "cert.pem").read_bytes()
        code, text = run("ca", "renew", rec.serial, "--dir", self.d / "pki")
        self.assertEqual(code or 0, 0, text)
        self.assertNotEqual((out / "cert.pem").read_bytes(), before)
        self.assertFalse((self.d / "pki" / "issued").exists(), "no second folder")

    def test_a_renewed_or_expired_certificate_is_not_reported_as_expiring(self):
        self.ca.issue("web.example", "server", days=10, out=self.d / "web")
        self.assertEqual([r.common_name for r in self.ca.expiring(30)], ["web.example"])
        self.ca.maintain(renew_within=30)
        self.assertEqual(self.ca.expiring(30), [], "the renewed one lasts 397 days; the old one is superseded")

    def test_a_certificate_signed_from_a_csr_is_not_renewed_with_a_key_the_ca_makes(self):
        from acxelin_core.pki import generate
        from acxelin_core.pki.est import _csr
        import base64
        from cryptography import x509
        csr = x509.load_der_x509_csr(base64.b64decode(_csr(generate("ML-DSA-65"), "app.example", ["app.example"])))
        _, rec = self.ca.sign(csr.public_key(), "app.example", "server", ["app.example"])
        code, text = run("ca", "renew", rec.serial, "--dir", self.d / "pki")
        self.assertEqual(code, 1)
        self.assertIn("its key is with", text)
        with self.assertRaisesRegex(CAError, "its key is with"):
            self.ca.renew(rec.serial)

    def test_doctor_reads_paths_from_the_configuration_files_folder(self):
        self.ca.issue("localhost", "server", out=self.d / "cfg" / "certs")
        (self.d / "cfg" / "edge.toml").write_text('[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\n'
                                                  'cert = "certs/chain.pem"\nkey = "certs/key.pem"\n')
        from acxelin_tls import checks
        found = checks.config(self.d / "cfg" / "edge.toml")
        self.assertFalse([m for level, m in found if level == "fail"], found)


@pytest.mark.parametrize("argv", [("ca", "acme", "--days", "0"), ("ca", "maintain", "--renew-within", "-1"), ("ca", "list", "--expiring", "-5")])
def test_numbers_that_can_only_fail_later_are_refused_at_once(tmp_path, argv):
    code, text = run(*argv, "--dir", tmp_path)
    assert code == 2 and "expected a number above 0" in text


def test_connect_send_understands_the_escapes_the_manual_uses():
    from acxelin_tls.edge_commands import unescape
    assert unescape(r"GET / HTTP/1.0\r\n\r\n") == "GET / HTTP/1.0\r\n\r\n"
    assert unescape(r"a\\nb") == "a\\nb"


def test_a_refused_localhost_says_refused_even_without_ipv6():
    from acxelin_core import tls
    errors = {"127.0.0.1": ConnectionRefusedError(111, "Connection refused"), "::1": OSError(97, "Address family not supported by protocol")}
    with mock.patch("socket.create_connection", side_effect=lambda addr, timeout: (_ for _ in ()).throw(errors[addr[0]])):
        with pytest.raises(ConnectionRefusedError):
            tls._dial("localhost", 1, 1)


def test_an_http_error_is_explained_in_words():
    assert "connection refused" in explain(urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")))
    assert "urlopen" not in explain(urllib.error.URLError(socket.timeout("timed out")))
