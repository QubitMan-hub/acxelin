"""What keeps a laptop working without help: a new invitation after a revocation replaces the old certificate, the certificate
renews before it runs out, `disconnect` stops a running client instead of being undone, and reconnecting under the kill switch
uses the addresses resolved before DNS was blocked."""
import datetime as dt
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from acxelin_core.pki import CA
from acxelin_vpn import app, join
from acxelin_vpn.wireguard import Client
from support_vpn import REASON

SOON = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).isoformat()
PAST = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).isoformat()


class InvitationTest(unittest.TestCase):
    def test_a_new_invitation_replaces_the_old_certificate_but_a_used_one_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            device = Path(d)
            self.assertTrue(join.must_enroll({"token": "t", "expires": SOON}, device))
            (device / "cert.pem").write_text("old")
            self.assertTrue(join.must_enroll({"token": "t", "expires": SOON}, device), "a new invitation after a revocation")
            self.assertFalse(join.must_enroll({"expires": SOON}, device), "the used invitation keeps the current certificate")
            self.assertFalse(join.must_enroll({"token": "t", "expires": PAST}, device))
            (device / "cert.pem").unlink()
            with self.assertRaisesRegex(ValueError, "expired"):
                join.must_enroll({"token": "t", "expires": PAST}, device)

    def test_the_app_takes_a_new_invitation_for_the_same_person(self):
        inv = lambda **k: json.dumps({"acxelin_invite": 1, "name": "alice", "enroll": "https://ca.example:9443", "ca_fingerprint": "0" * 64,
                                      "gateway": "vpn.example:7443", "expires": SOON} | k)
        with tempfile.TemporaryDirectory() as d:
            window = app.App(folder=d, apply=False)
            window.load("alice.acxinvite", inv())  # the used one, without a token
            window.load("alice.acxinvite", inv(token="fresh"))
            self.assertEqual(json.loads((Path(d) / "alice.acxinvite").read_text())["token"], "fresh")


class Tunnel:
    up_ = False

    def __init__(self, folder):
        self.folder = Path(folder)

    def down(self):
        self.up_ = False


@unittest.skipIf(REASON, REASON)
class ClientCareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        CA.init(d / "pki", "VPN Root").issue("alice", "client", out=d / "alice")
        (d / "alice" / "ca.crt").write_bytes((d / "pki" / "ca.crt").read_bytes())
        self.d = d

    def client(self, **kw):
        return Client("vpn.example:7443", self.d / "alice", apply=True, tunnel=Tunnel(self.d), kill_switch=mock.Mock(), **kw)

    def test_disconnect_stops_a_running_client(self):
        c = self.client()
        (self.d / "wg0.disconnect").write_bytes(b"")
        c.step()
        self.assertTrue(c.stop.is_set())
        self.assertFalse((self.d / "wg0.disconnect").exists())

    def test_the_certificate_renews_twice_a_day_at_most(self):
        (self.d / "alice" / "enroll.url").write_text("https://ca.example:9443\n")
        c = self.client()
        c.due = time.time() + 3600
        with mock.patch("acxelin_core.pki.est.renew", return_value=None) as renew:
            c.step()
            c.step()
        renew.assert_called_once_with("https://ca.example:9443", self.d / "alice", within_days=30, passphrase=None)

    def test_under_the_kill_switch_the_gateway_is_reached_at_its_pinned_address(self):
        c = self.client()
        with mock.patch("acxelin_vpn.wireguard.addresses", return_value=["203.0.113.9"]):
            self.assertEqual(c.pin("vpn.example"), "203.0.113.9")
        c.ks_on = True
        with mock.patch("acxelin_vpn.wireguard.addresses", side_effect=OSError("DNS blocked")):
            self.assertEqual(c.pin("vpn.example"), "203.0.113.9")
            with self.assertRaises(OSError):
                c.pin("other.example")


class ConsoleDefaultTest(unittest.TestCase):
    def test_the_console_uses_the_manuals_pki_folder_when_it_exists(self):
        from acxelin_vpn import console
        here = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                Path("pki").mkdir()
                Path("pki/ca.crt").write_text("x")
                args = mock.Mock(home=d, action="", ca=None, port=0, no_browser=True, container=False)
                with mock.patch.object(console, "run") as run:
                    console.cmd_console(args)
                self.assertEqual(run.call_args.kwargs["ca_dir"], "pki")
            finally:
                os.chdir(here)  # Windows cannot delete the folder it is standing in
