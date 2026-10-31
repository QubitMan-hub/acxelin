"""Attacks an adversarial review reproduced, each now refused: a gateway reply that would add a root command to the laptop's
WireGuard configuration, a renewal racing a revocation, one failed QKD call ending a site's key agreement for good, `sudo join`
handing a planted link's target to the person, and a peer that holds the key agreement service by sending a byte at a time."""
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from acxelin_core import tls
from acxelin_core.pki import CA, CAError, check_revocation, est
from acxelin_vpn import agreement, join, qkd
from acxelin_vpn.wireguard import Client, checked_reply
from support_vpn import REASON

GOOD = {"ok": True, "address": "10.8.0.2/24", "gateway": "gw", "gateway_public": "A" * 43 + "=", "endpoint": "vpn.example:51820",
        "routes": ["10.8.0.0/24"], "dns": ["10.8.0.1"], "rotate_s": 120}


class ReplyTest(unittest.TestCase):
    def test_nothing_from_the_gateway_reaches_the_configuration_unless_it_is_what_it_claims_to_be(self):
        checked_reply(dict(GOOD))
        checked_reply(GOOD | {"endpoint": "[2001:db8::1]:51820", "routes": ["0.0.0.0/0", "::/0"], "dns": []})
        injected = "\nPostUp = id > /tmp/pwned"
        for bad in ({"dns": ["10.8.0.1" + injected]}, {"address": "10.8.0.2/24" + injected}, {"routes": ["10.8.0.0/24" + injected]},
                    {"endpoint": "vpn.example:51820" + injected}, {"endpoint": "vpn example:51820"}, {"endpoint": "vpn.example:99999"},
                    {"routes": "10.8.0.0/24"}, {"routes": []}, {"dns": ["8.8.8.8"] * 9}, {"rotate_s": 1}, {"rotate_s": "120"}):
            with self.subTest(bad=bad), self.assertRaisesRegex(tls.TLSError, "malformed"):
                checked_reply(GOOD | bad)


@unittest.skipIf(REASON, REASON)
class LiveAttackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_a_gateway_that_injects_a_command_configures_nothing(self):
        ca = CA.init(self.tmp / "ca", "Root")
        ca.issue("127.0.0.1", "server", ["127.0.0.1"], out=self.tmp / "gw")
        ca.issue("alice", "client", [], out=self.tmp / "dev")
        shutil.copy(self.tmp / "ca/ca.crt", self.tmp / "dev/ca.crt")

        def respond(conn, addr):
            agreement.read_line(conn)
            agreement.send(conn, GOOD | {"endpoint": "127.0.0.1:51820", "dns": ["10.8.0.1\nPostUp = id > /tmp/pwned"]})
        srv = agreement.keyring("127.0.0.1:0", self.tmp / "gw/chain.pem", self.tmp / "gw/key.pem", self.tmp / "ca/ca.crt", respond)
        self.addCleanup(srv.stop)
        out = self.tmp / "wg0.conf"
        c = Client(f"127.0.0.1:{srv.port}", self.tmp / "dev", server_name="127.0.0.1", apply=False, config_out=out)
        with self.assertRaisesRegex(tls.TLSError, "malformed"):
            c.once()
        self.assertFalse(out.exists())

    def test_a_renewal_racing_a_revocation_never_leaves_a_valid_certificate(self):
        from acxelin_vpn.console import VPNConsole
        ca = CA.init(self.tmp / "ca", "Root")
        ca.crl()
        ca.issue("est.local", "server", ["127.0.0.1"], out=self.tmp / "est")
        ca.issue("mallory", "client", [], out=self.tmp / "mallory")
        shutil.copy(self.tmp / "ca/ca.crt", self.tmp / "mallory/ca.crt")
        srv = est.serve(self.tmp / "ca", "127.0.0.1:0", self.tmp / "est/chain.pem", self.tmp / "est/key.pem")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.stop, 1)
        url, stop = f"https://127.0.0.1:{srv.port}", threading.Event()

        def keep_renewing():
            n = 0
            while not stop.is_set():
                d = self.tmp / f"loop{n}"
                n += 1
                shutil.copytree(self.tmp / "mallory", d)
                try:
                    est.renew(url, d)
                except (CAError, tls.TLSError, OSError):
                    pass
        t = threading.Thread(target=keep_renewing, daemon=True)
        t.start()
        time.sleep(1.0)
        VPNConsole(self.tmp / "home", self.tmp / "ca").revoke({"name": "mallory"})
        stop.set()
        t.join(30)
        crl = (self.tmp / "ca/crl.pem").read_bytes()
        alive = []
        for r in CA(self.tmp / "ca").records():
            if r.common_name == "mallory":
                try:
                    check_revocation(int(r.serial, 16), crl, ca.cert, ca.cert.subject)
                    alive.append(r.serial)
                except CAError:
                    pass
        self.assertEqual(alive, [], "a certificate signed during the revocation escaped it")

    def test_a_peer_sending_a_byte_at_a_time_is_cut_off(self):
        class Drip:
            def recv(self, size, timeout):
                time.sleep(min(timeout, 0.1))
                return b" "
        start = time.monotonic()
        with self.assertRaisesRegex(tls.TLSError, "too slow"):
            agreement.read_line(Drip(), seconds=0.5)
        self.assertLess(time.monotonic() - start, 3)


class SiteTest(unittest.TestCase):
    def test_a_failed_qkd_call_does_not_end_the_sites_key_agreement(self):
        from acxelin_vpn.controller import Controller
        from test_vpn import site
        ctl = Controller(site(), charon=mock.Mock())
        calls = []

        def agree(peer):
            calls.append(1)
            if len(calls) == 1:
                raise qkd.QKDError("key server unreachable")
            ctl.stop.set()
        with mock.patch.object(ctl, "agree", side_effect=agree), mock.patch.object(ctl, "tunnel", return_value=None), \
                mock.patch("acxelin_vpn.controller.time.sleep"), mock.patch.object(ctl.stop, "wait", side_effect=lambda s=None: ctl.stop.is_set()):
            t = threading.Thread(target=ctl.initiator_loop, args=(ctl.site.peers[0],), daemon=True)
            t.start()
            t.join(10)
        self.assertEqual(len(calls), 2, "the loop tried again after the QKD error")


@unittest.skipIf(os.name == "nt" or os.geteuid() != 0, "needs root, as `sudo acxelin-vpn join` runs")
class GiveBackTest(unittest.TestCase):
    def test_sudo_join_never_hands_a_planted_links_target_to_the_person(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            victim = d / "victim"
            victim.write_text("root's")
            device = d / "device"
            device.mkdir()
            (device / "cert.pem").write_text("x")
            (device / "trap").symlink_to(victim)
            (d / "inv.acxinvite").write_text(json.dumps({}))
            with mock.patch.dict(os.environ, {"SUDO_UID": "4242", "SUDO_GID": "4242"}):
                join.give_back(d / "inv.acxinvite", device)
            self.assertEqual(victim.stat().st_uid, 0)
            self.assertEqual((device / "cert.pem").stat().st_uid, 4242)
