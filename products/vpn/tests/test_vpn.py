"""VPN tests. The unit tests always run. The integration test builds two sites in Linux network namespaces with real strongSwan
charon daemons and real `acxelin-vpn up` controllers; it needs root, iproute2, ACXELIN_STRONGSWAN (a strongSwan 6.0.2+ prefix)
and OpenSSL 3.5+. Set ACXELIN_VPN_DATAPLANE=1 where the kernel has ESP to also check traffic through the tunnel."""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from acxelin_core.pki import CA
from acxelin_vpn import PROFILES, Peer, Site, load_config, validate
from acxelin_vpn.charon import conn_config, ppk_pattern
from acxelin_vpn.controller import context
from support_vpn import REASON


def site(**kw):
    peer = Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True, keyring="10.0.0.2:7443")
    return Site(**({"name": "hq.acme", "address": "10.0.0.1", "cert": "c", "key": "k", "ca": "a", "peers": [peer]} | kw))


class ConfigTest(unittest.TestCase):
    def test_every_exchange_is_post_quantum_and_hybrid_except_the_strict_profile(self):
        for name, (ike, esp) in PROFILES.items():
            self.assertIn("mlkem1024" if name == "cnsa2" else "ke1_mlkem", ike)
            self.assertIn("mlkem1024" if name == "cnsa2" else "ke1_mlkem", esp)
            self.assertIn("aes256gcm16", esp)

    def test_conn_requires_a_ppk_and_pins_it_per_peer(self):
        s = site()
        c = conn_config(s, s.peers[0], "abc123abc123." + ppk_pattern("hq.acme", "branch.acme"))["branch.acme"]
        self.assertEqual((c["ppk_required"], c["local"]["auth"], c["remote"]["id"]), ("yes", "psk", "branch.acme"))
        self.assertEqual(c["ppk_id"], "abc123abc123.branch.acme.hq.acme.ppk.pqcsuite")
        responder = conn_config(s, s.peers[0])["branch.acme"]
        self.assertEqual(responder["ppk_id"], "*.branch.acme.hq.acme.ppk.pqcsuite")
        self.assertEqual(c["children"]["net"]["remote_ts"], ["10.2.0.0/16"])

    def test_both_sides_derive_from_the_same_context(self):
        self.assertEqual(context("hq", "branch", "t"), context("branch", "hq", "t"))
        self.assertNotEqual(context("hq", "branch", "t"), context("hq", "branch", "u"))

    def test_validation(self):
        with self.assertRaisesRegex(ValueError, "keyring"):
            validate(site(peers=[Peer("b", "1.2.3.4", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True)]))
        with self.assertRaisesRegex(ValueError, "keyring_listen"):
            validate(site(peers=[Peer("b", "1.2.3.4", ["10.1.0.0/16"], ["10.2.0.0/16"])]))
        with self.assertRaisesRegex(ValueError, "profile"):
            validate(site(peers=[Peer("b", "1.2.3.4", [], [], True, "1.2.3.4:1", profile="fast")]))
        with self.assertRaises(ValueError):
            validate(site(peers=[Peer("b", "1.2.3.4", ["not-a-net"], [], True, "1.2.3.4:1")]))

    def test_key_agreement_messages_must_be_json_objects(self):
        from acxelin_core import tls
        from acxelin_vpn.controller import Controller, read_line

        class Conn:
            def __init__(self, data):
                self.data = data

            def recv(self, size, timeout):
                data, self.data = self.data, b""
                return data
        self.assertEqual(read_line(Conn(b'{"ok": true}\n')), {"ok": True})
        for bad in (b"[1]\n", b'"x"\n', b"{nope\n"):
            with self.assertRaisesRegex(tls.TLSError, "not a JSON object"):
                read_line(Conn(bad))
        site = Site(name="hq", address="10.0.0.1", ca="ca.crt", cert="c.pem", key="k.pem", key_passphrase_env="ACXELIN_TEST_UNSET_VAR")
        with self.assertRaisesRegex(ValueError, "ACXELIN_TEST_UNSET_VAR is not set"):
            Controller(site, charon=object()).passphrase()

    def test_one_vici_request_at_a_time(self):
        import threading
        from acxelin_vpn.charon import Charon

        class Session:
            busy, overlaps = False, 0

            def list_sas(self):
                if Session.busy:
                    Session.overlaps += 1
                Session.busy = True
                time.sleep(0.01)
                yield {}
                Session.busy = False
        ch = Charon.__new__(Charon)
        ch.session, ch.lock = Session(), threading.Lock()
        threads = [threading.Thread(target=ch.tunnels) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(Session.overlaps, 0)

    def test_vici_transport_failure_reconnects_without_replaying_mutations(self):
        from unittest.mock import Mock, patch
        from acxelin_vpn.charon import Charon, CharonError
        broken, recovered = Mock(), Mock()
        broken.load_conn.side_effect = EOFError('daemon restarted')
        recovered.list_sas.return_value = iter([{}])
        with patch('acxelin_vpn.charon.connect', side_effect=[broken, recovered]) as connect:
            ch = Charon('unix:///test')
            with self.assertRaisesRegex(CharonError, 'next request will reconnect'):
                ch.load_conn({'peer':{}})
            broken.load_conn.assert_called_once()
            recovered.load_conn.assert_not_called()
            self.assertEqual(ch.tunnels(), [])
            self.assertEqual(connect.call_count, 2)
            broken.transport.socket.close.assert_called_once()
            ch.close()
            recovered.transport.socket.close.assert_called_once()

    def test_example_configs_load(self):
        root = Path(__file__).parent.parent / "config"
        for f in ("site-hq.toml", "site-branch.toml"):
            self.assertTrue(load_config(root / f).peers)
        from acxelin_vpn.wireguard import load_gateway
        self.assertTrue(load_gateway(root / "gateway.toml").pool)


class FakeCharon:
    def __init__(self, keys, tunnels):
        self.keys, self.sas, self.terminated = set(keys), list(tunnels), []

    def shared_ids(self):
        return sorted(self.keys)

    def unload_key(self, key_id):
        self.keys.discard(key_id)

    def terminate(self, peer):
        self.terminated.append(peer)
        self.sas = [t for t in self.sas if t["peer"] != peer]

    def tunnels(self):
        return self.sas


class FreshnessTest(unittest.TestCase):
    def test_tunnels_without_fresh_key_agreement_are_cut(self):
        from acxelin_vpn.controller import Controller
        s = site(peers=[Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], rotate_minutes=1),
                        Peer("lab.acme", "10.0.0.3", ["10.1.0.0/16"], ["10.3.0.0/16"], rotate_minutes=1)], keyring_listen="0.0.0.0:7443")
        left_over = {"psk-branch.acme", "ppk-branch.acme-aaaaaaaaaaaa", "psk-lab.acme", "ppk-lab.acme-bbbbbbbbbbbb", "psk-other"}
        tunnels = [{"peer": "branch.acme", "state": "ESTABLISHED", "established_s": 5}, {"peer": "lab.acme", "state": "ESTABLISHED", "established_s": 5}]
        ch = FakeCharon(left_over, tunnels)
        ctl = Controller(s, charon=ch)
        ctl.enforce_freshness()
        self.assertEqual(ch.terminated, [])
        ctl.started -= 400
        ctl.last_agreed["lab.acme"] = time.time()
        ctl.enforce_freshness()
        self.assertEqual(ch.terminated, ["branch.acme"])
        self.assertEqual(ch.keys, {"psk-lab.acme", "ppk-lab.acme-bbbbbbbbbbbb", "psk-other"})
        self.assertEqual(ctl.counts["stale_peers"], 1)


@unittest.skipIf(REASON, REASON)
class OutageGraceTest(unittest.TestCase):
    """A peer that has not re-agreed keys within the normal limit (300 s at rotate_minutes = 1) is kept on its last keys for up to
    outage_grace_minutes, only while the CRL can show it is not revoked; revocation is never delayed."""
    LIMIT = 3 * 60 + 120

    def setUp(self):
        from unittest.mock import Mock
        from acxelin_vpn.controller import Controller
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.d = Path(self.tmp.name)
        self.ca = CA.init(d / "pki", "Root")
        self.ca.crl()
        self.crl = d / "pki" / "crl.pem"
        self.recs = {n: self.ca.issue(n, "site", out=d / n)[1] for n in ("branch.acme", "lab.acme")}
        peers = [Peer(n, "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], rotate_minutes=1, outage_grace_minutes=g)
                 for n, g in (("branch.acme", 30), ("lab.acme", 0))]
        self.charon = FakeCharon({"psk-branch.acme", "ppk-branch.acme-aaaaaaaaaaaa", "psk-lab.acme", "ppk-lab.acme-bbbbbbbbbbbb"},
                                 [{"peer": n, "state": "ESTABLISHED", "established_s": 5} for n in ("branch.acme", "lab.acme")])
        self.ctl = Controller(site(peers=peers, ca=str(d / "pki" / "ca.crt"), crl=str(self.crl), keyring_listen="0.0.0.0:7443"), charon=self.charon)
        for n in ("branch.acme", "lab.acme"):
            self.ctl.serials[n] = (int(self.recs[n].serial, 16), self.ca.cert.subject)
            self.ctl.keys[n] = ["aaaaaaaaaaaa"]
        self.Mock = Mock
        self.silent(0)

    def silent(self, seconds, *names):
        for n in names or ("branch.acme", "lab.acme"):
            self.ctl.last_agreed[n] = time.time() - seconds

    def passes(self):
        self.ctl.enforce()

    def test_a_silent_peer_stays_inside_the_grace_window_and_is_cut_at_the_cap(self):
        self.silent(self.LIMIT + 60, "branch.acme")
        self.passes()
        self.assertEqual(self.charon.terminated, [], "past the normal limit, inside the grace: kept on its last keys")
        self.assertIn("psk-branch.acme", self.charon.keys)
        self.silent(self.LIMIT + 30 * 60 + 5, "branch.acme")
        self.passes()
        self.assertEqual(self.charon.terminated, ["branch.acme"])
        self.assertNotIn("psk-branch.acme", self.charon.keys)
        self.assertEqual((self.ctl.counts["stale_peers"], self.ctl.counts["grace_used"]), (1, 1))

    def test_a_peer_without_a_grace_is_cut_at_the_normal_limit_as_before(self):
        self.silent(self.LIMIT + 1, "lab.acme")
        self.passes()
        self.assertEqual((self.charon.terminated, self.ctl.counts["grace_used"]), (["lab.acme"], 0))

    def test_a_peer_revoked_inside_the_grace_window_is_cut_at_the_next_pass(self):
        self.silent(self.LIMIT + 60, "branch.acme")
        self.passes()
        self.assertEqual(self.charon.terminated, [])
        self.ca.revoke(self.recs["branch.acme"].serial, "keyCompromise")
        time.sleep(0.05)
        self.passes()
        self.assertEqual(self.charon.terminated, ["branch.acme"], "revoked inside the grace: cut at once")
        self.assertNotIn("psk-branch.acme", self.charon.keys)
        self.assertEqual((self.ctl.counts["revoked_peers"], self.ctl.status()["branch.acme"]["in_grace"]), (1, False))

    def test_freshness_alone_never_keeps_a_revoked_peer(self):
        self.silent(self.LIMIT + 60, "branch.acme")
        self.ca.revoke(self.recs["branch.acme"].serial, "keyCompromise")
        time.sleep(0.05)
        self.ctl.enforce_freshness()
        self.assertEqual(self.charon.terminated, ["branch.acme"])

    def test_a_crl_that_cannot_be_used_cancels_the_grace(self):
        good = self.crl.read_bytes()
        later = mock.patch("acxelin_core.pki.now", return_value=datetime.now(timezone.utc) + timedelta(days=8))  # past the CRL's next update
        for what, (ruin, restore) in {"expired": (later.start, later.stop), "damaged": (lambda: self.crl.write_bytes(b"not a CRL"), lambda: self.crl.write_bytes(good)),
                                      "missing": (self.crl.unlink, lambda: self.crl.write_bytes(good))}.items():
            with self.subTest(what):
                self.charon.sas = [{"peer": "branch.acme", "state": "ESTABLISHED", "established_s": 5}]
                self.charon.terminated.clear()
                self.ctl.serials["branch.acme"] = (int(self.recs["branch.acme"].serial, 16), self.ca.cert.subject)
                self.silent(self.LIMIT + 60, "branch.acme")
                self.passes()
                self.assertEqual(self.charon.terminated, [], "usable CRL: in grace")
                ruin()
                time.sleep(0.05)
                self.passes()
                self.assertEqual(self.charon.terminated, ["branch.acme"], f"{what} CRL: no grace")
                restore()

    def test_a_restarted_controller_gives_leftover_tunnels_no_grace(self):
        self.ctl.serials.clear()
        self.silent(self.LIMIT + 60, "branch.acme")
        self.passes()
        self.assertEqual(self.charon.terminated, ["branch.acme"], "no certificate seen since the start: nothing shows it is not revoked")

    def test_the_cap_is_hard_however_long_the_control_plane_stays_away(self):
        self.ctl.site.peers[0].outage_grace_minutes = 10
        for age in range(self.LIMIT - 55, self.LIMIT + 40 * 60, 60):
            self.silent(age, "branch.acme")
            self.passes()
            self.assertEqual("branch.acme" in self.charon.terminated, age > self.LIMIT + 10 * 60, f"at {age}s")
            if self.charon.terminated:
                break
        self.passes()
        self.assertEqual((self.charon.terminated, self.ctl.counts["grace_used"]), (["branch.acme"], 1))

    def test_a_peer_that_re_agrees_during_the_grace_leaves_it_and_is_kept(self):
        self.silent(self.LIMIT + 60, "branch.acme")
        with self.assertLogs("acxelin_vpn.controller", "WARNING") as logs:
            self.passes()
            self.assertTrue(self.ctl.status()["branch.acme"]["in_grace"])
            self.charon.load_keys = self.charon.load_conn = lambda *a: None
            self.ctl.install(self.ctl.site.peer("branch.acme"), "cccccccccccc", b"x" * 64, self.Mock(serial_number=int(self.recs["branch.acme"].serial, 16)))
            self.passes()
        self.assertFalse(self.ctl.status()["branch.acme"]["in_grace"])
        self.assertEqual(self.charon.terminated, [])
        self.assertEqual(len([m for m in logs.output if "grace" in m]), 2, "one line on entering, one on leaving")

    def test_the_grace_is_logged_when_it_starts_and_ends_not_on_every_pass(self):
        self.silent(self.LIMIT + 60, "branch.acme")
        with self.assertLogs("acxelin_vpn.controller", "WARNING") as logs:
            for _ in range(5):
                self.passes()
            self.silent(self.LIMIT + 3600, "branch.acme")
            for _ in range(3):
                self.passes()
        lines = [m for m in logs.output if "grace" in m]
        self.assertEqual(len(lines), 2, lines)

    def test_status_and_metrics_show_who_runs_on_last_keys_and_for_how_long(self):
        self.silent(self.LIMIT + 12 * 60, "branch.acme")
        self.silent(30, "lab.acme")
        self.passes()
        s = self.ctl.status()
        self.assertEqual(s["lab.acme"]["in_grace"], False)
        self.assertTrue(s["branch.acme"]["in_grace"])
        self.assertAlmostEqual(s["branch.acme"]["grace_elapsed_s"], 12 * 60, delta=5)
        self.assertAlmostEqual(s["branch.acme"]["grace_remaining_s"], 18 * 60, delta=5)
        self.assertEqual((s["branch.acme"]["grace_cap_s"], s["_events"]["grace_used"]), (30 * 60, 1))
        text = self.ctl.metrics()
        self.assertIn('acxelin_vpn_tunnel_in_grace{peer="branch.acme"} 1', text)
        self.assertIn('acxelin_vpn_tunnel_in_grace{peer="lab.acme"} 0', text)
        self.assertRegex(text, r'acxelin_vpn_tunnel_grace_remaining_seconds\{peer="branch.acme"\} \d+')
        self.assertIn('acxelin_vpn_events_total{event="grace_used"} 1', text)

    def test_a_missing_crl_still_cuts_peers_that_stopped_renewing(self):
        self.silent(self.LIMIT + 1, "lab.acme")
        self.crl.unlink()
        self.passes()
        self.assertEqual(self.charon.terminated, ["lab.acme"])


class OutageGraceConfigTest(unittest.TestCase):
    def peers(self, **kw):
        return [Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True, keyring="10.0.0.2:7443", **kw)]

    def test_defaults_to_off_and_is_limited_to_a_day(self):
        self.assertEqual(self.peers()[0].outage_grace_minutes, 0)
        validate(site(crl="crl.pem", peers=self.peers()))
        for ok in (0, 0.5, 30, 1440):
            validate(site(crl="crl.pem", peers=self.peers(outage_grace_minutes=ok)))
        for bad in (-1, -0.1, 1440.5, 100000, float("nan")):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "branch.acme: outage_grace_minutes must be between 0 and 1440"):
                validate(site(crl="crl.pem", peers=self.peers(outage_grace_minutes=bad)))
        with self.assertRaisesRegex(ValueError, "branch.acme: outage_grace_minutes needs crl"):
            validate(site(peers=self.peers(outage_grace_minutes=30)))

    def test_must_be_a_number_in_a_configuration_file(self):
        base = (Path(__file__).parent.parent / "config" / "site-hq.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "site.toml"
            for bad in ('"30"', "true", "[30]"):
                conf.write_text(base + f"outage_grace_minutes = {bad}\n", encoding="utf-8")
                with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "outage_grace_minutes must be a number"):
                    load_config(conf)
            conf.write_text(base + "outage_grace_minutes = 30\n", encoding="utf-8")
            self.assertEqual(load_config(conf).peers[0].outage_grace_minutes, 30)


class TunnelHealthTest(unittest.TestCase):
    def test_ike_without_installed_child_is_not_protected_and_is_retried(self):
        from unittest.mock import Mock
        from acxelin_vpn.charon import protected
        from acxelin_vpn.controller import Controller
        s = site(peers=[Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True)])
        t = {"peer":"branch.acme", "state":"ESTABLISHED", "ppk":True, "key_exchange":"CURVE_25519 + ML_KEM_768", "established_s":5, "children":[]}
        ch = FakeCharon([], [t])
        ctl = Controller(s, charon=ch)
        ctl.last_agreed['branch.acme'] = time.time()
        self.assertFalse(protected(t))
        self.assertIn('peer="branch.acme"} 0', ctl.metrics())
        ctl.agree = Mock()
        ch.initiate = Mock(side_effect=lambda name: ctl.stop.set())
        ctl.initiator_loop(s.peers[0])
        ctl.agree.assert_called_once_with(s.peers[0])
        ch.initiate.assert_called_once_with('branch.acme')
        for state in ('INSTALLING', 'DELETING', 'INSTALLED'):
            t['children'] = [{'state':state, 'bytes_in':0, 'bytes_out':0}]
            self.assertEqual(protected(t), state == 'INSTALLED')
        self.assertIn('peer="branch.acme"} 1', ctl.metrics())
        self.assertFalse(protected(t | {'ppk':False}))
        self.assertFalse(protected(t | {'key_exchange':'CURVE_25519'}))

    def test_status_query_failure_does_not_kill_reconnection_loop(self):
        from unittest.mock import Mock
        from acxelin_vpn.charon import CharonError
        from acxelin_vpn.controller import Controller
        s = site(peers=[Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True)])
        ch = Mock()
        ch.tunnels.side_effect = [CharonError('restarting'), []]
        ctl = Controller(s, charon=ch)
        ctl.stop = Mock()
        ctl.stop.is_set.side_effect = [False, False, True]
        ctl.agree = Mock()
        ctl.initiator_loop(s.peers[0])
        self.assertEqual(ctl.counts['failures'], 1)
        ctl.agree.assert_called_once_with(s.peers[0])
        ch.initiate.assert_called_once_with('branch.acme')
        ctl.stop.wait.assert_any_call(5)

    def test_responder_reinstalls_connection_after_daemon_state_loss(self):
        from unittest.mock import Mock
        from acxelin_vpn.controller import Controller
        s = site(peers=[Peer('branch.acme', '10.0.0.2', ['10.1.0.0/16'], ['10.2.0.0/16'])])
        ch = Mock()
        ctl = Controller(s, charon=ch)
        ctl.install(s.peers[0], 'aaaaaaaaaaaa', b'x'*64, Mock(serial_number=123))
        configured = ch.load_conn.call_args.args[0]['branch.acme']
        self.assertTrue(configured['ppk_id'].startswith('*.'))
        self.assertEqual(configured['ppk_required'], 'yes')



class CharonFailureTest(unittest.TestCase):
    """strongSwan missing, not answering, or refusing a request."""

    def test_without_the_extra_or_a_running_charon_the_error_says_what_to_do(self):
        import socket
        import types
        from unittest import mock
        from acxelin_vpn.charon import CharonError, connect
        with mock.patch.dict(sys.modules, {"vici": None}), self.assertRaisesRegex(CharonError, r'pip install "acxelin-vpn\[vpn\]"'):
            connect("unix:///var/run/charon.vici")
        fake = types.SimpleNamespace(Session=lambda sock: sock)
        with mock.patch.dict(sys.modules, {"vici": fake}):
            with self.assertRaisesRegex(CharonError, "unsupported VICI address http://x"):
                connect("http://x")
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            with self.assertRaisesRegex(CharonError, "is strongSwan running"):
                connect(f"tcp://127.0.0.1:{port}")
            if hasattr(socket, "AF_UNIX"):
                with self.assertRaisesRegex(CharonError, "is strongSwan running"):
                    connect(f"unix://{tempfile.mkdtemp()}/charon.vici")
            with socket.create_server(("127.0.0.1", 0)) as server:
                sock = connect(f"tcp://127.0.0.1:{server.getsockname()[1]}")
                self.assertEqual(sock.gettimeout(), 60)
                sock.close()

    def test_a_refused_request_keeps_the_session_and_reports_charon_s_words(self):
        from unittest import mock
        from acxelin_vpn import charon
        refused = type("CommandException", (Exception,), {})
        session = mock.Mock()
        session.terminate.side_effect = [refused("no matching SAs found"), refused("terminating SA failed")]
        session.load_conn.side_effect = refused("loading connection 'branch' failed")
        with mock.patch.object(charon, "CommandException", refused), mock.patch.object(charon, "connect", return_value=session):
            with charon.Charon("unix:///test") as ch:
                ch.terminate("branch")
                with self.assertRaisesRegex(charon.CharonError, "terminating SA failed"):
                    ch.terminate("branch")
                with self.assertRaisesRegex(charon.CharonError, "loading connection 'branch' failed"):
                    ch.load_conn({})
                self.assertIs(ch.session, session)
            session.transport.socket.close.assert_called_once()

    def test_what_charon_reports_is_read_as_text(self):
        from unittest import mock
        from acxelin_vpn import charon
        session = mock.Mock()
        session.version.return_value = {"daemon": b"charon", "version": b"6.0.2"}
        session.get_algorithms.return_value = {"ke": {b"ML_KEM_768": b"openssl", b"CURVE_25519": b"openssl", b"ML_KEM_1024": b"openssl"}}
        session.get_shared.return_value = {"keys": [b"psk-branch", b"ppk-branch-aaaaaaaaaaaa"]}
        session.initiate.return_value = iter([{"msg": b"establishing CHILD_SA net"}, {}])
        session.list_sas.return_value = iter([{b"branch": {
            "state": b"ESTABLISHED", "remote-host": b"10.0.0.2", "established": b"12", "encr-alg": b"AES_GCM_16", "encr-keysize": b"256",
            "dh-group": b"CURVE_25519", "ake1": b"ML_KEM_768", "ppk": b"yes",
            "child-sas": {b"net-1": {"state": b"INSTALLED", "encr-alg": b"AES_GCM_16", "encr-keysize": b"256", "bytes-in": b"42"}}}}])
        with mock.patch.object(charon, "connect", return_value=session):
            ch = charon.Charon("unix:///test")
        self.assertEqual(ch.version(), "charon 6.0.2")
        self.assertEqual(ch.ml_kem(), ["ML_KEM_1024", "ML_KEM_768"])
        self.assertEqual(ch.shared_ids(), ["psk-branch", "ppk-branch-aaaaaaaaaaaa"])
        self.assertEqual(ch.initiate("branch"), ["establishing CHILD_SA net", ""])
        ch.load_keys("hq", "branch", b"p" * 32, b"q" * 32, "tag.ppk", "aaaaaaaaaaaa")
        self.assertEqual([c.args[0]["id"] for c in session.load_shared.call_args_list], ["psk-branch", "ppk-branch-aaaaaaaaaaaa"])
        ch.unload_key("psk-branch")
        session.unload_shared.assert_called_once_with({"id": "psk-branch"})
        [t] = ch.tunnels()
        self.assertEqual((t["peer"], t["encryption"], t["key_exchange"], t["ppk"]), ("branch", "AES_GCM_16_256", "CURVE_25519 + ML_KEM_768", True))
        self.assertEqual(t["children"][0], {"name": "net-1", "state": "INSTALLED", "encryption": "AES_GCM_16_256", "bytes_in": 42, "bytes_out": 0, "packets_in": 0, "packets_out": 0})
        self.assertTrue(charon.protected(t))


class Conn:
    """Stands in for the peer's keyring connection after mutual TLS."""

    def __init__(self, name, reply=b'{"ok": true}\n', serial=7, msg=None):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from unittest.mock import Mock
        self.cert = Mock(serial_number=serial, subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]) if name else x509.Name([]))
        self.reply, self.sent = (msg if msg is not None else reply), []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def peer_certificate(self):
        return self.cert

    def recv(self, size, timeout):
        data, self.reply = self.reply, b""
        return data

    def sendall(self, data):
        self.sent.append(data)

    def export(self, label, context, length):
        return b"k" * length


class KeyAgreementFailureTest(unittest.TestCase):
    """A peer that is not who it should be, is revoked, or refuses: no keys reach charon."""

    def controller(self, *peers, **kw):
        from unittest.mock import Mock
        from acxelin_vpn.controller import Controller
        s = site(peers=list(peers) or None, **kw) if peers else site(**kw)
        return Controller(s, charon=Mock()), s

    def agree(self, conn, revocation=None):
        from unittest import mock
        from acxelin_vpn import controller
        ctl, s = self.controller()
        ctl.revocation = revocation
        with mock.patch.object(controller.tls, "client_context"), mock.patch.object(controller.tls, "connect", return_value=conn):
            try:
                return ctl.agree(s.peers[0])
            finally:
                self.charon_calls = ctl.charon.method_calls

    def test_the_wrong_peer_a_revoked_peer_and_a_refusal_load_no_keys(self):
        from unittest.mock import Mock
        from acxelin_core import tls
        from acxelin_core.pki import CAError
        with self.assertRaisesRegex(tls.TLSError, "presented 'lab.acme', expected 'branch.acme'"):
            self.agree(Conn("lab.acme"))
        self.assertEqual(self.charon_calls, [])
        with self.assertRaisesRegex(CAError, "revoked"):
            self.agree(Conn("branch.acme"), Mock(check=Mock(side_effect=CAError("certificate 7 is revoked"))))
        self.assertEqual(self.charon_calls, [])
        with self.assertRaisesRegex(tls.TLSError, "branch.acme refused the key agreement"):
            self.agree(Conn("branch.acme", b'{"ok": false}\n'))
        self.assertEqual(self.charon_calls, [])
        with self.assertRaisesRegex(tls.TLSError, "missing or too long"):
            self.agree(Conn("branch.acme", b""))
        tag = self.agree(Conn("branch.acme"))
        self.assertEqual([c[0] for c in self.charon_calls], ["load_keys", "load_conn"])
        self.assertRegex(tag, r"^[0-9a-f]{12}$")

    def test_the_responder_refuses_what_it_should_not_accept(self):
        import json
        responder = Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"])
        initiator = Peer("lab.acme", "10.0.0.3", ["10.1.0.0/16"], ["10.3.0.0/16"], initiate=True, keyring="10.0.0.3:7443")
        ctl, _ = self.controller(responder, initiator, keyring_listen="0.0.0.0:7443")
        line = lambda **m: json.dumps({"v": 1, "site": "branch.acme", "tag": "aaaaaaaaaaaa"} | m).encode() + b"\n"
        for name, msg in (("stranger.acme", line(site="stranger.acme")), ("lab.acme", line(site="lab.acme")), ("branch.acme", line(site="lab.acme")),
                          ("branch.acme", line(tag="../../etc")), ("", line())):
            conn = Conn(name, msg=msg)
            ctl.respond(conn, ("10.9.9.9", 1))
            self.assertEqual(conn.sent, [b'{"ok": false}\n'], name)
        self.assertEqual(ctl.counts["key_agreements_refused"], 5)
        self.assertEqual(ctl.charon.method_calls, [])
        conn = Conn("branch.acme", msg=line())
        ctl.respond(conn, ("10.0.0.2", 1))
        self.assertEqual(conn.sent, [b'{"ok": true}\n'])
        self.assertEqual(ctl.keys["branch.acme"], ["aaaaaaaaaaaa"])

    def test_only_the_two_newest_keys_stay_loaded(self):
        from unittest.mock import Mock
        ctl, s = self.controller()
        for tag in ("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"):
            ctl.install(s.peers[0], tag, b"x" * 64, Mock(serial_number=1))
        ctl.charon.unload_key.assert_called_once_with("ppk-branch.acme-aaaaaaaaaaaa")
        self.assertEqual(ctl.keys["branch.acme"], ["bbbbbbbbbbbb", "cccccccccccc"])

    def test_a_revoked_peer_is_cut_but_a_broken_crl_keeps_tunnels(self):
        from unittest.mock import Mock
        from acxelin_core.pki import CAError
        from acxelin_vpn.controller import Controller
        ch = FakeCharon({"psk-branch.acme", "ppk-branch.acme-aaaaaaaaaaaa", "psk-lab.acme"}, [{"peer": "branch.acme", "established_s": 1}])
        ctl = Controller(site(), charon=ch)
        ctl.enforce_revocations()
        ctl.serials = {"branch.acme": (7, None)}
        ctl.revocation = Mock(check=Mock(side_effect=CAError("the CRL signature does not verify")))
        ctl.enforce_revocations()
        self.assertEqual(ch.terminated, [])
        ctl.revocation.check.side_effect = CAError("certificate 7 is revoked")
        ctl.enforce_revocations()
        self.assertEqual((ch.terminated, ch.keys, ctl.serials, ctl.counts["revoked_peers"]), (["branch.acme"], {"psk-lab.acme"}, {}, 1))

    def test_a_strongswan_without_ml_kem_is_refused_at_start(self):
        from unittest.mock import Mock
        from acxelin_vpn.charon import CharonError
        responder = Peer("branch.acme", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"])
        ctl, _ = self.controller(responder)
        ctl.charon.version.return_value, ctl.charon.ml_kem.return_value = "charon 5.9.14", []
        with self.assertRaisesRegex(CharonError, "no ML-KEM; build 6.0.2"):
            ctl.start()
        ctl.charon.load_conn.assert_not_called()
        ctl.charon.ml_kem.return_value = ["ML_KEM_768"]
        ctl.crl_follow = Mock()
        ctl.start()
        self.assertEqual(list(ctl.charon.load_conn.call_args.args[0]), ["branch.acme"])
        ctl.charon.tunnels.return_value = []
        self.assertEqual(ctl.status()["branch.acme"], {"initiate": False, "profile": "standard", "keys_age_s": None, "certificate": None, "tunnel": None,
                                                       "in_grace": False})
        ctl.shutdown()
        self.assertTrue(ctl.stop.is_set())
        ctl.crl_follow.set.assert_called_once()


SS = os.environ.get("ACXELIN_STRONGSWAN")
READY = SS and os.geteuid() == 0 and shutil.which("ip") and sys.platform == "linux"


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


@unittest.skipUnless(READY, "needs root, iproute2 and ACXELIN_STRONGSWAN")
class SiteToSiteTest(unittest.TestCase):
    """hq (10.30.0.1, LAN 192.168.10.0/24) <-> branch (10.30.0.2, LAN 192.168.20.0/24); branch initiates."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.procs = []
        self.addCleanup(self.teardown)
        ca = CA.init(self.d / "pki", "VPN Root")
        for name, addr in (("hq.acme", "10.30.0.1"), ("branch.acme", "10.30.0.2")):
            ca.issue(name, "site", [addr], out=self.d / name)
        ca.crl()
        self.ca = ca
        sh("ip", "netns", "add", "pqc-hq")
        sh("ip", "netns", "add", "pqc-br")
        sh("ip", "link", "add", "pqc-vh", "type", "veth", "peer", "name", "pqc-vb")
        for ns, dev, addr, lan, other_lan, gw in (("pqc-hq", "pqc-vh", "10.30.0.1", "192.168.10.1", "192.168.20.0/24", "10.30.0.2"),
                                                  ("pqc-br", "pqc-vb", "10.30.0.2", "192.168.20.1", "192.168.10.0/24", "10.30.0.1")):
            sh("ip", "link", "set", dev, "netns", ns)
            sh("ip", "-n", ns, "addr", "add", f"{addr}/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
            sh("ip", "-n", ns, "link", "set", "lo", "up")
            sh("ip", "-n", ns, "addr", "add", f"{lan}/32", "dev", "lo")
            sh("ip", "-n", ns, "route", "add", other_lan, "via", gw)
        common = f'ca = "{self.d}/pki/ca.crt"\ncrl = "{self.d}/pki/crl.pem"\n'
        (self.d / "hq.toml").write_text(textwrap.dedent(f"""
            [site]
            name = "hq.acme"
            address = "10.30.0.1"
            cert = "{self.d}/hq.acme/chain.pem"
            key = "{self.d}/hq.acme/key.pem"
            vici = "unix://{self.d}/hq.vici"
            keyring_listen = "10.30.0.1:7443"
            """) + common + textwrap.dedent("""
            [[peer]]
            name = "branch.acme"
            address = "10.30.0.2"
            local_subnets = ["192.168.10.0/24"]
            remote_subnets = ["192.168.20.0/24"]
            rotate_minutes = 1
            """))
        (self.d / "br.toml").write_text(textwrap.dedent(f"""
            [site]
            name = "branch.acme"
            address = "10.30.0.2"
            cert = "{self.d}/branch.acme/chain.pem"
            key = "{self.d}/branch.acme/key.pem"
            vici = "unix://{self.d}/br.vici"
            """) + common + textwrap.dedent("""
            [[peer]]
            name = "hq.acme"
            address = "10.30.0.1"
            local_subnets = ["192.168.20.0/24"]
            remote_subnets = ["192.168.10.0/24"]
            initiate = true
            keyring = "10.30.0.1:7443"
            rotate_minutes = 1
            """))
        for ns, tag in (("pqc-hq", "hq"), ("pqc-br", "br")):
            conf = self.d / f"{tag}.conf"
            conf.write_text(f"charon {{\n plugins {{ vici {{ socket = unix://{self.d}/{tag}.vici }} }}\n"
                            f" filelog {{ log {{ path = {self.d}/{tag}.log\n flush_line = yes\n default = 1\n }} }}\n}}\n")
            self.spawn("ip", "netns", "exec", ns, "unshare", "-m", "sh", "-c",
                       f"mount -t tmpfs tmpfs /run && STRONGSWAN_CONF={conf} exec {SS}/libexec/ipsec/charon")
        self.wait(lambda: (self.d / "hq.vici").exists() and (self.d / "br.vici").exists(), "charon did not start")
        for ns, tag in (("pqc-hq", "hq"), ("pqc-br", "br")):
            self.spawn("ip", "netns", "exec", ns, sys.executable, "-m", "acxelin_vpn", "up", "--config", str(self.d / f"{tag}.toml"),
                       log=self.d / f"{tag}-controller.log")

    def spawn(self, *cmd, log=None):
        out = open(log, "w") if log else subprocess.DEVNULL
        self.procs.append(subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT))
        if log:
            out.close()

    def teardown(self):
        for p in reversed(self.procs):
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for ns in ("pqc-hq", "pqc-br"):
            sh("ip", "netns", "del", ns, check=False)
        if os.environ.get("ACXELIN_KEEP_LOGS"):
            print(f"logs kept in {self.d}", file=sys.stderr)
        else:
            shutil.rmtree(self.d, ignore_errors=True)

    def wait(self, cond, message, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if cond():
                    return
            except Exception:
                pass
            time.sleep(0.5)
        logs = "\n".join(f"--- {f.name}\n" + f.read_text()[-3000:] for f in sorted(self.d.glob("*.log")))
        self.fail(f"{message}\n{logs}")

    def tunnel(self, tag):
        from acxelin_vpn.charon import Charon
        with Charon(f"unix://{self.d}/{tag}.vici") as ch:
            return min(ch.tunnels(), key=lambda t: t["established_s"], default=None)

    def test_controller_recovers_after_responder_daemon_restart(self):
        self.wait(lambda: (t := self.tunnel('hq')) and t['state'] == 'ESTABLISHED' and t['ppk'], 'initial IKE negotiation failed')
        controllers = self.procs[2:4]
        self.procs[0].terminate()
        self.procs[0].wait(5)
        self.spawn('ip', 'netns', 'exec', 'pqc-hq', 'unshare', '-m', 'sh', '-c',
                   f'mount -t tmpfs tmpfs /run && STRONGSWAN_CONF={self.d}/hq.conf exec {SS}/libexec/ipsec/charon')
        self.wait(lambda: (t := self.tunnel('hq')) and t['state'] == 'ESTABLISHED' and t['ppk'],
                  'controller did not reconnect and restore responder configuration', 100)
        self.assertTrue(all(p.poll() is None for p in controllers), 'controllers must recover without being restarted')
        if os.environ.get('ACXELIN_VPN_DATAPLANE'):
            from acxelin_vpn.charon import protected
            self.wait(lambda: protected(self.tunnel('hq')), 'no encrypted child after daemon restart')
            sh('ip', 'netns', 'exec', 'pqc-br', 'ping', '-c', '3', '-W', '2', '-I', '192.168.20.1', '192.168.10.1')

    def test_quantum_safe_tunnel_rotation_and_revocation(self):
        up = lambda: (t := self.tunnel("hq")) and t["state"] == "ESTABLISHED" and t["ppk"]
        self.wait(up, "the tunnel did not come up with a PPK")
        t = self.tunnel("hq")
        self.assertIn("ML_KEM_768", t["key_exchange"])
        self.assertIn("CURVE_25519", t["key_exchange"])
        self.assertEqual(t["encryption"], "AES_GCM_16_256")

        if os.environ.get("ACXELIN_VPN_DATAPLANE"):
            from acxelin_vpn.charon import protected
            self.wait(lambda: protected(self.tunnel("hq")) and protected(self.tunnel("br")),
                      "IKE negotiated but no encrypted child SA was installed; check kernel IPsec support")
            sh("ip", "netns", "exec", "pqc-br", "ping", "-c", "3", "-W", "2", "-I", "192.168.20.1", "192.168.10.1")
            from support_vpn import redis_application
            application = redis_application(self, "pqc-hq", "pqc-br", "192.168.10.1", "192.168.20.1")
            self.wait(application, "Redis SET/GET did not cross the encrypted IPsec tunnel")
            child = self.tunnel("hq")["children"][0]
            self.assertEqual(child["state"], "INSTALLED")
            self.assertGreaterEqual(child["packets_in"], 3)

        agreements = lambda: (self.d / "hq-controller.log").read_text().count("new keys")
        born = lambda: time.time() - self.tunnel("br")["established_s"]
        self.wait(lambda: agreements() >= 2, "keys did not rotate within a minute", 90)
        rotated = time.time()
        self.wait(lambda: born() >= rotated - 3 and self.tunnel("br")["ppk"], "no new PPK-protected SA after rotation", 20)
        self.assertTrue(self.tunnel("br")["ppk"])
        if os.environ.get("ACXELIN_VPN_DATAPLANE"):
            self.wait(application, "Redis traffic failed after IPsec key rotation")

        serial = next(r.serial for r in self.ca.records() if r.common_name == "branch.acme")
        self.ca.revoke(serial, "keyCompromise")
        self.wait(lambda: self.tunnel("hq") is None, "hq kept the tunnel of a revoked branch", 40)
        log = (self.d / "hq-controller.log").read_text()
        self.assertIn("revoked", log)
