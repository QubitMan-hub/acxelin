"""Keys from quantum key distribution (ETSI GS QKD 014) mixed into a site's IPsec keys: both sites end with the same keys, which
differ from the post-quantum keys alone; a peer configured for QKD that arrives without a QKD key is refused, and a key server
that fails or answers badly stops the key agreement instead of weakening it."""
import base64
import json
import secrets
import unittest
from unittest.mock import Mock

from support_vpn import REASON
from test_vpn import Conn, site

from acxelin_vpn import Peer, Site, qkd, validate


class Pair:
    """Two key servers joined by one QKD link: what one hands out under an ID, the other returns for that ID, once."""
    def __init__(self):
        self.store, self.fail = {}, False

    def side(self, sae):
        pair = self

        class Side:
            sae_id = sae

            def new_key(self, peer_sae):
                if pair.fail:
                    raise qkd.QKDError("key server unreachable")
                key_id, key = "6f1c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f", secrets.token_bytes(32)
                pair.store[key_id] = (sae, peer_sae, key)
                return key_id, key

            def key(self, peer_sae, key_id):
                if key_id not in pair.store:
                    raise qkd.QKDError("no such key")
                origin, target, key = pair.store.pop(key_id)
                assert (origin, target) == (peer_sae, sae)
                return key
        return Side()


def qkd_site(name, peer_name, initiate, **kw):
    peer = Peer(peer_name, "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=initiate, keyring="10.0.0.2:7443" if initiate else "",
                qkd_sae_id="SAE_" + peer_name.split(".")[0].upper())
    return Site(name, "10.0.0.1", "c", "k", "a", peers=[peer], keyring_listen="" if initiate else "0.0.0.0:7443",
                qkd_kme="https://kme.example:8443", qkd_sae_id="SAE_" + name.split(".")[0].upper(), qkd_cert="c", qkd_key="k", qkd_ca="a", **kw)


class QKDMixTest(unittest.TestCase):
    def controllers(self):
        from unittest import mock
        from acxelin_vpn.controller import Controller
        pair = Pair()
        hq, branch = Controller(qkd_site("hq.acme", "branch.acme", True), charon=Mock()), Controller(qkd_site("branch.acme", "hq.acme", False), charon=Mock())
        hq.kme, branch.kme = pair.side("SAE_HQ"), pair.side("SAE_BRANCH")
        return hq, branch, pair, mock

    def test_both_sites_mix_the_same_qkd_key_into_their_ipsec_keys(self):
        from acxelin_vpn import controller
        hq, branch, pair, mock = self.controllers()
        sent = []
        conn = Conn("branch.acme", b'{"ok": true}\n')
        conn.sendall = sent.append
        with mock.patch.object(controller.tls, "client_context"), mock.patch.object(controller.tls, "connect", return_value=conn):
            hq.agree(hq.site.peers[0])
        msg = json.loads(sent[0])
        self.assertIn("qkd_key_id", msg)
        stored = dict(pair.store)
        reply = Conn("hq.acme", msg=sent[0])
        branch.respond(reply, ("10.0.0.1", 1))
        self.assertEqual(reply.sent, [b'{"ok": true}\n'])
        ours, theirs = hq.charon.load_keys.call_args.args, branch.charon.load_keys.call_args.args
        self.assertEqual(ours[2:4], theirs[2:4])  # same PSK and PPK on both sides
        self.assertNotEqual(ours[2] + ours[3], b"k" * 64)  # not the post-quantum keys alone
        self.assertEqual(len(ours[2] + ours[3]), 64)
        self.assertEqual(pair.store, {}, stored)  # the QKD key was used once
        self.assertEqual(hq.counts["qkd_keys"], 1)

    def test_a_peer_configured_for_qkd_that_sends_no_qkd_key_is_refused(self):
        hq, branch, pair, mock = self.controllers()
        line = json.dumps({"v": 1, "site": "hq.acme", "tag": "aaaaaaaaaaaa"}).encode() + b"\n"
        conn = Conn("hq.acme", msg=line)
        branch.respond(conn, ("10.0.0.1", 1))
        self.assertEqual(conn.sent, [b'{"ok": false}\n'])
        branch.charon.load_keys.assert_not_called()
        self.assertEqual(branch.counts["key_agreements_refused"], 1)

    def test_a_failing_key_server_stops_the_agreement_instead_of_weakening_it(self):
        from acxelin_vpn import controller
        hq, branch, pair, mock = self.controllers()
        pair.fail = True
        with mock.patch.object(controller.tls, "client_context"), mock.patch.object(controller.tls, "connect", return_value=Conn("branch.acme")):
            with self.assertRaisesRegex(qkd.QKDError, "unreachable"):
                hq.agree(hq.site.peers[0])
        hq.charon.load_keys.assert_not_called()

    def test_qkd_settings_come_all_together(self):
        s = qkd_site("hq.acme", "branch.acme", True)
        validate(s)
        s.qkd_cert = ""
        with self.assertRaisesRegex(ValueError, "qkd_"):
            validate(s)
        bad = qkd_site("hq.acme", "branch.acme", True)
        bad.peers[0].qkd_sae_id = "../etc"
        with self.assertRaisesRegex(ValueError, "qkd_sae_id"):
            validate(bad)
        plain = site()
        plain.peers[0].qkd_sae_id = "SAE_B"
        with self.assertRaisesRegex(ValueError, "qkd_kme"):
            validate(plain)


@unittest.skipIf(REASON, REASON)
class KeyServerTest(unittest.TestCase):
    """The ETSI GS QKD 014 client against a key server over mutual TLS."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from acxelin_core import https, tls
        from acxelin_core.pki import CA
        from acxelin_core.server import Server
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        ca = CA.init(tmp / "ca", "QKD Root")
        ca.issue("kme", "server", ["127.0.0.1"], out=tmp / "kme")
        ca.issue("SAE_HQ", "client", [], out=tmp / "sae")
        self.answer = None
        self.store = {}

        def app(method, path, headers, body, conn):
            if self.answer:
                return 200, self.answer, {"Content-Type": "application/json"}
            req = json.loads(body or b"{}")
            if path == "/api/v1/keys/SAE_BRANCH/enc_keys" and method == "POST":
                key_id, key = "6f1c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f", secrets.token_bytes(req["size"] // 8)
                self.store[key_id] = key
                return 200, json.dumps({"keys": [{"key_ID": key_id, "key": base64.b64encode(key).decode()}]}).encode(), {}
            if path == "/api/v1/keys/SAE_BRANCH/dec_keys" and method == "POST":
                ids = [k["key_ID"] for k in req["key_IDs"]]
                return 200, json.dumps({"keys": [{"key_ID": i, "key": base64.b64encode(self.store[i]).decode()} for i in ids]}).encode(), {}
            return 400, b'{"message": "bad request"}', {}
        make = lambda: tls.server_context(qkd.KME_POLICY, tmp / "kme/chain.pem", tmp / "kme/key.pem", tmp / "ca/ca.crt", True)
        self.server = Server(("127.0.0.1", 0), make, https.handler(app), ca=tmp / "ca/ca.crt", name="kme")
        self.server.start()
        self.addCleanup(self.server.stop)
        self.kme = qkd.KME(f"https://127.0.0.1:{self.server.port}", "SAE_HQ", tmp / "ca/ca.crt", tmp / "sae/chain.pem", tmp / "sae/key.pem")

    def test_a_key_handed_out_is_returned_by_its_id(self):
        key_id, key = self.kme.new_key("SAE_BRANCH")
        self.assertEqual(len(key), 32)
        self.assertEqual(self.kme.key("SAE_BRANCH", key_id), key)

    def test_bad_answers_are_refused(self):
        for answer in (b"not json", b'{"keys": []}', b'{"keys": [{"key_ID": "a", "key": "c2hvcnQ="}]}',
                       json.dumps({"keys": [{"key_ID": "x", "key": base64.b64encode(b"k" * 32).decode()}] * 2}).encode()):
            self.answer = answer
            with self.assertRaises(qkd.QKDError, msg=answer):
                self.kme.new_key("SAE_BRANCH")
        with self.assertRaises(ValueError):
            qkd.KME("http://127.0.0.1:1", "SAE_HQ", "a", "c", "k")  # QKD keys never travel without TLS
