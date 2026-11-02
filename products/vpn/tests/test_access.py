"""Per-user route sets: what each person is told they can reach, and the rules that make it true."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from acxelin_core.pki import CA
from acxelin_vpn import access
from acxelin_vpn.wireguard import Client, Gateway, GatewayConfig
from support_vpn import REASON
from test_wireguard import FakeWG


def config(**kw):
    return GatewayConfig(**({"name": "vpn", "endpoint": "vpn:51820", "keyring_listen": "0.0.0.0:7443", "pool": "10.99.0.0/24", "cert": "c", "key": "k", "ca": "a",
                             "routes": ["10.20.0.0/16", "10.30.0.0/16"], "manage_interface": False} | kw))


class ConfigTest(unittest.TestCase):
    def test_a_valid_access_table_is_accepted(self):
        cfg = config(access={"alice": ["10.20.1.0/24"], "bob": ["10.30.0.0/16", "10.20.5.0/24"]}, users=["alice", "bob", "carol"]).validate()
        self.assertEqual(cfg.access["alice"], ["10.20.1.0/24"])

    def test_every_mistake_is_named_with_the_way_out(self):
        cases = {
            "unknown user": (dict(access={"mallory": ["10.20.0.0/24"]}, users=["alice"]), "mallory.*not in users"),
            "outside routes": (dict(access={"alice": ["172.16.0.0/12"]}, users=["alice"]), "172.16.0.0/12.*not inside.*routes"),
            "not a network": (dict(access={"alice": ["10.20.0.0/33"]}, users=["alice"]), "10.20.0.0/33.*not a network"),
            "ipv6": (dict(access={"alice": ["fd00::/8"]}, users=["alice"]), "IPv4"),
            "empty": (dict(access={"alice": []}, users=["alice"]), "alice.*at least one network"),
            "everything": (dict(access={"alice": ["0.0.0.0/0"]}, users=["alice"]), "0.0.0.0/0"),
            "full tunnel": (dict(access={"alice": ["10.20.0.0/24"]}, users=["alice"], full_tunnel=True, routes=[]), "full_tunnel"),
            "not a list": (dict(access={"alice": "10.20.0.0/24"}, users=["alice"]), "list"),
            "too many": (dict(access={"alice": [f"10.20.{i}.0/24" for i in range(257)]}, users=["alice"]), "256"),
        }
        for name, (kw, pattern) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(ValueError, pattern):
                config(**kw).validate()

    def test_a_user_with_no_entry_is_unrestricted_as_before(self):
        self.assertEqual(config(users=["alice"]).validate().access, {})


class RulesetTest(unittest.TestCase):
    def test_one_rule_per_restricted_address_and_none_for_the_rest(self):
        text = access.ruleset("wg0", {"alice": ("10.99.0.2", ["10.20.1.0/24"]), "bob": ("10.99.0.3", ["10.30.0.0/16", "10.20.5.0/24"])})
        self.assertEqual(text.count("ip saddr 10.99.0.2"), 2, "once for packets forwarded to the office, once for packets aimed at the gateway itself")
        self.assertEqual(text.count("ip saddr"), 4)
        self.assertIn('iifname "wg0" ip saddr 10.99.0.2 ip daddr != { 10.20.1.0/24 } drop', text)
        self.assertIn("ip daddr != { 10.20.5.0/24, 10.30.0.0/16 }", text, "networks sorted, so the same configuration gives the same text")
        self.assertNotIn("carol", text)

    def test_the_text_replaces_the_old_table_in_one_step_and_is_deterministic(self):
        a = access.ruleset("wg0", {"alice": ("10.99.0.2", ["10.20.1.0/24"])})
        self.assertEqual(a, access.ruleset("wg0", {"alice": ("10.99.0.2", ["10.20.1.0/24"])}))
        lines = a.splitlines()
        self.assertEqual(lines[:2], ["table inet acxelin_vpn_access", "delete table inet acxelin_vpn_access"], "created if missing, then replaced, in one transaction")

    def test_names_and_addresses_that_could_inject_rules_are_refused_or_neutralised(self):
        text = access.ruleset("wg0", {'a"; drop }\naccept #': ("10.99.0.2", ["10.20.1.0/24"])})
        self.assertEqual(len(text.splitlines()), len(access.ruleset("wg0", {"a": ("10.99.0.2", ["10.20.1.0/24"])}).splitlines()))
        self.assertNotIn('a"', text)
        for bad_interface in ('wg0"; accept', "wg 0", "", "x" * 16):
            with self.subTest(interface=bad_interface), self.assertRaises(ValueError):
                access.ruleset(bad_interface, {})
        with self.assertRaises(ValueError):
            access.ruleset("wg0", {"a": ("10.99.0.2; accept", ["10.20.1.0/24"])})
        with self.assertRaises(ValueError):
            access.ruleset("wg0", {"a": ("10.99.0.2", ["10.20.1.0/24, 0.0.0.0/0"])})

    @unittest.skipUnless(shutil.which("nft"), "needs nft")
    def test_nft_itself_accepts_what_we_write(self):
        text = access.ruleset("wg0", {"alice": ("10.99.0.2", ["10.20.1.0/24"]), "bob": ("10.99.0.3", ["10.30.0.0/16"])})
        r = subprocess.run(["nft", "-c", "-f", "-"], input=text, capture_output=True, text=True)
        if "Operation not permitted" in r.stderr or "Permission denied" in r.stderr:
            self.skipTest("nft cannot check rules without privileges")
        self.assertEqual(r.returncode, 0, r.stderr)


class FakeFirewall:
    def __init__(self, fail=False):
        self.applied, self.fail = [], fail

    def apply(self, text):
        if self.fail:
            raise access.AccessError("nft said no")
        self.applied.append(text)


@unittest.skipIf(REASON, REASON)
class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.d = Path(self.tmp.name)
        self.ca = CA.init(d / "pki", "VPN Root")
        self.ca.issue("localhost", "server", out=d / "gw")
        self.ca.crl()
        for who in ("alice", "bob", "carol"):
            self.ca.issue(who, "client", out=d / who)
            (d / who / "ca.crt").write_bytes((d / "pki" / "ca.crt").read_bytes())
        self.fw = FakeFirewall()
        self.start(access={"alice": ["10.20.1.0/24"], "bob": ["10.30.0.0/16"]})

    def start(self, **kw):
        d = self.d
        self.cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24", cert=str(d / "gw" / "chain.pem"),
                                 key=str(d / "gw" / "key.pem"), ca=str(d / "pki" / "ca.crt"), crl=str(d / "pki" / "crl.pem"), private_key=str(d / "gw.key"),
                                 state=str(d / "state.json"), routes=["10.20.0.0/16", "10.30.0.0/16"], manage_interface=False, **kw).validate()
        self.gw = Gateway(self.cfg, FakeWG(), self.fw).start()
        self.addCleanup(self.gw.shutdown)

    def client(self, who):
        return Client(f"127.0.0.1:{self.gw.server.port}", self.d / who, server_name="localhost", apply=False, config_out=self.d / f"{who}.conf")

    def test_a_restricted_user_is_told_only_her_networks_and_the_others_everything_as_before(self):
        self.assertEqual(self.client("alice").agree()[0]["routes"], ["10.20.1.0/24"])
        self.assertEqual(self.client("bob").agree()[0]["routes"], ["10.30.0.0/16"])
        self.assertEqual(self.client("carol").agree()[0]["routes"], ["10.99.0.0/24", "10.20.0.0/16", "10.30.0.0/16"])

    def test_the_rules_are_applied_before_a_restricted_user_hears_her_address(self):
        reply, _ = self.client("alice").agree()
        self.assertTrue(self.fw.applied, "no rules were applied")
        self.assertIn(f"ip saddr {reply['address'].split('/')[0]} ip daddr != {{ 10.20.1.0/24 }} drop", self.fw.applied[-1])

    def test_an_unrestricted_user_causes_no_rules(self):
        self.client("carol").agree()
        self.assertTrue(not self.fw.applied or "carol" not in self.fw.applied[-1])

    def test_if_the_rules_cannot_be_applied_the_user_is_refused_in_words_and_gets_no_peer(self):
        self.fw.fail = True
        with self.assertRaisesRegex(Exception, "access rules"):
            self.client("alice").agree()
        self.assertEqual(self.gw.wg.peers_, {}, "a restricted user must never be connected without her restriction")

    def test_changing_a_users_networks_while_running_applies_at_once_and_a_failure_keeps_the_old_ones(self):
        self.client("alice").agree()
        import dataclasses
        new = dataclasses.replace(self.cfg, access={"alice": ["10.20.2.0/24"], "bob": ["10.30.0.0/16"]})
        self.assertTrue(self.gw.reconfigure(new))
        self.assertIn("{ 10.20.2.0/24 }", self.fw.applied[-1])
        self.fw.fail = True
        worse = dataclasses.replace(self.cfg, access={"alice": ["10.20.3.0/24"]})
        self.assertFalse(self.gw.reconfigure(worse), "a configuration whose rules cannot be applied is not applied")
        self.assertEqual(self.gw.cfg.access["alice"], ["10.20.2.0/24"])

    def test_starting_without_nft_for_a_restricted_configuration_is_refused_in_words(self):
        cfg = config(access={"alice": ["10.20.1.0/24"]}, manage_interface=True, users=["alice"]).validate()
        with self.assertRaisesRegex(RuntimeError, "nft"):
            access.require(cfg, which=lambda name: None)
        access.require(config(manage_interface=False, access={"alice": ["10.20.1.0/24"]}).validate(), which=lambda name: None)  # nothing manages the interface: rules are printed, not applied
        access.require(config().validate(), which=lambda name: None)  # nobody is restricted


class CommandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        (self.d / "state.json").write_text('{"alice": "10.99.0.2", "carol": "10.99.0.4"}', encoding="utf-8")
        base = Path(__file__).parent.parent / "config" / "gateway.toml"
        text = base.read_text(encoding="utf-8").replace('state = "/var/lib/acxelin-vpn/wireguard-state.json"', f'state = "{(self.d / "state.json").as_posix()}"')
        text = text.replace('routes = ["192.168.10.0/24"]', 'routes = ["192.168.10.0/24", "192.168.30.0/24"]').replace("users = []", 'users = ["alice", "carol", "dave"]')
        self.conf = self.d / "gateway.toml"
        text = text.replace('# "alice@acme.example" = ["192.168.10.0/24"]', 'alice = ["192.168.30.0/24"]')  # the sample's commented example, switched on
        self.assertIn('alice = ["192.168.30.0/24"]', text)
        self.conf.write_text(text, encoding="utf-8")

    def run_cli(self, *args):
        import os
        import sys
        p = subprocess.run([sys.executable, "-m", "acxelin_vpn", "access", *args, "--config", str(self.conf)], capture_output=True, text=True, env=dict(os.environ), timeout=60)
        return p.returncode, p.stdout, p.stderr

    def test_show_says_who_is_limited_and_that_everyone_else_gets_everything(self):
        code, out, err = self.run_cli("show")
        self.assertEqual(code, 0, err)
        self.assertIn("alice: 192.168.30.0/24 (tunnel address 10.99.0.2)", out)
        self.assertIn("everyone else (carol, dave) gets all routes", out)

    def test_rules_print_exactly_what_the_gateway_would_apply_for_the_leases_it_holds(self):
        code, out, err = self.run_cli("rules")
        self.assertEqual(code, 0, err)
        self.assertEqual(out, access.ruleset("wg0", {"alice": ("10.99.0.2", ["192.168.30.0/24"])}))

    def test_a_mistake_in_the_table_is_one_line_in_words(self):
        self.conf.write_text(self.conf.read_text(encoding="utf-8").replace('alice = ["192.168.30.0/24"]', 'alice = ["172.16.0.0/12"]'), encoding="utf-8")
        code, out, err = self.run_cli("show")
        self.assertNotEqual(code, 0)
        self.assertIn("not inside any of the routes", err + out)
