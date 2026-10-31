"""Bugs a correctness review reproduced, each now fixed: a full-tunnel laptop that could not renew once DNS was blocked, a pool
kept full by people who had left, two shipped configurations on the same ports, doctor failing a fresh gateway, a rotation the
laptops refuse, a failed setup that blocked the next one, and a silent tunnel that re-agreed keys every few seconds."""
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from acxelin_core.pki import CA
from acxelin_vpn import checks, setup
from acxelin_vpn.wireguard import Client, Gateway, GatewayConfig
from support_vpn import REASON
from test_wireguard import FakeWG

CONFIG = Path(__file__).resolve().parents[1] / "config"


class Tunnel:
    def __init__(self, folder, age=1):
        self.folder, self.up_, self.ups, self.age = Path(folder), False, 0, age

    def routes(self, r):
        return r

    def up(self, text):
        self.up_, self.ups = True, self.ups + 1

    def down(self):
        self.up_ = False

    def wg(self):
        return self

    def set_psk(self, *a):
        pass

    def device(self):
        return "wg0"

    def handshake_age(self, public):
        return self.age


@unittest.skipIf(REASON, REASON)
class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = d = Path(self.tmp.name)
        self.ca = CA.init(d / "pki", "Root")
        self.ca.issue("localhost", "server", out=d / "gw")
        self.ca.crl()

    def gateway(self, **kw):
        d = self.d
        cfg = GatewayConfig(**{"name": "localhost", "endpoint": "vpn.example.test:51820", "keyring_listen": "127.0.0.1:0", "pool": "10.99.0.0/24",
                               "cert": str(d / "gw/chain.pem"), "key": str(d / "gw/key.pem"), "ca": str(d / "pki/ca.crt"), "crl": str(d / "pki/crl.pem"),
                               "private_key": str(d / "gw.key"), "state": str(d / "state.json"), "manage_interface": False} | kw).validate()
        gw = Gateway(cfg, FakeWG()).start()
        self.addCleanup(gw.shutdown)
        return gw

    def person(self, name, **kw):
        self.ca.issue(name, "client", out=self.d / name)
        (self.d / name / "ca.crt").write_bytes((self.d / "pki/ca.crt").read_bytes())
        return Client(f"localhost:{self.gw.server.port}", self.d / name, server_name="localhost", **kw)

    def test_a_full_tunnel_laptop_renews_with_dns_blocked(self):
        self.gw = self.gateway(full_tunnel=True)
        ks = mock.Mock()
        c = self.person("alice", tunnel=Tunnel(self.d), kill_switch=ks)
        real = __import__("acxelin_vpn.wireguard", fromlist=["addresses"]).addresses
        lookup = lambda host: ["203.0.113.9"] if host == "vpn.example.test" else real(host)
        with mock.patch("acxelin_vpn.wireguard.addresses", side_effect=lookup):
            c.step()
        self.assertIsNone(c.error)
        with mock.patch("acxelin_vpn.wireguard.addresses", side_effect=OSError("DNS blocked by the kill switch")):
            c.due = 0
            c.step()
        self.assertIsNone(c.error, "the renewal used the addresses saved before the kill switch")
        self.assertEqual(ks.on.call_args.args[1], (["203.0.113.9"], 51820))

    def test_people_who_left_do_not_keep_the_pool_full(self):
        self.gw = self.gateway(pool="10.99.0.0/29")  # 10.99.0.2 to .6 for people
        for n in "abcde":
            self.person(n, apply=False).agree()
        self.gw.clients.clear()  # all five went offline (revoked, or left the company)
        reply, _ = self.person("f", apply=False).agree()
        self.assertTrue(reply["address"].startswith("10.99.0."), "a newcomer gets an address someone offline held")
        self.gw.clients.update({n: {"public": "x"} for n in self.gw.leases})  # everyone holding an address is connected
        with self.assertRaisesRegex(Exception, "address pool is full"):
            self.person("g", apply=False).agree()

    def test_a_rotation_the_laptops_would_refuse_is_refused_at_once(self):
        with self.assertRaisesRegex(ValueError, "rotate_minutes"):
            GatewayConfig(name="g", endpoint="g:51820", keyring_listen="0.0.0.0:7443", pool="10.99.0.0/24", cert="c", key="k", ca="a",
                          private_key="p", state="s", rotate_minutes=1500).validate()

    def test_a_tunnel_that_stays_silent_is_rebuilt_not_re_agreed_every_few_seconds(self):
        self.gw = self.gateway()
        t = Tunnel(self.d, age=400)
        c = self.person("quiet", tunnel=t, kill_switch=mock.Mock())
        c.step()
        self.assertEqual(t.ups, 1)
        c.step()
        self.assertEqual(t.ups, 2, "the tunnel was rebuilt after the silent-tunnel key agreement")


class SetupTest(unittest.TestCase):
    def test_a_bad_option_leaves_nothing_behind(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                setup.gateway(Path(d) / "s", "vpn.example.com", pool="10.0.0.0/30x", passphrase=None)
            self.assertFalse((Path(d) / "s").exists())

    @unittest.skipIf(REASON, REASON)
    def test_doctor_passes_a_gateway_setup_just_made(self):
        with tempfile.TemporaryDirectory() as d:
            conf = setup.gateway(Path(d) / "s", "localhost", passphrase=None)
            found = checks.config(conf)
            self.assertFalse([m for level, m in found if level == "fail"], found)


class ConfigTest(unittest.TestCase):
    def test_the_shipped_site_and_gateway_can_run_on_one_machine(self):
        site = tomllib.loads((CONFIG / "site-hq.toml").read_text())
        gw = tomllib.loads((CONFIG / "gateway.toml").read_text())["wireguard"]
        port = lambda a: a.rsplit(":", 1)[1]
        site_ports = {port(v) for v in _values(site, ("keyring_listen", "metrics"))}
        self.assertFalse(site_ports & {port(gw["keyring_listen"]), port(gw["metrics"])})


def _values(doc, keys):
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k in keys and isinstance(v, str):
                yield v
            yield from _values(v, keys)
    elif isinstance(doc, list):
        for v in doc:
            yield from _values(v, keys)


if __name__ == "__main__":
    time.sleep(0)
    unittest.main()
