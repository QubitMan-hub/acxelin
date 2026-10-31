"""`acxelin-vpn setup`: one command leaves a gateway that starts and agrees keys with a laptop; running it again does not overwrite
anything unless asked, and never replaces the certificate authority."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from acxelin_core.pki import CA
from acxelin_vpn import setup
from acxelin_vpn.wireguard import Client, Gateway, load_gateway
from support_vpn import REASON
from test_wireguard import FakeWG


@unittest.skipIf(REASON, REASON)
class SetupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name) / "vpn"

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "acxelin_vpn", "setup", "localhost", "--dir", str(self.d), "--no-encrypt", *args],
                              capture_output=True, text=True, timeout=120)

    def test_one_command_gives_a_gateway_that_works(self):
        r = self.run_cli("--route", "192.168.10.0/24", "--dns", "192.168.10.53")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("acxelin-vpn invite alice", r.stdout)
        cfg = load_gateway(self.d / "gateway.toml")
        self.assertEqual((cfg.routes, cfg.dns, cfg.name), (["192.168.10.0/24"], ["192.168.10.53"], "localhost"))
        cfg.keyring_listen, cfg.manage_interface = "127.0.0.1:0", False
        gw = Gateway(cfg, FakeWG()).start()
        self.addCleanup(gw.shutdown)
        ca = CA(self.d / "pki")
        ca.issue("alice", "client", out=self.d / "alice")
        (self.d / "alice" / "ca.crt").write_bytes((self.d / "pki" / "ca.crt").read_bytes())
        reply, _ = Client(f"127.0.0.1:{gw.server.port}", self.d / "alice", server_name="localhost", apply=False).agree()
        self.assertEqual(reply["routes"], ["10.99.0.0/24", "192.168.10.0/24"])

    def test_running_it_again_keeps_everything_unless_forced_and_never_replaces_the_ca(self):
        self.assertEqual(self.run_cli().returncode, 0)
        root = (self.d / "pki" / "ca.crt").read_bytes()
        again = self.run_cli()
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("--force", again.stderr)
        self.assertEqual(self.run_cli("--force").returncode, 0)
        self.assertEqual((self.d / "pki" / "ca.crt").read_bytes(), root)

    def test_a_name_that_is_not_a_host_name_is_refused(self):
        with self.assertRaisesRegex(ValueError, "host name"):
            setup.gateway(self.d, "vpn acme", passphrase=None)
