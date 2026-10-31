"""The VPN client on Linux, macOS and Windows. The unit tests check what each platform is told to do, against a recording stand-in for
its tools, and run everywhere. RealTunnelTest brings a real tunnel up with this machine's WireGuard, rotates its PSK and takes it
down; it runs in CI on macOS and Windows (ACXELIN_REAL_WIREGUARD=1, as root or administrator). Linux has its own namespace tests
with real traffic in test_wireguard."""
import base64
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from acxelin_core.pki import CA
from acxelin_vpn import platforms
from acxelin_vpn.platforms import FULL, SECRET, LinuxKillSwitch, MacKillSwitch, MacTunnel, Tunnel, WGError, WindowsTunnel
from acxelin_vpn.wireguard import Client, wg_quick


def key():
    k = x25519.X25519PrivateKey.generate()
    raw = lambda b: base64.b64encode(b).decode()
    return (raw(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
            raw(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))


class Recorder:
    """Stands in for the platform's tools: records each command (with the secret it was given) and answers from `replies`."""

    def __init__(self, replies=None, fail=()):
        self.calls, self.replies, self.fail = [], replies or {}, fail

    def __call__(self, cmd, secret=None, env=None):
        words = [Path(c).stem if i == 0 else ("SECRET" if c is SECRET else c) for i, c in enumerate(cmd)]
        self.calls.append((words, secret, env))
        if any(words[:len(f)] == list(f) for f in self.fail):
            raise WGError(" ".join(words))
        return next((v for k, v in self.replies.items() if words[:len(k)] == list(k)), "")

    def commands(self):
        return [c for c, _, _ in self.calls]


class TunnelTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.run = Recorder()

    def test_linux_and_macos_use_wg_quick_and_rotate_in_place(self):
        t = Tunnel("wg0", self.dir, self.run)
        t.up("[Interface]\nPrivateKey = x\n")
        self.assertEqual(self.run.commands()[-1], ["wg-quick", "up", str(self.dir / "wg0.conf")])
        if os.name != "nt":
            self.assertEqual((self.dir / "wg0.conf").stat().st_mode & 0o077, 0, "the configuration holds keys")
        t.wg().set_psk("PEER", "PSK")
        words, secret, _ = self.run.calls[-1]
        self.assertEqual((words, secret), (["wg", "set", "wg0", "peer", "PEER", "preshared-key", "SECRET"], "PSK"))
        t.up("again")
        self.assertEqual(self.run.commands()[-2:], [["wg-quick", "down", str(self.dir / "wg0.conf")], ["wg-quick", "up", str(self.dir / "wg0.conf")]])
        t.down()
        self.assertFalse(t.up_)

    def test_userspace_wireguard_is_passed_to_wg_quick(self):
        with mock.patch.dict(os.environ, {"ACXELIN_WIREGUARD_GO": "/opt/wireguard-go"}):
            Tunnel("wg0", self.dir, self.run).up("x")
        self.assertEqual(self.run.calls[-1][2]["WG_QUICK_USERSPACE_IMPLEMENTATION"], "/opt/wireguard-go")

    def test_ipv6_is_left_out_only_where_the_kernel_has_none(self):
        t = Tunnel("wg0", self.dir, self.run)
        with mock.patch.object(platforms, "ipv6", return_value=False):
            self.assertEqual(t.routes(FULL), ["0.0.0.0/0"])
        with mock.patch.object(platforms, "ipv6", return_value=True):
            self.assertEqual(t.routes(FULL), FULL)

    def test_macos_finds_the_utun_interface_wg_quick_chose(self):
        with mock.patch.object(Path, "read_text", return_value="utun7\n"):
            self.assertEqual(MacTunnel("wg0", self.dir, self.run).device(), "utun7")

    def test_windows_installs_a_tunnel_service_with_a_locked_down_configuration(self):
        t = WindowsTunnel("wg0", self.dir, self.run)
        t.up("[Interface]\n")
        conf = str(self.dir / "wg0.conf")
        self.assertEqual(self.run.commands(), [["icacls", conf, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"],
                                               ["wireguard", "/installtunnelservice", conf], ["wg", "show", "wg0"]])
        t.down()
        self.assertEqual(self.run.commands()[-1], ["wireguard", "/uninstalltunnelservice", "wg0"])

    def test_handshake_age(self):
        now = int(time.time())
        run = Recorder({("wg", "show", "wg0", "latest-handshakes"): f"GW\t{now - 200}\nOTHER\t0\n"})
        t = Tunnel("wg0", self.dir, run)
        self.assertAlmostEqual(t.handshake_age("GW"), 200, delta=5)
        self.assertIsNone(t.handshake_age("OTHER"))

    def test_this_machine(self):
        for kind, tunnel, kill in (("Linux", Tunnel, LinuxKillSwitch), ("Darwin", MacTunnel, MacKillSwitch), ("Windows", WindowsTunnel, platforms.KillSwitch)):
            with self.subTest(kind=kind), mock.patch.object(platforms, "system", return_value=kind):
                t, k = platforms.this_machine("wg0", self.dir)
                self.assertIs(type(t), tunnel)
                self.assertIs(type(k), kill)


class KillSwitchTest(unittest.TestCase):
    ENDPOINT, KEYRING = (["203.0.113.1", "2001:db8::1"], 51820), (["203.0.113.1"], 7443)

    def test_linux_fails_closed_while_the_rules_change(self):
        run = Recorder(fail=[("iptables", "-D"), ("ip6tables", "-D")])
        ks = LinuxKillSwitch(tempfile.mkdtemp(), run)
        with mock.patch.object(platforms, "ipv6", return_value=True):
            ks.on("wg0", self.ENDPOINT, self.KEYRING)
        v4 = [c for c in run.commands() if c[0] == "iptables"]
        added = [c[3:] for c in v4 if c[1] == "-A"]
        self.assertEqual(added[-1], ["-j", "REJECT"])
        self.assertIn(["-o", "wg0", "-j", "ACCEPT"], added)
        self.assertIn(["-d", "203.0.113.1", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"], added)
        self.assertIn(["-d", "203.0.113.1", "-p", "tcp", "--dport", "7443", "-j", "ACCEPT"], added)
        self.assertNotIn(["-d", "2001:db8::1", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"], added)
        order = [c[1] for c in v4 if c[1] in ("-A", "-I", "-E")]
        self.assertEqual(order[-2:], ["-I", "-E"], "the complete new chain is jumped to before the old one goes")
        self.assertIn(["-d", "2001:db8::1", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"],
                      [c[3:] for c in run.commands() if c[0] == "ip6tables" and c[1] == "-A"])
        n = len(run.calls)
        ks.on("wg0", self.ENDPOINT, self.KEYRING)
        self.assertEqual(len(run.calls), n, "an unchanged kill switch is not rebuilt at every key rotation")
        ks.off()
        self.assertIn(["iptables", "-X", "ACXELIN-KILLSWITCH"], run.commands())

    def test_macos_uses_a_pf_anchor_and_releases_pf_afterwards(self):
        run = Recorder({("pfctl", "-E"): "pf enabled\nToken : 12345\n"})
        folder = Path(tempfile.mkdtemp())
        ks = MacKillSwitch(folder, run)
        ks.on("utun4", self.ENDPOINT, self.KEYRING)
        rules = (folder / "killswitch.pf").read_text().splitlines()
        self.assertEqual(rules[-1], "block drop out quick all")
        self.assertIn("pass out quick on utun4 all", rules)
        self.assertIn("pass out quick proto udp to 2001:db8::1 port 51820", rules)
        self.assertIn("pass out quick proto tcp to 203.0.113.1 port 7443", rules)
        self.assertEqual(run.commands()[:2], [["pfctl", "-a", "com.apple/acxelin-vpn", "-f", str(folder / "killswitch.pf")], ["pfctl", "-E"]])
        ks.on("utun5", self.ENDPOINT, self.KEYRING)
        self.assertEqual(run.commands().count(["pfctl", "-E"]), 1, "pf is enabled once, with one reference")
        ks.off()
        self.assertEqual(run.commands()[-2:], [["pfctl", "-a", "com.apple/acxelin-vpn", "-F", "all"], ["pfctl", "-X", "12345"]])


class ServiceTest(unittest.TestCase):
    ARGV = [sys.executable, "-m", "acxelin_vpn", "connect", "vpn.acme:7443", "--cert-dir", "/etc/acxelin/alice & co"]

    def test_each_platform_starts_the_client_at_boot_and_restarts_it(self):
        path, text, start, stop = platforms.service(self.ARGV, "Linux")
        self.assertIn("Restart=always", text)
        self.assertIn(["systemctl", "enable", "--now", "acxelin-vpn"], start)
        path, text, start, stop = platforms.service(self.ARGV, "Darwin")
        self.assertIn("<key>KeepAlive</key><true/>", text)
        self.assertIn("<string>/etc/acxelin/alice &amp; co</string>", text)
        self.assertEqual(start, [["launchctl", "bootstrap", "system", str(path)]])
        path, text, start, stop = platforms.service(self.ARGV, "Windows")
        self.assertIn("goto again", text)
        self.assertEqual(start[0][:4], ["schtasks", "/create", "/tn", "acxelin-vpn"])
        self.assertIn("SYSTEM", start[0])


class FakeTunnel:
    def __init__(self):
        self.up_, self.ups, self.psks, self.age = False, [], [], None

    def up(self, text):
        self.up_ = True
        self.ups.append(text)

    def down(self):
        self.up_ = False

    def device(self):
        return "wg9"

    def routes(self, routes):
        return routes

    def wg(self):
        return self

    def set_psk(self, peer, psk):
        self.psks.append(psk)

    def handshake_age(self, peer):
        return self.age


class FakeKillSwitch:
    def __init__(self):
        self.state = None

    def on(self, device, endpoint, keyring):
        self.state = (device, endpoint, keyring)

    def off(self):
        self.state = None


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        CA.init(d / "pki", "Root").issue("alice", "client", out=d / "alice")
        cls.folder = d / "alice"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.tunnel, self.kill = FakeTunnel(), FakeKillSwitch()
        self.c = Client("127.0.0.1:7443", self.folder, tunnel=self.tunnel, kill_switch=self.kill)
        self.gw = key()[1]
        self.replies, self.fail = [], None

        def agree():
            if self.fail:
                raise OSError(self.fail)
            return self.replies[-1], f"psk{len(self.tunnel.ups) + len(self.tunnel.psks)}"
        self.c.agree = agree

    def reply(self, routes=("10.99.0.0/24",), **kw):
        self.replies.append({"address": "10.99.0.2/24", "routes": list(routes), "dns": [], "endpoint": "127.0.0.1:51820",
                             "gateway_public": self.gw, "rotate_s": 120} | kw)

    def test_the_tunnel_comes_up_once_and_later_keys_are_set_in_place(self):
        self.reply()
        self.c.once()
        self.c.once()
        self.assertEqual((len(self.tunnel.ups), len(self.tunnel.psks)), (1, 1))
        self.assertIsNone(self.kill.state)
        self.reply(routes=("10.99.0.0/24", "192.168.10.0/24"))
        self.c.once()
        self.assertEqual(len(self.tunnel.ups), 2, "new routes from the gateway bring the tunnel up again")

    def test_full_tunnel_turns_the_kill_switch_on_and_back_off(self):
        self.reply(routes=FULL)
        self.c.once()
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", self.tunnel.ups[-1])
        self.assertEqual(self.kill.state, ("wg9", (["127.0.0.1"], 51820), (["127.0.0.1"], 7443)))
        self.reply()
        self.c.once()
        self.assertIsNone(self.kill.state)

    def test_keys_are_renewed_right_after_waking_from_sleep(self):
        self.reply()
        self.c.step()
        agreed = len(self.tunnel.psks) + len(self.tunnel.ups)
        self.assertLessEqual(self.c.step(), 5.0, "the loop looks at the clock at least every five seconds")
        self.assertEqual(len(self.tunnel.psks) + len(self.tunnel.ups), agreed, "not due yet")
        with mock.patch("acxelin_vpn.wireguard.time.time", return_value=time.time() + 3600):
            self.c.step()
        self.assertEqual(len(self.tunnel.psks) + len(self.tunnel.ups), agreed + 1, "an hour of sleep: renewed at once")

    def test_a_quiet_tunnel_is_renewed_and_a_dead_one_taken_down_to_reach_the_gateway(self):
        self.reply()
        self.c.step()
        self.tunnel.age = 400
        self.fail = "timed out"
        self.assertLessEqual(self.c.step(), 1.0, "retried at once, now outside the tunnel")
        self.assertFalse(self.tunnel.up_)
        self.fail = None
        with mock.patch("acxelin_vpn.wireguard.time.time", return_value=time.time() + 2):
            self.c.step()
        self.assertTrue(self.tunnel.up_)

    def test_a_tunnel_that_will_not_come_up_is_retried_with_backoff_and_reported(self):
        self.reply()
        self.tunnel.up = mock.Mock(side_effect=WGError("wg-quick up: Unable to access interface: Operation not permitted"))
        waits = []
        for _ in range(4):
            self.c.step()
            waits.append(round(self.c.due - time.time()))
            self.c.due = 0
        self.assertEqual(waits, [5, 10, 20, 40])
        s = self.c.status()
        self.assertEqual(s["state"], "not_protected")
        self.assertIn("Operation not permitted", s["error"])
        self.assertIsNone(self.kill.state, "no kill switch for a tunnel that never came up")

    def test_close_lifts_the_kill_switch(self):
        self.reply(routes=FULL)
        self.c.once()
        self.c.close()
        self.assertFalse(self.tunnel.up_)
        self.assertIsNone(self.kill.state)


class ToolFailureTest(unittest.TestCase):
    """What the client says when this machine's WireGuard tools are missing, hang or refuse."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_a_missing_tool_says_how_to_install_it_on_this_platform(self):
        for kind, hint in (("Linux", "apt install"), ("Darwin", "brew install"), ("Windows", "wireguard.com/install")):
            with self.subTest(kind=kind), mock.patch.object(platforms, "system", return_value=kind):
                with self.assertRaisesRegex(WGError, f"acxelin-no-such-tool is not installed: .*{hint}"):
                    platforms.run(["acxelin-no-such-tool", "show"])

    def test_a_tool_that_hangs_or_fails_is_reported_and_the_secret_file_is_removed(self):
        kept = []
        real = subprocess.run

        def spy(cmd, **kw):
            kept.append(Path(cmd[-1]))
            self.assertEqual(Path(cmd[-1]).read_text(), "s3cret\n")
            return real(cmd, **kw)
        with mock.patch.object(platforms.subprocess, "run", spy), self.assertRaisesRegex(WGError, "bad key"):
            platforms.run([sys.executable, "-c", "import sys; sys.exit('bad key')", SECRET], secret="s3cret")
        self.assertFalse(kept[0].exists())
        with mock.patch.object(platforms.subprocess, "run", side_effect=subprocess.TimeoutExpired("wg", 60)):
            with self.assertRaisesRegex(WGError, "wg set gave no answer within 60 s"):
                platforms.run(["wg", "set"])
        self.assertIn("ok", platforms.run([sys.executable, "-c", "print('ok')"]))

    def test_wg_commands_and_dump(self):
        run = Recorder({("wg", "show", "wg0", "dump"): "PRIV\tPUB\t51820\toff\nGW\tPSK\t1.2.3.4:51820\t10.0.0.0/24,10.1.0.0/24\t17\t5\t6\t25\n"
                                                         "NEW\t(none)\t(none)\t10.9.0.2/32\t0\t0\t0\toff\n"})
        wg = platforms.WG("wg0", runner=run)
        wg.set_private_key("PRIVATE", 51820)
        wg.set_peer("GW", "PSK", ["10.0.0.0/24"], "1.2.3.4:51820", 25)
        wg.remove_peer("OLD")
        self.assertEqual(run.commands(), [["wg", "set", "wg0", "private-key", "SECRET", "listen-port", "51820"],
                                          ["wg", "set", "wg0", "peer", "GW", "preshared-key", "SECRET", "allowed-ips", "10.0.0.0/24",
                                           "endpoint", "1.2.3.4:51820", "persistent-keepalive", "25"],
                                          ["wg", "set", "wg0", "peer", "OLD", "remove"]])
        self.assertEqual([s for _, s, _ in run.calls], ["PRIVATE", "PSK", None])
        peers = wg.peers()
        self.assertEqual(peers["GW"], {"endpoint": "1.2.3.4:51820", "allowed_ips": ["10.0.0.0/24", "10.1.0.0/24"], "psk": True,
                                       "latest_handshake": 17, "rx_bytes": 5, "tx_bytes": 6})
        self.assertEqual((peers["NEW"]["endpoint"], peers["NEW"]["psk"]), (None, False))

    def test_taking_down_a_tunnel_that_is_already_down_is_not_an_error(self):
        run = Recorder(fail=[("wg-quick", "down")])
        t = Tunnel("wg0", self.dir, run)
        t.up("[Interface]\n")
        t.down()
        self.assertFalse(t.up_)
        w = WindowsTunnel("wg0", self.dir, Recorder(fail=[("wireguard", "/uninstalltunnelservice")]))
        w.up_ = True
        w.down()
        self.assertFalse(w.up_)

    def test_windows_gives_up_when_the_tunnel_service_never_starts(self):
        run = Recorder(fail=[("wg", "show")])
        clock = iter([0, 5, 25])
        with mock.patch.object(platforms.time, "monotonic", lambda: next(clock)), mock.patch.object(platforms.time, "sleep") as sleep:
            with self.assertRaisesRegex(WGError, "wg show wg0"):
                WindowsTunnel("wg0", self.dir, run).up("[Interface]\n")
        sleep.assert_called_once_with(0.5)
        self.assertEqual([c[0] for c in run.commands()], ["icacls", "wireguard", "wg", "wg"])

    def test_windows_leaves_the_kill_switch_to_wireguard(self):
        run = Recorder()
        k = platforms.KillSwitch(self.dir, run)
        k.on("wg0", (["1.2.3.4"], 51820), (["1.2.3.4"], 7443))
        k.off()
        self.assertEqual(run.calls, [])

    def test_lifting_the_kill_switch_survives_rules_that_are_already_gone(self):
        run = Recorder(fail=[("iptables",), ("ip6tables",)])
        LinuxKillSwitch(self.dir, run).off()
        self.assertIn(["iptables", "-X", "ACXELIN-KILLSWITCH"], run.commands())
        mac = MacKillSwitch(self.dir, Recorder(fail=[("pfctl",)]))
        mac.token.write_text("1234")
        mac.off()
        self.assertFalse(mac.token.exists(), "a pf that already let go still forgets its token")

    def test_each_platform_keeps_tunnels_in_a_system_folder(self):
        for kind, tail in (("Linux", "/run/acxelin-vpn"), ("Darwin", "/var/run/acxelin-vpn"), ("Windows", "Acxelin/vpn")):
            with self.subTest(kind=kind), mock.patch.object(platforms, "system", return_value=kind):
                self.assertTrue(platforms.folder().as_posix().endswith(tail))

    def test_install_and_uninstall_the_service(self):
        unit = self.dir / "acxelin-vpn.service"
        with mock.patch.object(platforms, "require_protected_code"), mock.patch.object(platforms, "service", lambda argv, kind=None, name=platforms.SERVICE: (unit if name == platforms.SERVICE else self.dir / "none.service", "x".join(argv), [["start"]], [["stop"], ["disable"]])):
            run = Recorder()
            self.assertEqual(platforms.install(["a", "b"], run), unit)
            self.assertEqual((unit.read_text(), run.commands()), ("axb", [["start"]]))
            run = Recorder(fail=[("stop",)])
            platforms.uninstall(run)
            self.assertFalse(unit.exists())
            self.assertEqual(run.commands(), [["stop"], ["disable"]], "a service that is not running is still removed")


@unittest.skipUnless(os.environ.get("ACXELIN_REAL_WIREGUARD") == "1", "brings a real tunnel up: set ACXELIN_REAL_WIREGUARD=1 (root or administrator)")
class RealTunnelTest(unittest.TestCase):
    """A split tunnel to a peer that never answers: enough to prove the platform's WireGuard takes the configuration, the PSK
    rotation and the removal. Full tunnel is left out here, because its kill switch would cut the CI runner off."""

    def test_up_rotate_down(self):
        folder = Path(tempfile.mkdtemp())
        tunnel, kill = platforms.this_machine("pqctest0", folder)
        private, _ = key()
        peer = key()[1]
        reply = {"address": "10.123.0.2/24", "routes": ["10.123.0.0/24"], "dns": [], "endpoint": "127.0.0.1:51999", "gateway_public": peer}
        psk1, psk2 = key()[0], key()[0]
        try:
            tunnel.up(wg_quick(private, reply, psk1))
            show = lambda: tunnel.wg().run("show", tunnel.device(), "preshared-keys")
            self.assertIn(psk1, show())
            tunnel.wg().set_psk(peer, psk2)
            self.assertIn(psk2, show())
            if platforms.system() == "Darwin":
                (folder / "check.pf").write_text(kill.rules(tunnel.device(), (["127.0.0.1"], 51999), (["127.0.0.1"], 7443)))
                subprocess.run(["pfctl", "-nf", str(folder / "check.pf")], check=True, capture_output=True)
        finally:
            tunnel.down()
        with self.assertRaises(WGError):
            platforms.WG("pqctest0", platforms.find("wg")).run("show", "pqctest0")


if __name__ == "__main__":
    unittest.main()
