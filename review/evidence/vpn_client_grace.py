"""What the VPN client does when a key agreement fails while WireGuard is still handshaking.

Real Client class, real CA and device certificate; the tunnel is a stand-in that records what the client tells it.
Run 1: the shipped step(). Run 2: the same step() with ONE changed condition, no change to any message the gateway sees.
"""
import tempfile
import time
from pathlib import Path

from acxelin_core import tls
from acxelin_core.pki import CA
from acxelin_vpn import wireguard as w


class Tunnel:
    def __init__(self, folder):
        self.folder, self.up_, self.calls, self.age = folder, True, [], 12

    def down(self):
        self.up_ = False
        self.calls.append("down")

    def handshake_age(self, public):
        return self.age

    def routes(self, r):
        return r

    def device(self):
        return "wg0"


class Kill:
    def on(self, *a):
        pass

    def off(self):
        pass


def client(folder):
    ca = CA.init(folder / "ca", "Evidence Root")
    ca.issue("alice", "client", out=folder / "dev")
    (folder / "dev" / "ca.crt").write_bytes((folder / "ca" / "ca.crt").read_bytes())
    t = Tunnel(folder)
    c = w.Client("gw.example:7443", folder / "dev", tunnel=t, kill_switch=Kill(), apply=True)
    c.last = {"address": "10.99.0.2/24", "routes": ["10.99.0.0/24"], "rotate_s": 120, "gateway_public": "G="}
    c.applied = {"gateway_public": "G="}
    c.agree = lambda: (_ for _ in ()).throw(tls.TLSError("cannot reach the keyring (partition)"))
    c.due = 0.0
    return c, t


with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    print("== 1. shipped step(): agreement fails, WireGuard handshake is 12 s old (tunnel healthy)")
    c, t = client(d / "one")
    c.step()
    print("   tunnel calls:", t.calls, "| tunnel up:", t.up_, "| retry in:", round(c.due - time.time()), "s")

    print("== 2. the same step() with one changed condition: tear down only when the tunnel itself looks dead")
    original = w.Client.step

    def step_proposed(self):
        # identical to the shipped step() except `and self.quiet()` on the tear-down line
        import inspect
        src = inspect.getsource(original).replace("if self.apply_ and self.tunnel.up_:", "if self.apply_ and self.tunnel.up_ and self.quiet():")
        ns = {}
        exec("import time\n" + "from acxelin_vpn.wireguard import *\nfrom acxelin_vpn.wireguard import log, explain, tls, WGError\n" + "\n".join(line[4:] for line in src.splitlines()), ns)  # noqa: S102
        return ns["step"](self)

    for age, label in ((12, "handshake 12 s old (healthy)"), (200, "handshake 200 s old (gateway no longer answers)")):
        c, t = client(d / f"two{age}")
        t.age = age
        step_proposed(c)
        print(f"   {label}: tunnel calls: {t.calls} | tunnel up: {t.up_} | status: {c.status()['state']}, error: {c.error!r}")
