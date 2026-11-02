"""The access rules against real packets: three network namespaces (a laptop with three tunnel addresses, the gateway with the rules, an office with two networks).

Needs root, iproute2, nftables and Python in each namespace; ACXELIN_REQUIRE_NETNS=1 turns "cannot run" into a failure (CI sets it)."""
import os
import shutil
import subprocess
import sys
import uuid

import pytest

from acxelin_vpn import access

NEEDS = ("ip", "nft")
WHY = ("needs root, `ip` and `nft`" if os.name == "posix" else "Linux only")


def usable():
    if os.name != "posix" or os.geteuid() != 0 or not all(shutil.which(c) for c in NEEDS):
        return False
    probe = f"acxprobe{uuid.uuid4().hex[:6]}"
    made = subprocess.run(["ip", "netns", "add", probe], capture_output=True).returncode == 0
    subprocess.run(["ip", "netns", "del", probe], capture_output=True)
    return made


if not usable() and os.environ.get("ACXELIN_REQUIRE_NETNS") == "1":
    pytest.fail(f"ACXELIN_REQUIRE_NETNS=1 but this machine cannot create network namespaces ({WHY})", pytrace=False)
pytestmark = pytest.mark.skipif(not usable(), reason=WHY)


def sh(*cmd, ns=None, input=None, check=True):
    argv = ["ip", "netns", "exec", ns, *cmd] if ns else list(cmd)
    r = subprocess.run(argv, capture_output=True, text=True, input=input, timeout=30)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(argv)}: {r.stderr.strip()}")
    return r


@pytest.fixture
def lab():
    n = uuid.uuid4().hex[:5]
    names = {"laptop": f"acxl{n}", "gateway": f"acxg{n}", "office": f"acxo{n}"}
    for ns in names.values():
        sh("ip", "netns", "add", ns)
    try:
        for a, b, na, nb in (("vc" + n, "wgt0", "laptop", "gateway"), ("vo" + n, "lan0", "office", "gateway")):
            sh("ip", "link", "add", a, "type", "veth", "peer", "name", b)
            sh("ip", "link", "set", a, "netns", names[na])
            sh("ip", "link", "set", b, "netns", names[nb])
        L, G, O = names["laptop"], names["gateway"], names["office"]
        for ns in (L, G, O):
            sh("ip", "link", "set", "lo", "up", ns=ns)
        for addr in ("10.99.0.2/24", "10.99.0.3/24", "10.99.0.4/24"):
            sh("ip", "addr", "add", addr, "dev", "vc" + n, ns=L)
        sh("ip", "link", "set", "vc" + n, "up", ns=L)
        sh("ip", "route", "add", "default", "via", "10.99.0.1", ns=L)
        sh("ip", "addr", "add", "10.99.0.1/24", "dev", "wgt0", ns=G)
        sh("ip", "addr", "add", "10.20.0.1/24", "dev", "lan0", ns=G)
        sh("ip", "addr", "add", "10.30.0.1/24", "dev", "lan0", ns=G)
        sh("ip", "link", "set", "wgt0", "up", ns=G)
        sh("ip", "link", "set", "lan0", "up", ns=G)
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=G)
        for addr in ("10.20.0.5/24", "10.30.0.5/24"):
            sh("ip", "addr", "add", addr, "dev", "vo" + n, ns=O)
        sh("ip", "link", "set", "vo" + n, "up", ns=O)
        sh("ip", "route", "add", "default", "via", "10.20.0.1", ns=O)
        server = subprocess.Popen(["ip", "netns", "exec", O, sys.executable, "-c",
                                   "import socket,threading\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',8000));s.listen(50)\n"
                                   "while True:\n c,_=s.accept();c.sendall(b'hi');c.close()"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        gateway_server = subprocess.Popen(["ip", "netns", "exec", G, sys.executable, "-c",
                                           "import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',9000));s.listen(50)\n"
                                           "while True:\n c,_=s.accept();c.sendall(b'hi');c.close()"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import time
        time.sleep(0.5)
        yield L, G
    finally:
        for p in ("server", "gateway_server"):
            if p in locals():
                locals()[p].kill()
        for ns in names.values():
            sh("ip", "netns", "del", ns, check=False)


def reaches(lab, source, destination, port=8000):
    laptop, _ = lab
    code = ("import socket,sys\ns=socket.socket();s.settimeout(1.5);s.bind((sys.argv[1],0))\n"
            "try:\n s.connect((sys.argv[2],int(sys.argv[3])));sys.exit(0 if s.recv(2)==b'hi' else 1)\nexcept OSError:\n sys.exit(1)")
    return sh(sys.executable, "-c", code, source, destination, str(port), ns=laptop, check=False).returncode == 0


def load(lab, restricted):
    sh("nft", "-f", "-", ns=lab[1], input=access.ruleset("wgt0", restricted))


def test_before_any_rules_everyone_reaches_everything(lab):
    for src in ("10.99.0.2", "10.99.0.3", "10.99.0.4"):
        assert reaches(lab, src, "10.20.0.5") and reaches(lab, src, "10.30.0.5")


def test_each_restricted_person_reaches_only_her_networks_and_an_unrestricted_one_everything(lab):
    load(lab, {"alice": ("10.99.0.2", ["10.20.0.0/24"]), "bob": ("10.99.0.3", ["10.30.0.0/24"])})
    assert reaches(lab, "10.99.0.2", "10.20.0.5") and not reaches(lab, "10.99.0.2", "10.30.0.5")
    assert reaches(lab, "10.99.0.3", "10.30.0.5") and not reaches(lab, "10.99.0.3", "10.20.0.5")
    assert reaches(lab, "10.99.0.4", "10.20.0.5") and reaches(lab, "10.99.0.4", "10.30.0.5"), "carol has no entry, so nothing changed for her"


def test_a_restricted_person_cannot_reach_other_people_or_the_gateway_itself(lab):
    load(lab, {"alice": ("10.99.0.2", ["10.20.0.0/24"])})
    assert reaches(lab, "10.99.0.4", "10.99.0.1", 9000), "an unrestricted laptop reaches a service on the gateway"
    assert not reaches(lab, "10.99.0.2", "10.99.0.1", 9000), "alice must not reach services on the gateway over the tunnel"


def test_a_changed_rule_set_takes_effect_at_once_and_clearing_it_restores_reach(lab):
    load(lab, {"alice": ("10.99.0.2", ["10.20.0.0/24"])})
    assert not reaches(lab, "10.99.0.2", "10.30.0.5")
    load(lab, {"alice": ("10.99.0.2", ["10.20.0.0/24", "10.30.0.0/24"])})
    assert reaches(lab, "10.99.0.2", "10.30.0.5")
    load(lab, {})
    assert reaches(lab, "10.99.0.2", "10.30.0.5") and reaches(lab, "10.99.0.2", "10.99.0.1", 9000)
