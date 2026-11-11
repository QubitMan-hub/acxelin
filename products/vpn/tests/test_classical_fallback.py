"""A per-peer classical fallback for partner gateways without hybrid ML-KEM: off unless that one peer asks for it; offers hybrid ML-KEM
first, then classical with an RFC 8784 PPK, then plain classical; and anything below hybrid is labelled NOT QUANTUM SAFE everywhere."""
import json
import logging
import os
import textwrap

import pytest

from acxelin_vpn import PROFILES, Peer, Site, load_config
from acxelin_vpn.charon import CLASSICAL, conn_config, tier


def site(*peers, **kw):
    return Site("hq.acme", "10.0.0.1", "hq.pem", "hq.key", "ca.crt", peers=list(peers), **kw)


def secret(tmp_path, name, size=48, mode=0o600):
    p = tmp_path / name
    p.write_bytes(os.urandom(size).hex().encode()[:size])
    os.chmod(p, mode)
    return str(p)


def posix(path):
    """A path as TOML takes it on every system: in a double-quoted TOML string a Windows backslash starts an escape."""
    return __import__("pathlib").Path(path).as_posix()


def strict(name="branch.acme"):
    return Peer(name, "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"])


def legacy(tmp_path, ppk=True, **kw):
    return Peer("partner.example", "198.51.100.40", ["10.1.0.0/16"], ["10.7.0.0/16"], classical_fallback=True,
                fallback_psk_file=secret(tmp_path, "partner.psk"), fallback_ppk_file=secret(tmp_path, "partner.ppk") if ppk else "", **kw)


# --- it never activates without an explicit per-peer setting

def test_off_by_default_and_a_strict_peer_is_unchanged_byte_for_byte(tmp_path):
    p = strict()
    assert p.classical_fallback is False
    alone = json.dumps(conn_config(site(p), p), sort_keys=True)
    with_partner = json.dumps(conn_config(site(p, legacy(tmp_path)), p), sort_keys=True)
    assert alone == with_partner, "another peer's fallback changes nothing for this one"
    c = conn_config(site(p), p)["branch.acme"]
    assert c["proposals"] == [PROFILES["standard"][0]] and c["ppk_required"] == "yes"
    assert c["children"]["net"]["esp_proposals"] == [PROFILES["standard"][1]]
    assert not any(x in json.dumps(c) for x in CLASSICAL.values())


def write(tmp_path, peer_extra, site_extra=""):
    f = tmp_path / "site.toml"
    f.write_text(textwrap.dedent("""
        [site]
        name = "hq.acme"
        address = "10.0.0.1"
        cert = "hq.pem"
        key = "hq.key"
        ca = "ca.crt"
        """) + site_extra + textwrap.dedent("""
        [[peer]]
        name = "partner.example"
        address = "198.51.100.40"
        local_subnets = ["10.1.0.0/16"]
        remote_subnets = ["10.7.0.0/16"]
        """) + peer_extra)
    return f


def test_secrets_without_the_switch_do_not_turn_it_on(tmp_path):
    psk = secret(tmp_path, "p.psk")
    with pytest.raises(ValueError, match="classical_fallback = true"):
        load_config(write(tmp_path, f'fallback_psk_file = "{posix(psk)}"\n'))
    with pytest.raises(ValueError, match="unknown settings classical_fallback"):
        load_config(write(tmp_path, "", "classical_fallback = true\n"))  # there is no site-wide switch
    with pytest.raises(ValueError):
        load_config(write(tmp_path, f'classical_fallback = "yes"\nfallback_psk_file = "{posix(psk)}"\n'))
    assert load_config(write(tmp_path, f'classical_fallback = true\nfallback_psk_file = "{posix(psk)}"\n')).peers[0].classical_fallback


# --- the order: hybrid ML-KEM, then classical with a PPK, then plain classical

def test_hybrid_first_then_classical_and_the_ppk_used_when_the_partner_supports_it(tmp_path):
    p = legacy(tmp_path)
    c = conn_config(site(p), p)["partner.example"]
    assert c["proposals"][0] == PROFILES["standard"][0], "hybrid ML-KEM is offered first"
    assert c["proposals"][1:] == [CLASSICAL["ike"]]
    assert c["children"]["net"]["esp_proposals"] == [PROFILES["standard"][1], CLASSICAL["esp"]]
    assert c["ppk_required"] == "no" and c["ppk_id"], "the PPK is used when the partner speaks RFC 8784, and not required"
    plain = legacy(tmp_path, ppk=False)
    c = conn_config(site(plain), plain)["partner.example"]
    assert "ppk_id" not in c and "ppk_required" not in c


@pytest.mark.parametrize("tunnel, expected", [
    ({"key_exchange": "CURVE_25519/ML_KEM_768", "ppk": True}, "hybrid"),
    ({"key_exchange": "CURVE_25519/ML_KEM_768", "ppk": False}, "hybrid"),
    ({"key_exchange": "CURVE_25519", "ppk": True}, "classical+ppk"),
    ({"key_exchange": "ECP_384", "ppk": False}, "classical"),
])
def test_the_tier_a_tunnel_reached(tunnel, expected):
    assert tier(tunnel | {"state": "ESTABLISHED"}) == expected


# --- refused where it cannot be right

def test_the_configuration_is_checked(tmp_path):
    with pytest.raises(ValueError, match="fallback_psk_file"):
        Peer("x", "1.2.3.4", [], [], classical_fallback=True).validate()
    if os.name != "nt":  # site-to-site tunnels run on Linux gateways (strongSwan); Windows ACLs are not read, as for TLS key files
        with pytest.raises(ValueError, match="readable only by its owner"):
            Peer("x", "1.2.3.4", [], [], classical_fallback=True, fallback_psk_file=secret(tmp_path, "open.psk", mode=0o644)).validate()
    with pytest.raises(ValueError, match="at least 32"):
        Peer("x", "1.2.3.4", [], [], classical_fallback=True, fallback_psk_file=secret(tmp_path, "short.psk", size=16)).validate()
    with pytest.raises(ValueError, match="cnsa2"):
        legacy(tmp_path, profile="cnsa2").validate()
    with pytest.raises(ValueError, match="keyring"):
        legacy(tmp_path, keyring="198.51.100.40:7443").validate()
    with pytest.raises(ValueError, match="qkd"):
        legacy(tmp_path, qkd_sae_id="SAE_2").validate()


# --- NOT QUANTUM SAFE in logs, metrics, status, CBOM and console

class FakeCharon:
    def __init__(self, tunnels=()):
        self.loaded, self.keys, self.conns, self.initiated, self.sas = [], set(), [], [], list(tunnels)

    def version(self):
        return "charon 6.1"

    def ml_kem(self):
        return ["ML_KEM_768"]

    def load_keys(self, site, peer, psk, ppk, ppk_id, key_tag):
        self.loaded.append((peer, psk, ppk, ppk_id))

    def load_static(self, site, peer, psk, ppk, ppk_id):
        self.loaded.append((peer, psk, ppk, ppk_id))

    def load_conn(self, config):
        self.conns.append(config)

    def initiate(self, peer, timeout_ms=15000):
        self.initiated.append(peer)

    def terminate(self, peer):
        pass

    def shared_ids(self):
        return []

    def unload_key(self, key_id):
        pass

    def tunnels(self):
        return self.sas


def classical_sa(peer="partner.example", ppk=True):
    return {"peer": peer, "state": "ESTABLISHED", "established_s": 10, "key_exchange": "CURVE_25519", "ppk": ppk,
            "encryption": "AES_GCM_16_256", "children": [{"state": "INSTALLED", "bytes_in": 1, "bytes_out": 2}]}


def test_the_controller_loads_static_keys_never_agrees_and_never_expires_the_partner(tmp_path):
    from acxelin_vpn.controller import Controller
    p = legacy(tmp_path)
    ch = FakeCharon()
    ctl = Controller(site(p), charon=ch)
    ctl.start()
    ctl.shutdown()
    assert [x[0] for x in ch.loaded] == ["partner.example"] and ch.loaded[0][1] == open(p.fallback_psk_file, "rb").read().strip()
    assert ch.conns and ch.conns[0]["partner.example"]["proposals"][1] == CLASSICAL["ike"]
    ch.sas = [classical_sa()]
    ctl.started -= 10_000
    ctl.enforce()
    assert ch.sas, "a static-key partner is not cut for lack of key agreements it cannot take part in"


def test_logs_status_and_metrics_say_not_quantum_safe(tmp_path, caplog):
    from acxelin_vpn.controller import Controller
    p, s = legacy(tmp_path), strict()
    ch = FakeCharon([classical_sa(), {"peer": "branch.acme", "state": "ESTABLISHED", "established_s": 5, "key_exchange": "CURVE_25519/ML_KEM_768",
                                      "ppk": True, "children": [{"state": "INSTALLED", "bytes_in": 0, "bytes_out": 0}]}])
    ctl = Controller(site(p, s), charon=ch)
    with caplog.at_level(logging.WARNING):
        ctl.report_tiers()
        ctl.report_tiers()
    lines = [m for m in caplog.messages if "NOT QUANTUM SAFE" in m and "partner.example" in m]
    assert len(lines) == 1, "once when the tier is seen, not on every pass"
    st = ctl.status()
    assert st["partner.example"]["quantum_safe"] is False and st["partner.example"]["tier"] == "classical+ppk"
    assert st["partner.example"]["classical_fallback"] is True and st["branch.acme"]["quantum_safe"] is True
    m = ctl.metrics()
    assert 'acxelin_vpn_tunnel_quantum_safe{peer="partner.example"} 0' in m
    assert 'acxelin_vpn_tunnel_quantum_safe{peer="branch.acme"} 1' in m
    assert 'acxelin_vpn_tunnel_tier{peer="partner.example",tier="classical+ppk"} 1' in m
    psk = open(p.fallback_psk_file).read()
    assert psk not in json.dumps(st) and psk not in m and not any(psk in x for x in caplog.messages)


def test_the_cbom_marks_the_partner_tunnel_not_quantum_safe_and_holds_no_secret(tmp_path):
    from acxelin_vpn.inventory import cbom
    psk = secret(tmp_path, "partner.psk")
    f = write(tmp_path, f'classical_fallback = true\nfallback_psk_file = "{posix(psk)}"\n')
    bom = cbom([f])
    doc = json.loads(bom)
    tunnel = next(c for c in doc["components"] if c["name"] == "tunnel hq.acme to partner.example")
    props = {x["name"]: x["value"] for x in tunnel.get("properties", [])}
    assert props["acxelin:quantum-safe"] == "false" and props["acxelin:label"] == "NOT QUANTUM SAFE"
    assert open(psk).read() not in bom


def test_the_console_shows_the_badge():
    page = (__import__("pathlib").Path(__import__("acxelin_vpn").__file__).parent / "console.html").read_text(encoding="utf-8")
    assert "Not quantum safe" in page and "t.quantum_safe === false" in page
