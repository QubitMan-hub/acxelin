"""Acxelin VPN: post-quantum site-to-site IPsec, and WireGuard remote access for people.

Key exchange is IKEv2 with a hybrid classical + ML-KEM exchange (RFC 9370), on the initial exchange and on every rekey; the
strict `cnsa2` profile uses ML-KEM-1024 alone, with only CNSA 2.0 algorithms everywhere.
strongSwan cannot yet authenticate with ML-DSA, so authentication is anchored in ML-DSA another way: the gateways agree keys
over post-quantum mutual TLS (ML-DSA certificates from our CA, X25519MLKEM768) and derive, from that session's exporter,
the IKE pre-shared key and an RFC 8784 post-quantum pre-shared key (PPK). Both rotate; a revoked gateway gets no new keys.
"""
import ipaddress
from dataclasses import dataclass, field

from acxelin_core.config import build, read_toml

NAME = "acxelin-vpn"
__version__ = "1.0.2"

PROFILES = {
    "standard": ("aes256gcm16-prfsha384-x25519-ke1_mlkem768", "aes256gcm16-x25519-ke1_mlkem768"),
    "high": ("aes256gcm16-prfsha512-ecp384-ke1_mlkem1024", "aes256gcm16-ecp384-ke1_mlkem1024"),
    "cnsa2": ("aes256gcm16-prfsha384-mlkem1024", "aes256gcm16-mlkem1024"),  # NSA CNSA 2.0: ML-KEM-1024, AES-256, SHA-384
}


@dataclass
class Peer:
    name: str
    address: str
    local_subnets: list
    remote_subnets: list
    initiate: bool = False
    keyring: str = ""
    profile: str = "standard"
    rotate_minutes: float = 60.0


@dataclass
class Site:
    name: str
    address: str
    cert: str
    key: str
    ca: str
    crl: str = ""
    crl_url: str = ""
    crl_every: float = 60.0
    key_passphrase_env: str = ""
    vici: str = "unix:///var/run/charon.vici"
    keyring_listen: str = ""
    metrics: str = ""
    peers: list = field(default_factory=list)

    def peer(self, name):
        return next((p for p in self.peers if p.name == name), None)


def load_config(path):
    doc = read_toml(path)
    if "site" not in doc:
        raise ValueError(f"{path}: missing [site]")
    site = build(Site, doc["site"], "[site]", peers=[build(Peer, p, f"peer #{i + 1}") for i, p in enumerate(doc.get("peer", []))])
    validate(site)
    return site


def validate(site):
    if not site.peers:
        raise ValueError("no [[peer]] sections")
    names = [p.name for p in site.peers]
    if len(set(names)) != len(names) or site.name in names:
        raise ValueError("peer names must be unique and differ from the site name")
    for p in site.peers:
        if p.profile not in PROFILES:
            raise ValueError(f"{p.name}: profile must be one of {', '.join(PROFILES)}")
    if len({p.profile == "cnsa2" for p in site.peers}) > 1:
        raise ValueError("profile = \"cnsa2\" must be set on every peer of a site or none: they share one key agreement service")
    for p in site.peers:
        if p.initiate and not p.keyring:
            raise ValueError(f"{p.name}: initiate = true needs keyring = \"host:port\" (the peer's key agreement service)")
        if p.rotate_minutes < 1:
            raise ValueError(f"{p.name}: rotate_minutes must be at least 1")
        for net in p.local_subnets + p.remote_subnets:
            ipaddress.ip_network(net)
    if site.crl_url and not site.crl:
        raise ValueError("crl_url needs crl = \"PATH\", where the copy is kept")
    if site.crl_every < 5:
        raise ValueError("crl_every must be at least 5 seconds")
    if any(not p.initiate for p in site.peers) and not site.keyring_listen:
        raise ValueError("peers that initiate towards this site need keyring_listen = \"0.0.0.0:7443\"")
