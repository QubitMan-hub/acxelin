"""Acxelin VPN: post-quantum site-to-site IPsec, and WireGuard remote access for people.

Key exchange is IKEv2 with a hybrid classical + ML-KEM exchange (RFC 9370), on the initial exchange and on every rekey; the
strict `cnsa2` profile uses ML-KEM-1024 alone, with only CNSA 2.0 algorithms everywhere.
strongSwan cannot yet authenticate with ML-DSA, so authentication is anchored in ML-DSA another way: the gateways agree keys
over post-quantum mutual TLS (ML-DSA certificates from our CA, X25519MLKEM768) and derive, from that session's exporter,
the IKE pre-shared key and an RFC 8784 post-quantum pre-shared key (PPK). Both rotate; a revoked gateway gets no new keys.
"""
import ipaddress
import re
from dataclasses import dataclass, field

from acxelin_core.config import build, read_toml

from .grace import check_minutes

NAME = "acxelin-vpn"
__version__ = "1.0.3"

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
    outage_grace_minutes: float = 0.0  # keep a silent peer on its last keys this long past the normal limit, while the CRL clears it
    qkd_sae_id: str = ""  # the peer's SAE ID on the QKD network: its keys get a QKD key mixed in
    # A partner gateway without Acxelin's key agreement (another vendor's IKEv2). Off unless set on this one peer; there is no site-wide
    # switch. It offers hybrid ML-KEM first, then classical with the RFC 8784 PPK in fallback_ppk_file, then plain classical:
    # anything below hybrid is NOT QUANTUM SAFE and is labelled so in logs, status, metrics, the CBOM and the console.
    classical_fallback: bool = False
    fallback_psk_file: str = ""  # the static IKE pre-shared key agreed with the partner out of band (owner-only, 32+ bytes)
    fallback_ppk_file: str = ""  # optional static RFC 8784 PPK, for partners that support it (owner-only, 32+ bytes)

    def validate(self):
        if not self.classical_fallback:
            if self.fallback_psk_file or self.fallback_ppk_file:
                raise ValueError(f"{self.name}: fallback_psk_file and fallback_ppk_file do nothing without classical_fallback = true on this peer")
            return
        if self.profile == "cnsa2":
            raise ValueError(f"{self.name}: classical_fallback cannot be used with profile = \"cnsa2\": CNSA 2.0 allows nothing classical")
        if self.keyring or self.qkd_sae_id:
            raise ValueError(f"{self.name}: classical_fallback is for a partner without Acxelin's key agreement, so it has no keyring and no qkd_sae_id")
        if not self.fallback_psk_file:
            raise ValueError(f"{self.name}: classical_fallback needs fallback_psk_file, the pre-shared key agreed with the partner")
        for what in ("fallback_psk_file", "fallback_ppk_file"):
            path = getattr(self, what)
            if path:
                read_secret(path, f"{self.name}: {what}")


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
    qkd_kme: str = ""  # https:// address of this site's QKD key server (ETSI GS QKD 014)
    qkd_sae_id: str = ""
    qkd_cert: str = ""
    qkd_key: str = ""
    qkd_ca: str = ""
    peers: list = field(default_factory=list)

    def peer(self, name):
        return next((p for p in self.peers if p.name == name), None)


def read_secret(path, where):
    """A static key from an owner-only file, at least 32 bytes after trimming whitespace. The owner-only rule is read from POSIX
    permissions, on the Linux gateways where site-to-site tunnels run; Windows ACLs are not read (as for TLS key files)."""
    import os
    import stat
    try:
        st, data = os.stat(path), open(path, "rb").read().strip()
    except OSError as e:
        raise ValueError(f"{where}: cannot read {path} ({e.strerror or e})") from None
    if os.name != "nt" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(f"{where}: {path} must be readable only by its owner (chmod 600)")
    if len(data) < 32:
        raise ValueError(f"{where}: {path} must hold at least 32 bytes of key")
    return data


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
        p.validate()
        if p.initiate and not p.keyring and not p.classical_fallback:
            raise ValueError(f"{p.name}: initiate = true needs keyring = \"host:port\" (the peer's key agreement service)")
        if p.rotate_minutes < 1:
            raise ValueError(f"{p.name}: rotate_minutes must be at least 1")
        check_minutes(f"{p.name}: ", p.outage_grace_minutes, site.crl)
        for net in p.local_subnets + p.remote_subnets:
            ipaddress.ip_network(net)
    qkd = [site.qkd_kme, site.qkd_sae_id, site.qkd_cert, site.qkd_key, site.qkd_ca]
    if any(qkd) and not all(qkd):
        raise ValueError("QKD needs all of qkd_kme, qkd_sae_id, qkd_cert, qkd_key and qkd_ca in [site]")
    for name, sae in [("[site]", site.qkd_sae_id)] + [(p.name, p.qkd_sae_id) for p in site.peers]:
        if sae and not re.match(r"^[A-Za-z0-9._-]{1,128}$", sae):
            raise ValueError(f"{name}: qkd_sae_id must be letters, digits, '.', '_' or '-'")
    if any(p.qkd_sae_id for p in site.peers) and not site.qkd_kme:
        raise ValueError("a peer with qkd_sae_id needs qkd_kme and the other qkd_ settings in [site]")
    if site.crl_url and not site.crl:
        raise ValueError("crl_url needs crl = \"PATH\", where the copy is kept")
    if site.crl_every < 5:
        raise ValueError("crl_every must be at least 5 seconds")
    if any(not p.initiate and not p.classical_fallback for p in site.peers) and not site.keyring_listen:
        raise ValueError("peers that initiate towards this site need keyring_listen = \"0.0.0.0:7443\"")
