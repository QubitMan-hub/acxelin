"""`acxelin-vpn evidence`: a signed bundle of what a site or gateway is and does (build, configuration, doctor, certificates,
its CBOM, what it reports while running), and the check of one. Keys, passphrases and pre-shared keys are never read into it."""
from pathlib import Path

from acxelin_core import evidence
from acxelin_core.config import read_toml

from . import NAME, __version__, checks, inventory, load_config


def _loaded(path):
    """The configuration as the VPN reads it, and the certificate files it names."""
    from .wireguard import load_gateway
    kind = next((k for k in ("site", "wireguard") if k in read_toml(path)), None)
    if kind is None:
        raise ValueError(f"{path}: no [site] or [wireguard] section")
    try:
        c = load_config(path) if kind == "site" else load_gateway(path)
    except ValueError as e:
        raise ValueError(e if str(path) in str(e) else f"{path}: {e}") from None
    return kind, [(role, getattr(c, role)) for role in ("cert", "ca", "qkd_cert", "qkd_ca") if getattr(c, role, "")]


def parts(a):
    kind, files = _loaded(a.config)
    out = {"build.json": {"product": NAME, "version": __version__, "environment": evidence.environment(),
                          "packages": evidence.packages(NAME, "acxelin-core", "cryptography")},
           "config.toml": Path(a.config).read_bytes(),
           "doctor.json": checks.prerequisites() + [{"level": lv, "message": m} for lv, m in checks.config(a.config)],
           "certificates.json": [row for role, f in files for row in evidence.certificates(f, role=role)],
           "cbom.json": inventory.cbom([a.config])}
    if a.status:
        out["status.json"] = evidence.fetch_status(a.status, f"start the {kind} with metrics on and give that address")
    return out


def options(p):
    p.add_argument("--config", required=True, help="the site or gateway configuration")


def add(sub):
    evidence.add_commands(sub, NAME, parts, options)
