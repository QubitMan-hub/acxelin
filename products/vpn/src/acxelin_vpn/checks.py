"""Deployment checks for `acxelin-vpn doctor --ca DIR --config FILE`: each check is (level, message) with level ok, warn or fail."""
import datetime as dt
import importlib.util
import os
import shutil
import sys
from pathlib import Path

from acxelin_core.config import read_toml
from acxelin_core.pki import CA, CAError, encrypted, now, signed_by
from cryptography import x509


def _private(path):
    """A key file readable by everyone fails, by its group warns (Kubernetes mounts secrets group-readable for fsGroup). POSIX
    permissions only; Windows ACLs are not checked."""
    if os.name == "nt":
        return []
    mode = os.stat(path).st_mode
    if mode & 0o004:
        return [("fail", f"{path} can be read by every user (chmod 600 it)")]
    return [("warn", f"{path} can be read by its group (chmod 600 it unless the group is this service's)")] if mode & 0o040 else []


def ca(root):
    root, out = Path(root), []
    try:
        c = CA(root)
    except (CAError, OSError, ValueError) as e:
        return [("fail", f"CA at {root}: {e}")]
    left = (c.cert.not_valid_after_utc - now()).days
    valid_now = c.cert.not_valid_before_utc <= now() < c.cert.not_valid_after_utc
    out.append(("fail" if not valid_now else "ok" if left > 365 else "warn",
                f"CA {c.cert.subject.rfc4514_string()} ({c.algorithm}) " +
                (f"valid for {left} more days" if valid_now else "is expired or not yet valid; restore a valid CA before serving certificates")))
    if (root / "signer.json").exists():
        out.append(("ok", "CA key is held by an external signer (KMS or HSM)"))
    else:
        out += _private(root / "ca.key")
        out.append(("ok", "CA key is encrypted") if encrypted(root / "ca.key") else
                   ("warn", "CA key is not encrypted (created with --no-encrypt): anyone who copies ca.key can issue certificates; use KMS, an HSM or an encrypted key"))
    try:
        records = c.records()
    except (OSError, ValueError, TypeError) as e:
        return out + [("fail", f"{root / 'index.json'} cannot be read ({e}): restore it from a backup")]
    crl = root / "crl.pem"
    try:
        listed = x509.load_pem_x509_crl(crl.read_bytes()) if crl.exists() else None
    except ValueError:
        listed = False
    if listed is None:
        out.append(("fail", f"no {crl}: mutual-TLS services cannot start (acxelin-vpn ca crl)"))
    elif listed is False or not signed_by(c.cert, listed.tbs_certlist_bytes, listed.signature):
        out.append(("fail", f"{crl} is damaged or not signed by this CA; every client would be refused (acxelin-vpn ca crl)"))
    else:
        missing = [r.common_name for r in records if r.status == "revoked" and listed.get_revoked_certificate_by_serial_number(int(r.serial, 16)) is None]
        if missing:
            out.append(("fail", f"{len(missing)} revoked certificate(s) not in crl.pem ({', '.join(missing[:5])}): run acxelin-vpn ca crl"))
        nxt = listed.next_update_utc
        days = (nxt - now()) / dt.timedelta(days=1)
        out.append(("fail" if days < 0 else "warn" if days < 2 else "ok",
                    f"CRL {'expired' if days < 0 else 'valid for'} {abs(days):.1f} days{'' if days >= 2 else ': run acxelin-vpn ca maintain'}"))
    newest = {}
    for r in records:
        if r.status == "valid" and r.kind != "ca" and r.path and dt.datetime.fromisoformat(r.not_after) > now():
            newest[r.path] = max(newest.get(r.path, r), r, key=lambda x: x.not_after)
    gone = [r for r in newest.values() if not all((Path(r.path) / f).exists() for f in ("cert.pem", "key.pem", "chain.pem"))]
    if gone:
        out.append(("warn", f"{len(gone)} valid certificate(s) recorded without their files ({', '.join(r.common_name for r in gone[:5])}): "
                            "moved elsewhere, or a crash while issuing; revoke any whose files are gone for good"))
    soon = c.expiring(30)
    out.append(("warn", f"{len(soon)} certificate(s) expire within 30 days: {', '.join(r.common_name for r in soon[:5])} "
                        "(ca maintain renews gateways and sites; laptops renew their own when the app or join runs)") if soon else ("ok", "no certificate expires within 30 days"))
    return out


def _files(where, d, names):
    out = []
    for k in [n for n in names if not (n == "crl" and d.get("crl_url"))]:  # with crl_url the copy appears at the first fetch
        p = d.get(k)
        if not p:
            continue
        if not Path(p).exists():
            out.append(("fail", f"{where}: {k} = {p} does not exist"))
        elif k in ("key", "private_key"):
            out += _private(p)
    return out


def config(path):
    """Load a site or gateway configuration, then look for settings that work but weaken the deployment."""
    from . import load_config
    from .wireguard import load_gateway
    try:
        doc = read_toml(path)
    except OSError as e:
        return [("fail", f"{path}: {e.strerror or e}")]
    except ValueError as e:
        return [("fail", str(e))]
    kind = next((k for k in ("site", "wireguard") if k in doc), None)
    if not kind:
        return [("fail", f"{path}: no [site] or [wireguard] section")]
    try:
        {"site": load_config, "wireguard": load_gateway}[kind](path)
    except (OSError, ValueError, CAError) as e:
        return [("fail", f"{path}: {e}")]
    s = doc[kind]
    out = [("ok", f"{path}: {kind} configuration loads")] + _files(f"{path} [{kind}]", s, ("cert", "key", "ca", "crl", "private_key"))
    if not s.get("crl"):
        out.append(("fail", f"{path} [{kind}]: no crl, so revoked peers keep getting keys"))
    elif not s.get("crl_url"):
        out.append(("warn", f"{path} [{kind}]: the CRL is a local file; set crl_url unless this machine is the CA"))
    return out


def prerequisites():
    """What this machine needs to run Acxelin VPN, as rows with product, level (ok, warn or fail), message and action."""
    from acxelin_core import openssl
    rows = []
    def add(part, level, message, action=""):
        rows.append({"product": part, "level": level, "message": message, "action": action})
    reason = openssl.available()
    if reason:
        add("key agreement", "fail", reason, "Once that is done, run `acxelin-vpn doctor` again")
    else:
        add("key agreement", "ok", f"{openssl.lib().version} can agree keys over post-quantum mutual TLS")
    if sys.platform.startswith("linux") and importlib.util.find_spec("vici") and shutil.which("swanctl") and shutil.which("ip"):
        add("ipsec", "ok", "IPsec control tools found; kernel support and tunnel traffic still need a deployment test")
    else:
        add("ipsec", "warn", "This machine is not set up as an IPsec gateway (fine for a laptop)",
            'Gateways need Linux with strongSwan 6.0.2+, iproute2 and pip install "acxelin-vpn[vpn]"; laptops use `acxelin-vpn join` or the app')
    if not shutil.which("wg"):
        add("wireguard", "warn", "The WireGuard command was not found on PATH", "Install the official WireGuard tools for this platform before joining")
    if not all(importlib.util.find_spec(m) for m in ("pystray", "PIL")):
        add("desktop", "warn", "The desktop app (tray icon) is not installed; `acxelin-vpn app` opens the VPN window in a browser instead",
            'pip install "acxelin-vpn[desktop]"')
    return rows
