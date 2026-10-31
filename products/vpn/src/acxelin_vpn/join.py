"""Joining a WireGuard gateway from an administrator's invitation: one file instead of four hand-copied values. Shared by
`vpn join` and the `vpn app` window, so both refuse the same things before anything on the machine changes."""
import datetime as dt
import json
import os
import re
import shutil
from pathlib import Path

from acxelin_core.files import write
from acxelin_core.http import hostport
from . import platforms

FIELDS = ("acxelin_invite", "name", "enroll", "ca_fingerprint", "gateway", "server_name", "expires")


def parse(text, where="this file"):
    try:
        inv = json.loads(text)
    except ValueError:
        inv = None
    if not isinstance(inv, dict) or inv.get("acxelin_invite") != 1 or not all(isinstance(inv.get(k), str) for k in ("name", "enroll", "ca_fingerprint", "gateway")) \
            or not inv["enroll"].startswith("https://") or not re.fullmatch(r"[0-9a-f]{64}", inv["ca_fingerprint"]):
        raise ValueError(f"{where} is not an Acxelin VPN invitation; ask your administrator for the .acxinvite file from `acxelin-vpn invite`")
    hostport(inv["gateway"])
    return inv


def read(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"{path} could not be read ({e.__class__.__name__}); check the file name, or ask your administrator for a new invitation") from None
    return parse(text, str(path))


def administrator():
    if os.name == "nt":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def preflight(command):
    """What must hold before a tunnel can be configured; `command` is what to run again once it does."""
    if not administrator():
        raise ValueError(f"connecting changes this machine's network, which needs administrator rights. Open an administrator terminal "
                         f"(Windows: Run as administrator; Linux/macOS: sudo) and run: {command}")
    if not shutil.which(platforms.find("wg")):
        raise ValueError(f"WireGuard is not installed: {platforms.INSTALL.get(platforms.system(), 'install wireguard-tools')}, then run this again")


def device_for(invitation, device=None):
    return Path(device or Path(invitation).with_suffix(""))


def must_enroll(inv, device):
    """True when the invitation's one-time token should be used: this machine has no certificate yet, or the administrator sent
    a new invitation (after a revocation, or for a certificate that ran out), which replaces the old certificate."""
    has = (Path(device) / "cert.pem").exists()
    if "token" not in inv:
        if has:
            return False
        raise ValueError(f"this invitation was already used and {device} holds no certificate; ask your administrator for a new invitation")
    if dt.datetime.fromisoformat(inv["expires"]) < dt.datetime.now(dt.timezone.utc):
        if has:
            return False
        raise ValueError(f"this invitation expired at {inv['expires']}; ask your administrator for a new one")
    return True


def make(ca, name, enroll, gateway, server_name=None, hours=24):
    """An invitation for `name`: where to enroll, the CA fingerprint to pin, the gateway, and a one-time enrollment token.
    Returns the file's bytes and when it expires; the token is in the bytes only, so treat them as a secret."""
    from cryptography.x509 import load_pem_x509_certificate
    from acxelin_core.pki.est import create_token, fingerprint
    hostport(gateway)
    if not isinstance(enroll, str) or not enroll.startswith("https://"):
        raise ValueError("the enrollment service must be the https:// address of `acxelin-vpn ca serve`")
    token = create_token(ca, name, "client", hours=hours)
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).replace(microsecond=0).isoformat()
    inv = {"acxelin_invite": 1, "name": name, "enroll": enroll, "ca_fingerprint": fingerprint(load_pem_x509_certificate(ca.anchor.read_bytes())),
           "gateway": gateway, "server_name": server_name, "expires": expires, "token": token}
    return json.dumps(inv, indent=1).encode(), expires


def enroll(inv, device, invitation, passphrase):
    """Pin the CA by the invitation's fingerprint, enroll with its one-time token, then remove the used token from the file."""
    from acxelin_core.pki import est
    device = Path(device)
    device.mkdir(parents=True, exist_ok=True)
    est.fetch_ca(inv["enroll"], inv["ca_fingerprint"], device / "ca.crt")
    cert = est.enroll(inv["enroll"], inv["token"], inv["name"], (), device, device / "ca.crt", passphrase=passphrase)
    write(device / "enroll.url", inv["enroll"].encode())  # where the certificate is renewed before it runs out
    write(Path(invitation), json.dumps({k: inv[k] for k in FIELDS if k in inv}, indent=1).encode(), secret=True)
    if os.name != "nt" and os.geteuid() == 0 and os.environ.get("SUDO_UID"):  # run with sudo: leave the person's files theirs
        for p in (Path(invitation), *device.rglob("*"), device):
            os.chown(p, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"])))
    return cert
