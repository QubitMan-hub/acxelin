"""`acxelin-tls evidence`: a signed bundle of what an edge is and does (build, configuration, doctor, certificates, live
handshakes, counters), and the check of one. Private keys and passphrases are never read into it."""
import socket
from pathlib import Path

from acxelin_core import evidence, tls
from acxelin_core.config import env_passphrase
from acxelin_core.http import explain, hostport

from . import NAME, __version__, checks, policies
from .common import policy
from .edge import load_config
from .edge_commands import _staple


def handshake(target, a):
    host, port = hostport(target, "")
    ctx = tls.client_context(policies.policy(a.policy), a.ca, a.cert, a.key, env_passphrase(a.key_passphrase_env))
    ctx.request_staple = True
    out = {"target": target, "policy": a.policy}
    try:
        with tls.connect(host, port, ctx, a.server_name, a.timeout) as conn:
            return out | conn.info() | {"ocsp": _staple(conn)}
    except (tls.TLSError, OSError, socket.gaierror) as e:
        return out | {"refused": explain(e) if isinstance(e, OSError) else str(e)}


def parts(a):
    if a.connect and not a.ca:
        raise ValueError("--connect checks the edge's certificate, so it needs --ca (the CA certificate to trust)")
    try:
        routes, _ = load_config(a.config)
    except ValueError as e:
        raise ValueError(e if str(a.config) in str(e) else f"{a.config}: {e}") from None
    out = {"build.json": {"product": NAME, "version": __version__, "environment": evidence.environment(),
                          "packages": evidence.packages(NAME, "acxelin-core", "cryptography")},
           "config.toml": Path(a.config).read_bytes(),
           "doctor.json": checks.prerequisites() + [{"level": lv, "message": m} for lv, m in checks.config(a.config)],
           "certificates.json": [row for r in routes for role in ("cert", "ca", "fallback_cert") if getattr(r, role)
                                 for row in evidence.certificates(getattr(r, role), route=r.name, role=role)]}
    for i, target in enumerate(a.connect, 1):
        out[f"connect-{i}.json"] = handshake(target, a)
    if a.status:  # after the handshakes, so its counters include them
        out["status.json"] = evidence.fetch_status(a.status, "start the edge with --metrics HOST:PORT and give that address")
    return out


def options(p):
    p.add_argument("--config", required=True, help="the edge configuration")
    p.add_argument("--connect", action="append", default=[], metavar="HOST:PORT", help="hand-shake with this address and record what was negotiated (repeatable)")
    p.add_argument("--ca", help="the CA certificate to trust for --connect")
    p.add_argument("--server-name", help="the name the certificate must match (default: the host)")
    p.add_argument("--cert", help="a client certificate for --connect, for mutual TLS")
    p.add_argument("--key", help="its key")
    p.add_argument("--key-passphrase-env")
    p.add_argument("--timeout", type=float, default=10.0)
    policy(p)


def add(sub):
    evidence.add_commands(sub, NAME, parts, options)
