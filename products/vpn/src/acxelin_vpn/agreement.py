"""The post-quantum key agreement both data planes use: one mutual TLS 1.3 session under the VPN's policy (hybrid ML-KEM key
exchange, ML-DSA certificates), one JSON line each way, and keys exported from that session (RFC 8446 section 7.5). IPsec takes
64 bytes (IKE PSK and PPK), WireGuard 32 (its PSK). Labels and contexts are pinned: deployed gateways and
computers derive the same keys only while they stay as they are."""
import json
import re
import secrets

from cryptography.x509.oid import NameOID

from acxelin_core import tls
from acxelin_core.http import hostport
from acxelin_core.server import Server

from .policies import POLICY

IPSEC = "EXPORTER-pqcsuite-ipsec-v1"
WIREGUARD = "EXPORTER-pqcsuite-wireguard-v1"
TAG = re.compile(r"^[0-9a-f]{12}$")


def new_tag():
    return secrets.token_hex(6)


def common_name(cert):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else ""


def ipsec_context(a, b, tag):
    return "|".join(sorted((a, b)) + [tag]).encode()


def wireguard_context(gateway, client, tag, client_public, gateway_public):
    return "|".join((gateway, client, tag, client_public, gateway_public)).encode()


def ipsec_keys(conn, a, b, tag):
    return conn.export(IPSEC, ipsec_context(a, b, tag), 64)


def wireguard_psk(conn, gateway, client, tag, client_public, gateway_public):
    return conn.export(WIREGUARD, wireguard_context(gateway, client, tag, client_public, gateway_public), 32)


def send(conn, msg):
    conn.sendall(json.dumps(msg).encode() + b"\n")


def read_line(conn, limit=4096):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = conn.recv(limit - len(buf), timeout=10)
        if not chunk or len(buf) + len(chunk) >= limit:
            raise tls.TLSError("key agreement message missing or too long")
        buf += chunk
    try:
        msg = json.loads(buf)
    except ValueError:
        msg = None
    if not isinstance(msg, dict):
        raise tls.TLSError("the key agreement message is not a JSON object")
    return msg


def dial(address, ca, cert, key, passphrase=None, server_name=None, timeout=10, policy=POLICY):
    """The initiator's side: a verified session to a keyring, presenting our certificate."""
    ctx = tls.client_context(policy, ca, cert, key, passphrase)
    return tls.connect(*address, ctx, server_name=server_name, timeout=timeout)


def keyring(listen, cert, key, ca, respond, crl=None, passphrase=lambda: None, max_connections=64, policy=POLICY):
    """The responder's side, started: certificate files are reloaded when they change, and a CRL, when given, is checked first."""
    make = lambda: tls.server_context(policy, cert, key, ca, True, passphrase())
    if policy.cert_algorithm:
        make()  # a certificate the policy cannot use fails here, not at every handshake
    server = Server(hostport(listen), make, respond, watch=[cert, key, ca], crl=crl or None, ca=ca, max_connections=max_connections, name="keyring")
    server.start()
    return server
