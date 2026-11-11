"""A key server for the gateways a site already has: firewalls that ask for keys over ETSI GS QKD 014 (Juniper SRX and MX,
Fortinet FortiGate, Palo Alto and others) get post-quantum keys from it without new hardware or a change to their tunnels.

Each site runs one beside its gateways. Two key servers agree a fresh shared secret over post-quantum mutual TLS (hybrid ML-KEM
key exchange, ML-DSA certificates from your CA, checked against the CRL), every `rotate_minutes`. A gateway asks its own
server for keys for a gateway at the other site (`enc_keys`) and sends the key IDs in its IKE exchange; the other gateway asks
its server for the same IDs (`dec_keys`). Each key is derived with HKDF-SHA384 from the secret of the epoch its ID names, the
two gateways' SAE IDs and the ID, so nothing but the IDs crosses between sites, and each ID is handed out once on each side.
The last four secrets are kept, so a key asked for just before a rotation can still be fetched.

This is post-quantum key delivery through the QKD interface, not quantum key distribution. The link between a gateway and its
own key server uses whatever TLS the gateway speaks (TLS 1.2 or 1.3, usually classical certificates): keep it on the site's
own network.
"""
import base64
import json
import logging
import re
import ssl
import threading
import uuid
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from acxelin_core import tls
from acxelin_core.config import build, read_toml
from acxelin_core.http import GuardedHTTPServer, content_length, hostport, http_server
from acxelin_core.pki import CAError, check_revocation

from . import agreement
from .qkd import SAE

log = logging.getLogger("acxelin-vpn.kme")
EXPORTER = "EXPORTER-acxelin-kme-v1"
EPOCHS, MAX_PER_REQUEST, MIN_BITS, MAX_BITS = 4, 16, 128, 1024
PATH = re.compile(r"^/api/v1/keys/([A-Za-z0-9._-]{1,128})/(status|enc_keys|dec_keys)$")


@dataclass
class KMEPeer:
    name: str  # the other key server's certificate name
    saes: list  # SAE IDs of the gateways behind it
    keyring: str = ""  # host:port of its key agreement service; empty when it dials this one


@dataclass
class KMEConfig:
    name: str  # this key server's certificate name (cert)
    listen: str  # ETSI GS QKD 014 for this site's gateways
    tls_cert: str  # what the gateways see: a certificate they trust (usually classical)
    tls_key: str
    sae_ca: str  # the CA that signed the gateways' client certificates; a gateway's SAE ID is its certificate's common name
    saes: list  # SAE IDs of this site's gateways
    keyring_listen: str  # post-quantum key agreement with the other key servers
    cert: str  # ML-DSA certificate and key from your CA, for the key agreement
    key: str
    ca: str
    peers: list = field(default_factory=list)
    crl: str = ""
    rotate_minutes: float = 10.0
    key_size: int = 256  # bits, when a gateway does not say

    def validate(self):
        names = [*self.saes, *(s for p in self.peers for s in p.saes)]
        if not self.saes or not all(isinstance(s, str) and SAE.match(s) for s in names):
            raise ValueError("saes are SAE IDs: letters, digits, '.', '_' or '-', and this site needs at least one")
        if len(set(names)) != len(names):
            raise ValueError("each SAE ID belongs to one site only")
        if len({p.name for p in self.peers}) != len(self.peers) or self.name in {p.name for p in self.peers}:
            raise ValueError("peer names must be unique and differ from this key server's name")
        for p in self.peers:
            if p.keyring:
                hostport(p.keyring)
        hostport(self.listen)
        hostport(self.keyring_listen)
        if not 0.25 <= self.rotate_minutes <= 1440:
            raise ValueError("rotate_minutes must be from 0.25 to 1440")
        if self.key_size % 8 or not MIN_BITS <= self.key_size <= MAX_BITS:
            raise ValueError(f"key_size must be a multiple of 8 from {MIN_BITS} to {MAX_BITS}")
        return self


def load(path):
    d = read_toml(path).get("kme")
    if not isinstance(d, dict):
        raise ValueError(f"{path} has no [kme] table")
    d = dict(d)
    peers = [build(KMEPeer, p, f"{path} [[kme.peer]] #{i + 1}") for i, p in enumerate(d.pop("peer", []))]
    here = Path(path).parent
    for k in ("tls_cert", "tls_key", "sae_ca", "cert", "key", "ca", "crl"):
        if isinstance(d.get(k), str) and d[k] and not Path(d[k]).is_absolute():
            d[k] = str(here / d[k])
    return build(KMEConfig, d, f"{path} [kme]", peers=peers).validate()


def key_id(tag, nbytes):
    """A UUID that names its epoch (the 6-byte tag) and its length; the rest is random."""
    raw = bytearray(bytes.fromhex(tag) + uuid.uuid4().bytes[6:])
    raw[7] = nbytes
    return str(uuid.UUID(bytes=bytes(raw), version=4))


def parse_id(text):
    try:
        b = uuid.UUID(str(text)).bytes
    except ValueError:
        return None, 0
    return b[:6].hex(), b[7]


def derive(secret, kid, master_sae, slave_sae, nbytes):
    return HKDF(hashes.SHA384(), nbytes, None, f"acxelin-kme-v1|{kid}|{master_sae}|{slave_sae}".encode()).derive(secret)


class Refused(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class KME:
    def __init__(self, cfg):
        self.cfg = cfg
        self.peer_of = {s: p for p in cfg.peers for s in p.saes}
        self.secrets = {p.name: OrderedDict() for p in cfg.peers}  # peer -> tag -> (secret, ids already handed to this site)
        self.lock, self.counts, self.stop = threading.Lock(), Counter(), threading.Event()
        self.keyring = self.https = None

    # --- key agreement between key servers

    def remember(self, peer, tag, secret):
        with self.lock:
            kept = self.secrets[peer]
            kept[tag] = (secret, set())
            while len(kept) > EPOCHS:
                kept.popitem(last=False)
        self.counts["key_agreements"] += 1

    def agree(self, peer):
        """Dial `peer` and agree a new secret; returns its tag."""
        tag = agreement.new_tag()
        with agreement.dial(hostport(peer.keyring), self.cfg.ca, self.cfg.cert, self.cfg.key, server_name=peer.name) as conn:
            cert = conn.peer_certificate()
            if agreement.common_name(cert) != peer.name:
                raise tls.TLSError(f"{peer.keyring} presented {agreement.common_name(cert)!r}, not {peer.name!r}")
            if self.cfg.crl:
                check_revocation(cert.serial_number, Path(self.cfg.crl).read_bytes(), self._anchor() + conn.peer_chain()[1:], cert.issuer)
            agreement.send(conn, {"v": 1, "kme": self.cfg.name, "tag": tag})
            reply = agreement.read_line(conn)
            if reply.get("ok") is not True:
                raise tls.TLSError(f"{peer.name} refused the key agreement")
            self.remember(peer.name, tag, conn.export(EXPORTER, self.context(peer.name, tag), 32))
        return tag

    def _anchor(self):
        from cryptography import x509
        return x509.load_pem_x509_certificates(Path(self.cfg.ca).read_bytes())

    def context(self, other, tag):
        return "|".join(sorted((self.cfg.name, other)) + [tag]).encode()

    def respond(self, conn, addr):
        cn = agreement.common_name(conn.peer_certificate())
        peer = next((p for p in self.cfg.peers if p.name == cn), None)
        msg = agreement.read_line(conn)
        tag = str(msg.get("tag", ""))
        if not peer or msg.get("kme") != cn or not agreement.TAG.match(tag):
            self.counts["refused"] += 1
            log.warning("key agreement refused from %s (%s): not a configured peer, or a malformed request", cn or "unknown", addr[0])
            return agreement.send(conn, {"ok": False})
        self.remember(peer.name, tag, conn.export(EXPORTER, self.context(peer.name, tag), 32))
        agreement.send(conn, {"ok": True})

    def initiator_loop(self, peer):
        delay = 0
        while not self.stop.wait(delay):
            try:
                self.agree(peer)
                delay = self.cfg.rotate_minutes * 60
            except (tls.TLSError, OSError, CAError, ValueError) as e:
                self.counts["agreement_failed"] += 1
                log.warning("key agreement with %s failed: %s; retrying in 5 s", peer.name, e)
                delay = 5

    # --- ETSI GS QKD 014 for this site's gateways

    def latest(self, peer):
        with self.lock:
            kept = self.secrets[peer.name]
            if not kept:
                raise Refused(503, f"no key agreement with {peer.name} yet")
            tag = next(reversed(kept))
            return tag, kept[tag][0]

    def remote(self, sae):
        peer = self.peer_of.get(sae)
        if not peer:
            raise Refused(400, f"{sae} is not a gateway at any site this key server knows")
        return peer

    def status(self, caller, slave):
        peer = self.remote(slave)
        with self.lock:
            ready = bool(self.secrets[peer.name])
        return {"source_KME_ID": self.cfg.name, "target_KME_ID": peer.name, "master_SAE_ID": caller, "slave_SAE_ID": slave,
                "key_size": self.cfg.key_size, "stored_key_count": 100000 if ready else 0, "max_key_count": 100000,
                "max_key_per_request": MAX_PER_REQUEST, "max_key_size": MAX_BITS, "min_key_size": MIN_BITS, "max_SAE_ID_count": 0}

    def enc_keys(self, caller, slave, number=1, size=None):
        peer = self.remote(slave)
        size = self.cfg.key_size if size is None else size
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= MAX_PER_REQUEST:
            raise Refused(400, f"number must be from 1 to {MAX_PER_REQUEST}")
        if not isinstance(size, int) or isinstance(size, bool) or size % 8 or not MIN_BITS <= size <= MAX_BITS:
            raise Refused(400, f"size must be a multiple of 8 from {MIN_BITS} to {MAX_BITS} bits")
        tag, secret = self.latest(peer)
        out = []
        for _ in range(number):
            kid = key_id(tag, size // 8)
            out.append({"key_ID": kid, "key": base64.b64encode(derive(secret, kid, caller, slave, size // 8)).decode()})
        self.counts["keys_delivered"] += number
        return {"keys": out}

    def dec_keys(self, caller, master_sae, ids):
        peer = self.remote(master_sae)
        if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_PER_REQUEST:
            raise Refused(400, f"key_IDs must list 1 to {MAX_PER_REQUEST} keys")
        out = []
        with self.lock:
            kept = self.secrets[peer.name]
            for kid in ids:
                kid = str(kid.get("key_ID", "")) if isinstance(kid, dict) else ""
                tag, nbytes = parse_id(kid)
                if tag not in kept or not MIN_BITS // 8 <= nbytes <= MAX_BITS // 8:
                    raise Refused(400, f"key {kid or '(none)'} is not available: unknown, or from a secret already rotated out")
                secret, handed = kept[tag]
                if kid in handed or any(kid == o[0] for o in out):
                    raise Refused(400, f"key {kid} was already delivered")
                out.append((kid, secret, nbytes, handed))
            for kid, _, _, handed in out:  # only once every key in the request is good
                handed.add(kid)
        self.counts["keys_delivered"] += len(out)
        return {"keys": [{"key_ID": kid, "key": base64.b64encode(derive(s, kid, master_sae, caller, n)).decode()} for kid, s, n, _ in out]}

    def handle(self, caller, method, path, query, body):
        m = PATH.match(path)
        if not m:
            raise Refused(404, "not an ETSI GS QKD 014 path")
        sae, what = m.groups()
        if caller not in self.cfg.saes:
            raise Refused(401, f"{caller or 'this client'} is not a gateway of this site")
        q = {k: v[-1] for k, v in parse_qs(query).items()}
        data = body if method == "POST" else {}
        if not isinstance(data, dict):
            raise Refused(400, "the request body must be a JSON object")
        if what == "status":
            return self.status(caller, sae)
        if what == "enc_keys":
            if data.get("additional_slave_SAE_IDs"):
                raise Refused(400, "keys for more than one other gateway are not supported (max_SAE_ID_count is 0)")
            num = lambda k: int(q[k]) if q.get(k, "").isdigit() else (data.get(k) if k in data else None)
            n = num("number")
            return self.enc_keys(caller, sae, 1 if n is None else n, num("size"))
        ids = data.get("key_IDs") if method == "POST" else ([{"key_ID": q["key_ID"]}] if "key_ID" in q else None)
        return self.dec_keys(caller, sae, ids)

    # --- running

    def start(self):
        c = self.cfg
        self.keyring = agreement.keyring(c.keyring_listen, c.cert, c.key, c.ca, self.respond, crl=c.crl or None)
        self.https = serve(self, c.listen)
        threading.Thread(target=self.https.serve_forever, daemon=True, name="kme-014").start()
        for p in c.peers:
            if p.keyring:
                threading.Thread(target=self.initiator_loop, args=(p,), daemon=True, name=f"kme-{p.name}").start()
        return self

    def shutdown(self):
        self.stop.set()
        if self.https:
            self.https.shutdown()
            self.https.server_close()
        if self.keyring:
            self.keyring.stop(1)

    def report(self):
        with self.lock:
            epochs = {p: len(k) for p, k in self.secrets.items()}
        return {"name": self.cfg.name, "peers": epochs, **self.counts}


def caller_of(sock):
    cert = sock.getpeercert() or {}
    return next((v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"), "")


def serve(kme, listen):
    """The ETSI GS QKD 014 listener: mutual TLS 1.2 or 1.3 with the gateways' own certificates."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(kme.cfg.tls_cert, kme.cfg.tls_key)
    ctx.load_verify_locations(kme.cfg.sae_ca)
    ctx.verify_mode = ssl.CERT_REQUIRED

    class Server(GuardedHTTPServer):
        def wrap(self, request):
            request.settimeout(10)
            request = ctx.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
            request.do_handshake()
            return request

    class Handler(BaseHTTPRequestHandler):
        timeout = 30
        server_version = "acxelin-kme"

        def reply(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def route(self):
            caller = caller_of(self.connection)
            u = urlsplit(self.path)
            try:
                body = None
                if self.command == "POST":
                    n = content_length(self.headers)
                    if n is None or n > 1 << 16:
                        raise Refused(400, "bad Content-Length")
                    try:
                        body = json.loads(self.rfile.read(n) or b"{}")
                    except ValueError:
                        raise Refused(400, "the request body is not JSON") from None
                self.reply(200, kme.handle(caller, self.command, u.path, u.query, body))
            except Refused as e:
                kme.counts["refused"] += 1
                log.warning("%s %s from %s: %s", self.command, u.path, caller or "unknown", e)
                self.reply(e.status, {"message": str(e)})

        do_GET = do_POST = route

        def log_message(self, *a):
            pass

    return http_server(listen, Handler, Server)
