"""Post-quantum WireGuard: remote access for laptops, and site-to-site links, on a WireGuard data plane.

WireGuard's handshake is X25519, but it mixes an optional 32-byte pre-shared key into every handshake. Here that key comes from
post-quantum mutual TLS: the client and the gateway prove who they are with ML-DSA certificates from our CA, agree keys over
X25519MLKEM768, and both derive the PSK from the TLS exporter, bound to both WireGuard public keys. An attacker who later breaks
X25519 still lacks the PSK. The PSK is replaced every few minutes; a client that stops re-agreeing (or whose certificate is
revoked) is removed from the gateway.

Each user (certificate common name) gets a stable address from the pool. A second device with the same certificate replaces
the first. A client listed under `sites` also routes the subnets behind it, which makes the same gateway a site-to-site hub.
With `full_tunnel`, clients send all their traffic through the gateway, which forwards it with NAT; their kill switch keeps
anything from leaving outside the tunnel (see platforms.py).
"""
import base64
import ipaddress
import json
import logging
import os
import platform
import shutil
import subprocess
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from acxelin_core import tls
from acxelin_core.config import build, env_passphrase, read_toml
from acxelin_core.files import write
from acxelin_core.http import explain, hostport
from acxelin_core.pki import CAError, algorithm_of, follow_crl
from acxelin_core.server import Revocation

from . import agreement, audit
from .agreement import TAG, common_name, read_line
from .platforms import FULL, WG, WGError, addresses, this_machine

log = logging.getLogger(__name__)
LIVE = {"users", "routes", "dns", "sites", "rotate_minutes"}
LABEL, context = agreement.WIREGUARD, agreement.wireguard_context
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(data):
    return base64.b64encode(data).decode()


def private_key(path):
    """Load the WireGuard private key at `path`, creating it (owner-only) the first time."""
    path = Path(path)
    if not path.exists():
        k = x25519.X25519PrivateKey.generate()
        write(path, b64(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).encode(), secret=True)
    raw = base64.b64decode(path.read_text().strip())
    return b64(raw), b64(x25519.X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(*RAW))


def valid_key(text):
    try:
        return len(base64.b64decode(text, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def ensure_interface(name, address, routes=()):
    """Linux: create the WireGuard interface (kernel module, else wireguard-go), give it its address and routes, bring it up."""
    if platform.system() != "Linux":
        raise WGError("creating interfaces is automatic on Linux only; elsewhere use --config-out and the WireGuard app")
    ip = lambda *a: subprocess.run(["ip", *a], capture_output=True, text=True)
    if ip("link", "show", name).returncode:
        if ip("link", "add", name, "type", "wireguard").returncode:
            go = os.environ.get("ACXELIN_WIREGUARD_GO") or shutil.which("wireguard-go")
            if not go:
                raise WGError("no WireGuard kernel module and no wireguard-go; install one of them")
            subprocess.run([go, name], capture_output=True, timeout=15, env=os.environ | {"WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD": "1"})
            if ip("link", "show", name).returncode:
                raise WGError(f"wireguard-go did not create {name}")
    for args in (("addr", "replace", address, "dev", name), ("link", "set", name, "up"),
                 *(("route", "replace", r, "dev", name) for r in routes)):
        r = ip(*args)
        if r.returncode:
            raise WGError(f"ip {' '.join(args)}: {r.stderr.strip()}")


def forward(interface, pool, on=True):
    """Linux, full tunnel: route clients' traffic onwards, NAT it to the gateway's own address, and let the replies back."""
    if on:
        flag = Path("/proc/sys/net/ipv4/ip_forward")
        try:
            flag.write_text("1")
        except OSError:  # read-only in a container: fine if it is already on
            if flag.read_text().strip() != "1":
                raise WGError("full tunnel needs IP forwarding, and /proc/sys is read-only here: start the container with "
                              "--sysctl net.ipv4.ip_forward=1") from None
    rules = [["-t", "nat", "POSTROUTING", "-s", pool, "!", "-o", interface, "-j", "MASQUERADE"], ["FORWARD", "-i", interface, "-j", "ACCEPT"],
             ["FORWARD", "-o", interface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]]
    for rule in rules:
        table, chain, spec = (rule[:2], rule[2], rule[3:]) if rule[0] == "-t" else ([], rule[0], rule[1:])
        present = subprocess.run(["iptables", *table, "-C", chain, *spec], capture_output=True).returncode == 0
        if on and not present:
            r = subprocess.run(["iptables", *table, "-I", chain, "1", *spec], capture_output=True, text=True)
            if r.returncode:
                raise WGError(f"iptables: {r.stderr.strip()}")
        elif not on and present:
            subprocess.run(["iptables", *table, "-D", chain, *spec], capture_output=True)


@dataclass
class GatewayConfig:
    name: str
    endpoint: str
    keyring_listen: str
    pool: str
    cert: str
    key: str
    ca: str
    crl: str = ""
    crl_url: str = ""
    crl_every: float = 60.0
    key_passphrase_env: str = ""
    interface: str = "wg0"
    listen_port: int = 51820
    private_key: str = "wireguard.key"
    state: str = "wireguard-state.json"
    routes: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    users: list = field(default_factory=list)
    sites: dict = field(default_factory=dict)
    rotate_minutes: float = 2.0
    metrics: str = ""
    manage_interface: bool = True
    full_tunnel: bool = False

    @property
    def network(self):
        return ipaddress.ip_network(self.pool)

    @property
    def address(self):
        return next(self.network.hosts())

    def validate(self):
        net = self.network
        if net.num_addresses < 4:
            raise ValueError("pool is too small")
        for r in self.routes + [n for v in self.sites.values() for n in v]:
            if ipaddress.ip_network(r).prefixlen == 0:
                raise ValueError("list the networks behind the gateway in routes; for all traffic set full_tunnel = true")
        hostport(self.endpoint)
        hostport(self.keyring_listen)
        if self.crl_url and not self.crl:
            raise ValueError("crl_url needs crl = \"PATH\", where the copy is kept")
        if self.crl_every < 5:
            raise ValueError("crl_every must be at least 5 seconds")
        if self.rotate_minutes < 0.25:
            raise ValueError("rotate_minutes must be at least 0.25")
        return self


def load_gateway(path):
    d = read_toml(path).get("wireguard")
    if d is None:
        raise ValueError(f"{path}: missing [wireguard]")
    return build(GatewayConfig, d, "[wireguard]").validate()


class Gateway:
    def __init__(self, cfg, wg=None):
        self.cfg = cfg
        self.wg = wg or WG(cfg.interface)
        self.private, self.public = private_key(cfg.private_key)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.clients = {}
        self.counts = Counter()
        self.leases = json.loads(Path(cfg.state).read_text()) if Path(cfg.state).exists() else {}
        self.server = self.crl_follow = self.revocation = None
        self.started = time.time()

    def event(self, action, cn, **detail):
        """The access history: connections, new devices, refusals and removals (not every key renewal), in the gateway's audit log."""
        try:
            audit.record(Path(self.cfg.state).parent, action, name=cn, **detail)
        except OSError as e:
            log.debug("access history not written: %s", e)

    def refuse(self, conn, cn, addr, why, reason=None):
        self.counts["refused"] += 1
        log.warning("keyring: refused %s from %s: %s", cn or "unknown", addr[0], why)
        self.event("refused", cn or "unknown", source=addr[0], reason=why)
        agreement.send(conn, {"ok": False} | ({"reason": reason} if reason else {}))

    def lease(self, cn):
        if cn not in self.leases:
            taken = set(self.leases.values()) | {str(self.cfg.address)}
            free = next((str(h) for h in self.cfg.network.hosts() if str(h) not in taken), None)
            if not free:
                raise CAError("the address pool is full")
            self.leases[cn] = free
            write(Path(self.cfg.state), json.dumps(self.leases, indent=1).encode())
        return self.leases[cn]

    def respond(self, conn, addr):
        cert = conn.peer_certificate()
        cn = common_name(cert)
        if self.revocation:  # checked here rather than by the server, so a revoked laptop is told why
            try:
                self.revocation.check(cert.serial_number, conn.peer_chain()[1:], cert.issuer)
            except CAError as e:
                revoked = "revoked" in str(e)
                self.counts["revoked_refused" if revoked else "refused"] += 1
                log.warning("keyring: refused %s from %s: %s", cn, addr[0], e)
                self.event("refused", cn, source=addr[0], reason="revoked" if revoked else "revocation list unusable")
                agreement.send(conn, {"ok": False, "reason": "revoked" if revoked else "crl"})
                return
        msg = read_line(conn)
        pub, tag = str(msg.get("public", "")), str(msg.get("tag", ""))
        if (self.cfg.users and cn not in self.cfg.users) or not valid_key(pub) or not TAG.match(tag) or pub == self.public:
            return self.refuse(conn, cn, addr, "not allowed, or a malformed request")
        if any(other != cn and c["public"] == pub for other, c in self.clients.items()):
            return self.refuse(conn, cn, addr, "its WireGuard key belongs to another person")
        psk = agreement.wireguard_psk(conn, self.cfg.name, cn, tag, pub, self.public)
        with self.lock:
            try:
                ip = self.lease(cn)
            except CAError as e:
                return self.refuse(conn, cn, addr, str(e))
            old = self.clients.get(cn)
            self.wg.set_peer(pub, b64(psk), [f"{ip}/32"] + self.cfg.sites.get(cn, []))
            if old and old["public"] != pub:
                self.wg.remove_peer(old["public"])
                self.counts["replaced_devices"] += 1
            now = time.time()
            self.clients[cn] = {"public": pub, "serial": cert.serial_number, "issuer": cert.issuer, "agreed": now, "address": ip, "tag": tag,
                                "since": old["since"] if old and old["public"] == pub else now}
        self.counts["key_agreements"] += 1
        log.info("%s: %s at %s, new PSK %s", cn, "rotated" if old else "connected", ip, tag)
        if not old or old["public"] != pub:
            self.event("new device" if old else "connected", cn, address=ip, source=addr[0])
        routes = FULL if self.cfg.full_tunnel else [str(self.cfg.network)] + self.cfg.routes
        reply = {"ok": True, "address": f"{ip}/{self.cfg.network.prefixlen}", "gateway": self.cfg.name, "gateway_public": self.public,
                 "endpoint": self.cfg.endpoint, "routes": routes, "dns": self.cfg.dns,
                 "rotate_s": int(self.cfg.rotate_minutes * 60)}
        agreement.send(conn, reply)

    def expire(self, revocation=None):
        """Remove clients whose certificate was revoked, and clients that stopped re-agreeing keys."""
        stale = time.time() - 3 * self.cfg.rotate_minutes * 60 - 30
        for cn, c in list(self.clients.items()):
            reason = None
            if revocation:
                try:
                    revocation.check(c["serial"], (), c.get("issuer"))
                except CAError as e:
                    if "revoked" in str(e):
                        reason, key = str(e), "revoked"
                    else:  # an unusable CRL cannot clear anyone, but laptops that stopped renewing still go
                        log.error("CRL problem: %s", e)
            if not reason and c["agreed"] < stale:
                reason, key = "stopped renewing its key", "expired"
            if reason:
                with self.lock:
                    if self.clients.get(cn) is not c:
                        continue
                    self.wg.remove_peer(c["public"])
                    self.clients.pop(cn)
                    if key == "revoked" and self.leases.pop(cn, None):
                        write(Path(self.cfg.state), json.dumps(self.leases, indent=1).encode())
                self.counts[key] += 1
                self.event("revoked, removed" if key == "revoked" else "disconnected", cn, reason=reason)
                log.warning("%s: %s; removed", cn, reason)

    def start(self):
        c = self.cfg
        held = common_name(x509.load_pem_x509_certificates(Path(c.cert).read_bytes())[0])
        if held != c.name:
            raise ValueError(f"the gateway's name is {c.name!r} but its certificate is for {held!r}: laptops derive their key from the "
                             "certificate's name, so set name to it (or issue a certificate for the name)")
        if c.manage_interface:
            ensure_interface(c.interface, f"{c.address}/{c.network.prefixlen}", [n for v in c.sites.values() for n in v])
            if c.full_tunnel:
                forward(c.interface, c.pool)
        self.wg.set_private_key(self.private, c.listen_port)
        for stale in self.wg.peers():
            self.wg.remove_peer(stale)
        if c.crl_url:
            self.crl_follow = follow_crl(c.crl_url, c.crl, c.ca, c.crl_every)
        self.revocation = Revocation(c.crl, c.ca) if c.crl else None
        self.server = agreement.keyring(c.keyring_listen, c.cert, c.key, c.ca, self.respond, None,
                                        lambda: env_passphrase(c.key_passphrase_env), max_connections=256)

        def watch():
            while not self.stop.wait(min(15, c.rotate_minutes * 30)):
                try:
                    self.expire(self.revocation)
                except (WGError, OSError) as e:
                    log.error("expiry check failed: %s", e)
        threading.Thread(target=watch, daemon=True, name="expiry").start()
        return self

    def shutdown(self):
        self.stop.set()
        if self.cfg.full_tunnel and self.cfg.manage_interface:
            forward(self.cfg.interface, self.cfg.pool, on=False)
        if self.crl_follow:
            self.crl_follow.set()
        if self.server:
            self.server.stop(2)

    def reconfigure(self, new):
        """Apply a changed configuration while running when only users, routes, dns, sites or rotate_minutes differ, removing
        users no longer listed; False when anything else changed and the gateway has to restart."""
        if any(getattr(self.cfg, k) != v for k, v in vars(new).items() if k not in LIVE):
            return False
        if new.sites != self.cfg.sites and new.manage_interface:  # routes to the subnets behind newly listed sites
            ensure_interface(new.interface, f"{new.address}/{new.network.prefixlen}", [n for v in new.sites.values() for n in v])
        self.cfg = new
        for cn, c in list(self.clients.items()):
            if new.users and cn not in new.users:
                with self.lock:
                    self.wg.remove_peer(c["public"])
                    self.clients.pop(cn, None)
                self.counts["removed"] += 1
                log.warning("%s: no longer in users; removed", cn)
        log.info("applied the new users, routes and settings; connected users get them at their next key agreement")
        return True

    def status(self):
        peers = self.wg.peers()
        return {cn: {"address": c["address"], "keys_age_s": int(time.time() - c["agreed"]), "since": int(c["since"]),
                     "certificate": format(c["serial"], "x"), **peers.get(c["public"], {})}
                for cn, c in self.clients.items()} | {"_events": dict(self.counts),
                "_gateway": {"started": int(self.started), "history": audit.recent(Path(self.cfg.state).parent, 50)}}

    def metrics(self):
        peers, now = self.wg.peers(), time.time()
        lines = ["# TYPE acxelin_vpn_wireguard_client_up gauge", "# TYPE acxelin_vpn_wireguard_bytes_total counter",
                 "# TYPE acxelin_vpn_wireguard_events_total counter"]
        for cn, c in self.clients.items():
            p = peers.get(c["public"], {})
            lines.append(f'acxelin_vpn_wireguard_client_up{{user="{cn}"}} {int(now - p.get("latest_handshake", 0) < 180)}')
            lines.append(f'acxelin_vpn_wireguard_bytes_total{{user="{cn}",direction="in"}} {p.get("rx_bytes", 0)}')
            lines.append(f'acxelin_vpn_wireguard_bytes_total{{user="{cn}",direction="out"}} {p.get("tx_bytes", 0)}')
        lines += [f'acxelin_vpn_wireguard_events_total{{event="{k}"}} {v}' for k, v in self.counts.items()]
        return "\n".join(lines) + "\n"


class Client:
    """A laptop or branch: agrees a PSK with the gateway, runs the tunnel with this machine's WireGuard, and repeats before the PSK
    goes stale. The schedule follows the wall clock, so keys are renewed right after the machine wakes from sleep; a tunnel that
    stopped working is taken down so the gateway can be reached directly, then brought back with fresh keys."""

    def __init__(self, keyring, folder, interface="wg0", server_name=None, apply=True, config_out=None, key_passphrase=None, ca=None,
                 tunnel=None, kill_switch=None, on_status=None, status_file=None):
        self.host, self.port = hostport(keyring)
        self.server_name = server_name or self.host
        self.dir = Path(folder)
        self.ca = ca or self.dir / "ca.crt"
        self.name = common_name(x509.load_pem_x509_certificate((self.dir / "cert.pem").read_bytes()))
        self.apply_, self.config_out, self.passphrase = apply, config_out, key_passphrase
        if apply and not tunnel:
            tunnel, kill_switch = this_machine(interface)
        self.tunnel, self.kill_switch = tunnel, kill_switch
        self.private, self.public = private_key(self.dir / "wireguard.key")
        self.applied, self.stop = None, threading.Event()
        self.due, self.failures = 0.0, 0
        self.last = self.error = self.since = self.reported = self.agreed_at = None
        self.details, self.on_status = {}, on_status
        self.ks_on, self.ks_changed = False, None
        self.status_file = status_file or (Path(tunnel.folder) / f"{interface}.status.json" if apply and hasattr(tunnel, "folder") else None)
        self.stop_file = Path(tunnel.folder) / f"{interface}.disconnect" if apply and hasattr(tunnel, "folder") else None
        self.renew_url = (self.dir / "enroll.url").read_text().strip() if (self.dir / "enroll.url").exists() else None
        self.renewed_at, self.pins = 0.0, {}

    def agree(self):
        tag = agreement.new_tag()
        with agreement.dial((self.pin(self.host), self.port), self.ca, self.dir / "chain.pem", self.dir / "key.pem", self.passphrase, self.server_name, 15) as conn:
            agreement.send(conn, {"v": 1, "public": self.public, "tag": tag})
            reply = read_line(conn)
            if reply.get("reason") == "revoked":
                raise tls.TLSError("this computer's certificate has been revoked: ask your administrator for a new invitation")
            if reply.get("reason") == "crl":
                raise tls.TLSError("the gateway cannot read its revocation list, so it lets no one in: tell your administrator")
            if reply.get("ok") is not True or not valid_key(str(reply.get("gateway_public", ""))):
                raise tls.TLSError("the gateway refused the key agreement (is this certificate allowed?)")
            peer = conn.peer_certificate()
            psk = agreement.wireguard_psk(conn, common_name(peer), self.name, tag, self.public, reply["gateway_public"])
            self.details = {"tls_group": conn.group, "gateway_certificate": algorithm_of(peer.public_key()), "gateway": common_name(peer)}
        return reply, b64(psk)

    def pin(self, host):
        """The address to reach `host` at. While the kill switch blocks DNS, the addresses resolved before it went on."""
        if self.ks_on and self.pins.get(host):
            return self.pins[host][0]
        try:
            self.pins[host] = addresses(host)
        except OSError:
            if not self.pins.get(host):
                raise
        return self.pins[host][0]

    def renew(self):
        """Renew this computer's certificate within 30 days of its end, checked twice a day, so a laptop keeps working past a year."""
        if not self.renew_url or time.time() - self.renewed_at < 43200:
            return
        self.renewed_at = time.time()
        from acxelin_core.pki import est
        try:
            if est.renew(self.renew_url, self.dir, within_days=30, passphrase=self.passphrase):
                log.info("this computer's certificate was renewed")
        except (CAError, tls.TLSError, OSError, ValueError) as e:
            log.warning("certificate renewal failed (%s); trying again later", explain(e))

    def apply(self, reply, psk):
        if self.apply_:
            shape = {k: reply[k] for k in ("address", "routes", "dns", "endpoint", "gateway_public")}
            if self.applied != shape or not self.tunnel.up_:
                host, port = hostport(reply["endpoint"])
                pinned = self.pin(host) if "0.0.0.0/0" in reply["routes"] else None  # wg-quick cannot resolve names under the kill switch
                endpoint = (f"[{pinned}]:{port}" if ":" in pinned else f"{pinned}:{port}") if pinned else reply["endpoint"]
                self.tunnel.up(wg_quick(self.private, reply | {"routes": self.tunnel.routes(reply["routes"]), "endpoint": endpoint}, psk))
                self.applied = shape
            else:
                self.tunnel.wg().set_psk(reply["gateway_public"], psk)
            if "0.0.0.0/0" in reply["routes"]:
                host, port = hostport(reply["endpoint"])
                self.kill_switch.on(self.tunnel.device(), (addresses(host), port), (addresses(self.host), self.port))
                self.killswitch(True)
            else:
                self.kill_switch.off()
                self.killswitch(False)
        if self.config_out:
            write(Path(self.config_out), wg_quick(self.private, reply, psk).encode(), secret=True)

    def killswitch(self, on):
        """Record a change (not every renewal) in the computer's own audit log, next to the tunnel's state."""
        if on != self.ks_on and hasattr(self.tunnel, "folder"):
            self.ks_on, self.ks_changed = on, audit.record(self.tunnel.folder, f"kill switch {'on' if on else 'off'}", device=self.name)

    def once(self):
        reply, psk = self.agree()
        self.apply(reply, psk)
        return reply

    def quiet(self):
        """The tunnel is up but WireGuard has not completed a handshake for over three minutes (it does one every two)."""
        if not (self.apply_ and self.tunnel.up_ and self.applied):
            return False
        try:
            age = self.tunnel.handshake_age(self.applied["gateway_public"])
        except (WGError, OSError):
            return False
        return age is not None and age > 180

    def step(self):
        """One pass of the loop; returns how long to wait before the next."""
        if self.stop_file and self.stop_file.exists():  # `acxelin-vpn disconnect` asked this client to stop
            log.info("disconnect requested; stopping")
            self.stop_file.unlink(missing_ok=True)
            self.stop.set()
            return 0
        self.renew()
        if time.time() >= self.due or self.quiet():
            try:
                reply = self.once()
                log.info("connected as %s through %s; next key in %ds", reply["address"], reply["endpoint"], reply["rotate_s"])
                self.failures, self.due = 0, time.time() + reply["rotate_s"]
                self.last, self.error, self.since, self.agreed_at = reply, None, self.since or time.time(), time.time()
            except (tls.TLSError, WGError, OSError, ValueError, KeyError) as e:
                self.failures += 1
                retry = min(5 * 2 ** (self.failures - 1), 60)
                self.error, self.since = explain(e), None
                log.warning("key agreement failed: %s; retrying in %ds", self.error, retry)
                if self.apply_ and self.tunnel.up_:
                    log.warning("taking the tunnel down to reach the gateway directly")
                    self.tunnel.down()
                    retry = 1
                self.due = time.time() + retry
        self.report()
        return max(0.5, min(5.0, self.due - time.time()))

    def status(self):
        """What a person needs to know: protected, connecting or not protected, and why. Protected means WireGuard has completed
        a handshake within three minutes using the PSK from the latest post-quantum key agreement, not merely that keys were agreed."""
        s = {"state": "not_protected", "gateway": f"{self.host}:{self.port}", "device": self.name, "error": self.error, "updated": time.time(),
             "renewal_failures": self.failures}
        if self.agreed_at:
            s["last_key_s"] = round(time.time() - self.agreed_at)
        if self.ks_changed:
            s["kill_switch_changed"] = {k: self.ks_changed[k] for k in ("time", "action")}
        if self.failures:
            s["retry_in_s"] = max(0, round(self.due - time.time()))
        if self.last and not self.error:
            age = None
            if self.apply_ and self.tunnel.up_:
                try:
                    age = self.tunnel.handshake_age(self.last["gateway_public"])
                except (WGError, OSError):
                    age = None
            full = "0.0.0.0/0" in self.last["routes"]
            s |= {"state": ("protected" if age is not None and age <= 180 else "connecting") if self.apply_ else "agreed",
                  "address": self.last["address"], "routes": self.last["routes"], "full_tunnel": full, "kill_switch": full and self.apply_,
                  "connected_since": self.since, "handshake_age_s": None if age is None else round(age), "next_key_s": max(0, round(self.due - time.time())),
                  "overdue": s["last_key_s"] > 2 * self.last["rotate_s"],  # renewal is late: still the last key, but nothing new arrives
                  "key_agreement": self.details | {"post_quantum": "MLKEM" in str(self.details.get("tls_group", "")).upper(),
                                                   "psk_rotation_s": self.last["rotate_s"]}}
        return s

    def report(self, s=None):
        s = s or self.status()
        if self.status_file:
            try:
                write(Path(self.status_file), json.dumps(s).encode())
            except OSError as e:
                log.debug("status file not written: %s", e)
        key = (s["state"], s.get("error"), s.get("address"))
        if key != self.reported:
            self.reported = key
            if self.on_status:
                self.on_status(s)

    def run(self):
        if self.stop_file:
            self.stop_file.unlink(missing_ok=True)
        while not self.stop.is_set():
            self.stop.wait(self.step())

    def close(self):
        """Take the tunnel down and lift the kill switch (after a deliberate stop; a crash leaves both, failing closed)."""
        if self.apply_:
            self.tunnel.down()
            self.kill_switch.off()
            self.killswitch(False)
        self.last = self.agreed_at = None
        self.failures = 0
        self.report({"state": "disconnected", "gateway": f"{self.host}:{self.port}", "device": self.name, "error": None, "updated": time.time()})


def wg_quick(private, reply, psk):
    """A wg-quick / WireGuard for Windows configuration. Its PSK is good until the next rotation, which `vpn connect` sets in place."""
    dns = f"DNS = {', '.join(reply['dns'])}\n" if reply["dns"] else ""
    return (f"[Interface]\nPrivateKey = {private}\nAddress = {reply['address']}\n{dns}\n[Peer]\nPublicKey = {reply['gateway_public']}\n"
            f"PresharedKey = {psk}\nEndpoint = {reply['endpoint']}\nAllowedIPs = {', '.join(reply['routes'])}\nPersistentKeepalive = 25\n")
