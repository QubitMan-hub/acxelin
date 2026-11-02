"""Runs one site: agrees keys with each peer over post-quantum mutual TLS, loads them into charon, rotates them, and cuts
tunnels whose peer certificate has been revoked."""
import logging
import threading
import time
from collections import Counter

from acxelin_core import tls
from acxelin_core.config import env_passphrase
from acxelin_core.http import explain, hostport
from acxelin_core.pki import CAError, follow_crl
from acxelin_core.server import Revocation

from . import agreement, qkd
from .agreement import TAG, common_name, read_line
from . import read_secret
from .charon import Charon, CharonError, conn_config, ppk_pattern, protected, tier
from .grace import Grace, crl_verdict
from .policies import policy_for

log = logging.getLogger(__name__)
LABEL, context = agreement.IPSEC, agreement.ipsec_context


class Controller:
    def __init__(self, site, charon=None):
        self.site = site
        self.charon = charon or Charon(site.vici)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.keys = {p.name: [] for p in site.peers}
        self.serials = {}
        self.last_agreed = {}
        self.counts = Counter()
        self.grace = Grace(log, self.counts)
        self.crl_follow = follow_crl(site.crl_url, site.crl, site.ca, site.crl_every) if site.crl_url else None
        self.revocation = Revocation(site.crl, site.ca) if site.crl else None
        self.server = None
        self.started = time.time()
        self.tiers = {}  # the last tier logged per peer, so NOT QUANTUM SAFE is said once per change, not every pass
        s = site
        self.kme = qkd.KME(s.qkd_kme, s.qkd_sae_id, s.qkd_ca, s.qkd_cert, s.qkd_key, self.passphrase) if s.qkd_kme else None

    def passphrase(self):
        return env_passphrase(self.site.key_passphrase_env)

    def install(self, peer, tag, material, cert):
        """Load the PSK and PPK derived from one key agreement; keep the previous PPK so SAs being rebuilt still find it."""
        psk, ppk = material[:32], material[32:]
        ppk_id = f"{tag}.{ppk_pattern(self.site.name, peer.name)}"
        with self.lock:
            self.charon.load_keys(self.site.name, peer.name, psk, ppk, ppk_id, tag)
            self.charon.load_conn(conn_config(self.site, peer, ppk_id if peer.initiate else None))
            self.keys[peer.name].append(tag)
            for old in self.keys[peer.name][:-2]:
                self.charon.unload_key(f"ppk-{peer.name}-{old}")
            self.keys[peer.name] = self.keys[peer.name][-2:]
        self.serials[peer.name] = (cert.serial_number, cert.issuer)
        self.last_agreed[peer.name] = time.time()
        self.counts["key_agreements"] += 1
        self.grace.end(peer.name, "it agreed new keys")
        log.info("%s: new keys %s (PSK + PPK from ML-DSA mutual TLS)", peer.name, tag)

    def load_fallback(self, peer):
        """A partner without Acxelin's key agreement: static keys from its files, hybrid first, classical after."""
        psk = read_secret(peer.fallback_psk_file, f"{peer.name}: fallback_psk_file")
        ppk = read_secret(peer.fallback_ppk_file, f"{peer.name}: fallback_ppk_file") if peer.fallback_ppk_file else None
        conf = conn_config(self.site, peer)
        with self.lock:
            self.charon.load_static(self.site.name, peer.name, psk, ppk, conf[peer.name].get("ppk_id"))
            self.charon.load_conn(conf)
        log.warning("%s: classical_fallback is on: hybrid ML-KEM is offered first; if the partner cannot do it, the tunnel is classical "
                    "(with its PPK when the partner supports RFC 8784) and NOT QUANTUM SAFE", peer.name)

    def fallback_loop(self, peer):
        """Bring the partner's tunnel up and keep it up; there are no keys to agree, so nothing rotates here."""
        while not self.stop.is_set():
            try:
                if not tier(self.tunnel(peer.name)):
                    with self.lock:
                        self.charon.initiate(peer.name)
                    self.counts["connects"] += 1
            except (CharonError, OSError) as e:
                self.counts["failures"] += 1
                log.warning("%s: %s; retrying in 30s", peer.name, explain(e))
            self.stop.wait(30)

    def report_tiers(self):
        """One warning each time a fallback peer's tunnel reaches a tier below hybrid, and one line when it returns to hybrid."""
        tunnels = {t["peer"]: t for t in self.charon.tunnels()}
        for p in self.site.peers:
            if not p.classical_fallback:
                continue
            now = tier(tunnels.get(p.name))
            if now == self.tiers.get(p.name):
                continue
            self.tiers[p.name] = now
            if now in ("classical", "classical+ppk"):
                log.warning("NOT QUANTUM SAFE: the tunnel to %s uses classical IKEv2%s; traffic recorded now could be read by a future "
                            "quantum computer", p.name, " with an RFC 8784 PPK" if now == "classical+ppk" else " without a PPK")
            elif now == "hybrid":
                log.info("%s: the tunnel uses hybrid ML-KEM (quantum safe)", p.name)

    def agree(self, peer):
        """Initiator side: connect to the peer's keyring, prove who we are, derive the keys, wait for the peer to confirm."""
        with agreement.dial(hostport(peer.keyring, peer.address), self.site.ca, self.site.cert, self.site.key, self.passphrase(), peer.name,
                            policy=policy_for(self.site)) as conn:
            cert = conn.peer_certificate()
            if common_name(cert) != peer.name:
                raise tls.TLSError(f"{peer.keyring} presented {common_name(cert)!r}, expected {peer.name!r}")
            if self.revocation:
                self.revocation.check(cert.serial_number, (), cert.issuer)
            tag, msg = agreement.new_tag(), {}
            if peer.qkd_sae_id:
                key_id, qkey = self.kme.new_key(peer.qkd_sae_id)
                msg = {"qkd_key_id": key_id}
            agreement.send(conn, {"v": 1, "site": self.site.name, "tag": tag} | msg)
            material = agreement.ipsec_keys(conn, self.site.name, peer.name, tag)
            if peer.qkd_sae_id:
                material = qkd.mix(material, qkey, context(self.site.name, peer.name, tag))
                self.counts["qkd_keys"] += 1
            if read_line(conn).get("ok") is not True:
                raise tls.TLSError(f"{peer.name} refused the key agreement")
        self.install(peer, tag, material, cert)
        return tag

    def respond(self, conn, addr):
        """Responder side, called by the keyring server after mutual TLS and the CRL check succeeded."""
        cert = conn.peer_certificate()
        name = common_name(cert)
        peer = self.site.peer(name)
        msg = read_line(conn)
        if not peer or peer.initiate or msg.get("site") != name or not TAG.match(str(msg.get("tag", ""))):
            self.counts["key_agreements_refused"] += 1
            log.warning("keyring: refused %s from %s", name or "unknown", addr[0])
            agreement.send(conn, {"ok": False})
            return
        material = agreement.ipsec_keys(conn, self.site.name, name, msg["tag"])
        if peer.qkd_sae_id:
            try:
                qkey = self.kme.key(peer.qkd_sae_id, msg.get("qkd_key_id"))
            except qkd.QKDError as e:
                self.counts["key_agreements_refused"] += 1
                log.warning("keyring: refused %s: no QKD key (%s)", name, e)
                agreement.send(conn, {"ok": False})
                return
            material = qkd.mix(material, qkey, context(self.site.name, name, msg["tag"]))
            self.counts["qkd_keys"] += 1
        self.install(peer, msg["tag"], material, cert)
        agreement.send(conn, {"ok": True})

    def tunnel(self, name):
        """The newest IKE SA with this peer; during a rotation the old one lingers until the responder replaces it."""
        with self.lock:
            return min((t for t in self.charon.tunnels() if t["peer"] == name), key=lambda t: t["established_s"], default=None)

    def initiator_loop(self, peer):
        rotate, backoff = peer.rotate_minutes * 60, 5
        while not self.stop.is_set():
            try:
                t = self.tunnel(peer.name)
                due = time.time() - self.last_agreed.get(peer.name, 0) >= rotate
                if due or not protected(t):
                    self.agree(peer)
                    with self.lock:
                        self.charon.initiate(peer.name)
                    self.counts["rotations" if t else "connects"] += 1
                backoff = 5
            except (tls.TLSError, CAError, CharonError, OSError, ValueError, qkd.QKDError) as e:
                self.counts["failures"] += 1
                log.warning("%s: %s; retrying in %ds", peer.name, explain(e), backoff)
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 300)
                continue
            self.stop.wait(min(30, rotate))

    def cut(self, name, why):
        """Close the tunnel with `name` and unload every key it had, including keys a previous controller run loaded."""
        with self.lock:
            self.charon.terminate(name)
            for key in self.charon.shared_ids():
                if key == f"psk-{name}" or key.startswith(f"ppk-{name}-"):
                    self.charon.unload_key(key)
            self.keys[name] = []
        self.serials.pop(name, None)
        log.warning("%s: %s; closed its tunnel and discarded its keys", name, why)

    def limit(self, peer):
        """Seconds without a key agreement after which a peer's tunnel is cut, before any outage grace."""
        return 3 * peer.rotate_minutes * 60 + 120

    def verdict(self, name):
        serial, issuer = self.serials.get(name, (None, None))  # none: no certificate seen since this run began, so nothing to clear
        return crl_verdict(self.revocation, serial, issuer)

    def enforce_freshness(self):
        """Keys are only good while the peer keeps proving itself: after three rotation periods without a key agreement (for
        example a revoked peer, or tunnels left from before a controller restart) the tunnel is closed. With outage_grace_minutes
        a peer is kept up to that much longer, but only while the CRL is usable and does not list it."""
        for p in self.site.peers:
            if p.classical_fallback:
                continue  # static keys: there are no key agreements to be fresh
            age, limit, cap = time.time() - self.last_agreed.get(p.name, self.started), self.limit(p), p.outage_grace_minutes * 60
            if age <= limit:
                continue
            if not (self.tunnel(p.name) or self.keys[p.name]):
                self.grace.end(p.name, "its tunnel and keys are gone")
                continue
            verdict, why = self.verdict(p.name)
            if verdict == "revoked":
                self.grace.end(p.name)
                self.cut(p.name, why)
                self.counts["revoked_peers"] += 1
            elif verdict == "ok" and age <= limit + cap:
                self.grace.begin(p.name, cap, age)
            else:
                note = f"; the outage grace of {p.outage_grace_minutes:g} minutes is over" if cap and verdict == "ok" else (
                    f"; the outage grace does not apply because the CRL cannot be used ({why})" if cap else "")
                self.grace.end(p.name)
                self.cut(p.name, f"no key agreement for {int(age)}s{note}")
                self.counts["stale_peers"] += 1

    def enforce_revocations(self):
        """Cut the tunnel and drop the keys of any peer whose certificate appears on the CRL."""
        if not self.revocation:
            return
        for name in list(self.serials):
            verdict, why = self.verdict(name)
            if verdict == "unusable":
                log.error("CRL problem, keeping tunnels as they are: %s", why)
                return
            if verdict == "revoked":
                self.grace.end(name)
                self.cut(name, why)
                self.counts["revoked_peers"] += 1

    def enforce(self):
        """One pass, every 15 seconds: revocations first, so the grace can never delay one."""
        self.enforce_revocations()
        self.enforce_freshness()

    def start(self):
        s = self.site
        log.info("%s: charon %s, ML-KEM available: %s", s.name, self.charon.version(), ", ".join(self.charon.ml_kem()) or "none")
        if not self.charon.ml_kem():
            raise CharonError("this strongSwan has no ML-KEM; build 6.0.2+ with the openssl (OpenSSL 3.5+) or ml plugin")
        for p in s.peers:
            if p.classical_fallback:
                self.load_fallback(p)
            elif not p.initiate:
                self.charon.load_conn(conn_config(s, p))
        if s.keyring_listen:
            self.server = agreement.keyring(s.keyring_listen, s.cert, s.key, s.ca, self.respond, s.crl, self.passphrase, policy=policy_for(s))
        for p in s.peers:
            if p.initiate:
                loop = self.fallback_loop if p.classical_fallback else self.initiator_loop
                threading.Thread(target=loop, args=(p,), daemon=True, name=p.name).start()

        def watch():
            while not self.stop.wait(15):
                try:
                    self.enforce()
                    self.report_tiers()
                except (CharonError, OSError) as e:
                    log.error("revocation check failed: %s", e)
        threading.Thread(target=watch, daemon=True, name="revocations").start()

    def shutdown(self):
        self.stop.set()
        if self.crl_follow:
            self.crl_follow.set()
        if self.server:
            self.server.stop(2)

    def status(self):
        tunnels = {t["peer"]: t for t in self.charon.tunnels()}
        return {p.name: {"initiate": p.initiate, "profile": p.profile, "keys_age_s": int(time.time() - self.last_agreed[p.name])
                         if p.name in self.last_agreed else None, "certificate": format(self.serials[p.name][0], "x") if p.name in self.serials else None,
                         "tunnel": tunnels.get(p.name), **self.grace_state(p), **self.safety(p, tunnels.get(p.name))} for p in self.site.peers} | {
            "_events": dict(self.counts)}

    def safety(self, p, t):
        """Whether the tunnel is quantum safe, in words a person reads: only hybrid ML-KEM is."""
        reached = tier(t) if p.classical_fallback else ("hybrid" if protected(t) else tier(t))
        return {"classical_fallback": p.classical_fallback, "tier": reached, "quantum_safe": None if reached is None else reached == "hybrid",
                **({"label": "NOT QUANTUM SAFE"} if reached in ("classical", "classical+ppk") else {})}

    def grace_state(self, p):
        return self.grace.state(p.name, time.time() - self.last_agreed.get(p.name, self.started), self.limit(p), p.outage_grace_minutes * 60)

    def metrics(self):
        lines = ["# TYPE acxelin_vpn_tunnel_up gauge", "# TYPE acxelin_vpn_bytes_total counter", "# TYPE acxelin_vpn_events_total counter",
                 "# TYPE acxelin_vpn_tunnel_in_grace gauge", "# TYPE acxelin_vpn_tunnel_grace_remaining_seconds gauge",
                 "# TYPE acxelin_vpn_tunnel_quantum_safe gauge", "# TYPE acxelin_vpn_tunnel_tier gauge"]
        tunnels = {t["peer"]: t for t in self.charon.tunnels()}
        for p in self.site.peers:
            t = tunnels.get(p.name)
            up = int(protected(t))
            lines.append(f'acxelin_vpn_tunnel_up{{peer="{p.name}"}} {up}')
            safe = self.safety(p, t)
            if safe["tier"]:
                lines.append(f'acxelin_vpn_tunnel_quantum_safe{{peer="{p.name}"}} {int(safe["quantum_safe"])}')
                lines.append(f'acxelin_vpn_tunnel_tier{{peer="{p.name}",tier="{safe["tier"]}"}} 1')
            g = self.grace_state(p)
            lines.append(f'acxelin_vpn_tunnel_in_grace{{peer="{p.name}"}} {int(g["in_grace"])}')
            if g["in_grace"]:
                lines.append(f'acxelin_vpn_tunnel_grace_remaining_seconds{{peer="{p.name}"}} {g["grace_remaining_s"]}')
            for c in (t or {}).get("children", []):
                lines.append(f'acxelin_vpn_bytes_total{{peer="{p.name}",direction="in"}} {c["bytes_in"]}')
                lines.append(f'acxelin_vpn_bytes_total{{peer="{p.name}",direction="out"}} {c["bytes_out"]}')
        lines += [f'acxelin_vpn_events_total{{event="{k}"}} {v}' for k, v in self.counts.items()]
        return "\n".join(lines) + "\n"
