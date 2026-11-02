"""strongSwan's charon, driven through its VICI API: no config files, no parsing of command output."""
import socket
import threading
from urllib.parse import urlparse

from . import PROFILES

TRANSPORT_ERRORS: tuple[type[Exception], ...]
try:
    from vici.exception import CommandException, SessionException, DeserializationException
    TRANSPORT_ERRORS = (OSError, EOFError, SessionException, DeserializationException)
except ImportError:
    CommandException = ()
    TRANSPORT_ERRORS = (OSError, EOFError)


class CharonError(Exception):
    pass


def connect(uri):
    try:
        import vici
    except ImportError:
        raise CharonError('the site-to-site VPN needs its extra: pip install "acxelin-vpn[vpn]"') from None
    u = urlparse(uri)
    s = None
    try:
        if u.scheme == "unix":
            if not hasattr(socket, "AF_UNIX"):
                raise CharonError(f"cannot reach charon at {uri}: this machine has no Unix sockets; strongSwan gateways run on Linux"
                                  " (use tcp://host:port to reach one from here)")
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(10)
            s.connect(u.path)
        elif u.scheme == "tcp":
            s = socket.create_connection((u.hostname, u.port), timeout=10)
        else:
            raise CharonError(f"unsupported VICI address {uri}; use unix:///path or tcp://host:port")
    except OSError as e:
        if s is not None:
            s.close()
        raise CharonError(f"cannot reach charon at {uri}: {e} (is strongSwan running?)") from None
    s.settimeout(60)
    return vici.Session(s)


def text(v):
    return v.decode() if isinstance(v, bytes) else v


def cipher(sa):
    """The encryption as strongSwan names it in proposals, key size included: AES_GCM_16_256."""
    alg, size = text(sa.get("encr-alg", b"")), text(sa.get("encr-keysize", b""))
    return f"{alg}_{size}" if alg and size else alg


def protected(tunnel):
    """PQ key negotiation is not a usable VPN until an encrypted child SA is installed."""
    return bool(tunnel and tunnel.get('state') == 'ESTABLISHED' and tunnel.get('ppk')
                and 'ML_KEM' in tunnel.get('key_exchange', '')
                and any(c.get('state') == 'INSTALLED' for c in tunnel.get('children', [])))


# What a classical_fallback peer offers after hybrid ML-KEM: common IKEv2 suites of other vendors' gateways. NOT QUANTUM SAFE.
CLASSICAL = {"ike": "aes256gcm16-prfsha384-x25519-ecp384", "esp": "aes256gcm16-x25519-ecp384"}


def tier(tunnel):
    """What an established tunnel reached: "hybrid" (ML-KEM in the key exchange), "classical+ppk" (classical with an RFC 8784 PPK)
    or "classical". Only hybrid is quantum safe."""
    if not tunnel or tunnel.get("state") != "ESTABLISHED":
        return None
    if "ML_KEM" in str(tunnel.get("key_exchange", "")):
        return "hybrid"
    return "classical+ppk" if tunnel.get("ppk") else "classical"


def ppk_pattern(site, peer):
    a, b = sorted((site, peer))
    return f"{a}.{b}.ppk.pqcsuite"


def conn_config(site, peer, ppk_id=None):
    """The VICI load-conn message for one peer. PSK authentication, PPK required, hybrid ML-KEM on IKE and every rekey. A
    classical_fallback peer also offers classical proposals after the hybrid one, and uses its static PPK only if the partner can."""
    if getattr(peer, "classical_fallback", False):
        return fallback_config(site, peer)
    ike, esp = PROFILES[peer.profile]
    return {peer.name: {
        "version": 2, "local_addrs": [site.address], "remote_addrs": [peer.address], "proposals": [ike],
        "ppk_id": ppk_id or f"*.{ppk_pattern(site.name, peer.name)}", "ppk_required": "yes",
        "rekey_time": "14400", "reauth_time": "0", "dpd_delay": "30",
        "unique": "replace", "mobike": "no",
        "local": {"auth": "psk", "id": site.name}, "remote": {"auth": "psk", "id": peer.name},
        "children": {"net": {"local_ts": peer.local_subnets, "remote_ts": peer.remote_subnets, "esp_proposals": [esp],
                             "rekey_time": "3600", "dpd_action": "restart" if peer.initiate else "clear",
                             "start_action": "none", "close_action": "none"}},
    }}


def fallback_config(site, peer):
    ike, esp = PROFILES[peer.profile]
    conf = {
        "version": 2, "local_addrs": [site.address], "remote_addrs": [peer.address], "proposals": [ike, CLASSICAL["ike"]],
        "rekey_time": "14400", "reauth_time": "0", "dpd_delay": "30", "unique": "replace", "mobike": "no",
        "local": {"auth": "psk", "id": site.name}, "remote": {"auth": "psk", "id": peer.name},
        "children": {"net": {"local_ts": peer.local_subnets, "remote_ts": peer.remote_subnets, "esp_proposals": [esp, CLASSICAL["esp"]],
                             "rekey_time": "3600", "dpd_action": "restart" if peer.initiate else "clear", "start_action": "none", "close_action": "none"}},
    }
    if peer.fallback_ppk_file:
        conf |= {"ppk_id": f"static.{ppk_pattern(site.name, peer.name)}", "ppk_required": "no"}
    return {peer.name: conf}


class Charon:
    def __init__(self, uri):
        self.uri = uri
        self.session = connect(uri)
        self.lock = threading.Lock()

    def close(self):
        with self.lock:
            if self.session is not None:
                self.session.transport.socket.close()
                self.session = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _call(self, method, *args):
        """Serialize requests; discard broken sessions without replaying an uncertain mutation."""
        with self.lock:
            try:
                if self.session is None:
                    self.session = connect(self.uri)
                result = getattr(self.session, method)(*args)
                return list(result) if hasattr(result, "__next__") else result
            except TRANSPORT_ERRORS as e:
                if self.session is not None:
                    self.session.transport.socket.close()
                    self.session = None
                raise CharonError("VICI connection lost; the next request will reconnect") from e
            except CommandException as e:
                raise CharonError(str(e)) from None

    def version(self):
        v = self._call("version")
        return f"{text(v['daemon'])} {text(v['version'])}"

    def ml_kem(self):
        """ML-KEM key exchanges this charon supports."""
        return sorted(text(k) for k in self._call("get_algorithms").get("ke", {}) if text(k).startswith("ML_KEM"))

    def load_keys(self, site, peer, psk, ppk, ppk_id, key_tag):
        self._call("load_shared", {"id": f"psk-{peer}", "type": "IKE", "data": psk, "owners": [site, peer]})
        self._call("load_shared", {"id": f"ppk-{peer}-{key_tag}", "type": "PPK", "data": ppk, "owners": [ppk_id]})

    def load_static(self, site, peer, psk, ppk, ppk_id):
        """A classical_fallback partner's keys from its files: no rotation, since the partner cannot take part in key agreement."""
        self._call("load_shared", {"id": f"psk-{peer}", "type": "IKE", "data": psk, "owners": [site, peer]})
        if ppk:
            self._call("load_shared", {"id": f"ppk-{peer}-static", "type": "PPK", "data": ppk, "owners": [ppk_id]})

    def unload_key(self, key_id):
        self._call("unload_shared", {"id": key_id})

    def shared_ids(self):
        return [text(k) for k in self._call("get_shared").get("keys", [])]

    def load_conn(self, config):
        self._call("load_conn", config)

    def initiate(self, peer, timeout_ms=15000):
        return [text(m.get("msg", b"")) for m in self._call("initiate", {"ike": peer, "child": "net", "timeout": timeout_ms, "init-limits": "no"})]

    def terminate(self, peer):
        try:
            self._call("terminate", {"ike": peer, "timeout": 5000, "force": "yes"})
        except CharonError as e:
            if "no matching" not in str(e):
                raise

    def tunnels(self):
        """One dict per IKE SA: who, state, algorithms, whether a PPK was used, and its child SAs with traffic counters."""
        out = []
        for sa in self._call("list_sas"):
            for name, ike in sa.items():
                kes = [text(ike.get(k)) for k in ["dh-group"] + [f"ake{i}" for i in range(1, 8)] if ike.get(k)]
                out.append({
                    "peer": text(name), "state": text(ike["state"]), "remote": text(ike.get("remote-host", b"")),
                    "established_s": int(text(ike.get("established", b"0"))), "encryption": cipher(ike),
                    "key_exchange": " + ".join(kes), "ppk": text(ike.get("ppk", b"no")) == "yes",
                    "children": [{"name": text(cn), "state": text(c["state"]), "encryption": cipher(c),
                                  "bytes_in": int(text(c.get("bytes-in", b"0"))), "bytes_out": int(text(c.get("bytes-out", b"0"))),
                                  "packets_in": int(text(c.get("packets-in", b"0"))), "packets_out": int(text(c.get("packets-out", b"0")))}
                                 for cn, c in ike.get("child-sas", {}).items()],
                })
        return out
