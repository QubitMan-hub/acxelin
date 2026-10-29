import re
import socket
import ssl

from cryptography import x509

from ..catalog import lookup, curve, pq_from_text, HYBRIDS
from ..model import Detection
from .artifacts import cert_record
from .probe import legacy_versions, tls_groups, ssh_kexinit
from .suites import suite, ssh_token

def _ctx():
    """A client context for looking, not trusting: the probe records what the server offers."""
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _handshake(host, port, ctx, timeout):
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            return t.version(), t.cipher(), t.getpeercert(binary_form=True)


def _split(target, default):
    target = target.split("://", 1)[-1].split("/", 1)[0]
    host, _, port = target.rpartition(":")
    if not host or not port.isdigit() or ":" in host and not host.endswith("]"):
        return target.strip("[]"), default
    return host.strip("[]"), int(port)


def group_algo(name):
    if m := re.fullmatch(r"ffdhe(\d+)", name):
        return "DH", {"key_size": int(m.group(1))}
    c = curve(name)
    if c:
        return "ECDH", {"curve": c}
    return lookup(name) or pq_from_text(name), {}


def probe(target, timeout=6.0):
    host, port = _split(target, 443)
    loc = f"tls://{host}:{port}"
    ep = {"target": loc, "kind": "tls"}
    sights, arts, notes = [], [], []

    def add(algo, snip, **p):
        if algo:
            sights.append(Detection(algo=algo, file=loc, line=0, evidence="live", detector="tls", snippet=snip, lang="tls",
                                   params={k: v for k, v in p.items() if v is not None}))
    version = cipher = der = None
    try:
        version, cipher, der = _handshake(host, port, _ctx(), timeout)
    except ssl.SSLError as e:
        failed = f"{type(e).__name__}: {e}"
    except Exception as e:
        ep["error"] = f"{type(e).__name__}: {e}"
        return sights, arts, [f"{loc}: handshake failed ({ep['error']})"], ep
    if version:
        ep.update(version=version, cipher=cipher[0])
        add(lookup(version), f"{version} {cipher[0]}", negotiated=True, cipher=cipher[0])
        for a, p in suite(cipher[0]):
            add(a, cipher[0], role="cipher-suite", **p)
    g = tls_groups(host, port, timeout)
    if not version and ("error" in g or not g.get("supported")):
        ep["error"] = failed
        return sights, arts, [f"{loc}: handshake failed ({failed})"], ep
    if not version:
        ep["version"] = "TLSv1.3"
        add(lookup("TLSv1.3"), "server answered a TLS 1.3 HelloRetryRequest", negotiated=True)
        notes.append(f"{loc}: the local OpenSSL could not finish a handshake ({failed}); key-exchange groups come from the "
                     "raw ClientHello probe, and the certificate, which TLS 1.3 encrypts, was not read")
    if "error" in g:
        notes.append(f"{loc}: group probe failed ({g['error']})")
    else:
        ep.update(preferred_group=g.get("preferred"), groups=g.get("supported", []), pq_groups=g.get("pq", []))
        for name in g.get("supported", []):
            a, p = group_algo(name)
            add(a, f"server accepts key-exchange group {name}" + (" (preferred)" if name == g.get("preferred") else ""), role="key-exchange", **p)
    if der:
        a, s = cert_record(x509.load_der_x509_certificate(der), loc, 0, source="live")
        arts.append(a)
        sights += s
        ep["cert"] = f"{a.algo}" + (f"-{a.params.get('key_size') or a.params.get('curve')}" if a.params else "") + f", expires {a.details['not_after'][:10]}"
    ep["legacy"], old = [], legacy_versions(host, port, timeout)
    if old is None:
        notes.append(f"{loc}: TLS 1.0 and 1.1 could not be checked (no answer); scan again to know")
    for name, code in old or []:
        ep["legacy"].append(name)
        add(name, f"server accepted {name} (cipher suite 0x{code:04X})", negotiated=False)
    return sights, arts, notes, ep


def probe_ssh(target, timeout=6.0):
    host, port = _split(target, 22)
    loc = f"ssh://{host}:{port}"
    ep = {"target": loc, "kind": "ssh"}
    try:
        r = ssh_kexinit(host, port, timeout)
    except Exception as e:
        ep["error"] = f"{type(e).__name__}: {e}"
        return [], [], [f"{loc}: SSH probe failed ({ep['error']})"], ep
    r["kex"] = [k for k in r["kex"] if not k.startswith(("kex-strict", "ext-info"))]
    ep.update(version=r["banner"], preferred_group=r["kex"][0] if r["kex"] else None, groups=r["kex"], hostkeys=r["hostkey"],
              pq_groups=[k for k in r["kex"] if lookup(k.split("@")[0]) in HYBRIDS])
    sights = []
    for field, role in (("kex", "key-exchange"), ("hostkey", "host-key"), ("ciphers", "cipher"), ("macs", "mac")):
        for tok in r[field]:
            for a, p in ssh_token(tok):
                if a:
                    sights.append(Detection(algo=a, file=loc, line=0, evidence="live", detector="ssh", snippet=f"{field}: {tok}", lang="ssh",
                                           params={k: v for k, v in dict(p, role=role).items() if v is not None}))
    return sights, [], [], ep
