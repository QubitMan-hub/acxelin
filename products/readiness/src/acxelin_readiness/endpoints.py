"""Post-quantum readiness of TLS endpoints: which key exchanges each accepts, what it negotiates, and its certificate."""
import datetime as dt
import html
import json
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from acxelin_core.config import read_text
from acxelin_core.http import explain, hostport
from acxelin_core.openssl import Context, OpenSSLUnavailable, TLSError
from acxelin_core.pki import algorithm_of

from . import __version__
from .brand import page as _page
from .detectors.probe import legacy_versions, tls_groups, weak_suites

log = logging.getLogger(__name__)
CIPHERSUITES = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"  # every TLS 1.3 suite, so the probe never limits what the server can pick
PQ = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024"]
CNSA2_GROUPS = {"SecP384r1MLKEM1024", "MLKEM1024"}
CLASSICAL = ["X25519", "secp256r1", "secp384r1", "secp521r1", "X448", "ffdhe2048", "ffdhe3072"]
CANON = {g.lower(): g for g in PQ + CLASSICAL}


def canonical(group):
    """A group as named in PQ and CLASSICAL, whatever case OpenSSL reports it in (x25519 for X25519)."""
    return CANON.get(group.lower(), group) if group else group


def _note(out, text):
    out["note"] = " ".join(filter(None, [out.get("note"), text]))
GRADES = {
    "A": "post-quantum key exchange only",
    "B": "post-quantum key exchange, classical still accepted",
    "C": "classical only: traffic recorded today can be decrypted later",
    "F": "unreachable, or no TLS at all",
}


def key_name(key):
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return algorithm_of(key) or type(key).__name__


def _result(target, protocol, **found):
    return {"target": target, "protocol": protocol, "accepts": [], "negotiated": None, "certificate": None, "error": None, "cnsa2": False,
            **found}


def _unverified():
    """A client context for looking, not trusting: legacy probes only record what the server offers."""
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return ctx


def _legacy(host, port, server_name, timeout):
    """(version, certificate) from a server that refuses TLS 1.3 but still talks TLS 1.2 or older."""
    import ssl
    from cryptography import x509
    ctx = _unverified()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=server_name) as s:
        der = s.getpeercert(binary_form=True)
        return s.version(), x509.load_der_x509_certificate(der) if der else None


def _newest(host, port, server_name, timeout):
    """(version, certificate) when this machine's Python offers the newest TLS it has."""
    from cryptography import x509
    with socket.create_connection((host, port), timeout=timeout) as raw, _unverified().wrap_socket(raw, server_hostname=server_name) as s:
        der = s.getpeercert(binary_form=True)
        return s.version(), x509.load_der_x509_certificate(der) if der else None


def _raw(out, e, host, port, cert, server_name, timeout):
    """A TLS 1.3 server graded from raw ClientHellos, when this machine's OpenSSL cannot ask for post-quantum groups."""
    g = tls_groups(host, port, timeout)
    if "error" in g or not g.get("supported"):
        out["error"], out["grade"] = explain(e), "F"
        return out
    out["accepts"] = [n for n in PQ + CLASSICAL if n in g["supported"]]
    out["negotiated"] = g.get("preferred") or (out["accepts"] or [None])[0]
    pq, classical = (any(n in out["accepts"] for n in s) for s in (PQ, CLASSICAL))
    out["grade"] = "A" if pq and not classical else "B" if pq else "C" if classical else "F"
    out["certificate"], out["legacy"] = _cert_info(cert), _old_versions(out, host, port, server_name or host, timeout)
    _weak(out, host, port, server_name or host, timeout)
    out["trusted"] = _trusted(host, port, server_name or host, timeout)
    _note(out, "Groups read with raw ClientHello messages: this machine's OpenSSL is older than 3.5.")
    return out


def _trusted(host, port, server_name, timeout):
    """Whether this machine's trust store accepts the certificate for this name (None when that cannot be told). A public site
    that is not trusted usually means a TLS-inspecting proxy answered instead, as inside many company networks."""
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=server_name):
            return True
    except ssl.SSLCertVerificationError:
        return False
    except (OSError, ValueError):
        return None


def _old_versions(out, host, port, server_name, timeout):
    """TLS 1.0 and 1.1, which should be off everywhere; None, with a note, when the server could not be asked."""
    found = legacy_versions(host, port, timeout, server_name)
    if found is None:
        _note(out, "TLS 1.0 and 1.1 could not be checked: the server did not answer. Check again.")
        return None
    return [name.replace(" ", "v") for name, _ in found]


def _weak(out, host, port, server_name, timeout):
    """RC4, 3DES and Diffie-Hellman under 2048 bits, which the server should not accept at all."""
    from .detectors.capture import suite_name
    found = weak_suites(host, port, timeout, server_name)
    if found is None:
        _note(out, "Weak cipher suites could not be checked: the server did not answer. Check again.")
    out["weak_suites"] = [f"{kind}{f' {bits}-bit' if bits else ''} ({suite_name(code)})" for kind, code, bits in found or []]
    return out["weak_suites"]


def _only_old(out, e, host, port, server_name, timeout):
    """A server this machine's TLS library will not talk to: one that speaks TLS 1.2 only with broken suites, or only TLS 1.0 or 1.1.
    Both are read with raw ClientHello messages."""
    if _weak(out, host, port, server_name, timeout):
        out["negotiated"], out["grade"] = "TLSv1.2", "C"
        out["legacy"] = _old_versions(out, host, port, server_name, timeout)
        _note(out, "Speaks TLS 1.2 only with suites this machine's TLS library refuses, read with raw ClientHello messages; the certificate was not read.")
        return out
    found = legacy_versions(host, port, timeout, server_name) or []
    if not found:
        out["error"], out["grade"] = explain(e), "F"
        return out
    out["legacy"] = [name.replace(" ", "v") for name, _ in found]
    out["negotiated"], out["grade"] = out["legacy"][-1], "C"
    _note(out, f"Accepts only {' and '.join(n for n, _ in found)}, read with raw ClientHello messages; the certificate was not read.")
    return out


BROWSER_GROUPS = "*X25519MLKEM768:*X25519:" + ":".join(g for g in PQ + CLASSICAL if g not in ("X25519MLKEM768", "X25519"))


def _hello(host, port, groups, server_name, timeout):
    """The group the server picks and its certificate. BROWSER_GROUPS sends key shares for X25519MLKEM768 and X25519 as browsers do,
    so the group reported is the one a browser gets; an OpenSSL that cannot read the '*' marks is offered the plain list."""
    try:
        ctx = Context(False, groups, None, CIPHERSUITES, verify=False)  # acxelin:ignore (a probe of what the server offers; no data is sent)
    except TLSError as e:
        if groups != BROWSER_GROUPS or "use groups" not in str(e):
            raise
        groups = ":".join(PQ + CLASSICAL)
        ctx = Context(False, groups, None, CIPHERSUITES, verify=False)  # acxelin:ignore (as above)
    try:
        with ctx.wrap(socket.create_connection((host, port), timeout=timeout), server_name, timeout) as conn:
            return conn.group, conn.peer_certificate()
    finally:
        ctx.close()


SSH_PQ = ("mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384", "sntrup761x25519-sha512",
          "sntrup761x25519-sha512@openssh.com")
SSH_META = ("ext-info-", "kex-strict-", "kex-guess")


def ssh_kexinit(host, port, timeout):
    """The server's banner and algorithm lists, read from its KEXINIT (it sends one right after the banners)."""
    import struct
    with socket.create_connection((host, port), timeout=timeout) as s:
        f = s.makefile("rb")
        banner = b""
        for _ in range(20):
            banner = f.readline(512)
            if banner.startswith(b"SSH-"):
                break
        if not banner.startswith(b"SSH-"):
            raise OSError("not an SSH server")
        s.sendall(b"SSH-2.0-acxelin_readiness_scan\r\n")
        try:
            n, pad = struct.unpack(">IB", f.read(5))
            if not 5 <= n <= 35000:  # a length below 5 would make the read below unbounded
                raise OSError("malformed SSH packet length")
            payload = f.read(n - 1)[:n - 1 - pad]
            if not payload or payload[0] != 20:
                raise OSError("the server did not send KEXINIT")
            lists, i = [], 17
            for _ in range(2):
                (m,) = struct.unpack(">I", payload[i:i + 4])
                lists.append(payload[i + 4:i + 4 + m].decode("ascii", "replace").split(","))
                i += 4 + m
        except struct.error:
            raise OSError("the server sent a truncated SSH packet") from None
    return banner.decode("ascii", "replace").strip(), lists[0], lists[1]


def probe_ssh(host, port, timeout):
    out = _result(f"ssh://{_join(host, port)}", "ssh")
    try:
        banner, kex, hostkeys = ssh_kexinit(host, port, timeout)
    except (OSError, ValueError) as e:
        out["error"], out["grade"] = explain(e), "F"
        return out
    kex = [k for k in kex if not k.startswith(SSH_META)]
    pq = [k for k in kex if k in SSH_PQ]
    out |= {"accepts": kex, "negotiated": pq[0] if pq else (kex[0] if kex else None), "banner": banner, "host_keys": hostkeys,
            "certificate": {"key": ", ".join(hostkeys[:3]), "expires": "", "days_left": None, "quantum_safe": False}}  # host keys do not expire
    out["grade"] = "A" if pq and len(pq) == len(kex) else "B" if pq else "C" if kex else "F"
    if "ssh-dss" in hostkeys:
        _note(out, "Still offers a DSA host key (ssh-dss), which OpenSSH removed in 9.8: remove it from HostKey.")
    return out


def _cert_info(cert):
    if not cert:
        return None
    try:
        key = key_name(cert.public_key())
    except Exception:
        key = cert.public_key_algorithm_oid.dotted_string
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "key": key,
            "expires": cert.not_valid_after_utc.date().isoformat(),
            "days_left": (cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days, "quantum_safe": key.startswith("ML-DSA")}


def endpoint(target):
    """(protocol, host, port) of a target written as host, host:port, [v6]:port, https://host/path or ssh://host[:port]."""
    ssh = target.startswith("ssh://")
    t = target.split("://", 1)[-1].split("/", 1)[0]
    bare = ":" not in t or t.endswith("]") or t.count(":") > 1 and not t.startswith("[")  # a port on IPv6 needs brackets
    host, port = (t.strip("[]"), None) if bare else hostport(t, "")
    if not host or not re.fullmatch(r"[\w.:%-]+", host):
        raise ValueError(f"expected host, host:port or ssh://host, got {target!r}")
    return ("ssh" if ssh else "tls"), host, port or (22 if ssh else 443)


def probe(target, server_name=None, timeout=8.0):
    kind, host, port = endpoint(target)
    if kind == "ssh":
        return probe_ssh(host, port, timeout)
    out = _result(_join(host, port), "tls")
    try:
        out["negotiated"], cert = _hello(host, port, BROWSER_GROUPS, server_name or host, timeout)
        out["negotiated"] = canonical(out["negotiated"])
    except (TLSError, OSError) as e:
        try:
            if isinstance(e, OpenSSLUnavailable):
                version, cert = _newest(host, port, server_name or host, timeout)
                if version == "TLSv1.3":
                    return _raw(out, e, host, port, cert, server_name, timeout)
            version, cert = _legacy(host, port, server_name or host, timeout)
        except (OSError, ValueError):
            return _only_old(out, e, host, port, server_name or host, timeout)
        out["negotiated"], out["grade"] = version, "C"  # no TLS 1.3, so no post-quantum group; which groups it takes was not read
        out["certificate"] = _cert_info(cert)
        out["legacy"] = _old_versions(out, host, port, server_name or host, timeout)
        _weak(out, host, port, server_name or host, timeout)
        out["trusted"] = _trusted(host, port, server_name or host, timeout)
        return out
    out["certificate"] = _cert_info(cert)
    for g in PQ + CLASSICAL:
        try:
            _hello(host, port, g, server_name or host, timeout)
            out["accepts"].append(g)
        except (TLSError, OSError):
            pass
    pq = any(g in out["accepts"] for g in PQ)
    classical = any(g in out["accepts"] for g in CLASSICAL)
    out["grade"] = "A" if pq and not classical else "B" if pq else "C" if classical else "F"
    cert_key = (out["certificate"] or {}).get("key")
    out["cnsa2"] = bool(out["accepts"]) and set(out["accepts"]) <= CNSA2_GROUPS and cert_key == "ML-DSA-87"
    out["legacy"] = _old_versions(out, host, port, server_name or host, timeout)
    _weak(out, host, port, server_name or host, timeout)
    if not cert_key or not cert_key.startswith("ML-DSA"):
        out["trusted"] = _trusted(host, port, server_name or host, timeout)
    return out


def _label(target):
    kind, host, port = endpoint(target)
    return ("ssh://" if kind == "ssh" else "") + _join(host, port)


def scan(targets, workers=16, timeout=8.0):
    """Every target gets a result: one server answering in a way nobody planned for is graded F, not the end of the scan."""
    def one(t):
        try:
            return probe(t, timeout=timeout)
        except Exception as e:
            log.exception("readiness: probing %s failed", t)
            return _result(_label(t), "ssh" if t.startswith("ssh://") else "tls", error=f"unexpected answer: {e}", grade="F")
    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(one, targets))


def summary(results):
    counts = {g: sum(r["grade"] == g for r in results) for g in GRADES}
    graded = counts["A"] + counts["B"] + counts["C"]
    certs = [r["certificate"] for r in results if r["certificate"]]
    return {"endpoints": len(results), "grades": counts, "pq_key_exchange": counts["A"] + counts["B"],
            "score": round((100 * counts["A"] + 50 * counts["B"]) / graded) if graded else None,
            "coverage": round(100 * graded / len(results)) if results else None, "cnsa2": sum(r.get("cnsa2", False) for r in results),
            "pq_certificates": sum(c["quantum_safe"] for c in certs), "expiring_30d": sum(c["days_left"] is not None and c["days_left"] < 30 for c in certs)}


def outlook(results):
    """What can happen if nothing changes, and what to do about it, most urgent first. Rules, not forecasts: each names its evidence."""
    cert = lambda r: r["certificate"] if r["protocol"] == "tls" and r["grade"] != "F" and r["certificate"] else None
    expired = [r for r in results if cert(r) and cert(r)["days_left"] < 0]
    soon = sorted((r for r in results if cert(r) and 0 <= cert(r)["days_left"] < 30), key=lambda r: cert(r)["expires"])
    tls_c = [r for r in results if r["grade"] == "C" and r["protocol"] == "tls"]
    ssh_c = [r for r in results if r["grade"] == "C" and r["protocol"] == "ssh"]
    hybrid = [r for r in results if r["grade"] == "B"]
    legacy = [r for r in results if r.get("legacy")]
    weak = [r for r in results if r.get("weak_suites")]
    untrusted = [r for r in results if r.get("trusted") is False]
    down = [r for r in results if r["grade"] == "F"]
    classical_key = [r for r in results if cert(r) and not cert(r)["quantum_safe"]]
    names = lambda rows: [r["target"] for r in rows]
    risks = [
        (weak, "Broken cipher suites still accepted (RC4, 3DES, or Diffie-Hellman under 2048 bits): a client that picks one can be attacked "
               "today, with no quantum computer."),
        (expired, "Certificate already expired: clients that check certificates refuse these connections now."),
        (soon, f"Certificate expires within 30 days (the first on {soon and cert(soon[0])['expires']}): from then on, clients that check certificates refuse these connections."),
        (tls_c + ssh_c, "Classical key exchange only: traffic recorded today can be decrypted once a large enough quantum computer exists (harvest now, "
                        "decrypt later). NIST IR 8547 (draft) deprecates quantum-vulnerable key exchange after 2030 at 112-bit strength and disallows it after 2035."),
        (hybrid, "Post-quantum offered, classical still accepted: a client that offers only classical key exchange gets a classical session, "
                 "which can be recorded now and decrypted later."),
        (legacy, "TLS 1.0 and 1.1 still accepted: a client that falls back to them uses protocols deprecated since 2021 (RFC 8996)."),
        (untrusted, "Certificate not trusted by this computer: a private CA, or a TLS-inspecting proxy answered instead, and then these grades describe the proxy."),
        (down, "Endpoint could not be graded: unreachable from here, or no TLS or SSH. Its exposure is unknown until it answers."),
        (classical_key, "Certificate key is classical (not ML-DSA): its signature is quantum-vulnerable, so a large enough quantum computer could "
                        "impersonate the server. Unlike recorded traffic, this risk only starts once such a computer exists."),
    ]
    actions = [
        (weak, "Switch off RC4, 3DES and Diffie-Hellman under 2048 bits in the server's cipher list; keep ECDHE with AES-GCM or ChaCha20-Poly1305."),
        (expired + soon, "Renew the certificate before it expires, and automate renewal (ACME)."),
        (tls_c, "Enable TLS 1.3 with hybrid X25519MLKEM768 key exchange alongside the current groups (OpenSSL 3.5 or later, or a TLS front end that has it). "
                "Clients without it keep working on classical key exchange."),
        (ssh_c, "Add mlkem768x25519-sha256 (OpenSSH 9.9 or later) or sntrup761x25519-sha512 (OpenSSH 9.0 or later) to KexAlgorithms."),
        (legacy, "Switch off TLS 1.0 and 1.1: set the minimum version to TLS 1.2."),
        (untrusted, "Check again from a network without TLS inspection, or confirm the private CA is intended."),
        (down, "Check the host name, port and firewall, then check again."),
        (hybrid, "Once your clients all offer post-quantum key exchange, stop accepting classical groups to reach grade A. Check client support "
                 "first: clients without it would be locked out."),
        (classical_key, "Plan ML-DSA certificates for when your CA and clients support them. Key exchange comes first: recorded traffic is the risk that starts today."),
    ]
    out = {"risks": [{"targets": names(rows), "text": t} for rows, t in risks if rows],
           "actions": [{"targets": names(rows), "text": t} for rows, t in actions if rows]}
    if results and not out["actions"]:
        out["actions"].append({"targets": [], "text": "Nothing to change now. Check again after configuration changes and certificate renewals."})
    return out


def report_html(results, title="Post-quantum readiness"):
    s, e = summary(results), html.escape
    tone = {"A": "ok", "B": "warn", "C": "bad", "F": "mute"}
    rows = "".join(
        f"<tr><td class=mono>{e(r['target'])}</td><td><span class='pill {tone[r['grade']]}'>{r['grade']}</span></td><td>{e(r['negotiated'] or '')}</td>"
        f"<td>{e(', '.join(r['accepts']) or (r['error'] or ''))}"
        f"{'<br><small class=warn>also accepts ' + e(' and '.join(r['legacy'])) + ': switch it off</small>' if r.get('legacy') else ''}</td>"
        f"<td>{e((r['certificate'] or {}).get('key', ''))}<br><small>{e((r['certificate'] or {}).get('issuer', ''))}</small>"
        f"{'<br><small class=warn>not trusted here: a private CA, or a TLS-inspecting proxy in the path (then this row describes the proxy)</small>' if r.get('trusted') is False else ''}</td>"
        f"<td class=mono>{e((r['certificate'] or {}).get('expires', ''))}</td></tr>"
        for r in sorted(results, key=lambda r: (r["grade"], r["target"])))
    legend = "".join(f"<li><span class='pill {tone[g]}'>{g}</span> {e(t)} <small>· {s['grades'][g]}</small></li>" for g, t in GRADES.items())
    tiles = "".join(f"<div class=tile><span>{label}</span><b>{value}</b></div>" for label, value in (
        ("post-quantum key exchange", f"{s['pq_key_exchange']}/{s['endpoints']}"), ("ML-DSA certificates", s["pq_certificates"]),
        ("meet CNSA 2.0", s["cnsa2"]), ("expire within 30 days", s["expiring_30d"])))
    body = (f"<div class=tiles>{tiles}</div><section class=panel><h2>What the grades mean</h2><ul>{legend}</ul></section>"
            "<section class=panel><h2>Endpoints</h2><div class=scroll tabindex=0 role=region aria-label='Endpoints'><table><thead><tr><th>Endpoint</th><th>Grade</th><th>Negotiated</th>"
            f"<th>Accepted key exchanges</th><th>Certificate key and issuer</th><th>Expires</th></tr></thead><tbody>{rows}</tbody></table></div></section>")
    return page(title, "Readiness assessment", f"{s['endpoints']} endpoints scanned for post-quantum key exchange and certificates.", body)


def _join(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def load_targets(items):
    """Targets from the command line and from .txt or .lst files, all checked before any is scanned."""
    targets, bad = [], []
    for item in items:
        lines = [(f"{item}:{n}", l.split("#")[0].strip()) for n, l in enumerate(read_text(item).splitlines(), 1)] \
            if item.endswith((".txt", ".lst")) else [(None, item)]
        for where, t in lines:
            if not t:
                continue
            try:
                endpoint(t)
                targets.append(t)
            except ValueError:
                bad.append(f"{where}: {t!r}" if where else repr(t))
    if bad:
        raise ValueError("not a host, host:port or ssh://host (ports run from 0 to 65535): " + ", ".join(bad[:10]) + (f" and {len(bad) - 10} more" if len(bad) > 10 else ""))
    return targets


def to_json(results):
    return json.dumps({"summary": summary(results), "endpoints": results}, indent=1)


def page(title, kicker, sub, body):
    return _page(title, kicker, title, sub, body, f"Acxelin Readiness {__version__}")
