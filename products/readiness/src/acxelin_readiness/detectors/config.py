import re

from ..catalog import lookup, pq_from_text, curve, CATALOG
from ..model import Detection
from . import iter_files, rel, is_test, read, DENY
from .lexer import split_hash
from .suites import cipher_string, ssh_token, sig_scheme, kms_spec

EXT = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".properties", ".toml", ".env", ".xml", ".json", ".tf", ".hcl"}
NAMES = {"sshd_config", "ssh_config", "openssl.cnf", "nginx.conf", "httpd.conf", "haproxy.cfg", "java.security", "dockerfile", ".env"}

TLSV = re.compile(r"\b(SSLv[23]|TLSv1(?:\.[0-3])?|TLS1_[0-3]_VERSION|TLS1_VERSION|TLSv1_[0-3])\b", re.I)
PAIRS = [
    (re.compile(r"""^\s*["']?(?:min[_-]?tls[_-]?version|minimum[_-]?tls[_-]?version|minTlsVersion|MinimumTlsVersion|min_tls)["']?\s*[=:]\s*["']?(?:TLS[_v]?)?\s*(1)[._](\d)""", re.I), "tlsmin"),
    (re.compile(r"^\s*(KexAlgorithms|HostKeyAlgorithms|PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|HostbasedAcceptedAlgorithms|CASignatureAlgorithms|Ciphers|MACs)\s+(.+)"), "ssh"),
    (re.compile(r"^\s*ssl_protocols\s+([^;#]+)", re.I), "protocols"),
    (re.compile(r"^\s*SSLProtocol\s+(.+)", re.I), "apache_protocols"),
    (re.compile(r"^\s*(?:ssl_ciphers|SSLCipherSuite|ssl-default-bind-ciphers|ssl-default-server-ciphers|ssl-default-bind-ciphersuites|CipherString|Ciphersuites|ssl_cipher|cipher[_-]?suites?|ciphers)\s*[=:\s]\s*(.+)", re.I), "ciphers"),
    (re.compile(r"^\s*(?:ssl_ecdh_curve|Groups|Curves|ssl-default-bind-curves|ssl_ecdh_curves|curves|groups|named[_-]?groups)\s*[=:\s]\s*(.+)", re.I), "groups"),
    (re.compile(r"^\s*[\w.\-\"']*(?:min[_-]?(?:tls|ssl|proto(?:col)?)?[_-]?version|MinProtocol|MaxProtocol|ssl-min-ver|ssl-max-ver|enabled[_-]?protocols|sslEnabledProtocols|sslProtocol|tls[_-]?versions?|protocols?)[\w\"']*\s*[=:]\s*(.+)", re.I), "protocols"),
    (re.compile(r"\bssl-(?:min|max)-ver\s+(\S+)", re.I), "protocols"),
    (re.compile(r"""^\s*["']?[\w./-]*ssl-ciphers["']?\s*:\s*(.+)""", re.I), "ciphers"),
    (re.compile(r"""^\s*["']?[\w./-]*ssl-protocols["']?\s*:\s*(.+)""", re.I), "protocols"),
    (re.compile(r"""^\s*["']?(?:ssl_policy|policy_name|SslPolicy|sslPolicy)["']?\s*[=:]\s*["']?((?:ELBSecurityPolicy|AppGwSslPolicy)[\w-]*)""", re.I), "lbpolicy"),
    (re.compile(r"""^\s*["']?(?:customer_master_key_spec|key_spec|KeySpec|CustomerMasterKeySpec|key_type|kty|KeyType)["']?\s*[=:]\s*["']?([\w\-]+)""", re.I), "kms"),
    (re.compile(r"""^\s*["']?(?:ecdsa_curve|ec_curve|curve|named_curve|crv)["']?\s*[=:]\s*["']?([\w-]+)""", re.I), "curve"),
    (re.compile(r"^\s*[\w.\-\"']*(?:algorithm|alg|signing[_-]?alg\w*|key[_-]?algorithm|keyAlgorithm|hash[_-]?algorithm|digest[_-]?algorithm|kex)[\w\"']*\s*[=:]\s*[\"']?([\w\-/]+)", re.I), "algo"),
    (re.compile(r"^\s*(?:[\w.\-\"']*(?:key[_-]?size|keysize|key[_-]?length|rsa[_-]?bits|modulus[_-]?length)[\w\"']*|[\"']?size[\"']?)\s*[=:]\s*[\"']?(\d{3,5})\b", re.I), "size"),
]


def is_config(p):
    return p.suffix.lower() in EXT or p.name.lower() in NAMES or p.name.lower().endswith((".conf", "_config"))


def _vals(s):
    return [t for t in re.split(r"[\s,;\"'\[\]]+", s.split("#")[0]) if t]


def lb_policy(name):
    """TLS versions (and hybrid PQ key exchange) a cloud load balancer's predefined policy allows, from its documented name."""
    n = name.upper()
    if n.startswith("APPGWSSLPOLICY"):
        date = re.search(r"(\d{8})(S?)", n)
        low = "1.0" if not date or date.group(1) < "20170401" else "1.2" if date.group(2) or date.group(1) >= "20220101" else "1.1"
        high = "1.3" if date and date.group(1) >= "20220101" else "1.2"
    else:
        v = re.search(r"TLS13-1-(\d)|TLS-1-(\d)|FS-1-(\d)", n)
        low = f"1.{next(g for g in v.groups() if g)}" if v else "1.0"
        high = "1.3" if "TLS13" in n else "1.2"
    out = [(lookup(f"TLSv{v}"), {"policy": name}) for v in ("1.0", "1.1", "1.2", "1.3") if low <= v <= high]
    return out + ([("X25519MLKEM768", {"policy": name})] if "PQ" in n else [])


def parse_line(kind, m):
    if kind == "protocols":
        return [(lookup(t), {}) for t in TLSV.findall(m.group(1))]
    if kind == "apache_protocols":
        return [(lookup(t.lstrip("+")), {}) for t in _vals(m.group(1)) if not t.startswith("-") and TLSV.match(t.lstrip("+"))]
    if kind == "ciphers":
        return cipher_string(m.group(1).split("#")[0].strip().rstrip(";"))
    if kind == "groups":
        out = []
        for g in re.split(r"[:,\s;\"']+", m.group(1).split("#")[0]):
            if not g or g.startswith(("!", "-")):
                continue
            cv = curve(g)
            a = "ECDH" if cv else lookup(g) or pq_from_text(g)
            if a:
                out.append((a, {"curve": cv} if cv else {}))
        return out
    if kind == "ssh":
        out = []
        for t in re.split(r",", m.group(2).split("#")[0].strip()):
            out += ssh_token(t)
        return out
    if kind == "tlsmin":
        return [(lookup(f"TLSv1.{m.group(2)}"), {"minimum": True})]
    if kind == "lbpolicy":
        return lb_policy(m.group(1))
    if kind == "kms":
        v = m.group(1)
        return kms_spec(v) or ([(lookup(v), {})] if v.upper() in ("RSA", "EC") and lookup(v) else [])
    if kind == "algo":
        v = m.group(1)
        r = sig_scheme(v) or kms_spec(v)
        return r if r else ([(lookup(v), {})] if lookup(v) else [])
    return []


SNIFF = re.compile(r"(?m)^[ \t]*(ssl_protocols|ssl_ciphers|ssl_ecdh_curve|SSLProtocol|SSLCipherSuite|KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|CipherString|MinProtocol)\b")


def sniffed(p, text):
    """A file with no extension, such as `conf`, counts as config when at least two different TLS/SSH directives start its lines."""
    return len({m.group(1) for m in SNIFF.finditer(text[:50000])}) >= 2


KEY_OPEN = re.compile(r"""^(\s*)["']?([\w.\-]+)["']?\s*[:=]\s*(\[)?\s*$""")
YAML_ITEM = re.compile(r"""^(\s*)-\s+["']?([^"'#\n]+?)["']?\s*(?:#.*)?$""")
JSON_ITEM = re.compile(r"""^\s*["']([^"']+)["']\s*,?\s*$""")


def list_items(stream):
    """Entries of multi-line YAML or JSON lists, as {line: "key: entry"}, so each entry is read as if written on its key's line."""
    out, lines = {}, stream.splitlines()
    for i, line in enumerate(lines):
        m = KEY_OPEN.match(line)
        if not m:
            continue
        indent, key, bracket = len(m.group(1)), m.group(2), m.group(3)
        for j in range(i + 1, min(len(lines), i + 200)):
            t = lines[j]
            if not t.strip() or t.strip().startswith("#"):
                continue
            if bracket:
                if t.strip().startswith("]"):
                    break
                item = JSON_ITEM.match(t)
            else:
                item = YAML_ITEM.match(t)
                if item and len(item.group(1)) < indent:
                    item = None
            if not item:
                break
            out[j + 1] = f"{key}: {item.group(item.lastindex).strip()}"
    return out


def scan(root, scope=False):
    sink, n = [], 0
    for p in iter_files(root, scope):
        if p.suffix and not is_config(p):
            continue
        text = read(p)
        if text is None or not is_config(p) and not sniffed(p, text):
            continue
        n += 1
        path = rel(root, p)
        base = {"test"} if is_test(path) else set()
        code, comments, _ = split_hash(text) if p.suffix.lower() not in (".json", ".xml") else (text, "", [])
        for stream, ctx in ((code, base), (comments, base | {"comment"})):
            items = list_items(stream)
            for i, line in enumerate(stream.splitlines(), 1):
                if not line.strip():
                    continue
                probe = items.get(i) or line.strip().lstrip("#; ").strip()
                if DENY.search(probe.split("=")[0].split(":")[0]):
                    continue
                for rx, kind in PAIRS:
                    m = rx.search(probe)
                    if not m:
                        continue
                    if kind == "curve":  # names the curve of the ECDSA or EC key just above it
                        cv = curve(m.group(1)) or {"P256": "P-256", "P384": "P-384", "P521": "P-521"}.get(m.group(1).upper())
                        near = next((s for s in reversed(sink) if s.file == path and 0 <= i - s.line <= 6 and s.algo in ("ECDSA", "ECC")), None)
                        if cv and near:
                            near.params.setdefault("curve", cv)
                        break
                    if kind == "size":
                        for s in reversed(sink):  # this file's detections are the newest: stop at the first from another file or out of reach
                            if s.file != path or i - s.line > 6:
                                break
                            if s.algo in ("RSA", "DSA", "DH", "ECDSA", "ECC") and 0 <= i - s.line and not s.params.get("key_size"):
                                if s.algo in ("ECDSA", "ECC"):
                                    cv = {"256": "P-256", "384": "P-384", "521": "P-521"}.get(m.group(1))
                                    if cv:
                                        s.params.setdefault("curve", cv)
                                else:
                                    s.params["key_size"] = int(m.group(1))
                                break
                        break
                    for a, params in parse_line(kind, m):
                        if a and a in CATALOG:
                            sink.append(Detection(algo=a, file=path, line=i, evidence="config", detector="config", snippet=probe[:160], lang="config",
                                                 params={k: v for k, v in params.items() if v}, context=set(ctx)))
                    break
    return sink, n
