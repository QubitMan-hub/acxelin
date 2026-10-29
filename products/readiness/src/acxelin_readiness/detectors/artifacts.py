import base64
import re
import hashlib
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, x25519, x448, dsa, dh

from ..catalog import curve, CATALOG
from ..model import Detection, Artifact
from . import iter_files, rel, is_test
from . import keystores

EXT = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".csr", ".cert", ".p8", ".pk8"}
SSH_NAMES = re.compile(r"^(id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|ssh_host_\w+_key(\.pub)?|authorized_keys|known_hosts)$")
K8S_B64 = re.compile(rb"""(?m)^\s*["']?(tls\.crt|ca\.crt|tls\.key|[\w.-]*\.(?:pem|crt))["']?\s*:\s*["']?([A-Za-z0-9+/]{80,}={0,2})["']?\s*,?$""")
PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.S)
SSH_LINE = re.compile(rb"^(?:[\w@.,*\[\]:-]+\s+)?((?:ssh|ecdsa|sk)-[\w@.-]+)\s+(AAAA[0-9A-Za-z+/=]+)", re.M)
with warnings.catch_warnings():  # cryptography deprecates the finite-field DH classes; recognising a DH key is still the job
    warnings.simplefilter("ignore")
    KEYS = [(algo, (getattr(mod, cls + "PublicKey"), getattr(mod, cls + "PrivateKey"))) for algo, mod, cls in [
        ("RSA", rsa, "RSA"), ("ECC", ec, "EllipticCurve"), ("DSA", dsa, "DSA"), ("DH", dh, "DH"), ("Ed25519", ed25519, "Ed25519"),
        ("Ed448", ed448, "Ed448"), ("X25519", x25519, "X25519"), ("X448", x448, "X448")]]
CODE_EXT = {".py", ".java", ".go", ".js", ".ts", ".c", ".cpp", ".cs", ".rs", ".rb", ".php", ".kt", ".yaml", ".yml", ".json", ".env", ".txt", ".conf", ".xml"}

OID = {c.oid: a for a, c in CATALOG.items() if c.oid}
SIG_OID = {
    "1.2.840.113549.1.1.4": ("RSA", "MD5"), "1.2.840.113549.1.1.5": ("RSA", "SHA-1"), "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"), "1.2.840.113549.1.1.13": ("RSA", "SHA-512"), "1.2.840.113549.1.1.10": ("RSA", None),
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"), "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256"), "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512"), "1.3.101.112": ("Ed25519", None), "1.3.101.113": ("Ed448", None),
    "1.2.840.10040.4.3": ("DSA", "SHA-1"), "2.16.840.1.101.3.4.3.2": ("DSA", "SHA-256"),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", None), "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", None), "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", None),
    "1.2.840.113549.1.1.14": ("RSA", "SHA-224"), "1.2.840.113549.1.1.2": ("RSA", "MD2"), "1.2.840.10045.4.3.1": ("ECDSA", "SHA-224"),
    **{f"2.16.840.1.101.3.4.3.{n}": ("SLH-DSA", None) for n in range(20, 32)},  # the twelve SLH-DSA parameter sets (FIPS 205)
}


def key_info(k):
    for algo, classes in KEYS:
        if isinstance(k, classes):
            return algo, {"curve": curve(k.curve.name)} if algo == "ECC" else {"key_size": k.key_size} if hasattr(k, "key_size") else {}
    return None, {}


def cert_record(cert, path, line, source="file"):
    try:
        pk_algo, pk_params = key_info(cert.public_key())
    except Exception:
        pk_algo, pk_params = OID.get(cert.public_key_algorithm_oid.dotted_string), {}
    sig_algo, sig_hash = SIG_OID.get(cert.signature_algorithm_oid.dotted_string, (None, None))
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:
        san = []
    details = {
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": format(cert.serial_number, "x"), "sha256": fp, "sig_oid": cert.signature_algorithm_oid.dotted_string,
        "pk_oid": cert.public_key_algorithm_oid.dotted_string, "self_signed": cert.subject == cert.issuer, "san": san[:10], "source": source,
    }
    art = Artifact(kind="certificate", file=path, line=line, algo=pk_algo or "unknown", params=pk_params, details=details)
    sights = []
    if pk_algo:
        sights.append(Detection(algo=pk_algo, file=path, line=line, evidence="artifact", detector="artifacts", snippet=f"certificate public key: {details['subject'][:80]}",
                               lang="x509", params=dict(pk_params, cert=fp[:16], role="subject-public-key")))
    if sig_algo:
        p = {"cert": fp[:16], "role": "certificate-signature"}
        if sig_hash and not details["self_signed"]:  # no client checks a self-signature, so its hash weakens nothing
            p["hash"] = sig_hash
        sights.append(Detection(algo=sig_algo, file=path, line=line, evidence="artifact", detector="artifacts", snippet=f"certificate signature: {details['subject'][:80]}",
                               lang="x509", params=p))
        if sig_hash:
            sights.append(Detection(algo=sig_hash, file=path, line=line, evidence="artifact", detector="artifacts", snippet="certificate signature hash",
                                   lang="x509", params={"cert": fp[:16], "role": "certificate-signature-hash"} | ({"purpose": "self-signature"} if details["self_signed"] else {})))
    return art, sights


def parse_pem(block, label, path, line):
    label = label.decode()
    if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"):
        try:
            a, s = cert_record(x509.load_pem_x509_certificate(block), path, line)
            return [a], s
        except Exception:
            return [], []
    if label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
        try:
            return request_record(x509.load_pem_x509_csr(block), path, line)
        except Exception:
            return [], []
    kind = "private-key" if "PRIVATE" in label else "public-key" if "PUBLIC" in label else None
    if not kind:
        return [], []
    algo, params, encrypted = None, {}, "ENCRYPTED" in label
    try:
        if label == "OPENSSH PRIVATE KEY":
            with warnings.catch_warnings():  # DSA keys are deprecated, and finding them is the point
                warnings.simplefilter("ignore")
                k = serialization.load_ssh_private_key(block, None)
        elif kind == "private-key":
            k = serialization.load_pem_private_key(block, None)
        else:
            k = serialization.load_pem_public_key(block)
        algo, params = key_info(k)
    except TypeError:
        encrypted = True
    except Exception:
        pass
    if not algo:
        algo = {"RSA": "RSA", "EC": "ECC", "DSA": "DSA"}.get(label.split()[0])
    return key_record(kind, algo, params, encrypted, label, path, line, "pem")


def key_record(kind, algo, params, encrypted, label, path, line, lang):
    art = Artifact(kind=kind, file=path, line=line, algo=algo or "unknown", params=params, details={"encrypted": encrypted, "label": label})
    sights = [Detection(algo=algo, file=path, line=line, evidence="artifact", detector="artifacts", snippet=label.lower(), lang=lang,
                        params=dict(params, role=kind))] if algo else []
    return [art], sights


def request_record(csr, path, line):
    """A certificate signing request: the public key it asks to have certified."""
    algo, params = key_info(csr.public_key())
    return key_record("public-key", algo, params, False, "certificate request", path, line, "x509")


def parse_der(data, path):
    """A binary certificate, private key (PKCS#1, PKCS#8, SEC1; encrypted ones counted, unread), public key or certificate request."""
    try:
        art, sights = cert_record(x509.load_der_x509_certificate(data), path, 1)
        return [art], sights
    except Exception:
        pass
    try:
        k = serialization.load_der_private_key(data, None)
        return key_record("private-key", *key_info(k), False, "der private key", path, 1, "der")
    except TypeError:
        return key_record("private-key", None, {}, True, "encrypted der private key", path, 1, "der")
    except Exception:
        pass
    for load, kind in ((serialization.load_der_public_key, "public-key"), (x509.load_der_x509_csr, "request")):
        try:
            k = load(data)
        except Exception:
            continue
        return request_record(k, path, 1) if kind == "request" else key_record(kind, *key_info(k), False, "der public key", path, 1, "der")
    return None


def scan_bytes(data, path, base_ctx):
    arts, sights = [], []
    for m in PEM.finditer(data):
        line = data.count(b"\n", 0, m.start()) + 1
        a, s = parse_pem(m.group(0), m.group(1), path, line)
        arts += a
        sights += s
    for m in SSH_LINE.finditer(data):
        line = data.count(b"\n", 0, m.start()) + 1
        try:
            with warnings.catch_warnings():  # DSA keys are deprecated, and finding them is the point
                warnings.simplefilter("ignore")
                k = serialization.load_ssh_public_key(m.group(1) + b" " + m.group(2))
            algo, params = key_info(k)
        except Exception:
            continue
        if algo:
            arts.append(Artifact(kind="public-key", file=path, line=line, algo=algo, params=params, details={"format": "openssh"}))
            sights.append(Detection(algo=algo, file=path, line=line, evidence="artifact", detector="artifacts", snippet=m.group(1).decode(),
                                   lang="ssh", params=dict(params, role="public-key")))
    for s in sights:
        s.context |= base_ctx
    return arts, sights


def scan(root, scope=False):
    arts, sights, n = [], [], 0
    for p in iter_files(root, scope):
        ext = p.suffix.lower()
        if ext in keystores.EXT:
            try:
                a, s = keystores.read(p.read_bytes(), rel(root, p))
            except OSError:
                continue
            base = {"test"} if is_test(rel(root, p)) else set()
            for x in s:
                x.context |= base
            arts += a
            sights += s
            n += 1
            continue
        if not (ext in EXT or SSH_NAMES.match(p.name) or ext in CODE_EXT):
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        path = rel(root, p)
        base = {"test"} if is_test(path) else set()
        if ext in (".yaml", ".yml", ".json"):
            for m in K8S_B64.finditer(data):
                try:
                    blob = base64.b64decode(m.group(2), validate=True)
                except ValueError:
                    continue
                a, s = scan_bytes(blob, path, base)
                line = data.count(b"\n", 0, m.start()) + 1
                for x in list(a) + list(s):
                    x.line = line
                for x in s:
                    x.context.add("deployed-secret")
                arts += a
                sights += s
        if ext in CODE_EXT and b"-----BEGIN" not in data and b"ssh-" not in data:
            continue
        n += 1
        if ext in (".der", ".cer", ".crt", ".key", ".csr", ".p8", ".pk8") and not data.lstrip().startswith(b"-----"):
            found = parse_der(data, path)
            if found:
                for x in found[1]:
                    x.context |= base
                arts += found[0]
                sights += found[1]
                continue
        a, s = scan_bytes(data, path, base)
        if ext in CODE_EXT:
            for x in s:
                x.context.add("embedded")
        arts += a
        sights += s
    return arts, sights, n
