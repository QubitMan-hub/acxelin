"""Evidence bundles: a zip whose manifest names every file with its SHA-256, optionally signed with an ML-DSA key whose
certificate chains to the customer's CA. `verify` reads the zip in memory and never unpacks it; a private key never goes in."""
import base64
import datetime as dt
import hashlib
import io
import json
import platform
import re
import sys
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .files import write as _write
from .pki import ALGORITHMS, CAError, signed_by

FORMAT = "acxelin-evidence/1"
LIMIT = 64 * 1024 * 1024  # bytes a bundle may hold, packed or unpacked
ENTRIES = 1000
RESERVED = {"manifest.json", "manifest.sig", "signer.pem"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _bytes(value):
    if isinstance(value, bytes):
        return value
    return (value if isinstance(value, str) else json.dumps(value, indent=1, sort_keys=True, default=str) + "\n").encode()


def _safe(name):
    return isinstance(name, str) and bool(NAME.fullmatch(name)) and ".." not in name


class Signer:
    """An ML-DSA key and its certificate chain (leaf first)."""

    def __init__(self, key, chain_pem):
        self.key, self.chain_pem = key, chain_pem

    @classmethod
    def load(cls, chain_path, key_path, passphrase=None):
        key = serialization.load_pem_private_key(Path(key_path).read_bytes(), passphrase)
        if not isinstance(key, tuple(ALGORITHMS.values())):
            raise ValueError(f"{key_path}: evidence is signed with ML-DSA; this is a {type(key).__name__.replace('PrivateKey', '').lstrip('_')} key")
        chain_pem = Path(chain_path).read_bytes()
        leaf = x509.load_pem_x509_certificates(chain_pem)[0]
        raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
        if leaf.public_key().public_bytes(*raw) != key.public_key().public_bytes(*raw):
            raise ValueError(f"{chain_path} is not the certificate of the key in {key_path}")
        return cls(key, chain_pem)

    def sign(self, data):
        return self.key.sign(data)


def create(product, parts, signer=None, created=None):
    """The bundle as zip bytes: each part (bytes, text, or anything JSON can hold), a manifest of their SHA-256, and the signature."""
    files = {}
    for name, value in parts.items():
        if not _safe(name) or name in RESERVED:
            raise ValueError(f"{name!r} cannot be a file name in an evidence bundle: letters, digits, dot, dash and underscore only")
        data = _bytes(value)
        if b"PRIVATE KEY-----" in data:
            raise ValueError(f"{name} holds a private key; an evidence bundle never does")
        files[name] = data
    created = created or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    manifest = json.dumps({"format": FORMAT, "product": product, "created": created.isoformat(),
                           "files": {n: sha256(b) for n, b in sorted(files.items())}}, indent=1, sort_keys=True).encode() + b"\n"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", manifest)
        for name, data in sorted(files.items()):
            z.writestr(name, data)
        if signer:
            z.writestr("manifest.sig", signer.sign(manifest))
            z.writestr("signer.pem", signer.chain_pem)
    return out.getvalue()


def write(path, data):
    _write(Path(path), data)


def _chains(chain, cas):
    """True if the leaf, through the intermediates it came with, was issued by one of `cas`."""
    der = lambda c: c.public_bytes(serialization.Encoding.DER)
    roots, pool, cert = {der(c) for c in cas}, chain[1:] + cas, chain[0]
    for _ in range(len(pool) + 1):
        issuer = next((c for c in pool if c.subject == cert.issuer and _signed(c, cert)), None)
        if issuer is None:
            return False
        if der(issuer) in roots:
            return True
        cert = issuer
    return False


def _signed(issuer, cert):
    try:
        return signed_by(issuer, cert.tbs_certificate_bytes, cert.signature)
    except (CAError, ValueError):
        return False


def verify(data, ca_pem=None):
    """What a bundle proves: {ok, product, created, files, signed_by, problems, notes}. With `ca_pem` it must be signed by a
    certificate that chains to that CA."""
    r = {"ok": False, "product": None, "created": None, "files": {}, "signed_by": None, "problems": [], "notes": []}
    problem = r["problems"].append
    if len(data) > LIMIT:
        problem(f"too large: over {LIMIT} bytes")
        return r
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        problem("not an evidence bundle: not a zip file")
        return r
    with z:
        infos = z.infolist()
        if len(infos) > ENTRIES or sum(i.file_size for i in infos) > LIMIT:
            problem(f"too large: over {ENTRIES} files or {LIMIT} bytes unpacked")
            return r
        names = [i.filename for i in infos]
        for n in sorted(set(names)):
            if not _safe(n):
                problem(f"unsafe file name {n!r}: an evidence bundle holds plain names only")
            elif names.count(n) > 1:
                problem(f"{n} appears more than once")
        if "manifest.json" not in names:
            problem("no manifest.json: not an evidence bundle")
            return r
        manifest_bytes = z.read("manifest.json")
        try:
            manifest = json.loads(manifest_bytes)
            assert manifest.get("format") == FORMAT and isinstance(manifest.get("files"), dict)
        except (ValueError, AssertionError, AttributeError):
            problem(f"manifest.json is not an {FORMAT} manifest")
            return r
        r["product"], r["created"] = manifest.get("product"), manifest.get("created")
        for name, digest in sorted(manifest["files"].items()):
            if name not in names:
                problem(f"{name} is in the manifest but missing")
            elif sha256(z.read(name)) != digest:
                problem(f"{name} was changed after the bundle was made")
            else:
                r["files"][name] = digest
        for name in sorted(set(names) - set(manifest["files"]) - RESERVED):
            problem(f"{name} is not in the manifest: it was added after the bundle was made")
        sig, pem = ("manifest.sig" in names), ("signer.pem" in names)
        if sig != pem:
            problem("the signature is incomplete: manifest.sig and signer.pem go together")
        elif sig:
            _signature(r, z.read("manifest.sig"), z.read("signer.pem"), manifest_bytes, ca_pem)
        elif ca_pem:
            problem("not signed, but a CA was given to check it against")
        else:
            r["notes"].append("not signed: anyone could have made this bundle")
    r["ok"] = not r["problems"]
    return r


def _signature(r, signature, chain_pem, manifest_bytes, ca_pem):
    problem = r["problems"].append
    try:
        chain = x509.load_pem_x509_certificates(chain_pem)
        leaf = chain[0]
        leaf.public_key().verify(signature, manifest_bytes)
    except InvalidSignature:
        problem("the signature does not match the manifest: the manifest was changed after signing")
        return
    except (ValueError, TypeError, IndexError):
        problem("signer.pem or manifest.sig cannot be read")
        return
    r["signed_by"] = leaf.subject.rfc4514_string()
    try:
        created = dt.datetime.fromisoformat(r["created"])
        if not leaf.not_valid_before_utc <= created <= leaf.not_valid_after_utc:
            problem(f"the signer's certificate was not valid when the bundle says it was made ({r['created']})")
    except (TypeError, ValueError):
        problem("the manifest's creation time cannot be read")
    if ca_pem is None:
        r["notes"].append(f"signed by {r['signed_by']}, but not checked against a CA: give the CA certificate to check who signed it")
        return
    try:
        cas = x509.load_pem_x509_certificates(ca_pem)
    except ValueError:
        problem("the CA certificate cannot be read")
        return
    if not _chains(chain, cas):
        problem(f"the signer's certificate ({r['signed_by']}) does not chain to the CA given")
    else:
        r["notes"].append("the signer's certificate chains to the CA given; whether it has since been revoked is not checked here")


def _b64sha256(data):
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def installed(dist):
    """Whether an installed distribution's files still match the hashes its wheel recorded (`dist`: a name or a Distribution)."""
    from importlib.metadata import distribution
    dist = distribution(dist) if isinstance(dist, str) else dist
    import csv
    modified, missing, checked = [], [], 0
    record = dist.read_text("RECORD") or ""
    for row in csv.reader(record.splitlines()):  # RECORD itself, not dist.files: that leaves out files deleted since install
        if len(row) < 2 or not row[1].startswith("sha256="):
            continue
        checked += 1
        path = Path(dist.locate_file(row[0]))
        if not path.is_file():
            missing.append(row[0])
        elif _b64sha256(path.read_bytes()) != row[1][7:]:
            modified.append(row[0])
    return {"name": dist.metadata["Name"], "version": dist.version, "files": checked, "modified": sorted(modified),
            "missing": sorted(missing), "record_sha256": sha256(record.encode())}


def environment():
    from . import openssl
    reason = openssl.available()
    return {"python": sys.version.split()[0], "implementation": platform.python_implementation(), "platform": platform.platform(),
            "machine": platform.machine(), "openssl": reason or openssl.lib().version}


def describe(r):
    """`verify`'s result as text for people."""
    out = [f"{'OK' if r['ok'] else 'FAILED'}: {r['product'] or 'unknown product'} evidence made {r['created'] or 'at an unknown time'}"]
    out += [f"  file  {n}  sha256 {h[:16]}…" for n, h in r["files"].items()]
    out.append(f"  signed by  {r['signed_by']}" if r["signed_by"] else "  not signed")
    out += [f"  note  {n}" for n in r["notes"]] + [f"  PROBLEM  {p}" for p in r["problems"]]
    return "\n".join(out)


def packages(*names):
    """installed() for each distribution, or that it is not installed."""
    from importlib.metadata import PackageNotFoundError
    out = []
    for n in names:
        try:
            out.append(installed(n))
        except PackageNotFoundError:
            out.append({"name": n, "installed": False})
    return out


def certificates(path, **where):
    """The public facts of each certificate in a PEM file: subject, issuer, serial, key algorithm, validity and fingerprint."""
    from cryptography.hazmat.primitives import hashes
    from .pki import algorithm_of
    rows = []
    for c in x509.load_pem_x509_certificates(Path(path).read_bytes()):
        key = c.public_key()
        rows.append(where | {"file": str(path), "subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                             "serial": format(c.serial_number, "x"),
                             "algorithm": algorithm_of(key) or type(key).__name__.lstrip("_").replace("PublicKey", ""),
                             "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
                             "sha256": c.fingerprint(hashes.SHA256()).hex()})
    return rows


def fetch_status(url, hint, timeout=5.0):
    """What a running service's /status says, or ValueError ending with `hint`."""
    import urllib.request
    from .http import explain
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"--status must start with http:// or https://, not {url!r}")
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/status", timeout=timeout) as r:
            return json.loads(r.read())
    except (OSError, ValueError) as e:
        raise ValueError(f"cannot read {url}/status: {explain(e) if isinstance(e, OSError) else e}; {hint}") from None


def add_commands(sub, product, collect, extra):
    """`evidence create` (its own options added by `extra(parser)`, then signing and --out) and `evidence verify`."""
    e = sub.add_parser("evidence", help="a signed bundle of what this deployment is and does, for an audit or a pilot; and its check")
    t = e.add_subparsers(dest="evidence_cmd", required=True)
    p = t.add_parser("create", help="build, configuration, doctor, certificates and live state in one signed zip")
    p.set_defaults(func=lambda a: _create(a, product, collect))
    extra(p)
    p.add_argument("--status", metavar="URL", help="the service's --metrics address, to record what it reports")
    p.add_argument("--sign-cert", help="certificate chain of an ML-DSA key from your CA, to sign the bundle")
    p.add_argument("--sign-key", help="that key")
    p.add_argument("--sign-key-passphrase-env", help="the signing key's passphrase is in this environment variable")
    p.add_argument("--out", help=f"the zip to write (default: {product}-evidence-<UTC time>.zip)")
    p = t.add_parser("verify", help="check a bundle: every file against its manifest, and the signature against your CA")
    p.set_defaults(func=_verify)
    p.add_argument("bundle")
    p.add_argument("--ca", help="the CA certificate the signer's certificate must chain to")
    p.add_argument("--json", action="store_true")


def _signer(a):
    from .config import env_passphrase
    if not (a.sign_cert or a.sign_key):
        return None
    if not (a.sign_cert and a.sign_key):
        raise ValueError("--sign-cert and --sign-key go together")
    return Signer.load(a.sign_cert, a.sign_key, env_passphrase(a.sign_key_passphrase_env))


def _create(a, product, collect):
    sign = _signer(a)  # before any probing: a wrong key or passphrase is said at once
    data = create(product, collect(a), sign)
    out = Path(a.out) if a.out else Path(f"{product}-evidence-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}.zip")
    write(out, data)
    who = x509.load_pem_x509_certificates(sign.chain_pem)[0].subject.rfc4514_string() if sign else None
    print(f"wrote {out}, {'signed by ' + who if who else 'not signed'}; check it with `{product} evidence verify {out}{' --ca CA.crt' if who else ''}`")
    return 0


def _verify(a):
    r = verify(Path(a.bundle).read_bytes(), Path(a.ca).read_bytes() if a.ca else None)
    print(json.dumps(r, indent=1) if a.json else describe(r))
    return 0 if r["ok"] else 2
