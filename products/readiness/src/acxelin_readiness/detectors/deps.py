import json
import re
import tomllib

from ..model import Library
from . import iter_files, rel, read
from .lexer import LANGS

MANIFESTS = {"pyproject.toml", "package.json", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "cargo.toml", "packages.config"}


def L(imports=None, implies=(), pq=False, note=""):
    """A known crypto library: its import marker (the package name unless given), algorithms it implies, PQ support, a note."""
    return imports, implies, pq, note


KNOWN = {
    "pypi": {
        "cryptography": L(pq=True), "pycryptodome": L("Crypto"), "pycryptodomex": L("Cryptodome"),
        "pycrypto": L("Crypto", note="Unmaintained since 2013 with known CVEs; replace with pycryptodome or cryptography"), "pyjwt": L("jwt"),
        "python-jose": L("jose"), "ecdsa": L(implies=("ECDSA",)), "rsa": L(implies=("RSA",)), "pynacl": L("nacl", implies=("Ed25519", "X25519")),
        "paramiko": L(), "pyopenssl": L("OpenSSL"), "liboqs-python": L("oqs", pq=True), "bcrypt": L(implies=("bcrypt",)),
        "argon2-cffi": L("argon2", implies=("Argon2",)), "m2crypto": L("M2Crypto"), "tink": L(),
        "kyber-py": L("kyber", implies=("ML-KEM",), pq=True, note="Educational implementation, not constant-time"),
        "dilithium-py": L("dilithium", implies=("ML-DSA",), pq=True, note="Educational implementation, not constant-time"),
    },
    "npm": {
        "node-forge": L(), "jsonwebtoken": L(), "jose": L(), "node-rsa": L(implies=("RSA",)), "elliptic": L(implies=("ECC",)),
        "tweetnacl": L(implies=("Ed25519", "X25519")), "crypto-js": L(note="Discontinued; migrate to WebCrypto or node:crypto"),
        "bcrypt": L(implies=("bcrypt",)), "bcryptjs": L(implies=("bcrypt",)), "@noble/curves": L(implies=("ECC",)), "@noble/post-quantum": L(pq=True),
        "openpgp": L(), "jsrsasign": L(implies=("RSA",)), "sshpk": L(),
    },
    "maven": {
        "org.bouncycastle": L(pq=True), "com.nimbusds:nimbus-jose-jwt": L("com.nimbusds.jose"), "io.jsonwebtoken": L(), "com.google.crypto.tink": L(),
        "org.openquantumsafe": L(pq=True),
    },
    "go": {
        "golang.org/x/crypto": L(), "github.com/cloudflare/circl": L(pq=True), "github.com/golang-jwt/jwt": L(),
        "filippo.io/mlkem768": L(implies=("ML-KEM-768",), pq=True), "github.com/open-quantum-safe/liboqs-go": L(pq=True),
    },
    "cargo": {
        "ring": L(), "rsa": L(implies=("RSA",)), "openssl": L(), "rustls": L(pq=True), "ed25519-dalek": L(implies=("Ed25519",)),
        "x25519-dalek": L(implies=("X25519",)), "aes-gcm": L(implies=("AES",)), "sha1": L(implies=("SHA-1",)),
        "md-5": L("md5", implies=("MD5",)), "md5": L(implies=("MD5",)), "ml-kem": L(implies=("ML-KEM",), pq=True),
        "ml-dsa": L(implies=("ML-DSA",), pq=True), "pqcrypto": L(pq=True), "oqs": L(pq=True),
    },
    "nuget": {
        "bouncycastle.cryptography": L("Org.BouncyCastle", pq=True), "portable.bouncycastle": L("Org.BouncyCastle"),
        "system.identitymodel.tokens.jwt": L("System.IdentityModel.Tokens.Jwt"), "nsec.cryptography": L("NSec.Cryptography"),
    },
}


def _match(eco, name):
    table = KNOWN[eco]
    n = name.lower() if eco in ("pypi", "npm", "nuget") else name
    if n in table:
        return n, table[n]
    for k, v in table.items():
        if eco in ("maven", "go") and n.startswith(k):
            return k, v
    return None, None


def _add(out, eco, name, version, manifest, line):
    key, info = _match(eco, name)
    if key and not any(l.name == key and l.manifest == manifest for l in out):
        imports, implies, pq, note = info
        out.append(Library(name=key, ecosystem=eco, manifest=manifest, line=line, version=version, imports=(imports or (key.replace("-", "_") if eco == "cargo" else key),), implies=implies, pq=pq, note=note))


def _lineno(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def parse_manifest(p, path, text, out):
    name = p.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        for i, l in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[.*?\])?\s*([<>=!~].*)?$", l.split("#")[0])
            if m:
                _add(out, "pypi", m.group(1), (m.group(2) or "").strip(), path, i)
    elif name == "pyproject.toml":
        try:
            d = tomllib.loads(text)
        except Exception:
            return
        table = lambda v, k: v.get(k) if isinstance(v, dict) else None
        listed, poetry = table(table(d, "project"), "dependencies"), table(table(table(d, "tool"), "poetry"), "dependencies")
        deps = [x for x in listed if isinstance(x, str)] if isinstance(listed, list) else []
        deps += list(poetry) if isinstance(poetry, dict) else []
        for dep in deps:
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(.*)$", dep)
            if m:
                _add(out, "pypi", m.group(1), m.group(2).strip(), path, _lineno(text, m.group(1)))
    elif name == "package.json":
        try:
            d = json.loads(text)
        except Exception:
            return
        for sect in ("dependencies", "devDependencies", "peerDependencies"):
            listed = d.get(sect) if isinstance(d, dict) else None
            for k, v in listed.items() if isinstance(listed, dict) else ():
                _add(out, "npm", k, str(v), path, _lineno(text, f'"{k}"'))
    elif name == "pom.xml":
        for m in re.finditer(r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?", text):
            _add(out, "maven", f"{m.group(1)}:{m.group(2)}", m.group(3) or "", path, text.count("\n", 0, m.start()) + 1)
    elif name in ("build.gradle", "build.gradle.kts"):
        for m in re.finditer(r"""['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]""", text):
            _add(out, "maven", f"{m.group(1)}:{m.group(2)}", m.group(3), path, text.count("\n", 0, m.start()) + 1)
    elif name == "go.mod":
        for i, l in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", l)
            if m:
                _add(out, "go", m.group(1), m.group(2), path, i)
    elif name == "cargo.toml":
        try:
            d = tomllib.loads(text)
        except Exception:
            return
        listed = d.get("dependencies")
        for k, v in listed.items() if isinstance(listed, dict) else ():
            if isinstance(v, (str, dict)):
                _add(out, "cargo", k, v if isinstance(v, str) else str(v.get("version", "")), path, _lineno(text, k))
    elif p.suffix.lower() == ".csproj" or name == "packages.config":
        for m in re.finditer(r'<(?:PackageReference|package)\s+(?:Include|id)="([^"]+)"(?:\s+[Vv]ersion="([^"]*)")?', text):
            _add(out, "nuget", m.group(1), m.group(2) or "", path, text.count("\n", 0, m.start()) + 1)


def used_by(lib, files):
    pats = []
    for mod in lib.imports:
        e = re.escape(mod)
        if lib.ecosystem == "pypi":
            pats.append(rf"^\s*(?:import|from)\s+{e}\b")
        elif lib.ecosystem == "npm":
            pats.append(rf"""(?:require\(\s*['"]{e}(?:/[^'"]*)?['"]|from\s+['"]{e}(?:/[^'"]*)?['"])""")
        elif lib.ecosystem == "go":
            pats.append(rf'"{e}[^"]*"')
        elif lib.ecosystem == "cargo":
            pats.append(rf"\b(?:use|extern crate)\s+{e}\b|\b{e}::")
        else:
            pats.append(rf"^\s*(?:import|using)\s+{e}")
    rx = re.compile("|".join(pats), re.M)
    return [path for path, text in files if rx.search(text)]


def scan(root, scope=False):
    libs, code = [], []
    for p in iter_files(root, scope):
        n = p.name.lower()
        if n.startswith("requirements") or n in MANIFESTS or p.suffix.lower() == ".csproj":
            t = read(p)
            if t:
                parse_manifest(p, rel(root, p), t, libs)
        elif p.suffix.lower() in LANGS:
            t = read(p)
            if t:
                code.append((rel(root, p), t))
    for lib in libs:
        lib.used_in = used_by(lib, code)
    return libs
