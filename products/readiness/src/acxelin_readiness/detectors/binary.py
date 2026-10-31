import io
import re
import zipfile

from ..catalog import pq_from_text
from ..model import Detection, Library
from . import iter_files, rel, is_test, SKIP_DIRS, BUILD_DIRS, READ_LIMIT
from .source import classify_literal
from .implementations import SHA1_K4, byte_tables, not_sha1, packed


EXTRA: list[tuple[str | None, dict, list[bytes]]] = [
    ("ChaCha20", {}, [b"expand 32-byte k"]),
    (None, {}, [b"ML-KEM-768", b"MLKEM768"]),
    (None, {}, [b"ML-DSA-65", b"MLDSA65", b"ML-DSA-44", b"ML-DSA-87"]),
]
VERSIONS = [
    (re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)[ \x00]"), "openssl"),
    (re.compile(rb"LibreSSL (\d+\.\d+\.\d+)"), "libressl"),
    (re.compile(rb"mbed TLS (\d+\.\d+\.\d+)"), "mbedtls"),
    (re.compile(rb"wolfSSL (\d+\.\d+\.\d+)"), "wolfssl"),
    (re.compile(rb"\x00go(1\.\d+(?:\.\d+)?)\x00"), "go"),
]
NATIVE_EXT = {".so", ".dll", ".exe", ".dylib", ".a", ".lib", ".o", ".node", ".pyd", ".bin", ".elf"}
MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
ARCHIVES = {".jar", ".war", ".ear", ".aar"}
CRYPTO_REFS = (b"javax/crypto", b"java/security", b"org/bouncycastle", b"javax/net/ssl")
MAX = READ_LIMIT
CLASS_MAX, ARCHIVE_BUDGET, ARCHIVE_ENTRIES = 4 << 20, 512 << 20, 50_000  # a class file over 4 MB is not code; an archive is read up to 512 MB


def _version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def lib_note(name, ver):
    t = _version_tuple(ver)
    if name == "openssl":
        if t < (1, 1, 1):
            return "End of life; no security fixes", False
        if t < (3, 0, 0):
            return "OpenSSL 1.1.1 reached end of life in September 2023", False
        return ("Supports ML-KEM, ML-DSA and SLH-DSA natively", True) if t >= (3, 5, 0) else ("", False)
    if name == "go":
        return ("crypto/tls offers X25519MLKEM768 by default", True) if t >= (1, 24) else ("", False)
    return "", False


def scan_native(data, path, base):
    sights, libs = [], []
    for algo, params, pats in byte_tables() + EXTRA:
        for pat in pats:
            i = data.find(pat)
            if i >= 0:
                sights.append(Detection(algo=algo or pq_from_text(pat.decode()), file=path, line=0, evidence="binary", detector="binary",
                                       snippet=f"{pat[:8].hex()}... at offset 0x{i:x}", lang="native",
                                       params=dict(params, role="implementation"), context=set(base)))
                break
    if not_sha1({s.algo for s in sights}, any(p in data for p in packed([SHA1_K4]))):
        sights = [s for s in sights if s.algo != "SHA-1"]
    seen = set()
    for rx, name in VERSIONS:
        m = rx.search(data)
        if m and name not in seen:
            seen.add(name)
            ver = m.group(1).decode()
            note, pq = lib_note(name, ver)
            libs.append(Library(name=name, ecosystem="binary", manifest=path, line=0, version=ver, used_in=[path], pq=pq, note=note))
    return sights, libs


def scan_class(data, where, base):
    if not any(r in data for r in CRYPTO_REFS):
        return []
    out, seen = [], set()
    for m in re.finditer(rb"[\x20-\x7e]{2,64}", data):
        if m.group(0) in seen:
            continue
        seen.add(m.group(0))
        hits, prose = classify_literal(m.group(0).decode())
        for a, p in [] if prose else hits:
            if a:
                out.append(Detection(algo=a, file=where, line=0, evidence="binary", detector="binary", snippet=f"class constant \"{m.group(0).decode()}\"",
                                    lang="jvm", params=dict(p), context=set(base)))
    return out


def scan_archive(data, path, base, depth=0, budget=None, checkpoint=None):
    """Classes in a jar, and in the jars inside it, within one budget of decompressed bytes and entries for the whole archive."""
    sights, budget = [], budget if budget is not None else [ARCHIVE_BUDGET, ARCHIVE_ENTRIES]
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return sights
    for info in z.infolist():
        n = info.filename
        if not (n.endswith(".class") or depth == 0 and n.endswith(".jar")):
            continue
        if info.file_size > (CLASS_MAX if n.endswith(".class") else MAX) or info.file_size > budget[0] or budget[1] <= 0:
            continue
        budget[0] -= info.file_size
        budget[1] -= 1
        if checkpoint:
            checkpoint()
        try:
            entry = z.read(info)
        except Exception:
            continue
        if n.endswith(".class"):
            sights += scan_class(entry, f"{path}!{n}", base)
        else:
            sights += scan_archive(entry, f"{path}!{n}", base, 1, budget, checkpoint)
    return sights


def scan(root, scope=False):
    sights, libs, n = [], [], 0
    for p in iter_files(root, scope, max_bytes=MAX, skip=SKIP_DIRS - BUILD_DIRS):
        ext = p.suffix.lower()
        if ext not in NATIVE_EXT and ext not in ARCHIVES and ext != ".class":
            try:
                with open(p, "rb") as f:
                    if not f.read(4).startswith(MAGIC):
                        continue
            except OSError:
                continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        path = rel(root, p)
        base = {"test"} if is_test(path) else set()
        n += 1
        if ext in ARCHIVES:
            sights += scan_archive(data, path, base, checkpoint=scope.checkpoint if scope else None)
        elif ext == ".class":
            sights += scan_class(data, path, base)
        else:
            s, l = scan_native(data, path, base)
            sights += s
            libs += l
    return sights, libs, n
