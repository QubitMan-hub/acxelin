"""PKCS#12 and Java keystores, read without a password: what protects them, and the certificates they hold in the clear."""
import struct

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

from ..model import Artifact, Detection
from . import artifacts

EXT = {".p12", ".pfx", ".jks", ".jceks", ".keystore", ".truststore"}
JKS, JCEKS = 0xFEEDFEED, 0xCECECECE


def _oid(dotted):
    first, second, *rest = map(int, dotted.split("."))
    body = bytearray([40 * first + second])
    for n in rest:
        chunk = [n & 0x7F]
        while n > 0x7F:
            n >>= 7
            chunk.append(0x80 | n & 0x7F)
        body += bytes(reversed(chunk))
    return bytes([6, len(body)]) + bytes(body)


PBE_SHA1 = "1.2.840.113549.1.12.1."
PROTECTION = {_oid(o): found for o, found in {
    PBE_SHA1 + "1": [("RC4", 128), ("SHA-1", None)], PBE_SHA1 + "2": [("RC4", 40), ("SHA-1", None)],
    PBE_SHA1 + "3": [("3DES", None), ("SHA-1", None)], PBE_SHA1 + "4": [("3DES", 112), ("SHA-1", None)],
    PBE_SHA1 + "5": [("RC2", 128), ("SHA-1", None)], PBE_SHA1 + "6": [("RC2", 40), ("SHA-1", None)],
    "1.2.840.113549.1.5.13": [("PBKDF2", None)], "1.2.840.113549.3.7": [("3DES", None)],
    "2.16.840.1.101.3.4.1.2": [("AES", 128)], "2.16.840.1.101.3.4.1.22": [("AES", 192)], "2.16.840.1.101.3.4.1.42": [("AES", 256)],
    "1.2.840.113549.2.7": [("SHA-1", None)], "1.2.840.113549.2.9": [("SHA-256", None)],
    "1.3.14.3.2.26": [("SHA-1", None)], "2.16.840.1.101.3.4.2.1": [("SHA-256", None)],
}.items()}


def _sight(algo, path, what, size=None, role="keystore-protection"):
    return Detection(algo=algo, file=path, line=1, evidence="artifact", detector="artifacts", snippet=what, lang="keystore",
                     params={"role": role, **({"key_size": size} if size else {})})


def _key(der, path, fmt, encrypted):
    """A private-key entry, named by its certificate's public key: the key itself is never read."""
    algo, params = artifacts.key_info(x509.load_der_x509_certificate(der).public_key())
    if not algo:
        return [], []
    art = Artifact(kind="private-key", file=path, line=1, algo=algo, params=params, details={"encrypted": encrypted, "format": fmt})
    return [art], [Detection(algo=algo, file=path, line=1, evidence="artifact", detector="artifacts", snippet=f"{fmt} private key entry",
                             lang="keystore", params=dict(params, role="private-key"))]


def _java(data):
    """(certificates, chain heads of private-key entries, secret-key entries); stops at the first damaged or unknown entry."""
    pos, certs, keys, secrets = 0, [], [], 0

    def take(n):
        nonlocal pos
        if n < 0 or pos + n > len(data):
            raise ValueError("truncated keystore")
        pos += n
        return data[pos - n:pos]
    u4 = lambda: struct.unpack(">I", take(4))[0]
    utf = lambda: take(struct.unpack(">H", take(2))[0])
    try:
        _, _, count = struct.unpack(">III", take(12))
        for _ in range(min(count, 10000)):
            tag = u4()
            utf(), take(8)
            if tag == 1:
                take(u4())
                for i in range(min(u4(), 100)):
                    utf()
                    der = take(u4())
                    certs.append(der)
                    if i == 0:
                        keys.append(der)
            elif tag == 2:
                utf()
                certs.append(take(u4()))
            else:
                secrets += tag == 3
                break  # a secret-key entry is a serialized Java object of no stated length
    except (ValueError, struct.error):
        pass
    return certs, keys, secrets


def read(data, path):
    arts, sights = [], []

    def add(der, source):
        try:
            a, s = artifacts.cert_record(x509.load_der_x509_certificate(der), path, 1, source=source)
        except ValueError:
            return
        arts.append(a)
        sights.extend(s)

    magic = struct.unpack(">I", data[:4])[0] if len(data) >= 4 else None
    if magic in (JKS, JCEKS):
        fmt = "JKS" if magic == JKS else "JCEKS"
        certs, keys, _ = _java(data)
        for der in certs:
            add(der, "keystore")
        for der in keys:
            try:
                a, s = _key(der, path, fmt, True)
            except ValueError:
                continue
            arts += a
            sights += s
        sights.append(_sight("SHA-1", path, f"{fmt} keystore integrity check"))
        if keys:
            sights += [_sight("SHA-1", path, "JKS private-key protection")] if fmt == "JKS" else \
                [_sight("MD5", path, "JCEKS private-key protection (PBEWithMD5AndTripleDES)"), _sight("3DES", path, "JCEKS private-key protection (PBEWithMD5AndTripleDES)")]
        return arts, sights
    if not data.startswith(b"\x30"):
        return arts, sights
    seen = set()
    for oid, found in PROTECTION.items():
        if oid in data:
            for algo, size in found:
                if (algo, size) not in seen:
                    seen.add((algo, size))
                    sights.append(_sight(algo, path, "PKCS#12 keystore protection", size))
    try:
        store = pkcs12.load_pkcs12(data, None)
    except (ValueError, TypeError):
        return arts, sights  # protected by a password: its protection is all that can be told
    for c in ([store.cert] if store.cert else []) + list(store.additional_certs):
        add(c.certificate.public_bytes(Encoding.DER), "keystore")
    if store.key is not None and store.cert:
        a, s = _key(store.cert.certificate.public_bytes(Encoding.DER), path, "PKCS12", False)
        arts += a
        sights += s
    return arts, sights
