"""QUIC v1 Initial packets. They are protected only with keys derived from the client's first connection ID (RFC 9001,
section 5.2), so anyone on the path can read the TLS ClientHello and ServerHello inside. Later packets are not read."""
import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _label(secret, label, n):
    full = b"tls13 " + label
    return HKDFExpand(hashes.SHA256(), n, struct.pack(">H", n) + bytes([len(full)]) + full + b"\x00").derive(secret)


def keys(dcid, side):
    """(key, iv, header-protection key) for the client's or the server's Initial packets."""
    secret = _label(hmac.new(SALT_V1, dcid, hashlib.sha256).digest(), b"client in" if side == "client" else b"server in", 32)
    return _label(secret, b"quic key", 16), _label(secret, b"quic iv", 12), _label(secret, b"quic hp", 16)


def varint(b, i):
    n, v = 1 << (b[i] >> 6), b[i] & 0x3F
    if i + n > len(b):
        raise IndexError("truncated varint")
    for k in range(1, n):
        v = v << 8 | b[i + k]
    return v, i + n


def initials(d):
    """(dcid, start, packet-number offset, end) of each version 1 Initial packet coalesced in one UDP datagram."""
    i = 0
    while i + 7 <= len(d) and d[i] & 0x80 and struct.unpack(">I", d[i + 1:i + 5])[0] == 1:
        kind, j = (d[i] >> 4) & 3, i + 5
        dcid = d[j + 1:j + 1 + d[j]]
        j += 1 + d[j]
        j += 1 + d[j]
        if kind == 3:
            return  # Retry: no length, nothing further to read
        if kind == 0:
            token, j = varint(d, j)
            j += token
        length, j = varint(d, j)
        if kind == 0:
            yield dcid, i, j, j + length
        i = j + length


def unprotect(d, start, pn_off, end, key, iv, hp):
    """The packet's frames, or None when it does not decrypt (another connection ID, or damage)."""
    sample = d[pn_off + 4:pn_off + 20]
    if len(sample) < 16 or end > len(d):
        return None
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    first = d[start] ^ (mask[0] & 0x0F)
    n = (first & 3) + 1
    pn = bytes(a ^ b for a, b in zip(d[pn_off:pn_off + n], mask[1:]))
    nonce = (int.from_bytes(iv, "big") ^ int.from_bytes(pn, "big")).to_bytes(12, "big")
    try:
        return AESGCM(key).decrypt(nonce, d[pn_off + n:end], bytes([first]) + d[start + 1:pn_off] + pn)
    except InvalidTag:
        return None


def crypto_frames(p):
    """(offset, data) of the CRYPTO frames in an Initial packet's payload; stops at any frame an Initial cannot carry."""
    i = 0
    while i < len(p):
        t, i = varint(p, i)
        if t in (0x00, 0x01):
            continue
        if t in (0x02, 0x03):
            _, i = varint(p, i)
            _, i = varint(p, i)
            count, i = varint(p, i)
            _, i = varint(p, i)
            for _ in range(2 * count + (3 if t == 0x03 else 0)):
                _, i = varint(p, i)
        elif t == 0x06:
            off, i = varint(p, i)
            n, i = varint(p, i)
            yield off, p[i:i + n]
            i += n
        else:
            return


def stream(pieces):
    """The CRYPTO stream from offset 0 for as long as it is contiguous."""
    out = b""
    for off, data in sorted(pieces):
        if off > len(out):
            break
        out += data[len(out) - off:]
    return out
