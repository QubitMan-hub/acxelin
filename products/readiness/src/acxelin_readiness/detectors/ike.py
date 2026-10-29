"""IKEv2's IKE_SA_INIT exchange and IKEv1's first Main or Aggressive Mode messages are sent in the clear, so their proposals,
the key-exchange group, any RFC 9370 additional key exchanges (where ML-KEM appears) and, for IKEv1, the authentication method
can be read from a capture. Nothing after them is read."""
import struct

GROUPS = {1: ("DH", {"key_size": 768}), 2: ("DH", {"key_size": 1024}), 5: ("DH", {"key_size": 1536}), 14: ("DH", {"key_size": 2048}),
          15: ("DH", {"key_size": 3072}), 16: ("DH", {"key_size": 4096}), 17: ("DH", {"key_size": 6144}), 18: ("DH", {"key_size": 8192}),
          19: ("ECDH", {"curve": "P-256"}), 20: ("ECDH", {"curve": "P-384"}), 21: ("ECDH", {"curve": "P-521"}), 31: ("X25519", {}),
          32: ("X448", {}), 35: ("ML-KEM-512", {}), 36: ("ML-KEM-768", {}), 37: ("ML-KEM-1024", {})}
ENCRYPTION = {2: ("DES", {}), 3: ("3DES", {}), 12: ("AES", {"mode": "CBC"}), 13: ("AES", {"mode": "CTR"}), 14: ("AES", {"mode": "CCM"}),
              15: ("AES", {"mode": "CCM"}), 16: ("AES", {"mode": "CCM"}), 18: ("AES", {"mode": "GCM"}), 19: ("AES", {"mode": "GCM"}),
              20: ("AES", {"mode": "GCM"}), 28: ("ChaCha20-Poly1305", {}), 7: ("Blowfish", {})}
HMACS = {1: "MD5", 2: "SHA-1", 5: "SHA-256", 6: "SHA-384", 7: "SHA-512"}  # PRF ids
INTEGRITY = {1: "MD5", 2: "SHA-1", 6: "MD5", 7: "SHA-1", 12: "SHA-256", 13: "SHA-384", 14: "SHA-512"}
AUTH = {3: ("RSA", {}), 4: ("RSA", {}), 5: ("RSA", {}), 9: ("ECDSA", {"curve": "P-256"}), 10: ("ECDSA", {"curve": "P-384"}),
        11: ("ECDSA", {"curve": "P-521"})}  # IKEv1 authentication methods (RFC 2409, RFC 4754); pre-shared keys name no algorithm
AUTH_T = 100  # not an IKE transform type: where IKEv1's authentication method goes
ROLES = {1: "cipher", 2: "prf", 3: "mac", 4: "key-exchange", AUTH_T: "authentication"} | {t: "additional-key-exchange" for t in range(6, 13)}
V1_CIPHERS = {1: 2, 5: 3, 7: 12, 3: 7}  # IKEv1 encryption ids as their IKEv2 equivalents
V1_HASHES = {1: 1, 2: 2, 4: 5, 5: 6, 6: 7}  # IKEv1 hash ids as IKEv2 PRF ids


def name(ttype, tid):
    """A transform as (algorithm, parameters) in the catalogue's terms, or (None, {}) for one this reader does not know."""
    if ttype == 4 or 6 <= ttype <= 12:
        return GROUPS.get(tid, (None, {}))
    if ttype == 1:
        return ENCRYPTION.get(tid, (None, {}))
    if ttype == AUTH_T:
        return AUTH.get(tid, (None, {}))
    hashes = HMACS if ttype == 2 else INTEGRITY if ttype == 3 else {}
    return ("HMAC", {"hash": hashes[tid]}) if tid in hashes else (None, {})


def _proposals(b):
    out, i = [], 0
    while i + 8 <= len(b):
        plen, spi, count = struct.unpack(">H", b[i + 2:i + 4])[0], b[i + 6], b[i + 7]
        j, transforms = i + 8 + spi, []
        for _ in range(count):
            tlen = struct.unpack(">H", b[j + 2:j + 4])[0]
            ttype, tid = b[j + 4], struct.unpack(">H", b[j + 6:j + 8])[0]
            attrs, keylen = b[j + 8:j + tlen], None
            if len(attrs) >= 4 and struct.unpack(">H", attrs[:2])[0] == 0x800E:
                keylen = struct.unpack(">H", attrs[2:4])[0]
            transforms.append((ttype, tid, keylen))
            if tlen < 8:
                break
            j += tlen
        out.append(transforms)
        if plen < 8 or b[i] == 0:
            break
        i += plen
    return out


def sa_init(b):
    """{"response", "proposals", "ke"} from an IKE_SA_INIT message, or None for anything else."""
    if len(b) < 28 or b[17] >> 4 != 2 or b[18] != 34:
        return None
    nxt, i, out = b[16], 28, {"response": bool(b[19] & 0x20), "proposals": [], "ke": None}
    while nxt and i + 4 <= len(b):
        plen = struct.unpack(">H", b[i + 2:i + 4])[0]
        body = b[i + 4:i + plen]
        if nxt == 33:
            out["proposals"] = _proposals(body)
        elif nxt == 34 and len(body) >= 2:
            out["ke"] = struct.unpack(">H", body[:2])[0]
        if plen < 4:
            break
        nxt, i = b[i], i + plen
    return out


def _v1_transforms(b):
    """IKEv1 transforms (each a list of SA attributes) as IKEv2-style (type, id, key length) tuples."""
    out, j = [], 0
    while j + 8 <= len(b):
        tlen, attrs, i, keylen, got = struct.unpack(">H", b[j + 2:j + 4])[0], b[j + 8:j + struct.unpack(">H", b[j + 2:j + 4])[0]], 0, None, []
        while i + 4 <= len(attrs):
            kind, val = struct.unpack(">HH", attrs[i:i + 4])
            if kind & 0x8000:
                i += 4
            else:  # a long attribute: the second field is its length
                val, i = int.from_bytes(attrs[i + 4:i + 4 + val], "big"), i + 4 + val
            kind &= 0x7FFF
            if kind == 1 and val in V1_CIPHERS:
                got.append((1, V1_CIPHERS[val]))
            elif kind == 2 and val in V1_HASHES:
                got.append((2, V1_HASHES[val]))
            elif kind == 3:
                got.append((AUTH_T, val))
            elif kind == 4:
                got.append((4, val))
            elif kind == 14:
                keylen = val
        out.append([(t, v, keylen if t == 1 else None) for t, v in got])
        if tlen < 8 or b[j] == 0:
            break
        j += tlen
    return out


def v1_sa(b):
    """{"response", "proposals"} from an unencrypted IKEv1 Main or Aggressive Mode message carrying an SA, or None."""
    if len(b) < 28 or b[17] >> 4 != 1 or b[18] not in (2, 4) or b[19] & 1 or b[16] != 1:
        return None
    sa = b[28:28 + struct.unpack(">H", b[30:32])[0]]
    i, proposals = 12, []
    while i + 8 <= len(sa):
        plen, spi = struct.unpack(">H", sa[i + 2:i + 4])[0], sa[i + 6]
        proposals += _v1_transforms(sa[i + 8 + spi:i + plen])
        if plen < 8 or sa[i] == 0:
            break
        i += plen
    return {"response": any(b[8:16]), "proposals": proposals, "ke": None, "version": 1}
