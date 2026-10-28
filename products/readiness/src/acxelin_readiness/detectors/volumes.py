"""Encrypted volumes: the cipher and key derivation written in a volume's own header, read without its passphrase. Only the
first bytes of a file are read, however large the volume is. LUKS 1 and 2 (also inside qcow2), qcow2's built-in AES,
BitLocker, encrypted macOS disk images and the plain-mode ciphers in crypttab."""
import json
import re
import struct

from ..catalog import lookup
from ..model import Detection
from . import iter_files, is_test, rel

EXT = {".img", ".luks", ".raw", ".bin", ".dmg", ".sparseimage", ".qcow2", ".vhd", ".vhdx", ".disk", ".part"}
HEAD = 65536
BITLOCKER = {0x8000: (128, "CBC"), 0x8001: (256, "CBC"), 0x8002: (128, "CBC"), 0x8003: (256, "CBC"), 0x8004: (128, "XTS"), 0x8005: (256, "XTS")}


def _cipher(spec, key_bytes):
    """("AES", {"key_size", "mode"}) from a dm-crypt cipher such as aes-xts-plain64 and its key length in bytes (XTS uses two keys)."""
    algo, _, mode = spec.partition("-")
    algo, mode = lookup(algo), mode.split("-")[0].upper() or None
    if not algo:
        return None, {}
    bits = key_bytes * 8 // (2 if mode == "XTS" else 1) if key_bytes else None
    return algo, {k: v for k, v in (("key_size", bits), ("mode", mode)) if v}


def _cstr(b):
    return b.split(b"\x00", 1)[0].decode("ascii", "replace").strip()


def luks(read, at=0):
    """[(algo, params, role)] from a LUKS header at offset `at`."""
    head = read(at, 4096)
    if head[:6] != b"LUKS\xba\xbe":
        return []
    version = struct.unpack(">H", head[6:8])[0]
    if version == 1:
        cipher, mode, hash_ = _cstr(head[8:40]), _cstr(head[40:72]), _cstr(head[72:104])
        algo, params = _cipher(f"{cipher}-{mode}", struct.unpack(">I", head[108:112])[0])
        return ([(algo, params, "volume-encryption")] if algo else []) + [("PBKDF2", {"hash": lookup(hash_)}, "volume-key-derivation")]
    size = struct.unpack(">Q", head[8:16])[0]
    if version != 2 or not 4096 < size <= 4 << 20:
        return []
    meta = json.loads(_cstr(read(at + 4096, size - 4096)) or "{}")
    out = []
    slot = next(iter(meta.get("keyslots", {}).values()), {})
    for seg in meta.get("segments", {}).values():
        algo, params = _cipher(str(seg.get("encryption", "")), int(slot.get("key_size") or 0))
        if algo:
            out.append((algo, params, "volume-encryption"))
    kdf = slot.get("kdf", {})
    if str(kdf.get("type", "")).startswith("argon2"):
        out.append(("Argon2", {}, "volume-key-derivation"))
    elif kdf.get("type") == "pbkdf2":
        out.append(("PBKDF2", {"hash": lookup(str(kdf.get("hash", "")))}, "volume-key-derivation"))
    return out


def qcow2(read):
    head = read(0, 4096)
    if head[:4] != b"QFI\xfb" or len(head) < 104:
        return []
    method, version = struct.unpack(">I", head[32:36])[0], struct.unpack(">I", head[4:8])[0]
    if method == 1:
        return [("AES", {"key_size": 128, "mode": "CBC"}, "volume-encryption")]  # qcow2's own AES: deprecated by QEMU, known weak
    if method != 2:
        return []
    i = struct.unpack(">I", head[100:104])[0] if version >= 3 else 72
    while i + 8 <= len(head):
        kind, length = struct.unpack(">II", head[i:i + 8])
        if kind == 0:
            break
        if kind == 0x0537BE77 and length >= 16:
            return luks(read, struct.unpack(">Q", head[i + 8:i + 16])[0])
        i += 8 + (length + 7) // 8 * 8
    return []


def bitlocker(read):
    boot = read(0, 512)
    if boot[3:11] != b"-FVE-FS-" or len(boot) < 0xB8:
        return []
    block = read(struct.unpack("<Q", boot[0xB0:0xB8])[0], 128)
    if block[:8] != b"-FVE-FS-" or len(block) < 104:
        return [("AES", {}, "volume-encryption")]  # a BitLocker volume whose metadata block was not found: AES of unread size
    bits, mode = BITLOCKER.get(struct.unpack("<I", block[100:104])[0], (None, None))
    return [("AES", {k: v for k, v in (("key_size", bits), ("mode", mode)) if v}, "volume-encryption")]


def dmg(read):
    head = read(0, 64)
    if head[:8] != b"encrcdsa" or len(head) < 28:
        return []
    bits = struct.unpack(">I", head[24:28])[0]
    return [("AES", {"key_size": bits} if bits in (128, 256) else {}, "volume-encryption")]


CRYPTTAB = re.compile(r"(?:^|,)cipher=([\w:-]+)")


def crypttab(text):
    out = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        m = CRYPTTAB.search(fields[3]) if len(fields) >= 4 else None
        if m:
            size = re.search(r"(?:^|,)size=(\d+)", fields[3])
            algo, params = _cipher(m.group(1), int(size.group(1)) // 8 * (2 if "-xts" in m.group(1) else 1) if size else 0)
            if algo:
                out.append((algo, params, "volume-encryption"))
    return out


def scan(root, scope=False):
    sights, n = [], 0
    for p in iter_files(root, scope, max_bytes=float("inf")):
        if p.suffix.lower() not in EXT and p.name != "crypttab":
            continue
        path = rel(root, p)
        try:
            with open(p, "rb") as f:
                def read(at, size):
                    f.seek(at)
                    return f.read(min(size, HEAD))
                if p.name == "crypttab":
                    found, what = crypttab(read(0, HEAD).decode("utf-8", "replace")), "crypttab entry"
                else:
                    found, what = [], ""
                    for reader, label in ((luks, "LUKS volume header"), (qcow2, "qcow2 disk image"), (bitlocker, "BitLocker volume"), (dmg, "encrypted disk image")):
                        found = reader(read)
                        if found:
                            what = label
                            break
        except (OSError, ValueError, struct.error, IndexError, AttributeError, TypeError):
            continue
        n += bool(found)
        for algo, params, role in found:
            sights.append(Detection(algo=algo, file=path, line=1, evidence="artifact", detector="volumes", snippet=what, lang="volume",
                                    params={k: v for k, v in dict(params, role=role).items() if v}, context={"test"} if is_test(path) else set()))
    return sights, n
