"""Encrypted volumes: the cipher and key derivation in a volume's header, read without its passphrase; disk images never fill the scan limit."""
import json
import struct

import pytest

from acxelin_readiness import workspace
from acxelin_readiness.detectors import volumes


def found(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    return {(s.algo, s.params.get("key_size"), s.params.get("mode"), s.params.get("hash"), s.params.get("role")) for s in volumes.scan(tmp_path)[0]}


def luks1(cipher=b"aes", mode=b"xts-plain64", hash_=b"sha256", key_bytes=64):
    pad = lambda b, n: b + b"\x00" * (n - len(b))
    return (b"LUKS\xba\xbe" + struct.pack(">H", 1) + pad(cipher, 32) + pad(mode, 32) + pad(hash_, 32) + struct.pack(">II", 4096, key_bytes)).ljust(4096, b"\x00")


def luks2(segment="aes-xts-plain64", key_size=64, kdf="argon2id"):
    meta = {"keyslots": {"0": {"type": "luks2", "key_size": key_size, "area": {"encryption": segment, "key_size": key_size}, "kdf": {"type": kdf, "hash": "sha256"}}},
            "segments": {"0": {"type": "crypt", "encryption": segment}}, "digests": {"0": {"type": "pbkdf2", "hash": "sha256"}}}
    area = json.dumps(meta).encode().ljust(12288, b"\x00")
    header = (b"LUKS\xba\xbe" + struct.pack(">HQ", 2, 4096 + len(area))).ljust(4096, b"\x00")
    return header + area


def test_a_luks1_volume_names_its_cipher_key_size_and_pbkdf2_hash(tmp_path):
    seen = found(tmp_path, "disk.img", luks1())
    assert ("AES", 256, "XTS", None, "volume-encryption") in seen and ("PBKDF2", None, None, "SHA-256", "volume-key-derivation") in seen


def test_a_luks2_volume_reads_its_segment_and_argon2(tmp_path):
    seen = found(tmp_path, "data.luks", luks2())
    assert ("AES", 256, "XTS", None, "volume-encryption") in seen and ("Argon2", None, None, None, "volume-key-derivation") in seen


def test_aes_128_in_xts_is_reported_as_128_bit(tmp_path):
    assert ("AES", 128, "XTS", None, "volume-encryption") in found(tmp_path, "small.img", luks1(key_bytes=32))


def test_a_cbc_luks_volume_keeps_its_mode(tmp_path):
    assert ("AES", 256, "CBC", None, "volume-encryption") in found(tmp_path, "old.img", luks1(mode=b"cbc-essiv:sha256", key_bytes=32))


def qcow2(method, luks=None):
    header = b"QFI\xfb" + struct.pack(">I", 3) + b"\x00" * 24 + struct.pack(">I", method)
    header = header.ljust(104, b"\x00")[:100] + struct.pack(">I", 104)
    if luks is None:
        return header + b"\x00" * 8
    ext = struct.pack(">IIQQ", 0x0537BE77, 16, 4096, len(luks)) + struct.pack(">II", 0, 0)
    return (header + ext).ljust(4096, b"\x00") + luks


def test_qcow2_built_in_aes_is_flagged_and_qcow2_luks_is_read(tmp_path):
    assert ("AES", 128, "CBC", None, "volume-encryption") in found(tmp_path, "vm.qcow2", qcow2(1))
    assert ("AES", 256, "XTS", None, "volume-encryption") in found(tmp_path, "vm2.qcow2", qcow2(2, luks1()))


def bitlocker(method):
    boot = bytearray(4096)
    boot[3:11] = b"-FVE-FS-"
    boot[0xB0:0xB8] = struct.pack("<Q", 8192)
    block = bytearray(4096)
    block[0:8] = b"-FVE-FS-"
    struct.pack_into("<I", block, 64 + 36, method)
    return bytes(boot) + bytes(4096) + bytes(block)


@pytest.mark.parametrize("method,bits,mode", [(0x8004, 128, "XTS"), (0x8005, 256, "XTS"), (0x8002, 128, "CBC"), (0x8001, 256, "CBC")])
def test_a_bitlocker_volume_names_its_encryption_method(tmp_path, method, bits, mode):
    assert ("AES", bits, mode, None, "volume-encryption") in found(tmp_path, "usb.vhd", bitlocker(method))


def test_an_encrypted_macos_disk_image_names_its_key_size(tmp_path):
    dmg = b"encrcdsa" + struct.pack(">IIIII", 2, 16, 0, 0, 256) + b"\x00" * 200
    assert ("AES", 256, None, None, "volume-encryption") in found(tmp_path, "secret.dmg", dmg)


def test_crypttab_plain_mode_ciphers_are_read(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/crypttab").write_text("# name device key options\nswap /dev/sda2 /dev/urandom swap,cipher=aes-cbc-essiv:sha256,size=256\nhome UUID=1 none luks\n")
    seen = {(s.algo, s.params.get("key_size"), s.params.get("mode"), s.params.get("role")) for s in volumes.scan(tmp_path)[0]}
    assert seen == {("AES", 256, "CBC", "volume-encryption")}


@pytest.mark.parametrize("data", [b"LUKS\xba\xbe" + b"\xff" * 20, b"LUKS\xba\xbe\x00\x02" + struct.pack(">Q", 2**60), b"QFI\xfb" + b"\xff" * 120,
                                  b"\x00\x00\x00-FVE-FS-" + b"\xff" * 300, b"encrcdsa", b""])
def test_a_damaged_header_is_skipped(tmp_path, data):
    found(tmp_path, "bad.img", data)


def test_a_folder_with_a_large_disk_image_still_scans_within_the_byte_limit(tmp_path):
    (tmp_path / "keys.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    with open(tmp_path / "big.img", "wb") as f:
        f.write(luks1())
        f.truncate(3_000_000_000)  # sparse: 3 GB on paper
    import time
    start = time.monotonic()
    names = {a["name"] for a in workspace.scan(tmp_path, max_bytes=512_000_000)["assets"]}
    assert "MD5" in names and any(n.startswith("AES") for n in names)
    assert time.monotonic() - start < 15, "only the image's header is read, never the whole volume"
