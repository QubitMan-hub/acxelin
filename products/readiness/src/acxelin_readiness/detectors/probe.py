import hashlib
import ipaddress
import os
import socket
import struct

from .. import pacing
from ..catalog import pq_from_text

GROUPS = {
    0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024", 0x6399: "X25519Kyber768Draft00",
    0x001D: "X25519", 0x001E: "X448", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x0100: "ffdhe2048",
}
HRR = hashlib.sha256(b"HelloRetryRequest").digest()
SUITES = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009C, 0x002F]
LEGACY = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}
WEAK = {"RC4": [0x0005, 0x0004, 0xC011, 0xC007], "3DES": [0x000A, 0x0016, 0xC012, 0xC008],
        "DHE": [0x0033, 0x0039, 0x009E, 0x009F, 0x0067, 0x006B]}  # broken today, or Diffie-Hellman whose size the server picks
LEGACY_SUITES = [0xC014, 0xC013, 0xC00A, 0xC009, 0x0035, 0x002F] + WEAK["3DES"] + WEAK["DHE"] + WEAK["RC4"]
SIGALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807, 0x0808, 0x0904, 0x0905, 0x0906, 0x0201, 0x0203]


def _u16(n):
    return struct.pack(">H", n)


def _ext(t, body):
    return _u16(t) + _u16(len(body)) + body


def client_hello(host, groups, version=None, suites=None):
    """A TLS 1.3 ClientHello, or with `version` a TLS 1.0, 1.1 or 1.2 one offering `suites`, which carries none of TLS 1.3's extensions."""
    exts = b""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        name = host.encode()
        exts += _ext(0x0000, _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name)
    g = b"".join(_u16(x) for x in groups)
    exts += _ext(0x000A, _u16(len(g)) + g)
    exts += _ext(0x000B, b"\x01\x00")
    if version in (None, 0x0303):
        s = b"".join(_u16(x) for x in SIGALGS)
        exts += _ext(0x000D, _u16(len(s)) + s)
    if version is None:
        exts += _ext(0x002B, b"\x04\x03\x04\x03\x03")
        exts += _ext(0x002D, b"\x01\x01")
        exts += _ext(0x0033, b"\x00\x00")
    cs = b"".join(_u16(x) for x in (suites or (SUITES if version is None else LEGACY_SUITES)))
    sid = os.urandom(32)
    body = _u16(version or 0x0303) + os.urandom(32) + bytes([32]) + sid + _u16(len(cs)) + cs + b"\x01\x00" + _u16(len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def _recv(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _dh_bits(sock, first):
    """The size of the server's Diffie-Hellman prime, from the ServerKeyExchange that follows a DHE ServerHello."""
    data = first
    for _ in range(16):
        j = 0
        while j + 4 <= len(data):
            t, ln = data[j], int.from_bytes(data[j + 1:j + 4], "big")
            if j + 4 + ln > len(data):
                break
            if t == 12 and ln >= 2:
                plen = struct.unpack(">H", data[j + 4:j + 6])[0]
                return int.from_bytes(data[j + 6:j + 6 + plen], "big").bit_length()
            if t == 14:
                return None
            j += 4 + ln
        hdr = _recv(sock, 5)
        if len(hdr) < 5 or hdr[0] != 0x16:
            return None
        data += _recv(sock, struct.unpack(">H", hdr[3:5])[0])
    return None


def server_hello(host, port, groups, timeout=5.0, version=None, name=None, suites=None, dh=False):
    """Returns (kind, info). kind is 'hrr', 'hello', 'alert', 'closed' (the server hung up on the hello, as some do to refuse it)
    or 'error' (no connection, or no answer in time)."""
    with pacing.slot(host, port):
        return _server_hello(host, port, groups, timeout, version, name, suites, dh)


def _server_hello(host, port, groups, timeout, version, name, suites, dh):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return "error", str(e)
    try:
        with sock:
            sock.sendall(client_hello(name or host, groups, version, suites))
            hdr = _recv(sock, 5)
            if len(hdr) < 5:
                return "closed", "connection closed"
            ctype, _, ln = hdr[0], hdr[1:3], struct.unpack(">H", hdr[3:5])[0]
            rec = _recv(sock, ln)
            bits = _dh_bits(sock, rec) if dh and ctype == 0x16 else None
    except (ConnectionResetError, BrokenPipeError):
        return "closed", "connection reset"
    except OSError as e:
        return "error", str(e)
    if ctype == 0x15:
        return "alert", rec[1] if len(rec) > 1 else None
    if ctype != 0x16 or not rec or rec[0] != 0x02:
        return "error", "unexpected response"
    b = rec[4:]
    version, rnd = struct.unpack(">H", b[:2])[0], b[2:34]
    i = 34
    i += 1 + b[i]
    suite = struct.unpack(">H", b[i:i + 2])[0]
    i += 3
    info = {"suite": suite, "version": version, "group": None, "dh_bits": bits}
    if i + 2 <= len(b):
        end = i + 2 + struct.unpack(">H", b[i:i + 2])[0]
        i += 2
        while i + 4 <= end:
            et, el = struct.unpack(">HH", b[i:i + 4])
            data = b[i + 4:i + 4 + el]
            if et == 0x002B and len(data) >= 2:
                info["version"] = struct.unpack(">H", data[:2])[0]
            if et == 0x0033 and len(data) >= 2:
                info["group"] = struct.unpack(">H", data[:2])[0]
            i += 4 + el
    return ("hrr" if rnd == HRR else "hello"), info


def legacy_versions(host, port, timeout=5.0, name=None):
    """[(name, suite)] of TLS 1.0 and 1.1 the server accepts, or None when it could not be asked (no connection or no answer). Offered as bytes, so the answer does not depend on whether this
    machine's OpenSSL still speaks them (many builds and system policies no longer do)."""
    found, answered = [], False
    for version, label in LEGACY.items():
        kind, info = server_hello(host, port, [0x001D, 0x0017, 0x0018], timeout, version, name)
        if kind == "closed":  # a refusal, or a flaky network: ask once more before counting it as a refusal
            kind, info = server_hello(host, port, [0x001D, 0x0017, 0x0018], timeout, version, name)
        answered |= kind != "error"
        if kind == "hello" and info["version"] == version:
            found.append((label, info["suite"]))
    return found if answered else None


def tls_groups(host, port, timeout=5.0):
    """Which key-exchange groups the server accepts, and which it prefers when offered all."""
    kind, info = server_hello(host, port, list(GROUPS), timeout)
    if kind in ("error", "closed"):
        return {"error": info}
    out = {"tls13": kind == "hrr" or (isinstance(info, dict) and info.get("version") == 0x0304), "preferred": None, "supported": []}
    if kind == "hrr":
        out["preferred"] = GROUPS.get(info["group"], hex(info["group"] or 0))
    if not out["tls13"]:
        return out
    for g, name in GROUPS.items():
        k, inf = server_hello(host, port, [g], timeout)
        if k == "hrr" and inf.get("group") == g:
            out["supported"].append(name)
    out["pq"] = [n for n in GROUPS.values() if pq_from_text(n) and n in out["supported"]]
    return out


def _namelist(b, i):
    n = struct.unpack(">I", b[i:i + 4])[0]
    return b[i + 4:i + 4 + n].decode("ascii", "replace").split(","), i + 4 + n


def ssh_kexinit(host, port=22, timeout=6.0):
    with pacing.slot(host, port), socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(b"SSH-2.0-acxelin_readiness_probe\r\n")
        buf = b""
        while b"\n" not in buf or not buf.lstrip().startswith(b"SSH-"):
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("no SSH banner")
            buf += chunk
            if b"SSH-" in buf:
                buf = buf[buf.index(b"SSH-"):]
        line, _, rest = buf.partition(b"\n")
        banner = line.strip().decode("ascii", "replace")
        while len(rest) < 5:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("connection closed before KEXINIT")
            rest += chunk
        plen = struct.unpack(">I", rest[:4])[0]
        while len(rest) < 4 + plen:
            chunk = sock.recv(65536)
            if not chunk:
                break
            rest += chunk
    pad = rest[4]
    payload = rest[5:4 + plen - pad]
    if not payload or payload[0] != 20:
        raise OSError("server did not send KEXINIT")
    i, lists = 17, []
    for _ in range(6):
        l, i = _namelist(payload, i)
        lists.append(l)
    return {"banner": banner, "kex": lists[0], "hostkey": lists[1], "ciphers": lists[2], "macs": lists[4]}


def weak_suites(host, port, timeout=5.0, name=None):
    """[(kind, suite, DH bits)] of RC4, 3DES and Diffie-Hellman under 2048 bits the server accepts at TLS 1.2, offered as bytes so the
    answer does not depend on this machine's TLS library; None when it could not be asked."""
    found, answered = [], False
    for kind, suites in WEAK.items():
        for _ in range(2):  # a hang-up is asked once more before it counts as a refusal
            got, info = server_hello(host, port, [0x001D, 0x0017, 0x0018], timeout, 0x0303, name, suites, dh=kind == "DHE")
            if got != "closed":
                break
        answered |= got != "error"
        if got == "hello" and info["suite"] in suites:
            bits = info["dh_bits"] if kind == "DHE" else None
            if kind != "DHE" or (bits and bits < 2048):
                found.append((kind, info["suite"], bits))
    return found if answered else None
