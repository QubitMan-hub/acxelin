"""Builds small synthetic packet captures for the capture detector's tests."""
import struct

from acxelin_readiness.detectors.probe import client_hello


def _eth_ip_tcp(src, dst, sport, dport, seq, payload):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, bytes(src), bytes(dst)) + tcp
    return b"\x00" * 12 + b"\x08\x00" + ip


def pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for f in frames:
        out += struct.pack("<IIII", 0, 0, len(f), len(f)) + f
    return out


def _record(hs_type, body):
    hs = bytes([hs_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def server_hello(suite, version=0x0304, group=None):
    ext = b""
    if version == 0x0304:
        ext += struct.pack(">HHH", 0x002B, 2, 0x0304)
    if group is not None:
        ext += struct.pack(">HHHH", 0x0033, 4 + 32, group, 32) + b"\x00" * 32
    body = struct.pack(">H", 0x0303) + b"\x01" * 32 + b"\x00" + struct.pack(">H", suite) + b"\x00" + struct.pack(">H", len(ext)) + ext
    return _record(2, body)


def server_key_exchange(curve):
    return _record(12, b"\x03" + struct.pack(">H", curve) + b"\x20" + b"\x00" * 32)


def kexinit(kex, hostkey, cipher, mac):
    lists = [kex, hostkey, cipher, cipher, mac, mac, "none", "none", "", ""]
    payload = b"\x14" + b"\x00" * 16 + b"".join(struct.pack(">I", len(x)) + x.encode() for x in lists) + b"\x00" + b"\x00" * 4
    pad = 8 - (len(payload) + 5) % 8 or 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def tls_capture(groups, sh, extra=b""):
    c, s = [10, 0, 0, 5], [10, 0, 0, 9]
    return [_eth_ip_tcp(c, s, 50000, 443, 1, client_hello("bank.example", groups)), _eth_ip_tcp(s, c, 443, 50000, 1, sh + extra)]


def ssh_capture(client_kex, server_kex):
    c, s = [10, 0, 0, 5], [10, 0, 0, 22]
    return [_eth_ip_tcp(c, s, 50001, 22, 1, b"SSH-2.0-OpenSSH_9.9\r\n" + kexinit(client_kex, "ssh-ed25519,rsa-sha2-512", "aes256-gcm@openssh.com", "hmac-sha2-256")),
            _eth_ip_tcp(s, c, 22, 50001, 1, b"SSH-2.0-OpenSSH_8.4\r\n" + kexinit(server_kex, "rsa-sha2-512", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com", "hmac-sha2-256"))]


def _eth_ip_udp(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes(src), bytes(dst)) + udp
    return b"\x00" * 12 + b"\x08\x00" + ip


def _varint(n):
    return bytes([n]) if n < 64 else struct.pack(">H", 0x4000 | n) if n < 16384 else struct.pack(">I", 0x80000000 | n)


def quic_initial(dcid, scid, crypto, side, pn=0, offset=0, pad_to=1200):
    """One protected QUIC v1 Initial packet (RFC 9001 section 5) carrying `crypto` at `offset` of the CRYPTO stream."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from acxelin_readiness.detectors.quic import keys
    key, iv, hp = keys(dcid if side == "client" else side, "client" if side == "client" else "server")
    frames = b"\x06" + _varint(offset) + _varint(len(crypto)) + crypto
    pn_bytes = struct.pack(">I", pn)  # a 4-byte packet number
    head = bytes([0xC3]) + struct.pack(">I", 1) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00"
    frames += b"\x00" * max(0, pad_to - len(head) - 2 - 4 - len(frames) - 16)
    head += struct.pack(">H", 0x4000 | (4 + len(frames) + 16)) + pn_bytes
    nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
    body = AESGCM(key).encrypt(nonce, frames, head)
    pn_off = len(head) - 4
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(body[:16])
    first = bytes([head[0] ^ (mask[0] & 0x0F)])
    return first + head[1:pn_off] + bytes(a ^ b for a, b in zip(pn_bytes, mask[1:5])) + body


def quic_capture(groups, server_group, split=True):
    """A client's ClientHello over two Initial packets (as a post-quantum key share makes it), and the server's ServerHello."""
    from acxelin_readiness.detectors.probe import client_hello
    c, s, dcid, scid, sscid = [10, 0, 0, 5], [10, 0, 0, 9], bytes.fromhex("8394c8f03e515708"), b"\x01\x02\x03\x04", b"\x0a\x0b\x0c\x0d"
    ch = client_hello("quic.example", groups)[5:]  # a handshake message: QUIC carries no TLS record layer
    half = len(ch) // 2 if split else len(ch)
    frames = [_eth_ip_udp(c, s, 51000, 443, quic_initial(dcid, scid, ch[:half], "client", 0)),
              *([_eth_ip_udp(c, s, 51000, 443, quic_initial(dcid, scid, ch[half:], "client", 1, offset=half))] if split else [])]
    sh = server_hello(0x1301, group=server_group)[5:]
    frames.append(_eth_ip_udp(s, c, 443, 51000, quic_initial(scid, sscid, sh, dcid, 0, pad_to=0)))
    return frames


def ike_transform(ttype, tid, keylen=None, last=False):
    attr = struct.pack(">HH", 0x800E, keylen) if keylen else b""
    return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attr), ttype, 0, tid) + attr


def ike_sa_init(transforms, ke, response):
    """An IKE_SA_INIT message: one proposal of (type, id, key length) transforms and a KE payload for group `ke`."""
    ts = b"".join(ike_transform(t, i, k, last=n == len(transforms) - 1) for n, (t, i, k) in enumerate(transforms))
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(ts), 1, 1, 0, len(transforms)) + ts
    sa = struct.pack(">BBH", 34, 0, 4 + len(proposal)) + proposal
    kep = struct.pack(">BBHHH", 0, 0, 8 + 32, ke, 0) + b"\x00" * 32
    body = sa + kep
    header = b"\x11" * 8 + (b"\x22" * 8 if response else b"\x00" * 8) + struct.pack(">BBBBII", 33, 0x20, 34, 0x20 if response else 0x08, 0, 28 + len(body))
    return header + body


def ike_capture(offer, ke_offer, chosen, ke_chosen, port=500):
    c, s = [10, 0, 0, 5], [10, 0, 0, 1]
    marker = b"\x00" * 4 if port == 4500 else b""
    return [_eth_ip_udp(c, s, port, port, marker + ike_sa_init(offer, ke_offer, False)),
            _eth_ip_udp(s, c, port, port, marker + ike_sa_init(chosen, ke_chosen, True))]


def _dtls(msg_type, body, seq, version, frags=1):
    """DTLS records (RFC 6347 section 4.2.2) carrying one handshake message, cut into `frags` fragments."""
    out, step = [], -(-len(body) // frags)
    for k, off in enumerate(range(0, len(body), step)):
        part = body[off:off + step]
        hs = bytes([msg_type]) + len(body).to_bytes(3, "big") + struct.pack(">H", seq) + off.to_bytes(3, "big") + len(part).to_bytes(3, "big") + part
        out.append(b"\x16" + struct.pack(">H", version) + b"\x00\x00" + (seq * 4 + k).to_bytes(6, "big") + struct.pack(">H", len(hs)) + hs)
    return out


def dtls_capture(groups, suite, version=0xFEFD, group=None):
    """A DTLS client offering `groups`, and a server answering with `suite` in a ServerHello split over two datagrams."""
    c, s = [10, 0, 0, 5], [10, 0, 0, 9]
    ch = client_hello("vpn.example", groups)[9:]
    ch = struct.pack(">H", version) + ch[2:35 + ch[34]] + b"\x00" + ch[35 + ch[34]:]  # DTLS adds an empty cookie after the session ID
    sh = server_hello(suite, version=0x0303, group=group)[9:]
    sh = struct.pack(">H", version) + sh[2:]
    first, second = _dtls(2, sh, 0, version, frags=2)
    return [_eth_ip_udp(c, s, 51000, 4433, _dtls(1, ch, 0, version)[0]), _eth_ip_udp(s, c, 4433, 51000, first), _eth_ip_udp(s, c, 4433, 51000, second)]


def ikev1_sa(transforms, response, exchange=2):
    """An IKEv1 Main Mode (2) or Aggressive Mode (4) message with one proposal; each transform is a list of (attribute, value)."""
    ts = b""
    for n, attrs in enumerate(transforms):
        a = b"".join(struct.pack(">HH", 0x8000 | k, v) for k, v in attrs)
        ts += struct.pack(">BBHBBH", 0 if n == len(transforms) - 1 else 3, 0, 8 + len(a), n + 1, 1, 0) + a
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(ts), 1, 1, 0, len(transforms)) + ts
    sa = struct.pack(">BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
    header = b"\x11" * 8 + (b"\x22" * 8 if response else b"\x00" * 8) + struct.pack(">BBBBII", 1, 0x10, exchange, 0, 0, 28 + len(sa))
    return header + sa


def ikev1_capture(offer, chosen, exchange=2):
    c, s = [10, 0, 0, 5], [10, 0, 0, 1]
    return [_eth_ip_udp(c, s, 500, 500, ikev1_sa(offer, False, exchange)), _eth_ip_udp(s, c, 500, 500, ikev1_sa(chosen, True, exchange))]
