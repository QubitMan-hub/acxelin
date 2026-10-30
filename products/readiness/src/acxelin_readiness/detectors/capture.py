"""Traffic captures: what clients and servers actually negotiated, read offline from a .pcap or .pcapng file.

Only the start of each connection is read: the TLS ClientHello and ServerHello (and a TLS 1.2 ServerKeyExchange), the SSH
banners and KEXINIT lists, the IKEv2 IKE_SA_INIT exchange, and the TLS handshake inside QUIC Initial packets, whose keys
anyone can derive from the connection ID. Nothing else is decrypted and no packet is sent.
"""
import struct
from collections import defaultdict
from pathlib import Path

from ..catalog import HYBRIDS, lookup, pq_from_text
from ..model import Detection
from . import ike, quic
from .probe import GROUPS, HRR
from .suites import ssh_token, suite
from .tls import group_algo

MAX_STREAM = 65536
VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}


def packets(data):
    """(linktype, frame) for every packet in a pcap or pcapng file."""
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(data)
        return
    magic = data[:4]
    order = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if not order or len(data) < 24:
        raise ValueError("not a pcap or pcapng file")
    link = struct.unpack(order + "I", data[20:24])[0]
    i = 24
    while i + 16 <= len(data):
        incl = struct.unpack(order + "I", data[i + 8:i + 12])[0]
        yield link, data[i + 16:i + 16 + incl]
        i += 16 + incl


def _pcapng(data):
    links, i = [], 0
    order = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    while i + 12 <= len(data):
        btype, blen = struct.unpack(order + "II", data[i:i + 8])
        if blen < 12:
            break
        body = data[i + 8:i + blen - 4]
        if btype == 0x0A0D0D0A:
            order = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        elif btype == 1:
            links.append(struct.unpack(order + "H", body[:2])[0])
        elif btype == 6 and len(body) >= 20:
            iface, cap = struct.unpack(order + "I", body[:4])[0], struct.unpack(order + "I", body[12:16])[0]
            yield (links[iface] if iface < len(links) else 1), body[20:20 + cap]
        elif btype == 3 and len(body) >= 4:
            yield (links[0] if links else 1), body[4:]
        i += blen


def ip_payload(link, frame):
    """(version, ip packet) from a link-layer frame."""
    if link == 1:
        etype, off = struct.unpack(">H", frame[12:14])[0], 14
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            etype, off = struct.unpack(">H", frame[off + 2:off + 4])[0], off + 4
    elif link == 113:
        etype, off = struct.unpack(">H", frame[14:16])[0], 16
    elif link == 276:
        etype, off = struct.unpack(">H", frame[0:2])[0], 20
    elif link == 0:
        etype, off = (0x0800 if frame[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02") else 0x86DD), 4
    elif link in (228, 229):  # raw IPv4 or IPv6, as captured on tunnel and VPN interfaces
        etype, off = (0x0800 if link == 228 else 0x86DD), 0
    elif link in (12, 101):
        etype, off = (0x0800 if frame[:1] and frame[0] >> 4 == 4 else 0x86DD), 0
    else:
        return None
    return {0x0800: 4, 0x86DD: 6}.get(etype), frame[off:]


def _transport(data, proto):
    """(src address, dst address, segment) for every IPv4 or IPv6 packet of `proto` (6 TCP, 17 UDP)."""
    for link, frame in packets(data):
        try:
            ver, ip = ip_payload(link, frame)
            if ver == 4 and ip[9] == proto:
                total = struct.unpack(">H", ip[2:4])[0] or len(ip)
                yield ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20])), ip[(ip[0] & 15) * 4:total]
            elif ver == 6 and ip[6] == proto:
                yield _v6(ip[8:24]), _v6(ip[24:40]), ip[40:40 + struct.unpack(">H", ip[4:6])[0]]
        except (TypeError, IndexError, struct.error):
            continue


def tcp_segments(data):
    """((src, sport), (dst, dport), seq, payload) for every TCP segment with data."""
    for a, b, tcp in _transport(data, 6):
        try:
            sport, dport, seq = struct.unpack(">HHI", tcp[:8])
            payload = tcp[(tcp[12] >> 4) * 4:]
        except (IndexError, struct.error):
            continue
        if payload:
            yield (a, sport), (b, dport), seq, payload


def udp_datagrams(data):
    """((src, sport), (dst, dport), payload) for every UDP datagram."""
    for a, b, udp in _transport(data, 17):
        try:
            sport, dport, length = struct.unpack(">HHH", udp[:6])
        except struct.error:
            continue
        yield (a, sport), (b, dport), udp[8:length if length >= 8 else None]


def flows(data):
    """{(client, server): [(sender, payload), ...]} for UDP, in capture order. The client is whoever spoke first."""
    out, first = defaultdict(list), {}
    for src, dst, payload in udp_datagrams(data):
        key = tuple(sorted((src, dst)))
        first.setdefault(key, src)
        out[key].append((src, payload))
    return {(c, k[1] if k[0] == c else k[0]): out[k] for k, c in first.items()}


def _v6(b):
    return "[" + ":".join(f"{x:x}" for x in struct.unpack(">8H", b)) + "]"


def streams(data):
    """{(client, server): (client bytes, server bytes)}, the start of each connection in order. The client is whoever spoke first."""
    parts = defaultdict(dict)
    first = {}
    for src, dst, seq, payload in tcp_segments(data):
        key = tuple(sorted((src, dst)))
        first.setdefault(key, src)
        parts[(src, dst)].setdefault(seq, payload)
    out = {}
    for key, client in first.items():
        server = key[1] if key[0] == client else key[0]

        def join(d):
            buf = b""
            for s in sorted(d):
                buf += d[s]
                if len(buf) > MAX_STREAM:
                    break
            return buf
        out[(client, server)] = (join(parts.get((client, server), {})), join(parts.get((server, client), {})))
    return out


def handshakes(buf):
    """Handshake messages (type, body) from the TLS records at the start of a stream."""
    data, i = b"", 0
    while i + 5 <= len(buf) and buf[i] in (0x14, 0x15, 0x16, 0x17):
        ln = struct.unpack(">H", buf[i + 3:i + 5])[0]
        if buf[i] == 0x16:
            data += buf[i + 5:i + 5 + ln]
        elif buf[i] == 0x17:
            break
        i += 5 + ln
    yield from messages(data)


def messages(data):
    """Handshake messages (type, body) in a run of handshake bytes: a TLS record's content, or a QUIC CRYPTO stream."""
    j = 0
    while j + 4 <= len(data):
        ln = int.from_bytes(data[j + 1:j + 4], "big")
        yield data[j], data[j + 4:j + 4 + ln]
        j += 4 + ln


def _extensions(b, i):
    out = {}
    if i + 2 > len(b):
        return out
    end = i + 2 + struct.unpack(">H", b[i:i + 2])[0]
    i += 2
    while i + 4 <= min(end, len(b)):
        t, ln = struct.unpack(">HH", b[i:i + 4])
        out[t] = b[i + 4:i + 4 + ln]
        i += 4 + ln
    return out


def client_hello(b):
    i = 2 + 32
    i += 1 + b[i]
    n = struct.unpack(">H", b[i:i + 2])[0]
    suites = [struct.unpack(">H", b[i + 2 + k:i + 4 + k])[0] for k in range(0, n, 2)]
    i += 2 + n
    i += 1 + b[i]
    ext = _extensions(b, i)
    groups = [struct.unpack(">H", ext[0x000A][2 + k:4 + k])[0] for k in range(0, len(ext.get(0x000A, b"")) - 2, 2)] if 0x000A in ext else []
    sni = ext.get(0x0000, b"")[5:].decode("ascii", "replace") if 0x0000 in ext else ""
    return {"suites": suites, "groups": groups, "sni": sni}


def server_hello(b):
    version, rnd = struct.unpack(">H", b[:2])[0], b[2:34]
    i = 34
    i += 1 + b[i]
    info = {"suite": struct.unpack(">H", b[i:i + 2])[0], "version": version, "group": None, "hrr": rnd == HRR}
    ext = _extensions(b, i + 3)
    if len(ext.get(0x002B, b"")) >= 2:
        info["version"] = struct.unpack(">H", ext[0x002B][:2])[0]
    if len(ext.get(0x0033, b"")) >= 2:
        info["group"] = struct.unpack(">H", ext[0x0033][:2])[0]
    return info


def suite_name(code):
    """A cipher suite code as a name the suite parser reads: IANA for TLS 1.3, else OpenSSL's name, else the hex code."""
    names = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
    if code in names:
        return names[code]
    return OPENSSL.get(code, f"0x{code:04X}")


def _openssl_names():
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return {c["id"] & 0xFFFF: ("RSA-" if c["kea"] == "kx-rsa" and not c["name"].startswith(("RSA", "TLS_")) else "") + c["name"]
            for c in ctx.get_ciphers()}  # OpenSSL leaves RSA key transport out of names like AES128-SHA


OPENSSL = _openssl_names()


def tls_session(cbuf, sbuf):
    ch = sh = None
    curve = dh_bits = None
    for t, body in handshakes(cbuf):
        if t == 1:
            ch = client_hello(body)
            break
    for t, body in handshakes(sbuf):
        if t == 2 and sh is None:
            sh = server_hello(body)
        elif t == 12 and len(body) >= 3 and sh and "DHE" in suite_name(sh["suite"]).replace("ECDHE", ""):
            plen = struct.unpack(">H", body[:2])[0]  # finite-field DHE: the prime comes first
            dh_bits = int.from_bytes(body[2:2 + plen], "big").bit_length()
        elif t == 12 and len(body) >= 3 and body[0] == 3:
            curve = struct.unpack(">H", body[1:3])[0]
    if not sh:
        return None
    return {"client": ch, "server": sh, "group": sh["group"] or curve, "dh_bits": dh_bits}


def quic_session(client, datagrams):
    """The TLS handshake carried in the Initial packets of one QUIC connection, as tls_session gives it."""
    dcid, sides, ks = None, {"client": [], "server": []}, {}
    for sender, d in datagrams:
        side = "client" if sender == client else "server"
        for pdcid, start, pn_off, end in quic.initials(d):
            if side == "client" and dcid is None:
                dcid = pdcid  # both directions' keys come from the client's first destination connection ID
            if dcid is None:
                continue
            key = ks.setdefault(side, quic.keys(dcid, side))
            plain = quic.unprotect(d, start, pn_off, end, *key)
            if plain:
                sides[side] += list(quic.crypto_frames(plain))
    ch = next((client_hello(b) for t, b in messages(quic.stream(sides["client"])) if t == 1), None)
    sh = next((server_hello(b) for t, b in messages(quic.stream(sides["server"])) if t == 2), None)
    return {"client": ch, "server": sh, "group": sh["group"]} if sh else None


DTLS = {0xFEFF: ("DTLS 1.0", "TLSv1.1"), 0xFEFD: ("DTLS 1.2", "TLSv1.2"), 0xFEFC: ("DTLS 1.3", "TLSv1.3")}  # and the TLS each is built on


def is_dtls(d):
    return len(d) >= 13 and d[0] == 0x16 and struct.unpack(">H", d[1:3])[0] in DTLS


def dtls_session(client, datagrams):
    """The unencrypted (epoch 0) handshake of one DTLS association, its fragments put back together, as tls_session gives it."""
    msgs = {}
    for sender, d in datagrams:
        i = 0
        while i + 13 <= len(d):
            epoch, ln = struct.unpack(">H", d[i + 3:i + 5])[0], struct.unpack(">H", d[i + 11:i + 13])[0]
            rec, i = d[i + 13:i + 13 + ln], i + 13 + ln
            if d[i - 13 - ln] != 0x16 or epoch:
                continue
            j = 0
            while j + 12 <= len(rec):
                t, total, seq = rec[j], int.from_bytes(rec[j + 1:j + 4], "big"), struct.unpack(">H", rec[j + 4:j + 6])[0]
                off, flen = int.from_bytes(rec[j + 6:j + 9], "big"), int.from_bytes(rec[j + 9:j + 12], "big")
                buf = msgs.setdefault((sender == client, seq, t), bytearray(total))
                if off + flen <= total:
                    buf[off:off + flen] = rec[j + 12:j + 12 + flen]
                j += 12 + flen
    hellos = [bytes(b) for (mine, _, t), b in sorted(msgs.items()) if mine and t == 1]
    ch = None
    if hellos:  # the last ClientHello, after any cookie exchange; DTLS adds the cookie after the session ID
        b = hellos[-1]
        sid = 35 + b[34]
        ch = client_hello(b[:sid] + b[sid + 1 + b[sid]:])
    sh = next((server_hello(bytes(b)) for (mine, _, t), b in sorted(msgs.items()) if not mine and t == 2), None)
    curve = next((struct.unpack(">H", b[1:3])[0] for (mine, _, t), b in msgs.items() if not mine and t == 12 and len(b) >= 3 and b[0] == 3), None)
    return {"client": ch, "server": sh, "group": sh["group"] or curve} if sh else None


def ike_session(client, datagrams):
    """The initiator's IKE_SA_INIT offer and the responder's choice."""
    offer = chosen = None
    for sender, d in datagrams:
        d = d[4:] if d[:4] == b"\x00" * 4 else d  # on port 4500 a four-byte zero marker comes first
        m = ike.sa_init(d) or ike.v1_sa(d)
        if not m:
            continue
        if sender == client and not m["response"] and offer is None:
            offer = m
        elif sender != client and m["response"] and m["proposals"] and chosen is None:
            chosen = m
    return {"offer": offer, "chosen": chosen} if chosen else None


def ssh_session(cbuf, sbuf):
    def kexinit(buf):
        line, _, rest = buf.partition(b"\n")
        if not line.startswith(b"SSH-") or len(rest) < 6:
            return line.strip().decode("ascii", "replace"), None
        plen, pad = struct.unpack(">I", rest[:4])[0], rest[4]
        payload = rest[5:4 + plen - pad]
        if not payload or payload[0] != 20:
            return line.strip().decode("ascii", "replace"), None
        i, lists = 17, []
        for _ in range(6):
            n = struct.unpack(">I", payload[i:i + 4])[0]
            lists.append(payload[i + 4:i + 4 + n].decode("ascii", "replace").split(","))
            i += 4 + n
        return line.strip().decode("ascii", "replace"), lists
    cb, cl = kexinit(cbuf)
    sb, sl = kexinit(sbuf)
    if not cl or not sl:
        return None
    agreed = [next((a for a in c if a in s), None) for c, s in zip(cl, sl)]
    return {"client": cb, "server": sb, "kex": agreed[0], "hostkey": agreed[1], "cipher": agreed[2], "mac": agreed[4],
            "client_pq": [k for k in cl[0] if lookup(k.split("@")[0]) in HYBRIDS]}


def named(server, session):
    """The server as its client named it (SNI), so sites that share an address stay apart; the address when no name was sent."""
    sni = (session.get("client") or {}).get("sni")
    return (sni, server[1]) if sni else server


def scan(path):
    """Detections, endpoint summaries and notes from one capture file."""
    data = Path(path).read_bytes()
    name = Path(path).name
    by_server, skipped, unknown = defaultdict(lambda: {"tls": [], "ssh": [], "quic": [], "ike": [], "dtls": []}), 0, []
    for (client, server), (cbuf, sbuf) in streams(data).items():
        try:  # a capture cut short by its snap length, or a damaged frame, ends that handshake only
            if cbuf[:4] == b"SSH-" or sbuf[:4] == b"SSH-":
                s = ssh_session(cbuf, sbuf)
                if s:
                    by_server[server]["ssh"].append(s)
            elif cbuf[:1] == b"\x16":
                s = tls_session(cbuf, sbuf)
                if s:
                    by_server[named(server, s)]["tls"].append(s)
            elif cbuf or sbuf:
                unknown.append(f"tcp {server[0]}:{server[1]}")
        except (struct.error, IndexError, KeyError, ValueError):
            skipped += 1
    for (client, server), datagrams in flows(data).items():
        kind = "ike" if {client[1], server[1]} & {500, 4500} else "dtls" if is_dtls(datagrams[0][1]) else "quic"
        try:
            s = {"ike": ike_session, "dtls": dtls_session, "quic": quic_session}[kind](client, datagrams)
            if s:
                by_server[named(server, s) if kind != "ike" else server][kind].append(s)
            else:
                unknown.append(f"udp {server[0]}:{server[1]}")
        except (struct.error, IndexError, KeyError, ValueError):
            skipped += 1
    sights, eps = [], []
    for (host, port), seen in sorted(by_server.items()):
        for kind, sessions in seen.items():
            if not sessions:
                continue
            loc = f"pcap://{name}/{host}:{port}" if kind in ("tls", "ssh") else f"pcap://{name}/{kind}/{host}:{port}"

            def add(algo, snip, **p):
                if algo:
                    sights.append(Detection(algo=algo, file=loc, line=0, evidence="live", detector="capture", snippet=snip, lang=kind,
                                           params={k: v for k, v in dict(p, observed=True).items() if v is not None}))
            ep = {"target": loc, "kind": kind, "observed": len(sessions)}
            if kind in ("tls", "quic", "dtls"):
                versions, suites_, groups = set(), set(), set()
                offered_pq = sum(any(pq_from_text(GROUPS.get(g, "")) for g in s["client"]["groups"]) for s in sessions if s["client"])
                for s in sessions:
                    v, base = DTLS.get(s["server"]["version"], (None, None))
                    v = v or VERSIONS.get(s["server"]["version"], hex(s["server"]["version"]))
                    versions.add(v)
                    add(lookup(base or v), f"negotiated {v}" + (f" (the cryptography of {lookup(base)})" if base else ""), negotiated=True)
                    name_ = suite_name(s["server"]["suite"])
                    suites_.add(name_)
                    for a, p in suite(name_):
                        add(a, f"negotiated {name_}", role="cipher-suite", **p)
                    if s.get("dh_bits"):
                        add("DH", f"negotiated DHE with a {s['dh_bits']}-bit prime", role="key-exchange", key_size=s["dh_bits"])
                    g = s["group"]
                    if g is not None:
                        gname = GROUPS.get(g, f"0x{g:04X}")
                        groups.add(gname)
                        a, p = group_algo(gname)
                        add(a, f"negotiated key-exchange group {gname}", role="key-exchange", **p)
                sni = sorted({s["client"]["sni"] for s in sessions if s["client"] and s["client"]["sni"]})
                ep.update(version=", ".join(sorted(versions)), cipher=", ".join(sorted(suites_)), groups=sorted(groups),
                          preferred_group=", ".join(sorted(groups)) or None, pq_groups=sorted(g for g in groups if pq_from_text(g)),
                          sni=sni, clients_offering_pq=offered_pq)
            elif kind == "ike":
                groups, offered_pq = set(), 0
                for s in sessions:
                    for ttype, tid, keylen in (s["chosen"]["proposals"] or [[]])[0]:
                        a, p = ike.name(ttype, tid)
                        if not a:
                            continue
                        p = dict(p, key_size=keylen) if keylen else p
                        label = a + "".join(f"-{v}" for v in p.values() if v)
                        add(a, f"negotiated IKEv{s['chosen'].get('version', 2)} {ike.ROLES.get(ttype, 'transform')}: {label}", role=ike.ROLES.get(ttype), **p)
                        if ike.ROLES.get(ttype, "").endswith("key-exchange"):
                            groups.add(label)
                    offer = (s["offer"] or {}).get("proposals") or []
                    offered_pq += any(ike.name(t, i)[0] in HYBRIDS or ike.name(t, i)[0].startswith("ML-KEM") for prop in offer for t, i, _ in prop
                                      if ike.name(t, i)[0])
                ep.update(version="IKEv2", groups=sorted(groups), preferred_group=", ".join(sorted(groups)) or None,
                          pq_groups=sorted(g for g in groups if g.startswith("ML-KEM")), clients_offering_pq=offered_pq)
            else:
                for s in sessions:
                    for field, role in (("kex", "key-exchange"), ("hostkey", "host-key"), ("cipher", "cipher"), ("mac", "mac")):
                        for a, p in ssh_token(s[field] or ""):
                            if a:
                                add(a, f"negotiated {field}: {s[field]}", role=role, **p)
                ep.update(version=sessions[0]["server"], groups=sorted({s["kex"] for s in sessions if s["kex"]}),
                          preferred_group=sessions[0]["kex"], pq_groups=sorted({s["kex"] for s in sessions if s["kex"] and lookup(s["kex"].split("@")[0]) in HYBRIDS}),
                          clients_offering_pq=sum(bool(s["client_pq"]) for s in sessions))
            eps.append(ep)
    notes = [f"capture {name}: {sum(e['observed'] for e in eps)} handshake(s) with {len(eps)} server(s) read; payloads are encrypted and were not read"]
    if unknown:
        names = sorted(set(unknown))
        notes.append(f"capture {name}: {len(names)} other conversation(s) were not TLS, DTLS, QUIC, SSH or IKE ({', '.join(names[:5])}"
                     + (" and more" if len(names) > 5 else "") + "); any cryptography in them is not reported")
    if skipped:
        notes.append(f"capture {name}: {skipped} handshake(s) cut short or damaged and not read (a capture's snap length may be too small)")
    return sights, eps, notes
