"""Shadow mode: read what a client's ClientHello offers and say whether `strict` or `cnsa2` would refuse it.

Only the groups, the signature schemes and the cipher suites are kept. The server name, the random, the session id, the key shares
and every other extension are skipped, and names come from the tables below, so a client cannot put its own text in the log."""
import re

LIMIT = 40  # entries kept per list; the rest of a long list is only counted
UNKNOWN = 16  # of them, codes this table does not know, shown in hex

GROUPS = {0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001E: "x448", 0x0100: "ffdhe2048",
          0x0101: "ffdhe3072", 0x0102: "ffdhe4096", 0x0103: "ffdhe6144", 0x0104: "ffdhe8192", 0x0200: "MLKEM512", 0x0201: "MLKEM768",
          0x0202: "MLKEM1024", 0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024"}
SIGALGS = {0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512", 0x0403: "ecdsa_secp256r1_sha256",
           0x0503: "ecdsa_secp384r1_sha384", 0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
           0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256", 0x0904: "mldsa44",
           0x0905: "mldsa65", 0x0906: "mldsa87"}
SUITES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256"}

STRICT_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}  # policies.PQC_GROUPS
CNSA2_GROUPS = {"SecP384r1MLKEM1024", "MLKEM1024"}
ML_DSA = {"mldsa44", "mldsa65", "mldsa87"}


def _name(value, table):
    if value & 0x0F0F == 0x0A0A:
        return "grease"  # RFC 8701 values clients add to keep servers honest
    return table.get(value)


def _names(values, table):
    out, unknown, more = [], 0, 0
    for v in values:
        n = _name(v, table)
        if n is None:
            if unknown >= UNKNOWN:
                more += 1
                continue
            unknown, n = unknown + 1, f"0x{v:04x}"
        if n not in out:
            out.append(n)
    return out + ([f"+{more}"] if more else [])


def _pairs(data):
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data) - 1, 2)]


def parse(record):
    """{"groups", "sigalgs", "suites"} (names) from one TLS record holding a ClientHello, or None when it is anything else or damaged."""
    try:
        if len(record) < 9 or record[0] != 0x16 or int.from_bytes(record[3:5], "big") != len(record) - 5:
            return None
        hs = record[5:]
        if hs[0] != 1 or int.from_bytes(hs[1:4], "big") != len(hs) - 4:
            return None
        body, pos = hs[4:], 34
        pos += 1 + body[pos]
        size = int.from_bytes(body[pos:pos + 2], "big")
        suites = _pairs(body[pos + 2:pos + 2 + size])
        pos += 2 + size
        pos += 1 + body[pos]
        total = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        if pos + total != len(body) or size % 2:
            return None
        groups, sigalgs = [], []
        end = pos + total
        while pos < end:
            kind, length = int.from_bytes(body[pos:pos + 2], "big"), int.from_bytes(body[pos + 2:pos + 4], "big")
            data = body[pos + 4:pos + 4 + length]
            if len(data) != length:
                return None
            if kind in (10, 13):
                if len(data) < 2 or int.from_bytes(data[:2], "big") != len(data) - 2:
                    return None
                (groups if kind == 10 else sigalgs).extend(_pairs(data[2:]))
            pos += 4 + length
        return {"groups": _names(groups, GROUPS), "sigalgs": _names(sigalgs, SIGALGS), "suites": _names(suites, SUITES)}
    except (IndexError, ValueError):
        return None


def reasons(policy, offered):
    """Why `policy` ("strict" or "cnsa2") would refuse a client that offered `offered` (from parse); empty when it would accept."""
    groups, sigalgs, suites = set(offered["groups"]), set(offered["sigalgs"]), set(offered["suites"])
    if policy == "cnsa2":
        return [text for ok, text in ((groups & CNSA2_GROUPS, "no ML-KEM-1024 key exchange offered"),
                                      ("mldsa87" in sigalgs, "cannot verify ML-DSA-87 certificates"),
                                      ("TLS_AES_256_GCM_SHA384" in suites, "no AES-256-GCM cipher suite offered")) if not ok]
    return [text for ok, text in ((groups & STRICT_GROUPS, "no post-quantum key exchange offered"),
                                  (sigalgs & ML_DSA, "cannot verify ML-DSA certificates")) if not ok]


def slug(reason):
    return re.sub(r"[^a-z0-9]+", "_", reason.lower()).strip("_")
