import re
from dataclasses import dataclass

SHOR, LEGACY, GROVER, SAFE = "shor", "legacy", "grover", "safe"
HYBRIDS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "sntrup761x25519"}


@dataclass(frozen=True)
class Algo:
    name: str
    family: str
    primitive: str
    threat: str
    bits: int | None = None
    level: int | None = None
    oid: str | None = None
    replace: str = ""


def _a(*args, **kw):
    a = Algo(*args, **kw)
    return a.name, a


CATALOG = dict([
    _a("RSA", "RSA", "pke", SHOR, oid="1.2.840.113549.1.1.1", replace="ML-KEM-768 for encryption, ML-DSA-65 for signatures"),
    _a("DSA", "DSA", "signature", LEGACY, oid="1.2.840.10040.4.1", replace="ML-DSA-65"),
    _a("DH", "DH", "key-agree", SHOR, oid="1.2.840.113549.1.3.1", replace="X25519MLKEM768 hybrid or ML-KEM-768"),
    _a("ECC", "ECC", "other", SHOR, oid="1.2.840.10045.2.1", replace="ML-DSA-65 or ML-KEM-768 depending on use"),
    _a("ECDSA", "ECDSA", "signature", SHOR, replace="ML-DSA-65 (or hybrid ECDSA+ML-DSA during transition)"),
    _a("ECDH", "ECDH", "key-agree", SHOR, replace="X25519MLKEM768 hybrid"),
    _a("Ed25519", "Ed25519", "signature", SHOR, 128, oid="1.3.101.112", replace="ML-DSA-44 or ML-DSA-65"),
    _a("Ed448", "Ed448", "signature", SHOR, 224, oid="1.3.101.113", replace="ML-DSA-87"),
    _a("X25519", "X25519", "key-agree", SHOR, 128, oid="1.3.101.110", replace="X25519MLKEM768 hybrid"),
    _a("X448", "X448", "key-agree", SHOR, 224, oid="1.3.101.111", replace="ML-KEM-1024"),
    _a("ML-KEM-512", "ML-KEM", "kem", SAFE, 128, 1, "2.16.840.1.101.3.4.4.1"),
    _a("ML-KEM-768", "ML-KEM", "kem", SAFE, 192, 3, "2.16.840.1.101.3.4.4.2"),
    _a("ML-KEM-1024", "ML-KEM", "kem", SAFE, 256, 5, "2.16.840.1.101.3.4.4.3"),
    _a("ML-KEM", "ML-KEM", "kem", SAFE),
    _a("ML-DSA-44", "ML-DSA", "signature", SAFE, 128, 2, "2.16.840.1.101.3.4.3.17"),
    _a("ML-DSA-65", "ML-DSA", "signature", SAFE, 192, 3, "2.16.840.1.101.3.4.3.18"),
    _a("ML-DSA-87", "ML-DSA", "signature", SAFE, 256, 5, "2.16.840.1.101.3.4.3.19"),
    _a("ML-DSA", "ML-DSA", "signature", SAFE),
    _a("SLH-DSA", "SLH-DSA", "signature", SAFE),
    _a("FN-DSA", "FN-DSA", "signature", SAFE),
    _a("HQC", "HQC", "kem", SAFE),
    _a("X25519MLKEM768", "X25519MLKEM768", "kem", SAFE, 192, 3),
    _a("sntrup761x25519", "sntrup761x25519", "kem", SAFE, 128),
    _a("SecP256r1MLKEM768", "SecP256r1MLKEM768", "kem", SAFE, 192, 3),
    _a("SecP384r1MLKEM1024", "SecP384r1MLKEM1024", "kem", SAFE, 256, 5),
    _a("AES", "AES", "block-cipher", GROVER, replace="AES-256"),
    _a("ChaCha20-Poly1305", "ChaCha20", "ae", SAFE, 256, 5),
    _a("ChaCha20", "ChaCha20", "stream-cipher", SAFE, 256, 5),
    _a("Salsa20", "Salsa20", "stream-cipher", SAFE, 256, 5),
    _a("AEGIS-128L", "AEGIS-128L", "ae", GROVER, 128, replace="AEGIS-256"),
    _a("AEGIS-256", "AEGIS-256", "ae", SAFE, 256, 5),
    _a("SM2", "SM2", "pke", SHOR, 128, replace="ML-KEM-768 for encryption and key exchange, ML-DSA-65 for signatures"),
    _a("SM3", "SM3", "hash", SAFE, 128, 2),
    _a("SM4", "SM4", "block-cipher", GROVER, 128, replace="AES-256, or SM4 only where regulation requires it"),
    _a("SHA-3", "SHA-3", "hash", SAFE, 128, 2),
    _a("3DES", "3DES", "block-cipher", LEGACY, 112, oid="1.2.840.113549.3.7", replace="AES-256-GCM"),
    _a("DES", "DES", "block-cipher", LEGACY, 56, replace="AES-256-GCM"),
    _a("RC4", "RC4", "stream-cipher", LEGACY, replace="AES-256-GCM or ChaCha20-Poly1305"),
    _a("RC2", "RC2", "block-cipher", LEGACY, replace="AES-256-GCM"),
    _a("Blowfish", "Blowfish", "block-cipher", LEGACY, replace="AES-256-GCM"),
    _a("MD2", "MD2", "hash", LEGACY, oid="1.2.840.113549.2.2", replace="SHA-256 or SHA3-256"),
    _a("MD4", "MD4", "hash", LEGACY, replace="SHA-256 or SHA3-256"),
    _a("MD5", "MD5", "hash", LEGACY, oid="1.2.840.113549.2.5", replace="SHA-256 or SHA3-256"),
    _a("SHA-1", "SHA-1", "hash", LEGACY, oid="1.3.14.3.2.26", replace="SHA-256 or SHA3-256"),
    _a("RIPEMD-160", "RIPEMD-160", "hash", LEGACY, oid="1.3.36.3.2.1", replace="SHA-256 or SHA3-256"),
    _a("SHA-224", "SHA-224", "hash", GROVER, 112, oid="2.16.840.1.101.3.4.2.4", replace="SHA-256 or larger"),
    _a("SHA-256", "SHA-256", "hash", SAFE, 128, 2, "2.16.840.1.101.3.4.2.1"),
    _a("SHA-384", "SHA-384", "hash", SAFE, 192, 4, "2.16.840.1.101.3.4.2.2"),
    _a("SHA-512", "SHA-512", "hash", SAFE, 256, 5, "2.16.840.1.101.3.4.2.3"),
    _a("SHA-512/224", "SHA-512", "hash", GROVER, 112, oid="2.16.840.1.101.3.4.2.5", replace="SHA-512/256, SHA-256 or larger"),  # output, not state, sets strength
    _a("SHA-512/256", "SHA-512", "hash", SAFE, 128, 2, "2.16.840.1.101.3.4.2.6"),
    _a("SHA3-224", "SHA3-224", "hash", GROVER, 112, oid="2.16.840.1.101.3.4.2.7", replace="SHA3-256 or larger"),
    _a("SHA3-256", "SHA3-256", "hash", SAFE, 128, 2, "2.16.840.1.101.3.4.2.8"),
    _a("SHA3-384", "SHA3-384", "hash", SAFE, 192, 4, "2.16.840.1.101.3.4.2.9"),
    _a("SHA3-512", "SHA3-512", "hash", SAFE, 256, 5, "2.16.840.1.101.3.4.2.10"),
    _a("BLAKE2", "BLAKE2", "hash", SAFE, 128),
    _a("HMAC", "HMAC", "mac", SAFE),
    _a("PBKDF2", "PBKDF2", "kdf", SAFE),
    _a("HKDF", "HKDF", "kdf", SAFE),
    _a("scrypt", "scrypt", "kdf", SAFE),
    _a("Argon2", "Argon2", "kdf", SAFE),
    _a("bcrypt", "bcrypt", "kdf", SAFE),
    _a("ConcatKDF", "ConcatKDF", "kdf", SAFE),
    _a("ANSI-X9.63-KDF", "ANSI-X9.63-KDF", "kdf", SAFE),
    _a("BalloonHashing", "BalloonHashing", "kdf", SAFE),
    _a("SPAKE2", "SPAKE2", "key-agree", SHOR, replace="A post-quantum PAKE when one is standardised; meanwhile a hybrid with ML-KEM"),
    _a("SSL 2.0", "SSL 2.0", "protocol", LEGACY, replace="TLS 1.3 with X25519MLKEM768"),
    _a("SSL 3.0", "SSL 3.0", "protocol", LEGACY, replace="TLS 1.3 with X25519MLKEM768"),
    _a("TLS 1.0", "TLS 1.0", "protocol", LEGACY, replace="TLS 1.3 with X25519MLKEM768"),
    _a("TLS 1.1", "TLS 1.1", "protocol", LEGACY, replace="TLS 1.3 with X25519MLKEM768"),
    _a("TLS 1.2", "TLS 1.2", "protocol", SHOR, replace="TLS 1.3 with X25519MLKEM768"),
    _a("TLS 1.3", "TLS 1.3", "protocol", SHOR, replace="Enable X25519MLKEM768 key exchange group"),
])

_ALIASES = {
    "RSA": ["RSA", "RSAES", "RSASSA", "RSAOAEP", "RSAPSS", "RSAES-OAEP", "RSASSA-PSS", "RSASSA-PKCS1-V1_5", "PS256", "PS384", "PS512",
            "RS256", "RS384", "RS512", "SSH-RSA", "RSA-SHA2-256", "RSA-SHA2-512", "EVP_PKEY_RSA", "RSAPUBLICKEY", "RSAPRIVATEKEY"],
    "DSA": ["DSA", "DSS", "SSH-DSS", "EVP_PKEY_DSA"],
    "DH": ["DH", "DIFFIEHELLMAN", "DHE", "EDH", "FFDHE2048", "FFDHE3072", "FFDHE4096", "EVP_PKEY_DH",
           "DIFFIE-HELLMAN-GROUP14-SHA256", "DIFFIE-HELLMAN-GROUP16-SHA512", "DIFFIE-HELLMAN-GROUP-EXCHANGE-SHA256"],
    "ECC": ["EC", "ECC", "EVP_PKEY_EC", "ELLIPTICCURVE"],
    "ECDSA": ["ECDSA", "ES256", "ES384", "ES512", "ECDSA-SHA2-NISTP256", "ECDSA-SHA2-NISTP384", "ECDSA-SHA2-NISTP521"],
    "ECDH": ["ECDH", "ECDHE", "ECMQV", "ECDH-SHA2-NISTP256", "ECDH-SHA2-NISTP384", "ECDH-SHA2-NISTP521"],
    "Ed25519": ["ED25519", "EDDSA", "SSH-ED25519", "EVP_PKEY_ED25519"],
    "Ed448": ["ED448", "EVP_PKEY_ED448"],
    "X25519": ["X25519", "CURVE25519", "CURVE25519-SHA256", "CURVE25519-SHA256@LIBSSH.ORG", "EVP_PKEY_X25519"],
    "X448": ["X448", "EVP_PKEY_X448"],
    "ML-KEM-512": ["MLKEM512", "ML-KEM-512", "KYBER512"],
    "ML-KEM-768": ["MLKEM768", "ML-KEM-768", "KYBER768"],
    "ML-KEM-1024": ["MLKEM1024", "ML-KEM-1024", "KYBER1024"],
    "ML-KEM": ["MLKEM", "ML-KEM", "KYBER"],
    "ML-DSA-44": ["MLDSA44", "ML-DSA-44", "DILITHIUM2"],
    "ML-DSA-65": ["MLDSA65", "ML-DSA-65", "DILITHIUM3"],
    "ML-DSA-87": ["MLDSA87", "ML-DSA-87", "DILITHIUM5"],
    "ML-DSA": ["MLDSA", "ML-DSA", "DILITHIUM"],
    "SLH-DSA": ["SLHDSA", "SLH-DSA", "SPHINCS+", "SPHINCSPLUS"],
    "FN-DSA": ["FNDSA", "FN-DSA", "FALCON", "FALCON512", "FALCON1024"],
    "HQC": ["HQC", "HQC128", "HQC192", "HQC256"],
    "X25519MLKEM768": ["X25519MLKEM768", "X25519_MLKEM768", "MLKEM768X25519", "MLKEM768X25519-SHA256", "X25519KYBER768DRAFT00"],
    "SecP256r1MLKEM768": ["SECP256R1MLKEM768", "P256MLKEM768"],
    "SecP384r1MLKEM1024": ["SECP384R1MLKEM1024", "P384MLKEM1024"],
    "sntrup761x25519": ["SNTRUP761X25519-SHA512", "SNTRUP761X25519-SHA512@OPENSSH.COM"],
    "AES": ["AES", "AES128", "AES192", "AES256", "AESGCM", "AESCCM", "AESSIV", "AESOCB3", "RIJNDAEL", "AESWRAP"],
    "ChaCha20-Poly1305": ["CHACHA20-POLY1305", "CHACHA20POLY1305", "CHACHA20-POLY1305@OPENSSH.COM", "XCHACHA20POLY1305"],
    "ChaCha20": ["CHACHA20", "XCHACHA20"],
    "Salsa20": ["SALSA20", "XSALSA20", "XSALSA20POLY1305"],
    "AEGIS-128L": ["AEGIS128L", "AEGIS-128L"],
    "AEGIS-256": ["AEGIS256", "AEGIS-256"],
    "SM2": ["SM2"],
    "SM3": ["SM3"],
    "SM4": ["SM4", "SMS4"],
    "SHA-3": ["SHA3", "KECCAK"],
    "3DES": ["3DES", "DESEDE", "TRIPLEDES", "DES3", "DES-EDE3", "DES-EDE3-CBC", "DES_EDE3", "DES-CBC3", "3DES-CBC", "TDEA"],
    "DES": ["DES", "DES-CBC", "DES-ECB", "SINGLEDES"],
    "RC4": ["RC4", "ARC4", "ARCFOUR", "ARCFOUR128", "ARCFOUR256"],
    "RC2": ["RC2", "ARC2"],
    "Blowfish": ["BLOWFISH", "BF", "BF-CBC"],
    "MD2": ["MD2"],
    "MD4": ["MD4"],
    "RIPEMD-160": ["RIPEMD160", "RIPEMD-160", "RMD160"],
    "MD5": ["MD5"],
    "SHA-1": ["SHA1", "SHA-1", "SHA", "SHA1PRNG"],
    "SHA-224": ["SHA224", "SHA-224"],
    "SHA-256": ["SHA256", "SHA-256", "SHA2", "SHA-2"],
    "SHA-384": ["SHA384", "SHA-384"],
    "SHA-512": ["SHA512", "SHA-512"],
    "SHA-512/224": ["SHA512/224", "SHA-512/224", "SHA512_224", "SHA512-224", "SHA-512-224"],
    "SHA-512/256": ["SHA512/256", "SHA-512/256", "SHA512_256", "SHA512-256", "SHA-512-256"],
    "SHA3-224": ["SHA3-224", "SHA3_224", "SHA3224"],
    "SHA3-256": ["SHA3-256", "SHA3_256", "SHA3256"],
    "SHA3-384": ["SHA3-384", "SHA3_384", "SHA3384"],
    "SHA3-512": ["SHA3-512", "SHA3_512", "SHA3512"],
    "BLAKE2": ["BLAKE2B", "BLAKE2S", "BLAKE2", "BLAKE2B512", "BLAKE2S256"],
    "HMAC": ["HMAC", "HS256", "HS384", "HS512", "HMACSHA1", "HMAC-SHA1", "HMACMD5", "HMAC-MD5", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMAC-SHA256", "HMAC-SHA2-256", "HMAC-SHA2-512"],
    "PBKDF2": ["PBKDF2", "PBKDF2WITHHMACSHA256", "PBKDF2WITHHMACSHA1", "PBKDF2HMAC", "PBKDF2_HMAC"],
    "HKDF": ["HKDF"],
    "scrypt": ["SCRYPT"],
    "Argon2": ["ARGON2", "ARGON2ID", "ARGON2I", "ARGON2D"],
    "bcrypt": ["BCRYPT"],
    "ConcatKDF": ["CONCATKDF", "CONCAT-KDF"],
    "ANSI-X9.63-KDF": ["ANSIX963KDF", "X963KDF", "ANSI-X9.63-KDF"],
    "BalloonHashing": ["BALLOONHASHING", "BALLOON"],
    "SPAKE2": ["SPAKE2", "SPAKE2PLUS"],
    "SSL 2.0": ["SSLV2", "SSL2", "PROTOCOL_SSLV2"],
    "SSL 3.0": ["SSLV3", "SSL3", "PROTOCOL_SSLV3"],
    "TLS 1.0": ["TLSV1", "TLSV1.0", "TLS1", "TLS1.0", "TLS10", "VERSIONTLS10", "PROTOCOL_TLSV1", "TLSV1_0", "TLS1_VERSION"],
    "TLS 1.1": ["TLSV1.1", "TLS1.1", "TLS11", "VERSIONTLS11", "PROTOCOL_TLSV1_1", "TLSV1_1", "TLS1_1_VERSION"],
    "TLS 1.2": ["TLSV1.2", "TLS1.2", "TLS12", "VERSIONTLS12", "PROTOCOL_TLSV1_2", "TLSV1_2", "TLS1_2_VERSION"],
    "TLS 1.3": ["TLSV1.3", "TLS1.3", "TLS13", "VERSIONTLS13", "TLSV1_3", "TLS1_3_VERSION"],
}
ALIAS = {a.upper(): k for k, v in _ALIASES.items() for a in v}
AMBIGUOUS = {"SHA", "EC", "BF", "DSS", "DH", "SHA2", "SHA-2", "TLS1", "DES", "P-256"}

CURVES = {"P-256": (128, "secp256r1 prime256v1 P256 nistp256 X9_62_prime256v1"), "P-384": (192, "secp384r1 P384 nistp384"),
          "P-521": (256, "secp521r1 P521 nistp521"), "P-224": (112, "secp224r1 P224"), "P-192": (80, "secp192r1 prime192v1"),
          "secp256k1": (128, ""), "brainpoolP256r1": (128, "")}
_norm = lambda s: re.sub(r"[^A-Z0-9]", "", s.upper())
CURVE_OF = {_norm(a): c for c, (_, names) in CURVES.items() for a in [c, *names.split()]}
_flat = lambda s: re.sub(r"[-_\s/.]", "", s)
FLAT_ALIAS: dict[str, str] = {}
for _k, _v in ALIAS.items():
    FLAT_ALIAS.setdefault(_flat(_k), _v)

MODES = {"ECB", "CBC", "CCM", "GCM", "CFB", "OFB", "CTR", "SIV", "OCB", "XTS", "EAX", "CFB8", "OCB3", "KW"}
PADDINGS = {"PKCS1PADDING": "pkcs1v15", "PKCS1": "pkcs1v15", "PKCS1V15": "pkcs1v15", "OAEP": "oaep", "PKCS5PADDING": "pkcs5",
            "PKCS7": "pkcs7", "PKCS7PADDING": "pkcs7", "NOPADDING": "raw", "OAEPWITHSHA-256ANDMGF1PADDING": "oaep", "OAEPPADDING": "oaep"}


def lookup(token):
    if not token:
        return None
    t = token.strip().strip("'\"`").upper()
    return ALIAS.get(t) or ALIAS.get(re.sub(r"[\s_]", "-", t)) or FLAT_ALIAS.get(_flat(t))


def pq_from_text(text):
    m = re.search(r"ml[-_]?kem[-_]?(512|768|1024)|kyber[-_]?(512|768|1024)", text, re.I)
    if m:
        return f"ML-KEM-{m.group(1) or m.group(2)}"
    m = re.search(r"ml[-_]?dsa[-_]?(44|65|87)", text, re.I)
    if m:
        return f"ML-DSA-{m.group(1)}"
    m = re.search(r"dilithium[-_]?([235])", text, re.I)
    if m:
        return {"2": "ML-DSA-44", "3": "ML-DSA-65", "5": "ML-DSA-87"}[m.group(1)]
    if re.search(r"slh[-_]?dsa|sphincs", text, re.I):
        return "SLH-DSA"
    if re.search(r"fn[-_]?dsa|falcon", text, re.I):
        return "FN-DSA"
    return None


def named_hash(name):
    """The hash inside names like HmacSHA256, HMAC-SHA-512 or PBKDF2WithHmacSHA1."""
    m = re.search(r"(?i)hmac[-_]?(sha3[-_]?(?:224|256|384|512)|sha[-_]?(?:1|224|256|384|512)|md5)(?!\d)", name)
    return lookup(m.group(1)) if m else None


def parse_transformation(s):
    parts = s.split("/")
    algo = lookup(parts[0]) or pq_from_text(parts[0])
    params = {"hash": named_hash(parts[0])} if algo in ("HMAC", "PBKDF2") and named_hash(parts[0]) else {}
    m = re.search(r"(128|192|256)", parts[0])
    if algo == "AES" and m:
        params["key_size"] = int(m.group(1))
    if len(parts) > 1 and parts[1].upper() in MODES and (algo not in CATALOG or CATALOG[algo].primitive == "block-cipher"):  # Java names RSA "RSA/ECB": one block, no mode
        params["mode"] = parts[1].upper()
    if len(parts) > 2:
        p = PADDINGS.get(parts[2].upper().replace(" ", ""))
        if p:
            params["padding"] = p
    return algo, params


def parse_symmetric_name(s):
    """Parses names like aes-256-gcm, AES_128_CBC, des-ede3-cbc, EVP_aes_128_ecb."""
    s0 = re.sub(r"^EVP_", "", s, flags=re.I)
    toks = [t for t in re.split(r"[-_\s]", s0) if t]
    if not toks:
        return None, {}
    head = toks[0].upper()
    params = {}
    if head.startswith("AES"):
        algo = "AES"
        m = re.search(r"(128|192|256)", s0)
        if m:
            params["key_size"] = int(m.group(1))
    elif head == "CHACHA20" and any(t.upper() == "POLY1305" for t in toks):
        algo = "ChaCha20-Poly1305"
    else:
        algo = "3DES" if len(toks) > 1 and lookup("-".join(toks[:2])) == "3DES" else lookup(head)
    for t in toks[1:]:
        if t.upper() in MODES:
            params["mode"] = t.upper()
    return algo, params


def curve(name):
    k = _norm(name or "")
    return CURVE_OF.get(k[3:] if k.startswith("NID") else k)


def classical_bits(algo, params):
    a = CATALOG.get(algo)
    if algo in ("RSA", "DSA", "DH"):
        n = params.get("key_size")
        if not n:
            return None
        return 80 if n < 2048 else 112 if n < 3072 else 128 if n < 7680 else 192 if n < 15360 else 256
    if algo in ("ECC", "ECDSA", "ECDH"):
        return CURVES.get(params.get("curve"), (None,))[0]
    if algo == "AES":
        return params.get("key_size")
    return a.bits if a else None


def quantum_level(algo, params):
    a = CATALOG.get(algo)
    if not a:
        return None
    if a.threat in (SHOR, LEGACY):
        return 0
    if algo == "AES":
        return {128: 1, 192: 3, 256: 5}.get(params.get("key_size"))
    return a.level


def variant(algo, p):
    if algo in ("RSA", "DSA", "DH") and p.get("key_size"):
        return f"{algo}-{p['key_size']}"
    if algo in ("ECC", "ECDSA", "ECDH") and p.get("curve"):
        return f"{algo}-{p['curve']}"
    if algo == "AES":
        return "-".join(str(x) for x in ("AES", p.get("key_size"), p.get("mode")) if x)
    if algo in ("HMAC", "PBKDF2") and p.get("hash"):
        return f"{algo}-{p['hash']}"
    return algo


def nist_status(algo, params):
    a = CATALOG.get(algo)
    if not a:
        return ""
    bits = classical_bits(algo, params)
    if a.threat == LEGACY or (bits is not None and bits < 112):
        return "Disallowed now (NIST SP 800-131A)"
    if a.threat == SHOR:
        if a.primitive == "protocol":
            return "Classical key exchange: quantum-vulnerable; NIST IR 8547 disallows it after 2035"
        if bits == 112:
            return "Deprecated after 2030, disallowed after 2035 (NIST IR 8547)"
        return "Disallowed after 2035 (NIST IR 8547)"
    if str(params.get("mode", "")).upper() == "ECB":
        return "Unsafe mode: ECB shows patterns in the data; use GCM (NIST SP 800-38D)"
    if a.threat == GROVER and (bits or 0) < 256:
        return "Acceptable, but prefer 256-bit strength for long-term data"
    return "Quantum-safe"
