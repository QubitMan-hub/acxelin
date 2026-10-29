import re

from ..catalog import lookup, pq_from_text, curve, parse_symmetric_name

SUITE_HASHES = {"SHA", "SHA1", "SHA256", "SHA384", "MD5"}
KX = {"ECDHE": "ECDH", "ECDH": "ECDH", "EECDH": "ECDH", "DHE": "DH", "EDH": "DH", "DH": "DH", "RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA",
      "KRSA": "RSA", "AECDSA": "ECDSA", "ARSA": "RSA", "KEECDH": "ECDH", "KEDH": "DH"}
KEYWORDS = {"HIGH", "MEDIUM", "LOW", "EXPORT", "DEFAULT", "ALL", "COMPLEMENTOFALL", "COMPLEMENTOFDEFAULT", "ANULL", "ENULL", "NULL",
            "@STRENGTH", "PROFILE=SYSTEM", "@SECLEVEL=0", "@SECLEVEL=1", "@SECLEVEL=2", "SUITEB128", "SUITEB192", "FIPS", "PSK", "SRP", "KRB5", "ADH", "AECDH"}


def suite(name):
    n = name.strip().upper()
    if not n or n.startswith(("!", "-")):
        return []
    n = re.sub(r"^(TLS|SSL)_", "", n).replace("_WITH_", "_")
    toks = [t for t in re.split(r"[-_]", n) if t]
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t in KX:
            out.append((KX[t], {}))
        elif t.startswith("AES"):
            size = t[3:] if t[3:].isdigit() else (toks[i + 1] if i + 1 < len(toks) and toks[i + 1].isdigit() else None)
            if size and not t[3:].isdigit():
                i += 1
            p = {"key_size": int(size)} if size else {}
            if i + 1 < len(toks) and toks[i + 1] in ("GCM", "CBC", "CCM"):
                p["mode"] = toks[i + 1]; i += 1
            elif "GCM" in t:
                p["mode"] = "GCM"
            out.append(("AES", p))
        elif t == "CHACHA20":
            out.append(("ChaCha20-Poly1305", {}))
            if i + 1 < len(toks) and toks[i + 1] == "POLY1305":
                i += 1
        elif t in ("3DES", "DES3") or (t == "DES" and i + 1 < len(toks) and toks[i + 1] in ("CBC3", "EDE3")):
            out.append(("3DES", {}))
            if t == "DES":
                i += 1
        elif t == "DES":
            out.append(("DES", {}))
        elif t in ("RC4", "RC2"):
            out.append((t, {}))
        elif t in SUITE_HASHES and i == len(toks) - 1:
            out.append(("HMAC", {"hash": lookup(t)}))  # the record MAC, or the HMAC-based PRF; the hash itself is carried
        elif t == "AESGCM":
            out.append(("AES", {"mode": "GCM"}))
        i += 1
    return out


def cipher_string(s):
    out = []
    for item in re.split(r"[:,\s]+", s.strip().strip("'\"")):
        if not item or item.startswith(("!", "-")) or item.upper() in KEYWORDS or item.startswith("@"):
            continue
        item = item.lstrip("+")
        if "+" in item:
            for part in item.split("+"):
                u = part.upper()
                if u in KX:
                    out.append((KX[u], {}))
                elif u in ("AESGCM", "AES256", "AES128", "AES"):
                    out.extend(suite(u))
                elif lookup(u):
                    out.append((lookup(u), {}))
            continue
        out.extend(suite(item) or ([(lookup(item), {})] if lookup(item) else []))
    return out


def ssh_token(tok):
    t = tok.strip().lower()
    if not t or t.startswith("-"):
        return []
    t = t.lstrip("+^")
    base = re.sub(r"@(openssh\.com|libssh\.org)$", "", t)
    if pq_from_text(base) or base in ("mlkem768x25519-sha256", "sntrup761x25519-sha512"):
        return [(lookup(t) or lookup(base) or pq_from_text(base), {})]
    m = re.match(r"diffie-hellman-group(\d+|-exchange)-(sha\d+)", base)
    if m:
        size = {"1": 1024, "14": 2048, "15": 3072, "16": 4096, "18": 8192}.get(m.group(1))
        return [("DH", {"key_size": size} if size else {}), (lookup(m.group(2)), {})]
    m = re.match(r"ecdh-sha2-(nistp\d+)", base)
    if m:
        return [("ECDH", {"curve": curve(m.group(1))})]
    m = re.match(r"ecdsa-sha2-(nistp\d+)(-cert-v01)?", base)
    if m:
        return [("ECDSA", {"curve": curve(m.group(1))})]
    if base.startswith("sk-ecdsa"):
        return [("ECDSA", {"curve": "P-256"})]
    if base in ("ssh-rsa", "ssh-rsa-cert-v01"):
        return [("RSA", {"hash": "SHA-1"}), ("SHA-1", {})]
    m = re.match(r"rsa-sha2-(256|512)", base)
    if m:
        return [("RSA", {"hash": f"SHA-{m.group(1)}"}), (f"SHA-{m.group(1)}", {})]
    if "ed25519" in base:
        return [("Ed25519", {})]
    if base.startswith("curve25519"):
        return [("X25519", {})]
    if base.startswith("ssh-dss"):
        return [("DSA", {})]
    m = re.match(r"hmac-(sha2-(256|512)|sha1|md5)(-96)?(-etm)?", base)
    if m:
        h = {"sha1": "SHA-1", "md5": "MD5"}.get(m.group(1)) or f"SHA-{m.group(2)}"
        return [("HMAC", {"hash": h})] + ([(h, {})] if h in ("SHA-1", "MD5") else [])
    if base.startswith("umac"):
        return []
    a, p = parse_symmetric_name(base.replace("-ctr", "-CTR").replace("-gcm", "-GCM").replace("-cbc", "-CBC"))
    return [(a, p)] if a else []


def sig_scheme(s):
    m = re.match(r"(SHA3?-?\d*|MD5|SHA1?)with(RSA|ECDSA|DSA|RSAandMGF1|PLAIN-ECDSA|CVC-ECDSA)", s, re.I)
    if m:
        h = lookup(m.group(1))
        sig = "RSA" if m.group(2).upper().startswith("RSA") else "ECDSA" if "ECDSA" in m.group(2).upper() else "DSA"
        p = {"hash": h} if h else {}
        if "MGF1" in m.group(2).upper():
            p["padding"] = "pss"
        return [(sig, p)] + ([(h, {})] if h else [])
    m = re.match(r"(RSA|ECDSA|DSA)-(SHA\d+|MD5|SHA1)$", s, re.I)
    if m:
        h = lookup(m.group(2))
        return [(m.group(1).upper(), {"hash": h}), (h, {})]
    m = re.match(r"(RS|PS|ES|HS)(256|384|512)$", s)
    if m:
        h = f"SHA-{m.group(2)}"
        algo = {"RS": "RSA", "PS": "RSA", "ES": "ECDSA", "HS": "HMAC"}[m.group(1)]
        p = {"hash": h}
        if m.group(1) == "ES":
            p["curve"] = {"256": "P-256", "384": "P-384", "512": "P-521"}[m.group(2)]
        if m.group(1) == "PS":
            p["padding"] = "pss"
        return [(algo, p), (h, {})]
    if s.upper() == "EDDSA":
        return [("Ed25519", {})]
    a = lookup(s) or pq_from_text(s)
    return [(a, {})] if a else []


NOISE_DH = {"25519": "X25519", "448": "X448"}
NOISE_CIPHER = {"ChaChaPoly": ("ChaCha20-Poly1305", {}), "AESGCM": ("AES", {"mode": "GCM", "key_size": 256})}


def noise_name(s):
    """A Noise Protocol Framework name, such as WireGuard's Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s."""
    m = re.fullmatch(r"Noise_[A-Za-z0-9+]+_(25519|448)_(ChaChaPoly|AESGCM)_(SHA256|SHA512|BLAKE2s|BLAKE2b)", s)
    if not m:
        return []
    cipher, p = NOISE_CIPHER[m.group(2)]
    return [(NOISE_DH[m.group(1)], {}), (cipher, dict(p)), (lookup(m.group(3)), {})]


def jose_alg(s):
    """A JOSE (JWE/JWA) identifier: A256GCM, A128CBC-HS256, A128KW, PBES2-HS512+A256KW, RSA-OAEP-256, RSA1_5, ECDH-ES+A128KW."""
    out = []
    for part in s.split("+"):
        m = re.fullmatch(r"A(128|192|256)(GCM|KW|GCMKW|CBC-HS(256|384|512))", part)
        if m:
            out.append(("AES", {"key_size": int(m.group(1)), "mode": "CBC" if m.group(3) else "GCM" if "GCM" in m.group(2) else "KW"}))
            if m.group(3):
                out.append(("HMAC", {"hash": f"SHA-{m.group(3)}"}))
            continue
        m = re.fullmatch(r"PBES2-HS(256|384|512)", part)
        if m:
            out.append(("PBKDF2", {"hash": f"SHA-{m.group(1)}"}))
            continue
        m = re.fullmatch(r"RSA-OAEP(?:-(256|384|512))?|RSA1_5", part)
        if m:
            out.append(("RSA", {"padding": "pkcs1v15" if part == "RSA1_5" else "oaep", "hash": f"SHA-{m.group(1)}" if m.group(1) else "SHA-1" if part != "RSA1_5" else None}))
            continue
        if part == "ECDH-ES":
            out.append(("ECDH", {}))
            continue
        return []
    return out


def kms_spec(v):
    """Key specs of cloud KMS and HSM services: AWS KMS (RSA_2048, ECC_NIST_P256, SYMMETRIC_DEFAULT, HMAC_256, ML_DSA_65),
    Google Cloud KMS (RSA_SIGN_PSS_2048_SHA256, EC_SIGN_P256_SHA256, GOOGLE_SYMMETRIC_ENCRYPTION) and Azure Key Vault (RSA-HSM, EC)."""
    v = v.strip().strip("\"'").upper()
    sha = lambda b: {"1": "SHA-1"}.get(b, f"SHA-{b}")
    m = re.fullmatch(r"(?:RSA_(?:SIGN_(?:PSS|PKCS1|RAW_PKCS1)|DECRYPT_OAEP)_(\d{4})(?:_SHA(\d+))?|RSA_(\d{4}))", v)
    if m:
        bits, h = m.group(1) or m.group(3), m.group(2)
        return [("RSA", {"key_size": int(bits), "hash": sha(h) if h else None})] + ([(sha(h), {})] if h else [])
    m = re.fullmatch(r"EC(?:C_NIST|_SIGN)_P(256|384|521)(?:_SHA(\d+))?", v)
    if m:
        algo = "ECDSA" if "SIGN" in v else "ECC"
        return [(algo, {"curve": f"P-{m.group(1)}"})] + ([(sha(m.group(2)), {})] if m.group(2) else [])
    if re.fullmatch(r"ECC_SECG_P256K1|EC_SIGN_SECP256K1_SHA256", v):
        return [("ECDSA" if "SIGN" in v else "ECC", {"curve": "secp256k1"})] + ([("SHA-256", {})] if "SHA256" in v else [])
    if v == "EC_SIGN_ED25519":
        return [("Ed25519", {})]
    if v in ("SYMMETRIC_DEFAULT", "GOOGLE_SYMMETRIC_ENCRYPTION", "AES_256_GCM"):
        return [("AES", {"key_size": 256, "mode": "GCM"})]
    m = re.fullmatch(r"AES_(128|256)_(GCM|CBC|CTR)", v)
    if m:
        return [("AES", {"key_size": int(m.group(1)), "mode": m.group(2)})]
    m = re.fullmatch(r"HMAC_(?:SHA)?(1|224|256|384|512)", v)
    if m:
        return [("HMAC", {"hash": sha(m.group(1))}), (sha(m.group(1)), {})]
    m = re.fullmatch(r"(?:PQ_SIGN_)?ML_DSA_(44|65|87)", v)
    if m:
        return [(f"ML-DSA-{m.group(1)}", {})]
    m = re.fullmatch(r"ML_KEM_(512|768|1024)", v)
    if m:
        return [(f"ML-KEM-{m.group(1)}", {})]
    if re.fullmatch(r"PQ_SIGN_SLH_DSA_\w+", v):
        return [("SLH-DSA", {})]
    if v in ("RSA-HSM", "EC-HSM", "SM2"):
        return [({"RSA-HSM": "RSA", "EC-HSM": "ECC", "SM2": "SM2"}[v], {})]
    return []
