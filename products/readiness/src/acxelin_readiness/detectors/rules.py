import re
from collections.abc import Callable

from ..catalog import lookup, pq_from_text, curve, parse_transformation, parse_symmetric_name
from .suites import sig_scheme, cipher_string

Q = r"""['"`]"""
RULES: dict[str, list[tuple[re.Pattern[str], Callable]]] = {}


def rule(langs, pattern):
    rx = re.compile(pattern)

    def deco(fn):
        for l in langs.split():
            RULES.setdefault(l, []).append((rx, fn))
        return fn
    return deco


def simple(langs, pattern, what=None, **params):
    """A rule with no logic. `what` is an algorithm, a tuple of them, a {last group: algorithm(s)} map, or None to look the last group up."""
    def fn(m, x):
        g = m.group(m.lastindex) if m.lastindex else None
        v = (lookup(g) or pq_from_text(g)) if what is None else what.get(g) if isinstance(what, dict) else what
        return [(a, dict(params)) for a in ((v,) if isinstance(v, str) else v or ()) if a]
    rule(langs, pattern)(fn)


# JVM
@rule("java", r'Cipher\.getInstance\(\s*"([^"]+)"(?=\s*[,)])')
def _(m, x):
    return [parse_transformation(m.group(1))]


@rule("java", r'\b(KeyPairGenerator|KeyGenerator|KeyAgreement|KeyFactory|MessageDigest|Mac|SecretKeyFactory|KEM)\.getInstance\(\s*"([^"]+)"(?=\s*[,)])')
def _(m, x):
    kind, s = m.group(1), m.group(2)
    if kind == "Mac":
        h = re.match(r"Hmac(\w+)", s, re.I)
        return [("HMAC", {"hash": lookup(h.group(1)) if h else None})]
    if kind == "SecretKeyFactory" and s.upper().startswith("PBKDF2"):
        h = re.search(r"Hmac(\w+)", s, re.I)
        return [("PBKDF2", {"hash": lookup(h.group(1)) if h else None})]
    if kind == "KeyGenerator" and s.lower().startswith("hmac"):
        return [("HMAC", {"hash": lookup(s[4:])})]
    a = lookup(s) or pq_from_text(s) or parse_transformation(s)[0]
    return [("ECDH" if kind == "KeyAgreement" and a == "ECC" else a, {})]


@rule("java", r'\bSignature\.getInstance\(\s*"([^"]+)"(?=\s*[,)])')
def _(m, x):
    return sig_scheme(m.group(1))


@rule("java", r'\.initialize\(\s*(\d{3,5})\b')
def _(m, x):
    x.attach({"key_size": int(m.group(1))}, ("RSA", "DSA", "DH", "ECC"))


@rule("java", r'\.init\(\s*(128|192|256)\s*[,)]')
def _(m, x):
    x.attach({"key_size": int(m.group(1))}, ("AES",))


@rule("java", r'new\s+(?:[\w$]+\.)*ECGenParameterSpec\(\s*"([^"]+)"')
def _(m, x):
    x.attach({"curve": curve(m.group(1))}, ("ECC", "ECDSA", "ECDH"))


@rule("java", r'new\s+(?:[\w$]+\.)*SecretKeySpec\([^;]*?,\s*"([^"]+)"\s*\)')
def _(m, x):
    return [parse_transformation(m.group(1))]


simple("java", r'SSLContext\.getInstance\(\s*"([^"]+)"')


@rule("java", r'setEnabledProtocols\((.*)\)')
def _(m, x):
    return [(lookup(v), {}) for v in re.findall(r'"(TLSv1(?:\.\d)?|SSLv3)"', m.group(1))]


BC = {"RSAKeyPairGenerator": "RSA", "RSAEngine": "RSA", "RSADigestSigner": "RSA", "ECKeyPairGenerator": "ECC", "ECDSASigner": "ECDSA",
      "ECDHBasicAgreement": "ECDH", "AESEngine": "AES", "AESFastEngine": "AES", "DESedeEngine": "3DES", "DESEngine": "DES", "RC4Engine": "RC4",
      "BlowfishEngine": "Blowfish", "MD5Digest": "MD5", "SHA1Digest": "SHA-1", "SHA256Digest": "SHA-256", "SHA512Digest": "SHA-512",
      "Ed25519Signer": "Ed25519", "X25519Agreement": "X25519", "DSASigner": "DSA", "DHBasicAgreement": "DH"}


@rule("java", r'new\s+(?:[\w$]+\.)*(\w+(?:Engine|Digest|Signer|Agreement|KeyPairGenerator|KEMGenerator|KEMExtractor))\s*\(')
def _(m, x):
    return [(BC.get(m.group(1)) or pq_from_text(m.group(1)), {"lib": "org.bouncycastle"})]


simple("java", r'\bMessageDigestAlgorithms\.(MD5|SHA_1|SHA_224|SHA_256|SHA_384|SHA_512(?:_224|_256)?|SHA3_256|SHA3_384|SHA3_512)\b', lib="commons-codec")
simple("java", r'\bgetDigest\(\s*"([^"]+)"(?=\s*[,)])', lib="commons-codec")
simple("java", r'\bDigestUtils\.(?:get(\w+?)Digest|(md5|sha1|sha256|sha384|sha512(?:_224|_256)?|sha3_256|sha3_384|sha3_512)(?:Hex)?)\s*\(', lib="commons-codec")

# libsodium: the same crypto_* names in C, PHP (sodium_crypto_*), the JS wrappers and C# bindings
SODIUM = [("aead_xchacha20poly1305", "ChaCha20-Poly1305"), ("aead_chacha20poly1305", "ChaCha20-Poly1305"), ("secretstream_xchacha20poly1305", "ChaCha20-Poly1305"),
          ("aead_aes256gcm", "AES"), ("stream_xchacha20", "ChaCha20"), ("stream_chacha20", "ChaCha20"), ("stream_xsalsa20", "Salsa20"),
          ("stream_salsa20", "Salsa20"), ("secretbox", "Salsa20"), ("box", ("X25519", "Salsa20")), ("sign", "Ed25519"), ("kx", "X25519"),
          ("scalarmult", "X25519"), ("generichash", "BLAKE2"), ("kdf", "BLAKE2"), ("hash_sha256", "SHA-256"), ("hash_sha512", "SHA-512"),
          ("hash", "SHA-512"), ("auth_hmacsha256", ("HMAC", "SHA-256")), ("auth_hmacsha512", ("HMAC", "SHA-512")), ("auth", ("HMAC", "SHA-512")),
          ("pwhash_scryptsalsa208sha256", "scrypt"), ("pwhash", "Argon2")]


@rule("c js csharp", r'(?<![A-Za-z0-9])(?:sodium_)?crypto_([a-z0-9]+(?:_[a-z0-9]+)*)\s*\(')
def _(m, x):
    before = x.text[x.text.rfind("\n", 0, m.start()) + 1:m.start()]
    if re.search(r"\bextern\b", before) or x.path.endswith((".h", ".hpp")) and re.match(r"\s*(?!return\b)(?:[A-Za-z_]\w*\s+|\*\s*)+$", before):
        return []
    name = m.group(1)
    algos = next((a for key, a in SODIUM if name == key or name.startswith(key + "_")), ())
    return [(a, {"lib": "libsodium"}) for a in ((algos,) if isinstance(algos, str) else algos)]


SODIUM_NET = {"SecretBox": "Salsa20", "PublicKeyBox": ("X25519", "Salsa20"), "SealedPublicKeyBox": ("X25519", "Salsa20"), "PublicKeyAuth": "Ed25519",
              "SecretAeadAes": "AES", "SecretAeadChaCha20Poly1305": "ChaCha20-Poly1305", "SecretAeadXChaCha20Poly1305": "ChaCha20-Poly1305",
              "GenericHash": "BLAKE2", "ScalarMult": "X25519"}
SODIUM_NET_METHODS = {"ArgonHash": "Argon2", "ScryptHash": "scrypt", "Sha256": "SHA-256", "Sha512": "SHA-512", "EncryptChaCha20": "ChaCha20",
                      "EncryptXChaCha20": "ChaCha20", "EncryptSalsa20": "Salsa20", "EncryptXSalsa20": "Salsa20", "SignHmacSha256": ("HMAC", "SHA-256"),
                      "SignHmacSha512": ("HMAC", "SHA-512")}
simple("csharp", r'\b(' + "|".join(SODIUM_NET) + r')\.\w+\s*\(', SODIUM_NET, lib="libsodium")
simple("csharp", r'\b(?:PasswordHash|CryptoHash|StreamEncryption|SecretKeyAuth)\.(' + "|".join(SODIUM_NET_METHODS) + r')\w*\s*\(', SODIUM_NET_METHODS, lib="libsodium")

# sjcl: its namespaces name the algorithm, both where it is implemented and where it is called
SJCL = {"cipher.aes": "AES", "hash.sha1": "SHA-1", "hash.sha256": "SHA-256", "hash.sha512": "SHA-512", "misc.hmac": "HMAC",
        "misc.pbkdf2": "PBKDF2", "misc.scrypt": "scrypt", "misc.hkdf": "HKDF", "ecc.ecdsa": "ECDSA", "ecc.elGamal": "ECDH", "encrypt": "AES", "json.encrypt": "AES"}
simple("js", r'\bsjcl\.(' + "|".join(re.escape(k) for k in sorted(SJCL, key=len, reverse=True)) + r')\b', SJCL, lib="sjcl")


# Go
@rule("go", r'\b(md5|sha1|sha256|sha512|sha3)\.(New\w*|Sum\w*)\(')
def _(m, x):
    pkg, fn = m.group(1), m.group(2)
    size = re.search(r"(224|256|384|512)", fn)
    name = {"md5": "MD5", "sha1": "SHA-1"}.get(pkg) or (f"SHA3-{size.group(1)}" if pkg == "sha3" and size else f"SHA-{size.group(1) if size else pkg[3:]}")
    return [(lookup(name) or name, {})]


@rule("go", r'\brsa\.GenerateKey\(\s*[^,]+,\s*(\d+)?')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1)) if m.group(1) else None})]


@rule("go", r'\brsa\.(SignPKCS1v15|SignPSS|EncryptOAEP|EncryptPKCS1v15|DecryptOAEP|DecryptPKCS1v15|VerifyPKCS1v15|VerifyPSS)\(')
def _(m, x):
    f = m.group(1)
    return [("RSA", {"padding": "oaep" if "OAEP" in f else "pss" if "PSS" in f else "pkcs1v15"})]


@rule("go", r'\becdsa\.GenerateKey\(\s*(?:elliptic\.(P\d+)\(\))?')
def _(m, x):
    return [("ECDSA", {"curve": curve(m.group(1)) if m.group(1) else None})]


@rule("go", r'\becdh\.(P256|P384|P521|X25519)\(\)')
def _(m, x):
    return [("X25519", {})] if m.group(1) == "X25519" else [("ECDH", {"curve": curve(m.group(1))})]


simple("go", r'\becdsa\.(?:Sign\w*|Verify\w*)\(', "ECDSA")
simple("go", r'\bed25519\.(?:GenerateKey|Sign|Verify|NewKeyFromSeed|PublicKey|PrivateKey)\b', "Ed25519")
simple("go", r'\bcurve25519\.(?:X25519|ScalarMult|ScalarBaseMult)\(', "X25519")
simple("go", r'\baes\.NewCipher\(', "AES")
simple("go", r'\bdes\.(NewTripleDESCipher|NewCipher)\(', {"NewTripleDESCipher": "3DES", "NewCipher": "DES"})
simple("go", r'\brc4\.NewCipher\(', "RC4")
simple("go", r'\bchacha20poly1305\.New\w*\(', "ChaCha20-Poly1305")
simple("go", r'\b(scrypt)\.Key\(|\b(hkdf)\.(?:New|Extract|Expand|Key)\(|\b(pbkdf2)\.Key\(|\b(argon2)\.(?:ID)?Key\(|\b(bcrypt)\.GenerateFromPassword\(')
simple("go", r'\bdsa\.(?:GenerateParameters|GenerateKey|Sign|Verify)\(', "DSA")


@rule("go", r'\bcipher\.New(GCM|CBCEncrypter|CBCDecrypter|CTR|CFBEncrypter|CFBDecrypter|OFB)\w*\(')
def _(m, x):
    x.attach({"mode": m.group(1)[:3].upper() if m.group(1) != "OFB" else "OFB"}, ("AES", "3DES", "DES"), window=12)


@rule("go", r'\btls\.(VersionTLS1[0-3]|VersionSSL30|X25519MLKEM768|X25519|CurveP256|CurveP384|CurveP521)\b')
def _(m, x):
    t = m.group(1)
    if t.startswith("Curve"):
        return [("ECDH", {"curve": curve(t[5:])})]
    return [(lookup("SSLv3" if t == "VersionSSL30" else t), {})]


@rule("go", r'\bmlkem\.(GenerateKey|NewDecapsulationKey|NewEncapsulationKey)(768|1024)\(')
def _(m, x):
    return [(f"ML-KEM-{m.group(2)}", {})]


simple("go", r'\bnoise\.(DH25519|DH448|CipherChaChaPoly|CipherAESGCM|HashBLAKE2s|HashBLAKE2b|HashSHA256|HashSHA512)\b',
       {"DH25519": "X25519", "DH448": "X448", "CipherChaChaPoly": "ChaCha20-Poly1305", "CipherAESGCM": "AES", "HashBLAKE2s": "BLAKE2",
        "HashBLAKE2b": "BLAKE2", "HashSHA256": "SHA-256", "HashSHA512": "SHA-512"}, lib="noise")


@rule("go", r'\bx509\.((?:MD5|SHA1|SHA256|SHA384|SHA512)WithRSA(?:PSS)?|ECDSAWithSHA(?:1|256|384|512)|DSAWithSHA(?:1|256)|PureEd25519)\b')
def _(m, x):
    t = m.group(1)
    if t == "PureEd25519":
        return [("Ed25519", {})]
    h = lookup(re.search(r"MD5|SHA\d+", t).group(0))
    sig = "ECDSA" if t.startswith("ECDSA") else "DSA" if t.startswith("DSA") else "RSA"
    return [(sig, {"hash": h, "padding": "pss" if t.endswith("PSS") else None}), (h, {})]


@rule("go", r'\bhmac\.New\(\s*(sha1|sha256|sha512|md5)\.New')
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1))})]




# JavaScript / TypeScript
@rule("js", r'\bcreateHmac\(\s*(?:' + Q + r'([\w-]+)' + Q + r'(?=\s*[,)]))?')
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1)) if m.group(1) else None})]


@rule("js", r'\bcreate(?:Cipheriv|Decipheriv|Cipher|Decipher)\(\s*' + Q + r'([\w-]+)' + Q + r'(?=\s*[,)])')
def _(m, x):
    return [parse_symmetric_name(m.group(1))]


def call_text(text, start, limit=4000):
    """The rest of the call whose arguments begin at `start`: up to its closing parenthesis, so a neighbouring call's options never count."""
    depth, j = 1, start
    while j < len(text) and depth and j - start < limit:
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        j += 1
    return text[start:j]


def key_params(near, algo=None):
    ec = algo in ("ECC", "ECDSA", "ECDH")
    ml = None if ec else re.search(r"modulusLength\s*:\s*(\d+)", near)
    nc = re.search(r"namedCurve\s*:\s*" + Q + r"([\w-]+)", near) if ec or algo is None else None
    return {"key_size": int(ml.group(1)) if ml else None, "curve": curve(nc.group(1)) if nc else None}


@rule("js", r'\bgenerateKeyPair(?:Sync)?\(\s*' + Q + r'([\w-]+)' + Q + r'(?=\s*[,)])')
def _(m, x):
    algo = lookup(m.group(1)) or pq_from_text(m.group(1))
    return [(algo, key_params(call_text(x.text, m.end()), algo))]


@rule("js", r'\bcreate(?:Sign|Verify)\(\s*' + Q + r'([\w-]+)' + Q + r'(?=\s*[,)])')
def _(m, x):
    return sig_scheme(m.group(1))


@rule("js", r'\bcreateECDH\(\s*' + Q + r'([\w-]+)' + Q + r'(?=\s*[,)])')
def _(m, x):
    return [("ECDH", {"curve": curve(m.group(1))})]


@rule("js", r'\bpbkdf2(?:Sync)?\([^;]*?' + Q + r'(sha\w+|md5)' + Q + r'(?=\s*[,)])')
def _(m, x):
    return [("PBKDF2", {"hash": lookup(m.group(1))})]


@rule("js", r'\bsubtle\.(generateKey|importKey|sign|verify|encrypt|decrypt|deriveKey|deriveBits|digest)\(')
def _(m, x):
    near = call_text(x.text, m.end())
    nm = re.search(r"name\s*:\s*" + Q + r"([\w-]+)" + Q, near) or (re.search(r"digest\(\s*" + Q + r"([\w-]+)" + Q, near) if m.group(1) == "digest" else None)
    if not nm:
        return []
    a = lookup(nm.group(1)) or parse_symmetric_name(nm.group(1))[0]
    p = key_params(near, a)
    if a == "AES":
        p.update(parse_symmetric_name(nm.group(1))[1])
        ln = re.search(r"length\s*:\s*(128|192|256)\b", near)
        if ln:
            p["key_size"] = int(ln.group(1))
    return [(a, p)]


@rule("js", r'\bjwt\.sign\(')
def _(m, x):
    alg = re.search(r"algorithm\s*:\s*" + Q + r"(\w+)" + Q, x.window_text(4))
    return sig_scheme(alg.group(1)) if alg else [("HMAC", {"hash": "SHA-256"})]


@rule("js", r'\bnew\s+NodeRSA\(')
def _(m, x):
    b = re.search(r"\bb\s*:\s*(\d+)", x.window_text(2))
    return [("RSA", {"key_size": int(b.group(1)) if b else None})]


@rule("js", r'\bpki\.rsa\.generateKeyPair\(\s*\{?\s*(?:bits\s*:\s*)?(\d+)?')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1)) if m.group(1) else None})]


@rule("js", r'\bnew\s+(?:elliptic\.)?(?:ec|EC)\(\s*' + Q + r'(\w+)' + Q)
def _(m, x):
    return [("ECC", {"curve": curve(m.group(1))})]


simple("js", r'\bcreateHash\(\s*' + Q + r'([\w-]+)' + Q + r'(?=\s*[,)])')
simple("js", r'\bcreateDiffieHellman(?:Group)?\(', "DH")
simple("js", r'\bcrypto\.scrypt(?:Sync)?\(', "scrypt")
simple("js", r'\b(?:minVersion|maxVersion)\s*:\s*' + Q + r'(TLSv1(?:\.\d)?)' + Q)
simple("js", r'\bsecureProtocol\s*:\s*' + Q + r'(\w+?)_method' + Q)


# C / C++ (OpenSSL)
simple("c", r'\bEVP_(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_384|sha3_512|blake2b512|blake2s256)\s*\(\s*\)')
simple("c", r'\bRSA_(?:public_encrypt|private_decrypt|sign|verify|new)\s*\(', "RSA")
simple("c", r'\bEVP_PKEY_CTX_new_id\(\s*(EVP_PKEY_\w+)')
simple("c", r'\b(ECDSA|ECDH|DH|DSA)_(?:do_sign|sign|verify|do_verify|compute_key|generate_key|new|generate_parameters_ex)\s*\(')
simple("c", r'\b(MD5|SHA1|SHA256|SHA512)(?:_Init|_Update|_Final)?\s*\(')
simple("c", r'\bSSL_CTX_set_(?:min|max)_proto_version\([^,]+,\s*(\w+)')
simple("c", r'\bPKCS5_PBKDF2_HMAC(?:_SHA1)?\(', "PBKDF2")


@rule("c", r'\bEVP_(aes_\d+_\w+|des_ede3\w*|des_\w+|rc4|rc2_\w+|bf_\w+|chacha20_poly1305|chacha20)\s*\(\s*\)')
def _(m, x):
    return [parse_symmetric_name(m.group(1))]


@rule("c", r'\bRSA_generate_key(?:_ex)?\s*\([^,]*,\s*(\d+)')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1))})]


@rule("c", r'\bEVP_PKEY_CTX_set_rsa_keygen_bits\([^,]+,\s*(\d+)')
def _(m, x):
    x.attach({"key_size": int(m.group(1))}, ("RSA",))


@rule("c", r'\bEVP_PKEY_CTX_set_ec_paramgen_curve_nid\([^,]+,\s*(NID_\w+)')
def _(m, x):
    x.attach({"curve": curve(m.group(1))}, ("ECC", "ECDSA", "ECDH"))


@rule("c", r'\bEVP_PKEY_(?:CTX_new_from_name|Q_keygen)\([^"]*"([^"]+)"(?:\s*,\s*(\d+))?')
def _(m, x):
    a = lookup(m.group(1)) or pq_from_text(m.group(1))
    return [(a, {"key_size": int(m.group(2)) if m.group(2) and a == "RSA" else None})]


@rule("c", r'\bEC_KEY_new_by_curve_name\(\s*(NID_\w+)')
def _(m, x):
    return [("ECC", {"curve": curve(m.group(1))})]


@rule("c", r'\b(TLSv1_method|TLSv1_1_method|SSLv3_method|SSLv2_method|TLSv1_client_method|TLSv1_server_method)\s*\(')
def _(m, x):
    return [(lookup(re.sub(r"_(client_|server_)?method$", "", m.group(1))), {})]


@rule("c", r'\bSSL_CTX_set1_(?:groups|curves)_list\([^,]+,\s*"([^"]+)"')
def _(m, x):
    return [("ECDH", {"curve": curve(g)}) if curve(g) else (lookup(g) or pq_from_text(g), {}) for g in m.group(1).split(":")]


@rule("c", r'\bSSL_CTX_set_(?:cipher_list|ciphersuites)\([^,]+,\s*"([^"]+)"')
def _(m, x):
    return cipher_string(m.group(1))


@rule("c", r'\bHMAC\(\s*EVP_(\w+)\(\)')
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1))})]



# C#
CS = {"RSA": "RSA", "DSA": "DSA", "ECDsa": "ECDSA", "ECDiffieHellman": "ECDH", "Aes": "AES", "TripleDES": "3DES", "DES": "DES", "RC2": "RC2",
      "MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA3_256": "SHA3-256", "SHA3_384": "SHA3-384",
      "SHA3_512": "SHA3-512", "HMACMD5": "HMAC", "HMACSHA1": "HMAC", "HMACSHA256": "HMAC", "HMACSHA384": "HMAC", "HMACSHA512": "HMAC",
      "HMACSHA3_256": "HMAC", "HMACSHA3_384": "HMAC", "HMACSHA3_512": "HMAC", "Rfc2898DeriveBytes": "PBKDF2", "RSACryptoServiceProvider": "RSA",
      "DSACryptoServiceProvider": "DSA", "TripleDESCryptoServiceProvider": "3DES", "DESCryptoServiceProvider": "DES", "RC2CryptoServiceProvider": "RC2",
      "MD5CryptoServiceProvider": "MD5", "SHA1CryptoServiceProvider": "SHA-1", "SHA1Managed": "SHA-1", "SHA256Managed": "SHA-256",
      "SHA384Managed": "SHA-384", "SHA512Managed": "SHA-512", "RijndaelManaged": "AES", "AesManaged": "AES", "AesGcm": "AES", "AesCcm": "AES",
      "ChaCha20Poly1305": "ChaCha20-Poly1305", "ECDsaCng": "ECDSA", "ECDsaOpenSsl": "ECDSA", "ECDiffieHellmanCng": "ECDH",
      "ECDiffieHellmanOpenSsl": "ECDH", "RSACng": "RSA", "RSAOpenSsl": "RSA", "MLKem": "ML-KEM", "MLDsa": "ML-DSA"}


@rule("csharp", r'\b(?:new\s+(' + "|".join(CS) + r')\s*\(|(' + "|".join(CS) + r')\.Create\s*\()\s*(\d+)?')
def _(m, x):
    c, n = m.group(1) or m.group(2), m.group(3)
    a = CS[c]
    return [(a, {"key_size": int(n) if a in ("RSA", "DSA") and n else None, "hash": lookup(c[4:]) if a == "HMAC" else None,
                 "mode": c[3:].upper() if c in ("AesGcm", "AesCcm") else None})]


@rule("csharp", r'\bCipherMode\.(ECB|CBC|CFB|OFB|CTS)\b')
def _(m, x):
    x.attach({"mode": m.group(1)}, ("AES", "3DES", "DES", "RC2"))


@rule("csharp", r'\bECCurve\.NamedCurves\.nistP(256|384|521)')
def _(m, x):
    x.attach({"curve": f"P-{m.group(1)}"}, ("ECDSA", "ECDH", "ECC"), window=4)


simple("csharp", r'\bSslProtocols\.(Tls13|Tls12|Tls11|Tls|Ssl3|Ssl2)\b',
       {"Tls": "TLS 1.0", "Tls11": "TLS 1.1", "Tls12": "TLS 1.2", "Tls13": "TLS 1.3", "Ssl3": "SSL 3.0", "Ssl2": "SSL 2.0"})
simple("csharp", r'\bHashAlgorithmName\.(SHA1|SHA256|SHA384|SHA512|MD5)\b')


# Rust
@rule("rust", r'\bRsaPrivateKey::new\([^,]+,\s*(\d+)')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1))})]


RING = {"ECDSA_P256": ("ECDSA", "P-256"), "ECDSA_P384": ("ECDSA", "P-384"), "ED25519": ("Ed25519", None), "RSA_PKCS1": ("RSA", None),
        "RSA_PSS": ("RSA", None), "X25519": ("X25519", None), "ECDH_P256": ("ECDH", "P-256"), "ECDH_P384": ("ECDH", "P-384")}


@rule("rust", r'\b(ECDSA_P256|ECDSA_P384|RSA_PKCS1|RSA_PSS|ECDH_P256|ECDH_P384)_\w+|\b(?:signature|agreement)::(ED25519|X25519)\b')
def _(m, x):
    a, c = RING[m.group(1) or m.group(2)]
    h = re.search(r"SHA(256|384|512)", m.group(0))
    return [(a, {"curve": c, "lib": "ring"})] + ([(f"SHA-{h.group(1)}", {"lib": "ring"})] if h else [])


@rule("rust", r'\baead::(AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305)\b')
def _(m, x):
    return [parse_symmetric_name(m.group(1))]


@rule("rust", r'\bAes(128|192|256)(Gcm|GcmSiv|Ctr|Cbc)?\b')
def _(m, x):
    return [("AES", {"key_size": int(m.group(1)), "mode": (m.group(2) or "")[:3].upper() or None})]


@rule("rust", r'\b(?:MlKem|ml_kem::MlKem)(512|768|1024)\b')
def _(m, x):
    return [(f"ML-KEM-{m.group(1)}", {})]


simple("rust", r'\b(Md5|Sha1|Sha224|Sha256|Sha384|Sha512)::(?:new|digest)\b|\b(md5)::compute\(')


@rule("java go js c csharp rust", r'(?<![\w.])[\w.]*(?:ml[-_]?kem|ml[-_]?dsa|slh[-_]?dsa|MLKem|MLDsa|MlKem|MlDsa|mlkem|mldsa)[-_]?(?:512|768|1024|44|65|87)?\w*')
def _(m, x):
    a = pq_from_text(m.group(0))
    return [(a, {}, "identifier")] if a else []


# Shell: WireGuard keys are Curve25519 by the protocol's definition
simple("hash", r'\bwg\s+(?:genkey|pubkey)\b', "X25519", lib="wireguard-tools")


# Swift: CryptoKit and the Security framework (Swift files are read with the C-family rules)
@rule("c", r'\b(P256|P384|P521)\.(Signing|KeyAgreement)\b')
def _(m, x):
    return [("ECDSA" if m.group(2) == "Signing" else "ECDH", {"curve": f"P-{m.group(1)[1:]}", "lib": "CryptoKit"})]


simple("c", r'\bCurve25519\.(Signing|KeyAgreement)\b', {"Signing": "Ed25519", "KeyAgreement": "X25519"}, lib="CryptoKit")
simple("c", r'\bChaChaPoly\.(?:seal|open|SealedBox)\b', "ChaCha20-Poly1305", lib="CryptoKit")


@rule("c", r'\bHMAC<\s*(SHA256|SHA384|SHA512|Insecure\.SHA1|Insecure\.MD5)\s*>')
def _(m, x):
    h = lookup(m.group(1).split(".")[-1])
    return [("HMAC", {"hash": h, "lib": "CryptoKit"})]


@rule("c", r'\bkSecAttrKeyType(RSA|ECSECPrimeRandom|EC)\b')
def _(m, x):
    n = re.search(r"kSecAttrKeySizeInBits\D{0,40}(\d{3,4})", x.window_text(6))
    algo = "RSA" if m.group(1) == "RSA" else "ECC"
    return [(algo, {"key_size": int(n.group(1)) if n and algo == "RSA" else None, "lib": "Security"})]


# Ruby: the OpenSSL and Digest standard libraries (Ruby files are read with the #-comment rules)
@rule("hash", r'\bOpenSSL::PKey::RSA\.(?:new|generate)\(\s*(\d{3,5})')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1)), "lib": "openssl-ruby"})]


simple("hash", r'\bOpenSSL::PKey::(RSA|DSA|DH)\b(?!\.(?:new|generate)\(\s*\d)', lib="openssl-ruby")


@rule("hash", r'\bOpenSSL::PKey::EC(?:\.generate|\.new)?\(\s*[\'"]([\w-]+)')
def _(m, x):
    return [("ECC", {"curve": curve(m.group(1)), "lib": "openssl-ruby"})]


simple("hash", r'\bOpenSSL::PKey::EC\b(?!(?:\.generate|\.new)?\(\s*[\'"])', "ECC", lib="openssl-ruby")
simple("hash", r'\bOpenSSL::PKey\.generate_(?:key|parameters)\(\s*[\'"](\w+)', lib="openssl-ruby")


@rule("hash", r'\bOpenSSL::HMAC\.(?:hexdigest|digest|base64digest|new)\(\s*(?:OpenSSL::Digest(?:::|\.new\(\s*)[\'"]?|[\'"])(\w+)')
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1)), "lib": "openssl-ruby"})]


simple("hash", r'\b(?:OpenSSL::)?Digest::(MD5|SHA1|SHA256|SHA384|SHA512|RMD160)\b', lib="ruby")
simple("hash", r'\bOpenSSL::Digest\.new\(\s*[\'"](\w+)', lib="openssl-ruby")
simple("hash", r'\bOpenSSL::(?:PKCS5|KDF)\.pbkdf2_hmac', "PBKDF2", lib="openssl-ruby")


@rule("hash", r'\bOpenSSL::Cipher(?:::Cipher)?\.new\(\s*[\'"]([\w-]+)')
def _(m, x):
    a, p = parse_symmetric_name(m.group(1))
    return [(a, dict(p, lib="openssl-ruby"))] if a else []


@rule("hash", r'\b(?:min_version|max_version|ssl_version)\s*=\s*(?:OpenSSL::SSL::)?:?(TLS1_3|TLS1_2|TLS1_1|TLS1|SSL3|SSLv3|TLSv1_2|TLSv1_1|TLSv1)(?:_VERSION)?\b')
def _(m, x):
    v = {"TLS1_3": "TLSv1.3", "TLS1_2": "TLSv1.2", "TLS1_1": "TLSv1.1", "TLS1": "TLSv1", "SSL3": "SSLv3"}.get(m.group(1), m.group(1).replace("_", "."))
    return [(lookup(v), {"lib": "openssl-ruby"})]


# PHP: the openssl extension and the hash functions (PHP files are read with the C-family rules)
simple("c", r'\bOPENSSL_KEYTYPE_(RSA|EC|DSA|DH)\b', {"RSA": "RSA", "EC": "ECC", "DSA": "DSA", "DH": "DH"}, lib="php-openssl")


@rule("c", r'[\'"]curve_name[\'"]\s*=>\s*[\'"]([\w-]+)')
def _(m, x):
    return [("ECC", {"curve": curve(m.group(1)), "lib": "php-openssl"})]


simple("c", r'\bOPENSSL_ALGO_(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|MD4|RMD160)\b', lib="php-openssl")


@rule("c", r'\bopenssl_(?:encrypt|decrypt)\(\s*[^,]+,\s*[\'"]([\w-]+)')
def _(m, x):
    a, p = parse_symmetric_name(m.group(1))
    return [(a, dict(p, lib="php-openssl"))] if a else []


@rule("c", r'\bhash_hmac(?:_file)?\(\s*[\'"](\w+)')
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1)), "lib": "php"})]


@rule("c", r'\bhash_pbkdf2\(\s*[\'"](\w+)')
def _(m, x):
    return [("PBKDF2", {"hash": lookup(m.group(1)), "lib": "php"})]


simple("c", r'\bhash(?:_file|_init)?\(\s*[\'"](\w+)[\'"]', lib="php")


# Shell: openssl and ssh-keygen command lines that make keys, sign or encrypt
@rule("hash", r'\bopenssl\s+genrsa\b[^\n|;&]*?(?:\s(\d{3,5}))?\s*(?=$|[|;&\n])')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1)) if m.group(1) else None, "lib": "openssl-cli"})]


@rule("hash", r'\bopenssl\s+(?:genpkey|req)\b[^\n|;&]*?(?:-algorithm\s+|-newkey\s+)([\w-]+)(?::(\d+))?([^\n|;&]*)')
def _(m, x):
    kind, bits, rest = m.group(1).lower(), m.group(2), m.group(3)
    if kind in ("rsa", "rsa-pss"):
        bits = bits or (re.search(r"rsa_keygen_bits:(\d+)", rest) or [None, None])[1]
        return [("RSA", {"key_size": int(bits) if bits else None, "lib": "openssl-cli"})]
    if kind == "ec":
        cv = re.search(r"ec_paramgen_curve:([\w-]+)", rest)
        return [("ECC", {"curve": curve(cv.group(1)) if cv else None, "lib": "openssl-cli"})]
    a = lookup(kind) or pq_from_text(kind)
    return [(a, {"lib": "openssl-cli"})] if a else []


@rule("hash", r'\bopenssl\s+ecparam\b[^\n|;&]*?-name\s+([\w-]+)')
def _(m, x):
    return [("ECC", {"curve": curve(m.group(1)), "lib": "openssl-cli"})]


simple("hash", r'\bopenssl\s+(?:req|x509|ca|dgst|ts|cms|smime)\b[^\n|;&]*?\s-(md5|sha1|sha224|sha256|sha384|sha512|sha3-256|sha3-512)\b', lib="openssl-cli")


@rule("hash", r'\bopenssl\s+(?:enc\s+[^\n|;&]*?-|(?=aes|des|bf|rc4))(aes-\d+-\w+|aes\d+|des-ede3-cbc|des3|des-cbc|des|bf-cbc|bf|rc4|chacha20)\b')
def _(m, x):
    t = m.group(1).lower()
    fixed = {"des3": ("3DES", {}), "des": ("DES", {}), "bf": ("Blowfish", {}), "bf-cbc": ("Blowfish", {}), "rc4": ("RC4", {}), "chacha20": ("ChaCha20", {})}
    a, p = fixed.get(t) or parse_symmetric_name(t.replace("aes128", "aes-128").replace("aes192", "aes-192").replace("aes256", "aes-256"))
    return [(a, dict(p, lib="openssl-cli"))] if a else []


@rule("hash", r'\bssh-keygen\b[^\n|;&]*?-t\s+([\w-]+)([^\n|;&]*)')
def _(m, x):
    t, bits = m.group(1).lower(), re.search(r"-b\s+(\d+)", m.group(0))
    bits = int(bits.group(1)) if bits else None
    if t.startswith("ecdsa"):
        return [("ECDSA", {"curve": {256: "P-256", 384: "P-384", 521: "P-521"}.get(bits, "P-256"), "lib": "ssh-keygen"})]
    if t in ("rsa", "dsa"):
        return [(t.upper(), {"key_size": bits, "lib": "ssh-keygen"})]
    a = lookup(t.replace("-sk", ""))
    return [(a, {"lib": "ssh-keygen"})] if a else []
