"""A short before-and-after for a finding, in the language of the file it was seen in (what the change looks like, not a patch), and
how hard the change is."""
from pathlib import PurePosixPath

LANGS = {".py": "Python", ".java": "Java", ".go": "Go", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "TypeScript",
         ".conf": "nginx"}
HASH = {"MD5": ("md5", "MD5", "md5.Sum", "md5"), "SHA-1": ("sha1", "SHA-1", "sha1.Sum", "sha1")}
SIGN = {"RSA", "ECDSA", "Ed25519", "Ed448", "DSA", "ECC"}
AGREE = {"ECDH", "X25519", "X448", "DH"}
TLS = {"SSL 2.0": "SSLv2", "SSL 3.0": "SSLv3", "TLS 1.0": "TLSv1", "TLS 1.1": "TLSv1.1", "TLS 1.2": "TLSv1.2"}
GCM = {
    "Python": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nnonce = os.urandom(12)  # new for every message\n"
              "ciphertext = AESGCM(key).encrypt(nonce, data, None)  # key: 32 bytes",
    "Java": "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\nc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));  // a new 12-byte iv each time",
    "Go": "block, _ := aes.NewCipher(key) // 32-byte key\naead, _ := cipher.NewGCM(block)\nsealed := aead.Seal(nil, nonce, data, nil) // a new nonce each time",
    "JavaScript": "const c = crypto.createCipheriv(\"aes-256-gcm\", key, iv); // a new 12-byte iv each time\n// send c.getAuthTag() with the ciphertext",
}
GCM["TypeScript"] = GCM["JavaScript"]
OLD = {"Python": "Cipher(algorithms.{py}(key), modes.{mode}(iv))", "Java": "Cipher.getInstance(\"{java}\")",
       "Go": "block, _ := {go}(key)", "JavaScript": "crypto.createCipheriv(\"{js}\", key, iv)"}
OLD["TypeScript"] = OLD["JavaScript"]
CIPHER_NAMES = {"DES": ("TripleDES", "CBC", "DES/CBC/PKCS5Padding", "des.NewCipher", "des-cbc"),
                "3DES": ("TripleDES", "CBC", "DESede/CBC/PKCS5Padding", "des.NewTripleDESCipher", "des-ede3-cbc"),
                "Blowfish": ("Blowfish", "CBC", "Blowfish/CBC/PKCS5Padding", "blowfish.NewCipher", "bf-cbc"),
                "AES-ECB": ("AES", "ECB", "AES/ECB/PKCS5Padding", "aes.NewCipher", "aes-128-ecb")}


def language(asset):
    """The language of the first place the finding was seen outside tests, if it is one with examples."""
    for path, _ in asset.get("locations", []):
        lang = LANGS.get(PurePosixPath(str(path)).suffix.lower())
        if lang == "nginx" and "nginx" not in str(path).lower():
            continue
        if lang and "test" not in str(path).lower():
            return lang
    return None


def example(asset):
    """{"language", "before", "after", "note"} for a finding that needs a change, or None when there is no example for it."""
    if asset.get("tier") in (None, "ok"):
        return None
    lang, algo, name = language(asset), asset.get("algorithm") or "", asset.get("name") or ""
    if not lang:
        return None
    out = None
    if algo in HASH and lang != "nginx":
        py, java, go, js = HASH[algo]
        before = {"Python": f"digest = hashlib.{py}(data).hexdigest()", "Java": f"MessageDigest md = MessageDigest.getInstance(\"{java}\");",
                  "Go": f"sum := {go}(data)", "JavaScript": f"crypto.createHash(\"{js}\").update(data).digest(\"hex\")"}
        after = {"Python": "digest = hashlib.sha256(data).hexdigest()", "Java": "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");",
                 "Go": "sum := sha256.Sum256(data)", "JavaScript": "crypto.createHash(\"sha256\").update(data).digest(\"hex\")"}
        before["TypeScript"], after["TypeScript"] = before["JavaScript"], after["JavaScript"]
        out = before.get(lang), after.get(lang), "For passwords, use a password hash such as Argon2 or scrypt instead."
    elif algo in SIGN and lang in ("Python", "Java"):
        out = {"Python": ("key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
                          "signature = key.sign(data, padding.PKCS1v15(), hashes.SHA256())",
                          "from cryptography.hazmat.primitives.asymmetric import mldsa\nkey = mldsa.MLDSA65PrivateKey.generate()\n"
                          "signature = key.sign(data)"),
               "Java": ("Signature s = Signature.getInstance(\"SHA256withRSA\");",
                        "KeyPairGenerator g = KeyPairGenerator.getInstance(\"ML-DSA\");\ng.initialize(NamedParameterSpec.ML_DSA_65);\n"
                        "Signature s = Signature.getInstance(\"ML-DSA\");  // Java 24 or later")}[lang] + (
            "For signatures. If the key encrypts or agrees keys instead, use ML-KEM-768.",)
    elif algo in AGREE and lang in ("Python", "Java", "Go"):
        out = {"Python": ("private = x25519.X25519PrivateKey.generate()\nshared = private.exchange(peer_public)",
                          "from cryptography.hazmat.primitives.asymmetric import mlkem\nprivate = mlkem.MLKEM768PrivateKey.generate()\n"
                          "shared, ciphertext = peer_public.encapsulate()  # the peer runs private.decapsulate(ciphertext)"),
               "Java": ("KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");",
                        "KeyPairGenerator g = KeyPairGenerator.getInstance(\"ML-KEM\");\ng.initialize(NamedParameterSpec.ML_KEM_768);\n"
                        "KEM.Encapsulated e = KEM.getInstance(\"ML-KEM\").newEncapsulator(peerPublic).encapsulate();  // Java 24 or later"),
               "Go": ("private, _ := ecdh.X25519().GenerateKey(rand.Reader)",
                      "dk, _ := mlkem.GenerateKey768()  // Go 1.24 or later\nshared, ciphertext := peerKey.Encapsulate()  // the peer runs dk.Decapsulate(ciphertext)")}[lang] + (
            "In TLS, prefer the hybrid group X25519MLKEM768 over writing this yourself.",)
    elif (algo in CIPHER_NAMES or algo == "AES" and "ECB" in name.upper()) and lang in OLD:
        py, mode, java, go, js = CIPHER_NAMES["AES-ECB" if algo == "AES" else algo]
        out = OLD[lang].format(py=py, mode=mode, java=java, go=go, js=js), GCM[lang], "AES-256-GCM also checks that nothing was changed."
    elif algo in TLS:
        v = TLS[algo]
        py, go = {"TLSv1": ("PROTOCOL_TLSv1", "VersionTLS10"), "TLSv1.1": ("PROTOCOL_TLSv1_1", "VersionTLS11"),
                  "TLSv1.2": ("PROTOCOL_TLSv1_2", "VersionTLS12"), "SSLv3": (None, "VersionSSL30")}.get(v, (None, None))
        out = {"Python": (py and f"ctx = ssl.SSLContext(ssl.{py})", "ctx = ssl.create_default_context()\nctx.minimum_version = ssl.TLSVersion.TLSv1_3"),
               "Java": (f"SSLContext.getInstance(\"{v}\")", "SSLContext.getInstance(\"TLSv1.3\")"),
               "Go": (go and f"MinVersion: tls.{go},", "MinVersion: tls.VersionTLS13,"),
               "JavaScript": (f"minVersion: \"{v}\"", "minVersion: \"TLSv1.3\""),
               "TypeScript": (f"minVersion: \"{v}\"", "minVersion: \"TLSv1.3\""),
               "nginx": (f"ssl_protocols {v} TLSv1.2;", "ssl_protocols TLSv1.3;")}.get(lang, (None, None)) + (
            "Keep TLS 1.2 only while old clients still need it.",)
    if not out or not out[0]:
        return None
    return {"language": lang, "before": out[0], "after": out[1], "note": out[2]}


SETTING = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".xml", ".json", ".properties", ".env", ".tf", ".hcl"}
KEYFILE = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks", ".keystore", ".bks", ".p7b", ".csr", ".pub"}
MANIFEST = {"requirements.txt", "pyproject.toml", "package.json", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "cargo.toml",
            "packages.config", "setup.py", "setup.cfg", "pipfile", "gemfile", "composer.json", "package-lock.json", "go.sum", "cargo.lock"}
BINARY = {".so", ".dll", ".exe", ".dylib", ".a", ".lib", ".jar", ".war", ".class", ".bin", ".elf", ".o"}
EFFORT = {"setting": "Change a setting", "reissue": "Reissue a key or certificate", "upgrade": "Upgrade a library",
          "code": "Change code", "replace": "Replace or rebuild a vendor component"}


def _kind(path):
    p = PurePosixPath(str(path).lower())
    if "://" in str(path):
        return "reissue" if str(path).startswith("aws://") else "setting"
    if p.name in MANIFEST:
        return "upgrade"
    if p.suffix in KEYFILE:
        return "reissue"
    if p.suffix in BINARY:
        return "replace"
    return "setting" if p.suffix in SETTING or p.name.endswith("_config") else "code"


def effort(asset):
    """How hard a finding is to change, judged by the hardest place it was seen outside tests: {"level", "text", "places"}."""
    if asset.get("tier") in (None, "ok"):
        return None
    places = [f for f, _ in asset.get("locations", []) if "test" not in str(f).lower()]
    if not places:
        return None
    level = max((_kind(f) for f in places), key=list(EFFORT).index)
    files = len(set(places))
    return {"level": level, "text": EFFORT[level] + (f" in {files} files" if level == "code" and files > 1 else ""), "places": files}
