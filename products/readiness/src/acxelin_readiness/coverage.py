"""What Acxelin Readiness tracks: the kinds of asset its CBOM holds, every algorithm it knows with its quantum verdict, and every
place it looks. One list for the console, the website and the manual (a test keeps SOURCES equal to the manual's table)."""
from .catalog import CATALOG

THREATS = {"safe": ("ok", "quantum-safe"), "grover": ("grover", "weakened: use the larger size"),
           "shor": ("exposed", "broken by a quantum computer"), "legacy": ("bad", "broken today")}
PRIMITIVES = [("kem", "Key encapsulation"), ("key-agree", "Key agreement"), ("pke", "Public-key encryption"), ("signature", "Signatures"),
              ("block-cipher", "Block ciphers"), ("stream-cipher", "Stream ciphers"), ("ae", "Authenticated encryption"), ("hash", "Hashes"),
              ("mac", "Message authentication"), ("kdf", "Key derivation and password hashing"), ("protocol", "Protocols"), ("other", "Other")]
KINDS = [
    {"key": "algorithm", "title": "Algorithms", "what": "A cipher, hash, signature, key exchange or KEM, with its size, mode and padding when they are visible.",
     "recorded": "primitive, functions, parameter set, classical and quantum security level, OID"},
    {"key": "protocol", "title": "Protocols", "what": "TLS, SSH, QUIC and IKEv2 as configured or negotiated: versions, cipher suites, key-exchange groups.",
     "recorded": "version, cipher suites, groups offered and chosen"},
    {"key": "certificate", "title": "Certificates", "what": "X.509 certificates in files, keystores, cloud accounts and live handshakes.",
     "recorded": "subject, issuer, validity, signature algorithm, public key, fingerprint"},
    {"key": "related-crypto-material", "title": "Keys and key material", "what": "Private and public keys, SSH keys, keystores and secrets written into code.",
     "recorded": "type, algorithm, size, format, whether it is encrypted; never the key itself"},
    {"key": "library", "title": "Libraries", "what": "Cryptography libraries in manifests, lockfiles, binaries and container images, and which algorithms they provide.",
     "recorded": "name, version, ecosystem, the algorithms it provides"},
]
SOURCES = [
    {"name": "Code", "what": "Python, JavaScript, TypeScript, Java, Go, C and C++, Rust, C#, Swift, PHP, Ruby, shell, Dockerfiles and more: calls, imports, constants, names and parameters"},
    {"name": "Configuration", "what": "YAML, JSON, TOML, INI, nginx, Apache, sshd, Kubernetes, Terraform: algorithm and cipher lists"},
    {"name": "Keys and certificates", "what": "PEM and DER certificates and keys, SSH keys and known hosts. PKCS#12 (`.p12`, `.pfx`) and Java keystores (`.jks`, `.jceks`, `.keystore`, `.truststore`): the algorithms that protect them, read without a password, and the certificates they hold in the clear. A key's algorithm is named from its certificate; key material is never read or written out"},
    {"name": "Encrypted volumes", "what": "The cipher, key size and key derivation in a volume's own header, read without its passphrase: LUKS 1 and 2 (also inside qcow2), qcow2's built-in AES, BitLocker, encrypted macOS disk images (`.dmg`, `.sparseimage`) and the plain-mode ciphers in `/etc/crypttab`. Only the first 64 KB of an image is read, and a large image does not count towards the scan's size limit. The BitLocker method is read from the layout the libbde project documents; it is checked against headers built from that description, not against a real volume"},
    {"name": "Binaries and images", "what": "Library versions and algorithm strings in compiled files; container images saved with `docker save` or as OCI archives"},
    {"name": "Dependencies", "what": "Package manifests and lockfiles of the common ecosystems"},
    {"name": "Live", "what": "TLS endpoints (accepted groups, certificate, grade) and SSH servers (algorithm lists, host keys)"},
    {"name": "Captures", "what": "Handshakes in `.pcap` and `.pcapng` files: what clients and servers actually negotiated over TLS, SSH, QUIC and IKEv2 (including ML-KEM as an RFC 9370 additional key exchange). QUIC's Initial packets are protected only by keys derived from the connection ID, which is how they are read; nothing after the handshake is"},
]


def strength(a):
    """'192-bit, NIST level 3', or what is known of it."""
    level = f"NIST level {a.level}" if a.level else ""
    return ", ".join(x for x in (f"{a.bits}-bit" if a.bits else "", level) if x)


def summary():
    algorithms = [{"name": a.name, "primitive": a.primitive, "threat": a.threat, "strength": strength(a), "replace": a.replace} for a in CATALOG.values()]
    return {"kinds": KINDS, "sources": SOURCES, "algorithms": algorithms, "primitives": PRIMITIVES,
            "threats": {k: {"class": c, "label": label} for k, (c, label) in THREATS.items()}}
