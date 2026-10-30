"""What the VPN protects traffic with, as a CycloneDX 1.6 CBOM, read from site and gateway configurations.

Every tunnel's IKE and ESP algorithms, the key agreement's TLS groups, signatures and cipher suites, the certificates, and the
keys and shared secrets by type, size and where they live. A value is never read into it: private keys are named by file, and
the PSK and PPK exist only in memory, so the CBOM says how they are made and how often they change. The same configuration
gives the same bytes, so a CBOM in version control changes only when the VPN does.
"""
import hashlib
import json
import uuid
from pathlib import Path

from acxelin_core.config import read_toml
from acxelin_core.pki import algorithm_of, encrypted
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import PROFILES, NAME, __version__, load_config
from .controller import LABEL as IPSEC_LABEL
from .policies import CNSA2, POLICY, policy_for
from .wireguard import LABEL as WG_LABEL, load_gateway

# name: (primitive, parameter set, mode, curve, NIST quantum security level, functions)
ALGORITHMS = {
    "ML-KEM-768": ("kem", "768", None, None, 3, ["encapsulate", "decapsulate"]),
    "ML-KEM-1024": ("kem", "1024", None, None, 5, ["encapsulate", "decapsulate"]),
    "X25519": ("key-agree", None, None, "Curve25519", 0, ["keygen"]),
    "ECDH-P-384": ("key-agree", None, None, "secp384r1", 0, ["keygen"]),
    "X25519MLKEM768": ("kem", "768", None, "Curve25519", 3, ["encapsulate", "decapsulate"]),
    "SecP256r1MLKEM768": ("kem", "768", None, "secp256r1", 3, ["encapsulate", "decapsulate"]),
    "SecP384r1MLKEM1024": ("kem", "1024", None, "secp384r1", 5, ["encapsulate", "decapsulate"]),
    "ML-DSA-44": ("signature", "44", None, None, 2, ["sign", "verify"]),
    "ML-DSA-65": ("signature", "65", None, None, 3, ["sign", "verify"]),
    "ML-DSA-87": ("signature", "87", None, None, 5, ["sign", "verify"]),
    "AES-256-GCM": ("ae", "256", "gcm", None, 5, ["encrypt", "decrypt"]),
    "AES-128-GCM": ("ae", "128", "gcm", None, 1, ["encrypt", "decrypt"]),
    "ChaCha20-Poly1305": ("ae", "256", None, None, None, ["encrypt", "decrypt"]),
    "HMAC-SHA384": ("mac", "384", None, None, None, ["tag"]),
    "HMAC-SHA512": ("mac", "512", None, None, None, ["tag"]),
    "SHA-256": ("hash", "256", None, None, None, ["digest"]),
    "SHA-384": ("hash", "384", None, None, None, ["digest"]),
    "BLAKE2s": ("hash", "256", None, None, None, ["digest"]),
}
# strongSwan proposal keywords, as the profiles spell them
PROPOSAL = {"aes256gcm16": "AES-256-GCM", "prfsha384": "HMAC-SHA384", "prfsha512": "HMAC-SHA512", "x25519": "X25519",
            "ecp384": "ECDH-P-384", "ke1_mlkem768": "ML-KEM-768", "ke1_mlkem1024": "ML-KEM-1024", "mlkem1024": "ML-KEM-1024"}
SUITES = {"TLS_AES_256_GCM_SHA384": ["AES-256-GCM", "SHA-384"], "TLS_CHACHA20_POLY1305_SHA256": ["ChaCha20-Poly1305", "SHA-256"],
          "TLS_AES_128_GCM_SHA256": ["AES-128-GCM", "SHA-256"]}
SIGNATURE_OIDS = {"2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}
SIGALGS = {"mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87"}


def ref(name):
    return f"algorithm/{name}"


def props(**kv):
    return [{"name": f"acxelin:{k.replace('_', '-')}", "value": str(v)} for k, v in kv.items() if v is not None]


def at(path):
    return {"occurrences": [{"location": Path(path).as_posix()}]}


class Inventory:
    def __init__(self):
        self.components = {}

    def add(self, c):
        """Each asset once; one seen in several files lists every place it was seen."""
        have = self.components.setdefault(c["bom-ref"], c)
        if have is not c and "evidence" in c:
            seen = {o["location"] for o in have.get("evidence", {}).get("occurrences", []) + c["evidence"]["occurrences"]}
            have["evidence"] = {"occurrences": [{"location": loc} for loc in sorted(seen)]}
        return c["bom-ref"]

    def algorithm(self, name):
        primitive, param, mode, curve, level, functions = ALGORITHMS[name]
        ap = {"primitive": primitive, "cryptoFunctions": functions, "executionEnvironment": "software-plain-ram"}
        ap |= {k: v for k, v in (("parameterSetIdentifier", param), ("mode", mode), ("curve", curve), ("nistQuantumSecurityLevel", level)) if v is not None}
        return self.add({"type": "cryptographic-asset", "bom-ref": ref(name), "name": name,
                         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap}})

    def protocol(self, key, name, pp, **extra):
        return self.add({"type": "cryptographic-asset", "bom-ref": f"protocol/{key}", "name": name,
                         "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp}} | ({"properties": props(**extra)} if extra else {}))

    def material(self, key, name, kind, algorithm=None, size=None, where=None, **extra):
        rp = {"type": kind} | ({"algorithmRef": self.algorithm(algorithm)} if algorithm else {}) | ({"size": size} if size else {})
        return self.add({"type": "cryptographic-asset", "bom-ref": f"{kind}/{key}", "name": name,
                         "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rp}}
                        | ({"evidence": at(where)} if where else {}) | ({"properties": props(**extra)} if extra else {}))

    def missing(self, key, name, path):
        return self.add({"type": "cryptographic-asset", "bom-ref": f"missing/{key}", "name": name,
                         "cryptoProperties": {"assetType": "certificate"}, "properties": props(missing=Path(path).as_posix())})

    def certificates(self, path):
        """Every certificate in a PEM file (a chain gives the leaf and its CA), each with its signature and public key."""
        try:
            certs = x509.load_pem_x509_certificates(Path(path).read_bytes())
        except (OSError, ValueError):
            return [self.missing(Path(path).as_posix(), f"certificate {Path(path).name}", path)]
        refs = []
        for cert in certs:
            fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            subject = cert.subject.rfc4514_string()
            key_algo = algorithm_of(cert.public_key())
            spki = hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            public = self.material(spki[:24], f"public key of {subject}", "public-key", key_algo if key_algo in ALGORITHMS else None,
                                   fingerprint=spki)
            cp = {"subjectName": subject, "issuerName": cert.issuer.rfc4514_string(),
                  "notValidBefore": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "notValidAfter": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "subjectPublicKeyRef": public, "certificateFormat": "X.509", "certificateExtension": "pem"}
            signature = SIGNATURE_OIDS.get(cert.signature_algorithm_oid.dotted_string)
            if signature:
                cp["signatureAlgorithmRef"] = self.algorithm(signature)
            refs.append(self.add({"type": "cryptographic-asset", "bom-ref": f"certificate/{fp[:24]}", "name": subject,
                                  "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp},
                                  "evidence": at(path), "properties": props(fingerprint=fp, serial=format(cert.serial_number, "x"))}))
        return refs

    def private_key(self, owner, path, cert_path):
        try:
            leaf = x509.load_pem_x509_certificates(Path(cert_path).read_bytes())[0]
            algo = algorithm_of(leaf.public_key())
        except (OSError, ValueError, IndexError):
            algo = None
        exists = Path(path).exists()
        return self.material(f"{owner}/{Path(path).as_posix()}", f"private key of {owner}", "private-key", algo if algo in ALGORITHMS else None,
                             where=path, encrypted=("yes" if encrypted(Path(path)) else "no") if exists else None,
                             missing=None if exists else Path(path).as_posix())

    def key_agreement(self, policy=POLICY):
        """The post-quantum mutual TLS both sites and gateways agree keys over."""
        groups = [self.algorithm({"MLKEM1024": "ML-KEM-1024"}.get(g, g)) for g in policy.groups.split(":")]
        signatures = [self.algorithm(SIGALGS[s]) for s in policy.sigalgs.split(":")]
        suites = [{"name": s, "algorithms": [self.algorithm(a) for a in SUITES[s]]} for s in policy.ciphersuites.split(":")]
        strict = policy is CNSA2
        return self.protocol("TLS-1.3-cnsa2" if strict else "TLS-1.3", "TLS 1.3 (CNSA 2.0)" if strict else "TLS 1.3",
                             {"type": "tls", "version": "1.3", "cipherSuites": suites, "cryptoRefArray": groups + signatures},
                             use="key agreement for IPsec and WireGuard: ML-DSA mutual TLS, then keys from the TLS exporter")

    def site(self, path):
        site = load_config(path)
        tls = self.key_agreement(policy_for(site))
        self.certificates(site.cert)
        self.certificates(site.ca)
        self.private_key(site.name, site.key, site.cert)
        everything = set()
        for p in site.peers:
            ike, esp = (proposal.split("-") for proposal in PROFILES[p.profile])
            ike_refs = {k: [self.algorithm(PROPOSAL[t]) for t in ike if t.startswith(prefix)] for k, prefix in
                        (("encr", "aes"), ("prf", "prf"), ("ke", ("x25519", "ecp", "ke1_", "mlkem")))}
            esp_refs = [self.algorithm(PROPOSAL[t]) for t in esp]
            everything |= set(ike) | set(esp)
            pair = f"{site.name} to {p.name}"
            psk = self.material(f"ike-psk/{site.name}/{p.name}", f"IKE PSK {pair}", "secret-key", size=256, derived=f"TLS exporter {IPSEC_LABEL}",
                                rotation=f"every {p.rotate_minutes:g} minutes", stored="no: held in strongSwan's memory only")
            ppk = self.material(f"ppk/{site.name}/{p.name}", f"PPK {pair}", "secret-key", size=256, derived=f"TLS exporter {IPSEC_LABEL}",
                                standard="RFC 8784 post-quantum preshared key", rotation=f"every {p.rotate_minutes:g} minutes",
                                stored="no: held in strongSwan's memory only")
            self.protocol(f"tunnel/{site.name}/{p.name}", f"tunnel {pair}",
                          {"type": "ike", "version": "2", "ikev2TransformTypes": ike_refs | {"auth": [psk]},
                           "cipherSuites": [{"name": PROFILES[p.profile][1], "algorithms": esp_refs}], "cryptoRefArray": [tls, psk, ppk]},
                          profile=p.profile, peer_address=p.address, local_subnets=" ".join(p.local_subnets),
                          remote_subnets=" ".join(p.remote_subnets), initiates="yes" if p.initiate else "no", config=Path(path).as_posix())
        self.protocol("IKEv2", "IKEv2", {"type": "ike", "version": "2", "cryptoRefArray": sorted(self.algorithm(PROPOSAL[t]) for t in everything)},
                      use="hybrid key exchange (RFC 9370) on the initial exchange and every rekey")
        self.protocol("IPsec-ESP", "IPsec ESP", {"type": "ipsec", "cryptoRefArray": sorted(self.algorithm(PROPOSAL[t]) for t in everything
                                                                                              if not t.startswith("prf"))})

    def gateway(self, path):
        g = load_gateway(path)
        tls = self.key_agreement()
        self.certificates(g.cert)
        self.certificates(g.ca)
        self.private_key(g.name, g.key, g.cert)
        wg = [self.algorithm(a) for a in ("X25519", "ChaCha20-Poly1305", "BLAKE2s")]
        psk = self.material(f"wireguard-psk/{g.name}", f"WireGuard PSK per person at {g.name}", "secret-key", size=256,
                            derived=f"TLS exporter {WG_LABEL}", rotation=f"every {g.rotate_minutes:g} minutes",
                            stored="no: held in the WireGuard interface only")
        private = self.material(f"wireguard-key/{g.name}", f"WireGuard private key of {g.name}", "private-key", "X25519", 256, where=g.private_key,
                                missing=None if Path(g.private_key).exists() else Path(g.private_key).as_posix())
        self.protocol(f"wireguard/{g.name}", "WireGuard", {"type": "other", "cryptoRefArray": wg + [psk, private, tls]},
                      endpoint=g.endpoint, pool=g.pool, full_tunnel="yes" if g.full_tunnel else "no", config=Path(path).as_posix())


def cbom(configs, name="Acxelin VPN"):
    """The CBOM, as the text to write, for the site and gateway configurations in `configs`."""
    inv = Inventory()
    for path in sorted(map(Path, configs), key=lambda p: p.as_posix()):
        doc = read_toml(path)
        if "site" in doc:
            inv.site(path)
        elif "wireguard" in doc:
            inv.gateway(path)
        else:
            raise ValueError(f"{path}: no [site] or [wireguard] section, so it is not an Acxelin VPN configuration")
    components = [inv.components[k] for k in sorted(inv.components)]
    body = json.dumps(components, sort_keys=True)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256((name + body).encode()).hexdigest())}", "version": 1,
           "metadata": {"tools": {"components": [{"type": "application", "name": NAME, "version": __version__}]},
                        "component": {"type": "application", "bom-ref": "root", "name": name}},
           "components": components}
    return json.dumps(bom, indent=1, sort_keys=True) + "\n"
