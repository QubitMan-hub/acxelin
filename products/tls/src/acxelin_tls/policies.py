"""What a connection through Acxelin TLS may negotiate: the product's named policies, handed to the core's TLS mechanism."""
from acxelin_core.tls import Policy, TLSError

PQC_GROUPS = "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768"
CIPHERSUITES = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

POLICIES = {
    # post-quantum only
    "strict": Policy("strict", PQC_GROUPS, "mldsa87:mldsa65:mldsa44", CIPHERSUITES),
    # prefers post-quantum, still talks to classical peers
    "transition": Policy("transition", PQC_GROUPS + ":X25519:secp256r1:secp384r1", None, CIPHERSUITES),
    # NSA CNSA 2.0: ML-KEM-1024, ML-DSA-87 and AES-256 only. Pure ML-KEM-1024: the CNSA 2.0 FAQ (ver. 2.2, p. 28) counts a hybrid
    # only where NSA named it, and it names no TLS hybrid
    "cnsa2": Policy("cnsa2", "MLKEM1024", "mldsa87", "TLS_AES_256_GCM_SHA384", "ML-DSA-87"),
}


def policy(name):
    if name not in POLICIES:
        raise TLSError(f"unknown policy {name}; choose from {', '.join(POLICIES)}")
    return POLICIES[name]
