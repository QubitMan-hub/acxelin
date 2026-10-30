"""What the VPN's own key agreement may negotiate: post-quantum hybrid key exchange, ML-DSA certificates and TLS 1.3 only.
Every gateway and computer must use the same policy to agree keys; a site whose peers use the `cnsa2` profile uses CNSA2."""
from acxelin_core.tls import Policy

POLICY = Policy("acxelin-vpn", "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768", "mldsa87:mldsa65:mldsa44",
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
CNSA2 = Policy("acxelin-vpn-cnsa2", "MLKEM1024", "mldsa87", "TLS_AES_256_GCM_SHA384", "ML-DSA-87")


def policy_for(site):
    return CNSA2 if site.peers and all(p.profile == "cnsa2" for p in site.peers) else POLICY
