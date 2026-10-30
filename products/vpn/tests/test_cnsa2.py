"""The strict profile, `cnsa2`: only the NSA's CNSA 2.0 suite on every layer. IKE and ESP use ML-KEM-1024 alone with AES-256-GCM
and SHA-384, and the key agreement allows only ML-KEM-1024, ML-DSA-87 certificates and AES-256. A site's peers are all strict or
none, because they share one key agreement service."""
import json
import textwrap

import pytest
from acxelin_core import tls
from acxelin_core.pki import CA

from acxelin_vpn import PROFILES, Peer, Site, agreement, inventory, validate
from acxelin_vpn.charon import conn_config
from acxelin_vpn.policies import CNSA2, POLICY, policy_for

CNSA = {"ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA-384", "HMAC-SHA384"}


def peer(name, profile="cnsa2", **kw):
    return Peer(name, "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True, keyring="10.0.0.2:7443", profile=profile, **kw)


def site(*peers):
    return Site("hq.acme", "10.0.0.1", "c", "k", "a", peers=list(peers))


def test_ike_and_esp_use_ml_kem_1024_alone_with_aes_256_and_sha_384():
    ike, esp = PROFILES["cnsa2"]
    assert (ike, esp) == ("aes256gcm16-prfsha384-mlkem1024", "aes256gcm16-mlkem1024")
    c = conn_config(site(peer("branch.acme")), peer("branch.acme"))["branch.acme"]
    assert c["proposals"] == [ike] and c["children"]["net"]["esp_proposals"] == [esp]
    assert not any(classical in ike + esp for classical in ("x25519", "ecp", "modp", "sha256", "mlkem768", "aes128"))


def test_the_key_agreement_allows_only_the_cnsa_suite():
    assert (CNSA2.groups, CNSA2.sigalgs, CNSA2.ciphersuites, CNSA2.cert_algorithm) == ("MLKEM1024", "mldsa87", "TLS_AES_256_GCM_SHA384", "ML-DSA-87")
    assert policy_for(site(peer("b1"), peer("b2"))) is CNSA2 and policy_for(site(peer("b1", "high"))) is POLICY


def test_a_site_cannot_mix_strict_and_ordinary_peers():
    with pytest.raises(ValueError, match="cnsa2"):
        validate(site(peer("b1"), peer("b2", "standard")))
    validate(site(peer("b1"), peer("b2")))


def test_a_certificate_that_is_not_ml_dsa_87_is_refused_before_any_connection(tmp_path):
    ca = CA.init(tmp_path / "ca", "VPN Root")
    ca.issue("hq.acme", "site", ["127.0.0.1"], out=tmp_path / "hq")  # ML-DSA-65, the default
    with pytest.raises(tls.TLSError, match="ML-DSA-87"):
        agreement.dial(("127.0.0.1", 9), tmp_path / "ca/ca.crt", tmp_path / "hq/chain.pem", tmp_path / "hq/key.pem", policy=CNSA2)
    with pytest.raises(tls.TLSError, match="ML-DSA-87"):
        agreement.keyring("127.0.0.1:0", tmp_path / "hq/chain.pem", tmp_path / "hq/key.pem", tmp_path / "ca/ca.crt", lambda c, a: None, policy=CNSA2)


def test_the_cbom_of_a_strict_site_lists_only_cnsa_algorithms_for_its_tunnels_and_key_agreement(tmp_path):
    ca = CA.init(tmp_path / "pki", "VPN Root")
    ca.issue("hq.acme", "site", ["203.0.113.10"], algorithm="ML-DSA-87", out=tmp_path / "hq")
    (tmp_path / "hq.toml").write_text(textwrap.dedent(f"""
        [site]
        name = "hq.acme"
        address = "203.0.113.10"
        cert = "{(tmp_path / 'hq' / 'chain.pem').as_posix()}"
        key = "{(tmp_path / 'hq' / 'key.pem').as_posix()}"
        ca = "{(tmp_path / 'pki' / 'ca.crt').as_posix()}"
        keyring_listen = "0.0.0.0:7443"
        [[peer]]
        name = "branch.acme"
        address = "198.51.100.7"
        local_subnets = ["10.1.0.0/16"]
        remote_subnets = ["10.2.0.0/16"]
        profile = "cnsa2"
        """))
    bom = json.loads(inventory.cbom([tmp_path / "hq.toml"], "Acme VPN"))
    named = {c["bom-ref"]: c["name"] for c in bom["components"]}
    protocols = {c["name"]: c["cryptoProperties"]["protocolProperties"] for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol"}
    tunnel = protocols["tunnel hq.acme to branch.acme"]
    used = {named[r] for refs in tunnel["ikev2TransformTypes"].values() for r in refs if named[r].startswith(("ML-", "AES", "HMAC"))}
    used |= {named[r] for s in tunnel["cipherSuites"] for r in s["algorithms"]}
    assert used <= CNSA and "ML-KEM-1024" in used
    agreement_tls = protocols["TLS 1.3 (CNSA 2.0)"]
    algos = {named[r] for r in agreement_tls["cryptoRefArray"]} | {named[r] for s in agreement_tls["cipherSuites"] for r in s["algorithms"]}
    assert algos <= CNSA, algos
