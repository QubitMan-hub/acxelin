"""NSA's CNSA 2.0 profile for IKEv2 (CNSA 2.0 FAQ ver. 2.2, October 2026, p. 29): a P-384 exchange first, then ML-KEM-1024 as an
additional key exchange (RFC 9370), with AES-256-GCM and SHA-384. It is the `cnsa2-rfc9370` profile. The older `cnsa2` profile,
ML-KEM-1024 alone, still loads in 1.x so running sites keep their tunnels, with a warning that it is not NSA's IKEv2 form."""
import json
import logging
import textwrap

import pytest
from acxelin_core.pki import CA

from acxelin_vpn import PROFILES, Peer, Site, inventory, load_config, validate
from acxelin_vpn.charon import conn_config
from acxelin_vpn.policies import CNSA2, policy_for

NSA_FORM = "cnsa2-rfc9370"


def peer(name, profile=NSA_FORM, **kw):
    return Peer(name, "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], initiate=True, keyring="10.0.0.2:7443", profile=profile, **kw)


def site(*peers):
    return Site("hq.acme", "10.0.0.1", "c", "k", "a", peers=list(peers))


def test_ike_and_esp_do_p_384_then_ml_kem_1024_with_aes_256_and_sha_384():
    ike, esp = PROFILES[NSA_FORM]
    assert (ike, esp) == ("aes256gcm16-prfsha384-ecp384-ke1_mlkem1024", "aes256gcm16-ecp384-ke1_mlkem1024")
    c = conn_config(site(peer("branch.acme")), peer("branch.acme"))["branch.acme"]
    assert c["proposals"] == [ike] and c["children"]["net"]["esp_proposals"] == [esp]
    assert not any(other in ike + esp for other in ("x25519", "modp", "sha256", "mlkem768", "aes128", "ecp256"))


def test_its_key_agreement_is_cnsa_only_and_a_site_is_all_cnsa_or_none():
    assert policy_for(site(peer("b1"), peer("b2"))) is CNSA2
    assert policy_for(site(peer("b1"), peer("b2", "cnsa2"))) is CNSA2, "both CNSA 2.0 profiles share the CNSA 2.0 key agreement"
    with pytest.raises(ValueError, match="cnsa2"):
        validate(site(peer("b1"), peer("b2", "standard")))


def test_it_has_no_classical_fallback(tmp_path):
    key = tmp_path / "psk"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    p = Peer("partner", "10.0.0.2", ["10.1.0.0/16"], ["10.2.0.0/16"], profile=NSA_FORM, classical_fallback=True, fallback_psk_file=str(key))
    with pytest.raises(ValueError, match="classical_fallback"):
        p.validate()


def config(tmp_path, profile):
    ca = CA.init(tmp_path / "pki", "VPN Root")
    ca.issue("hq.acme", "site", ["203.0.113.10"], algorithm="ML-DSA-87", out=tmp_path / "hq")
    path = tmp_path / "hq.toml"
    path.write_text(textwrap.dedent(f"""
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
        profile = "{profile}"
        """))
    return path


def test_the_older_cnsa2_profile_still_loads_with_a_warning_that_names_the_nsa_form(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        s = load_config(config(tmp_path, "cnsa2"))
    assert s.peers[0].profile == "cnsa2" and PROFILES["cnsa2"] == ("aes256gcm16-prfsha384-mlkem1024", "aes256gcm16-mlkem1024")
    assert any(NSA_FORM in m and "branch.acme" in m for m in caplog.messages), caplog.messages
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        load_config(config(tmp_path / "new", NSA_FORM))
    assert not any(NSA_FORM in m for m in caplog.messages)


def test_the_cbom_lists_p_384_and_ml_kem_1024_for_the_tunnel(tmp_path):
    bom = json.loads(inventory.cbom([config(tmp_path, NSA_FORM)], "Acme VPN"))
    named = {c["bom-ref"]: c["name"] for c in bom["components"]}
    tunnel = next(c["cryptoProperties"]["protocolProperties"] for c in bom["components"] if c["name"] == "tunnel hq.acme to branch.acme")
    ke = {named[r] for r in tunnel["ikev2TransformTypes"]["ke"]}
    assert ke == {"ECDH-P-384", "ML-KEM-1024"}
