"""The CA's key inside a PKCS#11 token (HSM, smart card, SoftHSM): it signs there and never leaves.

The first group needs nothing but Python. The second talks to a real PKCS#11 module with ML-DSA (PKCS#11 3.2): SoftHSM2 built from its develop
branch (release 2.7.0 has no ML-DSA). Set ACXELIN_SOFTHSM_MODULE to libsofthsm2.so and ACXELIN_SOFTHSM_UTIL to softhsm2-util (or put it next
to the module); ACXELIN_REQUIRE_SOFTHSM=1 turns "not set" into a failure, as CI does.
"""
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from acxelin_core import openssl
from acxelin_core.pki import CA, CAError, signers
from acxelin_core.pki import pkcs11

MODULE = os.environ.get("ACXELIN_SOFTHSM_MODULE")
PIN = "7391"


def test_a_public_key_from_a_token_becomes_the_standard_subject_public_key_info():
    if openssl.available() is not None:
        pytest.skip("needs OpenSSL 3.5+ for ML-DSA")
    for algorithm, cls_name in (("ML-DSA-44", "MLDSA44PrivateKey"), ("ML-DSA-65", "MLDSA65PrivateKey"), ("ML-DSA-87", "MLDSA87PrivateKey")):
        key = getattr(mldsa, cls_name).generate()
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        standard = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        assert pkcs11.spki(algorithm, raw) == standard


def test_the_parameter_set_names_the_algorithm_and_nothing_else_is_accepted():
    assert [pkcs11.algorithm_of(n) for n in (1, 2, 3)] == ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    with pytest.raises(signers.SignerError, match="parameter set 9"):
        pkcs11.algorithm_of(9)


def test_a_pin_in_the_configuration_file_is_refused(tmp_path):
    cfg = {"type": "pkcs11", "module": "/x.so", "token": "t", "key": "k", "pin": "1234"}
    with pytest.raises(signers.SignerError, match="PIN"):
        pkcs11.from_config(cfg)


def test_a_missing_pin_variable_is_an_error_in_words(monkeypatch):
    monkeypatch.delenv("ACXELIN_PKCS11_PIN", raising=False)
    with pytest.raises(signers.SignerError, match="ACXELIN_PKCS11_PIN"):
        pkcs11.from_config({"type": "pkcs11", "module": "/x.so", "token": "t", "key": "k"})


def test_a_module_that_does_not_exist_is_an_error_in_words(monkeypatch):
    monkeypatch.setenv("ACXELIN_PKCS11_PIN", PIN)
    with pytest.raises(signers.SignerError, match="cannot load the PKCS#11 module"):
        pkcs11.from_config({"type": "pkcs11", "module": "/no/such/module.so", "token": "t", "key": "k"})


def test_the_signer_configuration_of_a_pkcs11_ca_is_recognised():
    assert "pkcs11" in signers.__doc__ or "PKCS#11" in signers.__doc__


needs_softhsm = pytest.mark.skipif(not MODULE and os.environ.get("ACXELIN_REQUIRE_SOFTHSM") != "1",
                                   reason="set ACXELIN_SOFTHSM_MODULE (SoftHSM2 develop with ML-DSA); CI sets ACXELIN_REQUIRE_SOFTHSM=1")


@pytest.fixture
def token(softhsm_tokens, monkeypatch):
    monkeypatch.setenv("ACXELIN_PKCS11_PIN", PIN)
    assert softhsm_tokens, "more tests than tokens in the pool"
    return softhsm_tokens.pop()


def config(token, key="ca-key"):
    return {"type": "pkcs11", "module": MODULE, "token": token, "key": key}


@needs_softhsm
def test_a_ca_whose_key_lives_in_the_token_signs_certificates_and_crls(tmp_path, token):
    pkcs11.generate(MODULE, token, PIN, "ca-key", "ML-DSA-87")
    ca = CA.init(tmp_path / "ca", "Token Root", algorithm="ML-DSA-87", signer_config=config(token))
    assert ca.algorithm == "ML-DSA-87"
    root = x509.load_pem_x509_certificate((tmp_path / "ca/ca.crt").read_bytes())
    root.public_key().verify(root.signature, root.tbs_certificate_bytes)  # the self-signature verifies with standard ML-DSA
    out, rec = ca.issue("svc", "server", ["svc.example"], out=tmp_path / "svc")
    leaf = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)
    ca.revoke(rec.serial, "keyCompromise")
    crl = x509.load_pem_x509_crl((tmp_path / "ca/crl.pem").read_bytes())
    root.public_key().verify(crl.signature, crl.tbs_certlist_bytes)
    assert crl.get_revoked_certificate_by_serial_number(int(rec.serial, 16)) is not None


@needs_softhsm
def test_no_private_key_is_ever_written_where_the_ca_lives(tmp_path, token):
    pkcs11.generate(MODULE, token, PIN, "ca-key", "ML-DSA-65")
    CA.init(tmp_path / "ca", "Token Root", algorithm="ML-DSA-65", signer_config=config(token)).issue("svc", "server", out=tmp_path / "svc")
    assert not (tmp_path / "ca/ca.key").exists()
    leaked = [p.name for p in (tmp_path / "ca").rglob("*") if p.is_file() and b"PRIVATE KEY" in p.read_bytes()]
    assert leaked == []
    assert "pin" not in (tmp_path / "ca/signer.json").read_text(encoding="utf-8").lower().replace("pin_env", ""), "the PIN is never written down"


@needs_softhsm
def test_the_token_refuses_to_reveal_the_private_key(token):
    pkcs11.generate(MODULE, token, PIN, "ca-key", "ML-DSA-44")
    with pytest.raises(signers.SignerError, match="not extractable|cannot read"):
        pkcs11.Token(MODULE, token, PIN).read_private_value("ca-key")


@needs_softhsm
def test_a_wrong_pin_is_refused_in_words_without_printing_it(tmp_path, token, monkeypatch):
    pkcs11.generate(MODULE, token, PIN, "ca-key", "ML-DSA-65")
    monkeypatch.setenv("ACXELIN_PKCS11_PIN", "0000")
    with pytest.raises(CAError) as e:
        CA.init(tmp_path / "ca", "Token Root", algorithm="ML-DSA-65", signer_config=config(token))
    assert "PIN" in str(e.value) and "0000" not in str(e.value) and PIN not in str(e.value)


@needs_softhsm
def test_a_token_or_key_that_is_not_there_is_named(tmp_path, token):
    pkcs11.generate(MODULE, token, PIN, "ca-key", "ML-DSA-65")
    with pytest.raises(CAError, match="no token labelled 'nope'"):
        CA.init(tmp_path / "a", "X", algorithm="ML-DSA-65", signer_config=config("nope"))
    with pytest.raises(CAError, match="no ML-DSA key labelled 'missing'"):
        CA.init(tmp_path / "b", "X", algorithm="ML-DSA-65", signer_config=config(token, "missing"))


@needs_softhsm
def test_a_ca_reopened_later_signs_with_the_same_key(tmp_path, token):
    pkcs11.generate(MODULE, token, PIN, "ca-key", "ML-DSA-65")
    CA.init(tmp_path / "ca", "Token Root", algorithm="ML-DSA-65", signer_config=config(token))
    root = x509.load_pem_x509_certificate((tmp_path / "ca/ca.crt").read_bytes())
    reopened = CA(tmp_path / "ca")
    out, _ = reopened.issue("later", "server", out=tmp_path / "later")
    root.public_key().verify(x509.load_pem_x509_certificate((out / "cert.pem").read_bytes()).signature,
                             x509.load_pem_x509_certificate((out / "cert.pem").read_bytes()).tbs_certificate_bytes)


def test_the_structures_declare_packing_only_where_the_platform_needs_it():
    """Python 3.14 refuses `_pack_` on the gcc layout (Linux, macOS) outright, even as 0; PKCS#11 asks for 1-byte packing on Windows only."""
    for cls in (pkcs11.Attribute, pkcs11.Mechanism):
        assert hasattr(cls, "_pack_") == (os.name == "nt")
