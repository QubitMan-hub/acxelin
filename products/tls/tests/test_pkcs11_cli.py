"""`acxelin-tls ca init` with the CA key in a PKCS#11 token (SoftHSM2 with ML-DSA; see core/tests/test_pkcs11_signer.py for how to get one)."""
import os
import pytest
from cryptography import x509

from acxelin_tls import cli

MODULE = os.environ.get("ACXELIN_SOFTHSM_MODULE")
PIN = "7391"
needs = pytest.mark.skipif(not MODULE and os.environ.get("ACXELIN_REQUIRE_SOFTHSM") != "1", reason="set ACXELIN_SOFTHSM_MODULE; CI sets ACXELIN_REQUIRE_SOFTHSM=1")


@pytest.fixture
def tokens(softhsm_tokens):
    return softhsm_tokens


def run(*argv):
    try:
        return cli.main(["ca", *argv])
    except SystemExit as e:  # the command line always ends in sys.exit
        if e.code:
            raise
        return 0


@needs
def test_ca_init_can_generate_the_key_in_the_token_and_the_ca_works(tmp_path, tokens, monkeypatch, capsys):
    monkeypatch.setenv("ACXELIN_PKCS11_PIN", PIN)
    label = tokens.pop()
    assert run("init", "--name", "Token Root", "--dir", str(tmp_path / "pki"), "--pkcs11-module", MODULE, "--pkcs11-token", label,
               "--pkcs11-key", "root", "--pkcs11-generate") == 0
    assert "created ML-DSA-87" in capsys.readouterr().out
    assert not (tmp_path / "pki/ca.key").exists()
    assert run("issue", "server", "svc.example", "--dir", str(tmp_path / "pki"), "--out", str(tmp_path / "svc")) == 0
    root = x509.load_pem_x509_certificate((tmp_path / "pki/ca.crt").read_bytes())
    leaf = x509.load_pem_x509_certificate((tmp_path / "svc/cert.pem").read_bytes())
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)


@needs
def test_without_the_pin_variable_nothing_is_created(tmp_path, tokens, monkeypatch, capsys):
    monkeypatch.delenv("ACXELIN_PKCS11_PIN", raising=False)
    with pytest.raises(SystemExit):
        run("init", "--name", "X", "--dir", str(tmp_path / "pki"), "--pkcs11-module", MODULE, "--pkcs11-token", tokens.pop(), "--pkcs11-key", "root", "--pkcs11-generate")
    assert "ACXELIN_PKCS11_PIN" in capsys.readouterr().err and not (tmp_path / "pki/ca.crt").exists()


def test_only_one_place_for_the_key_may_be_named(tmp_path, capsys):
    with pytest.raises(SystemExit):
        run("init", "--name", "X", "--dir", str(tmp_path / "pki"), "--kms", "k", "--pkcs11-module", "/m.so", "--pkcs11-token", "t", "--pkcs11-key", "k")
    assert "only one" in capsys.readouterr().err


def test_a_pkcs11_module_needs_a_token_and_a_key(tmp_path, capsys):
    with pytest.raises(SystemExit):
        run("init", "--name", "X", "--dir", str(tmp_path / "pki"), "--pkcs11-module", "/m.so")
    assert "--pkcs11-token" in capsys.readouterr().err
