"""Revocation under an intermediate CA. A certificate is only cleared by a CRL from the CA that issued it, so the root's list
cannot vouch for a certificate the intermediate revoked; the root's list revokes the intermediate itself when both lists sit in
one file; and a resumed session, which carries no chain, is still checked against the right list."""
import pytest
from cryptography import x509

from acxelin_core.pki import CA, CAError
from acxelin_core.server import Revocation


@pytest.fixture
def pki(tmp_path):
    root = CA.init(tmp_path / "root", "Root")
    issuing = CA.init(tmp_path / "issuing", "Issuing", parent=root)
    _, dave = issuing.issue("dave", "client", out=tmp_path / "dave")
    _, erin = issuing.issue("erin", "client", out=tmp_path / "erin")
    leaf = lambda who: x509.load_pem_x509_certificate((tmp_path / who / "cert.pem").read_bytes())
    inter = x509.load_pem_x509_certificate((tmp_path / "issuing" / "ca.crt").read_bytes())
    return tmp_path, root, issuing, leaf("dave"), leaf("erin"), inter


def both(tmp_path, root, issuing):
    root.crl()
    issuing.crl()
    combined = tmp_path / "crls.pem"
    combined.write_bytes((tmp_path / "issuing" / "crl.pem").read_bytes() + (tmp_path / "root" / "crl.pem").read_bytes())
    return combined


def test_a_crl_from_another_ca_cannot_clear_a_certificate(pki):
    tmp_path, root, issuing, dave, erin, inter = pki
    issuing.revoke(format(dave.serial_number, "x"), "keyCompromise")
    root.crl()
    r = Revocation(tmp_path / "root" / "crl.pem", tmp_path / "root" / "ca.crt")
    with pytest.raises(CAError, match="Issuing"):
        r.check(dave.serial_number, [inter], dave.issuer)


def test_both_lists_in_one_file_revoke_the_leaf_and_the_intermediate(pki):
    tmp_path, root, issuing, dave, erin, inter = pki
    issuing.revoke(format(dave.serial_number, "x"), "keyCompromise")
    r = Revocation(both(tmp_path, root, issuing), tmp_path / "root" / "ca.crt")
    with pytest.raises(CAError, match="revoked"):
        r.check(dave.serial_number, [inter], dave.issuer)
    r.check(erin.serial_number, [inter], erin.issuer)
    root.revoke(format(inter.serial_number, "x"), "cACompromise")
    r = Revocation(both(tmp_path, root, issuing), tmp_path / "root" / "ca.crt")
    with pytest.raises(CAError, match="revoked"):
        r.check(erin.serial_number, [inter], erin.issuer)


def test_a_resumed_session_without_a_chain_is_still_checked(pki):
    tmp_path, root, issuing, dave, erin, inter = pki
    r = Revocation(both(tmp_path, root, issuing), tmp_path / "root" / "ca.crt")
    r.check(erin.serial_number, [inter], erin.issuer)
    r.check(erin.serial_number, [], erin.issuer)  # TLS session resumption: OpenSSL hands back no verified chain
    issuing.revoke(format(erin.serial_number, "x"), "keyCompromise")
    r = Revocation(both(tmp_path, root, issuing), tmp_path / "root" / "ca.crt")
    r.check(dave.serial_number, [inter], dave.issuer)
    with pytest.raises(CAError, match="revoked"):
        r.check(erin.serial_number, [], erin.issuer)


def test_a_certificate_issued_by_the_root_works_as_before(tmp_path):
    root = CA.init(tmp_path / "root", "Root")
    _, rec = root.issue("bob", "client", out=tmp_path / "bob")
    bob = x509.load_pem_x509_certificate((tmp_path / "bob" / "cert.pem").read_bytes())
    root.crl()
    r = Revocation(tmp_path / "root" / "crl.pem", tmp_path / "root" / "ca.crt")
    r.check(bob.serial_number, [], bob.issuer)
    root.revoke(format(bob.serial_number, "x"), "keyCompromise")
    with pytest.raises(CAError, match="revoked"):
        Revocation(tmp_path / "root" / "crl.pem", tmp_path / "root" / "ca.crt").check(bob.serial_number, [], bob.issuer)
