"""Findings that were wrong in review: unrelated sizes read as key sizes, deadlines a year early, certificates in the CBOM."""
import datetime as dt
import json
from collections import Counter

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acxelin_readiness import cli, workspace


def names(root):
    return {a["name"] for a in workspace.scan(root)["assets"]}


def test_a_cache_size_next_to_an_algorithm_is_not_a_key_size(tmp_path):
    (tmp_path / "app.yaml").write_text("jwt:\n  algorithm: RS256\n  cache_size: 1000\n")
    assert not any(n.startswith("RSA-1000") for n in names(tmp_path))


def test_a_key_size_written_as_size_is_still_read(tmp_path):
    (tmp_path / "cert.yaml").write_text("spec:\n  privateKey:\n    algorithm: RSA\n    size: 2048\n")
    assert "RSA-2048" in names(tmp_path)


@pytest.mark.parametrize("year,code", [(2030, 0), (2031, 2)])
def test_deprecated_after_2030_means_from_2031(tmp_path, year, code):
    (tmp_path / "k.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    args = ["scan", str(tmp_path), "--out", str(tmp_path / f"o{year}"), "--quiet", "--policy", "nist-ir-8547", "--as-of", str(year), "--fail-on-policy"]
    if code:
        with pytest.raises(SystemExit) as e:
            cli.main(args)
        assert e.value.code == code
    else:
        assert cli.main(args) == 0


def pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "api.internal")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(3)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def test_an_rsa_certificate_keeps_its_signature_reference_and_one_component_per_certificate(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    data = pem()
    (src / "server.pem").write_bytes(data)
    (src / "fullchain.pem").write_bytes(data)
    assert cli.main(["scan", str(src), "--out", str(tmp_path / "out"), "--quiet"]) == 0
    comps = json.loads((tmp_path / "out/cbom.json").read_text())["components"]
    refs = Counter(c["bom-ref"] for c in comps)
    assert [r for r, n in refs.items() if n > 1] == [], "bom-refs are unique"
    certs = [c for c in comps if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    assert len(certs) == 1 and len(certs[0]["evidence"]["occurrences"]) == 2
    assert certs[0]["cryptoProperties"]["certificateProperties"].get("signatureAlgorithmRef")


def test_a_certificate_signed_with_sha_224_names_its_signature_and_hash(tmp_path):
    from acxelin_readiness.detectors import artifacts
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "old")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(4)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3)).sign(key, hashes.SHA224()))
    (tmp_path / "old.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    roles = {(s.algo, s.params.get("role")) for s in artifacts.scan(tmp_path)[1]}
    assert {("RSA", "certificate-signature"), ("SHA-224", "certificate-signature-hash")} <= roles
    for oid in ("1.2.840.113549.1.1.2", "1.2.840.10045.4.3.1", "2.16.840.1.101.3.4.3.20", "2.16.840.1.101.3.4.3.31"):
        assert oid in artifacts.SIG_OID
