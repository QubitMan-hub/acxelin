"""Keystores: what protects a PKCS#12 or Java keystore and which certificates it holds, read without any password."""
import datetime as dt
import json
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from acxelin_readiness import workspace
from acxelin_readiness.detectors import artifacts


def certificate(key, name="app.internal"):
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90)).sign(key, hashes.SHA256()))


@pytest.fixture(scope="module")
def key():
    return ec.generate_private_key(ec.SECP256R1())


def p12(key, encryption):
    return pkcs12.serialize_key_and_certificates(b"app", key, certificate(key), None, encryption)


def legacy():
    return (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(2048)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(b"changeit"))


def found(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    arts, sights, _ = artifacts.scan(tmp_path)
    return arts, sights, {(s.algo, s.params.get("role")) for s in sights}


def test_a_modern_pkcs12_is_protected_by_aes_256_and_pbkdf2(tmp_path, key):
    _, sights, seen = found(tmp_path, "server.p12", p12(key, serialization.BestAvailableEncryption(b"changeit")))
    assert ("AES", "keystore-protection") in seen and ("PBKDF2", "keystore-protection") in seen
    assert next(s for s in sights if s.algo == "AES").params["key_size"] == 256
    assert not {"3DES", "RC2", "SHA-1"} & {a for a, _ in seen}


def test_a_legacy_pkcs12_shows_3des_and_sha_1(tmp_path, key):
    _, _, seen = found(tmp_path, "legacy.pfx", p12(key, legacy()))
    assert {("3DES", "keystore-protection"), ("SHA-1", "keystore-protection")} <= seen


def test_an_unprotected_pkcs12_lists_its_certificate_and_its_key_algorithm_never_the_key(tmp_path, key):
    arts, _, seen = found(tmp_path, "open.p12", p12(key, serialization.NoEncryption()))
    kinds = {(a.kind, a.algo) for a in arts}
    assert ("certificate", "ECC") in kinds and ("private-key", "ECC") in kinds
    secret = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    assert secret.hex() not in json.dumps([vars(a) for a in arts], default=str)


def jks(entries, magic=0xFEEDFEED):
    out = struct.pack(">III", magic, 2, len(entries))
    utf = lambda s: struct.pack(">H", len(s)) + s.encode()
    for tag, alias, der in entries:
        out += struct.pack(">I", tag) + utf(alias) + struct.pack(">Q", 0)
        if tag == 1:
            out += struct.pack(">I", 48) + bytes(48) + struct.pack(">I", 1) + utf("X.509") + struct.pack(">I", len(der)) + der
        else:
            out += utf("X.509") + struct.pack(">I", len(der)) + der
    return out + bytes(20)


def test_a_java_keystore_lists_its_certificates_and_its_sha_1_key_protection(tmp_path, key):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = lambda k, n: certificate(k, n).public_bytes(serialization.Encoding.DER)
    arts, _, seen = found(tmp_path, "server.jks", jks([(1, "server", der(rsa_key, "server")), (2, "root", der(key, "root"))]))
    certs = {a.details["subject"] for a in arts if a.kind == "certificate"}
    assert certs == {"CN=server", "CN=root"}
    private = [a for a in arts if a.kind == "private-key"]
    assert [(a.algo, a.details["format"], a.details["encrypted"]) for a in private] == [("RSA", "JKS", True)]
    assert ("SHA-1", "keystore-protection") in seen


def test_a_jceks_keystore_shows_md5_and_3des_protection(tmp_path, key):
    der = certificate(key).public_bytes(serialization.Encoding.DER)
    _, _, seen = found(tmp_path, "store.keystore", jks([(1, "k", der)], magic=0xCECECECE))
    assert {("MD5", "keystore-protection"), ("3DES", "keystore-protection")} <= seen


@pytest.mark.parametrize("data", [
    struct.pack(">III", 0xFEEDFEED, 2, 0xFFFFFFFF), struct.pack(">III", 0xFEEDFEED, 2, 1) + struct.pack(">I", 2) + b"\xff\xff",
    struct.pack(">III", 0xFEEDFEED, 2, 1) + struct.pack(">IH", 2, 1) + b"a" + bytes(8) + struct.pack(">H", 5) + b"X.509" + struct.pack(">I", 0x7FFFFFFF),
    b"\x30\x82\xff\xff" + bytes(50), b"",
])
def test_a_damaged_keystore_is_skipped_without_failing_the_scan(tmp_path, data):
    arts, sights, _ = found(tmp_path, "broken.jks" if data[:4] != b"\x30\x82\xff\xff" else "broken.p12", data)
    assert all(a.kind != "private-key" for a in arts)


def test_keystore_findings_reach_the_assessment(tmp_path, key):
    (tmp_path / "legacy.pfx").write_bytes(p12(key, legacy()))
    names = {a["name"] for a in workspace.scan(tmp_path)["assets"]}
    assert "3DES" in names and "SHA-1" in names


def test_a_keystore_scan_writes_a_valid_cyclonedx_cbom(tmp_path, key):
    import jsonschema
    from referencing import Registry, Resource
    from pathlib import Path
    from acxelin_readiness import cli
    (tmp_path / "src").mkdir()
    (tmp_path / "src/open.p12").write_bytes(p12(key, serialization.NoEncryption()))
    (tmp_path / "src/legacy.pfx").write_bytes(p12(key, legacy()))
    (tmp_path / "src/server.jks").write_bytes(jks([(1, "server", certificate(key).public_bytes(serialization.Encoding.DER))]))
    assert cli.main(["scan", str(tmp_path / "src"), "--out", str(tmp_path / "out"), "--quiet"]) == 0
    cbom = json.loads((tmp_path / "out/cbom.json").read_text())
    schemas = Path(__file__).resolve().parents[1] / ".cache/schemas"
    load = lambda n: json.loads((schemas / n).read_text())
    registry = Registry().with_resources([(s["$id"], Resource.from_contents(s)) for s in map(load, ("spdx.schema.json", "jsf-0.82.schema.json"))])
    jsonschema.Draft7Validator(load("bom-1.6.schema.json"), registry=registry).validate(cbom)
    formats = {c["cryptoProperties"]["relatedCryptoMaterialProperties"]["format"] for c in cbom["components"]
               if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material"}
    assert {"PKCS#12", "JKS"} <= formats


def test_a_keystore_entry_with_a_key_type_this_library_cannot_load_is_reported_not_fatal(tmp_path, key):
    der = bytearray(certificate(key).public_bytes(serialization.Encoding.DER))
    oid = bytes([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])  # id-ecPublicKey, 1.2.840.10045.2.1
    at = der.index(oid)
    der[at + 8] = 0x7F  # 1.2.840.10045.2.127: no library knows it
    arts, _, _ = found(tmp_path, "odd.jks", jks([(1, "odd", bytes(der))]))
    assert [(a.kind, a.algo) for a in arts if a.kind == "private-key"] == [("private-key", "unknown")]
    assert workspace.scan(tmp_path)["assets"] is not None


def test_binary_der_keys_and_certificate_requests_are_found_like_pem_ones(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from acxelin_readiness import workspace
    der, pem = serialization.Encoding.DER, serialization.Encoding.PEM
    r, e, ed = rsa.generate_private_key(public_exponent=65537, key_size=2048), ec.generate_private_key(ec.SECP384R1()), ed25519.Ed25519PrivateKey.generate()
    none = serialization.NoEncryption()
    (tmp_path / "rsa.pkcs1.der").write_bytes(r.private_bytes(der, serialization.PrivateFormat.TraditionalOpenSSL, none))
    (tmp_path / "ec.key").write_bytes(e.private_bytes(der, serialization.PrivateFormat.PKCS8, none))
    (tmp_path / "ed.der").write_bytes(ed.private_bytes(der, serialization.PrivateFormat.PKCS8, none))
    (tmp_path / "locked.der").write_bytes(r.private_bytes(der, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw")))
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "a")]))
    (tmp_path / "small.csr").write_bytes(csr.sign(rsa.generate_private_key(public_exponent=65537, key_size=1024), hashes.SHA256()).public_bytes(der))
    (tmp_path / "req.pem").write_bytes(csr.sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()).public_bytes(pem))
    found = {a["name"]: {f for f, _ in a["locations"]} for a in workspace.scan(tmp_path)["assets"]}
    assert {"rsa.pkcs1.der", "small.csr"} <= found.get("RSA-2048", set()) | found.get("RSA-1024", set())
    assert found["RSA-2048"] >= {"rsa.pkcs1.der"} and found["RSA-1024"] == {"small.csr"}
    assert found["ECC-P-384"] == {"ec.key"} and found["Ed25519"] == {"ed.der"} and "req.pem" in found["ECC-P-256"]
