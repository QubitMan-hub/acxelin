"""Every CBOM shape Readiness emits validates against CycloneDX 1.6, and other tools' CBOMs (CBOMkit's examples) are read without loss.

The schema is the CycloneDX project's own (tests/fixtures/cyclonedx, identical to CycloneDX/specification master when it was vendored).
"""
import json
import re
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from acxelin_readiness import cli, inventory, workspace

HERE = Path(__file__).resolve().parent
SCHEMAS = HERE / "fixtures/cyclonedx"
SAMPLES = HERE / "fixtures/cbomkit"


def validator():
    load = lambda n: json.loads((SCHEMAS / n).read_text(encoding="utf-8"))
    registry = Registry().with_resources([(s["$id"], Resource.from_contents(s)) for s in map(load, ("spdx.schema.json", "jsf-0.82.schema.json"))])
    return jsonschema.Draft7Validator(load("bom-1.6.schema.json"), registry=registry)


def problems(bom):
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:160]}" for e in validator().iter_errors(bom)]


def mixed_project(root):
    """One project that makes the scanner emit every kind of component it can: algorithm, protocol, certificate, key material, library."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    root.mkdir()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc.example.invalid")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    (root / "svc.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "svc.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "nginx.conf").write_text("server {\n ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n ssl_ciphers 'DES-CBC3-SHA:AES128-SHA';\n}\n", encoding="utf-8")
    (root / "app.py").write_text("import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n"
                                 "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\nhashlib.md5(b'x')\n", encoding="utf-8")
    (root / "requirements.txt").write_text("cryptography==42.0.0\npyjwt==1.7.1\n", encoding="utf-8")
    return root


def scanned(tmp_path, name="mixed"):
    src = mixed_project(tmp_path / f"{name}-src")
    assert cli.main(["scan", str(src), "--out", str(tmp_path / name), "--quiet"]) == 0
    return json.loads((tmp_path / name / "cbom.json").read_text(encoding="utf-8"))


def kinds(bom):
    return {c.get("cryptoProperties", {}).get("assetType") or c["type"] for c in bom["components"]}


def test_the_checker_rejects_a_broken_cbom():
    bad = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "cryptographic-asset", "name": "x",
           "cryptoProperties": {"assetType": "not-a-real-type"}}]}
    assert problems(bad), "a schema check that accepts anything proves nothing"


def test_a_scan_emitting_every_kind_of_component_validates(tmp_path):
    bom = scanned(tmp_path)
    assert problems(bom) == []
    assert {"algorithm", "protocol", "certificate", "related-crypto-material", "library"} <= kinds(bom)


def test_every_asset_type_the_code_can_emit_is_in_the_validated_scan(tmp_path):
    """Adding an asset type to cbom.py without a sample that is validated here fails this test."""
    source = (Path(cli.__file__).parent / "cbom.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'"assetType": "([a-z-]+)"', source))
    assert emitted <= kinds(scanned(tmp_path)), f"no validated sample for {emitted - kinds(scanned(tmp_path))}"


def test_the_merged_cbom_of_several_systems_validates(tmp_path):
    a, b = scanned(tmp_path, "alpha"), scanned(tmp_path, "beta")
    taken = set()
    systems = [inventory.load(tmp_path / n / "cbom.json", taken) for n in ("alpha", "beta")]
    merged = inventory.build("org", systems)
    assert problems(merged) == []
    assert len(a["components"]) and len(b["components"])


@pytest.mark.parametrize("sample", sorted(p.name for p in SAMPLES.glob("*-cbom.json")))
def test_a_cbomkit_example_is_valid_and_read_without_loss(sample):
    path = SAMPLES / sample
    original = json.loads(path.read_text(encoding="utf-8"))
    assert problems(original) == [], "the sample itself must be valid for the comparison to mean anything"
    algorithms = sum(1 for c in original["components"] if c.get("cryptoProperties", {}).get("assetType") == "algorithm")
    imported = workspace.imported(path, sample)
    unrated = re.search(r"; (\d+) algorithm name\(s\) not recognised", imported["notes"][0])
    assert imported["summary"]["crypto_assets"] + (int(unrated.group(1)) if unrated else 0) == algorithms, "every algorithm is rated or counted as unrecognised"


def test_the_cbomkit_examples_merge_into_a_valid_cbom_that_keeps_their_key_material():
    taken = set()
    samples = sorted(SAMPLES.glob("*-cbom.json"))
    merged = inventory.build("org", [inventory.load(p, taken) for p in samples])
    assert problems(merged) == []
    expected = sum(1 for p in samples for c in json.loads(p.read_text(encoding="utf-8"))["components"]
                   if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material")
    assert sum(1 for c in merged["components"] if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material") == expected
