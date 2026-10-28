"""Each finding says how it was seen, how sure the scan is, and which inputs it could not observe."""
import pcapgen

from acxelin_readiness import pipeline, workspace


def asset(tmp_path, files, name, captures=()):
    for f, text in files.items():
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text(text) if isinstance(text, str) else (tmp_path / f).write_bytes(text)
    if captures:
        a = next(a for a in pipeline.run(tmp_path, "p", captures=[str(tmp_path / c) for c in captures]).assets if a.variant == name)
        return workspace.evidence_view(a)
    return next(a for a in workspace.scan(tmp_path)["assets"] if a["name"] == name)


def test_a_key_generated_in_code_is_seen_in_code_with_nothing_missing(tmp_path):
    a = asset(tmp_path, {"k.py": "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n"}, "RSA-2048")
    assert a["seen"] == ["in code"] and a["missing"] == [] and a["confidence_level"] == "high"


def test_a_finding_seen_only_as_supported_says_what_was_not_seen():
    from acxelin_readiness.model import Asset, Detection
    found = Asset(ref="r", algo="RSA", variant="RSA", params={}, confidence=0.7, declared=False,
                  detections=[Detection(algo="RSA", file="lib.so", line=0, evidence="binary", detector="binary")])
    assert workspace.evidence_view(found) == {"seen": ["supported"], "missing": ["key size", "observed use"], "confidence_level": "medium"}


def test_a_configured_protocol_is_configured(tmp_path):
    a = asset(tmp_path, {"nginx.conf": "server {\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n"}, "TLS 1.2")
    assert a["seen"] == ["configured"]


def test_aes_without_its_size_or_mode_names_both(tmp_path):
    a = asset(tmp_path, {"c.py": "from cryptography.hazmat.primitives.ciphers import algorithms, Cipher\nc = Cipher(algorithms.AES(key), mode)\n"}, "AES")
    assert {"key size", "mode"} <= set(a["missing"])


def test_a_negotiated_group_in_a_capture_is_negotiated(tmp_path):
    a = asset(tmp_path, {"t.pcap": pcapgen.pcap(pcapgen.tls_capture([0x11EC], pcapgen.server_hello(0x1301, group=0x11EC)))}, "X25519MLKEM768", captures=["t.pcap"])
    assert a["seen"] == ["negotiated"] and a["confidence_level"] == "high"


def test_an_imported_finding_says_so():
    from acxelin_readiness.workspace import evidence_view  # noqa: F401 - the helper exists for scans; imports set their own
    import json
    import tempfile
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    (d / "x.json").write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"type": "cryptographic-asset", "name": "RSA-2048", "cryptoProperties": {"assetType": "algorithm"}}]}))
    a = workspace.imported(d / "x.json", "x")["assets"][0]
    assert a["seen"] == ["imported"] and a["confidence_level"] is None
