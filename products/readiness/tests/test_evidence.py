"""The compliance evidence report: certificates, endpoints and CBOMs mapped to NIST IR 8547 and CNSA 2.0."""
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, rsa
from cryptography.x509.oid import NameOID

from acxelin_readiness import cli, evidence


def make_cert(directory, name, key, days_left=365, sign_hash=None):
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=400)).not_valid_after(now + dt.timedelta(days=days_left)).sign(key, sign_hash))
    (directory / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


@pytest.fixture
def certs(tmp_path):
    d = tmp_path / "certs"
    d.mkdir()
    make_cert(d, "secret-site", mldsa.MLDSA87PrivateKey.generate())
    make_cert(d, "api", mldsa.MLDSA65PrivateKey.generate())
    make_cert(d, "lapsed", mldsa.MLDSA65PrivateKey.generate(), days_left=-30)
    make_cert(d, "legacy", rsa.generate_private_key(public_exponent=65537, key_size=2048), sign_hash=hashes.SHA256())
    (d / "notes.txt").write_text("not a certificate")
    return d


def test_certificates_are_classified_from_pem_files(certs):
    by = {r["name"]: r for r in evidence.certificates(certs)}
    assert set(by) == {"secret-site", "api", "lapsed", "legacy"}
    assert (by["secret-site"]["cnsa2"], by["secret-site"]["status"]) == ("compliant", "ready")
    assert (by["api"]["cnsa2"], by["api"]["status"]) == ("needs ML-DSA-87", "ready")
    assert (by["lapsed"]["status"], by["lapsed"]["cnsa2"]) == ("action", "expired")
    assert by["legacy"]["status"] == "plan" and "deprecated after 2030" in by["legacy"]["nist_ir_8547"] and by["legacy"]["cnsa2"] == "needs ML-DSA-87"


def test_a_folder_without_certificates_is_refused(tmp_path):
    (tmp_path / "x.txt").write_text("nothing here")
    with pytest.raises(ValueError, match="no certificates found"):
        evidence.certificates(tmp_path)


def ep(target, grade, accepts, negotiated, cnsa2=False, key=None, **kw):
    return {"target": target, "grade": grade, "accepts": accepts, "negotiated": negotiated, "cnsa2": cnsa2, "certificate": {"key": key} if key else None, **kw}


def test_endpoints_are_classified_by_grade_and_certificate_key():
    rows = evidence.endpoints([
        ep("a:443", "A", ["SecP384r1MLKEM1024"], "SecP384r1MLKEM1024", True, "ML-DSA-87"),
        ep("b:443", "B", ["X25519MLKEM768", "X25519"], "X25519MLKEM768", False, "ML-DSA-65"),
        ep("c:443", "A", ["X25519MLKEM768"], "X25519MLKEM768", False, "RSA-2048"),
        ep("ssh://d:22", "C", ["curve25519-sha256"], "curve25519-sha256", False, "ssh-ed25519", protocol="ssh"),
        {"target": "e:443", "grade": "F", "accepts": [], "error": "refused", "certificate": None},
        ep("f:443", "A", ["X25519MLKEM768", "TLSv1.1"], "X25519MLKEM768", False, "ML-DSA-65", legacy=["TLS 1.1"]),
    ])
    by = {r["name"]: r for r in rows}
    assert [by[n]["status"] for n in ("a:443", "b:443", "c:443", "ssh://d:22", "e:443", "f:443")] == ["ready", "transition", "transition", "action", "action", "action"]
    assert "RSA-2048 certificate: deprecated after 2030" in by["c:443"]["nist_ir_8547"]
    assert "TLS 1.1 accepted: disallowed now" in by["f:443"]["nist_ir_8547"]


def cbom(props_by_name, system="payments"):
    comps = [{"type": "cryptographic-asset", "name": n, "evidence": {"occurrences": [{"location": "keys.py", "line": 7}]},
              "properties": [{"name": k, "value": v} for k, v in p.items()]} for n, p in props_by_name.items()]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": system}}, "components": comps + [{"type": "library", "name": "cryptography"}]}


def test_a_cbom_from_any_system_becomes_rows_that_cite_locations_and_callers(tmp_path):
    bom = cbom({"RSA-1024": {"acxelin:tier": "critical", "acxelin:nist-status": "Disallowed now", "acxelin:recommendation": "ML-DSA-65",
                             "acxelin:code-impact": json.dumps({"callers": ["checkout.py#enroll"]})},
                "AES-256-GCM": {"acxelin:tier": "ok"}, "<script>alert(1)</script>": {"acxelin:tier": "medium", "acxelin:code-impact": "{not json"}})
    (tmp_path / "cbom.json").write_text(json.dumps(bom))
    (tmp_path / "findings.json").write_text(json.dumps({"patterns": [
        {"rule": "P001", "title": "Certificate verification switched off", "cwe": "CWE-295", "severity": "high", "file": "client.py", "line": 3, "fix": "verify"},
        {"rule": "P002", "title": "Secret written into source code", "cwe": "CWE-798", "severity": "low", "file": "tests/t.py", "line": 1, "fix": "x"}]}))
    rows = evidence.code(tmp_path)
    by = {r["name"]: r for r in rows}
    assert [by[n]["status"] for n in ("RSA-1024", "AES-256-GCM", "<script>alert(1)</script>")] == ["action", "ready", "plan"]
    assert "keys.py:7" in by["RSA-1024"]["detail"] and "checkout.py#enroll" in by["RSA-1024"]["detail"]
    assert (by["AES-256-GCM"]["cnsa2"], by["RSA-1024"]["cnsa2_deadline"]) == ("compliant", 2033)
    assert "client.py:3" in by["P001 Certificate verification switched off"]["detail"]
    assert not any(r["name"].startswith("P002") for r in rows), "low-severity patterns are not compliance rows"
    assert evidence.code(tmp_path / "cbom.json")[0]["name"] == "RSA-1024"
    assert "<script>alert" not in evidence.to_html(evidence.report(rows))


def test_cbom_properties_with_the_old_prefix_are_still_read(tmp_path):
    (tmp_path / "cbom.json").write_text(json.dumps(cbom({"RSA-1024": {"wolfpack:tier": "critical"}})))
    assert evidence.code(tmp_path)[0]["status"] == "action"


def test_input_that_is_not_a_cbom_is_refused_and_oversized_input_too(tmp_path):
    for name, data in (("cbom.json", b"[1, 2]"), ("bad.json", b"{not json"), ("other.json", b'{"bomFormat": "SPDX"}')):
        (tmp_path / name).write_bytes(data)
        with pytest.raises(ValueError):
            evidence.code(tmp_path / name)
    with open(tmp_path / "big.json", "wb") as f:
        f.truncate(evidence.LIMIT + 1)
    with pytest.raises(ValueError, match="larger than"):
        evidence.code(tmp_path / "big.json")


def test_the_report_page_counts_actions_and_has_one_script(certs):
    rep = evidence.report(evidence.certificates(certs))
    page = evidence.to_html(rep)
    assert "need action" in page and "Do these first" in page and page.count("<script") == 1
    assert "Wolf" not in page and "Acxelin Readiness" in page


def test_report_command_writes_the_page_and_the_evidence(certs, tmp_path, capsys):
    (tmp_path / "vpn.cbom.json").write_text(json.dumps(cbom({"IKEv2 ML-KEM-1024": {"acxelin:tier": "ok"}}, system="hq-gateway")))
    out = tmp_path / "out"
    assert cli.main(["report", "--certs", str(certs), "--cbom", str(tmp_path / "vpn.cbom.json"), "-o", str(out)]) == 0
    rep = json.loads((out / "assessment.json").read_text())
    assert rep["assets"] == 5 and any(i["name"] == "IKEv2 ML-KEM-1024" for i in rep["items"])
    assert (out / "report.html").read_text().startswith("<!doctype html>")
    printed = capsys.readouterr().out
    assert "lapsed" in printed and "report.html" in printed


def test_report_command_with_nothing_to_report_on_says_what_to_pass():
    import subprocess
    import sys
    run = subprocess.run([sys.executable, "-m", "acxelin_readiness", "report"], capture_output=True, text=True)
    assert run.returncode == 1 and "--certs" in run.stderr


def test_another_tools_cbom_without_priorities_is_rated_from_its_algorithms(tmp_path):
    comp = lambda name: {"type": "cryptographic-asset", "name": name, "cryptoProperties": {"assetType": "algorithm"},
                         "evidence": {"occurrences": [{"location": f"vendor://{name}"}]}}
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "vendor link"}},
           "components": [comp(n) for n in ("ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "RSA-2048", "MD5", "Frobnicate-9")]}
    (tmp_path / "vendor.cbom.json").write_text(json.dumps(bom))
    rows = {r["name"]: r for r in evidence.code(tmp_path / "vendor.cbom.json")}
    assert {n: rows[n]["status"] for n in rows} == {"ML-KEM-1024": "ready", "ML-DSA-87": "ready", "AES-256-GCM": "ready", "RSA-2048": "action", "MD5": "action"}
    assert [rows[n]["cnsa2"] for n in ("ML-KEM-1024", "ML-DSA-87", "AES-256-GCM")] == ["compliant"] * 3 and rows["RSA-2048"]["cnsa2"] != "compliant"
    assert all(r["evidence"]["estimated"] for r in rows.values()) and "vendor://RSA-2048" in rows["RSA-2048"]["detail"]
    assert "not classified" not in (rows["ML-KEM-1024"]["nist_ir_8547"], rows["RSA-2048"]["nist_ir_8547"])
    assert rows["AES-256-GCM"]["nist_ir_8547"] == "Quantum-safe" and "2035" in rows["RSA-2048"]["nist_ir_8547"]
