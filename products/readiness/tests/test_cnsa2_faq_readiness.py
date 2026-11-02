"""CNSA 2.0 as NSA's FAQ (ver. 2.2, October 2026) states it: required in new acquisitions from 1 January 2027, equipment that cannot do
it phased out by 31 December 2030, mandatory by 31 December 2031 (p. 17-19); LMS and XMSS only for signing firmware and software, never
HSS or XMSS^MT (p. 11); a hybrid counts only where NSA named it, and no TLS hybrid is named (p. 28)."""
import json

import pytest

from acxelin_core import openssl
from acxelin_core.pki import CA
from acxelin_core.server import Server
from acxelin_core.tls import Policy, server_context
from acxelin_readiness import compliance, endpoints, evidence, pipeline


def test_the_nsa_dates_are_the_faqs():
    nsa = [d for d in compliance.deadlines(["us"], ["national-security"], 2026) if "CNSA" in d["who"]]
    assert [d["year"] for d in nsa] == [2027, 2030, 2031]
    assert all(d["year"] != 2033 for d in compliance.deadlines(["us"], [], 2026))


def test_the_default_cnsa_deadline_is_2031(tmp_path):
    assert set(evidence.CNSA2_DEADLINE.values()) == {2031}
    (tmp_path / "keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    rsa = [a for a in pipeline.run(tmp_path, "t").assets if a.algo == "RSA"]
    assert rsa, "the fixture must give an RSA asset"
    result = compliance.evaluate(rsa, [], {"profiles": ["cnsa-2.0"]})
    assert [v.get("deadline") for v in result["violations"] if v["rule"] == "CNSA 2.0"] == [2031], result


def test_stateful_hash_signatures_lms_and_xmss_only_never_hss_or_xmss_mt(tmp_path):
    comp = lambda name: {"type": "cryptographic-asset", "name": name, "cryptoProperties": {"assetType": "algorithm"},
                         "properties": [{"name": "acxelin:tier", "value": "ok"}]}  # rated: an unrated unknown algorithm is not a row at all
    names = ("LMS_SHA256_M32_H10", "XMSS-SHA2_10_256", "XMSSMT-SHA2_20/2_256", "HSS-LMS", "SHA-512/224", "AES-256-GCM")
    (tmp_path / "v.cbom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [comp(n) for n in names]}))
    rows = {r["name"]: r["cnsa2"] for r in evidence.code(tmp_path / "v.cbom.json")}
    assert rows["LMS_SHA256_M32_H10"] == rows["XMSS-SHA2_10_256"] == "compliant for signing firmware and software only"
    assert rows["XMSSMT-SHA2_20/2_256"] != "compliant" and "compliant" not in rows["HSS-LMS"] and "compliant" not in rows["SHA-512/224"]
    assert rows["AES-256-GCM"] == "compliant"


@pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")
@pytest.mark.parametrize("groups,meets", [("MLKEM1024", True), ("SecP384r1MLKEM1024", False)])
def test_only_pure_ml_kem_1024_meets_cnsa_2_for_tls(tmp_path, request, groups, meets):
    ca = CA.init(tmp_path / "ca", "CNSA Test CA")
    out, _ = ca.issue("app.internal", "server", ["127.0.0.1"], out=tmp_path / "app", algorithm="ML-DSA-87")
    policy = Policy("t", groups, "mldsa87", "TLS_AES_256_GCM_SHA384")
    srv = Server(("127.0.0.1", 0), lambda: server_context(policy, out / "chain.pem", out / "key.pem"), lambda c, a: c.close(), name="t")
    srv.start()
    request.addfinalizer(lambda: srv.stop(grace=1))
    r = endpoints.probe(f"127.0.0.1:{srv.port}", timeout=5)
    assert r["accepts"] == [groups] and r["cnsa2"] is meets, r
