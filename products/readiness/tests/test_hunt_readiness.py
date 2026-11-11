"""Wrong results a correctness review reproduced on real projects, each now fixed: SLH-DSA certificates called quantum-vulnerable,
`PqDsa` read as DSA, `jwt.sign` with a variable algorithm called HMAC, snippets that show rewritten code, curves on one line
merged into one, SARIF results pointing at places that are not files, NIST wording for strong keys, and SHA-1's "1"."""
import tempfile
import unittest
from pathlib import Path

from acxelin_core import openssl
from acxelin_readiness import cbom, evidence, pipeline


def scan(files):
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            (Path(d) / name).parent.mkdir(parents=True, exist_ok=True)
            (Path(d) / name).write_text(text)
        return pipeline.run(d, "t")


class DetectorTest(unittest.TestCase):
    def test_pqdsa_is_not_dsa(self):
        r = scan({"src/sign_algo.rs": 'pub fn alg() -> SignAlgo { SignAlgo::PqDsa("ml-dsa-65") }\nlet a = PKCS_PQDSA_ML_DSA_65;\n'})
        self.assertNotIn("DSA", {s.algo for s in r.detections})

    def test_jwt_sign_with_a_variable_algorithm_is_not_called_hmac(self):
        r = scan({"sign.js": "const jwt = require('jsonwebtoken');\nfunction s(payload, privateKey, algorithm) {\n"
                             "  return jwt.sign(payload, privateKey, { algorithm: algorithm });\n}\n"})
        self.assertNotIn("HMAC", {s.algo for s in r.detections})
        r = scan({"sign.js": "const jwt = require('jsonwebtoken');\nconst t = jwt.sign(payload, 'secret');\n"})
        self.assertIn("HMAC", {s.algo for s in r.detections}, "no algorithm at all is still HS256")

    def test_snippets_show_the_source_as_written(self):
        r = scan({"a.js": "const crypto = require('crypto');\nconst algo = 'md5';\nfunction f(x) {\n"
                          "  console.log('digest done');\n  return crypto.createHash(algo).update(x).digest('hex');\n}\n"})
        snips = [s.snippet for s in r.detections if s.file == "a.js"]
        self.assertTrue(snips)
        self.assertTrue(all('"md5"' not in s and "'md5'" not in s or s.startswith("const algo") for s in snips), snips)
        self.assertTrue(any("createHash(algo)" in s for s in snips), snips)

    def test_two_curves_on_one_line_are_both_kept(self):
        r = scan({"jwt.js": "const jwt = require('jsonwebtoken');\nconst ALGS = ['ES384', 'ES512'];\njwt.verify(t, key, { algorithms: ALGS });\n"})
        curves = {s.params.get("curve") for s in r.detections if s.algo == "ECDSA"}
        self.assertTrue({"P-384", "P-521"} <= curves, curves)


class OutputTest(unittest.TestCase):
    def test_sarif_points_only_at_files(self):
        r = scan({"a.py": "import hashlib\nhashlib.md5(b'x')\n"})
        for a in r.assets:
            for s in a.detections[:1]:
                s.file = "pcap://cap.pcap/10.0.0.22:22"
        r2 = scan({"a.py": "import hashlib\nhashlib.md5(b'x')\n"})
        doc = cbom.sarif(r.assets + r2.assets, r.alerts)
        uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for run in doc["runs"] for res in run["results"] for loc in res["locations"]]
        self.assertTrue(uris)
        self.assertFalse([u for u in uris if "%3A//" in u or "://" in u], uris)

    def test_sha1_has_no_parameter_set_of_1(self):
        r = scan({"a.py": "import hashlib\nhashlib.sha1(b'x')\n"})
        comp = next(cbom.algorithm_component(a) for a in r.assets if a.algo == "SHA-1")
        self.assertNotEqual(comp["cryptoProperties"]["algorithmProperties"].get("parameterSetIdentifier"), "1")


@unittest.skipIf(openssl.available(), "needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")
class EvidenceTest(unittest.TestCase):
    def test_slh_dsa_and_strong_classical_certificates_are_described_right(self):
        from acxelin_core.pki import CA
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
        with tempfile.TemporaryDirectory() as d:
            CA.init(Path(d) / "slh", "SLH Root", algorithm="SLH-DSA-SHA2-128s")
            certs = Path(d) / "certs"
            certs.mkdir()
            (certs / "slh.pem").write_bytes((Path(d) / "slh" / "ca.crt").read_bytes())
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "rsa4096")])
            now = dt.datetime.now(dt.timezone.utc)
            c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
                 .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
            (certs / "rsa.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
            rows = {r["name"]: r for r in evidence.certificates(certs)}
        self.assertEqual(rows["SLH Root"]["status"], "ready", rows["SLH Root"])
        self.assertIn("FIPS 205", rows["SLH Root"]["nist_ir_8547"])
        self.assertNotIn("deprecated after 2030", rows["rsa4096"]["nist_ir_8547"], "RSA-4096 is not a 112-bit key")


class MergeTest(unittest.TestCase):
    def test_merge_gives_the_same_share_of_quantum_safe_as_the_scan(self):
        import json
        from acxelin_readiness import inventory
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "src"
            src.mkdir()
            (src / "a.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
                                      "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                                      "rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
                                      "ec.generate_private_key(ec.SECP256R1())\n")
            r = pipeline.run(str(src), "t")
            out = Path(d) / "out"
            out.mkdir()
            (out / "cbom.json").write_text(json.dumps(cbom.build("t", r.assets, r.artifacts, r.libraries)))
            merged = inventory.load(out / "cbom.json", set())
        self.assertEqual(merged["readiness"]["asymmetric"], r.readiness["asymmetric"])
        self.assertEqual(merged["readiness"]["percent"], r.readiness["percent"])


def test_es256k_is_ecdsa_on_secp256k1():
    from acxelin_readiness.detectors.suites import sig_scheme
    assert sig_scheme("ES256K")[0] == ("ECDSA", {"hash": "SHA-256", "curve": "secp256k1"})


def test_a_local_constant_does_not_reach_another_function():
    r = scan({"a.js": "const crypto = require('crypto');\nfunction a(x) {\n  const algo = 'md5';\n  return crypto.createHash(algo).update(x).digest();\n}\n"
                      "function b(x, algo) {\n  return crypto.createHash(algo).update(x).digest();\n}\n"})
    lines = {s.line for s in r.detections if s.algo == "MD5"}
    assert 4 in lines and 7 not in lines, lines
    r = scan({"b.js": "const crypto = require('crypto');\nconst ALGO = 'md5';\nfunction b(x) {\n  return crypto.createHash(ALGO).update(x).digest();\n}\n"})
    assert 4 in {s.line for s in r.detections if s.algo == "MD5"}, "a file-level constant still reaches every function"


def test_rust_unit_tests_in_the_source_file_count_as_tests():
    r = scan({"src/lib.rs": "use rsa::RsaPrivateKey;\npub fn make() { let k = RsaPrivateKey::new(&mut rng, 2048); }\n\n#[cfg(test)]\nmod tests {\n"
                            "    use super::*;\n    #[test]\n    fn t() { let k = RsaPrivateKey::new(&mut rng, 4096); if x { y(); } }\n}\n"
                            "pub fn after() { let k = RsaPrivateKey::new(&mut rng, 3072); }\n"})
    ctx = {s.line: "test" in s.context for s in r.detections if s.algo == "RSA"}
    assert ctx.get(8) is True and ctx.get(2) is False and ctx.get(10) is False, ctx


def test_a_refused_port_is_graded_after_one_connection():
    import socket
    from unittest import mock
    from acxelin_readiness import endpoints
    calls = []

    def refuse(*a, **k):
        calls.append(1)
        raise ConnectionRefusedError(111, "Connection refused")
    with mock.patch.object(socket, "create_connection", side_effect=refuse):
        r = endpoints.probe("127.0.0.1:1", timeout=1)
    assert r["grade"] == "F" and "refused" in r["error"]
    assert len(calls) == 1, len(calls)
