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


def test_the_string_scanner_matches_the_regex_it_replaces_exactly():
    import random
    from acxelin_readiness.detectors import names
    rng = random.Random(7)
    for _ in range(20000):
        text = "".join(rng.choice("\"'`\\\nab ") for _ in range(rng.randint(0, 40)))
        mark = lambda t: "<" + t + ">"
        assert names.blank_strings(text, mark) == names.QUOTED.sub(lambda m: mark(m.group(0)), text), repr(text)


@pytest.mark.parametrize("line", ['"' + '\\"' * 20000, "'" + "\\'" * 20000, '"""' * 3000 + "x", "'''a" * 5000])
def test_unterminated_strings_are_scanned_in_linear_time(tmp_path, line):
    import time
    (tmp_path / "a.py").write_text("x = 1\n" + line + "\n")
    (tmp_path / "a.c").write_text("const char *s = " + line + ";\n")  # C-family code goes through the string scanner; no third-party parser
    start = time.monotonic()
    workspace.scan(tmp_path)
    assert time.monotonic() - start < 3, "an opening quote then escaped quotes took the old regex 5 s per line"


def pem_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def test_only_the_key_a_config_names_is_marked_deployed(tmp_path):
    from acxelin_readiness import pipeline
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "server.key").write_bytes(pem_key())
    (tmp_path / "nginx.conf").write_text("server {\n  ssl_certificate_key a/server.key;\n}\n")
    deployed = {s.file for s in pipeline.run(tmp_path, "p").detections if "deployed" in s.context}
    assert "a/server.key" in deployed and "b/server.key" not in deployed


def test_neighbouring_javascript_key_calls_keep_their_own_parameters(tmp_path):
    from acxelin_readiness import pipeline
    (tmp_path / "keys.js").write_text("const c = require('crypto');\n"
                                      "c.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });\n"
                                      "c.generateKeyPairSync('rsa', { modulusLength: 1024 });\n")
    assets = pipeline.run(tmp_path, "p").assets
    assert "RSA-1024" in {a.variant for a in assets}
    assert all("curve" not in a.params for a in assets if a.algo == "RSA")
    assert all("key_size" not in a.params for a in assets if a.algo in ("ECC", "ECDSA", "ECDH"))


@pytest.mark.parametrize("name,want,ok", [("sha512_224", "SHA-512/224", False), ("sha512_256", "SHA-512/256", True), ("sha512", "SHA-512", True)])
def test_truncated_sha_512_is_named_and_rated_by_its_output(tmp_path, name, want, ok):
    from acxelin_readiness.catalog import CATALOG, SAFE
    (tmp_path / "h.py").write_text(f"import hashlib\nhashlib.new('{name}', b'x')\n")
    assets = workspace.scan(tmp_path)["assets"]
    assert [a["algorithm"] for a in assets] == [want] and (CATALOG[want].threat == SAFE) == ok


def test_a_fully_qualified_java_class_is_read_like_an_imported_one(tmp_path):
    body = 'KeyPairGenerator g = KeyPairGenerator.getInstance("EC");\ng.initialize(new {}ECGenParameterSpec("secp384r1"));\n'
    result = []
    for prefix in ("", "java.security.spec."):
        root = tmp_path / (prefix or "plain")
        root.mkdir()
        (root / "K.java").write_text("import java.security.*;\nclass K { void k() throws Exception {\n" + body.format(prefix) + "} }\n")
        result.append(sorted(a["name"] for a in workspace.scan(root)["assets"]))
    assert result[0] == result[1] and any("384" in n for n in result[1])


def test_sha_1_inside_rsa_oaep_is_not_called_broken_but_sha_1_elsewhere_still_is(tmp_path):
    (tmp_path / "oaep.py").write_text("from cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.asymmetric import padding\n"
                                      "OAEP = padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)\n")
    sha1 = next(a for a in workspace.scan(tmp_path)["assets"] if a["name"] == "SHA-1")
    assert sha1["tier"] == "low" and "OAEP" in sha1["why"]
    (tmp_path / "sig.py").write_text("from cryptography.hazmat.primitives import hashes\nh = hashes.Hash(hashes.SHA1())\n")
    assert next(a for a in workspace.scan(tmp_path)["assets"] if a["name"] == "SHA-1")["tier"] == "critical"


def test_a_findings_places_in_real_code_come_before_its_places_in_tests(tmp_path):
    (tmp_path / "a_tests").mkdir()
    (tmp_path / "a_tests/test_k.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "z.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    assert next(a for a in workspace.scan(tmp_path)["assets"] if a["name"] == "MD5")["locations"][0][0] == "z.py"


def test_javas_rsa_ecb_transformation_is_not_ecb_mode_but_aes_ecb_is(tmp_path):
    (tmp_path / "K.java").write_text('import javax.crypto.Cipher;\nclass K { void k() throws Exception {\n'
                                     'Cipher r = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\nCipher a = Cipher.getInstance("AES/ECB/PKCS5Padding");\n} }\n')
    found = {a["algorithm"]: a for a in workspace.scan(tmp_path)["assets"]}
    assert found["RSA"]["tier"] != "critical" and "AES" not in found["RSA"]["action"]
    assert found["AES"]["tier"] == "critical" and "ECB" in found["AES"]["why"]


@pytest.mark.parametrize("src", ["export const algs = {\n  'RSA-OAEP': rsaes(1),\n  A256GCM: gcm(256),\n}\nawait crypto.subtle.decrypt('RSA-OAEP', key, data)\n", "import hmac, hashlib\nhmac.new(k, m, hashlib.sha1)\n"])
def test_sha_1_carried_by_oaep_or_hmac_is_not_called_broken(tmp_path, src):
    (tmp_path / ("a.ts" if "const" in src else "a.py")).write_text(src)
    found = {a["algorithm"]: a for a in workspace.scan(tmp_path)["assets"]}
    assert found["SHA-1"]["tier"] == "low" and "collision" in found["SHA-1"]["why"]
    assert found.get("RSA", {}).get("tier") != "critical" and "Signature over" not in found.get("RSA", {}).get("why", "")


def test_sha_1_of_the_message_handed_to_hmac_is_still_broken(tmp_path):
    (tmp_path / "a.py").write_text("import hmac, hashlib\nhmac.new(k, hashlib.sha1(m).digest(), hashlib.sha256)\n")
    assert next(a for a in workspace.scan(tmp_path)["assets"] if a["name"] == "SHA-1")["tier"] == "critical"


def test_a_tls_1_2_rsa_suite_seen_in_a_capture_names_rsa_and_its_mac_hash_is_not_called_broken(tmp_path):
    from acxelin_readiness.detectors import capture
    from acxelin_readiness.detectors.suites import suite
    assert ("RSA", {}) in suite(capture.suite_name(0x002F)), "TLS_RSA_WITH_AES_128_CBC_SHA exchanges keys with RSA"
    (tmp_path / "nginx.conf").write_text("server {\n  ssl_protocols TLSv1.2;\n  ssl_ciphers AES128-SHA:ECDHE-RSA-AES128-SHA;\n}\n")
    sha1 = next(a for a in workspace.scan(tmp_path)["assets"] if a["name"] == "SHA-1")
    assert sha1["tier"] == "low" and "collision" in sha1["why"]


@pytest.mark.parametrize("link,strip", [(228, 14), (101, 14), (1, 0)])
def test_a_capture_of_raw_ip_frames_is_read_like_one_of_ethernet_frames(tmp_path, link, strip):
    import struct

    import pcapgen
    from acxelin_readiness.detectors import capture
    frames = capture.packets(pcapgen.pcap(pcapgen.tls_capture([0x11EC], pcapgen.server_hello(0x1301, group=0x11EC))))
    raw = [f[strip:] for _, f in frames]
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link) + b"".join(struct.pack("<IIII", 0, 0, len(f), len(f)) + f for f in raw)
    (tmp_path / "c.pcap").write_bytes(data)
    assert any(s.algo == "X25519MLKEM768" for s in capture.scan(tmp_path / "c.pcap")[0])


@pytest.mark.parametrize("tid,hash_", [(6, "MD5"), (7, "SHA-1"), (2, "SHA-1"), (12, "SHA-256")])
def test_every_ikev2_hmac_integrity_transform_is_named(tid, hash_):
    from acxelin_readiness.detectors import ike
    assert ike.name(3, tid) == ("HMAC", {"hash": hash_})


def test_the_python_index_keeps_bodies_only_where_crypto_is_named_and_still_follows_values_from_other_files(tmp_path):
    from acxelin_readiness.detectors import pyflow
    (tmp_path / "crypto_util.py").write_text("import hashlib\n\ndef digest(data, algo):\n    return hashlib.new(algo, data)\n")
    (tmp_path / "views.py").write_text("from crypto_util import digest\n\nclass Page:\n    def render(self, body):\n        return digest(body, 'md5')\n")
    idx = pyflow.Index(tmp_path)
    assert idx.modules["views.py"].defs["Page.render"].node is None and idx.modules["crypto_util.py"].defs["digest"].node is not None
    md5 = next(a for a in workspace.scan(tmp_path)["assets"] if a["name"] == "MD5")
    assert "crypto_util.py" in {f for f, _ in md5["locations"]}, "the value comes from a file whose function bodies were not kept"


def test_a_very_large_python_project_indexes_only_crypto_files_and_their_neighbours_and_says_so(tmp_path, monkeypatch):
    from acxelin_readiness.detectors import pyflow
    monkeypatch.setattr(pyflow, "LARGE", 10)
    (tmp_path / "settings.py").write_text("HASH = 'md5'\n")
    (tmp_path / "crypto_util.py").write_text("import hashlib\nfrom settings import HASH\n\ndef digest(data, algo):\n    return hashlib.new(algo, data)\n\n"
                                         "def fingerprint(data):\n    return hashlib.new(HASH, data)\n")
    (tmp_path / "views.py").write_text("from crypto_util import digest\n\ndef render(body):\n    return digest(body, 'sha1')\n")
    for i in range(20):
        (tmp_path / f"unrelated_{i}.py").write_text(f"def f{i}(x):\n    return x + {i}\n")
    idx = pyflow.Index(tmp_path)
    assert set(idx.modules) == {"settings.py", "crypto_util.py", "views.py"} and idx.limited
    names = {a["name"] for a in workspace.scan(tmp_path)["assets"]}
    assert {"MD5", "SHA-1"} <= names, "the default from settings and the value from the caller are both still followed"
    from acxelin_readiness import pipeline
    assert any("one import away" in n for n in pipeline.run(tmp_path, "p").notes)


def test_a_crypto_const_module_does_not_pull_in_every_other_package_s_const_importers(tmp_path, monkeypatch):
    from acxelin_readiness.detectors import pyflow
    monkeypatch.setattr(pyflow, "LARGE", 4)
    for pkg in ("lock", "light", "fan"):
        (tmp_path / pkg).mkdir()
        (tmp_path / pkg / "__init__.py").write_text("")
        (tmp_path / pkg / "sensor.py").write_text("from .const import DOMAIN\n")
    (tmp_path / "lock/const.py").write_text("import hashlib\nDOMAIN = hashlib.sha256(b'lock').hexdigest()\n")
    (tmp_path / "light/const.py").write_text("DOMAIN = 'light'\n")
    (tmp_path / "fan/const.py").write_text("DOMAIN = 'fan'\n")
    assert set(pyflow.Index(tmp_path).modules) == {"lock/const.py", "lock/sensor.py"}


def test_a_hostile_long_line_in_a_python_file_costs_little_and_hides_nothing_else(tmp_path):
    import time
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')  # not a password\n" + '"' + '\\"' * 20000 + "\n")
    start = time.monotonic()
    names = {a["name"] for a in workspace.scan(tmp_path)["assets"]}
    assert time.monotonic() - start < 3, "Python 3.11's tokenizer matched the rest of the line again for every character"
    assert "MD5" in names
