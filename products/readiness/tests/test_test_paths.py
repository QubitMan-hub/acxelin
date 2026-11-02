"""What counts as test code: only conventional test folders, as whole path segments, plus the customer's own patterns.
Test code only lowers a finding's priority; nothing is ever hidden."""
import json

import pytest

from acxelin_readiness import cli
from acxelin_readiness.detectors import is_test, extra_test_paths


@pytest.mark.parametrize("path", ["tests/a.py", "test/a.py", "src/test/java/com/acme/KeysTest.java", "web/__tests__/a.js", "spec/keys_spec.rb",
                                  "Tests/Crypto.cs", "a/b/TESTS/c.go", "src\\test\\java\\A.java"])
def test_conventional_test_folders_count(path):
    assert is_test(path)


@pytest.mark.parametrize("path", ["src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java", "testcode/A.java", "latest/a.go",
                                  "contests/a.py", "src/attestation/a.py", "UnitTestsNet46/jwk/JwkTest.cs", "benches/x25519.rs",
                                  "examples/a.py", "testing/server.go", "src/testutil.go", "test_keys.py", "keys_test.go", "tests.py",
                                  "app/spec.py", "test"])
def test_nothing_else_counts_and_never_a_substring(path):
    assert not is_test(path)


def test_customer_patterns_add_to_the_conventional_folders():
    with extra_test_paths(["benches", "qa/load/*", "*_it.py", "Test_Vectors"]):
        for p in ("benches/x25519.rs", "qa/load/run.py", "src/pay_it.py", "lib/test_vectors/rsa.json", "tests/a.py"):
            assert is_test(p), p
        assert not is_test("qa/unit.py") and not is_test("src/benchmarks/a.rs")
    with extra_test_paths(["lib/Crypto/SelfTest"]):  # a folder path covers what is inside it
        assert is_test("lib/crypto/selftest/PublicKey/vector.pem") and not is_test("lib/crypto/selftests.py") and not is_test("vendor/lib/crypto/selftest/a.pem")
    assert not is_test("benches/x25519.rs"), "patterns apply only inside their scan"


def assets(out):
    bom = json.loads((out / "cbom.json").read_text())
    rows = []
    for c in bom["components"]:
        p = {x["name"]: x["value"] for x in c.get("properties", [])}
        if c.get("type") == "cryptographic-asset" and "acxelin:tier" in p:
            rows.append((c["name"], p["acxelin:tier"], tuple(sorted(o["location"] for o in c.get("evidence", {}).get("occurrences", [])))))
    return rows


WEAK = 'import hashlib\n\ndef fingerprint(data):\n    return hashlib.md5(data).hexdigest()\n'


def test_code_in_a_testcode_folder_keeps_its_priority_and_test_code_is_lowered_but_never_hidden(tmp_path):
    for repo, folder in (("one", "testcode"), ("two", "tests")):
        (tmp_path / repo / folder).mkdir(parents=True)
        (tmp_path / repo / folder / "sign.py").write_text(WEAK)
    cli.main(["scan", str(tmp_path / "one"), "-o", str(tmp_path / "a"), "-q"])
    cli.main(["scan", str(tmp_path / "two"), "-o", str(tmp_path / "b"), "-q"])
    tier = lambda out: {name: t for name, t, _ in assets(out)}
    order = ["ok", "low", "medium", "high", "critical"]
    production, test = tier(tmp_path / "a"), tier(tmp_path / "b")
    assert "MD5" in test, "test code is listed, never hidden"
    assert order.index(test["MD5"]) < order.index(production["MD5"]), (test, production)


def test_patterns_from_the_settings_file_and_the_command_line(tmp_path):
    repo = tmp_path / "repo"
    (repo / "benches").mkdir(parents=True)
    (repo / "benches/sign.py").write_text(WEAK)
    cli.main(["scan", str(repo), "-o", str(tmp_path / "plain"), "-q"])
    plain = {n: t for n, t, _ in assets(tmp_path / "plain")}
    (repo / ".acxelin-readiness.toml").write_text('test_paths = ["benches"]\n')
    cli.main(["scan", str(repo), "-o", str(tmp_path / "cfg"), "-q"])
    cfg = {n: t for n, t, _ in assets(tmp_path / "cfg")}
    (repo / ".acxelin-readiness.toml").unlink()
    cli.main(["scan", str(repo), "-o", str(tmp_path / "flag"), "-q", "--test-path", "benches"])
    flag = {n: t for n, t, _ in assets(tmp_path / "flag")}
    order = ["ok", "low", "medium", "high", "critical"]
    assert "MD5" in cfg and "MD5" in flag, "lowered, never hidden"
    assert order.index(cfg["MD5"]) < order.index(plain["MD5"]) and cfg["MD5"] == flag["MD5"]
