"""CI pins the OpenSSL line customers run, and a different or missing OpenSSL fails the run instead of skipping tests."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("root_conftest", ROOT / "conftest.py")
conftest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(conftest)


def test_only_the_pinned_line_passes():
    assert conftest.openssl_problem("3.5", "OpenSSL 3.5.9 29 Sep 2026") is None
    assert conftest.openssl_problem("3.5", "OpenSSL 3.0.13 30 Jan 2024")
    assert conftest.openssl_problem("3.5", "OpenSSL 3.6.1 27 Jan 2026")
    assert conftest.openssl_problem("3.5", "OpenSSL 3.50.0")  # a prefix match on "3.5" is not the 3.5 line


def test_a_minimum_accepts_newer_lines_and_refuses_older_ones():
    assert conftest.openssl_problem("3.5+", "OpenSSL 3.6.1 27 Jan 2026") is None
    assert conftest.openssl_problem("3.5+", "OpenSSL 3.5.9 29 Sep 2026") is None
    assert conftest.openssl_problem("3.5+", "OpenSSL 4.0.0 1 Apr 2027") is None
    assert conftest.openssl_problem("3.5+", "OpenSSL 3.0.13 30 Jan 2024")
    assert conftest.openssl_problem("3.5+", "OpenSSL 3.4.9 1 Jan 2026")
    assert conftest.openssl_problem("3.5+", "garbage")
    assert "3.5" in conftest.openssl_problem("3.5", "OpenSSL 3.0.13 30 Jan 2024")


def run(want):
    env = {k: v for k, v in os.environ.items() if k != "ACXELIN_REQUIRE_OPENSSL"} | ({"ACXELIN_REQUIRE_OPENSSL": want} if want else {})
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tools/tests/test_threat_model_citations.py"],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False)


def test_a_wrong_line_stops_the_run_and_no_pin_changes_nothing():
    r = run("9.9")
    assert r.returncode == 4 and "ACXELIN_REQUIRE_OPENSSL=9.9" in r.stdout + r.stderr, r.stdout + r.stderr
    assert run(None).returncode == 0


def test_workflows_say_which_openssl_they_require():
    for name in ("acxelin-core.yml", "acxelin-tls.yml", "acxelin-vpn.yml"):
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        assert "ACXELIN_REQUIRE_OPENSSL" in text, name
        assert "--version=3.5.9" not in text and "openssl@3.5" not in text, f"{name}: a package version nobody verified"
