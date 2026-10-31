"""On GitHub Actions, each failing test becomes an annotation, so a failure can be read from the checks API without the log."""
import os

import pytest


def escape(text, prop=False):
    text = str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def pytest_runtest_logreport(report):
    if os.environ.get("GITHUB_ACTIONS") != "true" or not report.failed:
        return
    path, line = report.location[0], (report.location[1] or 0) + 1
    crash = getattr(report.longrepr, "reprcrash", None)
    message = crash.message if crash else (str(report.longrepr or "").strip().splitlines() or ["failed"])[-1]
    print(f"\n::error file={escape(path, True)},line={line},title={escape(report.nodeid, True)}::{escape(message[:500])}", flush=True)


def openssl_problem(want, version):
    """Why the OpenSSL the products loaded is not the line CI pins (ACXELIN_REQUIRE_OPENSSL=3.5), or None. A machine whose
    OpenSSL is too old would otherwise skip the tests that need 3.5 and pass, which proves nothing about the line customers run."""
    return None if version.split()[1:2] and version.split()[1].startswith(want + ".") else \
        f"ACXELIN_REQUIRE_OPENSSL={want}, but the products loaded {version!r}; point ACXELIN_OPENSSL (and LD_LIBRARY_PATH on Linux) at an OpenSSL {want} lib folder"


def pytest_sessionstart(session):
    want = os.environ.get("ACXELIN_REQUIRE_OPENSSL")
    if not want:
        return
    try:
        from acxelin_core import openssl
        version = openssl.lib().version
    except Exception as e:  # noqa: BLE001  any failure to load OpenSSL is the failure this guard exists for
        pytest.exit(f"ACXELIN_REQUIRE_OPENSSL={want}, but OpenSSL did not load: {e}", returncode=4)
    if problem := openssl_problem(want, version):
        pytest.exit(problem, returncode=4)
