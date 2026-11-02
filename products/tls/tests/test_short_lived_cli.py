"""Short-lived certificates from the command line and in `doctor`."""
import datetime as dt
import os
import subprocess
import sys

import pytest
from acxelin_core import openssl, pki
from acxelin_core.pki import CA
from cryptography import x509

from acxelin_tls import checks

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


def run(*args):
    p = subprocess.run([sys.executable, "-m", "acxelin_tls", *args], capture_output=True, text=True, env=dict(os.environ), timeout=120)
    return p.returncode, p.stdout, p.stderr


def lifetime(folder):
    cert = x509.load_pem_x509_certificate((folder / "cert.pem").read_bytes())
    return cert.not_valid_after_utc - cert.not_valid_before_utc


@pytest.fixture
def pki_dir(tmp_path):
    assert run("ca", "init", "--name", "Short Root", "--dir", str(tmp_path / "pki"), "--no-encrypt")[0] == 0
    return tmp_path / "pki"


def test_issue_for_a_number_of_hours_and_say_how_often_to_renew(pki_dir, tmp_path):
    code, out, err = run("ca", "issue", "server", "svc.example", "--dir", str(pki_dir), "--hours", "24", "--out", str(tmp_path / "svc"))
    assert code == 0, err
    assert lifetime(tmp_path / "svc") == dt.timedelta(hours=24)
    assert "24 hours" in out and "at least every 8 hours" in out, "a customer must be told the cost of a short lifetime: something has to renew it"


def test_days_and_hours_together_are_refused_by_name(pki_dir, tmp_path):
    code, _, err = run("ca", "issue", "server", "svc.example", "--dir", str(pki_dir), "--days", "30", "--hours", "24", "--out", str(tmp_path / "svc"))
    assert code == 2 and "--hours" in err and "--days" in err


def test_a_renewal_keeps_the_lifetime_unless_told_otherwise(pki_dir, tmp_path):
    assert run("ca", "issue", "server", "svc.example", "--dir", str(pki_dir), "--hours", "24", "--out", str(tmp_path / "svc"))[0] == 0
    serial = run("ca", "list", "--dir", str(pki_dir))[1].split()[0]
    code, out, err = run("ca", "renew", serial, "--dir", str(pki_dir), "--out", str(tmp_path / "svc"))
    assert code == 0, err
    assert lifetime(tmp_path / "svc") == dt.timedelta(hours=24)
    assert run("ca", "renew", serial, "--dir", str(pki_dir), "--out", str(tmp_path / "svc"), "--days", "30")[0] == 0
    assert lifetime(tmp_path / "svc") == dt.timedelta(days=30)


def test_maintain_does_nothing_early_and_says_so(pki_dir, tmp_path):
    run("ca", "issue", "server", "svc.example", "--dir", str(pki_dir), "--hours", "24", "--out", str(tmp_path / "svc"))
    before = (tmp_path / "svc" / "cert.pem").read_bytes()
    code, out, _ = run("ca", "maintain", "--dir", str(pki_dir))
    assert code == 0 and (tmp_path / "svc" / "cert.pem").read_bytes() == before and "renewed" not in out
    assert "nothing needed renewing" in out


def test_maintain_with_a_window_in_hours(pki_dir, tmp_path):
    run("ca", "issue", "server", "svc.example", "--dir", str(pki_dir), "--hours", "24", "--out", str(tmp_path / "svc"))
    before = (tmp_path / "svc" / "cert.pem").read_bytes()
    code, out, err = run("ca", "maintain", "--dir", str(pki_dir), "--renew-within-hours", "30")
    assert code == 0, err
    assert (tmp_path / "svc" / "cert.pem").read_bytes() != before and "renewed svc.example" in out
    code, _, err = run("ca", "maintain", "--dir", str(pki_dir), "--renew-within", "30", "--renew-within-hours", "8")
    assert code == 2 and "--renew-within-hours" in err


def test_doctor_names_the_interval_and_warns_when_a_certificate_is_late(pki_dir, tmp_path, monkeypatch):
    t0 = pki.now()
    CA(pki_dir).issue("svc.example", "server", hours=24, out=tmp_path / "svc")
    lines = dict((m, level) for level, m in checks.ca(pki_dir))
    assert any("at least every 8 hours" in m for m in lines), lines
    assert not any(level == "warn" and "due for renewal" in m for m, level in lines.items())
    for module in (pki, checks):
        monkeypatch.setattr(module, "now", lambda: t0 + dt.timedelta(hours=17))
    late = [(level, m) for level, m in checks.ca(pki_dir) if "due for renewal" in m]
    assert late and late[0][0] == "warn" and "svc.example" in late[0][1] and "ca maintain" in late[0][1]
