"""Short-lived certificates: a lifetime in hours, renewal that keeps the lifetime, and `maintain` renewing at the right moment (the clock is moved, not waited for)."""
import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509

from acxelin_core import openssl
from acxelin_core import pki
from acxelin_core.pki import CA, CAError

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


@pytest.fixture
def ca(tmp_path):
    return CA.init(tmp_path / "pki", "Short Root")


def lifetime(folder):
    cert = x509.load_pem_x509_certificate((Path(folder) / "cert.pem").read_bytes())
    return cert.not_valid_after_utc - cert.not_valid_before_utc


def at(monkeypatch, moment):
    monkeypatch.setattr(pki, "now", lambda: moment)


def test_a_certificate_can_live_for_a_number_of_hours(ca, tmp_path):
    out, rec = ca.issue("svc", "server", ["svc.example"], hours=24, out=tmp_path / "svc")
    assert lifetime(out) == dt.timedelta(hours=24)
    assert dt.datetime.fromisoformat(rec.not_after) - pki.now() <= dt.timedelta(hours=24)


@pytest.mark.parametrize("hours", [0, -3, 0.5, True, "24", float("nan"), 24 * 36500 + 1])
def test_a_lifetime_that_makes_no_sense_is_refused_in_words(ca, tmp_path, hours):
    with pytest.raises(CAError, match="hours"):
        ca.issue("svc", "server", hours=hours, out=tmp_path / "svc")


def test_days_and_hours_together_are_refused(ca, tmp_path):
    with pytest.raises(CAError, match="either days or hours"):
        ca.issue("svc", "server", days=30, hours=24, out=tmp_path / "svc")


def test_a_short_lived_renewal_keeps_its_lifetime_and_a_longer_one_renews_as_it_always_did(ca, tmp_path):
    out, rec = ca.issue("svc", "server", hours=24, out=tmp_path / "svc")
    ca.renew(rec.serial, out=out)
    assert lifetime(out) == dt.timedelta(hours=24), "a renewal of a 24-hour certificate must not become a 397-day one"
    week, rec7 = ca.issue("week", "server", days=7, out=tmp_path / "week")
    ca.renew(rec7.serial, out=week)
    assert lifetime(week) == dt.timedelta(days=7), "seven days is still short-lived"
    out90, rec90 = ca.issue("long", "server", days=90, out=tmp_path / "long")
    ca.renew(rec90.serial, out=out90)
    assert lifetime(out90) == dt.timedelta(days=397), "behaviour from before short-lived certificates existed, unchanged"


def test_a_renewal_can_still_choose_a_new_lifetime(ca, tmp_path):
    out, rec = ca.issue("svc", "server", hours=24, out=tmp_path / "svc")
    ca.renew(rec.serial, days=30, out=out)
    assert lifetime(out) == dt.timedelta(days=30)


def test_maintain_renews_a_short_lived_certificate_in_time_and_not_before(ca, tmp_path, monkeypatch):
    t0 = pki.now()
    out, rec = ca.issue("svc", "server", hours=24, out=tmp_path / "svc")
    before = (out / "cert.pem").read_bytes()
    at(monkeypatch, t0 + dt.timedelta(hours=10))  # 14 hours left, more than the 8 hours asked for
    renewed, _ = ca.maintain(renew_within_hours=8)
    assert renewed == [] and (out / "cert.pem").read_bytes() == before
    at(monkeypatch, t0 + dt.timedelta(hours=17))  # 7 hours left
    renewed, skipped = ca.maintain(renew_within_hours=8)
    assert [r.common_name for r in renewed] == ["svc"] and skipped == []
    assert (out / "cert.pem").read_bytes() != before and lifetime(out) == dt.timedelta(hours=24)
    new = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
    assert new.not_valid_before_utc == t0 + dt.timedelta(hours=17), "the new certificate starts when it was renewed"


def test_a_chain_of_renewals_never_leaves_a_gap(ca, tmp_path, monkeypatch):
    """Run maintain every 4 hours for three days: the certificate on disk is valid at every check."""
    t0 = pki.now()
    out, _ = ca.issue("svc", "server", hours=24, out=tmp_path / "svc")
    for step in range(1, 19):
        moment = t0 + dt.timedelta(hours=4 * step)
        at(monkeypatch, moment)
        ca.maintain(renew_within_hours=8)
        cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
        assert cert.not_valid_before_utc <= moment < cert.not_valid_after_utc, f"expired on disk at hour {4 * step}"


def test_maintain_that_runs_too_rarely_is_the_customers_gap_and_doctor_can_see_it(ca, tmp_path, monkeypatch):
    t0 = pki.now()
    out, rec = ca.issue("svc", "server", hours=24, out=tmp_path / "svc")
    at(monkeypatch, t0 + dt.timedelta(hours=30))  # nobody ran maintain for 30 hours
    assert ca.due(rec) is True and ca.remaining(rec) < dt.timedelta(0)


def test_the_share_of_life_left_decides_what_is_due(ca, tmp_path, monkeypatch):
    t0 = pki.now()
    _, short = ca.issue("short", "server", hours=24, out=tmp_path / "s")
    _, long = ca.issue("long", "server", days=397, out=tmp_path / "l")
    at(monkeypatch, t0 + dt.timedelta(hours=17))
    assert ca.due(short) is True and ca.due(long) is False
    at(monkeypatch, t0 + dt.timedelta(days=370))
    assert ca.due(long) is True, "a long certificate is due in its last 30 days, as before"


def test_old_calls_keep_working(ca, tmp_path):
    out, rec = ca.issue("svc", "server", ["svc.example"], 30, "ML-DSA-65", tmp_path / "svc")
    assert lifetime(out) == dt.timedelta(days=30)
    ca.maintain(60)
    assert ca.expiring(60)
