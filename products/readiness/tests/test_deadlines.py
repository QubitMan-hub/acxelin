"""Dated obligations for the countries and sectors an organisation chooses, shortening public certificate lifetimes, and the
board summary's crypto-agility and weakest-project lines."""
import datetime as dt

import pytest

from acxelin_readiness import compliance, endpoints
from test_board import KX, MD5, build, scan_all


def test_the_deadlines_follow_the_countries_and_sectors_chosen():
    eu = compliance.deadlines(["eu"], ["enterprise"], 2026)
    assert [d["year"] for d in eu] == [2026, 2030, 2035] and all(d["source"].startswith("https://") for d in eu)
    india = compliance.deadlines(["in"], ["critical-infrastructure"], 2026)
    assert [d["year"] for d in india] == [2029]
    assert [d["year"] for d in compliance.deadlines(["in"], ["enterprise"], 2026)] == [2033]
    assert compliance.deadlines(["ca"], ["enterprise"], 2026) == []  # Canada's roadmap is for federal departments
    assert [d["year"] for d in compliance.deadlines(["ca"], ["government"], 2026)] == [2031, 2035]
    assert compliance.deadlines(["us"], ["national-security"], 2026)[0]["year"] == 2030
    assert compliance.deadlines(["uk", "in"], ["critical-infrastructure"], 2030)[0]["passed"]
    with pytest.raises(ValueError):
        compliance.deadlines(["xx"], [], 2026)


def test_the_console_keeps_the_choice_and_the_board_names_the_next_deadline(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX}})
    assert scan_all(r)["next_deadline"]["year"] == 2030  # NIST IR 8547 until a choice is made
    r("POST", "/api/settings/deadlines", {"countries": ["in"], "sectors": ["critical-infrastructure"]})
    board = r("GET", "/api/overview")["board"]
    assert board["next_deadline"]["year"] == 2029 and "India" in board["next_deadline"]["who"]
    assert r("GET", "/api/overview")["deadline_choice"] == {"countries": ["in"], "sectors": ["critical-infrastructure"]}
    with pytest.raises(ValueError):
        r("POST", "/api/settings/deadlines", {"countries": ["xx"], "sectors": []})


def cert(issued, days):
    start = dt.datetime.combine(issued, dt.time(), dt.timezone.utc)
    return {"grade": "B", "protocol": "tls", "target": "shop.example:443", "trusted": True,
            "certificate": {"key": "RSA-2048", "expires": (start + dt.timedelta(days=days)).date().isoformat(), "days_left": 90,
                            "issued": issued.isoformat(), "lifetime_days": days, "quantum_safe": False}}


def test_public_certificates_longer_than_the_cap_for_their_issue_date_are_named():
    over = cert(dt.date(2026, 6, 1), 365)
    fine = cert(dt.date(2026, 1, 10), 397)
    private = dict(cert(dt.date(2026, 6, 1), 365), trusted=False)
    text = lambda o: " ".join(x["text"] for x in o["risks"])
    out = endpoints.outlook([over, fine, private], dt.date(2026, 10, 30))
    over_risk = next(x for x in out["risks"] if "longer than" in x["text"])
    assert over_risk["targets"] == ["shop.example:443"] and "200 days" in over_risk["text"]
    assert "100 days" in text(out) and any("ACME" in a["text"] for a in out["actions"])
    assert "longer than" not in text(endpoints.outlook([fine, private], dt.date(2026, 10, 30)))
    assert "100 days" not in text(endpoints.outlook([fine], dt.date(2029, 4, 1)))  # after the last step there is nothing left to warn about


def test_the_board_gives_crypto_agility_and_the_weakest_project(tmp_path):
    root, r = build(tmp_path, {"shop": {"keys.py": KX}, "web": {"nginx/site.conf": "ssl_protocols TLSv1 TLSv1.2;\n"}, "ledger": {"main.py": MD5}})
    board = scan_all(r)
    assert board["agility"]["without_code"] >= 1 and board["agility"]["total"] >= board["agility"]["without_code"]
    assert board["weakest"]["name"] in ("ledger", "web", "shop") and board["weakest"]["score"] <= board["score"]
