"""The parts of a quantum readiness assessment beyond the inventory: how long each system's data must stay secret and how much
the business depends on it (from the CMDB export), how hard each finding is to change, the third-party libraries every project
relies on, and India's roadmap deadline."""
import pytest

from acxelin_readiness import compliance, console as rc, owners, pipeline
from acxelin_readiness.examples import effort
from acxelin_readiness.rank import Horizon

KX = "from cryptography.hazmat.primitives.asymmetric import x25519\nx25519.X25519PrivateKey.generate()\n"


def test_a_cmdb_export_may_say_how_long_data_stays_secret_and_how_important_the_service_is():
    rules = owners.from_csv("path,owner,service,keep secret (years),importance\nsrc/,Payments,Card payments,25,Critical\nweb/,Web,,2,\n")
    assert rules == [("src/", "Payments", "Card payments", 25.0, "critical"), ("web/", "Web", "", 2.0, "")]
    assert owners.suggest(rules, [], ["src/a.py"]) == {"owner": "Payments", "source": "CMDB export", "service": "Card payments", "secret_years": 25.0, "importance": "critical"}
    assert owners.suggest(rules, [], ["web/a.py"]) == {"owner": "Web", "source": "CMDB export", "secret_years": 2.0}
    for bad in ("path,owner,keep secret (years)\nsrc/,a,forever\n", "path,owner,keep secret (years)\nsrc/,a,500\n", "path,owner,importance\nsrc/,a,huge\n"):
        with pytest.raises(ValueError):
            owners.from_csv(bad)
    assert owners.from_csv("path,owner\nsrc/,payments\n") == [("src/", "payments")]


def tier(root, secrets=()):
    a = next(a for a in pipeline.run(root, "shop", horizon=Horizon(secrets=tuple(secrets))).assets if a.algo == "X25519")
    return a.tier, a.why


def test_data_that_stays_secret_briefly_is_not_a_harvest_now_risk_but_long_lived_data_is(tmp_path):
    (tmp_path / "chat.py").write_text(KX)
    assert tier(tmp_path)[0] == "high" and "10y secrecy" in tier(tmp_path)[1]
    assert tier(tmp_path, [("chat.py", 1.0)])[0] == "medium"
    long = tier(tmp_path, [("*.py", 1.0), ("chat.py", 30.0)])
    assert long[0] == "high" and "30y secrecy (CMDB export)" in long[1]


def test_the_console_ranks_by_the_cmdb_lifetimes_from_the_next_scan_and_weighs_services_by_importance(tmp_path):
    root = tmp_path / "repos"
    (root / "shop").mkdir(parents=True)
    (root / "shop/chat.py").write_text(KX)
    (root / "shop/legacy.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (root / "shop/billing.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=3072)\n")
    app = rc.build(tmp_path / "home")
    r = lambda method, path, body=None: app.routes[(method, path)](body or {})[1]
    r("POST", "/api/setup", {"directory": str(root)})
    r("POST", "/api/projects/register", {"name": "shop"})

    def scan():
        r("POST", "/api/projects/scan", {"project": 0})
        while r("GET", "/api/projects/status")["running"]:
            pass
        return {a["algorithm"]: a for a in r("GET", "/api/projects/status")["last"]["assets"]}
    assert scan()["X25519"]["tier"] == "high"
    r("POST", "/api/projects/owners", {"project": 0, "csv": "path,owner,service,keep secret (years),importance\nchat.py,Chat,Chat,1,low\n"
                                                         "legacy.py,Ops,Intranet,,high\nbilling.py,Pay,Billing,20,critical\n"})
    assets = scan()
    assert assets["X25519"]["tier"] == "medium" and assets["RSA"]["tier"] == "high"
    ranked = r("GET", "/api/overview")["services"]
    assert [s["service"] for s in ranked] == ["Intranet", "Billing", "Chat"]
    assert ranked[1]["importance"] == "critical" and ranked[1]["risk"] > ranked[2]["risk"]
    assert ranked[2]["importance"] == "low"


@pytest.mark.parametrize("places,level", [
    ([("nginx/site.conf", 3)], "setting"), ([("tls://shop.example:443", 0)], "setting"), ([("certs/server.pem", 0)], "reissue"),
    ([("aws://kms/eu-west-1/k", 0)], "reissue"), ([("requirements.txt", 4)], "upgrade"), ([("app/keys.py", 2), ("conf/app.yaml", 1)], "code"),
    ([("lib/libcrypto.so", 0)], "replace"), ([("tests/test_keys.py", 1)], None),
])
def test_each_finding_says_how_hard_it_is_to_change(places, level):
    got = effort({"tier": "high", "locations": places})
    assert (got or {}).get("level") == level
    assert effort({"tier": "ok", "locations": places}) is None


def test_the_overview_lists_the_third_party_libraries_and_whether_they_support_post_quantum(tmp_path):
    root = tmp_path / "repos"
    for name, reqs in (("a", "cryptography==44\npycrypto==2.6\n"), ("b", "cryptography==45\n")):
        (root / name).mkdir(parents=True)
        (root / name / "requirements.txt").write_text(reqs)
        (root / name / "app.py").write_text("import cryptography, Crypto\n")
    app = rc.build(tmp_path / "home")
    r = lambda method, path, body=None: app.routes[(method, path)](body or {})[1]
    r("POST", "/api/setup", {"directory": str(root)})
    r("POST", "/api/projects/scan-all", {})
    while r("GET", "/api/overview")["scan_all"]["running"]:
        pass
    found = r("GET", "/api/overview")["libraries"]
    libs = {x["name"]: x for x in found}
    versions = {x["version"]: x["projects"] for x in found if x["name"] == "cryptography"}
    assert versions == {"==44": ["a"], "==45": ["b"]}, "each version is its own entry, so an old one is never hidden behind a new one"
    assert all(x["pq"] for x in found if x["name"] == "cryptography")
    assert not libs["pycrypto"]["pq"] and "Unmaintained" in libs["pycrypto"]["note"]


def test_indias_roadmap_wants_critical_infrastructure_post_quantum_by_the_end_of_2029(tmp_path):
    (tmp_path / "keys.py").write_text(KX)
    (tmp_path / "old.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    assets = pipeline.run(tmp_path, "shop").assets
    rules = lambda **policy: {v["asset"]: v for v in compliance.evaluate(assets, [], {"profiles": ["india-dst"]} | policy)["violations"]
                              if v["rule"] == "India DST roadmap"}
    found = rules(as_of=2029)
    assert found["X25519"]["deadline"] == 2029 and not found["X25519"]["overdue"] and found["MD5"]["overdue"]
    assert rules(as_of=2030)["X25519"]["overdue"]
    assert not rules(as_of=2030, india_deadline=2033)["X25519"]["overdue"]
    assert compliance.check({"profiles": ["india-dst"]}) == []
