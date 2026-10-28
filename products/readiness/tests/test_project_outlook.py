"""A repository's outlook: what can happen if nothing changes and what to do first, each point naming the findings it rests on."""
from acxelin_readiness import workspace


def asset(name, algo, tier, action="", status="open", owner="", hint=None, still=False, overdue=False, expired=False):
    return {"name": name, "algorithm": algo, "tier": tier, "action": action, "test_only": False, "locations": [["a.py", 1]], "owner_hint": hint,
            "tracking": {"status": status, "owner": owner, "still_found": still, "overdue": overdue, "expired": expired}}


def outlook(assets, coverage=None):
    return workspace.outlook({"assets": assets, "summary": {"coverage": coverage, "coverage_detail": {"files": 10, "read": 8, "not_read": {"over 2 MB": 2}}}})


def test_broken_and_quantum_vulnerable_cryptography_each_get_their_own_risk():
    o = outlook([asset("MD5", "MD5", "critical", "SHA-256"), asset("RSA-2048", "RSA", "high", "ML-KEM-768"), asset("ECDSA-P-256", "ECDSA", "medium", "ML-DSA-65"),
                 asset("AES-128-GCM", "AES", "low", "AES-256"), asset("SHA-256", "SHA-256", "ok")])
    risks = {r["text"].split(":")[0]: r["targets"] for r in o["risks"]}
    assert risks["Broken today"] == ["MD5"]
    assert risks["Recordable now, readable later"] == ["RSA-2048"]
    assert risks["Forgeable later"] == ["ECDSA-P-256"]
    assert risks["Weakened by quantum search"] == ["AES-128-GCM"]
    assert any("2035" in r["text"] and r["targets"] == ["ECDSA-P-256", "RSA-2048"] for r in o["risks"])
    assert all("SHA-256" not in r["targets"] for r in o["risks"])


def test_recommendations_put_the_worst_first_grouped_by_what_to_do():
    o = outlook([asset("RSA-2048", "RSA", "high", "ML-KEM-768"), asset("MD5", "MD5", "critical", "SHA-256"), asset("SHA-1", "SHA-1", "critical", "SHA-256"),
                 asset("RSA-3072", "RSA", "high", "ML-KEM-768")])
    assert [(a["text"], a["targets"]) for a in o["actions"][:2]] == [("Replace with SHA-256", ["MD5", "SHA-1"]), ("Replace with ML-KEM-768", ["RSA-2048", "RSA-3072"])]


def test_tracking_gaps_become_risks_and_actions():
    o = outlook([asset("MD5", "MD5", "critical", "SHA-256", status="fixed", still=True), asset("SHA-1", "SHA-1", "critical", "SHA-256", overdue=True),
                 asset("RSA", "RSA", "high", "ML-KEM-768", status="exception", expired=True)], coverage=80)
    texts = " ".join(r["text"] for r in o["risks"]) + " " + " ".join(a["text"] for a in o["actions"])
    assert "still found" in texts and "past its due date" in texts and "expired" in texts and "2 files were not analysed" in texts
    assert any(a["text"].startswith("Assign an owner") and a["targets"] == ["MD5", "RSA", "SHA-1"] for a in o["actions"])


def test_owned_or_suggested_findings_need_no_owner_action_and_a_clean_repository_says_so():
    o = outlook([asset("RSA-2048", "RSA", "high", "ML-KEM-768", hint={"owner": "@team", "source": "CODEOWNERS"})])
    assert not any(a["text"].startswith("Assign an owner") for a in o["actions"])
    clean = outlook([asset("SHA-256", "SHA-256", "ok")], coverage=100)
    assert clean["risks"] == [] and [a["targets"] for a in clean["actions"]] == [[]]
