"""What can happen and what to do, from endpoint grades: each rule fires only on the evidence it names."""
import datetime as dt

from acxelin_readiness import endpoints

TODAY = dt.date(2026, 10, 28)


def ep(target, grade, protocol="tls", key="ECDSA-secp256r1", days=200, **more):
    cert = {"key": key, "issuer": "CN=Example CA", "expires": (TODAY + dt.timedelta(days=days)).isoformat(), "days_left": days, "quantum_safe": key.startswith("ML-DSA")}
    return {"target": target, "grade": grade, "protocol": protocol, "accepts": [], "negotiated": None, "error": None, "cnsa2": False,
            "certificate": None if grade == "F" else cert} | more


def test_classical_endpoints_are_recordable_now_and_get_a_hybrid_key_exchange_first():
    o = endpoints.outlook([ep("a:443", "C"), ep("ssh://b:22", "C", "ssh", key="ssh-ed25519", days=9999), ep("c:443", "A", key="ML-DSA-65")])
    risk = next(r for r in o["risks"] if r["targets"] == ["a:443", "ssh://b:22"])
    assert "recorded" in risk["text"] and "2035" in risk["text"]
    actions = {a["text"]: a["targets"] for a in o["actions"]}
    assert any("X25519MLKEM768" in t and v == ["a:443"] for t, v in actions.items())
    assert any("mlkem768x25519-sha256" in t and v == ["ssh://b:22"] for t, v in actions.items())
    assert all("c:443" not in a["targets"] for a in o["risks"] + o["actions"])


def test_a_hybrid_endpoint_still_gives_classical_only_clients_a_classical_session():
    o = endpoints.outlook([ep("b:443", "B", key="ML-DSA-65")])
    assert [r["targets"] for r in o["risks"]] == [["b:443"]] and "client" in o["risks"][0]["text"]
    assert "client" in o["actions"][0]["text"], "dropping classical groups is advised only after checking clients"


def test_certificates_that_expire_soon_or_already_did_come_first():
    o = endpoints.outlook([ep("old:443", "A", key="ML-DSA-65", days=-3), ep("soon:443", "A", key="ML-DSA-65", days=10), ep("fine:443", "A", key="ML-DSA-65")])
    assert o["risks"][0]["targets"] == ["old:443"] and "expired" in o["risks"][0]["text"]
    assert o["risks"][1]["targets"] == ["soon:443"] and "2026-11-07" in o["risks"][1]["text"]
    assert o["actions"][0]["targets"] == ["old:443", "soon:443"] and "Renew" in o["actions"][0]["text"]


def test_old_tls_untrusted_certificates_and_unreachable_hosts_each_say_so():
    o = endpoints.outlook([ep("l:443", "A", key="ML-DSA-65", legacy=["TLSv1.0"]), ep("p:443", "C", trusted=False), ep("x:443", "F", error="refused")])
    risks = " ".join(r["text"] for r in o["risks"])
    assert "TLS 1.0 and 1.1" in risks and "proxy" in risks and "could not be graded" in risks
    assert ["x:443"] in [a["targets"] for a in o["actions"]]


def test_classical_certificate_keys_are_named_but_ranked_after_key_exchange():
    o = endpoints.outlook([ep("a:443", "A", key="RSA-2048")])
    assert [r["targets"] for r in o["risks"]] == [["a:443"]] and "signature" in o["risks"][0]["text"]
    assert "ML-DSA" in o["actions"][0]["text"]


def test_nothing_to_do_says_so_without_inventing_risk():
    o = endpoints.outlook([ep("a:443", "A", key="ML-DSA-87")])
    assert o["risks"] == [] and len(o["actions"]) == 1 and o["actions"][0]["targets"] == []
    assert endpoints.outlook([]) == {"risks": [], "actions": []}


def test_an_unexpected_answer_keeps_the_target_as_the_probe_writes_it():
    def boom(t, **kw):
        raise RuntimeError("odd")
    endpoints_probe, endpoints.probe = endpoints.probe, boom
    try:
        assert [r["target"] for r in endpoints.scan(["example.invalid", "ssh://h", "[::1]:8443"])] == ["example.invalid:443", "ssh://h:22", "[::1]:8443"]
    finally:
        endpoints.probe = endpoints_probe
