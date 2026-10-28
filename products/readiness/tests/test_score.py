"""The readiness score: a plainly defined average, kept with every scan so the console can show its trend."""
import time
from unittest.mock import patch

from acxelin_readiness import console as rc
from acxelin_readiness import endpoints, workspace


def asset(tier, test_only=False):
    return {"tier": tier, "test_only": test_only}


def test_a_project_scores_the_average_priority_of_its_listed_findings():
    assert workspace.score([asset("critical"), asset("ok")]) == 50
    assert workspace.score([asset("high"), asset("medium"), asset("low")]) == 50
    assert workspace.score([asset("ok"), asset("critical", test_only=True)]) == 100, "test-only findings are not listed, so not scored"
    assert workspace.score([]) is None and workspace.score([asset("high", test_only=True)]) is None, "no cryptography found is not proof of readiness"


def test_endpoints_score_a_100_b_50_c_0_and_leave_out_what_could_not_be_graded():
    rows = lambda *grades: [{"grade": g, "certificate": None} for g in grades]
    assert endpoints.summary(rows("A", "B", "C", "F"))["score"] == 50
    assert endpoints.summary(rows("A", "A"))["score"] == 100
    assert endpoints.summary(rows("F"))["score"] is None and endpoints.summary([])["score"] is None


def test_every_project_scan_keeps_its_score_in_the_history(tmp_path):
    (tmp_path / "shop").mkdir()
    (tmp_path / "shop/k.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    store = workspace.ProjectStore(tmp_path / "w.json")
    for _ in range(2):
        store.save(tmp_path / "shop", workspace.scan(tmp_path / "shop"))
    saved = store.assessment(tmp_path / "shop")
    assert isinstance(saved["summary"]["score"], int) and [h["summary"]["score"] for h in saved["history"]] == [saved["summary"]["score"]] * 2


def test_endpoint_checks_keep_a_bounded_score_history_across_restarts(tmp_path):
    app = rc.build(tmp_path)
    route = lambda method, path, body=None: app.routes[(method, path)](body or {})[1]
    for g in ("C", "B", "A"):
        with patch("acxelin_readiness.console.endpoints.scan", return_value=[{"target": "a.example.invalid:443", "grade": g, "protocol": "tls", "certificate": None}]):
            route("POST", "/api/endpoints/scan", {"targets": "a.example.invalid:443"})
            while route("GET", "/api/endpoints/status")["running"]:
                time.sleep(0.02)
    again = rc.build(tmp_path)
    assert [h["score"] for h in again.routes[("GET", "/api/endpoints/status")]({})[1]["history"]] == [0, 50, 100]
    with patch("acxelin_readiness.console.endpoints.scan", return_value=[{"target": "a.example.invalid:443", "grade": "A", "protocol": "tls", "certificate": None}]):
        for _ in range(40):
            again.routes[("POST", "/api/endpoints/scan")]({"targets": "a.example.invalid:443"})
            while again.routes[("GET", "/api/endpoints/status")]({})[1]["running"]:
                time.sleep(0.01)
    assert len(again.routes[("GET", "/api/endpoints/status")]({})[1]["history"]) == 30


def test_a_damaged_endpoint_history_does_not_stop_the_console(tmp_path):
    (tmp_path / "endpoints-history.json").write_text("{not json")
    assert rc.build(tmp_path).routes[("GET", "/api/endpoints/status")]({})[1]["history"] == []
