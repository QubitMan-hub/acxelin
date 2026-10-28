"""Readiness console journeys, at the API (spec: "Where each console feature goes"), on the shared console mechanism."""
import json
import time
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest
from acxelin_core import console as core

from acxelin_readiness import console as rc


@pytest.fixture
def home(tmp_path):
    return tmp_path / "state"


@pytest.fixture
def repos(tmp_path):
    root = tmp_path / "repos"
    (root / "shop").mkdir(parents=True)
    (root / "shop/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n\ndef issue_key():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (root / "shop/checkout.py").write_text("from keys import issue_key\n\ndef enroll_customer():\n    return issue_key()\n")
    (root / "empty").mkdir()
    return root


def call(app, method, path, body=None):
    status, payload = app.routes[(method, path)](body or {}) if (method, path) in app.routes else (404, {})
    return status, payload


@pytest.fixture
def app(home):
    return rc.build(home)


def wait(app, key="projects"):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        status = call(app, "GET", f"/api/{key}/status")[1]
        if not status["running"]:
            return status
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def setup(app, repos):
    assert call(app, "POST", "/api/setup", {"directory": str(repos)})[0] == 200


def test_first_run_needs_a_repository_folder_and_refuses_a_missing_one(app, repos, tmp_path):
    assert call(app, "GET", "/api/status")[1]["configured"] is False
    with pytest.raises(ValueError, match="existing folder"):
        app.routes[("POST", "/api/setup")]({"directory": str(tmp_path / "nope")})
    setup(app, repos)
    status = call(app, "GET", "/api/status")[1]
    assert status["configured"] and status["available"] == ["empty", "shop"]


def test_setup_survives_a_restart(app, repos, home):
    setup(app, repos)
    assert rc.build(home).routes[("GET", "/api/status")]({})[1]["configured"] is True


@pytest.mark.parametrize("name", ["../x", "a/b", ".hidden", "", "nope", "shop\\x"])
def test_registration_is_scoped_to_the_chosen_folder(app, repos, name):
    setup(app, repos)
    with pytest.raises(ValueError, match="inside the folder"):
        app.routes[("POST", "/api/projects/register")]({"name": name})


def test_register_scan_and_see_priorities(app, repos):
    setup(app, repos)
    assert call(app, "POST", "/api/projects/register", {"name": "shop"})[1] == {"project": 0}
    assert call(app, "POST", "/api/projects/register", {"name": "shop"})[1] == {"project": 0}
    call(app, "POST", "/api/projects/scan", {"project": 0})
    status = wait(app)
    assert status["error"] is None
    last = status["last"]
    assert last["summary"]["resolved_calls"] == 1
    assert any(a["algorithm"] == "RSA" and a["tier"] in ("critical", "high") for a in last["assets"])
    assert "snippet" not in json.dumps(status) and "key_size=2048" not in json.dumps(status)


def test_a_failed_scan_is_retryable_and_never_leaks_source(app, repos):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    with patch("acxelin_readiness.console.workspace.scan", side_effect=RuntimeError("PRIVATE_SENTINEL")):
        call(app, "POST", "/api/projects/scan", {"project": 0})
        status = wait(app)
    assert status["error"] and "PRIVATE_SENTINEL" not in json.dumps(status)
    call(app, "POST", "/api/projects/scan", {"project": 0})
    assert wait(app)["error"] is None


def test_cancel_keeps_the_previous_assessment(app, repos):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    call(app, "POST", "/api/projects/scan", {"project": 0})
    previous = wait(app)["last"]

    def slow(path, **kw):
        kw["cancel"].wait(10)
        raise rc.workspace.ScanStopped("Scan cancelled; the previous completed assessment is preserved")
    with patch("acxelin_readiness.console.workspace.scan", side_effect=slow):
        call(app, "POST", "/api/projects/scan", {"project": 0})
        assert call(app, "POST", "/api/projects/cancel")[1] == {"requested": True}
        status = wait(app)
    assert "cancelled" in status["error"] and status["last"]["finished"] == previous["finished"]
    with pytest.raises(ValueError, match="No project scan is running"):
        app.routes[("POST", "/api/projects/cancel")]({})


def test_tracking_a_finding_is_saved_with_its_owner(app, repos):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    call(app, "POST", "/api/projects/scan", {"project": 0})
    asset = wait(app)["last"]["assets"][0]
    call(app, "POST", "/api/projects/track", {"project": 0, "finding": asset["id"], "owner": "payments team", "status": "in_progress", "due": "2030-01-01"})
    saved = call(app, "GET", "/api/projects/status")[1]["last"]["assets"][0]["tracking"]
    assert saved["owner"] == "payments team" and saved["status"] == "in_progress"
    with pytest.raises(ValueError, match="Dates"):
        app.routes[("POST", "/api/projects/track")]({"project": 0, "finding": asset["id"], "status": "open", "due": "soon"})


def grade(target, g):
    return {"target": target, "grade": g, "protocol": "tls", "certificate": None, "group": "X25519MLKEM768" if g == "A" else "X25519"}


def test_endpoint_scan_reports_what_changed_since_the_scan_before(app):
    runs = iter([[grade("a.example.invalid:443", "F")], [grade("a.example.invalid:443", "A")]])
    with patch("acxelin_readiness.console.endpoints.scan", side_effect=lambda t: next(runs)):
        call(app, "POST", "/api/endpoints/scan", {"targets": "a.example.invalid:443"})
        first = wait(app, "endpoints")["last"]
        call(app, "POST", "/api/endpoints/scan", {"targets": "a.example.invalid:443"})
        second = wait(app, "endpoints")["last"]
    assert first["changes"] == [] and second["changes"] == [{"target": "a.example.invalid:443", "before": "F", "after": "A"}]


def test_endpoint_targets_are_checked_before_a_scan_starts(app):
    for bad in ({"targets": "not a host:xx"}, {"targets": "\n  "}, {"targets": ["h:1"] * 501}):
        with pytest.raises(ValueError):
            app.routes[("POST", "/api/endpoints/scan")](bad)


def test_endpoint_cbom_export_is_a_cyclonedx_document(app):
    with patch("acxelin_readiness.console.endpoints.scan", return_value=[grade("a.example.invalid:443", "F")]):
        call(app, "POST", "/api/endpoints/scan", {"targets": "a.example.invalid:443"})
        wait(app, "endpoints")
    status, payload = call(app, "POST", "/api/endpoints/cbom", {"targets": ["a.example.invalid:443"]})
    assert status == 200 and payload["cbom"]["bomFormat"] == "CycloneDX" and payload["cbom"]["specVersion"] == "1.6"


def test_the_console_signs_in_over_http_with_a_launch_ticket(app, home):
    server = core.start(app, home, port=0)
    port = server.server_address[1]
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
        assert b"Acxelin Readiness" in page and page.count(b"<script>") == 1
        ticket = app.sessions.ticket()
        post = lambda path, body, token=None: urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", json.dumps(body).encode(), {"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})}))
        token = json.loads(post("/api/session", {"ticket": ticket}).read())["token"]
        get = urllib.request.Request(f"http://127.0.0.1:{port}/api/status", headers={"Authorization": f"Bearer {token}"})
        assert json.loads(urllib.request.urlopen(get).read())["configured"] is False
        with pytest.raises(urllib.error.HTTPError) as e:
            post("/api/session", {"ticket": ticket})
        assert e.value.code == 401
    finally:
        server.shutdown()


def test_the_console_loads_no_other_product():
    import subprocess
    import sys
    code = "import sys, acxelin_readiness.console;" \
           "bad=[m for m in sys.modules if m.split('.')[0] in ('acxelin_tls','acxelin_vpn')]; assert not bad, bad"
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


def test_choosing_another_repository_shows_that_repositorys_own_results(app, repos):
    (repos / "api").mkdir()
    (repos / "api/a.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    setup(app, repos)
    for name in ("shop", "api"):
        call(app, "POST", "/api/projects/register", {"name": name})
    call(app, "POST", "/api/projects/scan", {"project": 0})
    wait(app)
    assert call(app, "POST", "/api/projects/select", {"project": 1})[1] == {"selected": 1}
    status = call(app, "GET", "/api/projects/status")[1]
    assert status["selected"] == 1 and status["last"] is None
    call(app, "POST", "/api/projects/select", {"project": 0})
    assert call(app, "GET", "/api/projects/status")[1]["last"]["project"] == "shop"


def test_registered_repositories_survive_a_restart_but_never_widen_when_the_folder_changes(app, repos, home, tmp_path):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    call(app, "POST", "/api/projects/scan", {"project": 0})
    wait(app)
    again = rc.build(home)
    status = again.routes[("GET", "/api/status")]({})[1]
    assert status["projects"] == [{"id": 0, "name": "shop"}]
    assert again.routes[("GET", "/api/projects/status")]({})[1]["last"]["assets"]
    other = tmp_path / "other"
    other.mkdir()
    again.routes[("POST", "/api/setup")]({"directory": str(other)})
    assert rc.build(home).routes[("GET", "/api/status")]({})[1]["projects"] == []
    again.routes[("POST", "/api/setup")]({"directory": str(repos)})
    (repos / "shop").rename(repos / "moved")
    (repos / "shop").symlink_to(other, target_is_directory=True)
    assert rc.build(home).routes[("GET", "/api/status")]({})[1]["projects"] == []


def test_choosing_another_folder_after_a_scan_starts_clean(app, repos, tmp_path):
    setup(app, repos)
    for name in ("empty", "shop"):
        call(app, "POST", "/api/projects/register", {"name": name})
    call(app, "POST", "/api/projects/select", {"project": 1})
    call(app, "POST", "/api/projects/scan", {"project": 1})
    wait(app)
    (tmp_path / "other/web").mkdir(parents=True)
    call(app, "POST", "/api/setup", {"directory": str(tmp_path / "other")})
    call(app, "POST", "/api/projects/register", {"name": "web"})
    status = call(app, "GET", "/api/projects/status")[1]
    assert status["selected"] == 0 and status["last"] is None, "results from the old folder are never shown under a new repository"


def test_a_folder_cannot_change_while_a_scan_runs(app, repos, tmp_path):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    with patch("acxelin_readiness.console.workspace.scan", side_effect=lambda *a, **k: time.sleep(0.5) or {}):
        call(app, "POST", "/api/projects/scan", {"project": 0})
        with pytest.raises(ValueError, match="scan"):
            app.routes[("POST", "/api/setup")]({"directory": str(tmp_path)})
        wait(app)


def test_after_a_restart_the_most_recent_repository_is_the_selected_one(app, repos, home):
    setup(app, repos)
    for name in ("empty", "shop"):
        call(app, "POST", "/api/projects/register", {"name": name})
    call(app, "POST", "/api/projects/scan", {"project": 0})
    wait(app)
    call(app, "POST", "/api/projects/select", {"project": 1})
    call(app, "POST", "/api/projects/scan", {"project": 1})
    wait(app)
    again = rc.build(home)
    assert again.routes[("GET", "/api/status")]({})[1]["selected"] == 1
    status = again.routes[("GET", "/api/projects/status")]({})[1]
    assert status["selected"] == 1 and status["last"]["project"] == "shop"


def test_endpoint_results_carry_what_can_happen_and_what_to_do(app):
    with patch("acxelin_readiness.console.endpoints.scan", return_value=[grade("a.example.invalid:443", "C")]):
        call(app, "POST", "/api/endpoints/scan", {"targets": "a.example.invalid:443"})
        outlook = wait(app, "endpoints")["last"]["outlook"]
    assert outlook["risks"][0]["targets"] == ["a.example.invalid:443"] and "X25519MLKEM768" in outlook["actions"][0]["text"]


def test_choosing_the_same_folder_again_keeps_its_repositories(app, repos):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    setup(app, repos)
    assert call(app, "GET", "/api/status")[1]["projects"] == [{"id": 0, "name": "shop"}]
