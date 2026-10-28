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


def fake_fetch(url, dest, token=None):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "sign.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    fake_fetch.tokens.append(token)
    return dest


fake_fetch.tokens = []


def test_a_github_repository_is_added_by_link_and_downloaded_again_for_each_scan(app, home):
    fake_fetch.tokens.clear()
    with patch("acxelin_readiness.console.remote.fetch", side_effect=fake_fetch):
        r = call(app, "POST", "/api/projects/github", {"url": "https://github.com/acme/payments"})[1]
        assert call(app, "GET", "/api/status")[1]["projects"] == [{"id": r["project"], "name": "github.com/acme/payments"}]
        call(app, "POST", "/api/projects/scan", {"project": r["project"]})
        last = wait(app)["last"]
        call(app, "POST", "/api/projects/scan", {"project": r["project"]})
        wait(app)
    assert last["project"] == "acme/payments" and any(a["name"] == "RSA-2048" for a in last["assets"]) and len(fake_fetch.tokens) == 2
    again = rc.build(home)
    assert [p["name"] for p in again.routes[("GET", "/api/status")]({})[1]["projects"]] == ["github.com/acme/payments"], "kept across restarts, no folder needed"


def test_a_github_download_that_fails_is_reported_and_keeps_the_last_result(app):
    with patch("acxelin_readiness.console.remote.fetch", side_effect=fake_fetch):
        i = call(app, "POST", "/api/projects/github", {"url": "https://github.com/acme/payments"})[1]["project"]
        call(app, "POST", "/api/projects/scan", {"project": i})
        wait(app)
    with patch("acxelin_readiness.console.remote.fetch", side_effect=rc.remote.Refused("Repository not found on GitHub.")):
        call(app, "POST", "/api/projects/scan", {"project": i})
        status = wait(app)
    assert status["error"] == "Repository not found on GitHub." and status["last"]["assets"]


@pytest.mark.parametrize("url", ["https://gitlab.com/a/b", "https://github.com/a", "file:///etc", "https://x@github.com/a/b", 7])
def test_only_github_repository_links_are_accepted(app, url):
    with pytest.raises(ValueError):
        app.routes[("POST", "/api/projects/github")]({"url": url})


def test_the_access_token_is_saved_owner_only_used_for_downloads_and_never_returned(app, home):
    fake_fetch.tokens.clear()
    secret = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"
    assert call(app, "POST", "/api/github/token", {"token": secret})[1] == {"saved": True}
    with patch("acxelin_readiness.console.remote.fetch", side_effect=fake_fetch):
        i = call(app, "POST", "/api/projects/github", {"url": "https://github.com/acme/private"})[1]["project"]
        call(app, "POST", "/api/projects/scan", {"project": i})
        wait(app)
    assert fake_fetch.tokens == [secret]
    responses = json.dumps([call(app, *route)[1] for route in (("GET", "/api/status"), ("GET", "/api/projects/status"), ("GET", "/api/endpoints/status"))])
    assert secret not in responses and json.loads(responses)[0]["github_token"] is True
    leaked = [p for p in home.rglob("*") if p.is_file() and p.name != "github-token" and secret.encode() in p.read_bytes()]
    assert leaked == []
    import os
    import stat
    if os.name == "posix":
        assert stat.S_IMODE((home / "github-token").stat().st_mode) == 0o600
    call(app, "POST", "/api/github/token", {"token": ""})
    assert not (home / "github-token").exists() and call(app, "GET", "/api/status")[1]["github_token"] is False


@pytest.mark.parametrize("bad", ["has space", "x" * 300, "line\nbreak", 5])
def test_a_token_that_cannot_be_one_is_refused(app, bad):
    with pytest.raises(ValueError):
        app.routes[("POST", "/api/github/token")]({"token": bad})


def test_a_refused_folder_change_is_not_saved(app, repos, home, tmp_path):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    with patch("acxelin_readiness.console.workspace.scan", side_effect=lambda *a, **k: time.sleep(0.5) or {}):
        call(app, "POST", "/api/projects/scan", {"project": 0})
        with pytest.raises(ValueError):
            app.routes[("POST", "/api/setup")]({"directory": str(tmp_path)})
        wait(app)
    assert json.loads((home / "settings.json").read_text())["directory"] == str(repos.resolve())


def test_a_home_folder_of_an_unknown_user_is_a_message_not_a_crash(app):
    with pytest.raises(ValueError):
        app.routes[("POST", "/api/setup")]({"directory": "~nosuchuser_zz/x"})


@pytest.mark.parametrize("damage", ['{"truncated', '{"o--r": 5}', '["x"]', '{"acme--shop": "https://gitlab.com/a/b"}'])
def test_a_damaged_github_list_starts_empty_instead_of_stopping_the_console(home, damage):
    home.mkdir(parents=True)
    (home / "github.json").write_text(damage)
    assert rc.build(home).routes[("GET", "/api/status")]({})[1]["projects"] == []


def test_unreadable_numbers_in_the_endpoint_history_are_dropped(home):
    home.mkdir(parents=True)
    (home / "endpoints-history.json").write_text('[{"finished": NaN, "score": 50}, {"finished": 1e300, "score": 1}, {"finished": 5, "score": Infinity},'
                                                  ' {"finished": 7, "score": 70}]')
    assert rc.build(home).routes[("GET", "/api/endpoints/status")]({})[1]["history"] == [{"finished": 7, "score": 70}]


def test_branches_that_differ_only_in_case_get_separate_folders(app):
    with patch("acxelin_readiness.console.remote.fetch", side_effect=fake_fetch):
        a = call(app, "POST", "/api/projects/github", {"url": "https://github.com/acme/shop/tree/Main"})[1]["project"]
        b = call(app, "POST", "/api/projects/github", {"url": "https://github.com/acme/shop/tree/main"})[1]["project"]
    console = app.routes[("GET", "/api/status")].__self__
    assert a != b and len({p.name.lower() for p in console.projects}) == 2, "Windows folders are case-insensitive"


def scanned(app, repos):
    setup(app, repos)
    call(app, "POST", "/api/projects/register", {"name": "shop"})
    call(app, "POST", "/api/projects/scan", {"project": 0})
    return wait(app)["last"]["assets"][0]


def track(app, finding, **fields):
    return call(app, "POST", "/api/projects/track", {"project": 0, "finding": finding, "owner": "", "due": "", **fields})


def test_a_finding_moves_through_planned_in_progress_and_fixed_with_each_step_logged(app, repos):
    asset = scanned(app, repos)
    for status in ("planned", "in_progress", "fixed"):
        assert track(app, asset["id"], status=status, owner="payments team")[0] == 200
    track(app, asset["id"], status="fixed", owner="payments team")  # saving without a change adds no entry
    t = call(app, "GET", "/api/projects/status")[1]["last"]["assets"][0]["tracking"]
    assert t["status"] == "fixed" and [e["status"] for e in t["log"]] == ["planned", "in_progress", "fixed"] and all("at" in e for e in t["log"])
    with pytest.raises(ValueError, match="planned"):
        app.routes[("POST", "/api/projects/track")]({"project": 0, "finding": asset["id"], "status": "done"})


def test_a_finding_marked_fixed_that_the_next_scan_still_finds_is_flagged(app, repos):
    asset = scanned(app, repos)
    track(app, asset["id"], status="fixed")
    assert call(app, "GET", "/api/projects/status")[1]["last"]["assets"][0]["tracking"]["still_found"] is False, "not yet rescanned"
    call(app, "POST", "/api/projects/scan", {"project": 0})
    assert wait(app)["last"]["assets"][0]["tracking"]["still_found"] is True


def test_a_fixed_finding_that_is_gone_after_a_rescan_is_confirmed(app, repos):
    asset = scanned(app, repos)
    track(app, asset["id"], status="fixed")
    (repos / "shop/keys.py").write_text("def issue_key():\n    return None\n")
    call(app, "POST", "/api/projects/scan", {"project": 0})
    gone = wait(app)["last"]["not_observed"]
    assert [(g["id"], g["tracking"]["status"], g["tracking"]["still_found"]) for g in gone] == [(asset["id"], "fixed", False)]


def test_the_change_log_keeps_the_last_fifty_changes(app, repos):
    asset = scanned(app, repos)
    for n in range(60):
        track(app, asset["id"], status="in_progress", owner=f"owner {n}")
    log = call(app, "GET", "/api/projects/status")[1]["last"]["assets"][0]["tracking"]["log"]
    assert len(log) == 50 and log[-1]["owner"] == "owner 59"


def other_tool_cbom(names=("RSA-2048", "SHA-1", "AES-256-GCM", "FancyCipher9000")):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"tools": [{"name": "codeql", "version": "2.19"}], "component": {"name": "billing"}},
            "components": [{"type": "cryptographic-asset", "name": n, "bom-ref": n, "cryptoProperties": {"assetType": "algorithm"},
                            "evidence": {"occurrences": [{"location": "src/Billing.java", "line": 10 + i}]}} for i, n in enumerate(names)]}


def test_another_tools_cbom_is_imported_as_a_project_with_priorities_tracking_and_a_score(app, home):
    r = call(app, "POST", "/api/projects/import", {"name": "billing.cbom.json", "cbom": other_tool_cbom()})[1]
    assert call(app, "GET", "/api/status")[1]["projects"] == [{"id": r["project"], "name": "Imported: billing.cbom.json"}]
    call(app, "POST", "/api/projects/scan", {"project": r["project"]})
    last = wait(app)["last"]
    tiers = {a["name"]: a["tier"] for a in last["assets"]}
    assert tiers["RSA-2048"] in ("high", "critical") and tiers["SHA-1"] == "critical" and "FancyCipher9000" not in tiers
    assert isinstance(last["summary"]["score"], int) and any("codeql" in n and "not recognised" in n for n in last["notes"])
    rsa = next(a for a in last["assets"] if a["name"] == "RSA-2048")
    assert rsa["locations"] == [["src/Billing.java", 10]] and "codeql" in rsa["uncertainty"]
    assert call(app, "POST", "/api/projects/track", {"project": r["project"], "finding": rsa["id"], "status": "planned", "owner": "billing"})[0] == 200
    again = rc.build(home)
    assert again.routes[("GET", "/api/status")]({})[1]["projects"][0]["name"] == "Imported: billing.cbom.json", "kept across restarts"


def test_importing_the_same_name_again_replaces_it_and_compares(app):
    i = call(app, "POST", "/api/projects/import", {"name": "billing.cbom.json", "cbom": other_tool_cbom()})[1]["project"]
    call(app, "POST", "/api/projects/scan", {"project": i})
    wait(app)
    assert call(app, "POST", "/api/projects/import", {"name": "billing.cbom.json", "cbom": other_tool_cbom(("RSA-2048",))})[1]["project"] == i
    call(app, "POST", "/api/projects/scan", {"project": i})
    last = wait(app)["last"]
    assert [a["name"] for a in last["assets"]] == ["RSA-2048"] and {a["name"] for a in last["not_observed"]} >= {"SHA-1"}


@pytest.mark.parametrize("body", [{"name": "x.json", "cbom": [1]}, {"name": "x.json", "cbom": {"bomFormat": "SPDX"}}, {"name": "", "cbom": {}},
                                  {"name": "x" * 300, "cbom": {}}, {"name": "x.json"}, {"name": 5, "cbom": {}}])
def test_anything_but_a_cyclonedx_cbom_with_a_name_is_refused(app, body):
    with pytest.raises(ValueError):
        app.routes[("POST", "/api/projects/import")](body)


def test_the_import_route_takes_a_large_cbom_but_others_keep_their_limit(app):
    assert app.limits[("POST", "/api/projects/import")] >= 16_000_000 and ("POST", "/api/projects/track") not in app.limits
