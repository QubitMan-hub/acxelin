"""Readiness console journeys in a real browser: what a customer does, not what the API returns.

Run with the Playwright browser installed (`python -m playwright install chromium`); skipped when it is not.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from acxelin_core import console as core

from acxelin_readiness import console as rc

sync = pytest.importorskip("playwright.sync_api")
AXE = Path(__file__).resolve().parents[4] / "tools/browser/node_modules/axe-core/axe.min.js"


@pytest.fixture(scope="module")
def browser():
    with sync.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"no Playwright browser: {e}")
        yield b
        b.close()


@pytest.fixture
def repos(tmp_path):
    root = tmp_path / "repos"
    (root / "shop").mkdir(parents=True)
    (root / "shop/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n\ndef issue_key():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (root / "api").mkdir()
    (root / "api/a.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    return root


@pytest.fixture
def console(tmp_path):
    app = rc.build(tmp_path / "home")
    server = core.start(app, tmp_path / "home", port=0)
    yield app, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def page(browser, console):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    yield pg
    ctx.close()


def open_console(page, console):
    app, base = console
    page.goto(f"{base}/#{app.sessions.ticket()}")


def fill_setup(page, repos):
    page.get_by_label("Folder path").fill(str(repos))
    page.get_by_role("button", name="Use this folder").click()
    page.get_by_label("Folder path").wait_for(state="detached")


def scan_shop(page):
    page.get_by_label("Add a repository").select_option("shop")
    page.get_by_role("button", name="Add and scan").click()  # adding starts the first scan
    page.get_by_text("RSA", exact=False).first.wait_for(timeout=30000)


def test_first_run_signs_in_without_leaving_a_ticket_or_cookie(page, console, repos):
    app, base = console
    ticket = app.sessions.ticket()
    page.goto(f"{base}/#{ticket}")
    page.get_by_role("heading", name="Where are your repositories?").wait_for()
    assert page.get_by_role("tab", name="Endpoints").is_visible(), "grading servers needs no repository folder"
    assert "#" not in page.url and ticket not in page.url
    assert page.context.cookies() == []
    assert page.evaluate("sessionStorage.getItem('acx-token')")
    fill_setup(page, repos)
    page.go_back() if False else None
    again = page.context.new_page()
    again.goto(f"{base}/#{ticket}")
    again.get_by_role("heading", name="This link has expired").wait_for()
    assert "acxelin-readiness console" in again.content()


def test_add_scan_see_priorities_and_assign_an_owner(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    assert page.get_by_text("critical").first.is_visible() or page.get_by_text("high").first.is_visible()
    page.get_by_text("Assign an owner").first.click()
    page.get_by_label("Owner").first.fill("payments team")
    page.get_by_role("button", name="Save").first.click()
    page.get_by_text("Owner: payments team").wait_for()
    assert "key_size=2048" not in page.content()


def test_an_open_list_of_places_and_a_half_typed_owner_survive_a_running_scan(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)

    def slow(path, **kw):
        kw["cancel"].wait(20)
        raise rc.workspace.ScanStopped("Scan cancelled; the previous completed assessment is preserved")
    with patch("acxelin_readiness.console.workspace.scan", side_effect=slow):
        page.get_by_role("button", name="Scan repository").click()
        page.get_by_role("button", name="Stop scan").wait_for()
        page.locator("details.where summary", has_text="RSA").click()
        page.locator("details.track summary").first.click()
        page.locator("details.track input[type=text]").first.fill("ali")
        page.wait_for_timeout(2000)
        assert page.locator("details.where", has_text="RSA").evaluate("d => d.open")
        assert page.locator("details.track input[type=text]").first.input_value() == "ali"
        page.get_by_role("button", name="Stop scan").click()
        page.get_by_text("cancelled", exact=False).wait_for()


def test_stopping_a_scan_keeps_the_previous_result(page, console, repos):
    app, _ = console
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    first = page.get_by_text("Scanned", exact=False).first.inner_text()

    def slow(path, **kw):
        kw["cancel"].wait(20)
        raise rc.workspace.ScanStopped("Scan cancelled; the previous completed assessment is preserved")
    with patch("acxelin_readiness.console.workspace.scan", side_effect=slow):
        page.get_by_role("button", name="Scan repository").click()
        page.get_by_role("button", name="Stop scan").click()
        page.get_by_text("cancelled", exact=False).wait_for()
    assert page.get_by_text("Scanned", exact=False).first.inner_text() == first
    page.get_by_role("button", name="Scan repository").wait_for()


def test_choosing_another_repository_shows_its_own_state(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    page.get_by_label("Add a repository").select_option("api")
    page.get_by_role("button", name="Add and scan").click()
    page.get_by_text("SHA-1", exact=False).first.wait_for(timeout=30000)
    assert not page.get_by_text("RSA", exact=False).count(), "api shows its own findings, not shop's"
    page.get_by_role("button", name="shop", exact=True).click()
    page.get_by_text("RSA", exact=False).first.wait_for()


def grade(target, g):
    return {"target": target, "grade": g, "protocol": "tls", "certificate": None, "negotiated": "TLS 1.3 X25519MLKEM768" if g == "A" else "TLS 1.3 X25519", "group": ""}


def test_endpoints_changes_since_the_last_check_and_cbom_download(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    page.get_by_role("tab", name="Endpoints").click()
    runs = iter([[grade("127.0.0.1:1", "F")], [grade("127.0.0.1:1", "A")]])
    with patch("acxelin_readiness.console.endpoints.scan", side_effect=lambda t: next(runs)):
        for g in ("F", "A"):
            page.get_by_label("Hosts to check").fill("127.0.0.1:1")
            page.get_by_role("button", name="Check endpoints").click()
            page.locator("#ep-result td .pill", has_text=g).wait_for()
            page.wait_for_function("!document.querySelector('#check').disabled")
        page.get_by_role("heading", name="Changed since the scan before").wait_for()
        assert "127.0.0.1:1: F → A" in page.content()
    with page.expect_download(timeout=60000) as d:
        page.get_by_role("button", name="Download CBOM").click()
    cbom = json.loads(Path(d.value.path()).read_text())
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    assert d.value.suggested_filename == "endpoints-cbom.json"


@pytest.mark.parametrize("width,scheme", [(1280, "light"), (1280, "dark"), (390, "light")])
def test_no_accessibility_violations_and_no_sideways_scroll(browser, console, repos, width, scheme):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = ctx.new_page()
    try:
        open_console(page, console)
        page.get_by_role("heading", name="Where are your repositories?").wait_for()
        views = []
        views.append(page.evaluate(AXE.read_text() + ";axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))"))
        fill_setup(page, repos)
        scan_shop(page)
        views.append(page.evaluate("axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))"))
        page.get_by_role("tab", name="Endpoints").click()
        views.append(page.evaluate("axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))"))
        assert views == [[], [], []], views
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    finally:
        ctx.close()


def test_keyboard_only_reaches_setup_and_submits(page, console, repos):
    open_console(page, console)
    page.get_by_label("Folder path").wait_for()
    assert page.evaluate("document.activeElement.id") == "dir"
    page.keyboard.type(str(repos))
    page.keyboard.press("Enter")
    page.get_by_label("Folder path").wait_for(state="detached")
    page.wait_for_function("document.activeElement && document.activeElement.id === 'tab-projects'")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement !== document.body")


def test_no_browser_errors_through_every_view(browser, console, tmp_path):
    ctx = browser.new_context()
    page = ctx.new_page()
    problems = []
    page.on("console", lambda m: m.type == "error" and problems.append(f"console: {m.text}"))
    page.on("pageerror", lambda e: problems.append(f"exception: {e}"))
    page.on("requestfailed", lambda r: problems.append(f"failed: {r.url} {r.failure}"))
    page.on("response", lambda r: r.status >= 400 and problems.append(f"HTTP {r.status}: {r.url}"))
    try:
        VIEWS(page, console, tmp_path)
        assert problems == []
    finally:
        ctx.close()


def VIEWS(page, console, tmp_path):
    root = tmp_path / "views"
    (root / "shop").mkdir(parents=True)
    (root / "shop/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    open_console(page, console)
    fill_setup(page, root)
    scan_shop(page)
    page.get_by_role("tab", name="Endpoints").click()
    page.get_by_label("Hosts to check").wait_for()
    page.get_by_role("tab", name="Projects").click()
    page.get_by_text("RSA", exact=False).first.wait_for()


def test_endpoints_work_before_choosing_a_repository_folder(page, console):
    open_console(page, console)
    page.get_by_role("tab", name="Endpoints").click()
    with patch("acxelin_readiness.console.endpoints.scan", side_effect=lambda t: [grade("example.com:443", "C")]):
        page.get_by_label("Hosts to check").fill("https://example.com/some/page")
        page.get_by_role("button", name="Check endpoints").click()
        page.get_by_text("example.com:443").first.wait_for()
    assert "Only the host and port are checked" in page.content(), "a pasted address says its path was not graded"


def test_the_folder_example_is_this_computers_own_kind_of_path(page, console):
    open_console(page, console)
    assert str(Path.home()) in page.get_by_label("Folder path").get_attribute("placeholder")


def test_a_finding_shows_where_it_is_and_the_priority_chips_filter_the_list(page, console, tmp_path):
    root = tmp_path / "many"
    (root / "shop").mkdir(parents=True)
    (root / "shop/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nimport hashlib\n\n"
                                      "rsa.generate_private_key(public_exponent=65537, key_size=2048)\nhashlib.md5(b'x').hexdigest()\n")
    open_console(page, console)
    fill_setup(page, root)
    scan_shop(page)
    page.get_by_text("MD5", exact=True).wait_for()
    page.get_by_role("button", name="Show only critical").click()
    page.wait_for_function("!document.body.innerText.includes('RSA-2048')")
    assert page.get_by_text("MD5", exact=True).is_visible()
    page.get_by_role("button", name="Show every priority").click()
    page.get_by_text("RSA-2048").wait_for()
    page.get_by_text("RSA-2048").click()
    page.get_by_text("keys.py:4").wait_for()


def test_a_finding_can_be_accepted_as_a_risk_until_a_date(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    page.get_by_text("Assign an owner").first.click()
    page.get_by_label("Status").first.select_option("exception")
    page.get_by_label("Why it is accepted").first.fill("Vendor appliance, replaced in 2027")
    assert page.get_by_label("Due date").first.get_attribute("type") == "date"
    page.get_by_label("Accepted until").first.fill("2099-01-01")
    page.get_by_role("button", name="Save").first.click()
    page.get_by_text("Accepted risk until 2099-01-01").wait_for()


def test_endpoints_say_what_can_happen_and_what_to_do_next(page, console):
    rows = [grade("a.example:443", "C") | {"certificate": {"key": "RSA-2048", "issuer": "CN=Old CA", "expires": "2026-01-01", "days_left": -5, "quantum_safe": False}},
            grade("ssh.example:22", "C") | {"target": "ssh://ssh.example:22", "protocol": "ssh",
                                            "certificate": {"key": "ssh-ed25519", "expires": "", "days_left": 9999, "quantum_safe": False}}]
    open_console(page, console)
    page.get_by_role("tab", name="Endpoints").click()
    with patch("acxelin_readiness.console.endpoints.scan", side_effect=lambda t: rows):
        page.get_by_label("Hosts to check").fill("a.example\nssh://ssh.example")
        page.get_by_role("button", name="Check endpoints").click()
        page.get_by_role("heading", name="What can happen").wait_for()
    recommend = page.locator("section.outlook", has=page.get_by_role("heading", name="What we recommend"))
    assert recommend.locator("ol > li").first.inner_text().startswith("Renew the certificate")
    assert "X25519MLKEM768" in recommend.inner_text() and "mlkem768x25519-sha256" in recommend.inner_text()
    table = page.locator("#ep-result table").inner_text()
    assert "expired 2026-01-01" in table and "9999" not in table, "SSH host keys have no expiry; an expired certificate says so"
    assert page.evaluate(AXE.read_text() + ";axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))") == []


def test_counts_match_the_listed_findings_when_some_are_only_in_tests(page, console, tmp_path):
    root = tmp_path / "tested"
    (root / "shop/tests").mkdir(parents=True)
    (root / "shop/keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (root / "shop/tests/test_keys.py").write_text("import hashlib\nhashlib.md5(b'x')\nhashlib.sha1(b'y')\n")
    open_console(page, console)
    fill_setup(page, root)
    scan_shop(page)
    page.get_by_text("only in tests").wait_for()
    assert page.locator(".counts button").inner_text().split()[-1] == str(page.locator("#pj-result tbody tr").count())


def test_after_a_restart_the_selected_repository_is_the_one_whose_results_show(browser, tmp_path, repos):
    first = rc.build(tmp_path / "home")
    first.routes[("POST", "/api/setup")]({"directory": str(repos)})
    for i, name in enumerate(("api", "shop")):
        first.routes[("POST", "/api/projects/register")]({"name": name})
        first.routes[("POST", "/api/projects/select")]({"project": i})
        first.routes[("POST", "/api/projects/scan")]({"project": i})
        while first.routes[("GET", "/api/projects/status")]({})[1]["running"]:
            pass
    app = rc.build(tmp_path / "home")
    server = core.start(app, tmp_path / "home", port=0)
    ctx = browser.new_context()
    try:
        page = ctx.new_page()
        page.goto(f"http://127.0.0.1:{server.server_address[1]}/#{app.sessions.ticket()}")
        page.get_by_text("RSA", exact=False).first.wait_for()
        assert page.locator(".list button[aria-current=true]").inner_text() == "shop"
    finally:
        ctx.close()
        server.shutdown()


def fake_fetch(url, dest, token=None):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "sign.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    return dest


def test_a_github_repository_is_scanned_from_the_first_screen_without_a_folder(page, console):
    open_console(page, console)
    with patch("acxelin_readiness.console.remote.fetch", side_effect=fake_fetch):
        page.get_by_label("Add from GitHub").fill("https://github.com/acme/payments")
        page.get_by_role("button", name="Download and scan").click()
        page.get_by_text("RSA-2048").wait_for(timeout=30000)
    assert page.get_by_role("heading", name="github.com/acme/payments").is_visible()


def test_a_private_repository_token_is_saved_without_ever_showing_it(page, console):
    secret = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"
    open_console(page, console)
    page.get_by_text("Private repositories").click()
    assert page.get_by_label("Access token").get_attribute("type") == "password"
    page.get_by_label("Access token").fill(secret)
    page.get_by_role("button", name="Save token").click()
    page.get_by_text("Private repositories: token saved").wait_for()
    assert secret not in page.content() and secret not in page.url
    page.get_by_text("Private repositories: token saved").click()
    page.get_by_role("button", name="Remove token").click()
    page.get_by_text("Private repositories", exact=True).wait_for()


def test_the_readiness_score_and_its_trend_show_for_projects_and_endpoints(page, console, repos):
    open_console(page, console)
    fill_setup(page, repos)
    scan_shop(page)
    page.locator(".score b").wait_for()
    assert page.locator(".score b").inner_text().isdigit()
    page.get_by_role("button", name="Scan repository").click()
    page.locator("svg.trend").wait_for(timeout=30000)
    page.get_by_role("tab", name="Endpoints").click()
    runs = iter([[grade("127.0.0.1:1", "C")], [grade("127.0.0.1:1", "A")]])
    with patch("acxelin_readiness.console.endpoints.scan", side_effect=lambda t: next(runs)):
        for g in ("C", "A"):
            page.get_by_label("Hosts to check").fill("127.0.0.1:1")
            page.get_by_role("button", name="Check endpoints").click()
            page.locator("#ep-result td .pill", has_text=g).wait_for()
            page.wait_for_function("!document.querySelector('#check').disabled")
    assert page.locator(".score b").inner_text() == "100"
    assert "from 0 to 100" in page.locator("svg.trend").get_attribute("aria-label")
    assert page.evaluate(AXE.read_text() + ";axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))") == []
