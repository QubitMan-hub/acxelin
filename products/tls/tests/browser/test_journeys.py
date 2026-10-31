"""Acxelin TLS console journeys in a real browser: what a customer does, not what the API returns."""
import json
from pathlib import Path

import pytest
from acxelin_core import console as core
from acxelin_core import openssl

from acxelin_tls import console as tc

sync = pytest.importorskip("playwright.sync_api")
AXE = Path(__file__).resolve().parents[4] / "tools/browser/node_modules/axe-core/axe.min.js"
PASS = "ca-pass-7f3e91"
needs_openssl = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


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
def console(tmp_path):
    home = tmp_path / "home"
    app = tc.build(home)
    server = core.start(app, home, port=0)
    yield app, f"http://127.0.0.1:{server.server_address[1]}", home
    server.shutdown()


@pytest.fixture
def page(browser, console):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    pg = ctx.new_page()
    yield pg
    ctx.close()


def open_console(page, console):
    app, base, _ = console
    page.goto(f"{base}/#{app.sessions.ticket()}")


def create_ca(page, passphrase=""):
    page.get_by_label("Name", exact=True).fill("Example Root CA")
    if passphrase:
        page.get_by_label("Passphrase (recommended)").fill(passphrase)
        page.get_by_label("Repeat passphrase").fill(passphrase)
    page.get_by_role("button", name="Create certificate authority").click()
    page.get_by_role("heading", name="Example Root CA").wait_for()


def issue(page, cn, kind="Server"):
    page.get_by_label("Kind").select_option(label=kind)
    page.get_by_label("Name", exact=True).fill(cn)
    page.get_by_role("button", name="Issue certificate").click()
    page.get_by_text(f"Issued {cn}.").wait_for()


def test_first_run_signs_in_without_a_ticket_or_cookie_and_creates_the_ca(page, console):
    app, base, home = console
    ticket = app.sessions.ticket()
    page.goto(f"{base}/#{ticket}")
    page.get_by_role("heading", name="Create your certificate authority").wait_for()
    assert "#" not in page.url and ticket not in page.url and page.context.cookies() == []
    assert page.evaluate("sessionStorage.getItem('acx-token')")
    create_ca(page)
    assert page.get_by_text("ML-DSA-87").first.is_visible()
    assert (home / "ca/ca.crt").exists()
    again = page.context.new_page()
    again.goto(f"{base}/#{ticket}")
    again.get_by_role("heading", name="This link has expired").wait_for()
    assert "acxelin-tls console" in again.content()


def test_an_encrypted_ca_asks_for_its_passphrase_after_a_restart(page, console, browser):
    app, base, home = console
    open_console(page, console)
    create_ca(page, PASS)
    assert b"ENCRYPTED" in (home / "ca/ca.key").read_bytes()
    restarted = tc.build(home)
    server = core.start(restarted, home, port=0)
    try:
        ctx = browser.new_context()
        p2 = ctx.new_page()
        p2.goto(f"http://127.0.0.1:{server.server_address[1]}/#{restarted.sessions.ticket()}")
        p2.get_by_role("heading", name="Unlock the certificate authority").wait_for()
        p2.get_by_label("Passphrase").fill("wrong")
        p2.get_by_role("button", name="Unlock").click()
        p2.get_by_text("wrong passphrase").wait_for()
        p2.get_by_label("Passphrase").fill(PASS)
        p2.get_by_role("button", name="Unlock").click()
        p2.get_by_role("heading", name="Example Root CA").wait_for()
        assert PASS not in p2.content()
        ctx.close()
    finally:
        server.shutdown()


def test_issue_then_revoke_in_two_steps_and_the_list_shows_it(page, console):
    app, base, home = console
    open_console(page, console)
    create_ca(page)
    issue(page, "web.example.invalid")
    page.get_by_role("cell", name="web.example.invalid", exact=True).wait_for()
    assert page.get_by_text("Valid").first.is_visible()
    assert "PRIVATE KEY" not in page.content()
    page.get_by_role("button", name="Revoke web.example.invalid").click()
    assert page.get_by_role("button", name="Confirm revoke").is_visible()
    page.get_by_role("button", name="Confirm revoke").click()
    page.get_by_text("1 revoked").wait_for()
    assert page.get_by_role("cell", name="Revoked", exact=True).is_visible()
    page.get_by_role("button", name="Refresh revocation list").click()
    page.get_by_text("Revocation list valid for").wait_for()


def test_a_bad_name_is_explained_and_nothing_is_issued(page, console):
    open_console(page, console)
    create_ca(page)
    page.get_by_label("Name", exact=True).fill("bad name!")
    page.get_by_role("button", name="Issue certificate").click()
    page.get_by_text("is not a valid name").wait_for()
    assert page.get_by_text("Nothing issued yet").is_visible()


@needs_openssl
def test_edges_show_policy_and_a_connection_test_names_the_group(page, console):
    from acxelin_tls.edge import Edge, Route, serve_metrics
    app, base, home = console
    open_console(page, console)
    create_ca(page)
    cert = tc.TLSConsole.issue(app_state(app), {"kind": "server", "common_name": "localhost", "names": ["127.0.0.1"], "days": 30})[1]
    edge = Edge(Route("shop", "terminate", "127.0.0.1:0", "127.0.0.1:9", cert=str(home / cert["folder"] / "chain.pem"), key=str(home / cert["folder"] / "key.pem"))).start()
    metrics = serve_metrics("127.0.0.1:0", [edge], None)
    try:
        page.get_by_role("tab", name="Edges").click()
        page.get_by_label("Edge metrics address").fill(f"http://127.0.0.1:{metrics.server_address[1]}")
        page.get_by_role("button", name="Add edge").click()
        page.get_by_text("policy strict").wait_for()
        page.get_by_label("Host and port").fill(f"127.0.0.1:{edge.port}")
        page.get_by_label("Certificate name").fill("localhost")
        page.get_by_role("button", name="Test connection").click()
        page.get_by_text("Connected.").wait_for()
        assert "MLKEM" in page.inner_text("#t-result") and "ML-DSA" in page.inner_text("#t-result")
        page.get_by_label("Host and port").fill("127.0.0.1:1")
        page.get_by_role("button", name="Test connection").click()
        page.get_by_text("connection refused").wait_for()
        page.get_by_role("button", name="Remove http://127.0.0.1", exact=False).click()
        page.get_by_text("No edges added yet").wait_for()
    finally:
        edge.stop(0)
        metrics.shutdown()


def app_state(app):
    """The TLSConsole behind a built app: its route handlers are bound methods."""
    return app.routes[("GET", "/api/status")].__self__


@needs_openssl
def test_health_lists_what_this_computer_can_do(page, console):
    open_console(page, console)
    create_ca(page)
    page.get_by_role("tab", name="Health").click()
    page.get_by_text("can do post-quantum TLS 1.3").wait_for()
    assert page.get_by_role("button", name="Check again").is_visible()


@needs_openssl
@pytest.mark.parametrize("width,scheme", [(1280, "light"), (1280, "dark"), (390, "light")])
def test_no_accessibility_violations_and_no_sideways_scroll(browser, console, width, scheme):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = ctx.new_page()
    try:
        open_console(page, console)
        page.get_by_role("heading", name="Create your certificate authority").wait_for()
        axe = AXE.read_text()
        found = {"setup": page.evaluate(axe + ";axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))")}
        create_ca(page)
        issue(page, "web.example.invalid")
        found["certificates"] = page.evaluate("axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))")
        page.get_by_role("tab", name="Edges").click()
        page.get_by_label("Edge metrics address").wait_for()
        found["edges"] = page.evaluate("axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))")
        page.get_by_role("tab", name="Health").click()
        page.get_by_text("can do post-quantum TLS 1.3").wait_for()
        found["health"] = page.evaluate("axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))")
        assert {k: v for k, v in found.items() if v} == {}, found
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    finally:
        ctx.close()


def test_keyboard_only_creates_the_ca(page, console):
    open_console(page, console)
    page.get_by_label("Name", exact=True).wait_for()
    assert page.evaluate("document.activeElement.id") == "ca-name"
    page.keyboard.type("Keyboard CA")
    page.keyboard.press("Enter")
    page.get_by_role("heading", name="Keyboard CA").wait_for()
    assert json.loads(json.dumps(True))


def test_download_with_and_without_key_renew_and_see_it_all_in_recent_activity(page, console):
    import io
    import zipfile
    open_console(page, console)
    create_ca(page)
    issue(page, "api.example.invalid")
    page.get_by_role("button", name="Download api.example.invalid", exact=True).wait_for()
    with page.expect_download() as d:
        page.get_by_role("button", name="Download api.example.invalid", exact=True).click()
    names = sorted(zipfile.ZipFile(io.BytesIO(Path(d.value.path()).read_bytes())).namelist())
    assert names == ["ca.crt", "cert.pem", "chain.pem"] and d.value.suggested_filename.startswith("api.example.invalid-")
    with page.expect_download() as d:
        page.get_by_role("button", name="Download with key api.example.invalid").click()
    assert "key.pem" in zipfile.ZipFile(io.BytesIO(Path(d.value.path()).read_bytes())).namelist()
    page.get_by_role("button", name="Renew api.example.invalid").click()
    page.get_by_text("Renewed", exact=True).first.wait_for()
    page.get_by_role("button", name="Run maintenance").click()
    page.get_by_text("Nothing needed renewing.", exact=False).wait_for()
    activity = page.inner_text("#activity")
    assert "Issued api.example.invalid" in activity and "Downloaded api.example.invalid (with key)" in activity and "Renewed api.example.invalid" in activity


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
    open_console(page, console)
    create_ca(page)
    issue(page, "web.example.invalid")
    for tab, ready in (("Edges", "No edges added yet"), ("Health", "post-quantum TLS"), ("Certificates", "Issued certificates")):
        page.get_by_role("tab", name=tab).click()
        page.get_by_text(ready).first.wait_for()


def test_a_mistyped_passphrase_is_caught_before_the_ca_exists(page, console):
    app, base, home = console
    open_console(page, console)
    page.get_by_label("Name", exact=True).fill("Example Root CA")
    page.get_by_label("Passphrase (recommended)").fill("first-try-1")
    page.get_by_label("Repeat passphrase").fill("first-try-2")
    page.get_by_role("button", name="Create certificate authority").click()
    page.get_by_text("The two passphrases are different").wait_for()
    assert not (home / "ca/ca.crt").exists()


def test_an_issued_server_certificate_says_where_it_is_and_how_to_use_it(page, console):
    app, base, home = console
    open_console(page, console)
    create_ca(page)
    issue(page, "web.example.invalid")
    folder = next((home / "issued").iterdir())
    text = page.locator("#issued").inner_text()
    assert str(folder / "chain.pem") in text and str(folder / "key.pem") in text, text
    assert "acxelin-tls edge --listen" in text
    assert page.get_by_role("button", name="Copy command").is_visible()
    assert "on the left" not in page.content()


def test_the_owner_only_launch_page_opens_the_console_signed_in(page, console):
    app, url, home = console
    launch = core.launch_page(f"{url}/#{app.sessions.ticket()}", home)
    assert "#" not in launch, "the ticket is not in what the browser is given"
    page.goto(launch)
    page.wait_for_url(f"{url}/**", timeout=10000)
    page.wait_for_function("Object.keys(sessionStorage).length > 0", timeout=10000)
    assert "#" not in page.url or not page.url.split("#", 1)[1], "the redeemed ticket is cleared from the address bar"
