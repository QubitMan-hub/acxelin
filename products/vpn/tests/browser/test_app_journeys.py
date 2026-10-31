"""The Acxelin VPN window in a real browser, against a real CA, enrollment service and WireGuard gateway on this machine (with
a stand-in for `wg`): one-time addresses, opening an invitation, enrolling, connecting and disconnecting, axe in light and dark
at desktop and phone width, and the guided tour. Moved from the suite's Playwright specs with their assertions."""
import re
import threading
from pathlib import Path

import pytest
from acxelin_core import tls
from acxelin_core.pki import CA, est

from acxelin_vpn import app, join
from acxelin_vpn.wireguard import Gateway, GatewayConfig

sync = pytest.importorskip("playwright.sync_api")
expect = sync.expect
AXE = Path(__file__).resolve().parents[4] / "tools/browser/node_modules/axe-core/axe.min.js"


class FakeWG:
    def __init__(self):
        self.peers_ = {}

    def set_private_key(self, key, listen_port=None):
        pass

    def set_peer(self, public, psk, allowed_ips, endpoint=None, keepalive=None):
        self.peers_[public] = allowed_ips

    def remove_peer(self, public):
        self.peers_.pop(public)

    def peers(self):
        return {k: {"latest_handshake": 0, "rx_bytes": 0, "tx_bytes": 0} for k in self.peers_}


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
def window(tmp_path):
    w = app.App(folder=tmp_path / "vpn", apply=False)
    server = app.serve(w)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield w, f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


@pytest.fixture
def invitation(tmp_path):
    try:
        tls.lib()
    except tls.OpenSSLUnavailable as e:
        pytest.skip(f"the gateway behind the window needs OpenSSL 3.5: {e}")
    d = tmp_path / "gw"
    ca = CA.init(d / "pki", "VPN Root")
    ca.issue("localhost", "server", out=d / "gw")
    ca.crl()
    cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24",
                        cert=str(d / "gw/chain.pem"), key=str(d / "gw/key.pem"), ca=str(d / "pki/ca.crt"), crl=str(d / "pki/crl.pem"),
                        private_key=str(d / "gw.key"), state=str(d / "state.json"), routes=["192.168.10.0/24"], manage_interface=False).validate()
    gw = Gateway(cfg, FakeWG()).start()
    srv = est.serve(d / "pki", "127.0.0.1:0", d / "gw/chain.pem", d / "gw/key.pem")
    srv.start()
    path = tmp_path / "laptop.acxinvite"
    path.write_bytes(join.make(ca, "bob", f"https://localhost:{srv.port}", f"127.0.0.1:{gw.server.port}", server_name="localhost", hours=1)[0])
    yield path
    gw.shutdown()
    srv.stop(1)


def axe(page):
    return page.evaluate(AXE.read_text() + ";axe.run().then(r=>r.violations.map(v=>v.id+': '+v.help))")


def test_without_a_valid_one_time_address_the_window_shows_no_state(browser, window):
    w, base = window
    page = browser.new_page()
    page.goto(base)
    expect(page.locator("#error")).to_contain_text("tray icon, or the address printed by acxelin-vpn app")
    page.goto("about:blank")
    page.goto(base + "#wrong")
    expect(page.locator("#error")).to_contain_text("already used or has expired")
    page.goto("about:blank")
    once = base + "#" + w.ticket()
    page.goto(once)
    expect(page.locator("#word")).to_have_text("Not set up")
    other = browser.new_page()
    other.goto(once)
    expect(other.locator("#error")).to_contain_text("already used")
    assert axe(page) == []
    page.close()
    other.close()


def test_open_an_invitation_enroll_connect_disconnect(browser, window, invitation):
    w, base = window
    for scheme, width in (("light", 1280), ("dark", 390)):
        ctx = browser.new_context(color_scheme=scheme, viewport={"width": width, "height": 850})
        page = ctx.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(base + "#" + w.ticket())
        expect(page).to_have_url(base)
        assert page.evaluate("document.documentElement.scrollWidth - innerWidth") <= 0
        assert axe(page) == []
        if scheme == "light":
            expect(page.locator("#word")).to_have_text("Not set up")
            page.set_input_files("#invite", str(invitation))
            expect(page.locator("#inv-name")).to_have_text("laptop.acxinvite")
            page.fill("#pass", "device pass")
            page.fill("#repeat", "something else")
            page.click("#connect")
            expect(page.locator("#error")).to_contain_text("different")
            page.click("#again .show")
            expect(page.locator("#repeat")).to_have_attribute("type", "text")
            page.fill("#pass", "device pass")
            page.fill("#repeat", "device pass")
            page.click("#connect")
        else:
            expect(page.locator("#again")).to_be_hidden()
            page.fill("#pass", "wrong")
            page.click("#connect")
            expect(page.locator("#error")).to_contain_text("does not unlock")
            page.fill("#pass", "device pass")
            page.click("#connect")
        expect(page.locator("#word")).to_have_text("Keys agreed, not protected", timeout=30000)
        expect(page).to_have_title(re.compile("Keys agreed, not protected"))
        page.reload()
        expect(page.locator("#word")).to_have_text("Keys agreed, not protected")
        expect(page.locator("#facts")).to_contain_text("10.99.0.")
        page.click("#more summary")
        expect(page.locator("#details")).to_contain_text("Post-quantum")
        expect(page.locator("#details")).to_contain_text("Key renewed")
        expect(page.locator("#warn")).to_be_hidden()
        if scheme == "light":
            w.client.agreed_at -= 3600
            page.reload()
            expect(page.locator("#warn")).to_contain_text("has not been renewed for 60 min")
            assert axe(page) == []
            w.client.agreed_at += 3600
            page.reload()
            expect(page.locator("#warn")).to_be_hidden()
            w.client.error = "this computer's certificate has been revoked: ask your administrator for a new invitation"
            page.reload()
            expect(page.locator("#line")).to_contain_text("access was revoked")
            expect(page.locator("#line")).not_to_contain_text("Trying again")
            assert axe(page) == []
            w.client.error = None
        assert axe(page) == []
        page.click("#disconnect")
        expect(page.locator("#word")).to_have_text("Disconnected")
        expect(page.locator("#pass")).to_have_value("")
        assert errors == []
        ctx.close()


def test_the_window_tour(browser, window):
    w, base = window
    page = browser.new_page()
    page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => false})")
    page.goto(base + "#" + w.ticket())
    card = page.locator(".tour-card")
    expect(card).to_contain_text("Step 1 of 6")
    assert page.evaluate(AXE.read_text() + ";axe.run('.tour-card').then(r=>r.violations.map(v=>v.id))") == []
    page.click(".tour-card .go")
    expect(card).to_contain_text("Step 2 of 6")
    page.click(".tour-card button:has-text('Back')")
    expect(card).to_contain_text("Step 1 of 6")
    for i in range(1, 6):
        page.keyboard.press("ArrowRight")
        expect(card).to_contain_text(f"Step {i + 1} of 6")
    expect(page.locator(".tour-card .go")).to_have_text("Finish")
    page.click(".tour-card .go")
    expect(card).to_have_count(0)
    page.click("#tour")
    expect(card).to_contain_text("Step 1 of 6")
    page.close()
