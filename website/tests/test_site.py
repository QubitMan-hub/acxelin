"""The website in a real browser: each product's journey from the home page, its pages naming only that product, real
demo output, working links, and accessibility on every page in light, dark and mobile."""
import functools
import http.server
import re
import sys
import threading
from pathlib import Path

import pytest

sync = pytest.importorskip("playwright.sync_api")
ROOT = Path(__file__).resolve().parents[2]
AXE = ROOT / "tools/browser/node_modules/axe-core/axe.min.js"
sys.path.insert(0, str(ROOT / "tools"))
import build_site  # noqa: E402

PRODUCTS = {"readiness": ("Acxelin Readiness", "See Acxelin Readiness", "sh install.sh"),
            "tls": ("Acxelin TLS", "See Acxelin TLS", "sh install.sh"),
            "vpn": ("Acxelin VPN", "See Acxelin VPN", "sh install.sh")}
PAGES = ["index.html"] + [f"{s}/{p}" for s, (_, pages) in build_site.SECTIONS.items() for p, _ in pages]
OLD = re.compile(r"Wolf ?Pack|wolfpack", re.I)


@pytest.fixture(scope="module")
def site():
    build_site.main()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(build_site.OUT))
    handler.log_message = lambda *a: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", build_site.OUT
    server.shutdown()


@pytest.fixture(scope="module")
def browser():
    with sync.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"no Playwright browser: {e}")
        yield b
        b.close()


@pytest.mark.parametrize("section", PRODUCTS)
def test_home_to_install_command_copied(browser, site, section):
    base, _ = site
    name, link, install = PRODUCTS[section]
    ctx = browser.new_context(permissions=["clipboard-read", "clipboard-write"])
    page = ctx.new_page()
    page.goto(base + "/index.html")
    page.get_by_role("link", name=link).click()
    page.get_by_role("heading", level=1).wait_for()
    assert page.url.endswith(f"/{section}/index.html")
    page.get_by_role("navigation", name=name).get_by_role("link", name="Set up", exact=True).click()
    page.get_by_role("heading", name=f"Set up {name}").wait_for()
    step = page.locator("ol.steps > li").filter(has=page.get_by_role("heading", name="Install", exact=True))
    step.get_by_role("button", name="Copy command").first.click()
    assert page.evaluate("navigator.clipboard.readText()") == install
    page.get_by_role("button", name="Copied").wait_for()
    ctx.close()


def test_each_product_page_names_only_its_own_product_and_the_home_page_only_routes(browser, site):
    base, _ = site
    page = browser.new_page()
    for section, (name, _, _) in PRODUCTS.items():
        others = [n for s, (n, _, _) in PRODUCTS.items() if s != section]
        expected = [name] + [label for _, label in build_site.SECTIONS[section][1]]
        for page_name, _ in build_site.SECTIONS[section][1]:
            page.goto(f"{base}/{section}/{page_name}")
            text = page.inner_text("body")
            assert not [o for o in others if o in text], (section, page_name)
            assert not OLD.search(text), (section, page_name, OLD.search(text).group(0))
            assert [a.inner_text() for a in page.get_by_role("navigation", name=name).get_by_role("link").all()] == expected
    page.goto(base + "/index.html")
    home = page.inner_text("body")
    assert all(n in home for n, _, _ in PRODUCTS.values())
    assert not re.search(r"how it works|set up|policy|CBOM \(", home, re.I), "the home page routes; product detail lives on product pages"
    page.close()


def test_demos_are_real_output(browser, site):
    base, out = site
    page = browser.new_page()
    page.goto(base + "/readiness/sample.html")
    page.frame_locator("iframe.report").get_by_text("payments-api").first.wait_for()
    assert '"specVersion": "1.6"' in (out / "readiness/sample-cbom.json").read_text()
    page.goto(base + "/tls/demo.html")
    tour = page.locator("pre code").first.inner_text()
    assert "refused, as it should be" in tour and "MLKEM768" in tour and "ML-DSA" in tour
    page.goto(base + "/vpn/demo.html")
    log = page.locator("pre code").first.inner_text()
    assert "TLSv1.3 X25519MLKEM768" in log and "new keys" in log and "was revoked" in log and "discarded its keys" in log
    page.get_by_role("button", name=re.compile("Both sides derive the same keys")).click()
    assert page.get_by_text("yes, compared after the run").is_visible()
    page.close()


def test_images_load_and_every_internal_link_resolves(browser, site):
    base, out = site
    page = browser.new_page()
    broken = []
    for path in PAGES:
        page.goto(f"{base}/{path}")
        assert page.evaluate("[...document.images].every(i => i.complete && i.naturalWidth > 0)"), path
        for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))"):
            if href.startswith(("http", "#", "mailto:")):
                continue
            if not ((out / path).parent / href.split("#")[0]).exists():
                broken.append((path, href))
    assert not broken, broken
    page.close()


@pytest.mark.parametrize("scheme,width", [("light", 1280), ("dark", 1280), ("light", 390)])
def test_every_page_passes_axe_and_does_not_scroll_sideways(browser, site, scheme, width):
    base, _ = site
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = ctx.new_page()
    axe = AXE.read_text()
    found = {}
    for path in PAGES:
        page.goto(f"{base}/{path}")
        page.wait_for_load_state("networkidle")
        v = page.evaluate(axe + ";axe.run({exclude:[['iframe']]}).then(r=>r.violations.map(v=>v.id+': '+v.nodes.slice(0,2).map(n=>n.html.slice(0,60)).join(' | ')))")
        if v:
            found[path] = v
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (path, "scrolls sideways")
    assert not found, found
    ctx.close()


def test_skip_link_reaches_the_main_content(browser, site):
    base, _ = site
    page = browser.new_page()
    page.goto(base + "/tls/index.html")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.className") == "skip"
    page.keyboard.press("Enter")
    assert page.evaluate("location.hash") == "#main"
    page.close()


def watch(page):
    """Every browser-side problem on a page: console errors, uncaught exceptions, failed requests and error responses."""
    problems = []
    page.on("console", lambda m: m.type == "error" and problems.append(f"console: {m.text}"))
    page.on("pageerror", lambda e: problems.append(f"exception: {e}"))
    page.on("requestfailed", lambda r: problems.append(f"failed: {r.url} {r.failure}"))
    page.on("response", lambda r: r.status >= 400 and problems.append(f"HTTP {r.status}: {r.url}"))
    return problems


def test_no_page_has_a_browser_error(browser, site):
    base, _ = site
    page = browser.new_page()
    problems = watch(page)
    for path in PAGES:
        page.goto(f"{base}/{path}")
        page.wait_for_load_state("networkidle")
    assert problems == []
    page.close()


def test_the_assets_page_shows_everything_readiness_tracks_from_the_product_itself(browser, site):
    """Every algorithm in Readiness's catalogue, every kind of asset its CBOM holds and every source its manual lists, so the page
    cannot promise what the product does not do or leave out what it does."""
    from acxelin_readiness.catalog import CATALOG
    base, _ = site
    page = browser.new_page()
    page.goto(base + "/readiness/assets.html")
    text = page.locator("main").inner_text()
    missing = [name for name in CATALOG if name not in text]
    assert not missing, missing
    for kind in ("Algorithms", "Protocols", "Certificates", "Keys and key material", "Libraries"):
        assert page.get_by_role("heading", name=kind, exact=True).count() == 1, kind
    manual = (ROOT / "products/readiness/docs/manual.md").read_text(encoding="utf-8")
    sources = re.findall(r"^\| ([A-Z][^|]+?) \|", manual.split("### What it reads", 1)[1].split("###", 1)[0], re.M)
    assert len(sources) >= 6 and all(s.strip() in text for s in sources if s.strip() != "Source"), sources
    assert page.get_by_text("quantum-safe", exact=False).count() and page.get_by_text("broken today", exact=False).count()
    page.close()
