"""Build the website into build/site: python tools/build_site.py

Pages in website/ hold only their content; this wraps each with the shared head, header and footer. A section's pages show
only that product's navigation. Each product's Manual page is its docs/manual.md, the same file its release folder ships. The Readiness sample report and CBOM are produced by running the product on its example project, and the VPN demo by two of its controllers agreeing keys.
"""
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC, OUT = ROOT / "website", ROOT / "build" / "site"
SECTIONS = {
    "tls": ("Acxelin TLS", [("index.html", "Overview"), ("how-it-works.html", "How it works"), ("set-up.html", "Set up"),
                            ("manual.html", "Manual"), ("demo.html", "Demo"), ("security.html", "Security")]),
    "vpn": ("Acxelin VPN", [("index.html", "Overview"), ("how-it-works.html", "How it works"), ("set-up.html", "Set up"),
                            ("manual.html", "Manual"), ("demo.html", "Demo"), ("security.html", "Security")]),
    "readiness": ("Acxelin Readiness", [("index.html", "Overview"), ("how-it-works.html", "How it works"), ("set-up.html", "Set up"),
                                         ("manual.html", "Manual"), ("sample.html", "Sample"), ("security.html", "Security")]),
}
LAYOUT = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="icon" href="{root}assets/acxelin-quantum.svg" type="image/svg+xml">
<link rel="stylesheet" href="{root}assets/site.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="wrap bar">
<a href="{root}index.html" aria-label="Acxelin Quantum, all products">{logo}</a>
<nav aria-label="{nav_label}">{nav}</nav>
</div></header>
<main id="main"><div class="wrap">
{body}
</div></main>
<footer><div class="wrap"><span>{footer}</span><nav aria-label="Company"><a href="https://acxelinquantum.com/">Talk to Acxelin Quantum</a><a href="{root}index.html">All products</a></nav></div></footer>
<script>
document.documentElement.classList.add("js");
document.querySelectorAll("main pre").forEach((pre) => {
  const wrap = document.createElement("div"), button = document.createElement("button"), what = pre.classList.contains("output") ? "output" : "command";
  wrap.className = "code";
  button.type = "button"; button.className = "copy"; button.textContent = "Copy"; button.setAttribute("aria-label", `Copy ${what}`);
  button.addEventListener("click", async () => {
    const say = (text, label) => { button.textContent = text; button.setAttribute("aria-label", label); };
    try { await navigator.clipboard.writeText(pre.innerText.replace(/\n$/, "")); say("Copied", "Copied"); }
    catch (e) { say("Select and copy", "Select and copy by hand"); }
    setTimeout(() => say("Copy", `Copy ${what}`), 1800);
  });
  pre.replaceWith(wrap); wrap.append(pre, button);
});
document.querySelectorAll(".frames").forEach((list) => {
  const items = [...list.children], buttons = items.map((li) => li.querySelector(".frame"));
  const select = (li) => items.forEach((item) => {
    const now = item === li, tree = item.querySelector(".tree");
    if (now) item.dataset.now = ""; else delete item.dataset.now;
    item.querySelector(".frame").setAttribute("aria-expanded", String(now));
    if (tree) tree.hidden = !now;
  });
  select(items.find((li) => "now" in li.dataset) || items[0]);
  buttons.forEach((b, i) => {
    b.addEventListener("click", () => select(items[i]));
    b.addEventListener("keydown", (e) => {
      const to = {ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: buttons.length - 1}[e.key];
      if (to === undefined || !buttons[to]) return;
      e.preventDefault(); buttons[to].focus(); select(items[to]);
    });
  });
});
</script>
</body>
</html>
"""


def logo():
    svg = (ROOT / "website/assets/acxelin-quantum.svg").read_text(encoding="utf-8")
    return svg.replace('class="logo"', 'class="logo" aria-hidden="true" focusable="false"')


def nav(section, current, root):
    if not section:
        return "".join(f'<a href="{key}/index.html">{name}</a>' for key, (name, _) in SECTIONS.items())
    name, pages = SECTIONS[section]
    mark = lambda href: ' aria-current="page"' if href == current else ""
    links = "".join(f'<a href="{href}"{mark(href)}>{label}</a>' for href, label in pages)
    return f'<a class="product" href="index.html">{name}</a>{links}'


def sample(out):
    """Run the product on its example project; the site shows what it really produced."""
    from acxelin_readiness import cli
    project = ROOT / "products/readiness/examples/payments-api"
    with tempfile.TemporaryDirectory() as tmp:
        cli.main(["scan", str(project), "-o", tmp, "-q"])
        shutil.copy(Path(tmp) / "report.html", out / "readiness/sample-report.html")
        shutil.copy(Path(tmp) / "cbom.json", out / "readiness/sample-cbom.json")
        bom = json.loads((Path(tmp) / "cbom.json").read_text())
    parts = [c for c in bom["components"] if c.get("type") == "cryptographic-asset" and (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"][:2]
    return bom, html.escape(json.dumps(parts, indent=2))


def tls_tour():
    """The real output of `acxelin-tls try` and the edge's log. The build fails when it cannot run (it needs OpenSSL 3.5+): the page never shows invented output."""
    run = subprocess.run([sys.executable, "-m", "acxelin_tls", "try"], capture_output=True, text=True, timeout=120)
    if run.returncode:
        sys.exit(f"acxelin-tls try failed (set ACXELIN_OPENSSL to an OpenSSL 3.5+ folder): {run.stderr or run.stdout}")
    return run.stdout.strip("\n"), run.stderr


class Recorder:
    """Stands in for strongSwan at build time: records what the controller hands it. Key bytes are kept for comparison only."""
    def __init__(self):
        self.keys, self.conns = [], []

    def version(self):
        return "recorder"

    def ml_kem(self):
        return ["ML_KEM_768"]

    def load_keys(self, *a):
        self.keys.append(a)

    def load_conn(self, conn):
        self.conns.append(conn)

    def tunnels(self):
        return []

    def shared_ids(self):
        return []

    def __getattr__(self, name):
        return lambda *a, **k: None


def vpn_tour():
    """Two real Acxelin VPN controllers on this machine: a branch agrees keys with headquarters over ML-DSA mutual TLS, then
    the branch is revoked and refused. strongSwan does not run at build time; a recorder takes what would be loaded into it."""
    import io
    import logging
    from acxelin_core.pki import CA
    from acxelin_vpn import Peer, Site
    from acxelin_vpn.controller import Controller
    log = io.StringIO()
    handler = logging.StreamHandler(log)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            ca = CA.init(d / "ca", "Acme VPN Root")
            issued = {n: ca.issue(n, "site", ["127.0.0.1"], out=d / n)[1] for n in ("hq.acme.example", "branch1.acme.example")}
            ca.crl()
            site = lambda name, other, listen="", **kw: Site(name, "127.0.0.1", str(d / name / "chain.pem"), str(d / name / "key.pem"), str(d / "ca/ca.crt"),
                                                             crl=str(d / "ca/crl.pem"), keyring_listen=listen,
                                                             peers=[Peer(other, "127.0.0.1", ["10.1.0.0/16"], ["10.2.0.0/16"], **kw)])
            hq = Controller(site("hq.acme.example", "branch1.acme.example", "127.0.0.1:0"), charon=Recorder())
            hq.start()
            try:
                branch = Controller(site("branch1.acme.example", "hq.acme.example", initiate=True, keyring=f"127.0.0.1:{hq.server.port}"), charon=Recorder())
                branch.agree(branch.site.peers[0])
                revoked_at = __import__("time").strftime("%H:%M:%S")
                ca.revoke(issued["branch1.acme.example"].serial, "keyCompromise")
                ca.crl()
                try:
                    branch.agree(branch.site.peers[0])
                    sys.exit("the revoked branch was not refused; the VPN demo would be wrong")
                except Exception:  # noqa: BLE001  the refusal is what the demo shows, read from headquarters' log
                    pass
                hq.enforce_revocations()
            finally:
                hq.stop.set()
                hq.server.stop(1)
            facts = {"revoked_at": revoked_at, "root": ca.algorithm, "site": issued["branch1.acme.example"].algorithm, "same": branch.charon.keys[0][2:] == hq.charon.keys[0][2:],
                     "psk": len(branch.charon.keys[0][2]), "ppk": len(branch.charon.keys[0][3]), "conn": branch.charon.conns[-1]["hq.acme.example"]}
    finally:
        root.removeHandler(handler)
    return log.getvalue(), facts


def find(pattern, text, what):
    m = re.search(pattern, text)
    if not m:
        sys.exit(f"the site shows only real output, and {what} was not in it; update tools/build_site.py to the product's new wording")
    return m


def frames(rows, label, caption, number, legend, start=1):
    """A capture: numbered frames, each a button over its detail tree. Without script every tree shows; with it, the selected one."""
    items = []
    for i, (t, what, kind, verdict, tree, now) in enumerate(rows, start):
        fields = "".join(f'<dt>{html.escape(k)}</dt>' + "".join(f'<dd{PLAIN if plain else ""}>{html.escape(x)}</dd>' for x in (v if isinstance(v, list) else [v]))
                         for k, v, plain in tree)
        key = f'<span class="key {kind}" aria-hidden="true"></span>' if kind in ("ok", "bad", "exposed") else ""
        items.append(f'<li class="{kind}"{" data-now" if now else ""}><button class="frame" type="button" aria-expanded="true" '
                     f'aria-controls="{label}-{i}"><span class="no">{i}</span><span class="t">{html.escape(t)}</span>'
                     f'<span class="what">{html.escape(what)}</span><span class="verdict">{key}{html.escape(verdict)}</span></button>'
                     f'<dl class="tree" id="{label}-{i}">{fields}</dl></li>')
    keys = "".join(f'<span><span class="key {k}" aria-hidden="true"></span>{html.escape(v)}</span>' for k, v in legend)
    return (f'<figure class="capture" aria-labelledby="{label}-cap"><div class="capture-bar"><span>{caption[0]}</span>'
            f'<span class="legend">{keys}</span></div><ol class="frames">{"".join(items)}</ol>'
            f'<figcaption id="{label}-cap"><b>Fig. {number}</b>{caption[1]}</figcaption></figure>')


TRY_BAR = "<strong>acxelin-tls try</strong> · captured when this site was built"
VPN_BAR = "<strong>Acxelin VPN key agreement, headquarters and a branch</strong> · captured when this site was built"
VPN_KEYS = [("ok", "post-quantum"), ("bad", "refused or cut off")]
TRY_KEYS = [("ok", "accepted, post-quantum"), ("bad", "refused")]
SCAN_BAR = "<strong>acxelin-readiness scan payments-api</strong> · captured when this site was built"
SCAN_KEYS = [("bad", "broken today"), ("exposed", "quantum-exposed"), ("ok", "post-quantum")]


def tls_rows(out):
    """The try run as five frames: what happened, in the order it happened, with what each side negotiated."""
    a = find(r"\((ML-DSA-\d+) root\) issues the edge an (ML-DSA-\d+) certificate", out, "the authority step")
    web = find(r"An ordinary web server starts on ([\d.]+:\d+)", out, "the web server step").group(1)
    start = find(r"(\d\d:\d\d:\d\d),\d+ INFO try: listening on ([\d.]+:\d+)", out, "the edge starting")
    ok = find(r"(\d\d:\d\d:\d\d),\d+ INFO try: [\d.]+:\d+ (TLSv1\.3) (\S+) (\S+) peer=", out, "the accepted handshake")
    kex = find(r"(?m)^\s+key exchange\s+(\S+)\s+\((.*?)\)", out, "the key exchange line")
    cert = find(r"(?m)^\s+certificate\s+(\S+)", out, "the certificate line").group(1)
    pagetext = find(r"(?m)^\s+page\s+(.*)", out, "the page line").group(1)
    no = find(r"(\d\d:\d\d:\d\d),\d+ WARNING try: rejected [\d.]+:\d+: handshake failed: ([^(]+?) \(", out, "the refused handshake")
    why = find(r"refused, as it should be: (.*)", out, "the refusal line").group(1)
    return [
        (start.group(1), "The authority issues the edge its certificate", "info", "set up",
         [("root", a.group(1), False), ("edge certificate", a.group(2), False)], False),
        (start.group(1), "An ordinary web server starts, with no post-quantum support", "info", "set up",
         [("listening", web, False), ("post-quantum", "none", False)], False),
        (start.group(1), "The edge starts in front of it, policy strict", "info", "set up",
         [("listening", start.group(2), False), ("accepts", "post-quantum clients only", True)], False),
        (ok.group(1), "A post-quantum client asks for the page", "ok", "accepted, post-quantum",
         [("protocol", ok.group(2), False), ("key exchange", f"{kex.group(1)}  ({kex.group(2)})", False), ("cipher", ok.group(4), False),
          ("certificate", f"{cert}  (post-quantum signature)", False), ("page", pagetext, True)], True),
        (no.group(1), "A client offering only X25519 tries the same", "bad", "refused",
         [("edge log", f"handshake failed: {no.group(2)}", False), ("outcome", f"Refused, as it should be: {why}.", True)], False),
    ]


def vpn_rows(log, facts):
    """The two-site run as seven frames: set-up, the mutual TLS handshake, the keys handed to strongSwan, then the revocation."""
    t = lambda m: m.group(1)
    listen = find(r"(\d\d:\d\d:\d\d),\d+ INFO keyring: listening on ([\d.]+:\d+)", log, "the key agreement service starting")
    shake = find(r"(\d\d:\d\d:\d\d),\d+ INFO keyring: [\d.]+:\d+ (TLSv1\.3) (\S+) (\S+) peer=CN=(\S+)", log, "the mutual TLS handshake")
    keys = find(r"(\d\d:\d\d:\d\d),\d+ INFO hq\.acme\.example: new keys (\w+) \(", log, "headquarters' new keys")
    refused = find(r"(\d\d:\d\d:\d\d),\d+ WARNING keyring: rejected [\d.]+:\d+: (certificate \w+ was revoked on [\d-]+)", log, "the refusal")
    cut = find(r"(\d\d:\d\d:\d\d),\d+ WARNING branch1\.acme\.example: .*?; (closed its tunnel and discarded its keys)", log, "the tunnel being cut")
    if not facts["same"]:
        sys.exit("the two sites derived different keys; the VPN demo would be wrong")
    conn = facts["conn"]
    return [
        (t(listen), "The authority issues both sites their certificates", "info", "set up",
         [("root", facts["root"], False), ("hq.acme.example", facts["site"], False), ("branch1.acme.example", facts["site"], False)], False),
        (t(listen), "Headquarters waits for branches to agree keys", "info", "set up",
         [("listening", listen.group(2), False), ("accepts", "TLS 1.3, hybrid ML-KEM, ML-DSA certificates from this authority", True)], False),
        (t(shake), "The branch connects over mutual TLS", "ok", "accepted, post-quantum",
         [("protocol", shake.group(2), False), ("key exchange", f"{shake.group(3)}  (ML-KEM-768 + X25519)", False), ("cipher", shake.group(4), False),
          ("branch presented", f"CN={shake.group(5)}, {facts['site']}", False), ("headquarters presented", f"CN=hq.acme.example, {facts['site']}", False)], False),
        (t(keys), "Both sides derive the same keys and hand them to strongSwan", "ok", "post-quantum",
         [("IKE pre-shared key", f"{facts['psk']} bytes, from the TLS session", True), ("post-quantum PPK", f"{facts['ppk']} bytes, RFC 8784", True),
          ("same on both sides", "yes, compared after the run" if facts["same"] else "no", True), ("agreement", keys.group(2), False),
          ("IKE proposal", conn["proposals"][0], False), ("ESP proposal", conn["children"]["net"]["esp_proposals"][0], False)], True),
        (facts["revoked_at"], "The branch's certificate is revoked", "info", "revoked",
         [("reason", "keyCompromise", False), ("revocation list", "re-signed by the authority", True)], False),
        (t(refused), "The branch tries to agree new keys", "bad", "refused",
         [("headquarters' log", refused.group(2), False), ("outcome", "No new keys. Nothing falls back.", True)], False),
        (t(cut), "Headquarters cuts the branch off", "bad", "cut off",
         [("headquarters' log", cut.group(2), False), ("in production", "within 15 seconds of the revocation list reaching the gateway", True)], False),
    ]


def vpn_capture(log, facts):
    return frames(vpn_rows(log, facts), "agree", (VPN_BAR, "The real run, frame by frame. strongSwan does not run when this site is built, so frame 4 shows what "
                  "was handed to it. Choose a frame to see what each side presented and derived."), 1, VPN_KEYS)


def tls_capture(out):
    return frames(tls_rows(out), "try", (TRY_BAR, "The real run, frame by frame. Choose a frame to see what each side presented and negotiated."), 1, TRY_KEYS)


def policy_ladder():
    """What each named policy lets a connection negotiate, read from the product's own policy table."""
    from acxelin_tls.policies import POLICIES
    said = {"strict": "Post-quantum only. The default.", "transition": "Also classical clients, while you migrate.",
            "cnsa2": "NSA CNSA 2.0: ML-KEM-1024 and ML-DSA-87 only."}
    rungs = []
    for name, pol in POLICIES.items():
        groups = "".join(f'<li><span class="key {"ok" if "MLKEM" in g.upper() else "exposed"}" aria-hidden="true"></span>{html.escape(g)}'
                         f'{"" if "MLKEM" in g.upper() else CLASSICAL}</li>' for g in pol.groups.split(":"))
        sig = ", ".join(x.replace("mldsa", "ML-DSA-") for x in pol.sigalgs.split(":")) if pol.sigalgs else "any, including a classical fallback for browsers"
        rungs.append(f'<div class="rung"><h3>{name}</h3><p>{html.escape(said.get(name, ""))}</p><ul aria-label="Key exchanges {name} accepts">{groups}</ul>'
                     f'<p class="cert">Certificates: {html.escape(sig)}</p></div>')
    return f'<div class="ladder">{"".join(rungs)}</div>'


VERDICT = [(r"Harvest now|Shor|Classical fallback", "exposed", "quantum-exposed"), (r"[Bb]roken|disallowed today|ECB", "bad", "broken today"),
           (r"Quantum-safe|hybrid ML-KEM group configured", "ok", "post-quantum")]


def verdict(rationale):
    return next(((k, v) for pattern, k, v in VERDICT if re.search(pattern, rationale)), ("info", "no quantum break"))


def readiness_rows(bom):
    """The sample scan's assets as ranked frames: tier, why, where, and the fix, exactly as the scan wrote them."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    assets = []
    for c in bom["components"]:
        p = {x["name"]: x["value"] for x in c.get("properties", [])}
        if c.get("type") == "cryptographic-asset" and p.get("acxelin:tier") in order:
            assets.append((order[p["acxelin:tier"]], -float(p.get("acxelin:risk-score", 0)), c, p))
    assets.sort(key=lambda a: a[:2])
    rows, chosen = [], False
    for _, _, c, p in assets:
        kind, word = verdict(p.get("acxelin:rationale", ""))
        word = "lower priority" if kind == "info" and p["acxelin:tier"] != "ok" else word
        seen = c.get("evidence", {}).get("occurrences", [])
        where = f'{seen[0]["location"]}:{seen[0].get("line", "")}' + (f"  and {len(seen) - 1} more" if len(seen) > 1 else "") if seen else "-"
        tree = [("tier", p["acxelin:tier"], False), ("why", p.get("acxelin:rationale", ""), True), ("where", where, False)]
        if p.get("acxelin:recommendation"):
            tree.append(("migrate to", p["acxelin:recommendation"], False))
        if p.get("acxelin:remediation"):
            tree.append(("change", p["acxelin:remediation"].replace("`", "").split(" | "), False))
        if p.get("acxelin:nist-status"):
            tree.append(("NIST", p["acxelin:nist-status"], True))
        now = kind == "exposed" and not chosen
        chosen = chosen or now
        rows.append((p["acxelin:tier"], f'{c["name"]} · {p.get("acxelin:exposure", "")}', kind, word, tree, now))
    return rows


def readiness_capture(bom):
    rows = readiness_rows(bom)
    return frames(rows, "scan", (SCAN_BAR, f"All {len(rows)} assets the sample scan ranked, most urgent first. Choose one to see why it ranks there and what to change."), 1, SCAN_KEYS)


def home_proof(out, bom, vpn):
    """The home page shows each product working: the top of the sample scan's queue, the decisive frames of the try run, and the
    VPN's key agreement and refusal."""
    scan = readiness_rows(bom)[:3]
    return (frames(scan, "home-scan", (SCAN_BAR, f"Acxelin Readiness: the three most urgent of the {len(readiness_rows(bom))} assets it ranked in a sample payments service."), 1, SCAN_KEYS)
            + frames(tls_rows(out)[3:], "home-try", (TRY_BAR, "Acxelin TLS: a post-quantum client is let through to an unchanged web server; a classical one is refused."), 2, TRY_KEYS, start=4)
            + frames(vpn_rows(*vpn)[2:6], "home-agree", (VPN_BAR, "Acxelin VPN: two sites agree their tunnel's keys over post-quantum mutual TLS; once revoked, the branch is refused."), 3, VPN_KEYS, start=3))


def mosca(bom):
    """Mosca's inequality drawn from the numbers the sample scan itself used: secrecy + migration against the assumed quantum year.
    Two drawings of the same numbers: a wide one, and a narrow one whose labels sit above the bars so a phone shows the whole verdict."""
    import datetime as dt
    text = " ".join(x["value"] for c in bom["components"] for x in c.get("properties", []) if x["name"] == "acxelin:rationale")
    m = find(r"data needs (\d+)y secrecy \+ (\d+)y migration = (\d+)y, but a CRQC is assumed in (\d+)y", text, "the Mosca rationale")
    shelf, mig, total, crqc = (int(x) for x in m.groups())
    now = dt.date.today().year
    end, q, exposed = now + total + 1, now + crqc, total - crqc
    desc = (f"Migration takes {mig} years, from {now} to {now + mig}. Data encrypted until then must stay secret {shelf} more years, "
            f"to {now + total}. A quantum computer is assumed in {q}. The last {exposed} years are exposed.")

    def draw(name, width, left, step):
        x = lambda year: left + (year - now) * ((width - left - 20) / (end - now))
        narrow = left == 0
        mig_y, sec_y = (44, 118) if narrow else (30, 90)
        axis = sec_y + 60
        label = (lambda y, t, n: f'<text class="label" x="0" y="{y - 10}">{t} <tspan class="note">{n}</tspan></text>') if narrow else \
                (lambda y, t, n: f'<text class="label" x="0" y="{y + 14}">{t}</text><text class="note" x="0" y="{y + 30}">{n}</text>')
        ticks = "".join(f'<line class="axis" x1="{x(y):.1f}" y1="{axis}" x2="{x(y):.1f}" y2="{axis + 6}"/>'
                        f'<text class="tick" x="{x(y):.1f}" y="{axis + 22}" text-anchor="middle">{y}</text>' for y in range(now, end + 1, step))
        return (f'<svg class="{name}" viewBox="0 0 {width} {axis + 40}" role="img" aria-labelledby="mosca-{name}-t mosca-{name}-d">'
                f'<title id="mosca-{name}-t">Mosca\'s inequality for the sample scan</title><desc id="mosca-{name}-d">{desc}</desc>'
                f'<defs><pattern id="hatch-{name}" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
                '<rect class="hatch-ground" width="7" height="7"/><line class="hatch-line" x1="0" y1="0" x2="0" y2="7"/></pattern></defs>'
                f'{label(mig_y, "Migration", f"{mig} years")}'
                f'<rect class="bar-mig" x="{x(now):.1f}" y="{mig_y}" width="{x(now + mig) - x(now):.1f}" height="26" rx="3"/>'
                f'{label(sec_y, "Must stay secret", f"{shelf} years")}'
                f'<rect class="bar-sec" x="{x(now + mig):.1f}" y="{sec_y}" width="{x(q) - x(now + mig):.1f}" height="26" rx="3"/>'
                f'<rect class="bar-exp" fill="url(#hatch-{name})" x="{x(q):.1f}" y="{sec_y}" width="{x(now + total) - x(q):.1f}" height="26" rx="3"/>'
                f'<text class="label" x="{(x(q) + x(now + total)) / 2:.1f}" y="{sec_y + 46}" text-anchor="middle">exposed {exposed} years</text>'
                f'<line class="crqc" x1="{x(q):.1f}" y1="12" x2="{x(q):.1f}" y2="{axis}"/>'
                f'<text class="label" x="{x(q) + (-8 if narrow else 8):.1f}" y="14" text-anchor="{"end" if narrow else "start"}">quantum computer assumed, {q}</text>'
                f'<line class="axis" x1="{x(now):.1f}" y1="{axis}" x2="{x(end):.1f}" y2="{axis}"/>{ticks}</svg>')

    return (f'<figure class="timeline">{draw("wide", 960, 140, 2)}{draw("narrow", 400, 0, 4)}<figcaption><b>Fig. 2</b>The sample scan\'s own numbers: '
            f'{shelf} years of secrecy plus {mig} years of migration is {total} years, but a quantum computer is assumed in {crqc}. '
            'Data protected by RSA or ECDH today stays exposed for the difference.</figcaption></figure>')


CLASSICAL = '<span class="visually-hidden"> (classical)</span>'
PLACEHOLDER = re.compile(r"{{\w+}}")
ITEM, NUMBER, LEAD, PLAIN = re.compile(r"^(-|\d+\.) "), re.compile(r"^\d+\. "), ' class="lead"', ' class="plain"'


def inline(text):
    parts = re.split(r"`([^`]*)`", text)
    out = []
    for i, part in enumerate(parts):
        if i % 2:
            out.append(f"<code>{html.escape(part)}</code>")
            continue
        part = html.escape(part, quote=False)
        part = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", part)
        part = re.sub(r"\*(.+?)\*", r"<em>\1</em>", part)
        out.append(re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2">\1</a>', part))
    return "".join(out)


def markdown(text):
    """The Markdown the manuals use: headings, paragraphs, lists, tables and code blocks. Each ## heading is a section."""
    lines, out, chapters, para = text.splitlines(), [], [], []
    def flush():
        if para:
            out.append(f"<p{LEAD if len(out) == 1 else ''}>{inline(' '.join(para))}</p>")
            para.clear()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("```"):
            flush()
            end = next(j for j in range(i + 1, len(lines)) if lines[j].strip().startswith("```"))
            out.append(f"<pre><code>{html.escape(chr(10).join(lines[i + 1:end]))}</code></pre>")
            i = end + 1
            continue
        if line.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            head = "".join(f"<th>{inline(c)}</th>" for c in rows[0])
            body = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rows[2:])
            label = html.escape(", ".join(re.sub(r"[`*]", "", c) for c in rows[0]), quote=True)
            out.append(f'<div class="scroll" tabindex="0" role="region" aria-label="Table: {label}"><table><thead><tr>{head}</tr></thead>'
                       f'<tbody>{body}</tbody></table></div>')
            continue
        if ITEM.match(line):
            flush()
            tag = "ul" if line.startswith("-") else "ol"
            items = []
            while i < len(lines) and ITEM.match(lines[i].strip()):
                items.append(f"<li>{inline(ITEM.sub('', lines[i].strip()))}</li>")
                i += 1
            out.append(f"<{tag}>{''.join(items)}</{tag}>")
            continue
        heading = re.match(r"(#{1,3}) (.*)", line)
        if heading:
            flush()
            level, title = len(heading.group(1)), heading.group(2)
            if level == 2:
                slug = re.sub(r"[^a-z0-9]+", "-", NUMBER.sub("", title).lower()).strip("-")
                chapters.append((slug, title))
                out.append(f'</section>\n<section class="chapter" aria-labelledby="{slug}">\n<h2 id="{slug}">{inline(title)}</h2>')
            else:
                out.append(f"<h{level}>{inline(title)}</h{level}>")
        elif line:
            para.append(line)
        else:
            flush()
        i += 1
    flush()
    toc = "".join(f'<li><a href="#{slug}">{inline(NUMBER.sub("", title))}</a></li>' for slug, title in chapters)
    first = next(n for n, block in enumerate(out) if block.startswith("</section>"))
    out.insert(first, f'<nav class="toc" aria-label="Contents"><h2>Contents</h2><ol>{toc}</ol></nav>')
    return "<section>\n" + "\n".join(out) + "\n</section>\n"


def manual(section):
    name = SECTIONS[section][0]
    text = (ROOT / "products" / section / "docs/manual.md").read_text(encoding="utf-8")
    return (f"<!-- title: {name} manual -->\n<!-- description: How to install, use and run {name}: first steps, everyday tasks, "
            f"troubleshooting and questions. -->\n{markdown(text)}")


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(SRC / "assets", OUT / "assets")
    for section in SECTIONS:
        (OUT / section).mkdir(parents=True)
        guide = ROOT / f"documents/acxelin-{section}-how-it-works.pdf"
        if guide.exists():
            shutil.copy(guide, OUT / section / "guide.pdf")
    bom, excerpt = sample(OUT)
    tour, log = tls_tour()
    vpn = vpn_tour()
    from acxelin_readiness import __version__ as readiness_version
    from acxelin_tls import __version__ as tls_version
    from acxelin_vpn import __version__ as vpn_version
    fill = {"{{CBOM_EXCERPT}}": excerpt, "{{TLS_TOUR}}": html.escape(tour), "{{TLS_CAPTURE}}": tls_capture(f"{tour}\n{log}"), "{{TLS_LADDER}}": policy_ladder(),
            "{{READINESS_CAPTURE}}": readiness_capture(bom), "{{MOSCA}}": mosca(bom),
            "{{VPN_CAPTURE}}": vpn_capture(*vpn), "{{VPN_LOG}}": html.escape(vpn[0].strip()), "{{HOME_PROOF}}": home_proof(f"{tour}\n{log}", bom, vpn)}
    versions = {"tls": tls_version, "readiness": readiness_version, "vpn": vpn_version}
    mark = logo()
    pages = [(src.relative_to(SRC), src.read_text(encoding="utf-8")) for src in sorted(SRC.rglob("*.html"))]
    pages += [(Path(section, "manual.html"), manual(section)) for section in SECTIONS]
    for rel, text in pages:
        meta = re.match(r"<!-- title: (.*?) -->\n<!-- description: (.*?) -->\n", text)
        if not meta:
            sys.exit(f"{rel}: the first two lines must be the title and description comments")
        section = rel.parts[0] if len(rel.parts) > 1 else None
        root = "../" if section else ""
        name = SECTIONS[section][0] if section else "Acxelin Quantum"
        body = text[meta.end():]
        for key, value in fill.items():
            body = body.replace(key, value)
        body = body.replace("{{VERSION}}", versions.get(section, "")).replace("{root}", root).replace("<pre>", '<pre tabindex="0">').replace('<pre class="output">', '<pre class="output" tabindex="0">')
        body = body.replace('<div class="scroll">', '<div class="scroll" tabindex="0" role="region" aria-label="Table, scrolls sideways">')
        if "{{" in body:
            sys.exit(f"{rel}: unknown placeholder {re.search(PLACEHOLDER, body).group(0)}")
        footer = f"{name} is made by Acxelin Quantum. © 2026 Acxelin Quantum. All rights reserved." if section else \
            "Post-quantum security products, each installed and run on its own. © 2026 Acxelin Quantum. All rights reserved."
        values = {"title": meta.group(1), "description": meta.group(2), "root": root, "logo": mark, "footer": footer, "body": body,
                  "nav": nav(section, rel.name, root), "nav_label": name}
        page = LAYOUT
        for key, value in values.items():
            page = page.replace("{" + key + "}", value)
        (OUT / rel).parent.mkdir(parents=True, exist_ok=True)
        (OUT / rel).write_text(page, encoding="utf-8")
    print(f"built {OUT}")


if __name__ == "__main__":
    main()
