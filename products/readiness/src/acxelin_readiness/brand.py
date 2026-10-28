"""The Acxelin look for Acxelin Readiness's HTML: Acxelin's colours, typeface and logo, in one self-contained page."""
import base64
import functools
from html import escape as e
from pathlib import Path

from . import __version__

ASSETS = Path(__file__).parent / "assets"
TONE = {"critical": "bad", "high": "bad", "medium": "warn", "low": "mute", "ok": "ok"}

CSS = """
:root{--bg:#faf9f5;--panel:#fff;--sunken:#f4f1e8;--ink:#2e3c4e;--ink-2:#3f4c59;--mute:#636e78;--line:#e6e0d2;--accent:#ffbf00;--accent-text:#8a6100;
--ok:#26734d;--warn:#8a6100;--bad:#b3431f;--mono:ui-monospace,"Cascadia Mono","SF Mono",Consolas,monospace;
--sans:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif;--display:"Host Grotesk","Segoe UI",system-ui,sans-serif;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#141a22;--panel:#1b232d;--sunken:#212b37;--ink:#eef0f2;--ink-2:#c9ced5;--mute:#8e98a4;--line:#2d3947;
--accent-text:#ffcf4d;--ok:#5ccf8e;--warn:#f2c14e;--bad:#f2877b;color-scheme:dark}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
main{max-width:1180px;margin:0 auto;padding:28px 24px 64px}
@media (max-width:560px){main{padding:20px 16px 48px}}
.brandbar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-bottom:18px;margin-bottom:26px;border-bottom:1px solid var(--line)}
.brandbar svg{width:150px;height:auto;color:var(--ink);display:block}.brandbar small{color:var(--mute);font-size:12px}
.kicker{margin:0 0 6px;font-size:12px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--accent-text)}
h1{font:500 28px/1.2 var(--display);letter-spacing:-.015em;margin:0 0 6px;text-wrap:balance}
h2{font:500 19px/1.3 var(--display);margin:36px 0 12px}
.sub{color:var(--mute);margin:0 0 24px;font-size:15px;max-width:80ch}
code{font-family:var(--mono);font-size:12.5px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.stats div{display:grid;gap:4px;align-content:start;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px 18px}
.stats span{color:var(--mute);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.1em}
.stats b{font:500 32px/1.15 var(--display);letter-spacing:-.02em;font-variant-numeric:tabular-nums}.stats small{color:var(--ink-2);font-size:13px}
.ready{display:flex;gap:28px;flex-wrap:wrap;margin-top:18px;align-items:end}
.bar{height:8px;border-radius:4px;background:var(--sunken);border:1px solid var(--line);width:260px;margin-top:6px;overflow:hidden}.bar i{display:block;height:100%;background:var(--accent)}
.scroll{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;min-width:760px}
th{text-align:left;font-size:11px;color:var(--mute);font-weight:600;letter-spacing:.08em;text-transform:uppercase;background:var(--sunken);padding:10px 12px;border-bottom:1px solid var(--line)}
td{border-bottom:1px solid var(--line);padding:10px 12px;vertical-align:top}tr:last-child td{border-bottom:0}
.dim{color:var(--mute)}.w{max-width:380px;overflow-wrap:anywhere}.yes{font-weight:600}tr.ok{color:inherit}
.pill,.tag,.new{white-space:nowrap;display:inline-block;padding:1px 8px;border-radius:6px;font-size:11.5px;font-weight:600;background:color-mix(in srgb,currentColor 9%,transparent)}
.new{margin-left:6px;color:var(--ink-2)}.tag{color:var(--accent-text)}.tag.critical,.tag.high,.bad{color:var(--bad)}.tag.medium,.warn{color:var(--warn)}.ok{color:var(--ok)}.mute{color:var(--mute)}.pill.mute{color:var(--ink-2)}
details{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin-bottom:8px}summary{cursor:pointer}
summary:focus-visible,.scroll:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.occ{margin:8px 0 4px;font-size:12.5px}.occ div{padding:3px 0;color:var(--mute);overflow-wrap:anywhere}.occ code{color:var(--ink)}
.alert{display:grid;grid-template-columns:90px 1fr;gap:12px;padding:10px 14px;background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:8px}
.fix{margin:10px 0 6px;font-size:12.5px}.fix div{padding:3px 0}.fix code{background:var(--sunken);border-radius:4px;padding:0 4px}
svg.trend{color:var(--accent-text)}
footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--line);color:var(--mute);font-size:12px}
[hidden]{display:none!important}.tools{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:14px 0}
.tools label{display:grid;gap:4px;color:var(--ink-2);font-size:12px}.tools input,.tools select,.tools button{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;max-width:100%}
.tools button{background:var(--accent);color:#111;cursor:pointer}.tools [role=status]{color:var(--mute);font-size:12px}
a{color:var(--ink);text-underline-offset:3px}input:focus-visible,select:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--accent-text);outline-offset:2px}
@media print{.tools{display:none!important}body{background:#fff}.scroll,details,.stats div{break-inside:avoid}}
"""


def tier(t):
    return f"<span class='pill {TONE[t]}'>{e(t)}</span>" if t else ""


@functools.cache
def _assets():
    font = base64.b64encode((ASSETS / "host-grotesk.woff2").read_bytes()).decode()
    return font, (ASSETS / "acxelin-quantum.svg").read_text(encoding="utf-8")


def page(title, kicker, heading, sub, body, footer):
    font, logo = _assets()
    icon = base64.b64encode(logo.encode()).decode()
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml;base64,{icon}">
<title>{e(title)}</title><style>@font-face{{font-family:"Host Grotesk";font-weight:400 600;src:url(data:font/woff2;base64,{font}) format("woff2")}}{CSS}</style></head>
<body><main><div class="brandbar">{logo}<small>Acxelin Readiness {__version__}</small></div>
<p class="kicker">{e(kicker)}</p><h1>{e(heading)}</h1><p class="sub">{sub}</p>
<div class="tools"><button type="button" onclick="print()">Print or save as PDF</button></div>
{body}
<footer>{footer} · Acxelin Readiness by Acxelin Quantum</footer></main></body></html>"""
