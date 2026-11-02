"""Customer-facing text and code never assume a person's gender: people are 'they', and named examples are referred to by name."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORDS = re.compile(r"\b(she|her|hers|herself|he|him|his|himself)\b", re.I)
PLACES = ["core/src", "products/tls/src", "products/vpn/src", "products/readiness/src", "products/tls/docs", "products/vpn/docs",
          "products/readiness/docs", "website", "documents", "products/tls/config", "products/vpn/config", "products/readiness/config"]
FILES = ["README.md", "core/CHANGELOG.md"] + [f"products/{p}/{f}" for p in ("tls", "vpn", "readiness") for f in ("README.md", "CHANGELOG.md")]
SUFFIXES = {".py", ".md", ".html", ".toml", ".js"}


def test_no_gendered_pronouns_for_people():
    found = []
    for p in [ROOT / f for f in FILES] + [p for place in PLACES for p in (ROOT / place).rglob("*")]:
        if p.suffix not in SUFFIXES or "node_modules" in p.parts or not p.is_file():
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if WORDS.search(line):
                found.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()[:120]}")
    assert not found, "use they/them, or the person's name:\n" + "\n".join(found)
