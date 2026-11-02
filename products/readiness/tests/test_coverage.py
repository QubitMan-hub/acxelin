"""What Readiness tracks, as one list the website, the console and the manual share."""
import re
from pathlib import Path

from acxelin_readiness import console as rc
from acxelin_readiness import coverage
from acxelin_readiness.catalog import CATALOG

MANUAL = Path(__file__).resolve().parents[1] / "docs" / "manual.md"


def test_the_sources_are_the_manuals_table_word_for_word():
    table = MANUAL.read_text(encoding="utf-8").split("### What it reads", 1)[1].split("###", 1)[0]
    rows = [[c.strip() for c in line.strip().strip("|").split("|")] for line in table.splitlines() if line.startswith("|")][2:]
    assert [(name, what) for name, what in rows] == [(s["name"], s["what"]) for s in coverage.SOURCES]


def test_every_algorithm_and_kind_is_described():
    data = coverage.summary()
    assert [a["name"] for a in data["algorithms"]] == list(CATALOG)
    assert {a["primitive"] for a in data["algorithms"]} <= {p for p, _ in coverage.PRIMITIVES}
    assert {a["threat"] for a in data["algorithms"]} <= set(coverage.THREATS)
    assert [k["title"] for k in data["kinds"]] == ["Algorithms", "Protocols", "Certificates", "Keys and key material", "Libraries"]
    assert all(re.fullmatch(r"[A-Z][^`]*", s["name"]) for s in data["sources"])


def test_the_console_serves_it_after_sign_in_only(tmp_path):
    app = rc.build(tmp_path / "state")
    status, payload = app.routes[("GET", "/api/coverage")]({})
    assert status == 200 and len(payload["algorithms"]) == len(CATALOG) and len(payload["sources"]) == len(coverage.SOURCES)
