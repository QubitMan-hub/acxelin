"""Every test a threat model or the review pack cites exists: a file by name or path, and a function when the citation names one."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = [p for d in ("core/tests", "tools/tests", *(f"products/{x}/tests" for x in ("readiness", "tls", "vpn"))) for p in (ROOT / d).rglob("test_*.py")]
CITE = re.compile(r"`((?:[\w./-]*/)?test_\w+(?:\.py)?(?:::\w+)*)`")
ANY = re.compile(r"`([^`]*(?:::|\btest_)[^`]*)`")


def citations():
    for doc in documents():
        for ref in CITE.findall(doc.read_text(encoding="utf-8")):
            yield doc.relative_to(ROOT).as_posix(), ref


def documents():
    return sorted([*ROOT.glob("products/*/docs/threat-model.md"), *ROOT.glob("review/*.md")])


def test_every_cited_test_exists():
    missing = []
    for doc, ref in citations():
        path, _, func = ref.partition("::")
        func = func.rpartition("::")[2]
        stem = Path(path).stem
        files = [p for p in TESTS if p.stem == stem and (not path.endswith(".py") or p.as_posix().endswith(path))]
        if not files or (func and not any(re.search(rf"def {func}\b", f.read_text(encoding="utf-8")) for f in files)):
            missing.append(f"{doc}: {ref}")
    assert not missing, "cited tests that do not exist:\n" + "\n".join(missing)


def test_the_check_sees_citations():
    assert sum(1 for _ in citations()) >= 10


def test_a_citation_the_check_cannot_read_is_an_error_not_a_skip():
    unreadable = []
    for doc in documents():
        for token in ANY.findall(doc.read_text(encoding="utf-8")):
            if "::" in token and not CITE.fullmatch(f"`{token}`"):
                unreadable.append(f"{doc.relative_to(ROOT).as_posix()}: {token}")
    assert not unreadable, "cited in a form the check cannot resolve:\n" + "\n".join(unreadable)
