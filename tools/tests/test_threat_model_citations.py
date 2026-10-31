"""Every test a threat model cites exists: a file by name or path, and a function when the citation names one."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = [p for d in ("core/tests", "tools/tests", *(f"products/{x}/tests" for x in ("readiness", "tls", "vpn"))) for p in (ROOT / d).rglob("test_*.py")]
CITE = re.compile(r"`((?:[\w./-]*/)?test_\w+(?:\.py)?(?:::\w+)?)`")


def citations():
    for doc in sorted(ROOT.glob("products/*/docs/threat-model.md")):
        for ref in CITE.findall(doc.read_text(encoding="utf-8")):
            yield doc.relative_to(ROOT).as_posix(), ref


def test_every_cited_test_exists():
    missing = []
    for doc, ref in citations():
        path, _, func = ref.partition("::")
        stem = Path(path).stem
        files = [p for p in TESTS if p.stem == stem and (not path.endswith(".py") or p.as_posix().endswith(path))]
        if not files or (func and not any(re.search(rf"def {func}\b", f.read_text(encoding="utf-8")) for f in files)):
            missing.append(f"{doc}: {ref}")
    assert not missing, "cited tests that do not exist:\n" + "\n".join(missing)


def test_the_check_sees_citations():
    assert sum(1 for _ in citations()) >= 10
