"""Held-out evaluation: Readiness against labels it was never tuned on (protocol: products/readiness/heldout/PROTOCOL.md).

    python -m acxelin_readiness.heldout --benchmark PATH_TO/BenchmarkJava --out products/readiness/heldout/results/owasp-1.2.json

The OWASP Benchmark is GPL-2.0 and is read from a checkout; nothing from it is copied into this repository.
"""
import argparse
import csv
import json
import math
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from . import __version__, workspace

CATEGORIES = ("crypto", "hash")
RULES = {"strict": {"critical"}, "broad": {"critical", "high"}}
LAYOUTS = ("neutral", "original")
CODE = Path("src/main/java/org/owasp/benchmark/testcode")


def wilson(k, n, z=1.96):
    """The Wilson score interval for k successes in n trials, or None when n is 0."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def confusion(pairs):
    c = Counter((actual, predicted) for actual, predicted in pairs)
    return {"tp": c[(True, True)], "fn": c[(True, False)], "fp": c[(False, True)], "tn": c[(False, False)]}


def rate(k, n):
    return None if n == 0 else {"value": k / n, "ci95": list(wilson(k, n)), "k": k, "n": n}


def rates(c):
    n = sum(c.values())
    return {"precision": rate(c["tp"], c["tp"] + c["fp"]), "recall": rate(c["tp"], c["tp"] + c["fn"]), "accuracy": rate(c["tp"] + c["tn"], n),
            "f1": None if (2 * c["tp"] + c["fp"] + c["fn"]) == 0 else 2 * c["tp"] / (2 * c["tp"] + c["fp"] + c["fn"])}


def load_expected(path, categories=CATEGORIES):
    out = {}
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if row and not row[0].startswith("#") and row[1] in categories:
                out[row[0]] = (row[1], row[2].strip().lower() == "true")
    return out


def materialize(checkout, dest, names, layout):
    """Copy the named test files under `dest`; returns {test name: path relative to dest}."""
    if layout not in LAYOUTS:
        raise ValueError(f"layout must be one of {', '.join(LAYOUTS)}")
    files = {}
    for name in names:
        source = Path(checkout) / CODE / f"{name}.java"
        if not source.is_file():
            raise FileNotFoundError(f"{name}: {source} does not exist; is the checkout complete?")
        rel = Path("src") / f"case_{name[-5:]}.java" if layout == "neutral" else CODE / f"{name}.java"
        target = Path(dest) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        files[name] = rel.as_posix()
    return files


def predict(assets, files, rule):
    if rule not in RULES:
        raise ValueError(f"rule must be one of {', '.join(RULES)}")
    hit = {Path(str(path)).as_posix() for a in assets if a["tier"] in RULES[rule] for path, _ in a["locations"]}
    return {name: rel in hit for name, rel in files.items()}


def git(folder, *args):
    r = subprocess.run(["git", "-C", str(folder), *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def evaluate(benchmark, layouts=LAYOUTS, categories=CATEGORIES):
    benchmark = Path(benchmark)
    expected = load_expected(benchmark / "expectedresults-1.2.csv", categories)
    out = {"protocol": "products/readiness/heldout/PROTOCOL.md", "readiness_version": __version__, "readiness_commit": git(Path(__file__).resolve().parent, "rev-parse", "HEAD"),
           "benchmark": "OWASP Benchmark for Java v1.2", "benchmark_commit": git(benchmark, "rev-parse", "HEAD"), "layouts": list(layouts), "rules": {k: sorted(v) for k, v in RULES.items()},
           "population": dict(Counter(c for c, _ in expected.values())), "results": {}}
    for layout in layouts:
        with tempfile.TemporaryDirectory() as d:
            files = materialize(benchmark, d, sorted(expected), layout)
            assessment = workspace.scan(d)
        out["results"][layout] = {"coverage": assessment["summary"].get("coverage"), "files_scanned": len(files)}
        for rule in RULES:
            predicted = predict(assessment["assets"], files, rule)
            block = {}
            groups = {"overall": sorted(expected)} | {c: sorted(n for n in expected if expected[n][0] == c) for c in categories}
            for group, names in groups.items():
                c = confusion((expected[n][1], predicted[n]) for n in names)
                block[group] = {"confusion": c, "rates": rates(c)}
                if group == "overall":
                    block[group]["missed"] = [n for n in names if expected[n][1] and not predicted[n]]  # named so a reader can open them; nothing is tuned from them
                    block[group]["false_alarms"] = [n for n in names if not expected[n][1] and predicted[n]]
            out["results"][layout][rule] = block
    return out


def algorithm_source(benchmark, result, layout="neutral", rule="strict"):
    """After the fact, descriptive only: how many tests read the algorithm name from benchmark.properties (a static scan of one file cannot know it) and how many of the
    errors are among them. Not one of the registered rates."""
    names = {n for group in ("missed", "false_alarms") for n in result["results"][layout][rule]["overall"][group]}
    expected = load_expected(Path(benchmark) / "expectedresults-1.2.csv")
    counts = {"property": [0, 0], "literal": [0, 0]}  # [tests, errors]
    for name in expected:
        text = (Path(benchmark) / CODE / f"{name}.java").read_text(encoding="utf-8", errors="replace")
        kind = "property" if "getProperty" in text and "benchmark.properties" in text else "literal"
        counts[kind][0] += 1
        counts[kind][1] += name in names
    return {k: {"tests": t, "errors": e} for k, (t, e) in counts.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benchmark", required=True, help="a checkout of OWASP-Benchmark/BenchmarkJava")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    result = evaluate(a.benchmark)
    result["after_the_fact"] = {"algorithm_source (neutral, strict)": algorithm_source(a.benchmark, result)}
    Path(a.out).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    for layout, block in result["results"].items():
        for rule in RULES:
            o = block[rule]["overall"]
            r = o["rates"]
            show = lambda m: "n/a" if m is None else f"{m['value']:.3f} [{m['ci95'][0]:.3f}, {m['ci95'][1]:.3f}]"
            print(f"{layout:9} {rule:7} tp={o['confusion']['tp']} fp={o['confusion']['fp']} fn={o['confusion']['fn']} tn={o['confusion']['tn']}  precision {show(r['precision'])}  recall {show(r['recall'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
