"""The scan, start to finish: detectors report everything they see, verification keeps what the evidence supports, ranking orders what to migrate first."""
import json
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import verify, rank, remedy
from .crawler import CodeCrawler
from .detectors.lexer import LANGS
from .detectors import iter_files, MAX_BYTES, source, config, artifacts, volumes, deps, tls, binary, implementations, params, capture, carried_hashes, oversized, snapshot, pyflow, patterns

DETECTORS = ("source", "implementations", "config", "artifacts", "volumes", "binary")




@dataclass
class Detected:
    detections: list
    artifacts: list
    libraries: list
    files: dict
    notes: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    crawler: CodeCrawler = field(default_factory=CodeCrawler)
    patterns: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)


def coverage(root, scope, oversized_files, unparsed_python):
    """Of the source and configuration files, how many were fully analysed: none over the read limit, none left unparsed."""
    files = sum(1 for p in iter_files(root, scope, max_bytes=float("inf")) if p.suffix.lower() in LANGS or config.is_config(p))
    not_read = {k: v for k, v in (("over 2 MB", oversized_files), ("Python that could not be parsed", unparsed_python)) if v}
    read = max(files - sum(not_read.values()), 0)
    return {"files": files, "read": read, "not_read": not_read, "percent": round(100 * read / files) if files else None}


def detect(root, scope=False, tls_targets=(), ssh_targets=(), captures=(), cache=None):
    """Every detector reports everything it sees; nothing is filtered before verification."""
    h = Detected([], [], [], dict.fromkeys(DETECTORS, 0), crawler=CodeCrawler(cache))
    found = {}

    def observe(path, tree):
        h.crawler.observe(path, tree)
        try:
            found[path] = pyflow.facts(tree)
        except RecursionError:
            pass
    unparsed = []
    on_code = lambda path, text, lang, parts: h.patterns.extend(patterns.scan_text(path, text, lang, parts))
    s, h.files["source"] = source.scan(root, scope, unparsed=unparsed, on_python=observe, on_source=h.crawler.observe_source,
                                       parse_python=h.crawler.parse_python, parse_index=h.crawler.peek_python, on_code=on_code)
    h.detections += s
    if unparsed:
        for path in unparsed:
            h.crawler.gap("Python (syntax errors)", path)
        h.notes.append(f"{len(unparsed)} Python file(s) could not be parsed by this Python ({sys.version.split()[0]}): newer syntax, nesting too deep "
                       f"to analyse, or not Python 3. Only their strings and comments were read, so calls in them were missed; run Acxelin Readiness on the "
                       f"project's Python or newer (the Docker image and GitHub Action use 3.14): "
                       + ", ".join(unparsed[:5]) + (" ..." if len(unparsed) > 5 else ""))
    big = oversized(root, scope)
    if big:
        for path in big:
            h.crawler.gap("Source exceeds 2 MB read limit", path)
        h.notes.append(f"{len(big)} source file(s) over {MAX_BYTES // 1_000_000} MB not read (usually generated or minified code): "
                       + ", ".join(big[:5]) + (" ..." if len(big) > 5 else ""))
    h.coverage = coverage(root, scope, len(big), len(unparsed))
    h.detections += params.scan(root, scope)
    h.patterns = patterns.ordered(h.patterns)
    s, h.files["implementations"] = implementations.scan(root, scope)
    h.detections += s
    s, h.files["config"] = config.scan(root, scope)
    h.detections += s
    h.artifacts, s, h.files["artifacts"] = artifacts.scan(root, scope)
    h.detections += s
    s, h.files["volumes"] = volumes.scan(root, scope)
    h.detections += s
    s, h.libraries, h.files["binary"] = binary.scan(root, scope)
    h.detections += s
    h.libraries = deps.scan(root, scope) + h.libraries
    for t in tls_targets:
        s, a, n, ep = tls.probe(t)
        h.detections += s
        h.artifacts += a
        h.notes += n
        h.endpoints.append(ep)
    for t in ssh_targets:
        s, _, n, ep = tls.probe_ssh(t)
        h.detections += s
        h.notes += n
        h.endpoints.append(ep)
    for f in captures:
        try:
            s, eps, n = capture.scan(f)
        except (OSError, ValueError) as err:
            h.notes.append(f"capture {f}: not read ({err})")
            continue
        h.detections += s
        h.endpoints += eps
        h.notes += n
    h.detections += carried_hashes(h.detections)
    pyflow.mark(h.detections, found)
    return h


@dataclass
class Result:
    project: str
    detections: list
    assets: list
    artifacts: list
    libraries: list
    alerts: list
    readiness: dict
    stats: dict
    notes: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    baseline: str = ""
    compliance: dict = field(default_factory=dict)
    relationships: dict = field(default_factory=dict)
    patterns: list = field(default_factory=list)


def load_baseline(path):
    bom = json.loads(Path(path).read_text(encoding="utf-8"))
    seen = set()
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        for o in (c.get("evidence") or {}).get("occurrences", []):
            seen.add((c.get("name"), o.get("location", "").split("!")[0]))
    return seen


def run(root, project, tls_targets=(), horizon=None, threshold=0.6, scope=False, ssh_targets=(), baseline=None, captures=(), cache=None):
    t0 = time.time()
    scope = snapshot(root, scope)
    horizon = horizon or rank.Horizon()
    h = detect(root, scope, tls_targets, ssh_targets, captures, cache)
    lines = verify.Lines(root)
    references = rank.follow_references(root, h.artifacts, h.detections, scope)
    detections = verify.verify(h.detections, threshold, lines)
    looks = rank.second_look(detections, lines, threshold)
    held = rank.recognise(detections, lines)
    verify.settle(detections)
    stores = rank.trust_stores(h.artifacts)
    for s in detections:
        if s.file in stores:
            s.context.add("trust-store")
    assets = rank.lead(verify.assets(detections), horizon)
    for a in assets:
        a.remedies = remedy.remedies(a)
    if baseline:
        seen = load_baseline(baseline)
        for a in assets:
            a.new_files = sorted({s.file.split("!")[0] for s in a.detections if (a.variant, s.file.split("!")[0]) not in seen})
    relationships = h.crawler.finish(assets)
    al = rank.alerts(h.artifacts, h.libraries, detections, stores)
    found = [p for p in h.patterns if not verify.ignored(lines(p.file), p.line)]
    verdicts = Counter(s.verdict for s in detections)
    stats = {"files_code": h.files["source"], "files_config": h.files["config"], "files_artifacts": h.files["artifacts"], "files_binary": h.files["binary"],
             "libraries": len(h.libraries), "endpoints": len(h.endpoints), "raw_detections": len(h.detections),
             **{v: verdicts[v] for v in ("accepted", "quarantined", "rejected", "suppressed")},
             "promoted_on_second_look": sum(looks.values()), "patterns": len(found), "second_look": looks, "held_as_formats": held, "references_followed": references,
             "coverage": h.coverage, "seconds": round(time.time() - t0, 2), "horizon": vars(horizon) | {"years_to_crqc": horizon.z}}
    return Result(project, detections, assets, h.artifacts, h.libraries, al, rank.readiness(assets), stats, h.notes, h.endpoints, str(baseline or ""), relationships=relationships,
                  patterns=found)
