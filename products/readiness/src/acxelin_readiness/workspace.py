"""A project workspace: scans with limits and cancellation, summaries kept per project, finding tracking, and migration evidence."""
import json
import base64
import zlib
import time
from collections import Counter
from pathlib import Path

from acxelin_core.files import locked, write

from . import owners
from .detectors import is_test


class ScanStopped(ValueError):
    pass


STATUSES = ('open', 'planned', 'in_progress', 'fixed', 'exception')


POINTS = {"ok": 100, "low": 75, "medium": 50, "high": 25, "critical": 0}
SEEN = {"call": "in code", "constant": "in code", "identifier": "in code", "config": "configured", "artifact": "configured",
        "import": "supported", "string": "supported", "binary": "supported"}
ORDER = ("negotiated", "offered", "in code", "configured", "supported")
NEEDS = {"RSA": "key_size", "DSA": "key_size", "DH": "key_size", "ECC": "curve", "ECDSA": "curve", "ECDH": "curve", "HMAC": "hash", "PBKDF2": "hash"}


def evidence_view(a):
    """How a finding was seen (strongest first), how sure the scan is, and the inputs it did not observe."""
    seen = set()
    for s in a.detections:
        if s.evidence == "live":
            seen.add("negotiated" if s.params.get("negotiated") or s.params.get("observed") else "offered")
        else:
            seen.add(SEEN.get(s.evidence, "supported"))
    if a.declared:
        seen = (seen - {"in code"}) | {"supported"}  # listed in a table of supported algorithms, not called
    if seen - {"supported"}:
        seen.discard("supported")  # calling, configuring or negotiating it already says it is supported
    missing = [{"key_size": "key size", "curve": "curve", "hash": "hash"}[NEEDS[a.algo]]] if a.algo in NEEDS and not a.params.get(NEEDS[a.algo]) else []
    if a.algo == "AES":
        missing += [n for k, n in (("key_size", "key size"), ("mode", "mode")) if not a.params.get(k)]
    if seen <= {"supported"}:
        missing.append("observed use")
    level = "high" if a.confidence >= 0.85 else "medium" if a.confidence >= 0.6 else "low"
    return {"seen": [x for x in ORDER if x in seen], "missing": missing, "confidence_level": level}


def score(assets):
    """0-100: the average priority of the listed (not test-only) findings; None when there is nothing to score."""
    listed = [POINTS[a["tier"]] for a in assets if not a["test_only"]]
    return round(sum(listed) / len(listed)) if listed else None


def scan(path, out=None, history=None, progress=None, exclude=(), cancel=None, max_files=50000, max_bytes=512_000_000, timeout=300, cache=None, name=None):
    notify = progress or (lambda stage: None)
    notify("Preparing project")
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError("Choose an existing project folder")
    from . import pipeline as pack, report
    notify("Analyzing source and cryptography")
    from .detectors import Scope, ScanLimitError
    deadline = time.monotonic() + timeout
    def checkpoint():
        if cancel and cancel.is_set():
            raise ScanStopped('Scan cancelled; the previous completed assessment is preserved')
        if time.monotonic() > deadline:
            raise ScanStopped('Scan time limit reached; narrow the project folder')
    excluded = []
    for destination in (out, history, *exclude):
        if destination:
            try:
                excluded.append(Path(destination).resolve().relative_to(root).as_posix())
            except ValueError:
                pass
    try:
        result = pack.run(root, name or root.name, scope=Scope(exclude=tuple(excluded), checkpoint=checkpoint, max_files=max_files, max_total_bytes=max_bytes), cache=cache)
    except ScanLimitError as error:
        raise ScanStopped(str(error)) from None
    checkpoint()
    notify("Preparing migration results")
    # Unified results deliberately omit source snippets and literal values. No code is uploaded/executed.
    for sighting in result.detections:
        sighting.snippet = ""
        sighting.params.pop("literal", None)
    for pattern in getattr(result, "patterns", []):
        pattern.snippet = ""
    assets = [{"name": a.variant, "algorithm": a.algo, "tier": a.tier, "why": a.why, "action": a.action,
               "confidence": a.confidence, "test_only": a.test_only, "declared": a.declared,
               "uncertainty": "Algorithm inferred from names or literals; confirm the implementation and dynamic dispatch" if all(s.evidence in {"identifier", "import", "string"} for s in a.detections) else "Static evidence; runtime use is not established",
               "locations": sorted({(s.file, s.line) for s in a.detections}, key=lambda fl: (is_test(fl[0]), fl)), "impact": a.params.get("code_impact"), "hybrid_context": a.params.get("hybrid_context", [])}
              | evidence_view(a) for a in result.assets]
    patterns = [{k: v for k, v in p.as_dict().items() if k != "snippet"} for p in getattr(result, "patterns", [])][:500]
    graph = result.relationships
    assessment = {"project": name or root.name, "finished": time.time(), "assets": assets, "patterns": patterns, "notes": result.notes,
                  "summary": {"crypto_assets": len(assets), "priorities": dict(Counter(a["tier"] for a in assets)), "score": score(assets),
                              "coverage": result.stats["coverage"].get("percent"), "coverage_detail": {k: v for k, v in result.stats["coverage"].items() if k != "percent"},
                              "python_files": graph.get("languages", {}).get("Python", 0), "languages": graph.get("languages", {}), "coverage_gaps": graph.get("skipped", {}),
                              "migration_candidates": sum(a["tier"] in {"critical", "high"} and not a["test_only"] and not a["declared"] for a in assets),
                              "security_patterns": sum(p["severity"] in {"critical", "high"} for p in patterns), "functions": sum(s["kind"] == "function" for s in graph["symbols"]),
                              "resolved_calls": sum(bool(c["target"]) for c in graph["calls"]), "calls": len(graph["calls"]),
                              "libraries": result.stats["libraries"], "seconds": result.stats["seconds"], "graph_limited": graph["limited"], "truncated_files": len(graph.get("truncated_files", {})), "incremental": graph.get("incremental", {})},
                  "evidence_boundary": "Static source evidence is not runtime protection or proof of business ownership.",
                  "codeowners": owners.codeowners(root), "relationships": graph}
    if out:
        folder = Path(out)
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        report.write_results(folder, name or root.name, result)
    if history:
        try:
            append_history(history, assessment)
        except (OSError, ValueError):
            assessment["notes"].append("History could not be saved; check the configured history file. Scan evidence remains available.")
    if out:
        write(folder / "assessment.json", json.dumps(assessment, indent=2).encode(), secret=True)
    notify("Complete")
    return assessment


VERBS = ("Switch", "Rotate", "Remove", "Re-sign", "Use", "Replace", "Enable", "Keep", "Move", "Reissue", "Shorten", "Plan", "TLS")


def outlook(result):
    """What can happen to this repository if nothing changes, and what to do first: rules over its findings, not forecasts."""
    from .catalog import CATALOG, GROVER, LEGACY, SHOR
    from .rank import TIERS
    listed = [a for a in result["assets"] if not a["test_only"]]
    names = lambda rows: sorted({a["name"] for a in rows})
    threat = lambda a: CATALOG[a["algorithm"]].threat if a["algorithm"] in CATALOG else None
    primitive = lambda a: CATALOG[a["algorithm"]].primitive if a["algorithm"] in CATALOG else None
    broken = [a for a in listed if a["tier"] == "critical" or threat(a) == LEGACY and a["tier"] != "ok"]
    later = [a for a in listed if a not in broken and threat(a) == SHOR and a["tier"] != "ok"]
    recordable = [a for a in later if primitive(a) != "signature"]
    forgeable = [a for a in later if primitive(a) == "signature"]
    weakened = [a for a in listed if threat(a) == GROVER and a["tier"] == "low"]
    t = lambda a: a.get("tracking") or {}
    still = [a for a in listed if t(a).get("still_found")]
    overdue = [a for a in listed if t(a).get("overdue") and t(a).get("status") not in ("fixed", "exception")]
    expired = [a for a in listed if t(a).get("expired")]
    unowned = [a for a in listed if a["tier"] != "ok" and not t(a).get("owner") and not a.get("owner_hint")
               and not (t(a).get("status") == "fixed" and not t(a).get("still_found"))]
    s, cd = result.get("summary", {}), result.get("summary", {}).get("coverage_detail") or {}
    unread = (cd.get("files", 0) - cd.get("read", 0)) if s.get("coverage") is not None and s["coverage"] < 100 else 0
    risks = [
        (broken, "Broken today: these can be attacked now, with no quantum computer (collisions, brute force or a disallowed protocol)."),
        (recordable, "Recordable now, readable later: what they protect can be recorded today and decrypted once a large enough quantum computer exists."),
        (forgeable, "Forgeable later: a large enough quantum computer could forge these signatures, so whatever trusts them (code, tokens, certificates) could be impersonated."),
        (later, "Deadline: NIST IR 8547 (draft) deprecates quantum-vulnerable public-key algorithms at 112-bit strength after 2030 and disallows them after 2035."),
        (weakened, "Weakened by quantum search: Grover's algorithm halves their effective strength; fine for most data, short for long-lived secrets."),
        (still, "Marked fixed, still found: the fix has not reached the code that was scanned."),
        (overdue, "Overdue: each of these is past its due date."),
        (expired, "Accepted risk expired: the reason given no longer covers these."),
    ]
    out = {"risks": [{"targets": names(rows), "text": text} for rows, text in risks if rows], "actions": []}
    if unread:
        out["risks"].append({"targets": [], "text": f"Not analysed: {unread} files were not analysed, so anything in them is unknown."})
    groups = {}
    for a in sorted(listed, key=lambda a: (TIERS.index(a["tier"]) if a["tier"] in TIERS else 9, a["name"])):
        if a["tier"] != "ok" and a.get("action"):
            groups.setdefault(a["action"], []).append(a)
    for action, rows in list(groups.items())[:8]:
        out["actions"].append({"targets": names(rows), "text": action if action.startswith(VERBS) else f"Replace with {action}"})
    for rows, text in ((still, "Find out why the fix did not land: scan the branch it was made on, then mark it fixed again."),
                       (overdue + expired, "Set a new due date, or renew the accepted risk with a current reason and end date."),
                       (unowned, "Assign an owner to each: on the finding itself, or from CODEOWNERS or a CMDB export.")):
        if rows:
            out["actions"].append({"targets": names(rows), "text": text})
    if unread:
        out["actions"].append({"targets": [], "text": "Bring the unread files into scope: exclude generated files over 2 MB, and scan with a newer Python for syntax this one cannot parse."})
    if not out["actions"]:
        out["actions"].append({"targets": [], "text": "Nothing to change now. Scan again after the code changes."})
    return out


def imported(path, name):
    """An assessment from another tool's CycloneDX CBOM. Priorities come from its own acxelin:* properties when present, else
    from the algorithm alone; components whose names this catalogue does not recognise are counted, not rated."""
    from . import inventory
    system = inventory.load(path, set())
    assets = [{"name": a["name"], "algorithm": a["algo"], "tier": a["tier"], "action": a["recommendation"],
               "why": "Priority estimated from the algorithm: the CBOM gives none" if a["estimated"] else "",
               "confidence": None, "test_only": False, "declared": False,
               "uncertainty": f"Imported from {system['tool']}; not verified by Acxelin Readiness",
               "locations": sorted({(str(o.get("location", "")), int(o.get("line") or 0)) for o in a["occurrences"] if isinstance(o, dict)}),
               "impact": None, "hybrid_context": [], "seen": ["imported"], "missing": [], "confidence_level": None}
              for a in system["assets"] if a["tier"]]
    unrated = sum(not a["tier"] for a in system["assets"])
    notes = [f"Imported from {system['tool']}: {len(assets)} algorithm(s) rated"] + \
            ([f"{unrated} algorithm name(s) not recognised and not rated"] if unrated else [])
    return {"project": name, "finished": time.time(), "assets": assets, "patterns": [], "notes": ["; ".join(notes) + "."],
            "summary": {"crypto_assets": len(assets), "priorities": dict(Counter(a["tier"] for a in assets)), "score": score(assets),
                        "imported_from": system["tool"]},
            "evidence_boundary": "Another tool's CBOM, read as given: its findings are not re-checked.", "relationships": {}}


def read_history(path):
    f = Path(path)
    if not f.exists():
        return []
    with f.open("rb") as source:
        raw = source.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Scan history exceeds the 1 MB limit")
    rows = json.loads(raw)
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("project"), str)
                                        or type(row.get("finished")) not in {int, float} or not 0 <= row["finished"] <= 2**53 or not isinstance(row.get("summary"), dict) for row in rows):
        raise ValueError("Scan history must contain project/time/summary records")
    return [{k: row[k] for k in ("project", "finished", "summary")} for row in rows[-100:]]


def append_history(path, assessment):
    """Persist bounded summaries under the same shared lock used for atomic CA state updates."""
    f = Path(path).absolute()
    f.parent.mkdir(parents=True, exist_ok=True)
    with locked(f.parent, "." + f.name + ".lock"):
        rows = read_history(f)[-99:] + [{k: assessment[k] for k in ("project", "finished", "summary")}]
        write(f, json.dumps(rows, indent=2).encode(), secret=True)


def finding_id(asset):
    """Ignore line shifts, but never equate findings from different files or algorithms."""
    import hashlib
    identity = [asset['algorithm'], asset['name'], sorted({p for p, _ in asset['locations']}), asset['test_only'], asset['declared']]
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


class ProjectStore:
    """Bounded single-administrator workspace. Shared locks preserve competing updates."""
    LIMIT = 16_000_000
    FINDINGS = 5000
    GRAPH_LIMIT = 64_000_000

    def __init__(self, path):
        self.path = Path(path).absolute()

    @staticmethod
    def key(path):
        import hashlib
        import os
        return hashlib.sha256(os.path.normcase(str(Path(path).resolve())).encode()).hexdigest()

    def read(self):
        if not self.path.exists():
            return {'version': 2, 'registrations': {}, 'projects': {}}
        with self.path.open('rb') as source:
            raw = source.read(self.LIMIT + 1)
        if len(raw) > self.LIMIT:
            raise ValueError('Project workspace exceeds 16 MB; choose a new workspace file')
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get('version') not in (1, 2) or not isinstance(data.get('registrations'), dict) or not isinstance(data.get('projects'), dict):
            raise ValueError('Invalid project workspace; preserve it and choose a new workspace file')
        return data

    def update(self, action):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with locked(self.path.parent, '.' + self.path.name + '.lock'):
            data = self.read()
            result = action(data)
            data['version'] = 2
            raw = json.dumps(data).encode()
            if len(raw) > self.LIMIT:
                raise ValueError('Project workspace exceeds 16 MB; choose a new workspace file')
            write(self.path, raw, secret=True)
            return result

    def register(self, parent, name):
        def change(data):
            names = data['registrations'].setdefault(self.key(parent), [])
            if name not in names:
                if len(names) >= 200:
                    raise ValueError('Workspace supports at most 200 registered repositories')
                names.append(name)
        self.update(change)

    def save(self, root, assessment):
        import copy
        def change(data):
            key = self.key(root)
            previous = data['projects'].get(key, {})
            tracking = previous.get('tracking', {})
            old = {a['id']: a for a in previous.get('assessment', {}).get('assets', [])}
            current = copy.deepcopy(assessment)
            for asset in current['assets']:
                asset['id'] = finding_id(asset)
            ids = {a['id'] for a in current['assets']}
            missing = {a['id']: a for a in previous.get('missing', [])}
            missing.update({k: a for k, a in old.items() if k not in ids})
            missing = {k: a for k, a in missing.items() if k not in ids}
            if len(ids) > self.FINDINGS:
                raise ValueError(f'Workspace supports at most {self.FINDINGS} findings per project; narrow the repository scope')
            keep = self.FINDINGS - len(ids)  # findings no longer observed are retired oldest first, with their tracking
            missing = dict(list(missing.items())[-keep:]) if keep else {}
            tracking = {k: v for k, v in tracking.items() if k in ids or k in missing}
            current['comparison'] = {'baseline': bool(previous), 'new': len(ids - old.keys()), 'persisting': len(ids & old.keys()),
                                     'not_observed': len(old.keys() - ids), 'previous_finished': previous.get('assessment', {}).get('finished')}
            history = previous.get('history', [])[-29:] + [{k: current[k] for k in ('project', 'finished', 'summary', 'comparison')}]
            graph = json.dumps(current.pop('relationships', {}), separators=(',', ':')).encode()
            if len(graph) > self.GRAPH_LIMIT:
                raise ValueError('Relationship graph exceeds 64 MB; narrow the repository scope')
            packed = base64.b64encode(zlib.compress(graph)).decode('ascii')
            data['projects'][key] = {'graph_zlib': packed, 'assessment': current, 'tracking': tracking, 'missing': list(missing.values()), 'history': history}
            return self.view(data['projects'][key])
        return self.update(change)

    @staticmethod
    def view(project):
        import copy
        result = copy.deepcopy(project['assessment'])
        if 'graph_zlib' in project:
            try:
                decoder = zlib.decompressobj()
                raw = decoder.decompress(base64.b64decode(project['graph_zlib'], validate=True), ProjectStore.GRAPH_LIMIT + 1)
                if len(raw) > ProjectStore.GRAPH_LIMIT or not decoder.eof or decoder.unused_data:
                    raise ValueError('Invalid or oversized stored relationship graph')
                graph = json.loads(raw)
                if not isinstance(graph, dict):
                    raise ValueError('Invalid stored relationship graph')
                result['relationships'] = graph
            except (zlib.error, ValueError, TypeError, RecursionError) as error:
                raise ValueError('Stored relationship graph is damaged or exceeds its size limit') from error
        result['history'] = copy.deepcopy(project.get('history', []))
        result['not_observed'] = copy.deepcopy(project.get('missing', []))
        cmdb, repo = project.get('owners', []), result.get('codeowners', [])
        result['owner_rules'] = len(cmdb)
        for asset in result['assets'] + result['not_observed']:
            asset['owner_hint'] = owners.suggest(cmdb, repo, sorted({f for f, _ in asset['locations']}))
        for asset in result['assets'] + result['not_observed']:
            asset['tracking'] = copy.deepcopy(project.get('tracking', {}).get(asset['id'], {'owner': '', 'due': '', 'status': 'open', 'reason': '', 'until': ''}))
            tracking = asset['tracking']
            today = time.strftime('%Y-%m-%d', time.gmtime())
            tracking['expired'] = tracking['status'] == 'exception' and tracking.get('until', '') < today
            tracking['overdue'] = bool(tracking.get('due') and tracking['due'] < today)
            tracking['log'] = tracking.get('log', [])
            tracking['still_found'] = False
        for asset in result['assets']:  # marked fixed, yet a scan after that still found it
            t = asset['tracking']
            t['still_found'] = t['status'] == 'fixed' and t.get('updated', 0) < result['finished']
        from .catalog import CATALOG
        for asset in result['assets'] + result['not_observed']:  # broken today, breakable by Shor, weakened by Grover, or safe
            c = CATALOG.get(asset.get('algorithm'))
            asset['threat'] = c.threat if c else None
        result['outlook'] = outlook(result)
        return result

    def assessment(self, root):
        record = self.read()['projects'].get(self.key(root))
        return self.view(record) if record else None

    def set_owners(self, root, rules):
        def change(data):
            project = data['projects'].get(self.key(root))
            if not project:
                raise ValueError('Scan this repository first')
            project['owners'] = [list(r) for r in rules]
            return len(rules)
        return self.update(change)

    def track(self, root, body):
        import datetime as dt
        if not isinstance(body.get('finding'), str):
            raise ValueError('Choose a finding from a completed assessment')
        fields = {k: body.get(k, '') for k in ('owner', 'due', 'status', 'reason', 'until')}
        if any(not isinstance(v, str) for v in fields.values()) or len(fields['owner']) > 120 or len(fields['reason']) > 1000:
            raise ValueError('Owner must be at most 120 characters and rationale at most 1000')
        if fields['status'] not in STATUSES:
            raise ValueError('Choose open, planned, in_progress, fixed or exception')
        for field in ('due', 'until'):
            if fields[field] and (len(fields[field]) != 10 or dt.date.fromisoformat(fields[field]).isoformat() != fields[field]):
                raise ValueError('Dates must use YYYY-MM-DD')
        if fields['status'] == 'exception' and (not fields['reason'].strip() or not fields['until'] or fields['until'] < dt.datetime.now(dt.timezone.utc).date().isoformat()):
            raise ValueError('An exception needs a rationale and a current or future expiry date')
        def change(data):
            project = data['projects'].get(self.key(root))
            if not project or body.get('finding') not in {a['id'] for a in project['assessment']['assets'] + project.get('missing', [])}:
                raise ValueError('Choose a finding from a completed assessment')
            log = project['tracking'].get(body['finding'], {}).get('log', [])
            step = {k: fields[k] for k in ('status', 'owner', 'due')}
            if not log or {k: log[-1].get(k) for k in step} != step:  # each change of status, owner or due date, the last 50
                log = (log + [step | {'at': time.time()}])[-50:]
            project['tracking'][body['finding']] = fields | {'updated': time.time(), 'log': log}
            return self.view(project)
        return self.update(change)

