"""A project workspace: scans with limits and cancellation, summaries kept per project, finding tracking, and migration evidence."""
import json
import base64
import zlib
import time
from collections import Counter
from pathlib import Path

from acxelin_core.files import locked, write


class ScanStopped(ValueError):
    pass


POINTS = {"ok": 100, "low": 75, "medium": 50, "high": 25, "critical": 0}


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
               "locations": sorted({(s.file, s.line) for s in a.detections}), "impact": a.params.get("code_impact"), "hybrid_context": a.params.get("hybrid_context", [])}
              for a in result.assets]
    patterns = [{k: v for k, v in p.as_dict().items() if k != "snippet"} for p in getattr(result, "patterns", [])][:500]
    graph = result.relationships
    assessment = {"project": name or root.name, "finished": time.time(), "assets": assets, "patterns": patterns, "notes": result.notes,
                  "summary": {"crypto_assets": len(assets), "priorities": dict(Counter(a["tier"] for a in assets)), "score": score(assets),
                              "python_files": graph.get("languages", {}).get("Python", 0), "languages": graph.get("languages", {}), "coverage_gaps": graph.get("skipped", {}),
                              "migration_candidates": sum(a["tier"] in {"critical", "high"} and not a["test_only"] and not a["declared"] for a in assets),
                              "security_patterns": sum(p["severity"] in {"critical", "high"} for p in patterns), "functions": sum(s["kind"] == "function" for s in graph["symbols"]),
                              "resolved_calls": sum(bool(c["target"]) for c in graph["calls"]), "calls": len(graph["calls"]),
                              "libraries": result.stats["libraries"], "seconds": result.stats["seconds"], "graph_limited": graph["limited"], "truncated_files": len(graph.get("truncated_files", {})), "incremental": graph.get("incremental", {})},
                  "evidence_boundary": "Static source evidence is not runtime protection or proof of business ownership.",
                  "relationships": graph}
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
            if len(ids) + len(missing) > 5000:
                raise ValueError('Workspace supports at most 5000 current and historical findings per project')
            current['comparison'] = {'baseline': bool(previous), 'new': len(ids - old.keys()), 'persisting': len(ids & old.keys()),
                                     'not_observed': len(old.keys() - ids), 'previous_finished': previous.get('assessment', {}).get('finished')}
            history = previous.get('history', [])[-29:] + [{k: current[k] for k in ('project', 'finished', 'summary', 'comparison')}]
            graph = json.dumps(current.pop('relationships', {}), separators=(',', ':')).encode()
            if len(graph) > self.GRAPH_LIMIT:
                raise ValueError('Relationship graph exceeds 64 MB; narrow the repository scope')
            packed = base64.b64encode(zlib.compress(graph)).decode('ascii')
            data['projects'][key] = {'graph_zlib': packed, 'assessment': current, 'tracking': tracking, 'missing': list(missing.values()), 'history': history, 'verifications': previous.get('verifications', [])}
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
        result['verifications'] = copy.deepcopy(project.get('verifications', []))
        present = {a['id'] for a in result['assets']}
        for evidence in result['verifications']:
            evidence['source_state'] = 'observed' if evidence['finding'] in present else 'not_observed'
            evidence['rescan_required'] = evidence['source_finished'] != result['finished']
            evidence['expired'] = time.time() - evidence['checked'] > 86400
        for asset in result['assets'] + result['not_observed']:
            asset['tracking'] = copy.deepcopy(project.get('tracking', {}).get(asset['id'], {'owner': '', 'due': '', 'status': 'open', 'reason': '', 'until': ''}))
            tracking = asset['tracking']
            today = time.strftime('%Y-%m-%d', time.gmtime())
            tracking['expired'] = tracking['status'] == 'exception' and tracking.get('until', '') < today
            tracking['overdue'] = bool(tracking.get('due') and tracking['due'] < today)
        return result

    def assessment(self, root):
        record = self.read()['projects'].get(self.key(root))
        return self.view(record) if record else None

    def record_verification(self, root, binding, observation, source_finished):
        def change(data):
            project = data['projects'].get(self.key(root))
            if not project or project['assessment']['finished'] != source_finished:
                raise ValueError('Assessment changed during verification; select the current finding and retry')
            evidence = binding | observation | {'source_finished': source_finished, 'checked': time.time(),
                                                'mapping_basis': 'Operator-supplied deployment association; source-to-release provenance is not independently verified'}
            project['verifications'] = project.get('verifications', [])[-99:] + [evidence]
            return self.view(project)
        return self.update(change)

    def track(self, root, body):
        import datetime as dt
        if not isinstance(body.get('finding'), str):
            raise ValueError('Choose a finding from a completed assessment')
        fields = {k: body.get(k, '') for k in ('owner', 'due', 'status', 'reason', 'until')}
        if any(not isinstance(v, str) for v in fields.values()) or len(fields['owner']) > 120 or len(fields['reason']) > 1000:
            raise ValueError('Owner must be at most 120 characters and rationale at most 1000')
        if fields['status'] not in {'open', 'in_progress', 'exception'}:
            raise ValueError('Choose open, in_progress or exception')
        for field in ('due', 'until'):
            if fields[field] and (len(fields[field]) != 10 or dt.date.fromisoformat(fields[field]).isoformat() != fields[field]):
                raise ValueError('Dates must use YYYY-MM-DD')
        if fields['status'] == 'exception' and (not fields['reason'].strip() or not fields['until'] or fields['until'] < dt.datetime.now(dt.timezone.utc).date().isoformat()):
            raise ValueError('An exception needs a rationale and a current or future expiry date')
        def change(data):
            project = data['projects'].get(self.key(root))
            if not project or body.get('finding') not in {a['id'] for a in project['assessment']['assets'] + project.get('missing', [])}:
                raise ValueError('Choose a finding from a completed assessment')
            project['tracking'][body['finding']] = fields | {'updated': time.time()}
            return self.view(project)
        return self.update(change)


def sample_project(parent):
    """Create an intentionally classical demonstration; never overwrite customer edits."""
    root = Path(parent) / 'sample-repository'
    if root.is_symlink():
        raise ValueError('Sample repository must not be a symlink')
    if not root.exists():
        root.mkdir(mode=0o700, parents=True)
        write(root / 'keys.py', b'from cryptography.hazmat.primitives.asymmetric import rsa\n\ndef issue_key():\n    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n', secret=True)
        write(root / 'checkout.py', b'from keys import issue_key\n\ndef enroll_customer():\n    return issue_key()\n', secret=True)
        write(root / 'README.md', b'# Sample migration project\n\nIntentionally classical RSA for static scanning only. Do not use for production security.\nScan, assign an owner, edit the example and rescan to compare evidence.\nThe scanner never executes this code. Existing edits are preserved on restart.\n', secret=True)
    if not root.is_dir():
        raise ValueError('Sample repository path must be a folder')
    return root
