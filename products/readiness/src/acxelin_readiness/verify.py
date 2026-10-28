import re
from collections import defaultdict
from pathlib import Path

from .catalog import CATALOG, variant
from .model import Asset

BASE = {"string": 0.35, "import": 0.45, "identifier": 0.65, "binary": 0.8, "constant": 0.85, "call": 0.9, "config": 0.9, "artifact": 0.95, "live": 1.0}
RANK = {k: i for i, k in enumerate(BASE)}
KIN = {"ECC": "EC", "ECDSA": "EC", "ECDH": "EC"}
HARD = {"comment": "appears only inside a comment", "doc": "appears only in a docstring", "prose": "mentioned in human-readable text, not used"}
KEY_PARAMS = ("key_size", "curve", "mode", "hash", "padding")


def _kin(a):
    return KIN.get(a, a)


def dedupe(detections):
    best = {}
    for s in detections:
        k = (s.file, s.line, s.algo, "comment" in s.context, s.params.get("role") if s.evidence == "artifact" else None)  # a certificate's key and signature stay apart
        cur = best.setdefault(k, s)
        if cur is not s:
            win, lose = (s, cur) if RANK[s.evidence] > RANK[cur.evidence] else (cur, s)
            mixed_purpose = win.evidence == lose.evidence == "call" and win.params.get("purpose") != lose.params.get("purpose")
            for p, v in lose.params.items():
                win.params.setdefault(p, v)
            if mixed_purpose:
                win.params["purpose"] = "unknown"
            best[k] = win
    return list(best.values())


class Lines:
    def __init__(self, root):
        self.root, self.cache = Path(root), {}

    def __call__(self, f):
        if f not in self.cache:
            p = self.root / f if self.root.is_dir() else self.root
            try:
                self.cache[f] = p.read_text(encoding="utf-8", errors="replace").splitlines() if "://" not in f and "!" not in f else []
            except OSError:
                self.cache[f] = []
        return self.cache[f]


def suppressed(s, lines):
    ls = lines(s.file)
    return ignored(ls, s.line)


def verify(detections, threshold=0.6, lines=None):
    """Verification: every detection gets a confidence from its evidence; only what clears the threshold enters the CBOM."""
    detections = dedupe(detections)
    by_file = defaultdict(list)
    for s in detections:
        if lines and s.line and suppressed(s, lines):
            s.confidence, s.verdict, s.reason = 0.0, "suppressed", "suppressed with an acxelin:ignore comment"
            continue
        hard = next((HARD[c] for c in ("comment", "doc", "prose") if c in s.context), None)
        if hard:
            s.confidence, s.verdict, s.reason = 0.0, "rejected", hard
            continue
        if s.algo not in CATALOG:
            s.confidence, s.verdict, s.reason = 0.0, "rejected", "unrecognised algorithm"
            continue
        s.confidence = BASE[s.evidence] + (0.05 if any(s.params.get(k) for k in KEY_PARAMS) else 0)
        by_file[s.file].append(s)
    for f, group in by_file.items():
        firsts = defaultdict(dict)  # per algorithm family, the first detection of each kind of evidence, in file order
        for n, o in enumerate(group):
            firsts[_kin(o.algo)].setdefault(o.evidence, (n, o))
        for s in group:
            other = min((x for e, x in firsts[_kin(s.algo)].items() if e != s.evidence), default=None, key=lambda x: x[0])
            if other:
                s.confidence += 0.25
                s.reason = f"corroborated by {other[1].evidence} evidence on line {other[1].line}"
            s.confidence = round(min(s.confidence, 1.0), 2)
            if s.confidence >= threshold:
                s.verdict = "accepted"
                s.reason = s.reason or f"{s.evidence} evidence"
            else:
                s.verdict = "quarantined"
                s.reason = {"import": "imported, but no usage observed in this file",
                            "string": "algorithm name in a string literal with no observed use"}.get(s.evidence, "weak evidence")
    return detections


def settle(detections):
    """After the second look: a name that is only a local look-alike is rejected; anything in code that can never run is held."""
    for s in detections:
        if "lookalike" in s.context and s.verdict != "suppressed":
            s.confidence, s.verdict, s.reason = 0.0, "rejected", "named like an algorithm, but a local definition that does no cryptography"
        elif "unreachable" in s.context and s.verdict == "accepted":
            s.verdict, s.reason = "quarantined", "in code that can never run (a constant-false branch, or after return or raise)"


IGNORE = ("acxelin:ignore", "wolfpack:ignore")  # the second is the old name, honoured through acxelin-readiness 1.x


def ignored(ls, line):
    """True when `line` (1-based) or the line above it carries a suppression comment."""
    return any(0 < k <= len(ls) and any(tag in ls[k - 1] for tag in IGNORE) for k in (line, line - 1))


def assets(detections):
    """Accepted detections grouped by variant. A detection with no parameters joins the one parameterised variant of its algorithm in its file."""
    kept = []
    for s in detections:
        if s.verdict == "accepted":
            p = {k: v for k, v in s.params.items() if k in KEY_PARAMS and v}
            kept.append((s, p, variant(s.algo, p) if p else None))
    known = defaultdict(set)
    for s, p, v in kept:
        if v:
            known[s.file, s.algo].add(v)
    groups = defaultdict(list)
    for s, p, v in kept:
        one = known[s.file, s.algo]
        name = v or (next(iter(one)) if len(one) == 1 else s.algo)
        use = s.params.get("purpose", "")
        use = use if use in {"non-security", "password"} else ""
        groups[name, use].append((s, p))
    out = []
    for (v, use), items in sorted(groups.items()):
        algo = items[0][0].algo
        if use:
            v += " (declared non-security)" if use == "non-security" else " (password hashing)"
        params = {"purpose": use} if use else {}
        for _, p in items:
            for k, val in p.items():
                params.setdefault(k, val)
        sl = [s for s, _ in items]
        out.append(Asset(ref=f"crypto/{re.sub(r'[^A-Za-z0-9.-]+', '-', v)}", algo=algo, variant=v, params=params, detections=sl,
                         confidence=max(s.confidence for s in sl), test_only=all("test" in s.context for s in sl),
                         declared=all("declared" in s.context for s in sl)))
    return out
