"""Owners for findings, from the repository's CODEOWNERS and from a CMDB export: path patterns, the last matching one wins.
A CMDB export may also name the business service each path belongs to, how many years its data must stay secret, and how
important it is to the business."""
import csv
import functools
import io
import re
from pathlib import Path

PLACES = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")  # the order GitHub looks in
PATHS = {"path", "pattern", "file", "folder", "directory"}
OWNERS = {"owner", "owners", "team", "owned by", "support group", "assigned to", "managed by"}
SERVICES = {"service", "business service", "application", "app", "system"}
YEARS = {"keep secret (years)", "keep secret", "secret years", "data lifetime", "retention (years)", "retention years"}
IMPORTANCE = {"importance", "criticality", "business criticality"}
LEVELS = ("critical", "high", "medium", "low")
MAX_RULES = 5000


@functools.lru_cache(maxsize=4096)
def _rx(pattern):
    """A CODEOWNERS pattern as GitHub reads it: anchored when it starts with or contains a slash, `*` within a folder,
    `**` across folders, and a folder matching everything under it."""
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    p, out, i = pattern.strip("/"), "", 0
    while i < len(p):
        if p.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif p.startswith("**", i):
            out, i = out + ".*", i + 2
        else:
            out, i = out + ("[^/]*" if p[i] == "*" else "[^/]" if p[i] == "?" else re.escape(p[i])), i + 1
    return re.compile(("" if anchored else "(?:.*/)?") + out + ("/.*" if pattern.endswith("/") else "(?:/.*)?"))


def match(rules, path):
    """The last rule matching `path`, or None: (pattern, owner) or (pattern, owner, service)."""
    return next((r for r in reversed(rules) if _rx(r[0]).fullmatch(path)), None)


def secrets(rules):
    """[(pattern, years)] for the rules that say how long their data must stay secret."""
    return tuple((r[0], float(r[3])) for r in rules if len(r) > 3 and r[3] != "")


def owner_of(rules, path):
    r = match(rules, path)
    return r[1] if r else None


def codeowners(root):
    """[(pattern, owners)] from the first CODEOWNERS file GitHub would use; [] when there is none."""
    for place in PLACES:
        f = Path(root) / place
        if f.is_file() and f.stat().st_size <= 1_000_000:
            rules = []
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split("#", 1)[0].split()
                if len(parts) >= 2:
                    rules.append((parts[0], " ".join(parts[1:])[:120]))
            return rules[-MAX_RULES:]
    return []


def from_csv(text):
    """[(pattern, owner)] from a CMDB export with a path (or pattern) column and an owner (or team) column; with a service (or
    application) column too, [(pattern, owner, service)]; with a keep-secret (years) or an importance column, [(pattern, owner,
    service, years or "", importance or "")]."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Choose a CSV with a path column and an owner column")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    head = [c.strip().lower() for c in rows[0]] if rows else []
    path = next((i for i, c in enumerate(head) if c in PATHS), None)
    owner = next((i for i, c in enumerate(head) if c in OWNERS), None)
    service = next((i for i, c in enumerate(head) if c in SERVICES), None)
    years = next((i for i, c in enumerate(head) if c in YEARS), None)
    importance = next((i for i, c in enumerate(head) if c in IMPORTANCE), None)
    if path is None or owner is None:
        raise ValueError("The CSV needs a path (or pattern) column and an owner (or team) column in its first row")
    cell = lambda r, i: r[i].strip() if i is not None and len(r) > i else ""
    def extra(r):
        y, level = cell(r, years), cell(r, importance).lower()
        try:
            y = float(y) if y else ""
        except ValueError:
            raise ValueError(f"Keep secret (years) must be a number of years, not {y[:20]!r}") from None
        if y != "" and not 0 <= y <= 100:
            raise ValueError("Keep secret (years) is between 0 and 100")
        if level and level not in LEVELS:
            raise ValueError(f"Importance is one of {', '.join(LEVELS)}, not {level[:20]!r}")
        return (y, level)
    more = years is not None or importance is not None
    rules = [(cell(r, path), cell(r, owner)) + ((cell(r, service),) if service is not None or more else ()) + (extra(r) if more else ())
             for r in rows[1:] if cell(r, path) and cell(r, owner)]
    if len(rules) > MAX_RULES:
        raise ValueError(f"At most {MAX_RULES} rows")
    if any(len(r[1]) > 120 or len(r[0]) > 400 or len(r) > 2 and len(r[2]) > 120 for r in rules):
        raise ValueError("An owner or a service is at most 120 characters and a path at most 400")
    return rules


def suggest(cmdb, repo, files):
    """{"owner", "source", "service"?} for a finding seen in `files`: a CMDB export first, then CODEOWNERS; None when neither names one."""
    for rules, source in ((cmdb, "CMDB export"), (repo, "CODEOWNERS")):
        for f in files:
            r = match(rules, f) if rules and "://" not in f else None
            if r:
                extra = dict(zip(("service", "secret_years", "importance"), r[2:]))
                return {"owner": r[1], "source": source} | {k: v for k, v in extra.items() if v != ""}
    return None
