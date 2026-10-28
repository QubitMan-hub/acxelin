"""Owners for findings, from the repository's CODEOWNERS and from a CMDB export: path patterns, the last matching one wins."""
import csv
import functools
import io
import re
from pathlib import Path

PLACES = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")  # the order GitHub looks in
PATHS = {"path", "pattern", "file", "folder", "directory"}
OWNERS = {"owner", "owners", "team", "owned by", "support group", "assigned to", "managed by"}
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


def owner_of(rules, path):
    """The owner of the last rule matching `path`, or None."""
    return next((owner for pattern, owner in reversed(rules) if _rx(pattern).fullmatch(path)), None)


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
    """[(pattern, owner)] from a CMDB export with a path (or pattern) column and an owner (or team) column."""
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
    if path is None or owner is None:
        raise ValueError("The CSV needs a path (or pattern) column and an owner (or team) column in its first row")
    rules = [(r[path].strip(), r[owner].strip()) for r in rows[1:] if len(r) > max(path, owner) and r[path].strip() and r[owner].strip()]
    if len(rules) > MAX_RULES:
        raise ValueError(f"At most {MAX_RULES} rows")
    if any(len(o) > 120 or len(p) > 400 for p, o in rules):
        raise ValueError("An owner is at most 120 characters and a path at most 400")
    return rules


def suggest(cmdb, repo, files):
    """{"owner", "source"} for a finding seen in `files`: a CMDB export first, then CODEOWNERS; None when neither names one."""
    for rules, source in ((cmdb, "CMDB export"), (repo, "CODEOWNERS")):
        for f in files:
            owner = owner_of(rules, f) if rules and "://" not in f else None
            if owner:
                return {"owner": owner, "source": source}
    return None
