"""Check a downloaded release against its SHA256SUMS, offline: python verify_release.py SHA256SUMS [FOLDER]

Run it in the folder that holds the release archive and, once extracted, the release folder. It reports files that are missing, files
whose bytes do not match, files in the release folder that the list does not name, and list entries that point outside the folder.
Standard library only. Exit status 0 only when nothing is reported. The list itself is trusted only if it was verified (see VERIFY.md).
"""
import hashlib
import re
import sys
from pathlib import Path

LINE = re.compile(r"([0-9a-f]{64}) [ *](.+)")


def verify(sums, base):
    base = Path(base).resolve()
    problems, listed = [], set()
    for n, raw in enumerate(Path(sums).read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        m = LINE.fullmatch(raw)
        if not m:
            problems.append(f"line {n} is not a SHA-256 checksum line")
            continue
        want, name = m.groups()
        target = (base / name).resolve()
        if base not in target.parents:
            problems.append(f"{name}: outside the release folder, not checked")
            continue
        listed.add(target)
        if not target.is_file():
            problems.append(f"{name}: missing")
        elif hashlib.sha256(target.read_bytes()).hexdigest() != want:
            problems.append(f"{name}: does not match its checksum")
    for top in sorted({p.relative_to(base).parts[0] for p in listed if p.relative_to(base).parts[1:]}):
        for extra in sorted(p for p in (base / top).rglob("*") if p.is_file() and p.resolve() not in listed):
            problems.append(f"{extra.relative_to(base).as_posix()}: not listed in the checksums")
    return problems


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    found = verify(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else Path(sys.argv[1]).resolve().parent)
    print("\n".join(found) if found else "every file matches its checksum, and nothing else is in the release folder")
    sys.exit(1 if found else 0)
