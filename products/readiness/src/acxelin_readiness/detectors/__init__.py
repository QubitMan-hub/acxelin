import os
import re
from dataclasses import dataclass, field, replace
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable

from ..catalog import CATALOG
from ..model import Detection

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__", "dist", "build", "target", ".tox",
             "site-packages", ".idea", ".vscode", ".gradle", ".mypy_cache", ".pytest_cache", "bin", "obj", "readiness-out"}
TEST_PARTS = {"test", "tests", "unit", "spec", "specs", "__tests__", "testdata", "test_data", "test_vectors", "selftest", "selftests", "fixtures", "mocks", "examples", "example", "samples", "sample", "demo",
              "bench", "benches", "benchmark", "benchmarks", "browsertest", "test-classes", "regress", "regression"}
TEST_DIR = re.compile(r"(?:^|[._-])(?:unit|integration|functional|i)?tests?(?:net\d+|core)?$|^tests?-")
BUILD_DIRS = {"dist", "build", "target", "bin", "obj"}
MAX_BYTES = 2_000_000
READ_LIMIT = 256_000_000  # no detector reads more of a file; a larger one (a disk image) is read only for its header
DENY = re.compile(r"disabl|disallow|deny|denied|block|forbid|reject|insecure|weak|deprecat|legacy_only|exclude|blacklist", re.I)


class ScanLimitError(ValueError):
    pass


@dataclass(frozen=True)
class Scope:
    """Which files the detectors walk. A pattern without "/" matches any file or folder name; one with "/" matches the path from the root."""
    checkpoint: Callable | None = field(default=None, compare=False, repr=False, kw_only=True)
    max_files: int = field(default=0, kw_only=True)
    max_total_bytes: int = field(default=0, kw_only=True)
    vendor: bool = False
    exclude: tuple = ()
    only: frozenset | None = None
    files: tuple | None = field(default=None, compare=False, repr=False)

    def excluded(self, relpath):
        name = relpath.rsplit("/", 1)[-1]
        return any(fnmatch(relpath, x) if "/" in x else fnmatch(name, x) for x in self.exclude)


def iter_files(root, scope=Scope(), max_bytes=MAX_BYTES, skip=None):
    scope = scope if isinstance(scope, Scope) else Scope(bool(scope))
    skip = SKIP_DIRS if skip is None else skip
    root = Path(root)
    if scope.checkpoint:
        scope.checkpoint()
    if root.is_file():
        if not root.is_symlink():
            yield root
        return
    if scope.files is not None:
        for p, size in scope.files:
            if scope.checkpoint:
                scope.checkpoint()
            folders = p.relative_to(root).parts[:-1]
            if size <= max_bytes and (scope.vendor or not set(folders) & skip):
                yield p
        return
    for d, dirs, files in os.walk(root):
        if scope.checkpoint:
            scope.checkpoint()
        here = Path(d).relative_to(root).as_posix()
        at = "" if here == "." else here + "/"
        dirs[:] = sorted(x for x in dirs if not (Path(d) / x).is_symlink() and (scope.vendor or x not in skip) and not scope.excluded(at + x))
        for f in sorted(files):
            if scope.checkpoint:
                scope.checkpoint()
            if scope.excluded(at + f) or scope.only is not None and at + f not in scope.only:
                continue
            p = Path(d) / f
            try:
                if not p.is_symlink() and p.stat().st_size <= max_bytes:
                    yield p
            except OSError:
                continue


def snapshot(root, scope=False):
    """Enumerate once per scan; keep only paths/sizes, never customer source contents."""
    scope = scope if isinstance(scope, Scope) else Scope(bool(scope))
    entries, total_bytes = [], 0
    for p in iter_files(root, scope, max_bytes=float("inf"), skip=SKIP_DIRS - BUILD_DIRS):
        try:
            size = p.stat().st_size
            total_bytes += size if size <= READ_LIMIT else 0
            if scope.max_files and len(entries) >= scope.max_files:
                raise ScanLimitError('Repository exceeds the scan file limit; narrow the project folder')
            if scope.max_total_bytes and total_bytes > scope.max_total_bytes:
                raise ScanLimitError('Repository exceeds the scan byte limit; narrow the project folder')
            entries.append((p, size))
        except OSError:
            continue
    entries.sort(key=lambda item: (is_test(rel(root, item[0])), rel(root, item[0])))
    return replace(scope, files=tuple(entries))


def oversized(root, scope=Scope()):
    """Source files over MAX_BYTES, which the detectors do not read (usually generated or minified code)."""
    from .lexer import LANGS
    if Path(root).is_file():
        return []
    return [rel(root, p) for p in iter_files(root, scope, max_bytes=float("inf")) if p.suffix.lower() in LANGS and p.stat().st_size > MAX_BYTES]


def rel(root, p):
    root = Path(root)
    try:
        return Path(p).relative_to(root if root.is_dir() else root.parent).as_posix()
    except ValueError:
        return Path(p).as_posix()


def is_test(relpath):
    parts = [x.lower() for x in Path(relpath).parts]
    name = parts[-1] if parts else ""
    return bool(TEST_PARTS & set(parts[:-1])) or any(TEST_DIR.search(d) for d in parts[:-1]) or name.startswith("test_") or any(
        name.endswith(s) for s in ("_test.go", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "test.java", "tests.cs", "_test.py", "_spec.rb"))


def read(p):
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def carried_hashes(detections):
    """A primitive parameterised with a hash (HMAC-SHA256, PBKDF2 over SHA-1, SHA256withRSA) also reports the hash itself."""
    have = {(s.file, s.line, s.algo) for s in detections}
    out = []
    for s in detections:
        h = s.params.get("hash")
        if h in CATALOG and h != s.algo and (s.file, s.line, h) not in have:
            have.add((s.file, s.line, h))
            params = {"role": f"hash of {s.algo}"} | ({"literal": s.params["literal"]} if "literal" in s.params else {})
            if s.algo in ("HMAC", "PBKDF2") or s.params.get("padding") == "oaep":
                params["purpose"] = "no-collision"  # these need no collision resistance from the hash
            out.append(Detection(algo=h, file=s.file, line=s.line, evidence=s.evidence, detector=s.detector, snippet=s.snippet, lang=s.lang,
                                params=params, context=set(s.context)))
    return out
