"""Shared private file writes and process/thread locking, independent of cryptographic protocols."""
import contextlib
import errno
import os
import secrets
import threading
import time
from pathlib import Path

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_HELD = threading.local()


@contextlib.contextmanager
def locked(root, filename=".lock"):
    """Serialize file-backed state across threads/processes; allow nested updates in one thread."""
    root = Path(root).resolve()
    if Path(filename).name != filename or filename in {".", ".."}:
        raise ValueError("Lock filename must be a single file name")
    key = str(root / filename)
    held = _HELD.__dict__.setdefault("roots", set())
    if key in held:
        yield
        return
    tl = _THREAD_LOCKS.setdefault(key, threading.Lock())
    with tl, os.fdopen(os.open(root / filename, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600), "a+b") as f:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            while True:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as e:
                    if e.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX)
        held.add(key)
        try:
            yield
        finally:
            held.discard(key)
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


def shared(action, tries=40):
    """Windows refuses to open or replace a file while another thread has it open (a CRL being read while its new copy is
    swapped in); such a clash lasts milliseconds, so try again briefly. Elsewhere this runs `action` once."""
    for n in range(tries):
        try:
            return action()
        except PermissionError:
            if os.name != "nt" or n == tries - 1:
                raise
            time.sleep(0.025)


def write(path, data, secret=False):
    """Write atomically; secret files are created owner-only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600 if secret else 0o644)
    try:
        if secret:  # private before the first byte: on Windows the new file starts with the folder's inherited ACL
            os.close(fd)
            owner_only(tmp)
            fd = os.open(tmp, os.O_WRONLY | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shared(lambda: os.replace(tmp, path))
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def append(path, line):
    """Add one line to a log that only its owner can read (audit logs name identities and administrative actions)."""
    if not os.path.exists(path):
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600))
        owner_only(path)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "ab") as f:
        f.write(line.encode() + b"\n")


def owner_only(path):
    """Windows ignores POSIX modes, so a secret file gets an ACL only its owner can use (inherited entries removed).
    Fails closed: a secret that cannot be made private is an error, not a warning. Nothing to do elsewhere: the mode did it."""
    if os.name != "nt":
        return
    import subprocess
    user, domain = os.environ.get("USERNAME"), os.environ.get("USERDOMAIN")
    who = f"{domain}\\{user}" if domain and user else user
    r = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:F"], capture_output=True, text=True)
    if r.returncode:
        raise OSError(f"cannot make {path} readable by its owner only: {(r.stderr or r.stdout).strip()}")


