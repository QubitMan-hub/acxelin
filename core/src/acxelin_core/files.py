"""Shared private file writes and process/thread locking, independent of cryptographic protocols."""
import contextlib
import errno
import ntpath
import os
import secrets
import stat
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




def windows_protected(path, roots, ntp=ntpath):
    """True when `path` sits inside one of `roots` (Program Files, the Windows folder), whose default permissions keep ordinary
    users from changing what is there. `..` is resolved first, and a folder that merely starts with a root's name is not inside it."""
    p = ntp.normcase(ntp.normpath(path))
    return any(p.startswith(ntp.normcase(ntp.normpath(r)) + ntp.sep) for r in roots)


def protected_location(paths, trusted_uids=(0,), trusted_gids=(), _below=None):
    """None when every path, once links are followed, and every folder above it is owned by a trusted user and writable by nobody
    else; otherwise a sentence saying which one is not. Code that runs with administrator rights must pass this: a file an ordinary
    user can change is a way for that user to become the administrator. Windows has no owner and mode to read, so a path there
    must be inside Program Files or the Windows folder, which is a rule about their default permissions, not a read of the real ones.
    `_below` stops the walk at a folder (tests use it). Links, the owner and the mode bits are checked; ACLs, mount options and network
    file systems are not."""
    ceiling = Path(_below).resolve() if _below else None
    for path in paths:
        if os.name == "nt":
            roots = [r for r in (os.environ.get(v) for v in ("ProgramFiles", "ProgramFiles(x86)", "SystemRoot")) if r]
            if not windows_protected(os.path.realpath(path), roots):
                return f"{path} is not inside Program Files or the Windows folder, so an ordinary user may be able to change it"
            continue
        try:
            real = Path(path).resolve(strict=True)
        except OSError:
            return f"{path} was not found"
        for p in (real, *real.parents):
            if ceiling and (p == ceiling or p in ceiling.parents):
                break
            st = p.stat()
            if st.st_uid not in trusted_uids:
                return f"{p} is owned by user {st.st_uid}, who is not an administrator"
            if st.st_mode & stat.S_IWOTH or (st.st_mode & stat.S_IWGRP and st.st_gid not in trusted_gids):
                return f"{p}: users other than its owner can write to it"
    return None
