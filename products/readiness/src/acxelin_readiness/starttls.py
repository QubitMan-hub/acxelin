"""Mail servers start TLS inside SMTP: the client says EHLO, sees STARTTLS offered, asks for it, and the TLS handshake follows on
the same connection. Targets written as smtp://host (port 25) or submission://host (587) are opened this way by every probe, so
a mail server is graded like any TLS endpoint."""
import socket
import time

SCHEMES = {"smtp": 25, "submission": 587}
_mail = set()  # (host, port) of the targets that start TLS inside SMTP


def expect(host, port):
    _mail.add((host, port))


def dial(host, port, timeout):
    """A connection to (host, port), ready for a TLS ClientHello."""
    s = socket.create_connection((host, port), timeout=timeout)
    if (host, port) in _mail:
        try:
            _smtp(s, timeout)
        except BaseException:
            s.close()
            raise
    return s


def _reply(s, deadline):
    """One SMTP reply (all its lines): (code, text). Bounded in time and size, like the other probes."""
    buf = b""
    while True:
        lines = buf.split(b"\r\n")
        done = [l for l in lines[:-1] if len(l) >= 4 and l[3:4] == b" "]
        if done:
            return int(done[0][:3]) if done[0][:3].isdigit() else 0, b"\n".join(lines[:-1]).decode("ascii", "replace")
        left = deadline - time.monotonic()
        if left <= 0 or len(buf) > 16384:
            raise OSError("the mail server's reply is too slow or too long")
        s.settimeout(left)
        chunk = s.recv(4096)
        if not chunk:
            raise OSError("the mail server closed the connection")
        buf += chunk


def _smtp(s, timeout):
    deadline = time.monotonic() + 2 * timeout
    code, text = _reply(s, deadline)
    if code != 220:
        raise OSError(f"not an SMTP server, or it refused the connection ({text[:80]!r})")
    s.sendall(b"EHLO acxelin-readiness.invalid\r\n")
    code, text = _reply(s, deadline)
    if code != 250 or "STARTTLS" not in text.upper():
        raise OSError("the mail server does not offer STARTTLS, so its mail travels unencrypted unless the sender insists")
    s.sendall(b"STARTTLS\r\n")
    code, text = _reply(s, deadline)
    if code != 220:
        raise OSError(f"the mail server refused STARTTLS ({text[:80]!r})")
    s.settimeout(timeout)
