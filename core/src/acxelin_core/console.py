"""The mechanism behind every product console: a loopback page plus JSON API, with its page script pinned by hash."""
import base64
import hashlib
import hmac
import json
import logging
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from .http import HTTP_IDLE, content_length

log = logging.getLogger(__name__)


def with_tour(html):
    """Put the shared guided tour (acxelin_core/tour.js) at the start of the page's one inline script, so its hash covers both."""
    return html.replace(b"<script>", b"<script>\n" + resources.files(__package__).joinpath("tour.js").read_bytes(), 1)


def policy(html):
    """The page's one inline script is allowed by its hash, so no other script can run even if markup were ever injected. The
    hash is of the script as a browser sees it, newlines normalised, so a CRLF checkout (Git on Windows) is not blocked."""
    script = html.split(b"<script>", 1)[1].split(b"</script>", 1)[0].replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    digest = base64.b64encode(hashlib.sha256(script).digest()).decode()
    return f"default-src 'self'; img-src 'self' data:; font-src data:; style-src 'self' 'unsafe-inline'; script-src 'sha256-{digest}'; frame-ancestors 'none'"


class Backoff:
    """After 10 wrong tokens from one address within a minute, that address is refused until the minute is over."""

    def __init__(self, limit=10, window=60.0):
        self.limit, self.window, self.lock, self.failures = limit, window, threading.Lock(), {}

    def blocked(self, addr):
        with self.lock:
            recent = [t for t in self.failures.pop(addr, []) if time.monotonic() - t < self.window]
            if recent:
                self.failures[addr] = recent
            return len(recent) >= self.limit

    def failed(self, addr):
        with self.lock:
            self.failures.setdefault(addr, []).append(time.monotonic())


class Handler(BaseHTTPRequestHandler):
    """A loopback JSON API behind one HTML page: every answer uncached, unsniffable and under the page's CSP."""
    csp = ""

    def reply(self, status, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(status)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                     ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", self.csp)):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def authorised(self, token):
        return hmac.compare_digest(self.headers.get("Authorization", "").removeprefix("Bearer ").encode(), token.encode())

    def json_body(self, limit):
        """The request's JSON object, or the (status, error) to answer instead."""
        n = content_length(self.headers)
        if n is None:
            return 400, {"error": "bad Content-Length"}
        if n > limit:
            return 413, {"error": "request too large"}
        try:
            body = json.loads(self.rfile.read(n)) if n else {}
        except (ValueError, RecursionError):
            return 400, {"error": "invalid JSON"}
        return body if isinstance(body, dict) else (400, {"error": "the body must be a JSON object"})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)



# The console access contract shared by every product console: a single-use launch ticket in the URL fragment (never sent
# to the server), redeemed once for a session token the page keeps in sessionStorage and sends as a Bearer header. No
# cookies, so a cross-site page has no credential to ride on.

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
CLIENT_JS = b"""const acx = (() => {
  let token = null;
  try { token = sessionStorage.getItem("acx-token"); } catch (e) {}
  const ticket = location.hash.slice(1);
  async function start() {
    if (ticket) {
      history.replaceState(null, "", location.pathname);
      const r = await fetch("/api/session", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ticket})}).catch(() => null);
      if (r && r.ok) { token = (await r.json()).token; try { sessionStorage.setItem("acx-token", token); } catch (e) {} }
    }
    return Boolean(token);
  }
  async function api(path, body) {
    const r = await fetch("/api/" + path, {method: body === undefined ? "GET" : "POST", headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                                           body: body === undefined ? undefined : JSON.stringify(body)});
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(data.error || r.statusText), {status: r.status});
    return data;
  }
  async function download(path, body) {
    const r = await fetch("/api/" + path, {method: "POST", headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"}, body: JSON.stringify(body)});
    if (!r.ok) { const data = await r.json().catch(() => ({})); throw Object.assign(new Error(data.error || r.statusText), {status: r.status}); }
    const name = ((r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/) || [])[1] || "download";
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a"); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return name;
  }
  return {start, api, download};
})();
"""


def with_client(html):
    """Put the shared session code at the start of the page's one inline script, so the page's CSP hash covers it."""
    return html.replace(b"<script>", b"<script>\n" + CLIENT_JS, 1)


class Sessions:
    """Launch tickets (single use, short lived) and the session tokens they are redeemed for."""

    def __init__(self, ticket_ttl=300.0, automation_token=None):
        self.ticket_ttl, self.lock, self.tickets, self.tokens = ticket_ttl, threading.Lock(), {}, set()
        if automation_token:
            self.tokens.add(automation_token)

    def ticket(self):
        code, now = secrets.token_urlsafe(32), time.monotonic()
        with self.lock:
            self.tickets = {k: t for k, t in self.tickets.items() if t > now} | {code: now + self.ticket_ttl}
        return code

    def redeem(self, code):
        with self.lock:
            if not isinstance(code, str) or self.tickets.pop(code, 0) <= time.monotonic():
                return None
            token = secrets.token_urlsafe(32)
            self.tokens.add(token)
        return token

    def authorised(self, header):
        given = (header or "").removeprefix("Bearer ").encode()
        with self.lock:
            tokens = list(self.tokens)
        return bool(given) and any(hmac.compare_digest(given, t.encode()) for t in tokens)


def refusal(headers):
    """The status that refuses this request before authentication, or None: loopback Host only (any port, so SSH forwards
    work, while DNS-rebinding names are refused), a same-origin Origin when present, and no fetch from another site or another
    local port (same-site)."""
    host = headers.get("Host") or ""
    name = host[1:].split("]")[0] if host.startswith("[") else host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if name not in LOOPBACK:
        return 421
    if headers.get("Origin") not in (None, f"http://{host}") or headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
        return 403
    return None


class Download:
    """A route's answer that the browser saves as a file instead of reading as JSON."""

    def __init__(self, name, data, content_type="application/octet-stream"):
        self.name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name) or "download"
        self.data, self.content_type = data, content_type


class App:
    """One product console: its page, its routes {(method, path): handler(body) -> (status, json)} and its sessions."""

    def __init__(self, html, routes, sessions=None, body_limit=1 << 17):
        self.html, self.routes, self.body_limit = with_client(html), routes, body_limit
        self.sessions = sessions or Sessions()


def serve(app, listen=("127.0.0.1", 0)):
    backoff = Backoff()

    class Console(Handler):
        csp, timeout = policy(app.html), HTTP_IDLE

        def send_file(self, status, d):
            self.send_response(status)
            for k, v in (("Content-Type", d.content_type), ("Content-Length", str(len(d.data))), ("Cache-Control", "no-store"),
                         ("Content-Disposition", f'attachment; filename="{d.name}"'), ("X-Content-Type-Options", "nosniff")):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(d.data)

        def log_request(self, code="-", size="-"):
            path = self.path.split("?")[0].split("#")[0].replace("\r", "").replace("\n", "")
            log.info("%s %s %s", self.command, path, code)

        def log_message(self, fmt, *args):
            pass  # the default line holds the full request target; log_request above records it without query or fragment

        def route(self, method):
            status = refusal(self.headers)
            if status:
                return self.reply(status, {"error": "wrong host" if status == 421 else "requests from other sites are refused"})
            path = self.path.split("?")[0]
            if method == "GET" and path == "/":
                return self.reply(200, app.html, "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.reply(404, {"error": "not found"})
            # Only a presented credential that is wrong counts towards the lockout, and a valid session is never locked out,
            # so requests another page can make without a credential cannot shut the real user out.
            addr = self.client_address[0]
            locked = {"error": "too many wrong attempts; wait a minute"}
            body = self.json_body(app.body_limit)
            if method == "POST" and path == "/api/session":
                if not isinstance(body, dict):
                    return self.reply(*body)
                ticket = body.get("ticket")
                if not isinstance(ticket, str) or not ticket:
                    return self.reply(401, {"error": "this link was already used or has expired; open the console again"})
                if backoff.blocked(addr):
                    return self.reply(429, locked)
                token = app.sessions.redeem(ticket)
                if not token:
                    backoff.failed(addr)
                    return self.reply(401, {"error": "this link was already used or has expired; open the console again"})
                return self.reply(200, {"token": token})
            credential = self.headers.get("Authorization")
            if not app.sessions.authorised(credential):
                if credential and backoff.blocked(addr):
                    return self.reply(429, locked)
                if credential:
                    backoff.failed(addr)
                return self.reply(401, {"error": "sign in again: open the console from its command"})
            if not isinstance(body, dict):
                return self.reply(*body)
            if method == "POST" and path == "/api/ticket":
                return self.reply(200, {"ticket": app.sessions.ticket()})
            handler = app.routes.get((method, path))
            if not handler:
                return self.reply(404, {"error": "not found"})
            try:
                status, answer = handler(body)
                if isinstance(answer, Download):
                    return self.send_file(status, answer)
                return self.reply(status, answer)
            except ValueError as e:
                return self.reply(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001 - the message may hold paths or data: log and answer with the type only
                log.error("%s %s failed: %s", method, path, type(e).__name__)
                return self.reply(500, {"error": "the console hit an unexpected error; try again, and check its terminal if it repeats"})

    server = ThreadingHTTPServer(listen, Console)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def link(sessions, port, tty=None):
    """Print a launch address for this console, but only to an interactive terminal (never into a log)."""
    if not (sys.stdout.isatty() if tty is None else tty):
        return None
    url = f"http://127.0.0.1:{port}/#{sessions.ticket()}"
    print(url)
    return url


def new_automation_token(path):
    """A long-lived token for scripts, written owner-only."""
    from .files import write
    token = secrets.token_urlsafe(32)
    write(path, (token + "\n").encode(), secret=True)
    return token


def start(app, home, port=8900, host="127.0.0.1"):
    """Serve `app` on loopback. The automation token lives in `home`/console.token (made once, owner-only), so
    `acxelin-<product> console link` from another process can ask this one for a launch ticket.
    `host` is loopback except inside a container, where the product passes 0.0.0.0 so a port published to the host's loopback reaches it;
    the Host check still refuses every request that does not name a loopback host."""
    from pathlib import Path
    token_file = Path(home) / "console.token"
    Path(home).mkdir(parents=True, exist_ok=True)
    token = token_file.read_text().strip() if token_file.exists() else new_automation_token(token_file)
    app.sessions.tokens.add(token)
    return serve(app, (host, port))


def link_running(port, home, tty=None):
    """Ask the console already running on `port` for a launch ticket and print its address (interactive terminals only)."""
    import urllib.request
    from pathlib import Path
    if not (sys.stdout.isatty() if tty is None else tty):
        return None
    token = (Path(home) / "console.token").read_text().strip()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/ticket", b"{}", {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # the token never goes through a proxy
    url = f"http://127.0.0.1:{port}/#{json.loads(direct.open(req, timeout=5).read())['ticket']}"
    print(url)
    return url
