"""The VPN window: a page on this machine's loopback address that joins from an invitation, connects, disconnects and says
whether this machine is protected. `acxelin-vpn app` holds the tunnel; closing the page leaves it as it is.

The page is reachable only on 127.0.0.1, only with the random token in the address the command opens, and only under its
own host name and origin (a page from elsewhere can neither borrow it through DNS rebinding nor lock it with wrong tokens). Passphrases go from the page to this process
and nowhere else; they are never written or logged."""
import json
import os
import re
import secrets
import threading
import time
from http.server import ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from acxelin_core.http import HTTP_IDLE, explain
from acxelin_core.console import Backoff, Handler, policy, with_tour
from acxelin_core.pki import encrypted
from acxelin_core.files import write
from . import join
from .wireguard import Client


class App:
    def __init__(self, invitation=None, folder=None, interface="wg0", apply=True):
        self.folder = Path(folder) if folder else Path.home() / ".acxelin-vpn"
        self.invitation = Path(invitation) if invitation else self.newest()
        self.interface, self.apply = interface, apply
        self.client = self.thread = self.on_quit = None
        self.lock, self.token, self.tickets = threading.Lock(), secrets.token_urlsafe(24), {}

    def ticket(self, ttl=300):
        """A one-time code for an address handed to a browser; it is exchanged for the session key once, so the key itself
        never appears on a command line or in browser history."""
        code = secrets.token_urlsafe(18)
        with self.lock:
            now = time.monotonic()
            self.tickets = {k: t for k, t in self.tickets.items() if t > now} | {code: now + ttl}
        return code

    def redeem(self, code):
        with self.lock:
            return isinstance(code, str) and self.tickets.pop(code, 0) > time.monotonic()

    def newest(self):
        found = sorted(self.folder.glob("*.acxinvite"), key=lambda p: p.stat().st_mtime) if self.folder.is_dir() else []
        return found[-1] if found else None

    def state(self):
        out = {"invitation": None, "enrolled": False, "needs_passphrase": False, "error": None, "apply": self.apply}
        if self.invitation:
            try:
                inv = join.read(self.invitation)
                device = join.device_for(self.invitation)
                out |= {"invitation": {"file": self.invitation.name, "name": inv["name"], "gateway": inv["gateway"], "expires": inv.get("expires")},
                        "enrolled": (device / "cert.pem").exists(), "needs_passphrase": not (device / "cert.pem").exists() or encrypted(device / "key.pem")}
            except ValueError as e:
                out["error"] = str(e)
        client = self.client
        out["status"] = client.status() if client else {"state": "disconnected"}
        return out

    def load(self, name, text):
        """Keep an invitation the person opened in the page next to the device folder it will create."""
        inv = join.parse(text, "the chosen file")
        stem = re.sub(r"[^A-Za-z0-9_-]", "_", Path(str(name)).stem)[:60] or inv["name"]
        path = self.folder / f"{stem}.acxinvite"
        if self.client:
            raise ValueError("disconnect before opening another invitation")
        if path.exists() and join.read(path)["name"] != inv["name"]:
            raise ValueError(f"{path.name} already holds an invitation for someone else; rename the file and open it again")
        if not path.exists() or "token" in inv:  # a new invitation for the same person replaces the used one
            write(path, text.encode(), secret=True)
        with self.lock:
            self.invitation = path
        return self.state()

    def connect(self, passphrase="", repeat=None):
        with self.lock:
            if self.client:
                raise ValueError("already connected or connecting; disconnect first")
            if not self.invitation:
                raise ValueError("open the invitation file your administrator sent first")
            inv, device = join.read(self.invitation), join.device_for(self.invitation)
            if self.apply:
                join.preflight("acxelin-vpn app")
            secret = passphrase.encode() if passphrase else None
            if join.must_enroll(inv, device):
                if not secret or repeat is None or passphrase != repeat:
                    raise ValueError("choose a passphrase for this device's key and type it twice; nothing was changed")
                join.enroll(inv, device, self.invitation, secret)
            elif encrypted(device / "key.pem"):
                try:
                    load_pem_private_key((device / "key.pem").read_bytes(), secret)
                except (TypeError, ValueError):
                    raise ValueError("that passphrase does not unlock this device's key; try again") from None
            self.client = Client(inv["gateway"], device, self.interface, inv.get("server_name"), self.apply, key_passphrase=secret)
            self.thread = threading.Thread(target=self.client.run, daemon=True)
            self.thread.start()
        return self.state()

    def disconnect(self):
        with self.lock:
            client, thread, self.client = self.client, self.thread, None
        if client:
            client.stop.set()
            thread.join(15)
            client.close()
        return self.state()

    def handle(self, method, path, body):
        try:
            if method == "GET" and path == "/api/state":
                return 200, self.state()
            if method == "POST" and path == "/api/invitation":
                if not isinstance(body.get("text"), str) or len(body["text"]) > 64_000:
                    raise ValueError("choose the .acxinvite file your administrator sent")
                return 200, self.load(body.get("name") or "invitation", body["text"])
            if method == "POST" and path == "/api/connect":
                fields = [body.get(k) for k in ("passphrase", "repeat")]
                if not isinstance(fields[0], str) or not isinstance(fields[1], (str, type(None))) or any(len(f or "") > 1024 for f in fields):
                    raise ValueError("enter the device key passphrase")
                return 200, self.connect(*fields)
            if method == "POST" and path == "/api/disconnect":
                return 200, self.disconnect()
            if method == "POST" and path == "/api/ticket":
                return 200, {"ticket": self.ticket()}
            if method == "POST" and path == "/api/quit" and self.on_quit:
                self.disconnect()
                return 200, {"stopping": True}
            return 404, {"error": "not found"}
        except (ValueError, OSError) as e:
            return 400, {"error": explain(e), "state": self.state()}
        except Exception as e:  # a failure must reach the page as words, never as a dropped request
            return 500, {"error": f"{e.__class__.__name__}: {explain(e)}", "state": self.state()}


def claim(folder, name):
    """One holder per name. Returns the open lock file to keep while this process runs, or None and what the running holder
    recorded (`name`.json), so a second launch reuses it instead of starting a client that fights over the tunnel."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    f = open(folder / f"{name}.lock", "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        try:
            return None, json.loads((folder / f"{name}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, None
    return f, None


def request(port, token, method, path, body=None, timeout=10):
    """Call a running window's API (the tray, and a second `vpn app`, use this)."""
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None,
                  {"Host": f"127.0.0.1:{port}", "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        r = c.getresponse()
        data = json.loads(r.read() or b"{}")
    except http.client.HTTPException as e:  # a service that stopped mid-answer is as unreachable as one that never answered
        raise ConnectionError(f"the VPN service stopped answering ({e.__class__.__name__})") from None
    finally:
        c.close()
    if r.status != 200:
        raise ValueError(data.get("error") or f"the VPN service answered {r.status}")
    return data


def serve(app, listen=("127.0.0.1", 0)):
    html = with_tour(resources.files(__package__).joinpath("app.html").read_bytes())
    backoff = Backoff()

    class App(Handler):
        csp, timeout = policy(html), HTTP_IDLE

        def route(self, method):
            port = self.server.server_address[1]
            hosts = (f"127.0.0.1:{port}", f"localhost:{port}")
            if self.headers.get("Host") not in hosts:
                return self.reply(421, {"error": "wrong host"})
            if self.headers.get("Origin") not in (None, *(f"http://{h}" for h in hosts)):
                return self.reply(403, {"error": "requests from other sites are refused"})
            path = self.path.split("?")[0]
            if method == "GET" and path == "/":
                return self.reply(200, html, "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.reply(404, {"error": "not found"})
            if backoff.blocked(self.client_address[0]):
                return self.reply(429, {"error": "too many wrong keys; wait a minute"})
            body = self.json_body(1 << 17)
            if method == "POST" and path == "/api/session":
                if not isinstance(body, dict) or not app.redeem(body.get("ticket")):
                    backoff.failed(self.client_address[0])
                    return self.reply(401, {"error": "this address was already used or has expired; run `acxelin-vpn app` (or open the tray icon) again"})
                return self.reply(200, {"token": app.token})
            if not self.authorised(app.token):
                backoff.failed(self.client_address[0])
                return self.reply(401, {"error": "open the address printed by `acxelin-vpn app` again"})
            if not isinstance(body, dict):
                return self.reply(*body)
            self.reply(*app.handle(method, path, body))
            if method == "POST" and path == "/api/quit" and app.on_quit:
                self.wfile.flush()
                app.on_quit()  # only once the answer has gone out, so the caller sees it before the service stops

    return ThreadingHTTPServer(listen, App)
