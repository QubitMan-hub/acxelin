"""The Acxelin VPN administrator console: Sites (each IPsec tunnel, its algorithms, its last key rotation and the peer's
certificate), People (invite someone, who is connected and since when, revoke someone) and Health.

Runs on acxelin-core's console mechanism; this module is only the product's page, routes and state. Sites and gateways are read
from the /status address they serve with `metrics = "HOST:PORT"`. A CA passphrase is held in memory for the life of the console
and never written anywhere; invitations go to the browser and are never written to disk, since they hold a one-time token.
"""
import functools
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from acxelin_core import console as core
from acxelin_core import shell
from acxelin_core.files import write
from acxelin_core.http import explain
from acxelin_core.pki import CA, CAError, encrypted

from . import __version__, audit, checks, join
from .ca_commands import CA_PASS_ENV

NAME = re.compile(r"[A-Za-z0-9@._-]{1,128}")
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
KINDS = ("site", "gateway")
MAX_SERVICES = 50


def task(fn):
    """Routes raise ValueError for a refused request; CA and file errors become the same, in words."""
    @functools.wraps(fn)
    def run(self, body):
        try:
            return fn(self, body)
        except (CAError, OSError) as e:
            raise ValueError(explain(e)) from None
    return run


def _text(body, key, what, pattern=None):
    v = body.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"Enter {what}")
    v = v.strip()
    if len(v) > 253 or pattern and not pattern.fullmatch(v):
        raise ValueError(f"{what[0].upper() + what[1:]} is not valid")
    return v


def _url(v):
    u = urllib.parse.urlsplit(v if isinstance(v, str) else "")
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("Enter the status address as http://HOST:PORT (the metrics setting of the site or gateway)")
    return v.rstrip("/")


class VPNConsole:
    def __init__(self, home, ca_dir=None):
        self.home = Path(home)
        self.ca_dir = Path(ca_dir) if ca_dir else self.home / "ca"
        self.passphrase = None
        self.lock = threading.Lock()
        given = os.environ.get(CA_PASS_ENV)  # a service's secret, so nobody types it into a browser
        if given and self._exists() and encrypted(self.ca_dir / "ca.key"):
            try:
                CA(self.ca_dir, given.encode()).signer
                self.passphrase = given.encode()
            except CAError:
                pass

    # --- files the console keeps: its settings and the services it reads

    def _load(self, name, default):
        try:
            return json.loads((self.home / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _save(self, name, data):
        self.home.mkdir(parents=True, exist_ok=True)
        write(self.home / name, json.dumps(data, indent=1).encode())

    def audit(self, action, detail):
        audit.record(self.ca_dir, action, **detail)

    def activity(self, n=15):
        return audit.recent(self.ca_dir, n)

    # --- the certificate authority

    def _exists(self):
        return (self.ca_dir / "ca.crt").exists()

    def _ca(self, sign=True):
        if not self._exists():
            raise ValueError(f"There is no certificate authority in {self.ca_dir} yet: create it with `acxelin-vpn ca init --dir {self.ca_dir}`")
        if sign and encrypted(self.ca_dir / "ca.key") and not self.passphrase:
            raise ValueError("The CA key is locked: unlock it with its passphrase")
        return CA(self.ca_dir, self.passphrase if sign else None)

    @task
    def status(self, body):
        if not self._exists():
            return 200, {"configured": False, "ca_dir": str(self.ca_dir)}
        ca = CA(self.ca_dir)
        return 200, {"configured": True, "name": ca.cert.subject.rfc4514_string().removeprefix("CN="), "algorithm": ca.algorithm,
                     "encrypted": encrypted(self.ca_dir / "ca.key"), "unlocked": self.passphrase is not None or not encrypted(self.ca_dir / "ca.key"),
                     "settings": self._load("settings.json", {}), "version": __version__}

    @task
    def create(self, body):
        name = _text(body, "name", "a name for the certificate authority")
        if self._exists():
            raise ValueError("A certificate authority already exists here")
        pw = body.get("passphrase")
        if pw is not None and not isinstance(pw, str):
            raise ValueError("The passphrase must be text")
        key = pw.encode() if pw else None
        CA.init(self.ca_dir, name, passphrase=key)
        ca = CA(self.ca_dir, key)
        ca.crl(7)
        with self.lock:
            self.passphrase = key
        self.audit("create", {"name": name})
        return 200, {"name": name, "algorithm": ca.algorithm}

    @task
    def unlock(self, body):
        pw = body.get("passphrase")
        if not isinstance(pw, str) or not pw:
            raise ValueError("Enter the CA passphrase")
        try:
            CA(self.ca_dir, pw.encode()).signer
        except CAError:
            raise ValueError("That passphrase does not open the CA key") from None
        self.passphrase = pw.encode()
        return 200, {"unlocked": True}

    def _certificate(self, records, serial):
        r = next((r for r in records if serial and r.serial == serial), None)
        return {"serial": r.serial, "common_name": r.common_name, "status": r.status, "not_after": r.not_after} if r else None

    # --- sites and gateways the console reads

    @task
    def add_service(self, body):
        kind = body.get("kind")
        if kind not in KINDS:
            raise ValueError("Choose site or gateway")
        name, url = _text(body, "name", "a name"), _url(body.get("url"))
        services = [s for s in self._load("services.json", []) if s["name"] != name]
        if len(services) >= MAX_SERVICES:
            raise ValueError(f"The console reads at most {MAX_SERVICES} sites and gateways")
        self._save("services.json", services + [{"kind": kind, "name": name, "url": url}])
        return 200, {"added": name}

    @task
    def remove_service(self, body):
        name = _text(body, "name", "a name")
        self._save("services.json", [s for s in self._load("services.json", []) if s["name"] != name])
        return 200, {"removed": name}

    @staticmethod
    def _fetch(url):
        try:
            with NO_PROXY.open(url + "/status", timeout=5) as r:
                data = json.loads(r.read(1 << 20))
            if not isinstance(data, dict):
                raise ValueError("not a status object")
            return data, None
        except (OSError, ValueError) as e:
            return None, f"cannot read {url}/status ({explain(e) if isinstance(e, OSError) else e}); is it running with metrics on?"

    def _services(self, kind):
        return [s for s in self._load("services.json", []) if s["kind"] == kind]

    @task
    def sites(self, body):
        records = CA(self.ca_dir).records() if self._exists() else []
        out = []
        for s in self._services("site"):
            data, error = self._fetch(s["url"])
            tunnels = []
            for peer, p in sorted((data or {}).items()):
                if peer.startswith("_") or not isinstance(p, dict):
                    continue
                t = p.get("tunnel") or {}
                children = t.get("children", [])
                tunnels.append({"peer": peer, "state": t.get("state", "no tunnel") if t else "no tunnel", "initiates": p.get("initiate"),
                                "protected": bool(t and t.get("state") == "ESTABLISHED" and t.get("ppk") and "ML_KEM" in t.get("key_exchange", "")
                                                  and any(c.get("state") == "INSTALLED" for c in children)),
                                "key_exchange": t.get("key_exchange"), "encryption": t.get("encryption"), "ppk": t.get("ppk"),
                                "last_rotation_s": p.get("keys_age_s"), "up_s": t.get("established_s"),
                                "bytes_in": sum(c.get("bytes_in", 0) for c in children), "bytes_out": sum(c.get("bytes_out", 0) for c in children),
                                "certificate": self._certificate(records, p.get("certificate"))})
            out.append({"name": s["name"], "url": s["url"], "error": error, "tunnels": tunnels})
        return 200, {"sites": out}

    # --- people

    @task
    def people(self, body):
        records = [r for r in (CA(self.ca_dir).records() if self._exists() else []) if r.kind == "client"]
        seen, gateways, history = {}, [], []
        for g in self._services("gateway"):
            data, error = self._fetch(g["url"])
            gw = (data or {}).get("_gateway") if isinstance((data or {}).get("_gateway"), dict) else {}
            gateways.append({"name": g["name"], "error": error, "up_s": int(time.time() - gw["started"]) if isinstance(gw.get("started"), (int, float)) else None})
            history += [e | {"gateway": g["name"]} for e in gw.get("history", []) if isinstance(e, dict)]
            for cn, c in (data or {}).items():
                if not cn.startswith("_") and isinstance(c, dict):
                    seen[cn] = c | {"gateway": g["name"]}
        now, out = time.time(), []
        for name in sorted({r.common_name for r in records} | set(seen)):
            mine = [r for r in records if r.common_name == name]
            c = seen.get(name)
            out.append({"name": name, "certificate": "valid" if any(r.status == "valid" for r in mine) else "revoked" if mine else "unknown",
                        "connected": bool(c and now - c.get("latest_handshake", 0) < 180), "agreed": bool(c),
                        "since": c.get("since") if c else None, "address": c.get("address") if c else None, "gateway": c.get("gateway") if c else None,
                        "bytes_in": c.get("rx_bytes") if c else None, "bytes_out": c.get("tx_bytes") if c else None,
                        "key_age_s": c.get("keys_age_s") if c else None,
                        "handshake_age_s": int(now - c["latest_handshake"]) if c and c.get("latest_handshake") else None})
        activity = sorted(self.activity(30) + history, key=lambda e: str(e.get("time", "")), reverse=True)[:30]
        return 200, {"people": out, "gateways": gateways, "activity": activity}

    @task
    def settings(self, body):
        enroll, gateway = _text(body, "enroll", "the enrollment service address"), _text(body, "gateway", "the gateway's address")
        server_name = body.get("server_name") or None
        if not enroll.startswith("https://"):
            raise ValueError("The enrollment service is the https:// address of `acxelin-vpn ca serve`")
        from acxelin_core.http import hostport
        hostport(gateway)
        if server_name is not None and not (isinstance(server_name, str) and NAME.fullmatch(server_name)):
            raise ValueError("The gateway's certificate name is not valid")
        self._save("settings.json", {"enroll": enroll, "gateway": gateway, "server_name": server_name})
        return 200, {"saved": True}

    @task
    def invite(self, body):
        name = _text(body, "name", "the person's name", NAME)
        hours = body.get("hours", 24)
        if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not 0 < hours <= 24 * 30:
            raise ValueError("An invitation lasts between a few minutes and 30 days (hours)")
        ca, s = self._ca(), self._load("settings.json", {})
        if not s.get("enroll") or not s.get("gateway"):
            raise ValueError("Set the enrollment service and the gateway's address first")
        data, expires = join.make(ca, name, s["enroll"], s["gateway"], s.get("server_name"), hours)
        self.audit("invite", {"name": name, "expires": expires})
        return 200, core.Download(f"{name}.acxinvite", data, "application/json")

    @task
    def revoke(self, body):
        name = _text(body, "name", "the person's name", NAME)
        ca = self._ca()
        valid = [r for r in ca.records() if r.kind == "client" and r.common_name == name and r.status == "valid"]
        if not valid:
            raise ValueError(f"{name} has no valid certificate to revoke")
        for r in valid:
            ca.revoke(r.serial)
        self.audit("revoke", {"name": name, "certificates": len(valid)})
        return 200, {"revoked": len(valid), "crl": str(self.ca_dir / "crl.pem")}

    # --- health

    @task
    def health(self, body):
        rows = [{k: r[k] for k in ("level", "message", "action")} for r in checks.prerequisites()]
        if self._exists():
            rows += [{"level": level, "message": message, "action": ""} for level, message in checks.ca(self.ca_dir)]
        for s in self._load("services.json", []):
            _, error = self._fetch(s["url"])
            rows.append({"level": "fail" if error else "ok", "message": error or f"{s['kind']} {s['name']} answers at {s['url']}", "action": ""})
        return 200, {"checks": rows, "version": __version__}


def page():
    return shell.render((Path(__file__).parent / "console.html").read_text(encoding="utf-8"))


def build(home, ca_dir=None):
    c = VPNConsole(home, ca_dir)
    routes = {("GET", "/api/status"): c.status, ("POST", "/api/ca/create"): c.create, ("POST", "/api/ca/unlock"): c.unlock, ("GET", "/api/sites"): c.sites,
              ("POST", "/api/services/add"): c.add_service, ("POST", "/api/services/remove"): c.remove_service,
              ("GET", "/api/people"): c.people, ("POST", "/api/people/settings"): c.settings, ("POST", "/api/people/invite"): c.invite,
              ("POST", "/api/people/revoke"): c.revoke, ("GET", "/api/health"): c.health}
    return core.App(page(), routes)


def run(home, port=8900, open_browser=True, ca_dir=None, host="127.0.0.1"):
    """Start the console and sign this browser in: the launch address carries a single-use ticket in its fragment."""
    import webbrowser
    app = build(home, ca_dir)
    server = core.start(app, home, port, host)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/#{app.sessions.ticket()}"
    if open_browser and webbrowser.open(url):
        print(f"Acxelin VPN console is open in your browser (http://127.0.0.1:{port}). Press Ctrl+C to stop.")
    else:
        core.link_running(port, home)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def cmd_console(a):
    import sys
    home = Path(a.home or os.environ.get("ACXELIN_VPN_HOME") or Path.home() / ".acxelin-vpn" / "console")
    if a.action == "link":
        try:
            if core.link_running(a.port, home) is None:
                print("acxelin-vpn: console link prints only to a terminal; run it in an interactive session", file=sys.stderr)
        except (OSError, ValueError) as e:
            sys.exit(f"acxelin-vpn: no console is running on port {a.port} ({e}); start one with `acxelin-vpn console`")
        return 0
    ca = a.ca or ("pki" if Path("pki/ca.crt").exists() else None)  # the folder the manual creates with `ca init --dir pki`
    return run(home, a.port, open_browser=not a.no_browser and not a.container, ca_dir=ca, host="0.0.0.0" if a.container else "127.0.0.1")


def add(sub):
    p = sub.add_parser("console", help="the administrator console in your browser: sites, people and health; `console link` prints a fresh address")
    p.set_defaults(func=cmd_console)
    p.add_argument("action", nargs="?", choices=["link"])
    p.add_argument("--port", type=int, default=8901, help="default: 8901")
    p.add_argument("--home", metavar="DIR", help="where the console keeps its settings, audit log and token (default: ~/.acxelin-vpn/console)")
    p.add_argument("--ca", metavar="DIR", help="the VPN's CA folder (default: HOME/ca)")
    p.add_argument("--container", action="store_true", help="inside a container: listen on every interface so a published port reaches it (publish it to 127.0.0.1 only)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser; print the launch address instead")
