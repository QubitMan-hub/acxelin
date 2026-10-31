"""The Acxelin TLS console: the certificate authority (create, issue, revoke, refresh the CRL), edges (status, connection test) and health.

Runs on acxelin-core's console mechanism; this module is only the product's pages, routes and state. A CA passphrase is held in
memory for the life of the console and is never written anywhere, so a restart locks an encrypted CA again.
"""
import datetime as dt
import functools
import io
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from acxelin_core import console as core
from acxelin_core import shell, tls
from acxelin_core.files import append, write
from acxelin_core.http import explain, hostport
from acxelin_core.pki import CA, CAError, encrypted
from cryptography import x509
from cryptography.x509.oid import NameOID

from . import __version__, checks, policies

NAME = re.compile(r"[A-Za-z0-9*._-]{1,253}")
MAX_EDGES = 50
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PQ_GROUPS = set(policies.PQC_GROUPS.split(":")) | {"MLKEM1024"}
KEYS = {"1.2.840.10045.2.1": "ECDSA", "1.2.840.113549.1.1.1": "RSA", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448"}


def task(fn):
    """Routes raise ValueError for a refused request; CA, TLS and file errors become the same, in words."""
    @functools.wraps(fn)
    def run(self, body):
        try:
            return fn(self, body)
        except (CAError, tls.TLSError, OSError) as e:
            raise ValueError(explain(e)) from None
    return run


def _text(body, key, what, limit=253):
    v = body.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"Enter {what}")
    if len(v.strip()) > limit:
        raise ValueError(f"{what[0].upper() + what[1:]} is too long")
    return v.strip()


class TLSConsole:
    def __init__(self, home, ca_dir=None):
        self.home = Path(home)
        self.ca_dir = Path(ca_dir) if ca_dir else self.home / "ca"
        self.passphrase = None
        self.lock = threading.Lock()
        given = os.environ.get("ACXELIN_TLS_CA_PASSPHRASE")  # a service's secret, so nobody types it into a browser
        if given and self._exists() and encrypted(self.ca_dir / "ca.key"):
            try:
                CA(self.ca_dir, given.encode()).signer
                self.passphrase = given.encode()
            except CAError:
                pass

    # --- audit

    def audit(self, action, detail):
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action, **detail})
        with self.lock:
            self.home.mkdir(parents=True, exist_ok=True)
            append(self.home / "audit.jsonl", line)

    def activity(self, n=12):
        try:
            with open(self.home / "audit.jsonl", encoding="utf-8", errors="replace") as f:
                lines = deque(f, n)
        except FileNotFoundError:
            return []
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out

    # --- the certificate authority

    def _exists(self):
        return (self.ca_dir / "ca.crt").exists()

    def _ca(self):
        if not self._exists():
            raise ValueError("There is no certificate authority yet: create one first")
        if encrypted(self.ca_dir / "ca.key") and not self.passphrase:
            raise ValueError("The CA key is locked: unlock it with its passphrase")
        return CA(self.ca_dir, self.passphrase)

    def _crl(self):
        f = self.ca_dir / "crl.pem"
        if not f.exists():
            return None
        crl = x509.load_pem_x509_crl(f.read_bytes())
        left = (crl.next_update_utc - dt.datetime.now(dt.timezone.utc)).total_seconds() / 86400
        return {"next_update": crl.next_update_utc.isoformat(), "days_left": round(left, 1)}

    @task
    def status(self, body):
        if not self._exists():
            return 200, {"configured": False}
        ca = CA(self.ca_dir)
        rows = ca.records()
        soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).isoformat()
        enc = encrypted(self.ca_dir / "ca.key")
        return 200, {"configured": True, "home": str(self.home), "name": next((str(a.value) for a in ca.cert.subject if a.oid == NameOID.COMMON_NAME), ""), "algorithm": ca.algorithm,
                     "encrypted": enc, "unlocked": bool(self.passphrase) or not enc, "crl": self._crl(),
                     "counts": {"valid": sum(r.status == "valid" for r in rows), "revoked": sum(r.status == "revoked" for r in rows),
                                "expiring": sum(r.status == "valid" and r.not_after < soon for r in rows)}, "activity": self.activity()}

    @task
    def create(self, body):
        name = _text(body, "name", "a name for the certificate authority", 120)
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
        return 200, {"name": name, "algorithm": ca.algorithm}

    @task
    def unlock(self, body):
        pw = body.get("passphrase")
        if not isinstance(pw, str) or not pw:
            raise ValueError("Enter the CA passphrase")
        if not self._exists():
            raise ValueError("There is no certificate authority yet: create one first")
        CA(self.ca_dir, pw.encode()).signer  # raises "wrong passphrase" without echoing it
        with self.lock:
            self.passphrase = pw.encode()
        return 200, {"unlocked": True}

    # --- certificates

    @task
    def certificates(self, body):
        if not self._exists():
            return 200, {"certificates": []}
        records = CA(self.ca_dir).records()
        current = {r.path: r.serial for r in records if r.path}
        rows = []
        for r in sorted(records, key=lambda r: r.not_after):
            row = {k: v for k, v in vars(r).items() if k != "path"}
            rows.append(row | {"has_files": bool(r.path) and current.get(r.path) == r.serial, "renewed": bool(r.path) and current[r.path] != r.serial})
        return 200, {"certificates": rows}

    @task
    def issue(self, body):
        ca = self._ca()
        kind = body.get("kind")
        if kind not in ("server", "client"):
            raise ValueError("Choose server or client")
        cn = _text(body, "common_name", "the name the certificate is for")
        names = body.get("names") or []
        names = [n.strip() for n in (re.split(r"[,\n]", names) if isinstance(names, str) else names) if isinstance(n, str) and n.strip()]
        for n in [cn, *names]:
            if not NAME.fullmatch(n) and not _is_ip(n):
                raise ValueError(f"{n!r} is not a valid name: use letters, digits, dots, dashes and underscores")
        days = body.get("days", 397)
        if type(days) is not int or not 1 <= days <= 3650:
            raise ValueError("Days must be a whole number from 1 to 3650")
        folder = Path("issued") / f"{re.sub(r'[^A-Za-z0-9.-]', '_', cn)}-{secrets.token_hex(3)}"
        _, rec = ca.issue(cn, kind, names, days, out=self.home / folder)
        self.audit("issue", {"serial": rec.serial, "common_name": cn, "kind": kind})
        where = self.home / folder
        return 200, {"serial": rec.serial, "common_name": cn, "kind": kind, "folder": folder.as_posix(), "files": ["chain.pem", "key.pem"],
                     "chain": str(where / "chain.pem"), "key": str(where / "key.pem")}

    @task
    def revoke(self, body):
        ca = self._ca()
        serial = _text(body, "serial", "the serial from the certificate list", 80)
        reason = body.get("reason") or "unspecified"
        if not isinstance(reason, str):
            raise ValueError("The reason must be text")
        try:
            ca.revoke(serial, reason)
            r = ca.find(serial)
        except CAError as e:
            raise ValueError(str(e) if "serial" in str(e).lower() else f"serial {serial}: {e}") from None
        self.audit("revoke", {"serial": r.serial, "common_name": r.common_name, "reason": reason})
        return 200, {"revoked": r.serial, "crl": self._crl()}

    @staticmethod
    def _files(r):
        """The serial of the certificate now in the record's folder, and the folder."""
        folder = Path(r.path)
        try:
            cert = x509.load_pem_x509_certificate((folder / "cert.pem").read_bytes())
        except (OSError, ValueError):
            raise ValueError(f"the files for {r.common_name} are no longer in {folder}") from None
        return format(cert.serial_number, "x"), folder

    def _record(self, ca, body):
        try:
            return ca.find(_text(body, "serial", "the serial from the certificate list", 80))
        except CAError as e:
            raise ValueError(str(e)) from None

    @task
    def renew(self, body):
        ca = self._ca()
        r = self._record(ca, body)
        if not r.path:
            raise ValueError("this certificate was signed from a request (CSR, EST or ACME); its key is with whoever asked for it, so renew it there")
        current = self._files(r)[0]
        if current != r.serial:
            raise ValueError(f"{r.common_name}'s folder already holds a newer certificate ({current}); renew that one")
        if encrypted(Path(r.path) / "key.pem"):
            raise ValueError(f"{r.common_name}'s key is encrypted with a passphrase the console does not hold: renew it with "
                             "`acxelin-tls ca renew --key-passphrase-env`, so the new key is encrypted too")
        _, new = ca.renew(r.serial, out=r.path)
        self.audit("renew", {"serial": r.serial, "new_serial": new.serial, "common_name": r.common_name})
        return 200, {"renewed": r.serial, "serial": new.serial, "not_after": new.not_after}

    @task
    def maintain(self, body):
        renewed, skipped = self._ca().maintain()
        self.audit("maintain", {"renewed": [r.serial for r in renewed]})
        return 200, {"renewed": [r.common_name for r in renewed], "skipped": [r.common_name for r in skipped], "crl": self._crl()}

    @task
    def download(self, body):
        """A zip with the certificate, its chain and the CA certificate; the private key only when asked for with a JSON true,
        never for a revoked certificate or an encrypted key, and every download is audited."""
        ca = CA(self.ca_dir) if self._exists() else self._ca()
        r = self._record(ca, body)
        with_key = body.get("key") is True
        if not r.path:
            raise ValueError("this certificate was signed from a request (CSR, EST or ACME); the console has no files for it")
        current, folder = self._files(r)
        if current != r.serial:
            raise ValueError(f"this certificate was renewed; its folder now holds {current}, download that one")
        if with_key and r.status == "revoked":
            raise ValueError("this certificate is revoked; its key is not handed out")
        if with_key and encrypted(folder / "key.pem"):
            raise ValueError("this key is encrypted with a passphrase; copy it from the CA machine")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name in ("cert.pem", "chain.pem") + (("key.pem",) if with_key else ()):
                z.writestr(name, (folder / name).read_bytes())
            z.writestr("ca.crt", ca.anchor.read_bytes())
        self.audit("download", {"serial": r.serial, "common_name": r.common_name, "key": with_key})
        return 200, core.Download(f"{r.common_name}-{r.serial[:8]}.zip", buf.getvalue(), "application/zip")

    @task
    def refresh(self, body):
        self._ca().crl(7)
        return 200, self._crl()

    # --- edges

    def _edges(self):
        f = self.home / "edges.json"
        return json.loads(f.read_text()) if f.exists() else []

    @task
    def add_edge(self, body):
        url = _text(body, "url", "the edge's metrics address, such as http://127.0.0.1:9100", 300).rstrip("/")
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Enter an http or https address, such as http://127.0.0.1:9100")
        with self.lock:
            edges = self._edges()
            if url not in edges:
                if len(edges) >= MAX_EDGES:
                    raise ValueError(f"At most {MAX_EDGES} edges")
                write(self.home / "edges.json", json.dumps(edges + [url]).encode())
        return 200, {"url": url}

    @task
    def remove_edge(self, body):
        url = _text(body, "url", "the edge to remove", 300)
        with self.lock:
            write(self.home / "edges.json", json.dumps([u for u in self._edges() if u != url]).encode())
        return 200, {"removed": url}

    @staticmethod
    def _fetch(url):
        """One edge's /status as routes with their quantum-safe handshake counts, or one error in words."""
        try:
            with NO_PROXY.open(url + "/status", timeout=3) as r:
                status = json.loads(r.read(1 << 20))
            if not isinstance(status, dict) or not all(isinstance(v, dict) for v in status.values()):
                raise ValueError("this address does not answer like an edge's /status")
            routes = []
            for name, v in status.items():
                groups = v.get("groups") if isinstance(v.get("groups"), dict) else {}
                routes.append({"name": name, **v, "quantum_safe": sum(c for g, c in groups.items() if g in PQ_GROUPS and isinstance(c, int))})
            return {"url": url, "routes": routes, "error": None}
        except (OSError, ValueError) as e:
            why = explain(e) if isinstance(e, OSError) else str(e)
            return {"url": url, "routes": [], "error": f"cannot read {url}/status: {why}; start the edge with --metrics HOST:PORT"}

    @task
    def edges(self, body):
        urls = self._edges()
        with ThreadPoolExecutor(max_workers=8) as pool:
            return 200, {"edges": list(pool.map(self._fetch, urls))}

    @task
    def test_edge(self, body):
        """Connect to host:port as a client of this CA: what was negotiated, or why it failed and what the server offers instead."""
        target = _text(body, "target", "the edge to test, as host:port", 300)
        host, port = hostport(target, "")
        if not host:
            raise ValueError("Enter host:port, such as localhost:8443")
        chosen = body.get("policy") or "strict"
        if chosen not in policies.POLICIES:
            raise ValueError("Choose strict, transition or cnsa2")
        name = body.get("server_name") or None
        if name is not None and not isinstance(name, str):
            raise ValueError("The certificate name must be text")
        if not self._exists():
            raise ValueError("There is no certificate authority yet: create one first; the test trusts its certificate")
        ca = CA(self.ca_dir)
        cert = key = None
        serial = body.get("client")
        r = None
        if serial:
            r = self._record(ca, {"serial": serial})
            if r.kind == "server":
                raise ValueError(f"{r.common_name} is a server certificate; choose a client certificate")
            if not r.path:
                raise ValueError("the console has no key for that certificate")
            folder = self._files(r)[1]
            if encrypted(folder / "key.pem"):
                raise ValueError("that client's key is encrypted; test it from the command line")
            cert, key = str(folder / "chain.pem"), str(folder / "key.pem")
        started = time.monotonic()
        out = {"target": target, "policy": chosen, "client": r.serial if r else None, "client_status": r.status if r else None}
        ctx = tls.client_context(policies.policy(chosen), ca.anchor, cert, key)
        try:
            with tls.connect(host, port, ctx, name, 5.0) as conn:
                out |= {"ok": True, **self._named(conn.info()), "ms": round((time.monotonic() - started) * 1000)}
                refused = self._accepted(conn)
                if refused:
                    out |= {"ok": False, "refused_after_handshake": True, "error": refused}
        except (tls.TLSError, OSError) as e:
            out |= {"ok": False, "error": explain(e) if isinstance(e, OSError) else str(e), "offers": self._probe(host, port, name),
                    "ms": round((time.monotonic() - started) * 1000)}
        finally:
            ctx.close()
        out["quantum_safe"] = out.get("group") in PQ_GROUPS
        self.audit("test", {"target": target, "ok": out["ok"], "client": out["client"]})
        return 200, out

    @staticmethod
    def _accepted(conn):
        """In TLS 1.3 the server checks a client certificate after the client's side of the handshake is done, so a refusal
        arrives on the first read: an alert, or the connection closing. Silence means the server is waiting for a request.
        An edge only dials its service after the handshake, and Windows takes about two seconds to report a refused connect."""
        try:
            data = conn.recv(timeout=3.0)
        except tls.TLSError as e:
            return None if "timed out" in str(e) else str(e)
        if data == b"":
            return ("the server closed the connection right after the handshake: either it refused the client certificate "
                    "(missing, untrusted or revoked), or the service behind it is down")
        return None

    @staticmethod
    def _named(info):
        return info | {"peer_key": KEYS.get(info.get("peer_key"), info.get("peer_key"))}

    @staticmethod
    def _probe(host, port, name):
        """What the server negotiates with an unverified, anything-goes client: tells 'classical only' from 'wrong CA'."""
        ctx = tls.client_context(policies.policy("transition"), verify=False)
        try:
            with tls.connect(host, port, ctx, name, 3.0) as c:
                return TLSConsole._named(c.info())
        except (tls.TLSError, OSError):
            return None
        finally:
            ctx.close()

    # --- health

    @task
    def health(self, body):
        rows = [{k: r[k] for k in ("level", "message", "action")} for r in checks.prerequisites()]
        if self._exists():
            rows += [{"level": level, "message": message, "action": ""} for level, message in checks.ca(self.ca_dir)]
        return 200, {"checks": rows, "version": __version__}


def _is_ip(s):
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def page():
    return shell.render((Path(__file__).parent / "console.html").read_text(encoding="utf-8"))


def build(home, ca_dir=None):
    t = TLSConsole(home, ca_dir)
    routes = {("GET", "/api/status"): t.status, ("POST", "/api/ca/create"): t.create, ("POST", "/api/ca/unlock"): t.unlock,
              ("GET", "/api/certificates"): t.certificates, ("POST", "/api/certificates/issue"): t.issue, ("POST", "/api/certificates/revoke"): t.revoke,
              ("POST", "/api/crl/refresh"): t.refresh, ("POST", "/api/certificates/renew"): t.renew,
              ("POST", "/api/certificates/maintain"): t.maintain, ("POST", "/api/certificates/download"): t.download, ("GET", "/api/edges"): t.edges, ("POST", "/api/edges/add"): t.add_edge,
              ("POST", "/api/edges/remove"): t.remove_edge, ("POST", "/api/edges/test"): t.test_edge, ("GET", "/api/health"): t.health}
    return core.App(page(), routes)


def run(home, port=8900, open_browser=True, ca_dir=None, host="127.0.0.1"):
    """Start the console and sign this browser in: the launch address carries a single-use ticket in its fragment."""
    import webbrowser
    app = build(home, ca_dir)
    server = core.start(app, home, port, host)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/#{app.sessions.ticket()}"
    if open_browser and webbrowser.open(url):
        print(f"Acxelin TLS console is open in your browser (http://127.0.0.1:{port}). Press Ctrl+C to stop.")
    else:
        core.link_running(port, home)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def cmd_console(a):
    import os
    import sys
    home = Path(a.home or os.environ.get("ACXELIN_TLS_HOME") or Path.home() / ".acxelin-tls")
    if a.action == "link":
        try:
            if core.link_running(a.port, home) is None:
                print("acxelin-tls: console link prints only to a terminal; run it in an interactive session", file=sys.stderr)
        except (OSError, ValueError) as e:
            sys.exit(f"acxelin-tls: no console is running on port {a.port} ({e}); start one with `acxelin-tls console`")
        return 0
    return run(home, a.port, open_browser=not a.no_browser and not a.container, ca_dir=a.ca, host="0.0.0.0" if a.container else "127.0.0.1")


def add(sub):
    p = sub.add_parser("console", help="open the console in your browser; `console link` prints a fresh launch address for a console already running")
    p.set_defaults(func=cmd_console)
    p.add_argument("action", nargs="?", choices=["link"])
    p.add_argument("--port", type=int, default=8900)
    p.add_argument("--home", metavar="DIR", help="where the console keeps the CA, issued certificates and its token (default: ~/.acxelin-tls)")
    p.add_argument("--ca", metavar="DIR", help="manage this CA folder (default: HOME/ca)")
    p.add_argument("--container", action="store_true", help="inside a container: listen on every interface so a published port reaches it (publish it to 127.0.0.1 only)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser; print the launch address instead")
