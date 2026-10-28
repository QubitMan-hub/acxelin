"""The Acxelin Readiness console: projects (scan a repository, track findings) and endpoints (grade live TLS and SSH servers).

Runs on acxelin-core's console mechanism; this module is only the product's pages, routes and state.
"""
import json
import re
import tempfile
import threading
import time
from pathlib import Path

from acxelin_core import console as core
from acxelin_core import shell
from acxelin_core.files import write

from . import cbom, endpoints, pipeline, workspace

MAX_TARGETS = 500


class Readiness:
    def __init__(self, home):
        self.home = Path(home)
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.store = workspace.ProjectStore(self.home / "workspace.json")
        self.history = self.home / "history.json"
        self.folder = None
        self.projects = []
        self.cache = None
        self.job = {"running": False, "stage": "", "error": None, "selected": 0, "last": None}
        self.ep = {"running": False, "error": None, "last": None}
        settings = self.home / "settings.json"
        if settings.exists():
            self.folder = Path(json.loads(settings.read_text())["directory"])
            self.reload()

    def reload(self):
        """The chosen folder's registered repositories, with the most recently scanned one selected."""
        self.projects = []
        for name in self.store.read()["registrations"].get(self.store.key(self.folder), []):
            try:
                self.projects.append(self.approved(name))
            except (OSError, ValueError):
                pass  # a stored name never grants access beyond today's chosen folder
        saved = [(a["finished"], i, a) for i, a in enumerate(self.store.assessment(p) for p in self.projects) if a]
        self.job.update(last=None, selected=0, error=None, stage="")
        if saved:
            _, self.job["selected"], self.job["last"] = max(saved, key=lambda s: s[:2])

    # --- first run and the repository folder

    def status(self, body):
        available = []
        if self.folder:
            try:
                available = sorted(p.name for p in self.folder.iterdir() if not p.name.startswith(".") and p.is_dir() and not p.is_symlink())[:200]
            except OSError:
                pass
        return 200, {"configured": bool(self.folder), "directory": str(self.folder or ""), "available": available, "example": str(Path.home() / "code"),
                     "projects": [{"id": i, "name": p.name} for i, p in enumerate(self.projects)], "selected": self.job["selected"]}

    def setup(self, body):
        d = body.get("directory")
        path = Path(d).expanduser().resolve() if isinstance(d, str) and d.strip() else None
        if not path or not path.is_dir():
            raise ValueError("Choose an existing folder: the one that holds the repositories you want to scan")
        write(self.home / "settings.json", json.dumps({"directory": str(path)}).encode(), secret=True)
        with self.lock:
            if self.job["running"]:
                raise ValueError("Wait for the running scan to finish, or stop it, before choosing another folder")
            self.folder = path
            self.reload()
        return 200, {"directory": str(path)}

    def approved(self, name):
        root = self.folder
        if not root or not isinstance(name, str) or not name or len(name) > 255 or Path(name).name != name or name.startswith(".") or "\\" in name:
            raise ValueError("Choose a repository inside the folder you set up")
        path = (root / name).resolve()
        if (root / name).is_symlink() or not path.is_relative_to(root) or not path.is_dir():
            raise ValueError("Choose a repository inside the folder you set up (symlinks and outside paths are refused)")
        return path

    # --- projects

    def register(self, body):
        path = self.approved(body.get("name"))
        self.store.register(self.folder, path.name)
        with self.lock:
            if path not in self.projects:
                self.projects.append(path)
            return 200, {"project": self.projects.index(path)}

    def selected(self, body):
        i = body.get("project")
        if type(i) is not int or not 0 <= i < len(self.projects):
            raise ValueError("Choose a registered project")
        return i, self.approved(self.projects[i].name)

    def project_status(self, body):
        with self.lock:
            state = dict(self.job)
        if self.projects and state["last"]:
            try:
                saved = self.store.assessment(self.projects[state["selected"]])
                if saved and saved["finished"] >= state["last"]["finished"]:
                    state["last"] = saved
            except (OSError, ValueError):
                state["workspace_error"] = "The saved workspace is unavailable; this session's results are kept."
        if state["last"]:
            state["last"] = {k: v for k, v in state["last"].items() if k != "relationships"}
        try:
            state["history"] = workspace.read_history(self.history)
        except (OSError, ValueError):
            state["history"] = []
        return 200, state

    def scan(self, body):
        i, path = self.selected(body)
        with self.lock:
            if self.job["running"]:
                raise ValueError("A project scan is already running")
            if self.cache is None:
                from .crawler import ParseCache
                self.cache = ParseCache()
            self.cancel.clear()
            self.job.update(running=True, stage="Preparing project", error=None, selected=i)

        def progress(stage):
            with self.lock:
                self.job["stage"] = stage

        def work():
            try:
                result = workspace.scan(path, history=self.history, progress=progress, exclude=[self.store.path], cancel=self.cancel, cache=self.cache)
                result["project_key"] = self.store.key(path)
                try:
                    result = self.store.save(path, result)
                except (OSError, ValueError):
                    result["notes"].append("The workspace could not be saved; this result is kept until the console closes. Check the folder's permissions and size.")
                with self.lock:
                    self.job["last"] = result
            except workspace.ScanStopped as error:
                with self.lock:
                    self.job["error"] = str(error)
            except Exception:  # source-sensitive failures are never echoed or logged with their contents
                with self.lock:
                    self.job["error"] = "The project scan failed. Check the folder's permissions and the source's syntax, then try again; `acxelin-readiness scan` shows details."
            finally:
                with self.lock:
                    self.job["running"] = False
        threading.Thread(target=work, daemon=True, name="project-scan").start()
        return 200, {"started": i}

    def select(self, body):
        i, path = self.selected(body)
        with self.lock:
            if self.job["running"]:
                raise ValueError("Wait for the running scan to finish, or stop it")
            self.job.update(last=self.store.assessment(path), selected=i, error=None, stage="")
        return 200, {"selected": i}

    def stop(self, body):
        with self.lock:
            if not self.job["running"]:
                raise ValueError("No project scan is running")
            self.cancel.set()
            self.job["stage"] = "Stopping at the next checkpoint"
        return 200, {"requested": True}

    def track(self, body):
        i, path = self.selected(body)
        with self.lock:
            result = self.store.track(path, body)
            if self.job["last"] and self.job["last"].get("project_key") == self.store.key(path):
                self.job["last"] = result
        return 200, {"saved": True}

    # --- endpoints

    @staticmethod
    def targets(body):
        raw = body.get("targets", "")
        if not isinstance(raw, (str, list)):
            raise ValueError("Targets must be text with one per line")
        items = raw if isinstance(raw, list) else re.split(r"[\n,]", raw)
        found = [str(t).strip() for t in items if str(t).strip()]
        if not found:
            raise ValueError("Enter at least one host, such as api.example.com:443")
        if len(found) > MAX_TARGETS:
            raise ValueError(f"At most {MAX_TARGETS} endpoints per scan")
        for t in found:
            endpoints.endpoint(t)
        return found

    def endpoint_status(self, body):
        with self.lock:
            return 200, dict(self.ep)

    def endpoint_scan(self, body):
        targets = self.targets(body)
        with self.lock:
            if self.ep["running"]:
                raise ValueError("An endpoint scan is already running")
            self.ep.update(running=True, error=None)

        def work():
            try:
                results = endpoints.scan(targets)
                with self.lock:
                    before = {e["target"]: e["grade"] for e in (self.ep["last"] or {}).get("endpoints", [])}
                    changes = [{"target": r["target"], "before": before[r["target"]], "after": r["grade"]}
                               for r in results if r["target"] in before and before[r["target"]] != r["grade"]]
                    self.ep["last"] = {"finished": time.time(), "targets": targets, "summary": endpoints.summary(results), "endpoints": results, "changes": changes,
                                       "outlook": endpoints.outlook(results)}
            except Exception:
                with self.lock:
                    self.ep["error"] = "The endpoint scan failed. Check the host names and your network, then try again."
            finally:
                with self.lock:
                    self.ep["running"] = False
        threading.Thread(target=work, daemon=True, name="endpoint-scan").start()
        return 200, {"started": len(targets)}

    def endpoint_cbom(self, body):
        targets = self.targets(body)
        with tempfile.TemporaryDirectory(prefix="readiness-endpoints-") as empty:
            r = pipeline.run(Path(empty), "endpoints", tls_targets=[t for t in targets if not t.startswith("ssh://")],
                             ssh_targets=[t.removeprefix("ssh://") for t in targets if t.startswith("ssh://")])
        return 200, {"cbom": cbom.build("endpoints", r.assets, r.artifacts, r.libraries, r.endpoints)}


def page():
    return shell.render((Path(__file__).parent / "console.html").read_text(encoding="utf-8"))


def build(home):
    r = Readiness(home)
    routes = {("GET", "/api/status"): r.status, ("POST", "/api/setup"): r.setup,
              ("POST", "/api/projects/register"): r.register, ("GET", "/api/projects/status"): r.project_status,
              ("POST", "/api/projects/select"): r.select, ("POST", "/api/projects/scan"): r.scan, ("POST", "/api/projects/cancel"): r.stop, ("POST", "/api/projects/track"): r.track,
              ("GET", "/api/endpoints/status"): r.endpoint_status, ("POST", "/api/endpoints/scan"): r.endpoint_scan,
              ("POST", "/api/endpoints/cbom"): r.endpoint_cbom}
    return core.App(page(), routes)


def run(home, port=8900, open_browser=True, host="127.0.0.1"):
    """Start the console and sign this browser in: the launch address carries a single-use ticket in its fragment."""
    import webbrowser
    app = build(home)
    server = core.start(app, home, port, host)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/#{app.sessions.ticket()}"
    if open_browser and webbrowser.open(url):
        print(f"Acxelin Readiness console is open in your browser (http://127.0.0.1:{port}). Press Ctrl+C to stop.")
    else:
        core.link_running(port, home)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0



