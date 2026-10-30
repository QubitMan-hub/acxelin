"""The Acxelin Readiness console: projects (scan a repository, track findings) and endpoints (grade live TLS and SSH servers).

Runs on acxelin-core's console mechanism; this module is only the product's pages, routes and state.
"""
import hashlib
import json
import math
import re
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

from acxelin_core import console as core
from acxelin_core import shell
from acxelin_core.files import write

from . import cbom, endpoints, evidence, owners, pipeline, remote, workspace
from .rank import Horizon

MAX_TARGETS = 500
WEIGHT = {"critical": 8, "high": 4, "medium": 2, "low": 1}
IMPORTANCE = {"critical": 4, "high": 3, "medium": 2, "": 2, "low": 1}  # a service with no importance given counts as medium
TOKEN = re.compile(r"[A-Za-z0-9_]{20,255}")


class Readiness:
    def __init__(self, home):
        self.home = Path(home)
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.store = workspace.ProjectStore(self.home / "workspace.json")
        self.history = self.home / "history.json"
        self.remote_dir, self.remote_file, self.token_file = self.home / "github", self.home / "github.json", self.home / "github-token"
        self.import_dir, self.import_file = self.home / "imports", self.home / "imports.json"
        self.folder = None
        self.projects = []
        self.cache = None
        self.job = {"running": False, "stage": "", "error": None, "selected": 0, "last": None}
        self.all = {"running": False, "done": 0, "total": 0, "current": "", "failed": []}
        self.github_api = remote.API
        self.ep_history = self.home / "endpoints-history.json"
        self.ep = {"running": False, "error": None, "last": None, "history": []}
        try:
            saved = json.loads(self.ep_history.read_text()) if self.ep_history.exists() else []
            number = lambda v, top: type(v) in (int, float) and math.isfinite(v) and 0 <= v <= top
            self.ep["history"] = [r for r in saved if isinstance(r, dict) and number(r.get("finished"), 2**33) and (r.get("score") is None or number(r.get("score"), 100))][-30:] \
                if isinstance(saved, list) else []
        except (OSError, ValueError):
            pass  # a damaged history starts again; it holds no findings
        settings = self.home / "settings.json"
        if settings.exists():
            self.folder = Path(json.loads(settings.read_text())["directory"])
        self.reload()

    def reload(self):
        """The chosen folder's registered repositories, with the most recently scanned one selected."""
        self.projects = []
        for name in self.store.read()["registrations"].get(self.store.key(self.folder), []) if self.folder else []:
            try:
                self.projects.append(self.approved(name))
            except (OSError, ValueError):
                pass  # a stored name never grants access beyond today's chosen folder
        self.projects += [self.remote_dir / name for name in self.remotes()]
        self.projects += [self.import_dir / name for name in self.imports()]
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
                     "projects": [{"id": i, "name": self.label(p)} for i, p in enumerate(self.projects)], "selected": self.job["selected"],
                     "github_token": self.token_file.exists()}

    def setup(self, body):
        d = body.get("directory")
        try:
            path = Path(d).expanduser().resolve() if isinstance(d, str) and d.strip() else None
        except (RuntimeError, OSError):
            path = None  # ~someone for an unknown user, or a path the system refuses
        if not path or not path.is_dir():
            raise ValueError("Choose an existing folder: the one that holds the repositories you want to scan")
        with self.lock:
            if self.job["running"]:
                raise ValueError("Wait for the running scan to finish, or stop it, before choosing another folder")
            write(self.home / "settings.json", json.dumps({"directory": str(path)}).encode(), secret=True)
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

    # --- GitHub repositories, downloaded into the console's own folder for each scan

    def remotes(self):
        """The saved GitHub links by folder name; a damaged file starts again rather than stopping the console."""
        try:
            saved = json.loads(self.remote_file.read_text()) if self.remote_file.exists() else {}
            return {k: v for k, v in saved.items() if isinstance(k, str) and isinstance(v, str) and remote.parse(v)}
        except (OSError, ValueError, AttributeError):
            return {}

    def label(self, path):
        if path.parent == self.import_dir:
            return "Imported: " + self.imports().get(path.name, path.name)
        return "github.com/" + remote.label(self.remotes()[path.name]) if path.parent == self.remote_dir else path.name

    # --- CBOMs from other tools, kept owner-only in the console's folder

    def imports(self):
        try:
            saved = json.loads(self.import_file.read_text()) if self.import_file.exists() else {}
            return {k: v for k, v in saved.items() if isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[a-z0-9]{1,40}-[0-9a-f]{8}\.json", k)}
        except (OSError, ValueError, AttributeError):
            return {}

    def import_cbom(self, body):
        name, bom = body.get("name"), body.get("cbom")
        if not isinstance(name, str) or not name.strip() or len(name) > 200:
            raise ValueError("Give the CBOM a name of up to 200 characters, such as its file name")
        if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components", []), list):
            raise ValueError("Choose a CycloneDX CBOM: a JSON file with bomFormat CycloneDX and a list of components")
        slug = re.sub(r"[^a-z0-9]+", "", name.lower())[:40] or "cbom"
        file = f"{slug}-{hashlib.sha256(name.strip().encode()).hexdigest()[:8]}.json"
        with self.lock:
            if self.job["running"]:
                raise ValueError("Wait for the running scan to finish, or stop it")
            known = self.imports()
            if file not in known and len(known) >= 200:
                raise ValueError("The console keeps at most 200 imported CBOMs")
            write(self.import_dir / file, json.dumps(bom).encode(), secret=True)
            write(self.import_file, json.dumps(known | {file: name.strip()}).encode(), secret=True)
            path = self.import_dir / file
            if path not in self.projects:
                self.projects.append(path)
            return 200, {"project": self.projects.index(path)}

    def github(self, body):
        url = body.get("url")
        owner, repo, ref = remote.parse(url)
        exact = f"{owner}/{repo}" + (f"@{ref}" if ref else "")  # branches differ by case; Windows folders do not
        name = f"{owner}--{repo}-{hashlib.sha256(exact.encode()).hexdigest()[:8]}"
        with self.lock:
            known = self.remotes()
            if name not in known:
                if len(known) >= 200:
                    raise ValueError("The console keeps at most 200 GitHub repositories")
                write(self.remote_file, json.dumps(known | {name: url.strip()}).encode(), secret=True)
            path = self.remote_dir / name
            if path not in self.projects:
                self.projects.append(path)
            return 200, {"project": self.projects.index(path)}

    def token(self, body):
        value = body.get("token")
        if value == "":
            self.token_file.unlink(missing_ok=True)
            return 200, {"saved": False}
        if not isinstance(value, str) or not TOKEN.fullmatch(value):
            raise ValueError("Paste a GitHub access token: letters, digits and underscores only, such as github_pat_…")
        write(self.token_file, value.encode(), secret=True)
        return 200, {"saved": True}

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
        p = self.projects[i]
        if p.parent == self.import_dir:
            if p.name not in self.imports():
                raise ValueError("Choose a registered project")
            return i, p
        if p.parent == self.remote_dir:
            if p.name not in self.remotes():
                raise ValueError("Choose a registered project")
            return i, p
        return i, self.approved(p.name)

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
        self.begin(i)

        def work():
            try:
                self.scan_one(path)
            finally:
                with self.lock:
                    self.job["running"] = False
        threading.Thread(target=work, daemon=True, name="project-scan").start()
        return 200, {"started": i}

    def begin(self, i):
        with self.lock:
            if self.job["running"]:
                raise ValueError("A project scan is already running")
            if self.cache is None:
                from .crawler import ParseCache
                self.cache = ParseCache()
            self.cancel.clear()
            self.job.update(running=True, stage="Preparing project", error=None, selected=i)

    def scan_one(self, path):
        """Scan or re-read one project and save it; a failure is kept in job["error"], never raised."""
        def progress(stage):
            with self.lock:
                self.job["stage"] = stage
        try:
            name = None
            if path.parent == self.remote_dir:
                progress("Downloading from GitHub")
                url = self.remotes()[path.name]
                remote.fetch(url, path, token=self.token_file.read_text().strip() if self.token_file.exists() else None)
                name = remote.label(url)
            if path.parent == self.import_dir:
                progress("Reading the imported CBOM")
                result = workspace.imported(path, self.imports()[path.name])
            else:
                horizon = Horizon(secrets=owners.secrets(self.store.owner_rules(path)))
                result = workspace.scan(path, history=self.history, progress=progress, exclude=[self.store.path], cancel=self.cancel, cache=self.cache, name=name, horizon=horizon)
            result["project_key"] = self.store.key(path)
            try:
                result = self.store.save(path, result)
            except (OSError, ValueError):
                result["notes"].append("The workspace could not be saved; this result is kept until the console closes. Check the folder's permissions and size.")
            with self.lock:
                self.job["last"] = result
        except (workspace.ScanStopped, remote.Refused) as error:
            with self.lock:
                self.job["error"] = str(error)
        except Exception:  # source-sensitive failures are never echoed or logged with their contents
            with self.lock:
                self.job["error"] = "The project scan failed. Check the folder's permissions and the source's syntax, then try again; `acxelin-readiness scan` shows details."

    # --- every project at once

    def scan_all(self, body):
        """Add every repository in the chosen folder, then scan all projects one after another."""
        if self.folder:
            for name in self.status({})[1]["available"]:
                try:
                    self.register({"name": name})
                except (OSError, ValueError):
                    pass
        with self.lock:
            targets = list(enumerate(self.projects))
        if not targets:
            raise ValueError("Add a repository first: choose a folder, a GitHub link or an organisation")
        self.begin(targets[0][0])
        self.all = {"running": True, "done": 0, "total": len(targets), "current": "", "failed": []}

        def work():
            try:
                for i, path in targets:
                    if self.cancel.is_set():
                        break
                    with self.lock:
                        self.all["current"], self.job["selected"], self.job["error"] = self.label(path), i, None
                    self.scan_one(path)
                    with self.lock:
                        if self.job["error"]:
                            self.all["failed"].append({"name": self.label(path), "error": self.job["error"]})
                        self.all["done"] += 1
            finally:
                with self.lock:
                    self.job["running"] = self.all["running"] = False
                    self.all["current"] = ""
        threading.Thread(target=work, daemon=True, name="scan-all").start()
        return 200, {"started": len(targets)}

    def github_org(self, body):
        token = self.token_file.read_text().strip() if self.token_file.exists() else None
        links = remote.organisation(body.get("org"), token=token, api=self.github_api)
        added = [self.github({"url": u})[1]["project"] for u in links]
        return 200, {"added": len(added), "projects": added}

    def overview(self, body):
        """Every project's latest result side by side, findings by business service across them, and the scheduled scans."""
        with self.lock:
            projects, scan_all = list(enumerate(self.projects)), dict(self.all)
        saved, rows, services, libraries = self.store.read()["projects"], [], {}, {}
        for i, path in projects:
            record = saved.get(self.store.key(path))
            if not record:
                rows.append({"id": i, "name": self.label(path), "scanned": False})
                continue
            v = workspace.ProjectStore.view(record, graph=False)
            live = [a for a in v["assets"] if not a["test_only"]]
            cmp = v.get("comparison") or {}
            rows.append({"id": i, "name": self.label(path), "scanned": True, "finished": v["finished"], "score": v["summary"].get("score"),
                         "tiers": dict(Counter(a["tier"] for a in live)), "new": cmp.get("new") if cmp.get("baseline") else None,
                         "gone": cmp.get("not_observed") if cmp.get("baseline") else None})
            for a in live:
                hint = a.get("owner_hint") or {}
                if hint.get("service") and a["tier"] != "ok":
                    s = services.setdefault(hint["service"], {"service": hint["service"], "critical": 0, "high": 0, "medium": 0, "low": 0, "projects": set(), "importance": ""})
                    s[a["tier"]] += 1
                    s["projects"].add(self.label(path))
                    s["importance"] = max(s["importance"], hint.get("importance", ""), key=lambda x: IMPORTANCE[x] if x else 0)
            for x in v.get("libraries", []):
                lib = libraries.setdefault((x["ecosystem"], x["name"]), {**x, "projects": set()})
                lib["projects"].add(self.label(path))
        for s in services.values():
            s["risk"] = IMPORTANCE.get(s["importance"], 2) * sum(WEIGHT[k] * s[k] for k in WEIGHT)
        ranked = sorted(({**s, "projects": sorted(s["projects"])} for s in services.values()),
                        key=lambda s: (-s["risk"], -s["critical"], -s["high"], s["service"]))
        libs = sorted(({**x, "projects": sorted(x["projects"])} for x in libraries.values()), key=lambda x: (x["pq"], -len(x["projects"]), x["name"]))
        return 200, {"projects": rows, "services": ranked, "libraries": libs, "scan_all": scan_all, "watch": watch_runs(self.home)}

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

    def owners(self, body):
        i, path = self.selected(body)
        text = body.get("csv")
        rules = [] if text == "" else owners.from_csv(text)
        with self.lock:
            n = self.store.set_owners(path, rules)
            if self.job["last"] and self.job["last"].get("project_key") == self.store.key(path):
                self.job["last"] = self.store.assessment(path)
        return 200, {"rules": n}

    def project_csv(self, body):
        i, path = self.selected(body)
        last = self.store.assessment(path)
        if not last:
            raise ValueError("Scan this repository first")
        rows = [[a["name"], a["algorithm"], a["tier"], a["action"] or a["why"], "; ".join(f"{f}:{n}" for f, n in a["locations"][:50]),
                 ", ".join(a.get("seen", [])), a.get("confidence_level") or "", ", ".join(a.get("missing", [])),
                 a["tracking"]["owner"] or (f"{a['owner_hint']['owner']} ({a['owner_hint']['source']})" if a.get("owner_hint") else ""),
                 (a.get("owner_hint") or {}).get("service", ""), a["tracking"]["status"], a["tracking"]["due"]] for a in last["assets"] if not a["test_only"]]
        return 200, {"csv": evidence.csv_text(["Asset", "Algorithm", "Priority", "What to do", "Places", "Seen as", "Confidence", "Not seen",
                                               "Owner", "Service", "Status", "Due"], rows)}

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
                    s = self.ep["last"]["summary"]
                    self.ep["history"] = self.ep["history"][-29:] + [{"finished": self.ep["last"]["finished"], "score": s["score"], "coverage": s["coverage"], "endpoints": s["endpoints"]}]
                    try:
                        write(self.ep_history, json.dumps(self.ep["history"]).encode(), secret=True)
                    except OSError:
                        pass  # this session still shows the trend
            except Exception:
                with self.lock:
                    self.ep["error"] = "The endpoint scan failed. Check the host names and your network, then try again."
            finally:
                with self.lock:
                    self.ep["running"] = False
        threading.Thread(target=work, daemon=True, name="endpoint-scan").start()
        return 200, {"started": len(targets)}

    def endpoint_csv(self, body):
        with self.lock:
            last = self.ep["last"]
        if not last:
            raise ValueError("Check endpoints first")
        c = lambda r, k: (r.get("certificate") or {}).get(k, "")
        return 200, {"csv": evidence.csv_text(["Endpoint", "Grade", "Negotiated", "Certificate key", "Expires", "Issuer"],
                                              [[r["target"], r["grade"], r.get("negotiated") or r.get("error") or "", c(r, "key"), c(r, "expires"), c(r, "issuer")]
                                               for r in last["endpoints"]])}

    def endpoint_cbom(self, body):
        targets = self.targets(body)
        with tempfile.TemporaryDirectory(prefix="readiness-endpoints-") as empty:
            r = pipeline.run(Path(empty), "endpoints", tls_targets=[t for t in targets if not t.startswith("ssh://")],
                             ssh_targets=[t.removeprefix("ssh://") for t in targets if t.startswith("ssh://")])
        return 200, {"cbom": cbom.build("endpoints", r.assets, r.artifacts, r.libraries, r.endpoints)}


def watch_runs(home):
    """The scheduled scans `acxelin-readiness watch` recorded for this console, newest first."""
    try:
        runs = json.loads((Path(home) / "watch.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [r for r in runs if isinstance(r, dict)][::-1][:50] if isinstance(runs, list) else []


def page():
    return shell.render((Path(__file__).parent / "console.html").read_text(encoding="utf-8"))


def build(home):
    r = Readiness(home)
    routes = {("GET", "/api/status"): r.status, ("POST", "/api/setup"): r.setup,
              ("POST", "/api/projects/register"): r.register, ("POST", "/api/projects/github"): r.github, ("POST", "/api/projects/import"): r.import_cbom, ("POST", "/api/projects/owners"): r.owners, ("POST", "/api/github/token"): r.token, ("GET", "/api/projects/status"): r.project_status,
              ("POST", "/api/projects/select"): r.select, ("POST", "/api/projects/scan"): r.scan, ("POST", "/api/projects/cancel"): r.stop, ("POST", "/api/projects/track"): r.track,
              ("GET", "/api/endpoints/status"): r.endpoint_status, ("POST", "/api/endpoints/scan"): r.endpoint_scan,
              ("POST", "/api/endpoints/cbom"): r.endpoint_cbom, ("POST", "/api/projects/csv"): r.project_csv,
              ("POST", "/api/projects/scan-all"): r.scan_all, ("POST", "/api/projects/github-org"): r.github_org, ("GET", "/api/overview"): r.overview, ("POST", "/api/endpoints/csv"): r.endpoint_csv}
    return core.App(page(), routes, limits={("POST", "/api/projects/import"): 16_000_000, ("POST", "/api/projects/owners"): 2_000_000})  # a CBOM can be large; read only after sign-in


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



