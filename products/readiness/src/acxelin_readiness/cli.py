import argparse
import os
import shutil
import sys
import tempfile
import tomllib
import warnings
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning

from . import __version__, pipeline, report, image, inventory, compliance, remote
from .rank import Horizon, TIERS
from .report import write_results
from .detectors import Scope

SETTINGS = {"exclude": list, "include_vendor": bool, "tls": list, "ssh": list, "shelf_life": (int, float), "migration": (int, float),
            "crqc_year": int, "threshold": (int, float), "fail_on": str, "name": str, "policy": dict}


START = """Acxelin Readiness: find the cryptography a quantum computer breaks, and what to migrate first.

Start here:
  acxelin-readiness scan PATH     find the cryptography in a repository, then open readiness-out/report.html
  acxelin-readiness console       scan repositories and endpoints from your browser
  acxelin-readiness grade HOST    grade a TLS or SSH endpoint from A to F
  acxelin-readiness doctor        check what this machine can scan
  acxelin-readiness --help        every command"""


def main(argv=None):
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    ap = argparse.ArgumentParser(prog="acxelin-readiness", description="Cryptographic inventory (CycloneDX 1.6 CBOM) and quantum migration planner")
    ap.add_argument("--version", action="version", version=f"acxelin-readiness {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="send the pipeline over a repository and/or live TLS and SSH endpoints")
    s.add_argument("path", nargs="?", default=None, help="folder to scan, a GitHub link (https://github.com/owner/repo; GITHUB_TOKEN for private ones), or a container image saved with `docker save` or as an OCI archive (default: current folder, or none if only --tls/--ssh are given)")
    s.add_argument("--tls", action="append", default=[], metavar="HOST:PORT", help="probe a live TLS endpoint, including which key-exchange groups it accepts (repeatable)")
    s.add_argument("--ssh", action="append", default=[], metavar="HOST[:PORT]", help="read a live SSH server's algorithm lists (repeatable)")
    s.add_argument("--pcap", action="append", default=[], metavar="FILE",
                   help="read TLS and SSH handshakes from a packet capture (.pcap or .pcapng): what clients and servers actually negotiated (repeatable)")
    s.add_argument("--changed-since", metavar="GIT_REF", help="scan only files changed since this git ref (and uncommitted ones): fast CI checks on a pull request")
    s.add_argument("--baseline", metavar="CBOM", help="previous cbom.json; report what is new and gate CI only on new findings")
    s.add_argument("-o", "--out", default="readiness-out")
    s.add_argument("--name", help="project name for the CBOM")
    s.add_argument("--config", metavar="FILE", help="settings file (default: .acxelin-readiness.toml in the scanned folder, if present)")
    s.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="leave out matching files and folders: a name glob (generated, *.min.js) or a path glob from the root (docs/old/*); repeatable")
    s.add_argument("--shelf-life", type=float, help="years the protected data must stay secret (Mosca X, default 10)")
    s.add_argument("--migration", type=float, help="years your migration will take (Mosca Y, default 5)")
    s.add_argument("--crqc-year", type=int, help="assumed year a cryptographically relevant quantum computer exists (default 2035)")
    s.add_argument("--threshold", type=float, help="verify confidence needed to accept a finding (default 0.6)")
    s.add_argument("--include-vendor", action="store_true", help="also scan vendor/, node_modules/ and similar")
    s.add_argument("--fail-on", choices=TIERS[:-1], help="exit 2 if any asset is at this tier or worse (for CI)")
    s.add_argument("--policy", action="append", default=[], choices=compliance.PROFILES, metavar="PROFILE",
                   help=f"check against a published transition standard (repeatable): {', '.join(compliance.PROFILES)}; own rules go in [policy] in .acxelin-readiness.toml")
    s.add_argument("--as-of", type=int, metavar="YEAR", help="judge policy deadlines as of this year (default: this year)")
    s.add_argument("--fail-on-policy", action="store_true", help="exit 2 if any policy rule is already broken (deadline passed or none)")
    s.add_argument("-q", "--quiet", action="store_true")
    m = sub.add_parser("merge", help="merge the CBOMs of many systems into one organisation inventory and dashboard")
    m.add_argument("cboms", nargs="+", metavar="CBOM", help="cbom.json files, or folders searched for them (other tools' CBOMs work too)")
    m.add_argument("--name", default="Organisation", help="organisation name for the inventory")
    m.add_argument("-o", "--out", default="inventory")
    m.add_argument("--fail-on", choices=TIERS[:-1], help="exit 2 if any system has an asset at this tier or worse")
    m.add_argument("--history", metavar="FILE", help="JSON-lines file of earlier runs: this run is added and the dashboard charts readiness over time")
    m.add_argument("-q", "--quiet", action="store_true")
    g = sub.add_parser("grade", help="grade TLS and SSH endpoints A to F for post-quantum key exchange, with their certificates")
    g.add_argument("targets", nargs="+", help="host (port 443), host:port, ssh://host (port 22), or .txt files with one per line")
    g.add_argument("--json", metavar="FILE")
    g.add_argument("--html", metavar="FILE")
    g.add_argument("--workers", type=int, default=16)
    g.add_argument("--timeout", type=float, default=8.0)
    r = sub.add_parser("report", help="compliance evidence: NIST IR 8547 and CNSA 2.0 status of certificates, endpoints and CBOMs")
    r.add_argument("--certs", metavar="DIR", help="a folder of PEM certificates")
    r.add_argument("--targets", nargs="+", metavar="TARGET", help="endpoints to grade now: host, host:port, ssh://host, or .txt files with one per line")
    r.add_argument("--cbom", action="append", default=[], metavar="PATH", help="a scan's output folder or any cbom.json (repeatable): code, or another product's exported inventory")
    r.add_argument("-o", "--out", default="readiness-report")
    r.add_argument("--timeout", type=float, default=8.0)
    sub.add_parser("doctor", help="check what this machine can scan")
    k = sub.add_parser("console", help="open the console in your browser; `console link` prints a fresh launch address for a console already running")
    k.add_argument("action", nargs="?", choices=["link"])
    k.add_argument("--port", type=int, default=8900)
    k.add_argument("--home", metavar="DIR", help="where the console keeps its settings, workspace and token (default: ~/.acxelin-readiness)")
    k.add_argument("--container", action="store_true", help="inside a container: listen on every interface so a published port reaches it (publish it to 127.0.0.1 only)")
    k.add_argument("--no-browser", action="store_true", help="do not open a browser; print the launch address instead")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        raise SystemExit(1 if e.code == 2 else e.code)
    if not a.cmd:
        print(START)
        return 0

    if a.cmd == "merge":
        return merge(a)
    if a.cmd == "grade":
        return grade(a)
    if a.cmd == "report":
        return report_command(a)
    if a.cmd == "doctor":
        return doctor()
    if a.cmd == "console":
        return console(a)

    link = a.path and a.path.startswith(("https://github.com/", "github.com/", "http://github.com/"))
    cfg = settings(a.config, None if link or a.path is None and (a.tls or a.ssh or a.pcap) else Path(a.path or "."))  # a downloaded repository's settings are not trusted
    a.exclude = cfg.get("exclude", []) + a.exclude
    a.tls = cfg.get("tls", []) + a.tls
    a.ssh = cfg.get("ssh", []) + a.ssh
    a.include_vendor = a.include_vendor or cfg.get("include_vendor", False)
    for k, default in (("shelf_life", 10), ("migration", 5), ("crqc_year", 2035), ("threshold", 0.6), ("fail_on", None), ("name", None)):
        if getattr(a, k) is None:
            setattr(a, k, cfg.get(k, default))
    policy = dict(cfg.get("policy", {}))
    problems = compliance.check(policy)
    if problems:
        sys.exit("acxelin-readiness: " + "; ".join(problems))
    policy["profiles"] = list(dict.fromkeys(policy.get("profiles", []) + a.policy))
    if a.as_of:
        policy["as_of"] = a.as_of
    a.fail_on_policy = a.fail_on_policy or policy.get("fail", False)
    if a.fail_on is not None and a.fail_on not in TIERS[:-1]:
        sys.exit(f"acxelin-readiness: fail_on must be one of {', '.join(TIERS[:-1])}")
    targets_only = a.path is None and (a.tls or a.ssh or a.pcap)
    if link:
        try:
            owner, repo, _ = remote.parse(a.path)
            downloaded = Path(tempfile.mkdtemp(prefix="readiness-github-"))
            root = remote.fetch(a.path, downloaded / repo, token=os.environ.get("GITHUB_TOKEN"))
        except ValueError as e:
            sys.exit(f"acxelin-readiness: {e}")
        a.name = a.name or f"{owner}/{repo}"
    else:
        downloaded = None
        root = Path(tempfile.mkdtemp()) if targets_only else Path(a.path or ".").resolve()
    if not root.exists():
        sys.exit(f"acxelin-readiness: {a.path} does not exist")
    name = a.name or ((a.tls + a.ssh + [Path(p).name for p in a.pcap])[0] if targets_only else root.name)
    if a.baseline:
        try:
            pipeline.load_baseline(a.baseline)
        except (OSError, ValueError, AttributeError) as e:
            sys.exit(f"acxelin-readiness: cannot read the baseline {a.baseline}: {e}")
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.exit(f"acxelin-readiness: cannot write to {out}: {e}")
    only = changed_files(root, a.changed_since) if a.changed_since else None
    h = Horizon(a.shelf_life, a.migration, a.crqc_year)
    unpacked, notes = None, []
    if image.is_image(root):
        unpacked = Path(tempfile.mkdtemp(prefix="readiness-image-"))
        notes = image.unpack(root, unpacked)
        name = a.name or root.name.split(".")[0]
    try:
        r = pipeline.run(unpacked or root, name, a.tls, h, a.threshold, Scope(a.include_vendor, tuple(a.exclude), only), a.ssh, a.baseline, a.pcap)
    finally:
        for folder in (unpacked, downloaded):
            if folder:
                shutil.rmtree(folder, ignore_errors=True)
    r.notes[:0] = notes
    if only is not None:
        r.notes.insert(0, f"incremental scan: {len(only)} file(s) changed since {a.changed_since}; the rest of the repository was not read")
    if any(policy.get(k) for k in ("profiles", "forbid", "min_bits", "require_hybrid")):
        r.compliance = compliance.evaluate(r.assets, r.endpoints, policy)
    try:
        write_results(out, name, r)
    except OSError as e:
        sys.exit(f"acxelin-readiness: cannot write to {out}: {e}")
    if not a.quiet:
        print(report.terminal(r))
        print(f"\nwrote {out / 'cbom.json'}, {out / 'report.html'}, {out / 'readiness.sarif'}, {out / 'findings.json'}, {out / 'relationships.json'}")
    if a.fail_on_policy and r.compliance and not r.compliance["passed"]:
        if not a.quiet:
            print(f"\nfailing: {r.compliance['overdue']} policy rule(s) already broken")
        sys.exit(2)
    if a.fail_on:
        bad = TIERS[:TIERS.index(a.fail_on) + 1]
        hits = [x for x in r.assets if x.tier in bad and (x.new_files or not a.baseline)]
        if hits:
            if not a.quiet:
                print(f"\nfailing: {len(hits)} asset(s) at {a.fail_on} or worse" + (" introduced since the baseline" if a.baseline else ""))
            sys.exit(2)
    return 0


def changed_files(root, ref):
    """Paths changed since `ref` plus uncommitted and untracked ones, relative to `root`, from git."""
    import subprocess
    run = lambda *args: subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.splitlines()
    try:
        top = Path(run("rev-parse", "--show-toplevel")[0])
        names = run("diff", "--name-only", ref) + run("ls-files", "--others", "--exclude-standard", "--full-name")
    except (OSError, subprocess.CalledProcessError, IndexError) as err:
        sys.exit(f"acxelin-readiness: --changed-since needs a git repository and a valid ref ({err})")
    out = set()
    for n in names:
        try:
            out.add((top / n).resolve().relative_to(Path(root).resolve()).as_posix())
        except ValueError:
            continue
    return frozenset(out)


def merge(a):
    files = inventory.cbom_files(a.cboms)
    if not files:
        sys.exit("acxelin-readiness: no cbom.json found in " + ", ".join(a.cboms))
    try:
        systems = inventory.run(files, a.name, a.out, a.history)
    except (OSError, ValueError) as err:
        sys.exit(f"acxelin-readiness: cannot merge: {err}")
    if not a.quiet:
        print(inventory.terminal(a.name, systems))
        print(f"\nwrote {Path(a.out) / 'inventory.html'}, {Path(a.out) / 'inventory.json'}, {Path(a.out) / 'cbom.json'}")
    if a.fail_on:
        bad = TIERS[:TIERS.index(a.fail_on) + 1]
        if any(s["readiness"]["worst"] in bad for s in systems):
            sys.exit(2)
    return 0


def settings(path, root):
    """Settings from --config, or from .acxelin-readiness.toml in the scanned folder. Keys are the long option names with underscores."""
    f = Path(path) if path else root / ".acxelin-readiness.toml" if root and root.is_dir() else None
    if not path and f is not None:
        old = root / ".wolfpack.toml"
        if old.exists() and f.exists():
            print(f"acxelin-readiness: {old} ignored: {f} is used (.wolfpack.toml is the old name)", file=sys.stderr)
        elif old.exists():
            print(f"acxelin-readiness: {old}: .wolfpack.toml is the old name; rename it to .acxelin-readiness.toml", file=sys.stderr)
            f = old
    if f is None or (not path and not f.exists()):
        return {}
    try:
        cfg = tomllib.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        sys.exit(f"acxelin-readiness: cannot read {f}: {e}")
    for k, v in cfg.items():
        if k not in SETTINGS:
            sys.exit(f"acxelin-readiness: {f}: unknown setting {k!r} (known: {', '.join(SETTINGS)})")
        if not isinstance(v, SETTINGS[k]) or (SETTINGS[k] is list and not all(isinstance(x, str) for x in v)):
            sys.exit(f"acxelin-readiness: {f}: {k} has the wrong type")
    return cfg


def grade(a):
    from . import endpoints
    try:
        targets = endpoints.load_targets(a.targets)
    except (OSError, ValueError) as e:
        sys.exit(f"acxelin-readiness: {e}")
    if not targets:
        sys.exit("acxelin-readiness: no targets: give host, host:port, ssh://host, or a .txt file with one per line")
    results = endpoints.scan(targets, a.workers, a.timeout)
    for r in results:
        print(f"{r.get('grade', 'F')}  {r.get('target', '?')}  {r.get('error') or r.get('negotiated') or ''}")
    if a.json:
        Path(a.json).write_text(endpoints.to_json(results), encoding="utf-8")
    if a.html:
        Path(a.html).write_text(endpoints.report_html(results), encoding="utf-8")
    return 0


def doctor():
    from acxelin_core import openssl
    reason = openssl.available()
    print(f"full TLS handshakes (OpenSSL 3.5+): {'available' if reason is None else 'not available: ' + reason}")
    print("  without them, grades and group acceptance still work; certificates of post-quantum-only endpoints are reported as not observed")
    try:
        import tree_sitter  # noqa: F401
        print("JavaScript, TypeScript, Java and Go relationships: available")
    except ImportError:
        print('JavaScript, TypeScript, Java and Go relationships: not available: pip install "acxelin-readiness[crawler]"')
    return 0


def console(a):
    from . import console as page
    home = Path(a.home or os.environ.get("ACXELIN_READINESS_HOME") or Path.home() / ".acxelin-readiness")
    if a.action == "link":
        from acxelin_core import console as core
        try:
            if core.link_running(a.port, home) is None:
                print("acxelin-readiness: console link prints only to a terminal; run it in an interactive session", file=sys.stderr)
        except (OSError, ValueError) as e:
            sys.exit(f"acxelin-readiness: no console is running on port {a.port} ({e}); start one with `acxelin-readiness console`")
        return 0
    return page.run(home, a.port, open_browser=not a.no_browser and not a.container, host="0.0.0.0" if a.container else "127.0.0.1")


def report_command(a):
    from . import endpoints, evidence
    if not (a.certs or a.targets or a.cbom):
        sys.exit("acxelin-readiness: nothing to report on: pass --certs, --targets or --cbom")
    rows = []
    try:
        if a.certs:
            rows += evidence.certificates(a.certs)
        if a.targets:
            targets = endpoints.load_targets(a.targets)
            if not targets:
                sys.exit("acxelin-readiness: no targets in --targets: give host, host:port, ssh://host, or a .txt file with one per line")
            rows += evidence.endpoints(endpoints.scan(targets, timeout=a.timeout))
        for source in a.cbom:
            rows += evidence.code(source)
    except (OSError, ValueError) as e:
        sys.exit(f"acxelin-readiness: {e}")
    rep = evidence.report(rows)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(evidence.to_html(rep), encoding="utf-8")
    (out / "assessment.json").write_text(evidence.to_json(rep), encoding="utf-8")
    first = [r for r in rows if r["status"] == "action"]
    print(f"{rep['assets']} assets: " + ", ".join(f"{n} {evidence.STATUS[s]}" for s, n in rep["status"].items() if n))
    for r in first[:5]:
        print(f"  do first: {r['name']}: {r['detail']}")
    if len(first) > 5:
        print(f"  ({len(first) - 5} more: see the report)")
    print(f"Report: {out / 'report.html'} (open it in a browser); assessment.json holds the evidence")
    return 0
