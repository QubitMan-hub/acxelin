"""Many projects at once: every repository in the folder (or a GitHub organisation) scanned in one go, one overview of them with
findings ranked by business service, what changed between two scans, a fix example in the finding's language, and the
scheduled scans `watch` recorded."""
import http.server
import json
import os
import threading
from pathlib import Path

import pytest

from acxelin_readiness import cli, console as rc, remote
from acxelin_readiness.examples import example

RSA = "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
MD5 = "import hashlib\nhashlib.md5(b'x')\n"


def wait(r):
    while r("GET", "/api/projects/status")["running"]:
        pass


@pytest.fixture
def two(tmp_path):
    root = tmp_path / "repos"
    for name, code in (("shop", RSA), ("ledger", MD5)):
        (root / name / "src").mkdir(parents=True)
        (root / name / "src" / "main.py").write_text(code)
    app = rc.build(tmp_path / "home")
    r = lambda method, path, body=None: app.routes[(method, path)](body or {})[1]
    r("POST", "/api/setup", {"directory": str(root)})
    return app, r, root, tmp_path


def test_scanning_everything_adds_every_repository_and_the_overview_ranks_them(two):
    app, r, root, _ = two
    assert r("POST", "/api/projects/scan-all")["started"] == 2
    wait(r)
    o = r("GET", "/api/overview")
    assert {p["name"]: p["scanned"] for p in o["projects"]} == {"shop": True, "ledger": True}
    assert o["scan_all"]["done"] == 2 and not o["scan_all"]["running"] and o["scan_all"]["failed"] == []
    ledger = next(p for p in o["projects"] if p["name"] == "ledger")
    assert ledger["tiers"].get("critical") or ledger["tiers"].get("high")


def test_services_are_ranked_across_projects_by_their_worst_findings(two):
    app, r, root, _ = two
    r("POST", "/api/projects/scan-all")
    wait(r)
    for i in (0, 1):
        r("POST", "/api/projects/owners", {"project": i, "csv": "path,owner,service\nsrc/,Team,Card payments\n"})
    svc = r("GET", "/api/overview")["services"]
    assert svc[0]["service"] == "Card payments" and svc[0]["projects"] == ["ledger", "shop"] and svc[0]["critical"] + svc[0]["high"] >= 2


def test_the_second_scan_names_what_is_new_and_what_was_fixed(two):
    app, r, root, _ = two
    r("POST", "/api/projects/register", {"name": "shop"})
    r("POST", "/api/projects/scan", {"project": 0})
    wait(r)
    (root / "shop/src/main.py").write_text(MD5)
    r("POST", "/api/projects/scan", {"project": 0})
    wait(r)
    cmp = r("GET", "/api/projects/status")["last"]["comparison"]
    assert [f["name"] for f in cmp["new_findings"]] == ["MD5"] and "RSA-2048" in [f["name"] for f in cmp["gone_findings"]]


def test_a_finding_carries_a_fix_example_in_its_files_language(two):
    app, r, root, _ = two
    r("POST", "/api/projects/register", {"name": "ledger"})
    r("POST", "/api/projects/scan", {"project": 0})
    wait(r)
    md5 = next(a for a in r("GET", "/api/projects/status")["last"]["assets"] if a["name"] == "MD5")
    assert md5["example"]["language"] == "Python" and "hashlib.sha256" in md5["example"]["after"]


@pytest.mark.parametrize("algorithm,name,path,before,after", [
    ("SHA-1", "SHA-1", "A.java", 'getInstance("SHA-1")', 'getInstance("SHA-256")'),
    ("MD5", "MD5", "x.go", "md5.Sum", "sha256.Sum256"),
    ("ECDH", "ECDH", "k.go", "ecdh.X25519", "mlkem.GenerateKey768"),
    ("3DES", "3DES", "C.java", "DESede", "AES/GCM/NoPadding"),
    ("TLS 1.0", "TLS 1.0", "s.go", "VersionTLS10", "VersionTLS13"),
    ("TLS 1.1", "TLS 1.1", "etc/nginx/site.conf", "TLSv1.1", "ssl_protocols TLSv1.3;"),
    ("AES", "AES-128-ECB", "e.ts", "aes-128-ecb", "aes-256-gcm"),
])
def test_examples_change_the_weak_call_into_its_replacement(algorithm, name, path, before, after):
    e = example({"algorithm": algorithm, "name": name, "tier": "high", "locations": [[path, 1]]})
    assert before in e["before"] and after in e["after"]


def test_no_example_for_safe_findings_tests_or_unknown_languages():
    assert example({"algorithm": "AES", "name": "AES-256", "tier": "ok", "locations": [["a.py", 1]]}) is None
    assert example({"algorithm": "MD5", "name": "MD5", "tier": "high", "locations": [["tests/a.py", 1]]}) is None
    assert example({"algorithm": "MD5", "name": "MD5", "tier": "high", "locations": [["a.rb", 1]]}) is None
    assert example({"algorithm": "TLS 1.0", "name": "TLS 1.0", "tier": "high", "locations": [["apache.conf", 1]]}) is None


def test_the_python_examples_run():
    data, key = b"message", os.urandom(32)
    for algorithm, name in (("MD5", "MD5"), ("RSA", "RSA-2048"), ("3DES", "3DES"), ("TLS 1.0", "TLS 1.0")):
        e = example({"algorithm": algorithm, "name": name, "tier": "high", "locations": [["a.py", 1]]})
        exec("import hashlib, os, ssl\n" + e["after"], {"data": data, "key": key})
    e = example({"algorithm": "X25519", "name": "X25519", "tier": "high", "locations": [["a.py", 1]]})
    from cryptography.hazmat.primitives.asymmetric import mlkem
    peer = mlkem.MLKEM768PrivateKey.generate()
    space = {"peer_public": peer.public_key()}
    exec(e["after"], space)
    assert peer.decapsulate(space["ciphertext"]) == space["shared"]


class Org:
    """GitHub's repository list: page 1 full, page 2 short; an archived repository and a fork are left out."""
    def __init__(self, org_status=200):
        names = [f"r{n}" for n in range(100)] + ["last", "old", "copy"]
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.startswith("/orgs/") and org_status != 200:
                    self.send_response(org_status)
                    self.end_headers()
                    return
                page = int(self.path.split("&page=")[1])
                rows = [{"name": n, "archived": n == "old", "fork": n == "copy"} for n in names[(page - 1) * 100: page * 100]]
                body = json.dumps(rows).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        outer.names = names


@pytest.mark.parametrize("status", [200, 404])
def test_an_organisation_or_a_user_lists_its_repositories_without_archived_ones_or_forks(status):
    s = Org(status)
    try:
        links = remote.organisation("acme", api=s.api, limit=500)
    finally:
        s.httpd.shutdown()
    assert len(links) == 101 and "https://github.com/acme/last" in links and not any(x.endswith(("/old", "/copy")) for x in links)
    with pytest.raises(ValueError):
        remote.organisation("../etc")


def test_the_console_adds_an_organisations_repositories(two):
    app, r, root, _ = two
    s = Org()
    app_routes = app.routes
    try:
        console = app_routes[("POST", "/api/projects/github-org")].__self__
        console.github_api = s.api
        out = r("POST", "/api/projects/github-org", {"org": "https://github.com/acme"})
    finally:
        s.httpd.shutdown()
    assert out["added"] == 101 and len(r("GET", "/api/status")["projects"]) == 101


def test_scheduled_scans_appear_in_the_overview(two):
    app, r, root, tmp = two
    assert cli.main(["watch", str(root / "shop"), "-o", str(tmp / "w"), "--once", "--home", str(tmp / "home")]) == 0
    (root / "shop/src/legacy.py").write_text(MD5)
    assert cli.main(["watch", str(root / "shop"), "-o", str(tmp / "w"), "--once", "--home", str(tmp / "home")]) == 0
    runs = r("GET", "/api/overview")["watch"]
    assert len(runs) == 2 and runs[0]["new_count"] >= 1 and ["MD5", "src/legacy.py"] in runs[0]["new"] and runs[1]["first"]
    assert Path(runs[0]["out"]).name == "w"
