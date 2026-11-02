"""The interop matrix: which real TLS implementations talk to Acxelin TLS under each policy, and which do not, with what was negotiated.

    python tests/interop/matrix.py [--write FILE.md] [--json FILE.json]

Rows are the peers found on this machine (OpenSSL 3.5 command line, Node, curl, Go 1.24+, nginx); each row says the OpenSSL or Go version it
runs on, because what a peer can do follows from that: ML-KEM key exchange needs OpenSSL 3.5 (or Go 1.24), and verifying ML-DSA certificates
needs OpenSSL 3.5. A peer that is not installed is listed as not run, with the reason, never silently left out. Every cell is checked against
what its row's capabilities predict; the exit status is 1 if any cell differs. The group that was negotiated is read from the edge's own
/status counters, not from what the client says. Not covered: Chromium/BoringSSL, strongSwan, WireGuard (needs two machines), and any
peer this machine does not have.
"""
import argparse
import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from acxelin_core import tls
from acxelin_core.pki import CA
from acxelin_tls import policies

HERE = Path(__file__).resolve().parent
MODES = ("strict", "transition", "cnsa2")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(cmd, timeout=40, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(cmd, 255, "", f"{type(e).__name__}: {e}")


def version_tuple(text):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    return tuple(int(x or 0) for x in m.groups()) if m else (0, 0, 0)


def openssl_cli():
    for c in [os.environ.get("ACXELIN_OPENSSL_CLI"), str(Path(os.environ.get("ACXELIN_OPENSSL", "/nonexistent")).parent / "bin" / "openssl"), shutil.which("openssl")]:
        if c and Path(c).exists():
            r = run([c, "version"])
            if r.returncode == 0 and version_tuple(r.stdout) >= (3, 5):
                return c, r.stdout.strip()
    return None, None


class Peers:
    """What is installed, the library each one runs on, and what that library can do."""

    def __init__(self, work):
        self.work, self.info, self.missing = Path(work), {}, {}
        cli, ver = openssl_cli()
        if cli:
            self.info["openssl"] = {"label": f"openssl s_client {ver.split()[1]}", "cmd": cli, "pq": True, "mldsa": True, "lib": ver}
        else:
            self.missing["openssl"] = "no OpenSSL 3.5+ command line (set ACXELIN_OPENSSL_CLI)"
        if shutil.which("node"):
            lib = run(["node", "-p", "process.versions.openssl"]).stdout.strip()
            v = version_tuple(lib)
            self.info["node"] = {"label": f"node {run(['node', '--version']).stdout.strip()} (OpenSSL {lib})", "pq": v >= (3, 5), "mldsa": v >= (3, 5), "lib": lib}
        else:
            self.missing["node"] = "node is not installed"
        if shutil.which("curl"):
            out = run(["curl", "--version"]).stdout
            m = re.search(r"OpenSSL/(\S+)", out)
            if m:
                v = version_tuple(m.group(1))
                self.info["curl"] = {"label": f"curl {version_tuple(out)[0]}.{version_tuple(out)[1]} (OpenSSL {m.group(1)})", "pq": v >= (3, 5), "mldsa": v >= (3, 5), "lib": m.group(1)}
            else:
                self.missing["curl"] = "this curl is not built on OpenSSL"
        else:
            self.missing["curl"] = "curl is not installed"
        go = shutil.which("go")
        gv = version_tuple(run([go, "version"]).stdout) if go else (0, 0, 0)
        if go and gv >= (1, 24):
            ok = all(run([go, "build", "-o", str(self.work / name), str(HERE / f"{src}.go")], cwd=HERE).returncode == 0 for name, src in (("goclient", "client"), ("goserver", "server")))
            if ok:
                self.info["go"] = {"label": f"go {gv[0]}.{gv[1]}.{gv[2]}", "pq": True, "mldsa": False, "lib": "crypto/tls"}
            else:
                self.missing["go"] = "go could not build the test client and server"
        else:
            self.missing["go"] = f"needs Go 1.24+ for X25519MLKEM768 (found {'.'.join(map(str, gv)) if go else 'none'})"
        nginx = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)
        if nginx:
            text = run([nginx, "-V"]).stderr
            lib = re.search(r"running with OpenSSL (\S+)", text) or re.search(r"built with OpenSSL (\S+)", text)  # the library it loads, not the one it was built against
            self.info["nginx"] = {"label": f"nginx {version_tuple(run([nginx, '-v']).stderr)[0]}.{version_tuple(run([nginx, '-v']).stderr)[1]} (OpenSSL {lib.group(1) if lib else '?'})",
                                  "cmd": nginx, "pq": bool(lib) and version_tuple(lib.group(1)) >= (3, 5), "mldsa": False, "lib": lib.group(1) if lib else "?"}
        else:
            self.missing["nginx"] = "nginx is not installed"


class Pki:
    def __init__(self, work):
        w = self.work = Path(work)
        self.ca = CA.init(w / "pki", "Interop Root")
        self.ca.issue("localhost", "server", ["127.0.0.1"], algorithm="ML-DSA-87", out=w / "srv87")
        self.ca.issue("localhost", "server", ["127.0.0.1"], algorithm="ML-DSA-65", out=w / "srv65")
        self.classical()
        trust = (w / "pki" / "ca.crt").read_bytes() + b"\n" + (w / "fb.pem").read_bytes()
        (w / "trust.pem").write_bytes(trust)  # both anchors: whichever certificate a server presents can be verified
        self.trust = w / "trust.pem"

    def classical(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        now, key = dt.datetime.now(dt.timezone.utc), ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=7))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), False)
                .sign(key, hashes.SHA256()))
        (self.work / "fb.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (self.work / "fb.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello\n")

    def log_message(self, *a):
        pass


class Edges:
    """One edge per policy in front of a tiny backend; negotiated groups are read from its /status counters."""

    def __init__(self, work, pki):
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.procs, self.ports, self.metrics = [], {}, {}
        for mode in MODES:
            cert = "srv87" if mode == "cnsa2" else "srv65"
            self.ports[mode], self.metrics[mode] = free_port(), free_port()
            cmd = [sys.executable, "-m", "acxelin_tls", "edge", "--listen", f"127.0.0.1:{self.ports[mode]}", "--target", f"127.0.0.1:{self.backend.server_port}",
                   "--policy", mode, "--cert", str(Path(work) / cert / "chain.pem"), "--key", str(Path(work) / cert / "key.pem"), "--metrics", f"127.0.0.1:{self.metrics[mode]}"]
            if mode == "transition":
                cmd += ["--fallback-cert", str(Path(work) / "fb.pem"), "--fallback-key", str(Path(work) / "fb.key")]
            self.procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True))
        for mode in MODES:
            end = time.monotonic() + 20
            while time.monotonic() < end:
                try:
                    socket.create_connection(("127.0.0.1", self.ports[mode]), 1).close()
                    break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError(f"the {mode} edge did not start: {self.procs[MODES.index(mode)].stderr.read()[:300]}")

    def groups(self, mode):
        status = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.metrics[mode]}/status", timeout=5))
        total = {}
        for route in status.values():
            for g, n in route.get("groups", {}).items():
                total[g] = total.get(g, 0) + n
        return total

    def stop(self):
        for p in self.procs:
            p.terminate()
        self.backend.shutdown()


def client_cells(peers, pki, edges):
    """Rows: peers as clients of the edge. Each tuple: (label, capabilities, argv function(port) -> command)."""
    trust, p = str(pki.trust), peers.info
    rows = []
    if "openssl" in p:
        base = lambda port, *x: [p["openssl"]["cmd"], "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost", "-verify_hostname", "localhost", "-CAfile", trust, "-tls1_3", *x]
        rows.append(("openssl", p["openssl"]["label"] + ", default groups", p["openssl"], lambda port: base(port), True))
        rows.append(("openssl-1024", p["openssl"]["label"] + ", -groups MLKEM1024", p["openssl"], lambda port: base(port, "-groups", "MLKEM1024"), True))
    if "node" in p:
        rows.append(("node", p["node"]["label"], p["node"], lambda port: ["node", str(HERE / "client.js"), f"https://localhost:{port}/", trust], False))
    if "curl" in p:
        rows.append(("curl", p["curl"]["label"], p["curl"], lambda port: ["curl", "-sS", "--cacert", trust, "--resolve", f"localhost:{port}:127.0.0.1", f"https://localhost:{port}/", "-o", os.devnull], False))
    if "go" in p:
        rows.append(("go", p["go"]["label"], p["go"], lambda port: [str(peers.work / "goclient"), f"https://127.0.0.1:{port}/", trust], False))
    return rows


def client_expectation(caps, mode, only_1024):
    """(should the handshake succeed, should the negotiated group be post-quantum). `only_1024`: the client offers pure MLKEM1024 alone,
    which only cnsa2 serves."""
    if mode == "strict":
        ok = caps["pq"] and caps["mldsa"] and not only_1024
        return ok, ok
    if mode == "transition":
        return not only_1024, caps["pq"] and not only_1024
    ok = caps["mldsa"] and only_1024
    return ok, ok


def run_client_cells(peers, pki, edges):
    results = []
    for key, label, caps, argv, _openssl in client_cells(peers, pki, edges):
        cells = {}
        for mode in MODES:
            before = edges.groups(mode)
            if key == "openssl" or key == "openssl-1024":
                r = run(argv(edges.ports[mode]), input="GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                ok = r.returncode == 0 and "Verification: OK" in r.stdout and "Negotiated TLS1.3 group" in r.stdout
            else:
                r = run(argv(edges.ports[mode]))
                ok = r.returncode == 0
            time.sleep(0.2)
            after = edges.groups(mode)
            new = {g: n - before.get(g, 0) for g, n in after.items() if n > before.get(g, 0)}
            group = next(iter(new), "")
            want_ok, want_pq = client_expectation(caps, mode, key == "openssl-1024")
            pq = "MLKEM" in group.upper()
            cells[mode] = {"ok": ok, "group": group, "expected_ok": want_ok, "expected_pq": want_pq,
                           "match": ok == want_ok and (not ok or pq == want_pq)}
        results.append({"peer": label, "cells": cells})
    return results


def server_peers(peers, pki):
    """Peers as servers for the Acxelin client: yields (label, caps, port, stop())."""
    work, p = peers.work, peers.info
    started = []
    if "openssl" in p:
        port = free_port()
        proc = subprocess.Popen([p["openssl"]["cmd"], "s_server", "-accept", str(port), "-cert", str(work / "srv87" / "chain.pem"), "-key", str(work / "srv87" / "key.pem"),
                                 "-tls1_3", "-groups", "X25519MLKEM768:SecP384r1MLKEM1024:MLKEM1024", "-www", "-quiet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started.append((p["openssl"]["label"].replace("s_client", "s_server") + ", ML-DSA-87 certificate", {"pq": True, "mldsa": True}, port, proc))
    if "go" in p:
        port = free_port()
        proc = subprocess.Popen([str(work / "goserver"), f"127.0.0.1:{port}", str(work / "fb.pem"), str(work / "fb.key")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started.append((p["go"]["label"] + " server, ECDSA certificate", {"pq": True, "mldsa": False}, port, proc))
    if "nginx" in p:
        port = free_port()
        (work / "nginx").mkdir(exist_ok=True)
        (work / "nginx" / "nginx.conf").write_text(
            f"daemon off; pid {work / 'nginx' / 'pid'}; error_log {work / 'nginx' / 'err'};\nevents {{}}\nhttp {{ access_log off; client_body_temp_path {work / 'nginx'}/b; proxy_temp_path {work / 'nginx'}/p; "
            f"fastcgi_temp_path {work / 'nginx'}/f; uwsgi_temp_path {work / 'nginx'}/u; scgi_temp_path {work / 'nginx'}/s;\n server {{ listen 127.0.0.1:{port} ssl; ssl_certificate {work / 'fb.pem'}; "
            f"ssl_certificate_key {work / 'fb.key'}; ssl_protocols TLSv1.3; location / {{ return 200 \"hello\\n\"; }} }} }}\n", encoding="utf-8")
        proc = subprocess.Popen([p["nginx"]["cmd"], "-c", str(work / "nginx" / "nginx.conf"), "-p", str(work / "nginx")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started.append((p["nginx"]["label"] + " server, ECDSA certificate", {"pq": p["nginx"]["pq"], "mldsa": False}, port, proc))
    for _, _, port, proc in started:
        end = time.monotonic() + 15
        while time.monotonic() < end:
            try:
                socket.create_connection(("127.0.0.1", port), 1).close()
                break
            except OSError:
                time.sleep(0.2)
    return started


def server_expectation(caps, mode, cert_is_mldsa):
    """(success, post-quantum group) for the Acxelin client under `mode` against a server with these capabilities and certificate."""
    if mode == "transition":
        return True, caps["pq"]
    return (cert_is_mldsa and caps["pq"]), (cert_is_mldsa and caps["pq"])


def run_server_cells(peers, pki):
    results, started = [], server_peers(peers, pki)
    try:
        for label, caps, port, _ in started:
            cells = {}
            for mode in MODES:
                ctx = tls.client_context(policies.policy(mode), ca=str(pki.trust))
                try:
                    conn = tls.connect("127.0.0.1", port, ctx, "localhost", 10)
                    conn.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    try:
                        body = conn.recv(timeout=10)  # any reply: s_server -www answers with its own status page, the others with "hello"
                    except tls.TLSError:
                        body = b""
                    ok, group, detail = bool(body), conn.group, ""
                    conn.close()
                except tls.TLSError as e:
                    ok, group, detail = False, "", str(e)[:120]
                want_ok, want_pq = server_expectation(caps, mode, "ML-DSA" in label)
                cells[mode] = {"ok": ok, "group": group, "detail": detail, "expected_ok": want_ok, "expected_pq": want_pq,
                               "match": ok == want_ok and (not ok or ("MLKEM" in group.upper()) == want_pq)}
            results.append({"peer": label, "cells": cells})
    finally:
        for *_, proc in started:
            proc.terminate()
    return results


def cell_text(c):
    if c["ok"]:
        return f"pass, {c['group'] or '?'}"
    return "refused"


def markdown(peers, clients, servers, when):
    lines = ["# Interop matrix", "", f"Generated {when} by `products/tls/tests/interop/matrix.py` on {sys.platform}, Python {sys.version.split()[0]}, "
             f"{tls.openssl.version() if hasattr(tls, 'openssl') and hasattr(tls.openssl, 'version') else 'OpenSSL via acxelin-core'}. A cell reads `pass, <group negotiated>` or `refused`; "
             "`!=` marks a cell that differs from what the peer's library predicts.", "",
             "## Real clients against the Acxelin TLS edge", "", "| Client | strict | transition | cnsa2 |", "|---|---|---|---|"]
    for row in clients:
        lines.append(f"| {row['peer']} | " + " | ".join(cell_text(row["cells"][m]) + ("" if row["cells"][m]["match"] else " (!= expected)") for m in MODES) + " |")
    lines += ["", "## The Acxelin client against real servers", "", "| Server | strict | transition | cnsa2 |", "|---|---|---|---|"]
    for row in servers:
        lines.append(f"| {row['peer']} | " + " | ".join(cell_text(row["cells"][m]) + ("" if row["cells"][m]["match"] else " (!= expected)") for m in MODES) + " |")
    if peers.missing:
        lines += ["", "## Not run", ""] + [f"- {name}: {why}" for name, why in sorted(peers.missing.items())]
    lines += ["", "## How to read it", "",
              "- `strict` needs a post-quantum key exchange and ML-DSA certificates: only peers on OpenSSL 3.5+ can pass. `transition` serves everyone, post-quantum where the peer can, "
              "with a classical fallback certificate. `cnsa2` needs pure MLKEM1024 (the CNSA 2.0 FAQ names no TLS hybrid) and an ML-DSA-87 certificate, which no default client offers.",
              "- The group in the edge rows is read from the edge's own counters. The group in the server rows is what the Acxelin client reports for the connection.",
              "- Not covered: Chromium/BoringSSL, strongSwan and WireGuard peers (IPsec needs root and a second machine), and any peer not installed here.", ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--write")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    with tempfile.TemporaryDirectory() as work:
        peers, pki = Peers(work), None
        pki = Pki(work)
        edges = Edges(work, pki)
        try:
            clients = run_client_cells(peers, pki, edges)
        finally:
            edges.stop()
        servers = run_server_cells(peers, pki)
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = markdown(peers, clients, servers, when)
    print(text)
    if a.write:
        Path(a.write).write_text(text, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps({"generated": when, "clients": clients, "servers": servers, "not_run": peers.missing}, indent=1), encoding="utf-8")
    bad = [(r["peer"], m) for rows in (clients, servers) for r in rows for m, c in r["cells"].items() if not c["match"]]
    if not (clients or servers):
        print("no peer ran: nothing was tested", file=sys.stderr)
        return 1
    if bad:
        print("cells that differ from the prediction:", bad, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
