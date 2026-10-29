"""End-to-end scenarios with real applications behind the products, driven through the `acxelin-tls` command line and checked
with independent clients (the OpenSSL 3.5 command line, curl, psql, redis-cli, mosquitto). Each scenario is skipped when its
application is not installed."""
import functools
import http.server
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from acxelin_core import tls
from acxelin_core.pki import CA
from support_tls import REASON
import support_tls


def openssl_cli():
    """An `openssl` command line of version 3.5 or newer, used only as an independent client in these tests."""
    for c in [os.environ.get("ACXELIN_OPENSSL_CLI"), str(Path(os.environ.get("ACXELIN_OPENSSL", "/nonexistent")).parent / "bin" / "openssl"), "/opt/openssl35/bin/openssl", shutil.which("openssl")]:
        if c and Path(c).exists():
            v = subprocess.run([c, "version"], capture_output=True, text=True).stdout.split()
            if len(v) > 1 and tuple(int(x) for x in v[1].split(".")[:2] if x.isdigit()) >= (3, 5):
                return c
    return None


OPENSSL = openssl_cli()
PG_BIN = max((p.parent for p in Path("/usr/lib/postgresql").glob("*/bin/initdb")), key=lambda p: int(p.parent.name), default=None)


def free_port():
    with socket.create_server(("127.0.0.1", 0)) as s:
        return s.getsockname()[1]


def wait_port(port, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"nothing listens on {port}")


def need(*tools):
    missing = [t for t in tools if not (shutil.which(t) or Path(t).exists())]
    return unittest.skipIf(missing, f"needs {', '.join(missing)}")


def ec_certificate(d, name="app.internal"):
    """A self-signed ECDSA certificate, as a classical server or a browser-facing fallback would have."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False).sign(key, hashes.SHA256()))
    (d / "ec.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "ec.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


@unittest.skipIf(REASON, REASON)
class Scenario(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.addCleanup(self.show_logs)
        self.procs = []
        self.addCleanup(self.stop_all)
        self.ca = CA.init(self.d / "pki", "Scenario Root")
        self.ca.crl()

    def show_logs(self):
        """pytest shows this only for a failing test: why a process the test started never answered."""
        for log in sorted(self.d.glob("*.log")):
            print(f"--- {log.name}\n{log.read_text(errors='replace')[-2000:]}")

    def stop_all(self):
        for p in reversed(self.procs):
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            if p.stdout:
                p.stdout.close()

    def spawn(self, *cmd, log=None, **kw):
        out = open(log or os.devnull, "w")
        p = subprocess.Popen([str(c) for c in cmd], stdout=out, stderr=subprocess.STDOUT, **kw)
        out.close()
        self.procs.append(p)
        return p

    def postgres(self):
        data, port = self.d / "pg", free_port()
        data.mkdir()
        shutil.chown(data, "postgres")
        os.chmod(self.d, 0o755)
        subprocess.run(["runuser", "-u", "postgres", "--", PG_BIN / "initdb", "-D", data, "-A", "trust", "--encoding=UTF8"],
                       check=True, capture_output=True)
        self.spawn("runuser", "-u", "postgres", "--", PG_BIN / "postgres", "-D", data, "-p", port, "-k", data,
                   "-c", "listen_addresses=127.0.0.1")
        wait_port(port)
        deadline = time.monotonic() + 30  # the port opens before the server accepts connections
        while subprocess.run([PG_BIN / "pg_isready", "-h", "127.0.0.1", "-p", str(port)], capture_output=True).returncode:
            if time.monotonic() > deadline:
                raise TimeoutError(f"PostgreSQL on {port} never accepted connections")
            time.sleep(0.2)
        return port

    def pqc(self, *args, log):
        return self.spawn(sys.executable, "-m", "acxelin_tls", *args, log=self.d / log)

    def edge(self, config, name):
        (self.d / f"{name}.toml").write_text(config)
        self.pqc("edge", "--config", self.d / f"{name}.toml", log=f"{name}.log")

    def route(self, name, mode, listen, target, **extra):
        lines = [f'[[edge]]\nname = "{name}"\nmode = "{mode}"\nlisten = "127.0.0.1:{listen}"\ntarget = "127.0.0.1:{target}"']
        for k, v in extra.items():
            lines.append(f"{k} = {str(v).lower() if isinstance(v, bool) else v if isinstance(v, (int, float)) else repr(str(v))}")
        return "\n".join(lines) + "\n"

    def tunnel(self, upstream, mtls=True):
        """An originate edge on the client side and a terminate edge in front of the service: what a branch office runs."""
        srv, _ = self.ca.issue("service.internal", "server", ["127.0.0.1"], out=self.d / "srv")
        cli, _ = self.ca.issue("branch", "client", out=self.d / "branch")
        front, local = free_port(), free_port()
        self.edge(self.route("front", "terminate", front, upstream, cert=srv / "chain.pem", key=srv / "key.pem",
                             ca=self.d / "pki" / "ca.crt", require_client_cert=mtls, crl=self.d / "pki" / "crl.pem"), "front")
        wait_port(front)
        self.edge(self.route("local", "originate", local, front, server_name="service.internal", ca=self.d / "pki" / "ca.crt",
                             cert=cli / "chain.pem", key=cli / "key.pem"), "local")
        wait_port(local)
        return local

    def s_client(self, port, *extra, name="app.internal", cafile=None, send=b"GET / HTTP/1.0\r\nHost: app.internal\r\n\r\n"):
        r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-servername", name, "-verify_hostname", name,
                            "-CAfile", str(cafile or self.d / "pki" / "ca.crt"), "-verify_return_error", "-ign_eof", *extra],
                           input=send, capture_output=True, timeout=30)
        return r.returncode, r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")

    def edge_log(self, name):
        return (self.d / f"{name}.log").read_text(errors="replace")


class WebTest(Scenario):
    """A web app (nginx) behind the TLS edge, reached by third-party clients."""

    def nginx(self):
        port = free_port()
        (self.d / "www").mkdir()
        (self.d / "www" / "index.html").write_text("hello from nginx\n")
        (self.d / "nginx.conf").write_text(
            f"daemon off; master_process off; pid {self.d}/nginx.pid; error_log {self.d}/nginx-error.log;\n"
            f"events {{}}\nhttp {{ access_log off; client_body_temp_path {self.d}; proxy_temp_path {self.d};\n"
            f"  server {{ listen 127.0.0.1:{port}; root {self.d}/www; }} }}\n")
        self.spawn("nginx", "-p", self.d, "-c", self.d / "nginx.conf")
        wait_port(port)
        return port

    def web_edge(self, policy="strict", mtls=False, **extra):
        out, _ = self.ca.issue("app.internal", "server", ["127.0.0.1"], out=self.d / "app")
        port = free_port()
        self.metrics = free_port()
        cfg = f'[metrics]\nlisten = "127.0.0.1:{self.metrics}"\n' + self.route(
            "web", "terminate", port, self.nginx(), policy=policy, cert=out / "chain.pem", key=out / "key.pem",
            ca=self.d / "pki" / "ca.crt", require_client_cert=mtls, crl=self.d / "pki" / "crl.pem", **extra)
        self.edge(cfg, "web")
        wait_port(port)
        return port

    @need("nginx")
    @unittest.skipUnless(OPENSSL, "needs an OpenSSL 3.5+ command line")
    def test_openssl_client_gets_the_page_over_ml_kem_and_ml_dsa(self):
        port = self.web_edge()
        code, out = self.s_client(port)
        self.assertEqual(code, 0, out)
        self.assertIn("hello from nginx", out)
        self.assertIn("X25519MLKEM768", out)
        self.assertIn("Verify return code: 0 (ok)", out)
        self.assertRegex(out, r"(?i)peer signature type: (mldsa65|ML-DSA-65)")
        code, out = self.s_client(port, "-groups", "X25519")
        self.assertNotEqual(code, 0, "strict must refuse a classical key exchange")
        import urllib.request
        metrics = urllib.request.urlopen(f"http://127.0.0.1:{self.metrics}/metrics", timeout=5).read().decode()
        self.assertIn('group="X25519MLKEM768"', metrics)

    @need("nginx", "curl")
    def test_classical_clients_under_transition_with_a_fallback_certificate(self):
        ec_certificate(self.d)
        port = self.web_edge("transition", fallback_cert=self.d / "ec.pem", fallback_key=self.d / "ec.key")
        (self.d / "both.pem").write_bytes((self.d / "ec.pem").read_bytes() + (self.d / "pki" / "ca.crt").read_bytes())
        r = subprocess.run(["curl", "-sS", "--noproxy", "*", "--max-time", "10", "--cacert", self.d / "both.pem", "--resolve", f"app.internal:{port}:127.0.0.1",
                            f"https://app.internal:{port}/"], capture_output=True, text=True)
        self.assertEqual(r.stdout, "hello from nginx\n", r.stderr + self.edge_log("web"))
        if OPENSSL:
            code, out = self.s_client(port, "-sigalgs", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", "-groups", "X25519:P-256",
                                      cafile=self.d / "ec.pem")
            self.assertEqual(code, 0, out)
            self.assertIn("hello from nginx", out)
            self.assertRegex(out, r"(?i)peer signature type: ecdsa")
            # a client that can verify both is given the trusted classical fallback (the PQC repo's hardening), still over ML-KEM
            code, out = self.s_client(port, cafile=self.d / "both.pem")
            self.assertEqual(code, 0, out)
            self.assertIn("X25519MLKEM768", out)
            self.assertRegex(out, r"(?i)peer signature type: ecdsa")
            # a client that only offers ML-DSA still gets the post-quantum certificate
            code, out = self.s_client(port, "-sigalgs", "mldsa65:mldsa87:mldsa44")
            self.assertEqual(code, 0, out)
            self.assertIn("X25519MLKEM768", out)
            self.assertRegex(out, r"(?i)peer signature type: (mldsa65|ML-DSA-65)")

    @need("nginx")
    @unittest.skipUnless(OPENSSL, "needs an OpenSSL 3.5+ command line")
    def test_mutual_tls_and_revocation_with_openssl_as_the_client(self):
        port = self.web_edge(mtls=True)
        alice, rec = self.ca.issue("alice", "client", out=self.d / "alice")
        code, out = self.s_client(port, "-cert", alice / "cert.pem", "-key", alice / "key.pem")
        self.assertIn("hello from nginx", out)
        code, out = self.s_client(port)
        self.assertNotIn("hello from nginx", out)
        self.ca.revoke(rec.serial, "keyCompromise")
        time.sleep(0.2)
        code, out = self.s_client(port, "-cert", alice / "cert.pem", "-key", alice / "key.pem")
        self.assertNotIn("hello from nginx", out)
        # repeated rejections from one address are counted in /status rather than logged (no log flooding), so count them there
        import json
        import urllib.request
        status = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.metrics}/status").read())["web"]
        self.assertGreaterEqual(sum(v for k, v in status.items() if k.startswith(("handshake_failed", "rejected", "refused")) and isinstance(v, int)), 2, status)

    @need("nginx")
    def test_many_concurrent_clients(self):
        from concurrent.futures import ThreadPoolExecutor
        from acxelin_core.https import request
        port = self.web_edge()
        ctx = support_tls.client_context(self.d / "pki" / "ca.crt")

        def get(_):
            with tls.connect("127.0.0.1", port, ctx, "app.internal", 20) as c:
                return request(c, "GET", "/", "app.internal")[2]
        start = time.monotonic()
        with ThreadPoolExecutor(32) as pool:
            bodies = list(pool.map(get, range(300)))
        self.assertEqual(set(bodies), {b"hello from nginx\n"})
        self.assertLess(time.monotonic() - start, 120)


class TunnelTest(Scenario):
    """Legacy clients that cannot speak post-quantum TLS reach a service through two edges."""

    @need("redis-server", "redis-cli")
    def test_redis(self):
        port = free_port()
        self.spawn("redis-server", "--port", port, "--bind", "127.0.0.1", "--save", "", "--appendonly", "no")
        wait_port(port)
        local = self.tunnel(port)
        cli = lambda *a: subprocess.run(["redis-cli", "-p", str(local), *a], capture_output=True, text=True, timeout=15).stdout.strip()
        self.assertEqual(cli("SET", "pqc", "ML-KEM"), "OK")
        self.assertEqual(cli("GET", "pqc"), "ML-KEM")

    @need("mosquitto", "mosquitto_pub", "mosquitto_sub")
    def test_mqtt(self):
        port = free_port()
        (self.d / "mosquitto.conf").write_text(f"listener {port} 127.0.0.1\nallow_anonymous true\n")
        self.spawn("mosquitto", "-c", self.d / "mosquitto.conf")
        wait_port(port)
        local = self.tunnel(port)
        sub = subprocess.Popen(["mosquitto_sub", "-p", str(local), "-t", "plant/temp", "-C", "1", "-W", "20"], stdout=subprocess.PIPE, text=True)
        time.sleep(1)
        subprocess.run(["mosquitto_pub", "-p", str(local), "-t", "plant/temp", "-m", "21.5"], check=True, timeout=15)
        self.assertEqual(sub.communicate(timeout=25)[0].strip(), "21.5")

    @unittest.skipUnless(PG_BIN and shutil.which("psql"), "needs PostgreSQL")
    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("runuser"), "needs root to run postgres as its own user")
    def test_postgres(self):
        port = self.postgres()
        local = self.tunnel(port)
        r = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(local), "-U", "postgres", "-tAc", "select 6 * 7"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "42", r.stderr)








if __name__ == "__main__":
    unittest.main()


class BrowserTest(Scenario):
    """A real browser: Chromium negotiates X25519MLKEM768 but cannot verify ML-DSA certificates yet."""

    def browser(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("needs Playwright")
        pw = sync_playwright().start()
        self.addCleanup(pw.stop)
        try:
            b = pw.chromium.launch()
        except Exception as e:  # noqa: BLE001
            self.skipTest(f"no Playwright browser: {e}")
        self.addCleanup(b.close)
        return b.new_context(ignore_https_errors=True).new_page()  # the fallback is self-signed here; trust is not what this checks

    def test_a_browser_gets_post_quantum_key_exchange_through_transition_and_strict_needs_ml_dsa(self):
        page = self.browser()
        www = self.d / "www"
        www.mkdir()
        (www / "index.html").write_text("<title>behind the edge</title><h1>hello from behind the edge</h1>")
        # served from a port this process already holds: a port freed for another process to bind can be taken first (macOS)
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(www)))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        web = httpd.server_address[1]
        srv, _ = self.ca.issue("localhost", "server", ["localhost", "127.0.0.1"], out=self.d / "srv")
        ec_certificate(self.d, "localhost")
        port, metrics, strict = free_port(), free_port(), free_port()
        self.pqc("edge", "--listen", f"127.0.0.1:{port}", "--target", f"127.0.0.1:{web}", "--policy", "transition", "--cert", srv / "chain.pem",
                 "--key", srv / "key.pem", "--fallback-cert", self.d / "ec.pem", "--fallback-key", self.d / "ec.key", "--metrics", f"127.0.0.1:{metrics}", log="t.log")
        self.pqc("edge", "--listen", f"127.0.0.1:{strict}", "--target", f"127.0.0.1:{web}", "--cert", srv / "chain.pem", "--key", srv / "key.pem", log="s.log")
        for p in (web, port, metrics, strict):
            wait_port(p)
        page.goto(f"https://localhost:{port}/")
        self.assertEqual(page.inner_text("h1"), "hello from behind the edge")
        import json
        import urllib.request
        groups = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{metrics}/status").read())["edge"]["groups"]
        self.assertIn("X25519MLKEM768", groups, groups)
        from acxelin_core.openssl import Context, TLSError
        classical = Context(False, "X25519MLKEM768:X25519", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ed25519", verify=False)
        self.addCleanup(classical.close)
        with self.assertRaises((TLSError, OSError)):  # strict keeps no classical certificate: a client without ML-DSA signatures is refused
            classical.wrap(socket.create_connection(("127.0.0.1", strict), timeout=10), "localhost", 10).close()
        try:  # browsers differ: Chromium 156 verifies ML-DSA in TLS and gets through; earlier ones are refused like the client above
            page.goto(f"https://localhost:{strict}/", timeout=10000)
        except Exception:  # noqa: BLE001
            return
        self.assertEqual(page.inner_text("h1"), "hello from behind the edge")


class RevocationFollowTest(Scenario):
    def test_a_revocation_reaches_a_remote_edge_through_the_published_crl_and_ends_the_session(self):
        import shutil as sh
        upstream = free_port()
        listener = socket.create_server(("127.0.0.1", upstream))
        self.addCleanup(listener.close)

        def echo():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                import threading
                def serve(c):
                    with c:
                        while data := c.recv(4096):
                            c.sendall(data)
                threading.Thread(target=serve, args=(conn,), daemon=True).start()
        import threading
        threading.Thread(target=echo, daemon=True).start()
        pub, front = free_port(), free_port()
        self.pqc("ca", "publish", "--dir", self.d / "pki", "--listen", f"127.0.0.1:{pub}", log="publish.log")
        wait_port(pub)
        srv, _ = self.ca.issue("service.internal", "server", ["127.0.0.1"], out=self.d / "srv")
        cli, rec = self.ca.issue("partner", "client", out=self.d / "partner")
        sh.copy(self.d / "pki" / "crl.pem", self.d / "edge-crl.pem")
        self.edge(self.route("front", "terminate", front, upstream, cert=srv / "chain.pem", key=srv / "key.pem", ca=self.d / "pki" / "ca.crt",
                             require_client_cert=True, crl=self.d / "edge-crl.pem", crl_url=f"http://127.0.0.1:{pub}/crl.pem", crl_every=5), "front")
        wait_port(front)
        ctx = support_tls.client_context(self.d / "pki" / "ca.crt", cli / "chain.pem", cli / "key.pem")
        conn = tls.connect("127.0.0.1", front, ctx, "service.internal", 10)
        conn.sendall(b"ping")
        self.assertEqual(conn.recv(timeout=5), b"ping")
        r = subprocess.run([sys.executable, "-m", "acxelin_tls", "ca", "revoke", rec.serial, "--dir", self.d / "pki"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        deadline, cut = time.monotonic() + 30, False
        while time.monotonic() < deadline and not cut:
            try:
                conn.sendall(b"still?")
                cut = conn.recv(timeout=1) == b""
            except (tls.TLSError, OSError):
                cut = True
        self.assertTrue(cut, "the revoked client's open session must end once the edge has the new CRL\n" + self.edge_log("front"))
        self.assertIn("saved", self.edge_log("front"))
        with self.assertRaises((tls.TLSError, OSError)):
            again = tls.connect("127.0.0.1", front, ctx, "service.internal", 5)
            again.sendall(b"x")
            if again.recv(timeout=3) == b"":
                raise OSError("closed after the handshake")
