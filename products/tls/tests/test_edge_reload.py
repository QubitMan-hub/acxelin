"""Changes made on the customer's side reach the running services without anyone copying files or restarting them: a CRL
published by the CA, edited configuration files, endpoints that change grade, and new releases."""
import support_tls
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509

from acxelin_core import tls
from acxelin_core.http import PEM, serve_http
from acxelin_core.pki import CA, shared
from support_tls import REASON, wait


def revoked(path):
    return {r.serial_number for r in x509.load_pem_x509_crl(shared(Path(path).read_bytes))}


NOT_HTTP = b"not http at all\r\n\r\n"


def garbage_server(test, answer):
    """An address that answers one request with `answer`, however broken."""
    srv = socket.create_server(("127.0.0.1", 0))
    test.addCleanup(srv.close)

    def serve():
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(answer)
        conn.close()
    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}"








class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@unittest.skipIf(REASON, REASON)
class EdgeReloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.d = Path(self.tmp.name)
        self.ca = CA.init(d / "pki", "Root")
        self.ca.crl()
        self.srv, _ = self.ca.issue("localhost", "server", ["127.0.0.1"], out=d / "srv")
        self.apps = {}
        for name in ("one", "two"):
            app = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
            app.name = name
            threading.Thread(target=app.serve_forever, daemon=True).start()
            self.addCleanup(app.shutdown)
            self.apps[name] = f"127.0.0.1:{app.server_address[1]}"

    def port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def route(self, name, port, app, **kw):
        from acxelin_tls.edge import Route
        if kw.get("crl"):
            kw.setdefault("require_client_cert", True)  # a CRL only checks the client certificates a route requires
        return Route(name, "terminate", f"127.0.0.1:{port}", self.apps[app], cert=str(self.srv / "chain.pem"), key=str(self.srv / "key.pem"),
                     ca=str(self.d / "pki" / "ca.crt"), **kw)

    def get(self, port, who=None):
        ctx = support_tls.client_context(self.d / "pki" / "ca.crt", who and who / "chain.pem", who and who / "key.pem")
        with tls.connect("127.0.0.1", port, ctx, "localhost", 5) as c:
            c.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = b""
            while chunk := c.recv(timeout=5):
                data += chunk
        return data.rsplit(b"\r\n\r\n", 1)[-1].decode()

    def test_changed_routes_apply_and_untouched_ones_keep_running(self):
        from acxelin_tls.edge import Edge, reconcile
        a, b, c = self.port(), self.port(), self.port()
        edges = [Edge(r).bind() for r in (self.route("web", a, "one"), self.route("api", b, "one"))]
        for e in edges:
            threading.Thread(target=e.serve_forever, daemon=True).start()
        self.addCleanup(lambda: [e.stop(0) for e in list(edges)])
        api = edges[1]
        self.assertEqual(self.get(a), "one")
        reconcile(edges, [self.route("web", a, "two"), self.route("api", b, "one"), self.route("new", c, "two")])
        self.assertEqual(self.get(a), "two")
        self.assertEqual(self.get(c), "two")
        self.assertIs(next(e for e in edges if e.route.name == "api"), api)
        taken = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(taken.close)
        with self.assertLogs(level="ERROR"):
            reconcile(edges, [self.route("web", taken.getsockname()[1], "one"), self.route("api", b, "one")])
        self.assertEqual(self.get(a), "two")
        self.assertEqual(sorted(e.route.name for e in edges), ["api", "web"])
        with self.assertRaises((tls.TLSError, OSError)):
            self.get(c)

    def test_a_certificate_renewed_within_one_timestamp_tick_is_still_reloaded(self):
        from acxelin_core.server import Server
        chain = self.srv / "chain.pem"
        s = Server(("127.0.0.1", 0), lambda: support_tls.server_context(chain, self.srv / "key.pem"), lambda c, a: None, watch=[chain])
        self.addCleanup(s.stop, 0)
        before = os.stat(chain).st_mtime_ns
        self.ca.renew(self.ca.records()[-1].serial, out=self.srv)
        os.utime(chain, ns=(before, before))
        self.assertTrue(s.reload_if_changed())

    def test_a_route_that_cannot_bind_leaves_no_crl_follower_behind(self):
        from acxelin_tls.edge import Edge
        httpd = serve_http("127.0.0.1:0", {"/crl.pem": (PEM, lambda: (self.d / "pki" / "crl.pem").read_text())})
        self.addCleanup(httpd.shutdown)
        taken = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(taken.close)
        followers = lambda: sum(t.name == "crl" and t.is_alive() for t in threading.enumerate())
        before = followers()
        route = self.route("web", taken.getsockname()[1], "one", crl=str(self.d / "edge-crl.pem"),
                           crl_url=f"http://127.0.0.1:{httpd.server_address[1]}/crl.pem", crl_every=5)
        with self.assertRaises(OSError):
            Edge(route).bind()
        self.assertTrue(wait(lambda: followers() == before, 10))

    def test_a_revocation_at_the_ca_reaches_the_edge(self):
        from acxelin_tls.edge import Edge
        who, rec = self.ca.issue("laptop", "client", out=self.d / "laptop")
        httpd = serve_http("127.0.0.1:0", {"/crl.pem": (PEM, lambda: (self.d / "pki" / "crl.pem").read_text())})
        self.addCleanup(httpd.shutdown)
        port = self.port()
        e = Edge(self.route("mtls", port, "one", require_client_cert=True, crl=str(self.d / "edge-crl.pem"),
                            crl_url=f"http://127.0.0.1:{httpd.server_address[1]}/crl.pem", crl_every=5)).start()
        self.addCleanup(e.stop, 0)
        self.assertEqual(self.get(port, who), "one")
        self.ca.revoke(rec.serial)

        def refused():
            try:
                return self.get(port, who) == ""
            except (tls.TLSError, OSError):
                return True
        self.assertTrue(wait(refused, 12))








if __name__ == "__main__":
    unittest.main()
