"""One listening port, several services: the edge picks the route by the name (SNI) and protocol (ALPN) the client asks for."""
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from acxelin_core import openssl, tls
from acxelin_core.pki import CA

from acxelin_tls import edge, policies

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


def backend(name):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = name.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def world(tmp_path):
    ca = CA.init(tmp_path / "pki", "Routing Root")
    certs = {}
    for name in ("pay.test", "api.test", "other.test"):
        certs[name], _ = ca.issue(name, "server", [name], out=tmp_path / name)
    ca.issue("partner", "client", out=tmp_path / "partner")
    ca.crl()
    servers = {n: backend(n) for n in ("pay", "api", "rest")}
    started = []
    yield ca, certs, servers, started, tmp_path
    for e in started:
        e.stop(grace=0)
    for s in servers.values():
        s.shutdown()


def route(world, name, listen, backend_name, **kw):
    ca, certs, servers, _, tmp = world
    cert = certs[kw.pop("cert")]
    return edge.Route(name=name, mode="terminate", listen=listen, target=f"127.0.0.1:{servers[backend_name].server_address[1]}", cert=str(cert / "chain.pem"),
                      key=str(cert / "key.pem"), **kw)


def free():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{s.getsockname()[1]}"


def fetch(world, listen, name, client=None):
    ca, _, _, _, tmp = world
    host, port = listen.rsplit(":", 1)
    ctx = tls.client_context(policies.policy("strict"), str(tmp / "pki" / "ca.crt"), *([str(tmp / client / "chain.pem"), str(tmp / client / "key.pem")] if client else []))
    conn = tls.connect(host, int(port), ctx, name, 10)
    try:
        conn.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = conn.recv(timeout=10)
            if not chunk:
                break
            data += chunk
        return data.split(b"\r\n\r\n", 1)[1].decode()
    finally:
        conn.close()


def start(world, *routes):
    for r in routes:
        world[3].append(edge.Edge(r).bind())
    time.sleep(0.3)


def test_the_name_the_client_asks_for_picks_the_service_and_its_certificate(world):
    listen = free()
    start(world, route(world, "pay", listen, "pay", cert="pay.test", sni=["pay.test"], shared=True),
          route(world, "api", listen, "api", cert="api.test", sni=["api.test"], shared=True),
          route(world, "rest", listen, "rest", cert="other.test", shared=True))
    assert fetch(world, listen, "pay.test") == "pay"
    assert fetch(world, listen, "api.test") == "api"
    assert fetch(world, listen, "other.test") == "rest", "a route with no name is the default"


def test_each_route_keeps_its_own_rules_on_the_shared_port(world):
    listen = free()
    ca, _, _, _, tmp = world
    start(world, route(world, "pay", listen, "pay", cert="pay.test", sni=["pay.test"], shared=True, ca=str(tmp / "pki" / "ca.crt"), crl=str(tmp / "pki" / "crl.pem"),
                       require_client_cert=True),
          route(world, "api", listen, "api", cert="api.test", sni=["api.test"], shared=True))
    assert fetch(world, listen, "api.test") == "api", "no client certificate needed on the route that does not ask for one"
    with pytest.raises(Exception):
        fetch(world, listen, "pay.test")
    assert fetch(world, listen, "pay.test", client="partner") == "pay"


def test_a_name_nothing_serves_is_closed_and_counted_and_the_others_carry_on(world):
    listen = free()
    start(world, route(world, "pay", listen, "pay", cert="pay.test", sni=["pay.test"], shared=True))
    with pytest.raises(Exception):
        fetch(world, listen, "stranger.test")
    assert fetch(world, listen, "pay.test") == "pay"


def test_a_route_can_leave_and_come_back_without_disturbing_the_other(world):
    listen = free()
    pay = route(world, "pay", listen, "pay", cert="pay.test", sni=["pay.test"], shared=True)
    api = route(world, "api", listen, "api", cert="api.test", sni=["api.test"], shared=True)
    start(world, pay, api)
    world[3][1].stop(grace=0)
    assert fetch(world, listen, "pay.test") == "pay"
    with pytest.raises(Exception):
        fetch(world, listen, "api.test")
    world[3][1] = edge.Edge(api).bind()
    time.sleep(0.3)
    assert fetch(world, listen, "api.test") == "api"


def test_configuration_mistakes_are_named(tmp_path):
    def load(body):
        f = tmp_path / "edge.toml"
        f.write_text(body, encoding="utf-8")
        return edge.load_config(f)
    base = 'cert = "c.pem"\nkey = "k.pem"\ntarget = "127.0.0.1:1"\n'
    ok, _ = load(f'[[edge]]\nname = "a"\nmode = "terminate"\nlisten = "0.0.0.0:8443"\nsni = ["a.example"]\n{base}[[edge]]\nname = "b"\nmode = "terminate"\nlisten = "0.0.0.0:8443"\n{base}')
    assert [r.shared for r in ok] == [True, True]
    alone, _ = load(f'[[edge]]\nname = "a"\nmode = "terminate"\nlisten = "0.0.0.0:8443"\n{base}')
    assert alone[0].shared is False, "a route alone on its port is served exactly as before"
    cases = {
        "same name twice": ('sni = ["a.example"]', 'sni = ["a.example"]', "both"),
        "two defaults": ('', '', "default"),
        "bad name": ('sni = ["a b"]', '', "not a server name"),
        "bad protocol": ('alpn = [""]', '', "protocol"),
    }
    for label, (first, second, pattern) in cases.items():
        body = f'[[edge]]\nname = "a"\nmode = "terminate"\nlisten = "0.0.0.0:8443"\n{first}\n{base}[[edge]]\nname = "b"\nmode = "terminate"\nlisten = "0.0.0.0:8443"\n{second}\n{base}'
        with pytest.raises(ValueError, match=pattern):
            load(body)
    with pytest.raises(ValueError, match="terminate"):
        load('[[edge]]\nname = "a"\nmode = "originate"\nlisten = "127.0.0.1:8443"\nsni = ["a.example"]\nca = "ca.pem"\ntarget = "127.0.0.1:1"\n')
