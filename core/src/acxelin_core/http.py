"""A small loopback HTTP server for JSON, metrics and health routes, and host:port parsing."""
import ipaddress
import logging
import os
import socket
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

METRICS, JSON, PEM = "text/plain; version=0.0.4; charset=utf-8", "application/json", "application/x-pem-file"


def hostport(s, default_host="0.0.0.0"):
    host, _, port = s.rpartition(":")
    if not (port.isascii() and port.isdigit() and int(port) <= 65535):
        raise ValueError(f"expected host:port with a port from 0 to 65535, got {s!r}")
    return host.strip("[]") or default_host, int(port)


HTTP_IDLE = 30  # seconds an HTTP client may stay silent before its connection is closed


def explain(e):
    """An OSError in words: 'host not found' rather than '[Errno -2] Name or service not known'."""
    if isinstance(e, socket.gaierror):
        return "host not found (not in DNS or the hosts file)"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused (nothing is listening on that port)"
    if isinstance(e, TimeoutError):
        return "no answer (timed out; is a firewall dropping it?)"
    if isinstance(e, ConnectionResetError):
        return "the connection was reset by the other side"
    if isinstance(e, OSError) and e.strerror:
        return f"{e.strerror}: {e.filename}" if e.filename else e.strerror
    return str(e)


def network(host):
    """The unit connection caps count by: one /24 for IPv4 and one /64 for IPv6, the block a single customer usually gets, so
    an attacker cannot multiply its share by using more addresses from its own block. Loopback addresses count one by one."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return host if ip.is_loopback else str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False))


class GuardedHTTPServer(ThreadingHTTPServer):
    """At most `max_connections` at once and `per_client` from one network, each closed `deadline` seconds after it opened
    whatever it is doing: a few machines trickling requests cannot hold every thread or file descriptor. `wrap` turns the
    accepted socket into the one requests are read from (TLS, for ACME)."""
    daemon_threads = True
    max_connections, per_client, deadline = 128, 16, 30.0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.guard, self.held, self.watched, self.closed = threading.Lock(), Counter(), {}, threading.Event()
        threading.Thread(target=self._reap, daemon=True, name="http-deadline").start()

    def server_close(self):
        self.closed.set()
        super().server_close()

    def wrap(self, request):
        return request

    def process_request(self, request, address):
        net = network(address[0])
        with self.guard:
            refused = sum(self.held.values()) >= self.max_connections or self.held[net] >= self.per_client
            if not refused:
                self.held[net] += 1
        if refused:
            return self.shutdown_request(request)
        try:
            super().process_request(request, address)
        except BaseException:
            self._release(net)
            raise

    def process_request_thread(self, request, address):
        me, start = threading.get_ident(), time.monotonic()
        try:
            with self.guard:
                self.watched[me] = request, start
            request = self.wrap(request)
            with self.guard:
                self.watched[me] = request, start
            super().process_request_thread(request, address)
        except OSError:
            self.shutdown_request(request)
        finally:
            with self.guard:
                self.watched.pop(me, None)
            self._release(network(address[0]))

    def _release(self, net):
        with self.guard:
            self.held[net] -= 1
            if self.held[net] <= 0:
                del self.held[net]

    def _reap(self):
        while not self.closed.wait(0.5):
            t = time.monotonic()
            with self.guard:
                late = [s for s, start in self.watched.values() if t - start > self.deadline]
            for s in late:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def serve_http(address, routes):
    """Answers GET on a background thread. `routes` maps a path to (content type, function returning the body as text, or
    None for 404); /healthz always answers ok."""

    routes = {"/healthz": ("text/plain; charset=utf-8", lambda: "ok\n"), **routes}

    class Handler(BaseHTTPRequestHandler):
        timeout = HTTP_IDLE

        def do_GET(self):
            ctype, fn = routes.get(self.path, (None, lambda: None))
            body = fn()
            if body is None:
                self.send_error(404)
                return
            body = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = http_server(address, Handler, GuardedHTTPServer)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def content_length(headers):
    """An HTTP request's body length, or None unless the header is a plain non-negative number (int() would accept "-1",
    and reading -1 bytes reads until the client stops sending)."""
    values = headers.get_all("Content-Length", []) if hasattr(headers, "get_all") else [headers.get("Content-Length", "0")]
    if len(values) > 1 or headers.get("Transfer-Encoding"):
        return None
    v = values[0] if values else "0"
    return int(v) if 0 < len(v) <= 20 and v.isascii() and v.isdigit() else None


def file_stamp(path):
    """What changes when a file is rewritten, even twice within one timestamp tick: its mtime in ns, size and inode."""
    st = os.stat(path)
    return st.st_mtime_ns, st.st_size, st.st_ino


class ConfigWatch:
    """Follows a service's configuration file: when it changes (checked every few seconds) or on `poke()` (SIGHUP), the file
    is loaded again once it has stopped changing (an editor may write it in several steps) and, if it loads and validates,
    handed to `apply`. A file that does not load is logged and the running configuration stays as it is."""

    def __init__(self, path, load, apply, every=5.0, settle=0.3, log=None):
        self.path, self.load, self.apply, self.every, self.settle = path, load, apply, every, settle
        self.log = log or logging.getLogger(__name__)
        self.seen = file_stamp(self.path)
        self.wake, self.stopped = threading.Event(), False
        threading.Thread(target=self._loop, daemon=True, name="config").start()

    def poke(self):
        self.wake.set()

    def stop(self):
        self.stopped = True
        self.wake.set()

    def _loop(self):
        log = self.log
        while True:
            poked = self.wake.wait(self.every)
            self.wake.clear()
            if self.stopped:
                return
            try:
                stamp = file_stamp(self.path)
                if stamp == self.seen and not poked:
                    continue
                while True:
                    time.sleep(self.settle)
                    now = file_stamp(self.path)
                    if now == stamp:
                        break
                    stamp = now
                self.seen = stamp
                new = self.load(self.path)
            except Exception as e:
                log.error("%s changed but cannot be used, keeping the running configuration: %s", self.path, e)
                continue
            log.info("%s changed; applying it", self.path)
            try:
                self.apply(new)
            except Exception:
                log.exception("applying %s failed", self.path)


def restart(module):
    """Replace this process with `python -m module` and the same arguments (same PID, so systemd and supervisors keep following it)."""
    logging.getLogger(__name__).info("restarting to apply the new configuration")
    logging.shutdown()
    os.execv(sys.executable, [sys.executable, "-m", module, *sys.argv[1:]])


def nodelay(sock):
    """Send each write at once. With Nagle's algorithm on, a reply that follows a small unacknowledged write waits up to
    40 ms for the peer's delayed ACK, which multiplies request/response latency (databases, Redis, APIs)."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass  # not TCP (a Unix socket in tests), or already closed
    return sock


def listen(address, backlog=1024, reuse_port=False):
    """A listening socket for (host, port). An IPv6 host gets an IPv6 socket; "::" (every interface, the default) also takes
    IPv4 clients, and falls back to IPv4 alone on a machine without IPv6."""
    if ":" not in address[0]:
        return socket.create_server(address, backlog=backlog, reuse_port=reuse_port)
    try:
        return socket.create_server(address, family=socket.AF_INET6, backlog=backlog, reuse_port=reuse_port,
                                    dualstack_ipv6=address[0] == "::" and socket.has_dualstack_ipv6())
    except OSError:
        if address[0] != "::":
            raise
        return socket.create_server(("0.0.0.0", address[1]), backlog=backlog, reuse_port=reuse_port)  # no IPv6 here


def http_server(listen_on, handler, server_class=None):
    """A ThreadingHTTPServer on "host:port" (default host 127.0.0.1), on the same socket listen() gives."""
    httpd = (server_class or ThreadingHTTPServer)(("127.0.0.1", 0), handler, bind_and_activate=False)
    httpd.socket.close()
    httpd.socket = listen(hostport(listen_on, "127.0.0.1"), backlog=128)
    httpd.address_family = httpd.socket.family
    httpd.server_address = httpd.socket.getsockname()[:2]
    httpd.server_name, httpd.server_port = httpd.server_address
    return httpd
