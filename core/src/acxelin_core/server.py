"""A threaded PQC TLS 1.3 server: connection limits, handshake timeouts, CRL checks, certificate hot-reload and stats."""
import ipaddress
import fnmatch
import logging
import os
import socket
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from cryptography import x509

from .files import shared
from .http import file_stamp, listen, network, nodelay
from .pki import CAError, check_revocation
from .openssl import TLSError

log = logging.getLogger(__name__)


HINTS = {  # OpenSSL's words for the two ways a client without post-quantum support is refused
    "no shared signature algorithms": " (the client does not offer compatible ML-DSA signatures: use policy transition with a "
                                      "fallback certificate)",
    "no suitable key share": " (the client offers none of the key exchanges this policy allows: strict needs a post-quantum hybrid "
                             "such as X25519MLKEM768, cnsa2 needs ML-KEM-1024; update the client, or use policy transition)",
}


def open_files(needed):
    """Raise this process's open-file limit to its hard limit (systemd starts services with a soft limit of 1024, enough
    for only about 500 connections), and warn when `needed` still does not fit. None where there is no such limit."""
    try:
        import resource
    except ImportError:
        return None  # Windows: no per-process descriptor limit for sockets
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    for target in (hard, 65536, 10240):
        if target == resource.RLIM_INFINITY and sys.platform == "darwin":
            continue  # macOS accepts "unlimited" but its kernel caps descriptors far lower, silently
        if soft != resource.RLIM_INFINITY and (target == resource.RLIM_INFINITY or target > soft):
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
                soft = target
                break
            except (ValueError, OSError):
                continue
    if soft != resource.RLIM_INFINITY and needed > soft:
        log.warning("this process may open only %d files but its connection limits need about %d (two per connection); "
                    "raise LimitNOFILE (systemd) or ulimit -n, or lower max_connections", soft, needed)
    return soft


def is_loopback(host):
    """Connections from this machine (a sidecar, a health check, a local tunnel) are not rate-limited."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Revocation:
    """Checks client certificates against a CRL file, re-reading it whenever it changes. Fails closed."""

    def __init__(self, crl_path, ca_path):
        if not os.path.isfile(crl_path):
            raise ValueError(f"no CRL at {crl_path}: write one with `ca crl` (every client would be refused without it)")
        with open(ca_path, "rb") as f:
            self.crl_path, self.cas = crl_path, x509.load_pem_x509_certificates(f.read())
        self.stamp, self.data, self.swept = None, None, file_stamp(crl_path)
        self.issuers = {}  # CA certificates seen in verified chains, by subject: a resumed session brings none
        self.lock = threading.Lock()

    def changed_since_sweep(self):
        m = file_stamp(self.crl_path)
        if m == self.swept:
            return False
        self.swept = m
        return True

    def check(self, serial, chain=(), issuer=None):
        """`chain` is the verified chain above the certificate, where an intermediate CA's certificate comes from; `issuer` is the
        certificate's issuer name, whose CRL alone can clear it. Each intermediate is checked too, when its issuer's CRL is in the
        file (the root revoking an intermediate)."""
        m = file_stamp(self.crl_path)
        with self.lock:
            if m != self.stamp:
                self.data, self.stamp = shared(Path(self.crl_path).read_bytes), m
            for c in chain:
                self.issuers[c.subject.public_bytes()] = c
            data, known = self.data, list(self.issuers.values())
        cas = self.cas + known
        check_revocation(serial, data, cas, issuer)
        for c in known if issuer is not None else ():
            try:
                check_revocation(c.serial_number, data, cas, c.issuer)
            except CAError as e:
                if "revoked" in str(e):
                    raise CAError(f"the issuing CA {c.subject.rfc4514_string()} is revoked: {e}") from None


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts, self.groups, self.active = Counter(), Counter(), 0

    def add(self, key, n=1):
        with self.lock:
            self.counts[key] += n

    def opened(self, group):
        with self.lock:
            self.counts["handshakes"] += 1
            self.groups[group] += 1
            self.active += 1

    def closed(self):
        with self.lock:
            self.active -= 1

    def snapshot(self):
        with self.lock:
            return {"active": self.active, **self.counts, "groups": dict(self.groups)}


def peek_client_hello(sock, timeout=3.0):
    """The first TLS record the client sent (a ClientHello fits in one), read without taking it off the socket, so the handshake that
    follows sees every byte. None when nothing sensible arrives within `timeout`, the client hangs up, or it is not a TLS handshake record."""
    deadline, previous = time.monotonic() + timeout, sock.gettimeout()
    try:
        while (left := deadline - time.monotonic()) > 0:
            sock.settimeout(left)
            data = sock.recv(16384 + 5, socket.MSG_PEEK)
            if not data:
                return None
            if len(data) >= 5:
                size = int.from_bytes(data[3:5], "big")
                if data[0] != 0x16 or data[1] != 3 or not 4 <= size <= 16384:
                    return None
                if len(data) >= 5 + size:
                    return data[:5 + size]
            time.sleep(0.01)  # a peek returns what is there at once; wait for the rest instead of spinning
    except OSError:
        return None
    finally:
        try:
            sock.settimeout(previous)
        except OSError:
            pass
    return None


def client_names(record):
    """(server name in lower case or None, [application protocols]) from one TLS record holding a ClientHello; (None, []) for anything else or anything damaged."""
    try:
        if not record or len(record) < 9 or record[0] != 0x16 or int.from_bytes(record[3:5], "big") != len(record) - 5:
            return None, []
        hs = record[5:]
        if hs[0] != 1 or int.from_bytes(hs[1:4], "big") != len(hs) - 4:
            return None, []
        body, pos = hs[4:], 34
        pos += 1 + body[pos]
        pos += 2 + int.from_bytes(body[pos:pos + 2], "big")
        pos += 1 + body[pos]
        total = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        if pos + total != len(body):
            return None, []
        name, protocols, end = None, [], pos + total
        while pos < end:
            kind, length = int.from_bytes(body[pos:pos + 2], "big"), int.from_bytes(body[pos + 2:pos + 4], "big")
            data = body[pos + 4:pos + 4 + length]
            if len(data) != length:
                return None, []
            if kind == 0 and name is None and len(data) >= 5 and data[2] == 0:
                size = int.from_bytes(data[3:5], "big")
                text = data[5:5 + size]
                if len(text) == size and 0 < size <= 253 and text.isascii() and all(33 <= b < 127 for b in text):
                    name = text.decode().lower()
            elif kind == 16 and len(data) >= 3 and not protocols:
                i = 2
                while i < len(data) and len(protocols) < 16:
                    n = data[i]
                    item = data[i + 1:i + 1 + n]
                    if len(item) != n or not 0 < n <= 255 or not all(33 <= b < 127 for b in item):
                        protocols = []
                        break
                    protocols.append(item.decode())
                    i += 1 + n
            pos += 4 + length
        return name, protocols
    except (IndexError, ValueError):
        return None, []


class Router:
    """One listening address shared by several servers, chosen per connection by the server name (SNI) and application protocol (ALPN) in
    the ClientHello, which is read without being consumed (the chosen server's handshake sees every byte). The most specific route wins: a
    name beats a wildcard beats none, and a protocol adds to it; a connection nothing matches, or that sends no readable hello in time, is closed."""
    shared = {}
    shared_lock = threading.Lock()

    def __init__(self, address, reuse_port=False, hello_timeout=3.0, max_routing=256, name="router"):
        self.name, self.hello_timeout = name, hello_timeout
        self.sock = listen(address, reuse_port=reuse_port)
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self.routes, self.lock, self.stats = [], threading.Lock(), Stats()
        self.slots, self.stopping = threading.BoundedSemaphore(max_routing), threading.Event()

    @classmethod
    def at(cls, address, reuse_port=False):
        """The router already listening on this address in this process, or a new one that serves in the background."""
        with cls.shared_lock:
            router = cls.shared.get(address)
            if router is None or router.stopping.is_set():
                router = cls.shared[address] = cls(address, reuse_port)
                threading.Thread(target=router.serve_forever, daemon=True, name=f"router-{address[1]}").start()
            return router

    def add(self, server, sni=(), alpn=()):
        with self.lock:
            self.routes.append((server, tuple(n.lower() for n in sni), tuple(alpn)))

    def remove(self, server):
        with self.lock:
            self.routes = [r for r in self.routes if r[0] is not server]
            empty = not self.routes
        if empty:
            self.close()

    def pick(self, name, protocols):
        best, score = None, -1
        with self.lock:
            routes = list(self.routes)
        for server, names, alpns in routes:
            if names:
                if name is None:
                    continue
                exact = name in names
                if not exact and not any(fnmatch.fnmatchcase(name, n) for n in names):
                    continue
                points = 4 if exact else 2
            else:
                points = 0
            if alpns:
                if not set(alpns) & set(protocols):
                    continue
                points += 1
            if points > score:
                best, score = server, points
        return best

    def serve_forever(self):
        while not self.stopping.is_set():
            try:
                sock, addr = self.sock.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                if self.stopping.is_set():
                    break
                time.sleep(0.2)
                continue
            if not self.slots.acquire(blocking=False):
                self.stats.add("refused_busy")
                sock.close()
                continue
            try:
                threading.Thread(target=self._route, args=(sock, addr), daemon=True).start()
            except RuntimeError:
                self.slots.release()
                self.stats.add("refused_busy")
                sock.close()

    def _route(self, sock, addr):
        try:
            record = peek_client_hello(sock, self.hello_timeout)
            if record is None:
                self.stats.add("unreadable")
                sock.close()
                return
            server = self.pick(*client_names(record))
            if server is None:
                self.stats.add("unrouted")
                log.info("%s: no route for a client at %s; closed", self.name, addr[0])
                sock.close()
                return
            server.adopt(sock, addr)
        except OSError:
            sock.close()
        finally:
            self.slots.release()

    def close(self):
        self.stopping.set()
        with self.shared_lock:
            for key, value in list(self.shared.items()):
                if value is self:
                    del self.shared[key]
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class Server:
    """Accepts TCP connections, runs the PQC handshake, and hands each verified Connection to `handler(conn, address)`.

    `make_context` is called again whenever a watched file (certificate, key, CA) changes, so renewed certificates take effect
    without a restart. Existing connections keep the context they started with.
    """

    def __init__(self, address, make_context, handler, watch=(), crl=None, ca=None, max_connections=512,
                 handshake_timeout=10.0, name="tls", reuse_port=False, max_per_client=0, max_rate_per_client=50.0, hello=None, bind=True):
        self.address, self.make_context, self.handler, self.name = address, make_context, handler, name
        self.ctx = make_context()
        self.watch = {p: file_stamp(p) for p in watch if p}
        self.revocation = Revocation(crl, ca) if crl else None
        self.slots = threading.BoundedSemaphore(max_connections)
        self.max_connections, self.per_host = max_connections, max(8, max_connections // 16)
        self.per_client = max_per_client or max(16, max_connections // 8)
        self.lock, self.handshaking, self.open = threading.Lock(), Counter(), Counter()
        self.rate, self.buckets, self.warned = max_rate_per_client, {}, {}
        self.handshake_timeout, self.hello = handshake_timeout, hello  # hello(address, first TLS record or None): a product's look at who is asking
        self.stats = Stats()
        self.stopping = threading.Event()
        self.threads = set()
        self.live = {}  # connection -> (client certificate serial, chain above it), for closing revoked ones
        self.sock = listen(address, reuse_port=reuse_port) if bind else None  # bind=False: a Router hands this server its connections (adopt)
        if self.sock:
            self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1] if self.sock else 0

    def reload_if_changed(self):
        """Rebuild the context when a watched file changed. A missing or broken file keeps the old context serving."""
        try:
            changed = [p for p, m in self.watch.items() if file_stamp(p) != m]
            if not changed:
                return False
            ctx = self.make_context()
            self.watch = {p: file_stamp(p) for p in self.watch}
        except (TLSError, OSError, ValueError) as e:
            log.error("%s: keeping the old certificates, reload failed: %s", self.name, e)
            self.stats.add("reload_failed")
            return False
        self.ctx = ctx
        log.info("%s: reloaded certificates after %s changed", self.name, ", ".join(map(str, changed)))
        self.stats.add("reloads")
        return True

    def serve_forever(self):
        host = self.address[0] or "*"
        if self.sock is None:  # behind a Router: no accepting here, only the upkeep an accept loop does
            log.info("%s: serving the connections a router gives it on %s", self.name, host)
            while not self.stopping.wait(1.0):
                self.reload_if_changed()
                self.close_revoked()
            return
        log.info("%s: listening on %s:%d", self.name, f"[{host}]" if ":" in host else host, self.port)
        while not self.stopping.is_set():
            try:
                self._accept_loop()
            except Exception:  # noqa: BLE001  a route that stopped accepting would look healthy while refusing everyone
                self.stats.add("accept_loop_failed")
                log.exception("%s: the accept loop failed; starting it again", self.name)
                time.sleep(0.5)

    def _accept_loop(self):
        last_watch = time.monotonic()
        while not self.stopping.is_set():
            if time.monotonic() - last_watch > 5:
                self.reload_if_changed()
                last_watch = time.monotonic()
            self.close_revoked()
            try:
                sock, addr = self.sock.accept()
                nodelay(sock)
            except (socket.timeout, TimeoutError):
                continue
            except OSError as e:
                if self.stopping.is_set():
                    break
                self.stats.add("accept_failed")
                log.error("%s: accept failed, retrying: %s", self.name, e)
                time.sleep(0.5)
                continue
            self.adopt(sock, addr)

    def adopt(self, sock, addr):
        """Take a connection that was accepted elsewhere (by this server's own accept loop, or by a Router) through the same limits and handshake."""
        nodelay(sock)
        if not self.slots.acquire(blocking=False):
            self.stats.add("refused_busy")
            self._refuse(addr[0], "connection limit reached")
            sock.close()
            return
        refused = self._admit(addr[0])
        if refused:
            self.slots.release()
            self.stats.add("refused_host")
            self._refuse(addr[0], refused)
            sock.close()
            return
        t = threading.Thread(target=self._run, args=(sock, addr, self.ctx), daemon=True)
        with self.lock:
            self.threads.add(t)
        try:
            t.start()
        except RuntimeError as e:  # out of threads: refuse this one and keep serving the rest
            self.stats.add("refused_busy")
            self._refuse(addr[0], f"no thread for it ({e})")
            sock.close()
            self._handshake_over(addr[0])
            self._release(t, addr[0])

    def close_revoked(self):
        """When the CRL changes, close open connections whose client certificate it now revokes: a stolen device holding a
        long-lived connection (a database pool, MQTT, a tunnel) is cut off within a second or two, not at its next reconnect."""
        try:
            if not (self.revocation and self.revocation.changed_since_sweep()):
                return
        except OSError:
            return  # the CRL file is being replaced; the next pass sees it
        with self.lock:
            live = list(self.live.items())
        for conn, (serial, chain, issuer) in live:
            try:
                self.revocation.check(serial, chain, issuer)
            except (CAError, ValueError, OSError) as e:
                log.warning("%s: closing %s, its certificate is no longer accepted: %s", self.name, conn.peer_name, e)
                self.stats.add("revoked_closed")
                try:
                    conn.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _admit(self, host):
        """None, or why `host` waits. An address opens at most `rate` connections a second (bursts of twice that): a handshake
        costs milliseconds of CPU, so one machine reconnecting as fast as it can would otherwise take nearly all of it and
        slow everyone else's new connections 40-fold. A network (/24 or /64) holds at most `per_client` connections, and once
        half the connections are taken at most `per_host` unfinished handshakes: a few machines opening connections and sending
        nothing cannot lock everyone else out. This machine is held to the caps only once half the connections are taken."""
        with self.lock:
            local, net = is_loopback(host), network(host)
            if self.rate and not local and not self._take(host):
                return f"it opens more than {self.rate:g} connections a second (max_rate_per_client)"
            if not local or len(self.threads) >= self.max_connections // 2:
                if len(self.threads) >= self.max_connections // 2 and self.handshaking[net] >= self.per_host:
                    return "too many unfinished handshakes from it"
                if self.open[net] >= self.per_client:
                    return f"its network {net} already holds {self.open[net]} connections (max_per_client)"
            self.handshaking[net] += 1
            self.open[net] += 1
            return None

    def _take(self, host):
        """Token bucket per address; called under the lock. Addresses quiet for a minute are forgotten."""
        t = time.monotonic()
        tokens, last = self.buckets.get(host, (2 * self.rate, t))
        tokens = min(2 * self.rate, tokens + (t - last) * self.rate)
        if len(self.buckets) > 10000:
            self.buckets = {h: v for h, v in self.buckets.items() if t - v[1] < 60}
        self.buckets[host] = (tokens - 1, t) if tokens >= 1 else (tokens, t)
        return tokens >= 1

    def _refuse(self, host, why):
        self._warn(host, "refusing", f"refusing {host}, {why}", why.split(" ", 1)[0])

    def _warn(self, host, kind, message, reason=""):
        """One warning per address and kind every 10 seconds: a flood is refused without filling the disk with log lines."""
        key, t = (host, kind, reason), time.monotonic()
        with self.lock:
            quiet = t - self.warned.get(key, -60) >= 10
            if quiet:
                self.warned[key] = t
                if len(self.warned) > 10000:
                    self.warned = {k: v for k, v in self.warned.items() if t - v < 60}
        if quiet:
            log.warning("%s: %s (repeats from this address are counted in /status, not logged, for 10 s)", self.name, message)

    def _handshake_over(self, host):
        host = network(host)
        with self.lock:
            self.handshaking[host] -= 1
            if not self.handshaking[host]:
                del self.handshaking[host]

    def _run(self, sock, addr, ctx):
        peer = f"{addr[0]}:{addr[1]}"
        conn = None
        try:
            if self.hello:
                try:
                    self.hello(addr[0], peek_client_hello(sock, min(self.handshake_timeout, 3.0)))
                except Exception:  # noqa: BLE001  a report about the client must never stop it from being served
                    log.exception("%s: the hello hook failed", self.name)
            try:
                conn = ctx.wrap(sock, timeout=self.handshake_timeout)
                cert = conn.peer_certificate()
                if self.revocation and cert:
                    self.revocation.check(cert.serial_number, conn.peer_chain()[1:], cert.issuer)
            except (TLSError, CAError, OSError, ValueError) as e:
                if any(x in str(e) for x in ("Broken pipe", "Connection reset")):
                    self.stats.add("client_left")
                    log.info("%s: %s closed the connection during the handshake", self.name, peer)
                    return
                self.stats.add("handshake_failed")
                hint = next((h for k, h in HINTS.items() if k in str(e)), "")
                self._warn(addr[0], "rejected", f"rejected {peer}: {e}{hint}")
                return
            finally:
                self._handshake_over(addr[0])
            info = conn.info()
            if self.revocation and cert:
                conn.peer_name = peer
                with self.lock:
                    self.live[conn] = (cert.serial_number, conn.peer_chain()[1:], cert.issuer)
            self.stats.opened(info["group"])
            log.info("%s: %s %s %s %s peer=%s", self.name, peer, info["version"], info["group"], info["cipher"], info["peer"] or "-")
            try:
                self.handler(conn, addr)
            except (TLSError, OSError) as e:
                log.info("%s: %s closed: %s", self.name, peer, e)
            except Exception:
                self.stats.add("handler_failed")
                log.exception("%s: %s: handler failed", self.name, peer)
            finally:
                self.stats.closed()
        finally:
            if conn:
                with self.lock:
                    self.live.pop(conn, None)
                conn.close()
            else:
                sock.close()
            self._release(threading.current_thread(), addr[0])

    def _release(self, thread, host):
        self.slots.release()
        net = network(host)
        with self.lock:
            self.threads.discard(thread)
            self.open[net] -= 1
            if not self.open[net]:
                del self.open[net]

    def start(self):
        t = threading.Thread(target=self.serve_forever, daemon=True, name=self.name)
        t.start()
        return t

    def stop(self, grace=10.0):
        """Stop accepting, then give open connections up to `grace` seconds to finish. Connections still open after that are
        checked against the CRL until they end, so a configuration reload does not exempt them from revocation."""
        self.stopping.set()
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
        deadline = time.monotonic() + grace
        with self.lock:
            threads = list(self.threads)
        for t in threads:
            t.join(max(0, deadline - time.monotonic()))
        if self.revocation:
            threading.Thread(target=self._sweep_until_drained, daemon=True, name=f"{self.name}-crl").start()

    def _sweep_until_drained(self):
        while True:
            with self.lock:
                if not self.threads:
                    return
            self.close_revoked()
            time.sleep(1)
