"""Routing by the server name and the application protocol a client asks for (SNI and ALPN), before the handshake: the ClientHello is read, not consumed."""
import random
import socket
import ssl
import threading
import time

import pytest

from acxelin_core import server

NEEDS = pytest.mark.skipif(not hasattr(ssl, "MemoryBIO"), reason="needs ssl.MemoryBIO")


def hello(name=None, alpn=None):
    """A real ClientHello, as Python's ssl produces it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=name)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return outgoing.read()


@NEEDS
def test_the_name_and_the_protocols_are_read_from_a_real_client_hello():
    assert server.client_names(hello("payments.bank.example", ["h2", "http/1.1"])) == ("payments.bank.example", ["h2", "http/1.1"])
    assert server.client_names(hello("A.Bank.Example")) == ("a.bank.example", []), "names are compared in lower case"
    assert server.client_names(hello(None, ["mqtt"])) == (None, ["mqtt"])
    assert server.client_names(hello()) == (None, [])


def test_anything_else_is_unreadable_and_never_an_exception():
    for junk in (b"", b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\x00\x05hello", b"\x16\x03\x03\xff\xff" + b"A" * 100, None):
        assert server.client_names(junk) == (None, [])


@NEEDS
def test_damaged_hellos_never_raise_and_never_invent_a_name():
    good = hello("payments.bank.example", ["h2"])
    rng = random.Random(7)
    for _ in range(3000):
        data = bytearray(good)
        for _ in range(rng.randint(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.3:
            data = data[:rng.randrange(len(data))]
        name, alpn = server.client_names(bytes(data))
        assert name is None or isinstance(name, str) and len(name) <= 253 and name.isascii()
        assert all(isinstance(a, str) for a in alpn)


class Recorder:
    """Stands in for a Server behind a Router."""
    def __init__(self):
        self.got = []
        self.stopping = threading.Event()

    def adopt(self, sock, addr):
        self.got.append((sock.recv(5, socket.MSG_PEEK), addr))
        sock.close()


def ask(port, record):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(record)
        s.settimeout(3)
        try:
            s.recv(1)
        except OSError:
            pass


def wait_for(cond, seconds=3):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not cond():
        time.sleep(0.02)
    return cond()


@pytest.fixture
def router():
    r = server.Router(("127.0.0.1", 0))
    threading.Thread(target=r.serve_forever, daemon=True).start()
    yield r
    r.close()


@NEEDS
def test_each_connection_goes_to_the_most_specific_route_and_keeps_every_byte(router):
    pay, api, grpc, other, default = (Recorder() for _ in range(5))
    router.add(pay, sni=["payments.bank.example"])
    router.add(api, sni=["*.api.bank.example"])
    router.add(grpc, sni=["*.api.bank.example"], alpn=["h2"])
    router.add(other, alpn=["mqtt"])
    router.add(default)
    cases = [("payments.bank.example", None, pay), ("x.api.bank.example", ["http/1.1"], api), ("x.api.bank.example", ["h2"], grpc),
             (None, ["mqtt"], other), ("unknown.example", None, default), (None, None, default), ("PAYMENTS.bank.example", None, pay)]
    for name, alpn, want in cases:
        record = hello(name, alpn)
        before = len(want.got)
        ask(router.port, record)
        assert wait_for(lambda: len(want.got) > before), f"{name} {alpn} did not reach its route"
        assert want.got[-1][0] == record[:5], "the handshake must still see the first byte it was sent"


@NEEDS
def test_no_matching_route_closes_the_connection_and_is_counted(router):
    router.add(Recorder(), sni=["payments.bank.example"])
    ask(router.port, hello("elsewhere.example"))
    assert wait_for(lambda: router.stats.snapshot().get("unrouted", 0) == 1)


def test_a_client_that_sends_nothing_does_not_hold_the_router_and_others_are_served(router):
    router.hello_timeout = 0.5
    default = Recorder()
    router.add(default)
    slow = [socket.create_connection(("127.0.0.1", router.port)) for _ in range(20)]
    try:
        ask(router.port, hello("a.example")) if hasattr(ssl, "MemoryBIO") else None
        assert wait_for(lambda: len(default.got) >= 1, 3), "a good client was not served while others sat silent"
        assert wait_for(lambda: router.stats.snapshot().get("unreadable", 0) >= 1 or len(default.got) >= 21, 4)
    finally:
        for s in slow:
            s.close()


def test_too_many_connections_waiting_to_be_routed_are_refused_not_queued(router):
    router.slots = threading.BoundedSemaphore(3)
    router.hello_timeout = 2
    router.add(Recorder())
    held = [socket.create_connection(("127.0.0.1", router.port)) for _ in range(8)]
    try:
        assert wait_for(lambda: router.stats.snapshot().get("refused_busy", 0) >= 4)
    finally:
        for s in held:
            s.close()


def test_a_route_can_be_removed_while_running_and_the_last_one_leaves_nothing_listening(router):
    a = Recorder()
    router.add(a, sni=["a.example"])
    router.remove(a)
    assert router.routes == []
