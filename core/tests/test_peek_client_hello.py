"""The server can read a client's first TLS record without consuming it, so the handshake that follows is unaffected."""
import socket
import threading
import time

from acxelin_core.server import peek_client_hello


def record(size):
    return b"\x16\x03\x01" + size.to_bytes(2, "big") + b"\x01" * size


def pair():
    server = socket.create_server(("127.0.0.1", 0))
    client = socket.create_connection(server.getsockname())
    peer, _ = server.accept()
    server.close()
    return client, peer


def test_a_record_that_arrives_in_pieces_is_read_whole_and_left_in_the_queue():
    client, peer = pair()
    data = record(300)
    threading.Thread(target=lambda: (client.sendall(data[:50]), time.sleep(0.2), client.sendall(data[50:])), daemon=True).start()
    assert peek_client_hello(peer, 3) == data
    peer.settimeout(2)
    got = b""
    while len(got) < len(data):
        got += peer.recv(4096)
    assert got == data, "peeking consumed nothing"


def test_a_client_that_sends_nothing_or_hangs_up_gives_none_after_the_timeout():
    client, peer = pair()
    start = time.monotonic()
    assert peek_client_hello(peer, 0.3) is None and time.monotonic() - start < 2
    client.close()
    assert peek_client_hello(peer, 1) is None


def test_something_that_is_not_a_tls_record_or_is_too_long_gives_none():
    for junk in (b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\xff\xff" + b"A" * 100, b"\x15\x03\x03\x00\x02\x02\x28", b"\x16\x02\x00\x00\x10" + b"\x00" * 16):
        client, peer = pair()
        client.sendall(junk)
        assert peek_client_hello(peer, 0.5) is None, junk[:8]
