"""The plain HTTP servers (CRL publishing, metrics, ACME) cannot be held by a few machines: one network gets a fixed share of the
connections, and a client trickling its request a byte at a time is cut off when its time is up."""
import socket
import time
import unittest

from acxelin_core.http import serve_http


def opened(port, source="127.0.0.1"):
    s = socket.create_connection(("127.0.0.1", port), timeout=5, source_address=(source, 0))
    s.sendall(b"GET /heal")
    return s


def closed(s, within):
    s.settimeout(within)
    try:
        return s.recv(1) == b""
    except ConnectionResetError:
        return True
    except TimeoutError:
        return False


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.httpd = serve_http("127.0.0.1:0", {})
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.port = self.httpd.server_address[1]

    def test_one_network_gets_its_share_and_no_more(self):
        held = [opened(self.port) for _ in range(self.httpd.per_client)]
        self.addCleanup(lambda: [s.close() for s in held])
        time.sleep(0.3)
        self.assertTrue(closed(opened(self.port), 3), "one more from the same network is refused")
        try:
            s = opened(self.port, "127.0.0.2")
        except OSError:
            self.skipTest("this machine has no 127.0.0.2")
        s.sendall(b"thz HTTP/1.0\r\n\r\n")
        s.settimeout(5)
        self.assertIn(b"200", s.recv(100), "another network is still served")

    def test_a_request_trickled_a_byte_at_a_time_runs_out_of_time(self):
        self.httpd.deadline = 1.5
        s = opened(self.port)
        start = time.monotonic()
        try:
            while time.monotonic() - start < 8:
                s.sendall(b"x")
                time.sleep(0.2)
        except OSError:
            pass
        self.assertLess(time.monotonic() - start, 5)
