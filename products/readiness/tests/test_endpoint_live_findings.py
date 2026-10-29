"""What a run against real servers on a real network showed: a server that speaks only TLS 1.0 or 1.1, an old-version probe that
could not finish, OpenSSL's lower-case group names, and SSH host keys, which have no expiry."""
import socket
import ssl
import struct
import threading

from test_legacy_tls import server

from acxelin_readiness import endpoints
from acxelin_readiness.detectors import probe


def test_a_server_that_speaks_only_tls_1_0_or_1_1_is_graded_classical_with_its_old_versions_named(request, tmp_path):
    port = server(request, tmp_path, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
    r = endpoints.probe(f"127.0.0.1:{port}", timeout=5)
    assert r["grade"] == "C" and r["error"] is None, r
    assert r["legacy"] == ["TLSv1.0", "TLSv1.1"] and r["negotiated"] == "TLSv1.1" and r["accepts"] == []
    assert "TLS 1.0" in r["note"] or "1.1" in r["note"]


def test_an_old_version_probe_that_cannot_finish_says_so_instead_of_none(request, tmp_path):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    assert probe.legacy_versions("127.0.0.1", port, 2) is None, "no answer at all is not the same as 'none accepted'"
    current = server(request, tmp_path, ssl.TLSVersion.TLSv1_2)
    assert probe.legacy_versions("127.0.0.1", current, 2) == []


def test_group_names_from_openssl_match_the_accepted_list():
    assert [endpoints.canonical(g) for g in ("x25519", "X25519MLKEM768", "x25519mlkem768", "secp384r1", "brainpoolP256r1")] == \
        ["X25519", "X25519MLKEM768", "X25519MLKEM768", "secp384r1", "brainpoolP256r1"]


def _ssh_server(request):
    names = lambda *xs: b"".join(struct.pack(">I", len(x)) + x for x in xs)
    payload = b"\x14" + b"\x00" * 16 + names(b"mlkem768x25519-sha256,curve25519-sha256", b"ssh-ed25519", b"", b"", b"", b"", b"", b"", b"", b"") + b"\x00" * 5
    pad = 8 - (len(payload) + 5) % 8 or 8
    packet = struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad
    sock = socket.create_server(("127.0.0.1", 0))
    request.addfinalizer(sock.close)

    def serve():
        try:
            conn, _ = sock.accept()
            with conn:
                conn.sendall(b"SSH-2.0-test\r\n" + packet)
                conn.recv(100)
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_ssh_host_keys_have_no_made_up_expiry_and_the_summary_copes(request):
    r = endpoints.probe(f"ssh://127.0.0.1:{_ssh_server(request)}", timeout=5)
    assert r["grade"] == "B" and r["certificate"]["days_left"] is None and r["certificate"]["expires"] == ""
    s = endpoints.summary([r])
    assert s["expiring_30d"] == 0
    endpoints.outlook([r])
