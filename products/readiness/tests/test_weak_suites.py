"""Servers that still accept RC4, 3DES or 1024-bit Diffie-Hellman, as badssl.com's rc4, 3des and dh1024 hosts do: the raw probe
offers those suites itself, so the answer does not depend on whether this machine's TLS library still speaks them."""
import socket
import ssl
import threading

import pcapgen
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from test_legacy_tls import server

from acxelin_readiness import endpoints
from acxelin_readiness.detectors import probe


def _raw_server(request, reply):
    """Answers every ClientHello with the same handshake bytes: a server that speaks a suite this machine's TLS library refuses."""
    sock = socket.create_server(("127.0.0.1", 0))
    request.addfinalizer(sock.close)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(4096)
                    conn.sendall(reply)
                except OSError:
                    pass
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


@pytest.mark.parametrize("suite,kind", [(0x0005, "RC4"), (0x000A, "3DES")])
def test_a_server_that_speaks_tls_1_2_only_with_a_broken_suite_is_named_and_not_called_tls_1_0_only(request, suite, kind):
    port = _raw_server(request, pcapgen.server_hello(suite, version=0x0303))
    assert kind in [w[0] for w in probe.weak_suites("127.0.0.1", port, 3)]
    r = endpoints.probe(f"127.0.0.1:{port}", timeout=3)
    assert r["grade"] == "C" and r["negotiated"] == "TLSv1.2" and kind in " ".join(r["weak_suites"]) and "only TLS 1.0" not in (r.get("note") or "")
    o = endpoints.outlook([r])
    assert any(kind in x["text"] and r["target"] in x["targets"] for x in o["risks"])
    assert any(x["text"].startswith("Switch off RC4") and r["target"] in x["targets"] for x in o["actions"])


def test_a_1024_bit_dh_server_is_named_with_its_size(request, tmp_path):
    params = dh.generate_parameters(generator=2, key_size=1024)
    (tmp_path / "dh.pem").write_bytes(params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))
    port = server(request, tmp_path, ssl.TLSVersion.TLSv1_2, dh=tmp_path / "dh.pem", ciphers="DHE-RSA-AES128-SHA:@SECLEVEL=0")
    found = probe.weak_suites("127.0.0.1", port, 3)
    assert ("DHE", 1024) in [(w[0], w[2]) for w in found], found
    assert "1024" in " ".join(endpoints.probe(f"127.0.0.1:{port}", timeout=3)["weak_suites"])


def test_a_3des_only_tls_1_2_server_speaks_tls_1_2_with_3des(request, tmp_path):
    port = server(request, tmp_path, ssl.TLSVersion.TLSv1_2, ciphers="DES-CBC3-SHA:@SECLEVEL=0")
    r = endpoints.probe(f"127.0.0.1:{port}", timeout=3)
    assert r["grade"] == "C" and r["negotiated"] == "TLSv1.2" and "3DES" in " ".join(r["weak_suites"]), r


def test_a_modern_server_has_no_weak_suites(request, tmp_path):
    port = server(request, tmp_path, ssl.TLSVersion.TLSv1_2, ciphers="ECDHE-RSA-AES128-GCM-SHA256")
    assert probe.weak_suites("127.0.0.1", port, 3) == []
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    assert probe.weak_suites("127.0.0.1", port, 2) is None
