"""TLS 1.0 and 1.1 found on real servers: one that still accepts them next to TLS 1.2, and one that accepts TLS 1.2 only. The scan
offers the old versions as raw ClientHello bytes, so the answer does not depend on whether this machine's OpenSSL still speaks them."""
import datetime as dt
import socket
import ssl
import subprocess
import sys
import threading
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from acxelin_readiness import endpoints
from acxelin_readiness.detectors import probe, tls


def server(request, tmp_path, oldest, newest=ssl.TLSVersion.TLSv1_2):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "old.internal")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.minimum_version, ctx.maximum_version = oldest, newest
    except (ssl.SSLError, ValueError) as e:
        pytest.skip(f"this machine's OpenSSL cannot run a {oldest.name} server: {e}")
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    sock = socket.create_server(("127.0.0.1", 0))
    request.addfinalizer(sock.close)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                ctx.wrap_socket(conn, server_side=True).close()
            except (OSError, ssl.SSLError):
                conn.close()
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


@pytest.fixture
def old(request, tmp_path):
    return server(request, tmp_path, ssl.TLSVersion.TLSv1)


@pytest.fixture
def current(request, tmp_path):
    return server(request, tmp_path, ssl.TLSVersion.TLSv1_2)


def test_the_raw_probe_finds_tls_1_0_and_1_1_only_where_they_are_accepted(old, current):
    assert [name for name, _ in probe.legacy_versions("127.0.0.1", old)] == ["TLS 1.0", "TLS 1.1"]
    assert probe.legacy_versions("127.0.0.1", current) == []


def test_the_answer_does_not_depend_on_this_machines_openssl_offering_old_versions(old):
    code = ("import sys; sys.modules['ssl'] = None\n"  # no TLS library at all on the probing side
            "from acxelin_readiness.detectors.probe import legacy_versions\n"
            f"print([n for n, _ in legacy_versions('127.0.0.1', {old})])")
    run = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert run.stdout.strip() == "['TLS 1.0', 'TLS 1.1']", run.stderr


def test_a_scan_reports_the_old_versions_and_names_the_suite(old, current):
    sights, _, _, ep = tls.probe(f"127.0.0.1:{old}")
    assert ep["version"] == "TLSv1.2" and ep["legacy"] == ["TLS 1.0", "TLS 1.1"]
    old_sights = {s.algo: s for s in sights if s.algo in ("TLS 1.0", "TLS 1.1")}
    assert set(old_sights) == {"TLS 1.0", "TLS 1.1"} and "server accepted TLS 1.0" in old_sights["TLS 1.0"].snippet
    assert all(s.params.get("negotiated") is False for s in old_sights.values())
    assert tls.probe(f"127.0.0.1:{current}")[3]["legacy"] == []


def test_the_grader_tells_the_operator_to_switch_old_versions_off(old, current):
    results = {r["target"]: r for r in endpoints.scan([f"127.0.0.1:{old}", f"127.0.0.1:{current}"], timeout=5)}
    assert results[f"127.0.0.1:{old}"]["legacy"] == ["TLSv1.0", "TLSv1.1"]
    assert results[f"127.0.0.1:{current}"]["legacy"] == []


def test_an_openssl_too_old_to_offer_post_quantum_groups_does_not_grade_a_tls_1_3_server_classical(request, tmp_path, current, monkeypatch):
    from acxelin_core.openssl import OpenSSLUnavailable

    def too_old(*a):
        raise OpenSSLUnavailable("this machine's OpenSSL 3.0 is too old: post-quantum TLS needs OpenSSL 3.5 or newer")
    monkeypatch.setattr(endpoints, "_hello", too_old)
    modern = server(request, tmp_path, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
    monkeypatch.setattr(endpoints, "tls_groups", lambda *a: {"error": "reset"})
    r = endpoints.probe(f"127.0.0.1:{modern}", timeout=5)
    assert r["grade"] == "F" and "too old" in r["error"] and r["negotiated"] is None
    monkeypatch.setattr(endpoints, "tls_groups", lambda *a: {"tls13": True, "preferred": "X25519MLKEM768", "supported": ["X25519MLKEM768", "X25519"]})
    r = endpoints.probe(f"127.0.0.1:{modern}", timeout=5)
    assert (r["grade"], r["accepts"], r["negotiated"], r["error"]) == ("B", ["X25519MLKEM768", "X25519"], "X25519MLKEM768", None), "the raw ClientHello probe needs no new OpenSSL"
    assert r["certificate"]["key"] == "RSA-2048" and "raw ClientHello" in r["note"]
    assert endpoints.probe(f"127.0.0.1:{current}", timeout=5)["grade"] == "C", "a server with no TLS 1.3 cannot offer post-quantum groups"
