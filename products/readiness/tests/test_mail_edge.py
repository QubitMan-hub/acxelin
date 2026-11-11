"""Mail servers start TLS inside SMTP (STARTTLS on port 25 or 587), where a web-only scanner never looks: `smtp://host` and
`submission://host` are graded like any TLS endpoint, after the SMTP exchange, and a server that does not offer STARTTLS says so."""
import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acxelin_readiness import endpoints


def mail_server(request, tmp_path, starttls=True):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "mx.example.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    sock = socket.create_server(("127.0.0.1", 0))
    request.addfinalizer(sock.close)
    talks = []

    def one(conn):
        try:
            conn.settimeout(5)
            f = conn.makefile("rb")
            conn.sendall(b"220 mx.example.test ESMTP ready\r\n")
            line = f.readline()
            talks.append(line)
            conn.sendall(b"250-mx.example.test\r\n250-PIPELINING\r\n" + (b"250 STARTTLS\r\n" if starttls else b"250 8BITMIME\r\n"))
            if f.readline().strip().upper() != b"STARTTLS":
                return
            conn.sendall(b"220 2.0.0 Ready to start TLS\r\n")
            ctx.wrap_socket(conn, server_side=True).close()
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=one, args=(conn,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1], talks


def test_a_mail_server_is_graded_after_starttls(request, tmp_path):
    port, talks = mail_server(request, tmp_path)
    r = endpoints.probe(f"smtp://127.0.0.1:{port}", timeout=5)
    assert r["target"] == f"smtp://127.0.0.1:{port}"
    assert not r.get("error"), r
    assert r["negotiated"] and r["grade"] in "ABC"
    assert r["certificate"]["subject"] == "CN=mx.example.test"
    assert talks and talks[0].startswith(b"EHLO ")


def test_a_mail_server_without_starttls_says_so(request, tmp_path):
    port, _ = mail_server(request, tmp_path, starttls=False)
    r = endpoints.probe(f"smtp://127.0.0.1:{port}", timeout=5)
    assert r["grade"] == "F" and "STARTTLS" in r["error"]


@pytest.mark.parametrize("target,port", [("smtp://mx.example.test", 25), ("submission://mail.example.test", 587), ("smtps://mail.example.test", 465)])
def test_mail_targets_take_their_ports(target, port):
    assert endpoints.endpoint(target)[2] == port
    assert endpoints.load_targets([target]) == [target]


def test_scan_tls_reads_a_mail_server_too(request, tmp_path):
    from acxelin_readiness.detectors import tls
    port, _ = mail_server(request, tmp_path)
    sights, arts, notes, ep = tls.probe(f"smtp://127.0.0.1:{port}", timeout=5)
    assert ep["target"] == f"smtp://127.0.0.1:{port}"
    assert sights, notes
