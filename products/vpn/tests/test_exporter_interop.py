"""The keys the VPN derives from a TLS session (RFC 8446 section 7.5) are the ones an independent TLS implementation derives.

Go's crypto/tls is the other side: it shares no code with OpenSSL. If the two disagree on the label, the context or the bytes, a Go-built
or OpenSSL-built peer could never share a key with this one, and this test fails. Needs Go 1.24+; set ACXELIN_REQUIRE_INTEROP=1 to fail instead of skip without it.
"""
import datetime as dt
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acxelin_core import tls
from acxelin_vpn import agreement

GO = shutil.which("go")
SOURCE = Path(__file__).resolve().parent / "interop" / "export_server.go"
LAX = tls.Policy("lax", "X25519MLKEM768:X25519", None, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")  # Go has no ML-DSA certificates


def go_version():
    m = re.search(r"go(\d+)\.(\d+)", subprocess.run([GO, "version"], capture_output=True, text=True).stdout) if GO else None
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


if go_version() < (1, 24) and os.environ.get("ACXELIN_REQUIRE_INTEROP") == "1":
    pytest.fail("ACXELIN_REQUIRE_INTEROP=1 but Go 1.24+ is not installed", pytrace=False)
pytestmark = pytest.mark.skipif(go_version() < (1, 24), reason="needs Go 1.24+ (the other TLS implementation); ACXELIN_REQUIRE_INTEROP=1 makes this a failure")


@pytest.fixture(scope="module")
def go_server(tmp_path_factory):
    work = tmp_path_factory.mktemp("go")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False).sign(key, hashes.SHA256()))
    (work / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (work / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    binary = work / ("export_server.exe" if os.name == "nt" else "export_server")
    built = subprocess.run([GO, "build", "-o", str(binary), str(SOURCE)], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    return work, binary


def exchange(go_server, label, context, length):
    """Our client against the Go server; returns (our export, Go's export)."""
    work, binary = go_server
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([str(binary), f"127.0.0.1:{port}", str(work / "c.pem"), str(work / "k.pem"), label, context, str(length)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "listening"
        conn = tls.connect("127.0.0.1", port, tls.client_context(LAX, ca=str(work / "c.pem")), "localhost", 10)
        conn.sendall(b"go\n")
        ours = conn.export(label, context.encode(), length)
        theirs = proc.stdout.readline().strip()
        conn.close()
    finally:
        proc.kill()
    return ours.hex(), theirs


def test_the_wireguard_key_is_what_go_derives(go_server):
    context = agreement.wireguard_context("gw.example", "alice", "0123456789ab", "CLIENTPUB=", "GATEWAYPUB=")
    ours, theirs = exchange(go_server, agreement.WIREGUARD, context.decode(), 32)
    assert ours == theirs and len(ours) == 64


def test_the_ipsec_keys_are_what_go_derives(go_server):
    context = agreement.ipsec_context("site-b", "site-a", "ba9876543210")
    ours, theirs = exchange(go_server, agreement.IPSEC, context.decode(), 64)
    assert ours == theirs and len(ours) == 128


def test_a_different_context_gives_a_different_key(go_server):
    a, _ = exchange(go_server, agreement.WIREGUARD, "one", 32)
    b, _ = exchange(go_server, agreement.WIREGUARD, "two", 32)
    assert a != b, "the check above would pass for a constant if the context were ignored"


def test_the_labels_are_the_pinned_ones():
    assert (agreement.WIREGUARD, agreement.IPSEC) == ("EXPORTER-pqcsuite-wireguard-v1", "EXPORTER-pqcsuite-ipsec-v1"), "rule 5: these do not change"
    assert sys.version_info >= (3, 11)
