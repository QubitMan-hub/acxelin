"""Problems found by using Acxelin TLS as a first-time customer would; each test shows the problem fixed."""
import os
import socket
import subprocess
import sys
import time

import pytest
from acxelin_core import openssl, tls
from acxelin_core.pki import CA

from acxelin_tls import checks, policies

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


def run(*a, env=None):
    return subprocess.run([sys.executable, "-m", "acxelin_tls", *map(str, a)], capture_output=True, text=True, timeout=120,
                          env={**os.environ, **(env or {})})


def test_doctor_fails_a_route_whose_certificate_its_policy_cannot_use(tmp_path):
    ca = CA.init(tmp_path / "pki", "Root")
    out, _ = ca.issue("hr.test", "server", ["hr.test"], out=tmp_path / "hr")
    conf = tmp_path / "edge.toml"
    conf.write_text(f'[[edge]]\nname = "hr"\nmode = "terminate"\nlisten = "127.0.0.1:1"\ntarget = "127.0.0.1:2"\npolicy = "cnsa2"\n'
                    f'cert = "{(out / "chain.pem").as_posix()}"\nkey = "{(out / "key.pem").as_posix()}"\n')
    rows = checks.config(conf)
    assert any(level == "fail" and "cnsa2" in msg and "ML-DSA-87" in msg for level, msg in rows), rows
    assert not any(level == "ok" and "loads" in msg for level, msg in rows), "it must not also say the configuration is fine"


def test_the_policy_message_reads_an_ml_dsa(tmp_path):
    ca = CA.init(tmp_path / "pki", "Root")
    out, _ = ca.issue("hr.test", "server", ["hr.test"], out=tmp_path / "hr")
    with pytest.raises(tls.TLSError, match="needs an ML-DSA-87 certificate"):
        tls.server_context(policies.policy("cnsa2"), out / "chain.pem", out / "key.pem")


def test_renew_says_where_the_new_certificate_is_and_that_the_old_folder_still_holds_the_old_one(tmp_path):
    env = {"ACXELIN_TLS_CA_PASSPHRASE": "pass phrase 1"}
    assert run("ca", "init", "--name", "Root", "--dir", tmp_path / "pki", env=env).returncode == 0
    r = run("ca", "issue", "server", "pay.test", "--dir", tmp_path / "pki", "--out", tmp_path / "pay", env=env)
    serial = r.stdout.split("certificate ")[1].split()[0]
    r = run("ca", "renew", serial[:12], "--dir", tmp_path / "pki", env=env)
    assert r.returncode == 0, r.stderr
    assert str(tmp_path / "pay") in r.stdout and "--out" in r.stdout, r.stdout


def test_a_name_no_route_serves_is_described_once_with_a_hint(tmp_path):
    from acxelin_tls import edge
    ca = CA.init(tmp_path / "pki", "Root")
    out, _ = ca.issue("pay.test", "server", ["pay.test"], out=tmp_path / "pay")
    with socket.socket() as f:
        f.bind(("127.0.0.1", 0))
        port = f.getsockname()[1]
    e = edge.Edge(edge.Route(name="pay", mode="terminate", listen=f"127.0.0.1:{port}", target="127.0.0.1:9", cert=str(out / "chain.pem"),
                             key=str(out / "key.pem"), sni=["pay.test"], shared=True)).start()
    try:
        time.sleep(0.3)
        ctx = tls.client_context(policies.policy("strict"), tmp_path / "pki" / "ca.crt")
        with pytest.raises(tls.TLSError) as caught:
            tls.connect("127.0.0.1", port, ctx, "evil.test", 5)
    finally:
        e.stop(grace=0)
    msg = str(caught.value)
    assert msg.count("handshake failed") == 1, msg
    assert "server name" in msg, msg


def test_connect_shows_the_stapled_ocsp_answer(tmp_path):
    from acxelin_core.pki import ocsp
    from cryptography import x509
    from acxelin_tls import edge
    ca = CA.init(tmp_path / "pki", "Root")
    out, _ = ca.issue("shop.test", "server", ["shop.test"], out=tmp_path / "shop")
    (tmp_path / "staple.der").write_bytes(ocsp.respond(ca, x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())))
    sink = socket.socket()
    sink.bind(("127.0.0.1", 0))
    sink.listen(4)
    with socket.socket() as f:
        f.bind(("127.0.0.1", 0))
        port = f.getsockname()[1]
    e = edge.Edge(edge.Route(name="shop", mode="terminate", listen=f"127.0.0.1:{port}", target=f"127.0.0.1:{sink.getsockname()[1]}",
                             cert=str(out / "chain.pem"), key=str(out / "key.pem"), ocsp_staple=str(tmp_path / "staple.der"))).start()
    try:
        time.sleep(0.3)
        r = run("connect", f"127.0.0.1:{port}", "--ca", tmp_path / "pki" / "ca.crt", "--server-name", "shop.test")
        assert r.returncode == 0, r.stderr
        assert "ocsp" in r.stdout and "good" in r.stdout, r.stdout
    finally:
        e.stop(grace=0)
        sink.close()


def test_a_route_on_a_shared_port_says_which_port(tmp_path, caplog):
    from acxelin_tls import edge
    ca = CA.init(tmp_path / "pki", "Root")
    out, _ = ca.issue("a.test", "server", ["a.test"], out=tmp_path / "a")
    with socket.socket() as f:
        f.bind(("127.0.0.1", 0))
        port = f.getsockname()[1]
    with caplog.at_level("INFO"):
        e = edge.Edge(edge.Route(name="a", mode="terminate", listen=f"127.0.0.1:{port}", target="127.0.0.1:9", cert=str(out / "chain.pem"),
                                 key=str(out / "key.pem"), sni=["a.test"], shared=True)).start()
        time.sleep(0.5)
        e.stop(grace=0)
    assert any(f"127.0.0.1:{port}" in m and "a.test" in m for m in caplog.messages), caplog.messages


def test_doctor_says_when_the_stapled_answer_is_missing_or_about_to_end(tmp_path):
    from acxelin_core.pki import ocsp
    from cryptography import x509
    ca = CA.init(tmp_path / "pki", "Root")
    out, _ = ca.issue("shop.test", "server", ["shop.test"], out=tmp_path / "shop")
    conf = tmp_path / "edge.toml"
    conf.write_text(f'[[edge]]\nname = "shop"\nmode = "terminate"\nlisten = "127.0.0.1:1"\ntarget = "127.0.0.1:2"\nocsp_staple = "staple.der"\n'
                    f'cert = "{(out / "chain.pem").as_posix()}"\nkey = "{(out / "key.pem").as_posix()}"\n')
    assert any(level == "warn" and "no OCSP answer" in msg for level, msg in checks.config(conf))
    cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
    (tmp_path / "staple.der").write_bytes(ocsp.respond(ca, cert, hours=6))
    assert any(level == "warn" and "ends in" in msg for level, msg in checks.config(conf)), checks.config(conf)
    (tmp_path / "staple.der").write_bytes(ocsp.respond(ca, cert, hours=72))
    assert any(level == "ok" and "valid for 2 more days" in msg for level, msg in checks.config(conf)), checks.config(conf)
