"""An edge staples a fresh OCSP answer for its own certificate to clients that ask, follows the file that refreshes it, and never
lets a missing or stale one break a handshake."""
import socket
import subprocess
import sys
import time

import pytest
from acxelin_core import openssl, tls
from acxelin_core.pki import CA, CAError
from acxelin_core.pki import ocsp as ocsp_
from cryptography import x509
from cryptography.x509 import ocsp

from acxelin_tls import edge, policies

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


@pytest.fixture
def world(tmp_path):
    ca = CA.init(tmp_path / "pki", "Staple Root")
    out, rec = ca.issue("shop.test", "server", ["shop.test"], out=tmp_path / "shop")
    sink = socket.socket()
    sink.bind(("127.0.0.1", 0))
    sink.listen(8)
    started = []
    yield ca, out, rec, sink, started, tmp_path
    for e in started:
        e.stop(grace=0)
    sink.close()


def free():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def route(world, **kw):
    ca, out, _, sink, started, tmp = world
    r = edge.Route(name="shop", mode="terminate", listen=f"127.0.0.1:{free()}", target=f"127.0.0.1:{sink.getsockname()[1]}",
                   cert=str(out / "chain.pem"), key=str(out / "key.pem"), **kw)
    e = edge.Edge(r).start()
    started.append(e)
    time.sleep(0.2)
    return r


def staple_of(world, r, ask=True):
    ctx = tls.client_context(policies.policy("strict"), str(world[5] / "pki" / "ca.crt"))
    ctx.request_staple = ask
    host, port = r.listen.rsplit(":", 1)
    with tls.connect(host, int(port), ctx, "shop.test", 10) as conn:
        return conn.staple


def issue_staple(world, hours=24):
    ca, out, *_ = world
    path = world[5] / "staple.der"
    path.write_bytes(ocsp_.respond(ca, x509.load_pem_x509_certificate((out / "cert.pem").read_bytes()), hours))
    return path


def test_a_client_that_asks_gets_the_answer_and_a_refreshed_file_is_followed_without_a_restart(world):
    path = issue_staple(world)
    r = route(world, ocsp_staple=str(path))
    cert = x509.load_pem_x509_certificate((world[1] / "cert.pem").read_bytes())
    assert ocsp_.check(staple_of(world, r), cert, world[0].cert) == ocsp.OCSPCertStatus.GOOD
    assert staple_of(world, r, ask=False) is None
    world[0].revoke(world[2].serial, "keyCompromise")
    issue_staple(world)
    later = path.stat().st_mtime + 5
    import os
    os.utime(path, (later, later))
    assert ocsp_.check(staple_of(world, r), cert, world[0].cert) == ocsp.OCSPCertStatus.REVOKED


def test_without_a_file_the_edge_still_serves_and_says_so(world, caplog):
    with caplog.at_level("WARNING", logger="acxelin"):
        r = route(world, ocsp_staple=str(world[5] / "missing.der"))
    assert staple_of(world, r) is None
    assert any("missing.der" in m and "no staple" in m for m in caplog.messages), caplog.messages


def test_an_answer_for_another_certificate_is_never_sent(world):
    ca = world[0]
    other, _ = ca.issue("other.test", "server", ["other.test"], out=world[5] / "other")
    path = world[5] / "staple.der"
    path.write_bytes(ocsp_.respond(ca, x509.load_pem_x509_certificate((other / "cert.pem").read_bytes())))
    assert staple_of(world, route(world, ocsp_staple=str(path))) is None


def test_the_setting_is_checked_when_the_configuration_loads(world, tmp_path):
    with pytest.raises(ValueError, match="ocsp_staple is for terminate routes"):
        edge.Route(name="x", mode="originate", listen="127.0.0.1:1", target="127.0.0.1:2", ocsp_staple="s.der").validate()
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "cert.pem").write_bytes((world[1] / "cert.pem").read_bytes())
    r = edge.Route(name="x", mode="terminate", listen="127.0.0.1:1", target="127.0.0.1:2", cert=str(bare / "cert.pem"), key=str(world[1] / "key.pem"),
                   ocsp_staple=str(tmp_path / "s.der"))
    with pytest.raises(ValueError, match="chain.pem.*CA"):
        edge.Edge(r)
    conf = tmp_path / "edge.toml"
    conf.write_text(f'[[edge]]\nmode = "terminate"\nlisten = "127.0.0.1:1"\ntarget = "127.0.0.1:2"\ncert = "{(world[1] / "chain.pem").as_posix()}"\n'
                    f'key = "{(world[1] / "key.pem").as_posix()}"\nocsp_staple = "staple.der"\n')
    assert edge.load_config(conf)[0][0].ocsp_staple == str(tmp_path / "staple.der")


def test_the_ca_command_writes_the_answer_for_a_certificate(world):
    ca, out, rec, _, _, tmp = world
    run = lambda *a: subprocess.run([sys.executable, "-m", "acxelin_tls", *map(str, a)], capture_output=True, text=True, timeout=60)
    done = run("ca", "ocsp", "--dir", tmp / "pki", "--cert", out / "chain.pem", "--out", tmp / "ans.der", "--hours", "12")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "good" in done.stdout and "12 hours" in done.stdout
    cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
    assert ocsp_.check((tmp / "ans.der").read_bytes(), cert, ca.cert) == ocsp.OCSPCertStatus.GOOD
    bad = run("ca", "ocsp", "--dir", tmp / "pki", "--cert", out / "chain.pem", "--out", tmp / "x.der", "--hours", "500")
    assert bad.returncode != 0 and "between 1 and 168" in bad.stdout + bad.stderr
    assert not (tmp / "x.der").exists()
    with pytest.raises(CAError):
        ocsp_.check(b"junk", cert, ca.cert)
