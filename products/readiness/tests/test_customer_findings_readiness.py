"""Problems found by using Acxelin Readiness as a first-time customer would; each test shows the problem fixed."""
import pytest

from acxelin_core import openssl
from acxelin_core.pki import CA
from acxelin_core.server import Server
from acxelin_core.tls import Policy, server_context
from acxelin_readiness.detectors import tls as live

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


@pytest.mark.parametrize("policy", [
    Policy("strict", "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768", "mldsa87:mldsa65:mldsa44", "TLS_AES_256_GCM_SHA384"),
    Policy("cnsa2", "MLKEM1024:SecP384r1MLKEM1024", "mldsa87", "TLS_AES_256_GCM_SHA384"),
], ids=["strict", "cnsa2"])
def test_scan_reads_the_certificate_of_a_post_quantum_only_server(tmp_path, request, policy):
    """The README says a full TLS 1.3 handshake through OpenSSL 3.5 reads these certificates; `scan --tls` only tried Python's ssl."""
    ca = CA.init(tmp_path / "ca", "Scan Test CA")
    out, _ = ca.issue("app.internal", "server", ["127.0.0.1"], out=tmp_path / "app", algorithm="ML-DSA-87")
    srv = Server(("127.0.0.1", 0), lambda: server_context(policy, out / "chain.pem", out / "key.pem"), lambda c, a: c.close(), name=policy.name)
    srv.start()
    request.addfinalizer(lambda: srv.stop(grace=1))
    sights, arts, notes, ep = live.probe(f"127.0.0.1:{srv.port}", timeout=5)
    assert arts, notes
    assert any("ML-DSA" in (d.algo or "") for d in sights), [d.algo for d in sights]
    assert not any("was not read" in n for n in notes), notes
    assert ep.get("version") == "TLSv1.3", ep


def test_a_quiet_scan_that_fails_its_gate_still_says_why(tmp_path, capsys):
    """`-q` in CI exited 2 with nothing printed: the job failed and nobody could see what for."""
    from acxelin_readiness import cli
    (tmp_path / "Pay.java").write_text('class Pay { Object c = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding"); }\n')
    with pytest.raises(SystemExit) as stop:
        cli.main(["scan", str(tmp_path), "-o", str(tmp_path / "out"), "--fail-on", "high", "-q"])
    assert stop.value.code == 2
    assert "failing: " in capsys.readouterr().err
