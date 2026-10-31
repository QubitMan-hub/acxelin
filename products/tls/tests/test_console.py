"""Acxelin TLS console journeys at the API (spec: "Where each console feature goes"), on the shared console mechanism."""
import json
import os
import logging
import urllib.error
import urllib.request

import pytest
from acxelin_core import console as core
from acxelin_core import openssl

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from acxelin_tls import console as tc  # noqa: E402

needs_openssl = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")
PASS = "ca-pass-7f3e91"


@pytest.fixture
def home(tmp_path):
    return tmp_path / "state"


@pytest.fixture
def app(home):
    return tc.build(home)


def call(app, method, path, body=None):
    return app.routes[(method, path)](body or {})


def make_ca(app, passphrase=None):
    return call(app, "POST", "/api/ca/create", {"name": "Example Root CA", "passphrase": passphrase})


def issue(app, kind="server", cn="web.example.invalid", names=None):
    return call(app, "POST", "/api/certificates/issue", {"kind": kind, "common_name": cn, "names": names or []})[1]


def test_first_run_has_no_ca_and_creating_one_needs_a_name(app):
    assert call(app, "GET", "/api/status")[1]["configured"] is False
    with pytest.raises(ValueError, match="name"):
        call(app, "POST", "/api/ca/create", {"name": "  "})
    assert make_ca(app)[0] == 200
    status = call(app, "GET", "/api/status")[1]
    assert status["configured"] and status["name"] == "Example Root CA" and status["algorithm"] == "ML-DSA-87" and status["encrypted"] is False
    with pytest.raises(ValueError, match="already"):
        make_ca(app)


def test_an_encrypted_ca_stays_locked_after_a_restart_until_the_right_passphrase(app, home):
    make_ca(app, PASS)
    assert b"ENCRYPTED" in (home / "ca/ca.key").read_bytes()
    assert call(app, "GET", "/api/status")[1]["unlocked"] is True
    again = tc.build(home)
    status = call(again, "GET", "/api/status")[1]
    assert status["encrypted"] and status["unlocked"] is False
    with pytest.raises(ValueError, match="unlock"):
        issue(again)
    with pytest.raises(ValueError, match="passphrase"):
        call(again, "POST", "/api/ca/unlock", {"passphrase": "wrong"})
    call(again, "POST", "/api/ca/unlock", {"passphrase": PASS})
    assert issue(again)["common_name"] == "web.example.invalid"


def test_issued_certificates_are_listed_and_their_keys_stay_on_disk(app, home):
    make_ca(app)
    out = issue(app, names=["127.0.0.1"])
    assert (home / out["folder"] / "chain.pem").exists() and (home / out["folder"] / "key.pem").exists()
    rows = call(app, "GET", "/api/certificates")[1]["certificates"]
    assert [(r["common_name"], r["kind"], r["status"]) for r in rows] == [("web.example.invalid", "server", "valid")]
    assert "PRIVATE KEY" not in json.dumps(out) + json.dumps(rows)


@pytest.mark.parametrize("cn", ["", "bad name!", "x" * 300])
def test_certificate_names_are_checked(app, cn):
    make_ca(app)
    with pytest.raises(ValueError):
        issue(app, cn=cn)


def test_issuing_needs_a_ca_first(app):
    with pytest.raises(ValueError, match="create"):
        issue(app)


def test_revoking_lists_the_certificate_as_revoked_and_refreshes_the_crl(app, home):
    make_ca(app)
    row = issue(app, kind="client", cn="alice.example.invalid")
    before = call(app, "GET", "/api/status")[1]["crl"]
    call(app, "POST", "/api/certificates/revoke", {"serial": row["serial"], "reason": "keyCompromise"})
    rows = call(app, "GET", "/api/certificates")[1]["certificates"]
    assert [r["status"] for r in rows] == ["revoked"]
    from cryptography import x509
    crl = x509.load_pem_x509_crl((home / "ca/crl.pem").read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(int(row["serial"], 16)) is not None
    assert call(app, "GET", "/api/status")[1]["crl"]["days_left"] >= (before or {"days_left": 0})["days_left"] > -1
    with pytest.raises(ValueError, match="serial"):
        call(app, "POST", "/api/certificates/revoke", {"serial": "deadbeefdeadbeef"})


def test_the_crl_can_be_refreshed_on_demand(app):
    make_ca(app)
    out = call(app, "POST", "/api/crl/refresh")[1]
    assert out["days_left"] > 0


@needs_openssl
def test_edges_report_their_policy_and_a_connection_test_names_the_negotiated_group(app, home):
    from acxelin_tls.edge import Edge, Route, serve_metrics
    make_ca(app)
    cert = issue(app, cn="localhost", names=["127.0.0.1"])
    edge = Edge(Route("shop", "terminate", "127.0.0.1:0", "127.0.0.1:9", cert=str(home / cert["folder"] / "chain.pem"), key=str(home / cert["folder"] / "key.pem"))).start()
    metrics = serve_metrics("127.0.0.1:0", [edge], None)
    try:
        url = f"http://127.0.0.1:{metrics.server_address[1]}"
        call(app, "POST", "/api/edges/add", {"url": url})
        shown = call(app, "GET", "/api/edges")[1]["edges"]
        assert shown[0]["url"] == url and shown[0]["routes"][0]["name"] == "shop" and shown[0]["routes"][0]["policy"] == "strict" and shown[0]["error"] is None
        test = call(app, "POST", "/api/edges/test", {"target": f"127.0.0.1:{edge.port}", "server_name": "localhost"})[1]
        # the edge forwards to a dead port, so the handshake succeeds and the connection then closes: both are reported
        assert test["ok"] is False and test["refused_after_handshake"] and "service behind it is down" in test["error"]
        assert test["quantum_safe"] and test["group"] in ("X25519MLKEM768", "SecP384r1MLKEM1024", "SecP256r1MLKEM768") and test["peer_key"].startswith("ML-DSA")
    finally:
        edge.stop(0)
        metrics.shutdown()


@needs_openssl
def test_an_unreachable_edge_and_a_refused_connection_are_explained_in_words(app):
    make_ca(app)
    call(app, "POST", "/api/edges/add", {"url": "http://127.0.0.1:1"})
    shown = call(app, "GET", "/api/edges")[1]["edges"][0]
    assert shown["error"] and "Traceback" not in shown["error"]
    out = call(app, "POST", "/api/edges/test", {"target": "127.0.0.1:1"})[1]
    assert out["ok"] is False and "connection refused" in out["error"] and out["offers"] is None


@pytest.mark.parametrize("url", ["ftp://x", "not a url", "http://", "javascript:alert(1)"])
def test_edge_addresses_must_be_http_urls(app, url):
    with pytest.raises(ValueError, match="http"):
        call(app, "POST", "/api/edges/add", {"url": url})


@needs_openssl
def test_health_lists_each_check_with_its_level_and_what_to_do(app):
    make_ca(app)
    rows = call(app, "GET", "/api/health")[1]["checks"]
    assert rows and all(set(r) >= {"level", "message"} and r["level"] in ("ok", "warn", "fail") for r in rows)
    assert any("OpenSSL" in r["message"] and r["level"] == "ok" for r in rows)


def test_secrets_never_reach_responses_logs_or_files(app, home, caplog):
    caplog.set_level(logging.DEBUG)
    responses = [make_ca(app, PASS)[1], call(app, "GET", "/api/status")[1], issue(app), call(app, "GET", "/api/certificates")[1]]
    with pytest.raises(ValueError):
        call(tc.build(home), "POST", "/api/ca/unlock", {"passphrase": "wrong-" + PASS})
    assert PASS not in json.dumps(responses) and PASS not in caplog.text
    assert PASS.encode() not in b"".join(p.read_bytes() for p in home.rglob("*") if p.is_file())


def test_the_console_signs_in_over_http_and_loads_no_other_product(app, home):
    server = core.start(app, home, port=0)
    port = server.server_address[1]
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
        assert b"Acxelin TLS" in page and page.count(b"<script>") == 1
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status")
        assert e.value.code == 401
    finally:
        server.shutdown()
    import subprocess
    import sys
    code = "import sys, acxelin_tls.console;" \
           "bad=[m for m in sys.modules if m.split('.')[0] in ('acxelin_readiness','acxelin_vpn')]; assert not bad, bad"
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


def test_the_console_can_manage_a_ca_folder_somewhere_else(tmp_path, home):
    from acxelin_core.pki import CA
    CA.init(tmp_path / "pki", "Existing CA")
    other = tc.build(home, ca_dir=tmp_path / "pki")
    status = call(other, "GET", "/api/status")[1]
    assert status["configured"] and status["name"] == "Existing CA"
    issue(other)
    assert [r.common_name for r in CA(tmp_path / "pki").records()] == ["web.example.invalid"]


def test_a_passphrase_in_the_environment_unlocks_without_being_typed(tmp_path, home, monkeypatch):
    from acxelin_core.pki import CA
    CA.init(tmp_path / "pki", "Locked CA", passphrase=PASS.encode())
    assert call(tc.build(home, ca_dir=tmp_path / "pki"), "GET", "/api/status")[1]["unlocked"] is False
    monkeypatch.setenv("ACXELIN_TLS_CA_PASSPHRASE", PASS)
    app = tc.build(home, ca_dir=tmp_path / "pki")
    assert call(app, "GET", "/api/status")[1]["unlocked"] is True
    assert "ACXELIN_TLS_CA_PASSPHRASE" not in os.environ, "the browser and everything it starts would inherit it"
    assert issue(app)["common_name"] == "web.example.invalid"
    monkeypatch.setenv("ACXELIN_TLS_CA_PASSPHRASE", "wrong")
    assert call(tc.build(home, ca_dir=tmp_path / "pki"), "GET", "/api/status")[1]["unlocked"] is False


# --- from the PQC repo's console: renew, maintain, download, audit, edge counts, connection outcomes

import io  # noqa: E402
import zipfile  # noqa: E402


def audit_actions(home):
    return [json.loads(line)["action"] for line in (home / "audit.jsonl").read_text().splitlines()]


def test_issue_renew_revoke_and_maintain_are_audited_and_shown_as_activity(app, home):
    make_ca(app)
    r = issue(app, cn="api.example.invalid", names=["10.0.0.5"])
    row = call(app, "GET", "/api/certificates")[1]["certificates"][0]
    assert (row["names"], row["has_files"], row["renewed"]) == (["api.example.invalid", "10.0.0.5"], True, False) and "path" not in row
    new = call(app, "POST", "/api/certificates/renew", {"serial": r["serial"]})[1]
    rows = {x["serial"]: x for x in call(app, "GET", "/api/certificates")[1]["certificates"]}
    assert rows[r["serial"]]["renewed"] and rows[new["serial"]]["has_files"]
    with pytest.raises(ValueError, match="newer certificate"):
        call(app, "POST", "/api/certificates/renew", {"serial": r["serial"]})
    call(app, "POST", "/api/certificates/revoke", {"serial": r["serial"], "reason": "superseded"})
    assert call(app, "POST", "/api/certificates/maintain")[1]["renewed"] == []
    assert audit_actions(home)[-4:] == ["issue", "renew", "revoke", "maintain"]
    assert [a["action"] for a in call(app, "GET", "/api/status")[1]["activity"][:4]] == ["maintain", "revoke", "renew", "issue"]
    if os.name != "nt":
        assert os.stat(home / "audit.jsonl").st_mode & 0o077 == 0


def test_download_gives_the_key_only_when_asked_and_never_for_a_revoked_certificate(app, home):
    make_ca(app)
    r = issue(app, kind="client", cn="partner")
    _, d = call(app, "POST", "/api/certificates/download", {"serial": r["serial"]})
    assert d.content_type == "application/zip" and d.name == f"partner-{r['serial'][:8]}.zip"
    assert sorted(zipfile.ZipFile(io.BytesIO(d.data)).namelist()) == ["ca.crt", "cert.pem", "chain.pem"]
    z = zipfile.ZipFile(io.BytesIO(call(app, "POST", "/api/certificates/download", {"serial": r["serial"], "key": True})[1].data))
    assert b"PRIVATE KEY" in z.read("key.pem") and z.read("ca.crt") == (home / "ca/ca.crt").read_bytes()
    only_true = zipfile.ZipFile(io.BytesIO(call(app, "POST", "/api/certificates/download", {"serial": r["serial"], "key": "yes"})[1].data))
    assert "key.pem" not in only_true.namelist(), "only a JSON true hands out the key"
    call(app, "POST", "/api/certificates/revoke", {"serial": r["serial"]})
    with pytest.raises(ValueError, match="revoked"):
        call(app, "POST", "/api/certificates/download", {"serial": r["serial"], "key": True})
    downloads = [json.loads(line) for line in (home / "audit.jsonl").read_text().splitlines() if json.loads(line)["action"] == "download"]
    assert [d["key"] for d in downloads] == [False, True, False]


def test_an_encrypted_key_is_not_handed_out(app, home):
    make_ca(app)
    _, rec = tc.TLSConsole(home)._ca().issue("ops", "client", out=home / "issued/ops", passphrase=b"pw")
    with pytest.raises(ValueError, match="encrypted"):
        call(app, "POST", "/api/certificates/download", {"serial": rec.serial, "key": True})
    assert call(app, "POST", "/api/certificates/download", {"serial": rec.serial})[0] == 200


def test_a_csr_signed_certificate_has_no_files_to_download_or_renew(app, home):
    from acxelin_core.pki import CA, generate
    from cryptography import x509 as cx
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    make_ca(app)
    key = generate("ML-DSA-65")
    csr = cx.CertificateSigningRequestBuilder().subject_name(cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, "device")])).sign(key, None)
    rec = CA(home / "ca").sign_csr(csr.public_bytes(serialization.Encoding.PEM), "client")[1]
    for route in ("/api/certificates/download", "/api/certificates/renew"):
        with pytest.raises(ValueError, match="request"):
            call(app, "POST", route, {"serial": rec.serial})


def test_edge_status_counts_quantum_safe_handshakes(app):
    from acxelin_core.http import JSON, serve_http
    status = {"web": {"mode": "terminate", "policy": "transition", "active": 2, "handshakes": 5, "handshake_failed": 1, "groups": {"X25519MLKEM768": 3, "X25519": 2}}}
    httpd = serve_http("127.0.0.1:0", {"/status": (JSON, lambda: json.dumps(status))})
    try:
        call(app, "POST", "/api/edges/add", {"url": f"http://127.0.0.1:{httpd.server_address[1]}"})
        e = call(app, "GET", "/api/edges")[1]["edges"][0]
        assert e["routes"][0]["name"] == "web" and e["routes"][0]["quantum_safe"] == 3 and e["routes"][0]["active"] == 2
        bogus = serve_http("127.0.0.1:0", {"/status": (JSON, lambda: "[1, 2]")})
        call(app, "POST", "/api/edges/add", {"url": f"http://127.0.0.1:{bogus.server_address[1]}"})
        assert "does not answer like an edge" in call(app, "GET", "/api/edges")[1]["edges"][1]["error"]
        bogus.shutdown()
    finally:
        httpd.shutdown()


@pytest.fixture
def servers(app, home):
    """An mTLS server trusting this console's CA (with its CRL), and a server from another CA."""
    import support_tls
    from acxelin_core.pki import CA
    from acxelin_core.server import Server
    make_ca(app)
    srv = issue(app, cn="localhost", names=["127.0.0.1"])
    folder = home / srv["folder"]
    mtls = Server(("127.0.0.1", 0), lambda: support_tls.server_context(folder / "chain.pem", folder / "key.pem", home / "ca/ca.crt", True),
                  lambda c, a: c.sendall(b"ok"), crl=str(home / "ca/crl.pem"), ca=str(home / "ca/ca.crt"))
    mtls.start()
    other = CA.init(home.parent / "other", "Stranger Root")
    out, _ = other.issue("localhost", "server", ["127.0.0.1"], out=home.parent / "stranger")
    stranger = Server(("127.0.0.1", 0), lambda: support_tls.server_context(out / "chain.pem", out / "key.pem"), lambda c, a: c.sendall(b"ok"))
    stranger.start()
    yield mtls, stranger
    mtls.stop(0)
    stranger.stop(0)


@needs_openssl
def test_mutual_tls_passes_with_a_client_certificate_and_is_refused_without_or_after_revocation(app, servers):
    import time
    mtls, _ = servers
    serial = issue(app, kind="client", cn="partner")["serial"]
    ok = call(app, "POST", "/api/edges/test", {"target": f"127.0.0.1:{mtls.port}", "server_name": "localhost", "client": serial})[1]
    assert (ok["ok"], ok["group"], ok["peer_key"], ok["quantum_safe"]) == (True, "X25519MLKEM768", "ML-DSA-65", True)
    bare = call(app, "POST", "/api/edges/test", {"target": f"127.0.0.1:{mtls.port}", "server_name": "localhost"})[1]
    assert bare["ok"] is False and bare["refused_after_handshake"]
    call(app, "POST", "/api/certificates/revoke", {"serial": serial})
    time.sleep(1.1)  # the server notices a rewritten CRL by its timestamp
    revoked = call(app, "POST", "/api/edges/test", {"target": f"127.0.0.1:{mtls.port}", "server_name": "localhost", "client": serial})[1]
    assert revoked["ok"] is False and revoked["client_status"] == "revoked"


@needs_openssl
def test_a_server_from_another_ca_is_refused_and_what_it_offers_is_shown(app, servers):
    _, stranger = servers
    out = call(app, "POST", "/api/edges/test", {"target": f"127.0.0.1:{stranger.port}", "server_name": "localhost"})[1]
    assert out["ok"] is False and (out["offers"]["group"], out["offers"]["peer_key"]) == ("X25519MLKEM768", "ML-DSA-65")


def test_a_server_certificate_cannot_be_used_as_the_client(app):
    make_ca(app)
    serial = issue(app, kind="server", cn="web")["serial"]
    with pytest.raises(ValueError, match="server certificate"):
        call(app, "POST", "/api/edges/test", {"target": "localhost:1", "client": serial})


@pytest.mark.parametrize("body", [{"serial": ["x"]}, {"serial": "x" * 500}, {"serial": None}, {"kind": 5, "common_name": {}}, {"target": 7}, {"url": []}])
def test_malformed_input_is_refused_in_words_never_an_internal_error(app, body):
    make_ca(app)
    for route in ("/api/certificates/revoke", "/api/certificates/renew", "/api/certificates/download", "/api/certificates/issue", "/api/edges/test", "/api/edges/add"):
        with pytest.raises(ValueError):
            call(app, "POST", route, body)
