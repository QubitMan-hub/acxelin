"""`acxelin-tls evidence create` packs what a pilot needs to show: the build and whether its installed files still match the wheel,
the configuration, the doctor's findings, the certificates (public parts only), live handshakes and the edge's counters, all
signed with an ML-DSA key from the customer's CA. `evidence verify` checks it. Keys and passphrases never go in."""
import json
import zipfile

import pytest

from acxelin_core import openssl
from acxelin_core.http import serve_http
from acxelin_core.pki import CA

from acxelin_tls import cli
from acxelin_tls.edge import Edge, load_config

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


@pytest.fixture
def site(tmp_path, monkeypatch):
    ca = CA.init(tmp_path / "pki", "Pilot Root")
    ca.issue("localhost", "server", ["127.0.0.1"], out=tmp_path / "web", passphrase=b"correct horse battery")
    ca.issue("auditor.acme", "client", out=tmp_path / "auditor")
    CA.init(tmp_path / "other", "Another Root")
    monkeypatch.setenv("WEB_KEY_PASS", "correct horse battery")
    conf = tmp_path / "edge.toml"
    conf.write_text('[[edge]]\nname = "web"\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:9"\n'
                    'cert = "web/chain.pem"\nkey = "web/key.pem"\nkey_passphrase_env = "WEB_KEY_PASS"\n')
    edge = Edge(load_config(conf)[0][0]).start()
    status = serve_http("127.0.0.1:0", {"/status": ("application/json", lambda: json.dumps({"web": {"policy": "strict", "active": 0, "groups": {"X25519MLKEM768": 3}}}))})
    yield tmp_path, conf, edge.port, f"http://127.0.0.1:{status.server_address[1]}"
    edge.stop(0)
    status.shutdown()


def run(*argv):
    with pytest.raises(SystemExit) as stop:
        cli.main(list(map(str, argv)))
    return stop.value.code


def entries(path):
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def create(d, conf, port, status, *extra):
    out = d / "evidence.zip"
    code = run("evidence", "create", "--config", conf, "--connect", f"127.0.0.1:{port}", "--ca", d / "pki" / "ca.crt",
               "--server-name", "localhost", "--status", status, "--sign-cert", d / "auditor" / "chain.pem",
               "--sign-key", d / "auditor" / "key.pem", "--out", out, *extra)
    assert code == 0
    return out


def test_a_pilot_bundle_holds_the_build_config_certificates_handshake_and_counters(site, capsys):
    d, conf, port, status = site
    e = entries(create(d, conf, port, status))
    assert e["config.toml"] == conf.read_bytes()
    build = json.loads(e["build.json"])
    assert build["product"] == "acxelin-tls" and build["environment"]["openssl"].startswith("OpenSSL 3.")
    assert {p["name"] for p in build["packages"]} >= {"acxelin-tls", "acxelin-core", "cryptography"}
    certs = json.loads(e["certificates.json"])
    assert certs[0]["route"] == "web" and certs[0]["role"] == "cert" and certs[0]["algorithm"] == "ML-DSA-65" and len(certs[0]["sha256"]) == 64
    hello = json.loads(e["connect-1.json"])
    assert hello["group"] == "X25519MLKEM768" and hello["peer_key"].startswith("ML-DSA") and hello["target"] == f"127.0.0.1:{port}"
    assert json.loads(e["status.json"])["web"]["groups"]["X25519MLKEM768"] == 3
    assert any("loads" in r["message"] for r in json.loads(e["doctor.json"]))
    assert run("evidence", "verify", d / "evidence.zip", "--ca", d / "pki" / "ca.crt") == 0
    out = capsys.readouterr().out
    assert "OK" in out and "auditor.acme" in out


def test_no_key_and_no_passphrase_ever_go_into_the_bundle(site):
    d, conf, port, status = site
    raw = b"".join(entries(create(d, conf, port, status)).values())
    for secret in ((d / "web" / "key.pem").read_bytes(), (d / "auditor" / "key.pem").read_bytes(), b"correct horse battery"):
        assert secret not in raw
    assert b"PRIVATE KEY" not in raw


def test_a_refused_handshake_is_recorded_as_evidence_not_an_error(site):
    d, conf, port, status = site
    e = entries(create(d, conf, port, status, "--policy", "cnsa2"))
    hello = json.loads(e["connect-1.json"])
    assert "refused" in hello and "group" not in hello


def test_verify_catches_a_changed_file_and_a_foreign_ca(site, capsys):
    d, conf, port, status = site
    out = create(d, conf, port, status)
    assert run("evidence", "verify", out, "--ca", d / "other" / "ca.crt") == 2
    assert "does not chain" in capsys.readouterr().out
    e = entries(out)
    e["config.toml"] = e["config.toml"].replace(b"127.0.0.1:9", b"10.0.0.5:80")
    forged = d / "forged.zip"
    with zipfile.ZipFile(forged, "w") as z:
        for n, b in e.items():
            z.writestr(n, b)
    assert run("evidence", "verify", forged, "--ca", d / "pki" / "ca.crt") == 2
    assert "config.toml was changed" in capsys.readouterr().out


def test_verify_json_and_an_unsigned_bundle(site, capsys):
    d, conf, port, status = site
    out = d / "plain.zip"
    assert run("evidence", "create", "--config", conf, "--out", out) == 0
    capsys.readouterr()
    assert run("evidence", "verify", out, "--json") == 0
    r = json.loads(capsys.readouterr().out)
    assert r["ok"] and r["signed_by"] is None and "config.toml" in r["files"]
    assert run("evidence", "verify", out, "--ca", d / "pki" / "ca.crt") == 2


def test_an_unreachable_status_address_says_what_to_do(site, capsys):
    d, conf, port, status = site
    assert run("evidence", "create", "--config", conf, "--status", "http://127.0.0.1:9", "--out", d / "x.zip") == 1
    assert "--metrics" in capsys.readouterr().err
    assert not (d / "x.zip").exists()



def test_the_counters_are_read_after_the_handshakes_so_they_include_them(site, monkeypatch):
    from acxelin_core import evidence

    from acxelin_tls import evidence_commands
    d, conf, port, status = site
    order = []
    real_status, real_handshake = evidence.fetch_status, evidence_commands.handshake
    monkeypatch.setattr(evidence, "fetch_status", lambda *a, **k: order.append("status") or real_status(*a, **k))
    monkeypatch.setattr(evidence_commands, "handshake", lambda *a, **k: order.append("handshake") or real_handshake(*a, **k))
    create(d, conf, port, status)
    assert order == ["handshake", "status"]
