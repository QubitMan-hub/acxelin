"""`acxelin-vpn evidence create` packs a site's build, configuration, doctor findings, certificates (public parts), its CBOM and
what the running site reports, signed with an ML-DSA key from the customer's CA. Site keys, passphrases and a partner's
pre-shared keys never go in."""
import json
import zipfile

import pytest

from acxelin_core.http import serve_http
from acxelin_core.pki import CA

from acxelin_vpn import cli


@pytest.fixture
def site(tmp_path, monkeypatch):
    ca = CA.init(tmp_path / "pki", "VPN Root")
    ca.issue("hq.acme", "site", ["203.0.113.10"], algorithm="ML-DSA-87", out=tmp_path / "hq", passphrase=b"site key words")
    ca.issue("auditor.acme", "client", out=tmp_path / "auditor")
    CA.init(tmp_path / "other", "Another Root")
    monkeypatch.setenv("HQ_KEY_PASS", "site key words")
    psk = tmp_path / "partner.psk"
    psk.write_bytes(b"partner-shared-secret-" + b"k" * 20)
    psk.chmod(0o600)
    p = lambda name: (tmp_path / name).as_posix()
    conf = tmp_path / "hq.toml"
    conf.write_text(f'[site]\nname = "hq.acme"\naddress = "203.0.113.10"\ncert = "{p("hq/chain.pem")}"\nkey = "{p("hq/key.pem")}"\n'
                    f'ca = "{p("pki/ca.crt")}"\nkey_passphrase_env = "HQ_KEY_PASS"\nkeyring_listen = "0.0.0.0:7443"\n'
                    '[[peer]]\nname = "branch.acme"\naddress = "198.51.100.7"\nlocal_subnets = ["10.1.0.0/16"]\nremote_subnets = ["10.2.0.0/16"]\n'
                    '[[peer]]\nname = "partner.example"\naddress = "192.0.2.9"\nlocal_subnets = ["10.1.0.0/16"]\nremote_subnets = ["10.9.0.0/16"]\n'
                    f'classical_fallback = true\nfallback_psk_file = "{p("partner.psk")}"\n')
    status = serve_http("127.0.0.1:0", {"/status": ("application/json", lambda: json.dumps(
        {"tunnels": {"branch.acme": {"state": "ESTABLISHED", "tier": "hybrid", "quantum_safe": True}}}))})
    yield tmp_path, conf, f"http://127.0.0.1:{status.server_address[1]}"
    status.shutdown()


def run(*argv):
    with pytest.raises(SystemExit) as stop:
        cli.main(list(map(str, argv)))
    return stop.value.code


def create(d, conf, status):
    out = d / "evidence.zip"
    assert run("evidence", "create", "--config", conf, "--status", status, "--sign-cert", d / "auditor" / "chain.pem",
               "--sign-key", d / "auditor" / "key.pem", "--out", out) == 0
    with zipfile.ZipFile(out) as z:
        return out, {n: z.read(n) for n in z.namelist()}


def test_a_site_bundle_holds_its_build_config_certificates_cbom_and_live_state(site, capsys):
    d, conf, status = site
    out, e = create(d, conf, status)
    assert e["config.toml"] == conf.read_bytes()
    assert json.loads(e["build.json"])["product"] == "acxelin-vpn"
    certs = json.loads(e["certificates.json"])
    assert {(c["role"], c["algorithm"]) for c in certs} >= {("cert", "ML-DSA-87"), ("ca", "ML-DSA-87")}
    cbom = json.loads(e["cbom.json"])
    assert any(c["name"] == "ML-KEM-768" for c in cbom["components"])
    assert json.loads(e["status.json"])["tunnels"]["branch.acme"]["quantum_safe"] is True
    assert any("loads" in r["message"] for r in json.loads(e["doctor.json"]))
    assert run("evidence", "verify", out, "--ca", d / "pki" / "ca.crt") == 0
    assert "auditor.acme" in capsys.readouterr().out
    assert run("evidence", "verify", out, "--ca", d / "other" / "ca.crt") == 2


def test_no_site_key_passphrase_or_partner_key_goes_into_the_bundle(site):
    d, conf, status = site
    raw = b"".join(create(d, conf, status)[1].values())
    for secret in ((d / "hq" / "key.pem").read_bytes(), (d / "auditor" / "key.pem").read_bytes(), b"site key words",
                   (d / "partner.psk").read_bytes()):
        assert secret not in raw
    assert b"PRIVATE KEY" not in raw


def test_a_configuration_that_does_not_load_is_refused_before_anything_is_written(site, capsys):
    d, conf, status = site
    bad = d / "bad.toml"
    bad.write_text("[site]\nname = \"x\"\n")
    assert run("evidence", "create", "--config", bad, "--out", d / "x.zip") == 1
    assert not (d / "x.zip").exists() and "bad.toml" in capsys.readouterr().err
