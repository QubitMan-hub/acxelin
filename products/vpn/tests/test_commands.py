"""Every `acxelin-vpn` command explains itself and fails in words, and the whole invite-then-join journey runs with no other
Acxelin product, nor the old suite, importable."""
import contextlib
import io
import re
import subprocess
import sys
from pathlib import Path

import pytest

from acxelin_vpn import cli
from support_vpn import REASON


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), pytest.raises(SystemExit) as e:
        cli.main(list(argv))
    return e.value.code, out.getvalue()


def commands():
    sub = next(a for a in cli.parser()._actions if a.dest == "cmd").choices
    for name, p in sub.items():
        nested = next((a for a in p._actions if a.dest == "ca_cmd"), None)
        yield from ([(name, n) for n in nested.choices] if nested else [(name,)])


def test_every_command_has_help():
    found = list(commands())
    expected = {"doctor", "up", "status", "check", "setup", "invite", "join", "app", "desktop", "gateway", "connect", "install", "disconnect",
                "uninstall", "console", "inventory"} | {f"ca {c}" for c in ("init", "issue", "revoke", "crl", "maintain", "list", "serve")}
    assert {" ".join(c) for c in found} == expected
    for c in found:
        code, text = run(*c, "--help")
        assert code == 0 and "usage: acxelin-vpn" in text and len(text) > 120, c


def test_no_command_prints_where_to_start():
    code, text = run()
    assert code == 0 and "Start here" in text and "acxelin-vpn join" in text


@pytest.mark.parametrize("argv,words", [
    (("invite", "bob", "--enroll", "http://ca.example:9443", "--gateway", "vpn.example:7443"), "--enroll must be the https:// address"),
    (("join", "no-such.acxinvite", "--no-apply"), "could not be read"),
    (("ca", "list", "--dir", "no-such-ca"), "no-such-ca"),
    (("status", "--vici", "unix:///no/such/charon.vici"), r"cannot reach charon|acxelin-vpn\[vpn\]"),
    (("up", "--config", "no-such.toml"), "no-such.toml"),
], ids=["invite-http", "join-missing", "ca-missing", "status-no-charon", "up-missing"])
def test_errors_are_one_line_in_words(argv, words, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, text = run(*argv)
    assert code == 1 and text.startswith("error: ") and re.search(words, text) and "Traceback" not in text and text.count("\n") == 1


@pytest.mark.skipif(bool(REASON), reason=REASON or "")
def test_invite_then_join_needs_no_other_product():
    """The gateway, enrollment service, invitation and join of the end-to-end test, in a Python where Acxelin TLS, Acxelin
    Readiness cannot be imported."""
    test = Path(__file__).with_name("test_wireguard.py")
    code = ("import sys\nfor m in ('acxelin_tls', 'acxelin_readiness'): sys.modules[m] = None\nimport pytest\n"
            f"sys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', {str(test) + '::GatewayTest::test_invite_then_join_enrolls_and_agrees_keys_in_one_step'!r}]))")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300, cwd=test.parent)
    assert r.returncode == 0 and "1 passed" in r.stdout, r.stdout + r.stderr


# Moved from the suite's tests/test_cli.py with their assertions; the commands are now acxelin-vpn's.

def test_a_diagnostic_agreement_does_not_claim_a_connection():
    from unittest.mock import patch
    with patch("acxelin_vpn.wireguard.Client") as client:
        client.return_value.once.return_value = {"address": "10.0.0.2", "endpoint": "gateway:51820", "routes": ["10.0.0.0/24"], "rotate_s": 120}
        code, out = run("connect", "gateway:7443", "--cert-dir", "client", "--once", "--no-apply")
    assert code == 0
    assert "no tunnel activated" in out and "--once does not keep keys fresh" in out and "connected as" not in out
    assert not client.call_args.args[4]


def test_config_files_name_what_is_missing_or_wrong(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('[site]\nname = "x"\n')
    code, out = run("up", "--config", str(cfg))
    assert code == 1 and "[site]: missing address" in out and "Traceback" not in out
    cfg.write_text('[wireguard]\nname = "x"\n')
    code, out = run("gateway", "--config", str(cfg))
    assert code == 1 and "[wireguard]: missing endpoint" in out and "Traceback" not in out


def test_check_without_the_gateway_extra_says_how_to_add_it():
    from unittest import mock
    with mock.patch.dict(sys.modules, {"vici": None}):
        code, out = run("check")
    assert code == 1 and 'acxelin-vpn[vpn]' in out


def test_a_guided_device_key_connect_prompts_without_disclosing_the_secret(tmp_path):
    from unittest.mock import patch
    from acxelin_core.pki import CA
    ca = CA.init(tmp_path / "ca", "Test")
    ca.issue("device", "client", out=tmp_path / "device", passphrase=b"PRIVATE_DEVICE_PASSPHRASE")
    args = ["connect", "gateway.example:7443", "--cert-dir", str(tmp_path / "device"), "--no-apply", "--once"]
    with patch("sys.stdin.isatty", return_value=True), patch("getpass.getpass", return_value="PRIVATE_DEVICE_PASSPHRASE"), \
            patch("acxelin_vpn.wireguard.Client") as client:
        client.return_value.once.return_value = {"address": "10.0.0.2", "endpoint": "gateway.example:51820", "routes": [], "rotate_s": 120}
        code, out = run(*args)
    assert code == 0 and client.call_args.args[6] == b"PRIVATE_DEVICE_PASSPHRASE" and "PRIVATE_DEVICE" not in out
    with patch("sys.stdin.isatty", return_value=False), patch("acxelin_vpn.wireguard.Client") as client:
        code, out = run(*args)
    assert code != 0 and "--key-passphrase-env" in out
    client.assert_not_called()
    with patch("acxelin_vpn.platforms.install") as install, patch("acxelin_vpn.wireguard.Client") as client:
        code, out = run("install", "gateway.example:7443", "--cert-dir", str(tmp_path / "device"))
    assert code != 0
    install.assert_not_called()
    client.assert_not_called()


def test_a_unix_socket_address_on_a_machine_without_them_fails_in_words(monkeypatch):
    import socket
    import types
    monkeypatch.setitem(sys.modules, "vici", types.ModuleType("vici"))  # the gateway extra, installed as on Windows CI
    monkeypatch.delattr(socket, "AF_UNIX", raising=False)
    code, out = run("check", "--vici", "unix:///var/run/charon.vici")
    assert code == 1 and "no Unix sockets" in out and "Traceback" not in out
