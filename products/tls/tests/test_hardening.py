"""Settings that looked fine but were not: an originate tunnel open to the network, a CRL that checked nothing, numbers that
stopped every connection, paths read from the wrong folder, a renewal that dropped a key's encryption, and a client report that
said yes when the server had said no."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

import pytest

from acxelin_core.cli import positive
from acxelin_tls.edge import Route, load_config, proxy_header

from support_tls import REASON


def route(**kw):
    return Route(**({"name": "web", "mode": "terminate", "listen": "127.0.0.1:0", "target": "127.0.0.1:8080", "cert": "c", "key": "k"} | kw))


@pytest.mark.parametrize("kw,message", [
    ({"crl": "crl.pem"}, "needs ca"),
    ({"crl": "crl.pem", "ca": "ca.crt"}, "require_client_cert"),
    ({"idle_timeout": 0}, "idle_timeout"), ({"idle_timeout": -1}, "idle_timeout"), ({"max_connections": 0}, "max_connections"),
    ({"max_per_client": -1}, "max_per_client"), ({"max_rate_per_client": -2}, "max_rate_per_client"), ({"handshake_timeout": 0}, "handshake_timeout"),
])
def test_settings_that_would_check_nothing_or_stop_everything_are_refused(kw, message):
    with pytest.raises(ValueError, match=message):
        route(**kw).validate()
    route(ca="ca.crt").validate()  # a CA without a CRL is harmless
    route(crl="crl.pem", ca="ca.crt", require_client_cert=True).validate()


def test_relative_paths_are_read_from_the_config_files_folder(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "edge.toml").write_text('[[edge]]\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:8080"\nmode = "terminate"\n'
                                                'cert = "web/chain.pem"\nkey = "/abs/key.pem"\n')
    here = os.getcwd()
    os.chdir("/")
    try:
        (r,), _ = load_config(tmp_path / "etc" / "edge.toml")
    finally:
        os.chdir(here)
    assert r.cert == str(tmp_path / "etc" / "web" / "chain.pem") and Path(r.key) == Path("/abs/key.pem").resolve()


def test_an_ipv4_client_on_a_dual_stack_listener_gets_an_ipv4_proxy_header():
    assert proxy_header(("::ffff:192.0.2.7", 5000), ("::ffff:10.0.0.1", 8443)) == b"PROXY TCP4 192.0.2.7 10.0.0.1 5000 8443\r\n"
    assert proxy_header(("2001:db8::7", 5000), ("2001:db8::1", 8443)) == b"PROXY TCP6 2001:db8::7 2001:db8::1 5000 8443\r\n"


@pytest.mark.parametrize("value", ["0", "-1", "inf", "nan", "100000000"])
def test_day_and_hour_counts_must_be_sensible(value):
    with pytest.raises(argparse.ArgumentTypeError):
        positive(float)(value)
    assert positive(int)("397") == 397


def run(*args, env=None):
    return subprocess.run([sys.executable, "-m", "acxelin_tls", *args], capture_output=True, text=True, timeout=60, env=env)


def test_originate_listens_on_this_machine_only_by_default():
    from acxelin_tls import edge_commands
    p = argparse.ArgumentParser()
    edge_commands.add(p.add_subparsers())
    a = p.parse_args(["edge", "--mode", "originate", "--target", "remote:8443", "--ca", "ca.crt"])
    assert a.listen is None
    seen = []
    with pytest.MonkeyPatch.context() as m:
        m.setattr("acxelin_tls.edge.Edge", lambda r: seen.append(r) or (_ for _ in ()).throw(SystemExit))
        with pytest.raises(SystemExit):
            edge_commands.cmd_edge(a)
    assert seen[0].listen == "127.0.0.1:8443"


@pytest.mark.skipif(REASON, reason=REASON or "")
def test_an_encrypted_key_is_not_renewed_into_an_unencrypted_one(tmp_path):
    env = os.environ | {"ACXELIN_TLS_CA_PASSPHRASE": "ca-pass", "KP": "key-pass"}
    assert run("ca", "init", "--dir", str(tmp_path / "pki"), "--name", "Root", env=env).returncode == 0
    assert run("ca", "issue", "server", "web", "--dir", str(tmp_path / "pki"), "--out", str(tmp_path / "web"), "--key-passphrase-env", "KP", env=env).returncode == 0
    serial = run("ca", "list", "--dir", str(tmp_path / "pki"), env=env).stdout.split()
    serial = next(s for s in serial if len(s) >= 16 and all(c in "0123456789abcdef" for c in s))
    r = run("ca", "renew", serial, "--dir", str(tmp_path / "pki"), env=env)
    assert r.returncode != 0 and "encrypted" in r.stderr + r.stdout
    assert b"ENCRYPTED" in (tmp_path / "web" / "key.pem").read_bytes()


@pytest.mark.skipif(REASON, reason=REASON or "")
def test_connect_reports_a_refused_client_instead_of_success(tmp_path):
    from types import SimpleNamespace
    from acxelin_core import tls
    from acxelin_core.pki import CA
    from acxelin_core.server import Server
    from acxelin_tls import edge_commands, policies
    ca = CA.init(tmp_path / "pki", "Root")
    ca.issue("localhost", "server", ["127.0.0.1"], out=tmp_path / "srv")
    make = lambda: tls.server_context(policies.policy("strict"), tmp_path / "srv/chain.pem", tmp_path / "srv/key.pem", tmp_path / "pki/ca.crt", True)
    srv = Server(("127.0.0.1", 0), make, lambda conn, addr: conn.recv(timeout=5), name="mtls")
    srv.start()
    try:
        a = SimpleNamespace(cmd="connect", target=f"127.0.0.1:{srv.port}", policy="strict", ca=str(tmp_path / "pki/ca.crt"), cert=None, key=None,
                            key_passphrase_env=None, server_name="localhost", timeout=5, send=None, json=True)
        with pytest.raises(tls.TLSError, match="closed the connection|refused"):
            edge_commands.cmd_tls(a)
    finally:
        srv.stop()
