import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from acxelin_core import config, console, files, http


@dataclass
class Settings:
    name: str
    port: int = 1
    tags: list = field(default_factory=list)


def test_config_reports_unknown_missing_and_mistyped_settings():
    assert config.build(Settings, {"name": "a"}, "x").name == "a"
    for doc, words in (({"name": "a", "nope": 1}, "unknown settings nope"), ({}, "missing name"), ({"name": "a", "port": "1"}, "port must be a whole number")):
        with pytest.raises(ValueError, match=words):
            config.build(Settings, doc, "x")


def test_config_reads_utf16_and_bom_text(tmp_path):
    for data in ('name = "a"\n'.encode("utf-16"), b'\xef\xbb\xbfname = "a"\n'):
        (tmp_path / "c.toml").write_bytes(data)
        assert config.read_toml(tmp_path / "c.toml") == {"name": "a"}


def test_files_write_secret_is_owner_only(tmp_path):
    files.write(tmp_path / "s", b"x", secret=True)
    assert (tmp_path / "s").read_bytes() == b"x"
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "s").stat().st_mode) == 0o600


def test_hostport_takes_the_default_host_from_the_caller():
    assert http.hostport(":80", "127.0.0.1") == ("127.0.0.1", 80)
    assert http.hostport("[::1]:9", "0.0.0.0") == ("::1", 9)
    with pytest.raises(ValueError):
        http.hostport("host:99999")


def test_serve_http_answers_healthz_and_routes():
    server = http.serve_http("127.0.0.1:0", {"/x": (http.JSON, lambda: '{"a": 1}')})
    port = server.server_address[1]
    assert urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz").read() == b"ok\n"
    assert json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/x").read()) == {"a": 1}
    server.shutdown()


def test_backoff_policy_comes_from_the_caller():
    for limit in (2, 5):
        b = console.Backoff(limit=limit, window=60)
        for _ in range(limit):
            b.failed("1.2.3.4")
        assert b.blocked("1.2.3.4") and not b.blocked("5.6.7.8")


# The console access contract (spec: "Console access and security").

def test_ticket_is_single_use_and_expires():
    s = console.Sessions(ticket_ttl=0.2)
    t = s.ticket()
    assert s.redeem(t) and not s.redeem(t)
    late = s.ticket()
    time.sleep(0.3)
    assert s.redeem(late) is None


def test_redeemed_ticket_gives_a_session_token_that_authorises():
    s = console.Sessions()
    token = s.redeem(s.ticket())
    assert len(token) >= 43 and s.authorised(f"Bearer {token}")
    assert not s.authorised("Bearer wrong") and not s.authorised(None)


@pytest.mark.parametrize("host,origin,site,status", [
    ("127.0.0.1:8900", None, None, None),
    ("localhost:9000", "http://localhost:9000", "same-origin", None),
    ("[::1]:8900", None, None, None),
    ("evil.example:8900", None, None, 421),
    ("127.0.0.1.evil.example", None, None, 421),
    ("localhost:8900", "http://evil.example", None, 403),
    ("localhost:8900", "http://localhost:8901", None, 403),
    ("localhost:8900", None, "cross-site", 403),
])
def test_request_checks_refuse_foreign_hosts_origins_and_cross_site(host, origin, site, status):
    headers = {"Host": host, **({"Origin": origin} if origin else {}), **({"Sec-Fetch-Site": site} if site else {})}
    assert console.refusal(headers) == (None if status is None else status)


def test_console_page_flow_issues_no_cookie_and_keeps_secrets_out_of_logs(tmp_path, caplog):
    caplog.set_level("DEBUG")
    html = b"<!doctype html><title>t</title><script>1</script>"
    app = console.App(html, {("GET", "/api/status"): lambda body: (200, {"ok": True})})
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/")
        assert "Set-Cookie" not in page.headers and "sha256-" in page.headers["Content-Security-Policy"]
        ticket = app.sessions.ticket()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/session", json.dumps({"ticket": ticket}).encode(), {"Content-Type": "application/json"})
        answer = urllib.request.urlopen(req)
        token = json.loads(answer.read())["token"]
        assert "Set-Cookie" not in answer.headers
        api = urllib.request.Request(f"http://127.0.0.1:{port}/api/status", headers={"Authorization": f"Bearer {token}"})
        assert json.loads(urllib.request.urlopen(api).read()) == {"ok": True}
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/status?token={token}"))
        assert e.value.code == 401
        assert ticket not in caplog.text and token not in caplog.text
    finally:
        server.shutdown()


def test_lockout_after_ten_wrong_tokens_per_address():
    app = console.App(b"<script>1</script>", {})
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    codes = []
    try:
        for _ in range(11):
            try:
                urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/x", headers={"Authorization": "Bearer no"}))
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        assert codes[:10] == [401] * 10 and codes[10] == 429
    finally:
        server.shutdown()


def test_link_prints_only_to_an_interactive_terminal(capsys):
    s = console.Sessions()
    assert console.link(s, 8900, tty=False) is None and capsys.readouterr().out == ""
    url = console.link(s, 8900, tty=True)
    assert url.startswith("http://127.0.0.1:8900/#") and "?" not in url and url in capsys.readouterr().out


def test_automation_token_file_is_owner_only(tmp_path):
    token = console.new_automation_token(tmp_path / "console.token")
    assert (tmp_path / "console.token").read_text().strip() == token
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "console.token").stat().st_mode) == 0o600


def test_core_imports_no_product_and_loads_no_openssl_on_import():
    code = "import sys, acxelin_core, acxelin_core.config, acxelin_core.files, acxelin_core.http, acxelin_core.console, acxelin_core.pki;" \
           "bad=[m for m in sys.modules if m.split('.')[0] in ('acxelin_readiness','acxelin_tls','acxelin_vpn')];" \
           "assert not bad, bad; assert 'acxelin_core.openssl' not in sys.modules"
    import subprocess
    assert subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parent).returncode == 0


def test_ticket_route_mints_a_ticket_only_for_an_authorised_caller():
    app = console.App(b"<script>1</script>", {})
    app.sessions.tokens.add("automation-token")
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/ticket", b"{}", {"Content-Type": "application/json"}))
        assert e.value.code == 401
        ok = urllib.request.Request(f"http://127.0.0.1:{port}/api/ticket", b"{}", {"Authorization": "Bearer automation-token", "Content-Type": "application/json"})
        assert app.sessions.redeem(json.loads(urllib.request.urlopen(ok).read())["ticket"])
    finally:
        server.shutdown()


def test_run_writes_the_automation_token_and_link_running_reaches_the_running_console(tmp_path, capsys):
    app = console.App(b"<script>1</script>", {})
    server = console.start(app, tmp_path, port=0)
    port = server.server_address[1]
    try:
        assert (tmp_path / "console.token").exists()
        url = console.link_running(port, tmp_path, tty=True)
        assert url.startswith(f"http://127.0.0.1:{port}/#") and url in capsys.readouterr().out
        assert app.sessions.redeem(url.split("#", 1)[1])
        assert console.link_running(port, tmp_path, tty=False) is None and capsys.readouterr().out == ""
    finally:
        server.shutdown()


def test_start_reuses_an_existing_automation_token(tmp_path):
    first = console.start(console.App(b"<script>1</script>", {}), tmp_path, port=0)
    token = (tmp_path / "console.token").read_text()
    first.shutdown()
    second = console.start(console.App(b"<script>1</script>", {}), tmp_path, port=0)
    second.shutdown()
    assert (tmp_path / "console.token").read_text() == token


def test_a_console_can_listen_on_all_interfaces_in_a_container_and_still_refuses_foreign_hosts(tmp_path):
    app = console.App(b"<script>1</script>", {})
    server = console.start(app, tmp_path, port=0, host="0.0.0.0")
    port = server.server_address[1]
    try:
        assert server.server_address[0] == "0.0.0.0"
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/").status == 200
        req = urllib.request.Request(f"http://127.0.0.1:{port}/", headers={"Host": "evil.example"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 421
    finally:
        server.shutdown()


def test_a_route_can_answer_with_a_file_download_but_only_when_signed_in():
    app = console.App(b"<script>1</script>", {("POST", "/api/file"): lambda body: (200, console.Download("a b/c.zip", b"PK\x03\x04data", "application/zip"))})
    app.sessions.tokens.add("t")
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/file", b"{}", {"Authorization": "Bearer t", "Content-Type": "application/json"}))
        assert r.read() == b"PK\x03\x04data" and r.headers["Content-Type"] == "application/zip"
        assert r.headers["Content-Disposition"] == 'attachment; filename="a_b_c.zip"' and r.headers["Cache-Control"] == "no-store"
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/api/file", b"{}", {"Content-Type": "application/json"}))
        assert e.value.code == 401
    finally:
        server.shutdown()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACLs")
def test_secret_files_on_windows_get_an_owner_only_acl(tmp_path):
    import subprocess
    files.write(tmp_path / "s", b"x", secret=True)
    files.append(tmp_path / "audit.jsonl", "line")
    for f in (tmp_path / "s", tmp_path / "audit.jsonl"):
        acl = subprocess.run(["icacls", str(f)], capture_output=True, text=True).stdout
        assert os.environ["USERNAME"].lower() in acl.lower(), acl
        assert not any(w in acl for w in ("Everyone", "BUILTIN\\Users", "Authenticated Users")), acl


def test_the_script_hash_matches_what_a_browser_hashes_on_a_crlf_checkout():
    """Git on Windows checks pages out with CRLF; a browser normalises newlines before hashing an inline script, so a hash of
    the raw bytes would block every page read as bytes (the VPN app window)."""
    import base64
    import hashlib
    from acxelin_core.console import policy
    lf = b"<html><script>\nconst a = 1;\nrun(a);\n</script></html>"
    browser = "sha256-" + base64.b64encode(hashlib.sha256(b"\nconst a = 1;\nrun(a);\n").digest()).decode()
    assert browser in policy(lf) and browser in policy(lf.replace(b"\n", b"\r\n")) and browser in policy(lf.replace(b"\n", b"\r"))


def test_a_secret_is_made_owner_only_before_any_byte_is_written(tmp_path, monkeypatch):
    from acxelin_core import files
    sizes = []
    monkeypatch.setattr(files, "owner_only", lambda p: sizes.append(Path(p).stat().st_size))
    files.write(tmp_path / "token", b"secret-value", secret=True)
    files.append(tmp_path / "audit.log", "first line")
    assert sizes == [0, 0] and (tmp_path / "token").read_bytes() == b"secret-value"


def raw(port, method, path, headers=None, body=b""):
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body, {"Host": f"127.0.0.1:{port}", **(headers or {})})
    r = c.getresponse()
    return r.status, r.read()


def test_a_same_site_page_on_another_local_port_is_refused(tmp_path):
    assert console.refusal({"Host": "127.0.0.1:8900", "Sec-Fetch-Site": "same-site"}) == 403
    assert console.refusal({"Host": "127.0.0.1:8900", "Sec-Fetch-Site": "none"}) is None


def test_requests_without_a_credential_never_lock_out_the_real_user():
    app = console.App(b"<script>1</script>", {("GET", "/api/status"): lambda body: (200, {"ok": True})})
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        assert [raw(port, "GET", "/api/status")[0] for _ in range(15)] == [401] * 15
        ticket = app.sessions.ticket()
        assert raw(port, "POST", "/api/session", {"Content-Type": "application/json"}, json.dumps({"ticket": ticket}).encode())[0] == 200
    finally:
        server.shutdown()


def test_a_signed_in_session_keeps_working_while_wrong_tokens_are_locked_out():
    app = console.App(b"<script>1</script>", {("GET", "/api/status"): lambda body: (200, {"ok": True})})
    app.sessions.tokens.add("the-real-token")
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        codes = [raw(port, "GET", "/api/status", {"Authorization": "Bearer wrong"})[0] for _ in range(11)]
        assert codes[:10] == [401] * 10 and codes[10] == 429, "guessing is still locked out"
        assert raw(port, "GET", "/api/status", {"Authorization": "Bearer the-real-token"})[0] == 200
        assert raw(port, "POST", "/api/session", {"Content-Type": "application/json"}, json.dumps({"ticket": app.sessions.ticket()}).encode())[0] == 429
    finally:
        server.shutdown()


def test_hostile_bodies_and_failing_handlers_get_an_answer_without_internals(caplog):
    def boom(body):
        raise RuntimeError("/home/secret/path exploded")
    app = console.App(b"<script>1</script>", {("POST", "/api/boom"): boom})
    app.sessions.tokens.add("t")
    server = console.serve(app, ("127.0.0.1", 0))
    port = server.server_address[1]
    try:
        status, body = raw(port, "POST", "/api/session", {"Content-Type": "application/json"}, b"[" * 100000)
        assert status == 400 and b"invalid JSON" in body
        status, body = raw(port, "POST", "/api/boom", {"Authorization": "Bearer t", "Content-Type": "application/json"}, b"{}")
        assert status == 500 and b"exploded" not in body and "exploded" not in caplog.text
    finally:
        server.shutdown()


def test_link_running_never_sends_the_automation_token_through_a_proxy(tmp_path, monkeypatch, capsys):
    import socket
    trap = socket.socket()
    trap.bind(("127.0.0.1", 0))
    trap.listen(1)
    trap.settimeout(0.5)
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{trap.getsockname()[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{trap.getsockname()[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr(urllib.request, "_opener", None)  # urlopen caches its proxy settings from the first call
    app = console.App(b"<script>1</script>", {})
    server = console.start(app, tmp_path, port=0)
    try:
        assert console.link_running(server.server_address[1], tmp_path, tty=True)
        with pytest.raises(socket.timeout):
            trap.accept()
    finally:
        server.shutdown()
        trap.close()
