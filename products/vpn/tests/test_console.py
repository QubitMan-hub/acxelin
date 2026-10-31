"""The administrator console: Sites (each IPsec tunnel, its algorithms, its last key rotation and the peer's certificate),
People (invite someone and download their invitation, who is connected and since when, revoke someone and watch their session
end) and Health. It runs on acxelin-core's console mechanism, so the API is only reachable on loopback with a session."""
import http.client
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from acxelin_core import console as core
from acxelin_core.pki import CA
from acxelin_core.server import Revocation

from acxelin_vpn import console, join
from support_vpn import REASON

PASS = "vpn-ca-pass-31c9"


class Status:
    """A running site or gateway's /status, as `acxelin-vpn up` and `acxelin-vpn gateway` serve it with metrics on."""
    def __init__(self, data):
        self.data = data
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(outer.data() if callable(outer.data) else outer.data).encode()
                self.send_response(200 if self.path == "/status" else 404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    CA.init(h / "ca", "VPN Root", passphrase=PASS.encode())
    return h


@pytest.fixture
def app(home):
    a = console.build(home)
    srv = core.serve(a)
    port = srv.server_address[1]
    token = a.sessions.redeem(a.sessions.ticket())

    def call(path, body=None, headers=None, raw=False):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        h = {"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"} | ({"Authorization": f"Bearer {token}"} if token else {}) | (headers or {})
        c.request("GET" if body is None else "POST", f"/api/{path}", None if body is None else json.dumps(body), h)
        r = c.getresponse()
        data = r.read()
        return (r.status, data, dict(r.getheaders())) if raw else (r.status, json.loads(data))
    call.port, call.app = port, a
    yield call
    srv.shutdown()


def unlocked(app):
    assert app("ca/unlock", {"passphrase": "wrong"})[0] == 400
    assert app("ca/unlock", {"passphrase": PASS}) == (200, {"unlocked": True})


def test_status_says_what_is_set_up_and_a_locked_ca_asks_for_its_passphrase(app):
    code, s = app("status")
    assert code == 200 and s["configured"] and s["encrypted"] and not s["unlocked"] and s["name"] == "VPN Root"
    code, e = app("people/invite", {"name": "alice"})
    assert code == 400 and "locked" in e["error"]
    unlocked(app)
    assert app("status")[1]["unlocked"]


def test_the_console_creates_the_certificate_authority_once_and_keeps_its_passphrase_in_memory(tmp_path):
    a = console.build(tmp_path / "fresh")
    srv = core.serve(a)
    token = a.sessions.redeem(a.sessions.ticket())

    def call(path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=30)
        c.request("GET" if body is None else "POST", f"/api/{path}", None if body is None else json.dumps(body),
                  {"Host": f"127.0.0.1:{srv.server_address[1]}", "Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        r = c.getresponse()
        return r.status, json.loads(r.read())
    try:
        assert call("status")[1]["configured"] is False
        assert call("ca/create", {"name": ""})[0] == 400
        code, r = call("ca/create", {"name": "Example VPN Root", "passphrase": PASS})
        assert code == 200 and r["name"] == "Example VPN Root"
        s = call("status")[1]
        assert s["configured"] and s["encrypted"] and s["unlocked"]
        ca = tmp_path / "fresh/ca"
        assert (ca / "crl.pem").exists() and PASS.encode() not in b"".join(f.read_bytes() for f in ca.rglob("*") if f.is_file())
        assert any(e["action"] == "create" and e["name"] == "Example VPN Root" for e in console.audit.recent(ca))
        code, e = call("ca/create", {"name": "Again"})
        assert code == 400 and "already" in e["error"]
    finally:
        srv.shutdown()


def test_sites_show_each_tunnel_its_algorithms_last_rotation_and_the_peers_certificate(app, home):
    unlocked(app)
    _, rec = CA(home / "ca", PASS.encode()).issue("branch.acme", "site", ["10.0.0.2"], out=home / "branch")
    site = Status({"branch.acme": {"initiate": True, "profile": "standard", "keys_age_s": 42, "certificate": rec.serial,
                                   "tunnel": {"peer": "branch.acme", "state": "ESTABLISHED", "key_exchange": "CURVE_25519 + ML_KEM_768", "ppk": True,
                                              "encryption": "AES_GCM_16_256", "established_s": 300,
                                              "children": [{"name": "net", "state": "INSTALLED", "encryption": "AES_GCM_16_256", "bytes_in": 10, "bytes_out": 20}]}},
                   "lab.acme": {"initiate": False, "profile": "high", "keys_age_s": None, "tunnel": None}, "_events": {"key_agreements": 3}})
    assert app("services/add", {"kind": "site", "name": "hq", "url": site.url})[0] == 200
    code, d = app("sites")
    assert code == 200 and [s["name"] for s in d["sites"]] == ["hq"]
    branch, lab = d["sites"][0]["tunnels"]
    assert (branch["peer"], branch["protected"], branch["key_exchange"], branch["encryption"], branch["last_rotation_s"]) == \
        ("branch.acme", True, "CURVE_25519 + ML_KEM_768", "AES_GCM_16_256", 42)
    assert branch["certificate"]["status"] == "valid" and branch["certificate"]["common_name"] == "branch.acme" and branch["certificate"]["not_after"]
    assert (lab["peer"], lab["protected"], lab["state"]) == ("lab.acme", False, "no tunnel")


def test_an_unreachable_site_and_a_bad_address_are_explained_in_words(app):
    assert app("services/add", {"kind": "site", "name": "gone", "url": "http://127.0.0.1:1"})[0] == 200
    site = app("sites")[1]["sites"][0]
    assert site["error"] and "127.0.0.1:1" in site["error"]
    for bad in ("file:///etc/passwd", "ftp://x", "not a url", ""):
        code, e = app("services/add", {"kind": "site", "name": "x", "url": bad})
        assert code == 400 and "http://" in e["error"]
    assert app("services/add", {"kind": "router", "name": "x", "url": "http://127.0.0.1:2"})[0] == 400
    assert app("services/remove", {"name": "gone"})[0] == 200 and app("sites")[1]["sites"] == []


def test_inviting_a_person_downloads_an_invitation_that_joins_and_is_audited(app, home):
    unlocked(app)
    code, e = app("people/invite", {"name": "alice"})
    assert code == 400 and "enrollment service" in e["error"]
    assert app("people/settings", {"enroll": "https://ca.example:9443", "gateway": "vpn.example:7443", "server_name": "vpn.example"})[0] == 200
    code, data, headers = app("people/invite", {"name": "alice", "hours": 12}, raw=True)
    assert code == 200 and 'filename="alice.acxinvite"' in headers["Content-Disposition"]
    inv = join.parse(data)
    assert (inv["name"], inv["gateway"], inv["enroll"], inv["server_name"]) == ("alice", "vpn.example:7443", "https://ca.example:9443", "vpn.example") and inv["token"]
    assert not list(home.rglob("*.acxinvite")), "the invitation holds a one-time token: it goes to the browser, never to disk"
    acts = app("people")[1]["activity"]
    assert acts[0]["action"] == "invite" and acts[0]["name"] == "alice" and inv["token"] not in json.dumps(acts)
    for bad in ({"name": ""}, {"name": "a/b"}, {"name": "alice", "hours": 0}, {"name": "alice", "hours": "x"}):
        assert app("people/invite", bad)[0] == 400, bad
    assert app("people/settings", {"enroll": "http://ca.example", "gateway": "vpn.example:7443"})[0] == 400


@pytest.mark.skipif(bool(REASON), reason=REASON or "")
def test_who_is_connected_since_when_and_revoking_someone_ends_their_session(app, home, tmp_path):
    from test_wireguard import FakeWG
    from acxelin_vpn.wireguard import Client, Gateway, GatewayConfig
    unlocked(app)
    ca = CA(home / "ca", PASS.encode())
    ca.issue("localhost", "server", out=tmp_path / "gw")
    for who in ("alice", "bob"):
        ca.issue(who, "client", out=tmp_path / who)
        (tmp_path / who / "ca.crt").write_bytes((home / "ca" / "ca.crt").read_bytes())
    ca.crl()
    cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24",
                        cert=str(tmp_path / "gw" / "chain.pem"), key=str(tmp_path / "gw" / "key.pem"), ca=str(home / "ca" / "ca.crt"),
                        crl=str(home / "ca" / "crl.pem"), private_key=str(tmp_path / "gw.key"), state=str(tmp_path / "state.json"),
                        manage_interface=False).validate()
    class LiveWG(FakeWG):  # a WireGuard whose peers completed a handshake just now
        def peers(self):
            return {k: {"latest_handshake": time.time(), "rx_bytes": 1, "tx_bytes": 1} for k in self.peers_}
    gw = Gateway(cfg, LiveWG()).start()
    try:
        status = Status(gw.status)
        assert app("services/add", {"kind": "gateway", "name": "remote access", "url": status.url})[0] == 200
        for who in ("alice", "bob"):
            Client(f"127.0.0.1:{gw.server.port}", tmp_path / who, server_name="localhost", apply=False).agree()
        people = {p["name"]: p for p in app("people")[1]["people"]}
        assert people["alice"]["connected"] and people["alice"]["since"] and people["alice"]["address"] == "10.99.0.2"
        assert people["alice"]["certificate"] == "valid" and people["bob"]["connected"]
        code, r = app("people/revoke", {"name": "alice"})
        assert code == 200 and r["revoked"] == 1
        gw.expire(Revocation(cfg.crl, cfg.ca))  # what the gateway's watch does every few seconds once it has the new CRL
        people = {p["name"]: p for p in app("people")[1]["people"]}
        assert not people["alice"]["connected"] and people["alice"]["certificate"] == "revoked" and people["bob"]["connected"]
        d = app("people")[1]
        acts = [{k: v for k, v in a.items() if k != "time"} for a in d["activity"]]
        assert {"action": "revoke", "name": "alice", "certificates": 1} in acts, "the administrator's revoke"
        assert any(a["action"] == "revoked, removed" and a["name"] == "alice" and a["gateway"] == "remote access" for a in acts), "the gateway cutting her off"
        assert any(a["action"] == "connected" and a["name"] == "bob" for a in acts)
        bob = next(p for p in d["people"] if p["name"] == "bob")
        assert (bob["bytes_in"], bob["bytes_out"]) == (1, 1) and bob["key_age_s"] is not None and bob["handshake_age_s"] is not None
        assert d["gateways"][0]["name"] == "remote access" and d["gateways"][0]["up_s"] is not None and not d["gateways"][0]["error"]
        assert app("people/revoke", {"name": "alice"})[0] == 400, "nobody valid by that name is left to revoke"
    finally:
        gw.shutdown()


def test_health_lists_each_check_with_what_to_do(app):
    code, d = app("health")
    assert code == 200 and d["version"] and {c["level"] for c in d["checks"]} <= {"ok", "warn", "fail"}
    assert any("CA VPN Root" in c["message"] or "CN=VPN Root" in c["message"] for c in d["checks"])


@pytest.mark.parametrize("headers,status", [
    ({"Authorization": ""}, 401), ({"Authorization": "Bearer wrong"}, 401),
    ({"Host": "evil.example"}, 421), ({"Origin": "http://evil.example"}, 403), ({"Sec-Fetch-Site": "cross-site"}, 403),
], ids=["no-token", "wrong-token", "wrong-host", "wrong-origin", "cross-site"])
def test_the_console_refuses_requests_it_should_not_answer(app, headers, status):
    assert app("status", headers=headers)[0] == status


def test_wrong_tokens_lock_the_address_out(app):
    codes = [app("status", headers={"Authorization": "Bearer wrong"})[0] for _ in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429


def test_the_console_listens_on_loopback_and_the_page_carries_no_cookie(home):
    a = console.build(home)
    srv = core.start(a, home, port=0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
        r = c.getresponse()
        page = r.read().decode()
        assert r.status == 200 and "Set-Cookie" not in dict(r.getheaders()) and "Acxelin VPN" in page
        assert all(t in page for t in ("Sites", "People", "Health"))
    finally:
        srv.shutdown()
