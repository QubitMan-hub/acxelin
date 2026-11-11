"""A laptop whose key agreement fails while its tunnel still works stays on the last key, shown as degraded, up to the customer's cap.
A revoked laptop is always cut off at once. No message on the wire changes: the gateway still decides who keeps a place."""
import json
import logging
import time

import pytest

from acxelin_core import tls
from acxelin_core.pki import CA
from acxelin_vpn import desktop, join
from acxelin_vpn import wireguard as w


class Tunnel:
    def __init__(self, folder):
        self.folder, self.up_, self.calls, self.age = folder, True, [], 12

    def down(self):
        self.up_ = False
        self.calls.append("down")

    def handshake_age(self, public):
        return self.age

    def routes(self, r):
        return r

    def device(self):
        return "wg0"


class Kill:
    def on(self, *a):
        pass

    def off(self):
        pass


@pytest.fixture
def make(tmp_path):
    ca = CA.init(tmp_path / "ca", "Grace Root")
    ca.issue("alice", "client", out=tmp_path / "dev")
    (tmp_path / "dev" / "ca.crt").write_bytes((tmp_path / "ca" / "ca.crt").read_bytes())

    def client(error=tls.TLSError("cannot reach the keyring"), **kw):
        t = Tunnel(tmp_path)
        c = w.Client("gw.example:7443", tmp_path / "dev", tunnel=t, kill_switch=Kill(), apply=True, **kw)
        c.last = {"address": "10.99.0.2/24", "routes": ["10.99.0.0/24"], "rotate_s": 120, "gateway_public": "G=", "endpoint": "gw.example:51820"}
        c.applied = {"gateway_public": "G="}
        c.agreed_at = time.time() - 100
        c.agree = lambda: (_ for _ in ()).throw(error)
        c.due = 0.0
        return c, t
    return client


def test_a_working_tunnel_is_kept_on_the_last_key_and_shown_as_degraded(make, caplog):
    c, t = make(keep_minutes=15)
    with caplog.at_level(logging.WARNING):
        c.step()
        c.due = 0.0
        c.step()
    assert t.calls == [] and t.up_, "the tunnel still handshakes, so it is not taken down"
    s = c.status()
    assert s["state"] == "degraded" and s["error"] and s["address"] == "10.99.0.2/24"
    assert 14 * 60 < s["degraded_left_s"] <= 15 * 60 and s["degraded_since"] <= time.time()
    assert sum("last key" in m for m in caplog.messages) == 1, "one line on entering, not one per retry"


def test_a_dead_tunnel_is_still_taken_down_at_once(make):
    c, t = make(keep_minutes=15)
    t.age = 200
    c.step()
    assert t.calls == ["down"] and c.status()["state"] == "not_protected"
    assert c.due - time.time() <= 1.5, "and the agreement is retried directly within a second"


def test_the_customers_cap_is_hard(make, monkeypatch, caplog):
    c, t = make(keep_minutes=1)
    now = time.time()
    monkeypatch.setattr(w.time, "time", lambda: now)
    c.step()
    assert c.status()["state"] == "degraded"
    monkeypatch.setattr(w.time, "time", lambda: now + 59)
    c.due = 0.0
    c.step()
    assert t.calls == []
    monkeypatch.setattr(w.time, "time", lambda: now + 61)
    c.due = 0.0
    with caplog.at_level(logging.WARNING):
        c.step()
    assert t.calls == ["down"] and c.status()["state"] == "not_protected"
    assert any("cap" in m for m in caplog.messages)


def test_a_cap_of_zero_is_the_old_behaviour(make):
    c, t = make(keep_minutes=0)
    c.step()
    assert t.calls == ["down"] and c.status()["state"] == "not_protected"


@pytest.mark.parametrize("reason", ["revoked", "crl"])
def test_a_revoked_laptop_is_always_cut_off_never_degraded(make, reason):
    c, t = make(error=w.Refused(reason), keep_minutes=600)
    c.step()
    assert t.calls == ["down"]
    s = c.status()
    assert s["state"] == "not_protected" and "degraded_since" not in s
    assert ("revoked" in s["error"]) if reason == "revoked" else ("revocation list" in s["error"])


def test_renewal_working_again_ends_degraded(make, caplog):
    c, t = make(keep_minutes=15)
    c.step()
    assert c.status()["state"] == "degraded"
    reply = {"address": "10.99.0.2/24", "routes": ["10.99.0.0/24"], "rotate_s": 120, "gateway_public": "G=", "endpoint": "gw.example:51820"}
    c.once = lambda: reply
    c.due = 0.0
    with caplog.at_level(logging.INFO):
        c.step()
    s = c.status()
    assert s["state"] == "protected" and "degraded_since" not in s and t.calls == []
    assert any("left degraded" in m for m in caplog.messages)


def test_the_tray_and_the_window_say_degraded():
    state = {"invitation": "a.acxinvite", "status": {"state": "degraded", "address": "10.99.0.2/24", "degraded_left_s": 600}}
    assert desktop.summary(state) == "degraded"
    assert desktop.headline(state).startswith("Degraded")
    assert desktop.TONES["degraded"] != desktop.TONES["protected"] and desktop.TONES["degraded"] != desktop.TONES["not_protected"]
    page = (w.Path(desktop.__file__).parent / "app.html").read_text(encoding="utf-8")
    assert 'degraded: "Degraded' in page and 'main[data-state="degraded"]' in page


def invitation(**extra):
    return json.dumps({"acxelin_invite": 1, "name": "alice", "enroll": "https://ca.example:9443", "ca_fingerprint": "ab" * 32,
                       "gateway": "gw.example:7443", **extra})


def test_the_cap_travels_in_the_invitation_and_older_invitations_still_work():
    assert join.keep_minutes(join.parse(invitation())) == w.KEEP_MINUTES
    assert join.keep_minutes(join.parse(invitation(keep_minutes=30))) == 30
    assert join.keep_minutes(join.parse(invitation(keep_minutes=0))) == 0
    assert join.parse(invitation(something_new="x"))["name"] == "alice"
    for bad in (-1, 10_000, "15", True):
        with pytest.raises(ValueError, match="keep_minutes"):
            join.parse(invitation(keep_minutes=bad))


def full(c):
    c.last = c.last | {"routes": ["0.0.0.0/0"]}
    return c


def test_with_a_full_tunnel_a_timed_out_agreement_means_the_tunnel_is_dead_so_no_grace(make):
    """In full-tunnel mode the agreement travels through the tunnel: a working tunnel always reaches the gateway, so silence there
    means the tunnel itself is broken (the gateway forgot this laptop), however recent the last handshake was."""
    c, t = make(error=TimeoutError("timed out"), keep_minutes=15)
    full(c).step()
    assert t.calls == ["down"] and c.status()["state"] == "not_protected"


def test_with_a_full_tunnel_a_refused_agreement_still_gets_the_grace(make):
    c, t = make(error=ConnectionRefusedError("refused"), keep_minutes=15)
    full(c).step()
    assert t.calls == [] and c.status()["state"] == "degraded", "the key service is down, the tunnel works"
