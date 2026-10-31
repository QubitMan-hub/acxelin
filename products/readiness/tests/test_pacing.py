"""Live probes are gentle by default: at most two new connections a second to one host:port, one at a time, four endpoints at once.
--aggressive is the old behaviour, so a scan can still be run as fast as it can go."""
import socket
import ssl
import struct
import threading
import time
from unittest.mock import patch

import pytest
from acxelin_core import openssl

from acxelin_readiness import cli, endpoints, pacing, pipeline
from acxelin_readiness.workspace import SettingsError, read_settings
from test_grades import PQ, SUITES, classical_server, closed_port, ec_certificate, pq_server

needs_openssl = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


def peak(stamps, span=1.0):
    s = sorted(stamps)
    return max((sum(1 for u in s if t <= u < t + span) for t in s), default=0)


class Recorder:
    """A server that notes when each connection arrived and how many were open at once. A connection is open until its client closes
    it, so a probe that starts the next before closing the last shows as two."""

    def __init__(self, request, handler, hold=0.0):
        self.sock = socket.create_server(("127.0.0.1", 0), backlog=128)
        request.addfinalizer(self.sock.close)
        self.stamps, self.peak, self.live, self.hold, self.handler = [], 0, [], hold, handler
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.stamps.append(time.monotonic())
            for d in self.live:
                d.wait(0.05)
            self.live = [d for d in self.live if not d.is_set()]
            done = threading.Event()
            self.live.append(done)
            self.peak = max(self.peak, len(self.live))
            threading.Thread(target=self.handle, args=(conn, done), daemon=True).start()

    def handle(self, conn, done):
        try:
            time.sleep(self.hold)
            conn.settimeout(2)
            conn = self.handler(conn) or conn
            while conn.recv(4096):
                pass
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()
            done.set()


def tls_handler(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)

    def handle(conn):
        try:
            return ctx.wrap_socket(conn, server_side=True)
        except (OSError, ssl.SSLError):
            return None
    return handle


def ssh_handler():
    names = lambda *xs: b"".join(struct.pack(">I", len(x)) + x for x in xs)
    payload = b"\x14" + b"\x00" * 16 + names(b"mlkem768x25519-sha256,curve25519-sha256", b"ssh-ed25519", *[b""] * 8) + b"\x00" * 5
    pad = 8 - (len(payload) + 5) % 8 or 8
    packet = b"SSH-2.0-test\r\n" + struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad

    def handle(conn):
        conn.sendall(packet)
    return handle


# --- the pacer

def test_two_connections_a_second_to_one_host_and_the_rest_wait():
    pacer, entered = pacing.Pacer(2), []
    for _ in range(5):
        with pacer.slot("h", 1, [0.0]):
            entered.append(time.monotonic())
    assert peak(entered) <= 2 and entered[-1] - entered[0] >= 2.0 and pacer.opened == {"h:1": 5}


def test_one_connection_at_a_time_to_a_host_even_when_the_rate_would_allow_more():
    pacer, live, seen, errors = pacing.Pacer(1000), [0], [0], []

    def work():
        with pacing.using(pacer), pacing.slot("h", 1):
            live[0] += 1
            seen[0] = max(seen[0], live[0])
            time.sleep(0.02)
            live[0] -= 1
    threads = [threading.Thread(target=work) for _ in range(8)]
    start = time.monotonic()
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    assert seen[0] == 1 and time.monotonic() - start >= 8 * 0.02, errors


def test_other_hosts_and_other_ports_do_not_wait_for_each_other():
    pacer = pacing.Pacer(1)
    with pacer.slot("a", 1, [0.0]), pacer.slot("a", 2, [0.0]), pacer.slot("b", 1, [0.0]):
        pass
    assert pacer.opened == {"a:1": 1, "a:2": 1, "b:1": 1}


def test_a_slot_is_given_back_when_the_probe_fails():
    pacer = pacing.Pacer(1000)
    with pytest.raises(OSError), pacer.slot("h", 1, [0.0]):
        raise OSError("refused")
    with pacer.slot("h", 1, [0.0]):
        pass


def test_cancelling_stops_waiting_for_the_pacer_at_once():
    pacer = pacing.Pacer(0.05)
    with pacer.slot("h", 1, [0.0]):
        pass
    outcome = []

    def wait():
        try:
            with pacer.slot("h", 1, [0.0]):
                outcome.append("entered")
        except pacing.Cancelled:
            outcome.append("cancelled")
    t = threading.Thread(target=wait)
    t.start()
    time.sleep(0.3)
    began = time.monotonic()
    pacer.stop()
    t.join(5)
    assert outcome == ["cancelled"] and time.monotonic() - began < 1.0, "a 20 second wait ended with the cancel"


def test_cancelling_also_ends_the_wait_behind_a_busy_connection():
    cancel, pacer = threading.Event(), None
    pacer = pacing.Pacer(1000, cancel=cancel)
    release, outcome = threading.Event(), []

    def hold():
        with pacer.slot("h", 1, [0.0]):
            release.wait(10)
    holder = threading.Thread(target=hold)
    holder.start()
    time.sleep(0.1)

    def wait():
        try:
            with pacer.slot("h", 1, [0.0]):
                outcome.append("entered")
        except pacing.Cancelled:
            outcome.append("cancelled")
    t = threading.Thread(target=wait)
    t.start()
    time.sleep(0.2)
    cancel.set()
    t.join(2)
    release.set()
    holder.join(5)
    assert outcome == ["cancelled"]


def test_an_endpoint_that_waits_too_long_gives_up_instead_of_hanging_the_scan():
    pacer = pacing.Pacer(0.1, wait_limit=0.3)
    with pacer.slot("h", 1, [0.0]):
        pass
    began = time.monotonic()
    with pytest.raises(pacing.GaveUp, match="h:1"), pacer.slot("h", 1, [0.0]):
        pass
    assert time.monotonic() - began < 2.0


def test_waiting_costs_no_processor_time():
    pacer = pacing.Pacer(0.5)
    with pacer.slot("h", 1, [0.0]):
        pass
    cpu = []

    def wait():
        began = time.thread_time()
        with pacer.slot("h", 1, [0.0]):
            pass
        cpu.append(time.thread_time() - began)
    t = threading.Thread(target=wait)
    t.start()
    t.join(10)
    assert cpu and cpu[0] < 0.1, "about two seconds of waiting"


def test_rate_zero_is_unlimited_and_still_counts():
    pacer = pacing.Pacer(0)
    began = time.monotonic()
    for _ in range(50):
        with pacer.slot("h", 1, [0.0]):
            pass
    assert time.monotonic() - began < 1.0 and pacer.opened == {"h:1": 50}


def test_without_a_pacer_a_slot_does_nothing():
    with pacing.slot("h", 1):
        pass


def test_profiles_default_to_gentle_and_aggressive_is_the_old_behaviour():
    assert pacing.profile() == pacing.Profile(2, 4)
    assert pacing.profile(aggressive=True) == pacing.Profile(0, 16)
    assert pacing.profile(rate=5, workers=2) == pacing.Profile(5, 2)
    assert pacing.profile(rate=1, aggressive=True) == pacing.Profile(1, 16), "a number you give wins over the profile"


@pytest.mark.parametrize("rate,workers", [(-1, None), (float("nan"), None), (float("inf"), None), (None, 0), (None, -3), (True, None), (None, True), (None, 2.5), ("2", None)])
def test_nonsense_settings_are_refused(rate, workers):
    with pytest.raises(ValueError):
        pacing.profile(rate, workers)


def test_the_summary_line_names_the_hosts_and_the_counts():
    pacer = pacing.Pacer(2)
    for host, n in (("a", 3), ("b", 1)):
        for _ in range(n):
            with pacer.slot(host, 443, [0.0]):
                pass
    assert pacer.summary() == "opened 4 connections: a:443 3, b:443 1"
    assert pacing.Pacer(2).summary() == ""


# --- against a server

@needs_openssl
def test_a_tls_endpoint_is_probed_slowly_and_one_connection_at_a_time_by_default(request, tmp_path):
    cert, key = ec_certificate(tmp_path)
    server = Recorder(request, tls_handler(cert, key), hold=0.02)
    result = endpoints.scan([f"127.0.0.1:{server.port}"], timeout=5)[0]
    assert result["grade"] != "F" and not result["error"], result
    assert len(server.stamps) >= 15, "one endpoint is many connections; the point is to space them out"
    assert peak(server.stamps) <= 2 and server.peak == 1


@needs_openssl
def test_aggressive_reproduces_the_old_burst_and_the_same_connections(request, tmp_path):
    cert, key = ec_certificate(tmp_path)
    old = Recorder(request, tls_handler(cert, key))
    endpoints.probe(f"127.0.0.1:{old.port}", timeout=5)
    fast = Recorder(request, tls_handler(cert, key))
    began = time.monotonic()
    endpoints.scan([f"127.0.0.1:{fast.port}"], pacing.AGGRESSIVE, timeout=5)
    assert len(fast.stamps) == len(old.stamps) and peak(fast.stamps) > 4 and time.monotonic() - began < 10
    assert peak(old.stamps) > 4


@needs_openssl
def test_gentle_and_aggressive_grade_the_same_servers_the_same(request, tmp_path):
    from acxelin_core.pki import CA
    from acxelin_core.tls import Policy
    CA.init(tmp_path / "ca", "Pacing Test CA")
    out, _ = CA(tmp_path / "ca").issue("app.internal", "server", ["127.0.0.1"], out=tmp_path / "app")
    ec_cert, ec_key = ec_certificate(tmp_path)
    ports = [pq_server(request, Policy("transition", PQ + ":X25519", None, SUITES), out / "chain.pem", out / "key.pem"),
             classical_server(request, ec_cert, ec_key, ssl.TLSVersion.TLSv1_3)]
    targets = [f"127.0.0.1:{p}" for p in ports]
    fast = endpoints.scan(targets, pacing.AGGRESSIVE, timeout=5)
    slow = endpoints.scan(targets, timeout=5)
    assert [r["grade"] for r in fast] == ["B", "C"]
    assert slow == fast


def test_endpoints_on_one_host_share_its_allowance(request):
    server = Recorder(request, ssh_handler(), hold=0.05)
    targets = [f"ssh://127.0.0.1:{server.port}"] * 6
    results = endpoints.scan(targets, timeout=5)
    assert [r["grade"] for r in results] == ["B"] * 6
    assert peak(server.stamps) <= 2 and server.peak == 1 and len(server.stamps) == 6


def test_aggressive_runs_every_endpoint_at_once_as_before(request):
    server = Recorder(request, ssh_handler(), hold=0.2)
    results = endpoints.scan([f"ssh://127.0.0.1:{server.port}"] * 6, pacing.AGGRESSIVE, timeout=5)
    assert [r["grade"] for r in results] == ["B"] * 6
    assert peak(server.stamps) == 6 and server.peak > 1


def test_different_hosts_are_not_slowed_by_each_other(request):
    servers = [Recorder(request, ssh_handler()) for _ in range(4)]
    began = time.monotonic()
    results = endpoints.scan([f"ssh://127.0.0.1:{s.port}" for s in servers] * 2, timeout=5)
    assert len(results) == 8 and all(peak(s.stamps) <= 2 for s in servers) and time.monotonic() - began < 3


# --- odd answers

def test_a_paced_scan_gives_every_odd_target_a_result(request):
    def hang(conn):
        time.sleep(1.5)

    def garbage(conn):
        conn.sendall(b"\x00\xff" * 64 + b"HTTP/1.1 400 nonsense\r\n")
    hanging, garbled = Recorder(request, hang), Recorder(request, garbage)
    targets = ["nonexistent-host.invalid:443", f"127.0.0.1:{closed_port()}", f"127.0.0.1:{hanging.port}", f"127.0.0.1:{garbled.port}",
               f"ssh://127.0.0.1:{garbled.port}"]
    began = time.monotonic()
    results = endpoints.scan(targets, timeout=0.3)
    assert [r["target"] for r in results] == [endpoints._label(t) for t in targets]
    assert [r["grade"] for r in results] == ["F"] * 5 and all(r["error"] for r in results)
    assert time.monotonic() - began < 60


def test_a_probe_that_raises_still_gives_a_result_and_releases_its_host(request):
    server = Recorder(request, ssh_handler())
    real = endpoints.probe_ssh
    calls = []

    def flaky(host, port, timeout):
        calls.append(1)
        if len(calls) == 1:
            with pacing.slot(host, port):
                raise RuntimeError("odd")
        return real(host, port, timeout)
    with patch.object(endpoints, "probe_ssh", flaky):
        results = endpoints.scan([f"ssh://127.0.0.1:{server.port}"] * 2, timeout=5)
    assert [r["grade"] for r in results] == ["F", "B"] and "odd" in results[0]["error"]


def test_a_scan_that_waits_too_long_for_a_host_grades_that_endpoint_f_and_goes_on(request):
    server = Recorder(request, ssh_handler())
    pacer = pacing.Pacer(0.05, wait_limit=0.4)
    results = endpoints.scan([f"ssh://127.0.0.1:{server.port}"] * 2, timeout=5, pacer=pacer)
    assert [r["grade"] for r in results] == ["B", "F"] and "127.0.0.1" in results[1]["error"]


# --- cancelling

def test_cancelling_a_scan_stops_it_without_waiting_out_the_pacing(request):
    server = Recorder(request, ssh_handler())
    pacer = pacing.Pacer(0.05)
    outcome = []

    def run():
        try:
            endpoints.scan([f"ssh://127.0.0.1:{server.port}"] * 6, timeout=5, pacer=pacer)
            outcome.append("finished")
        except pacing.Cancelled:
            outcome.append("cancelled")
    t = threading.Thread(target=run)
    began = time.monotonic()
    t.start()
    time.sleep(0.5)
    pacer.stop()
    t.join(10)
    assert outcome == ["cancelled"] and time.monotonic() - began < 5, "left alone it takes 100 seconds"
    assert len(server.stamps) == 1


def test_an_interrupted_scan_stops_its_workers(request):
    server = Recorder(request, ssh_handler())
    pacer = pacing.Pacer(0.05)
    with patch.object(endpoints, "probe", side_effect=KeyboardInterrupt):
        began = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            endpoints.scan([f"ssh://127.0.0.1:{server.port}"] * 3, timeout=5, pacer=pacer)
    assert time.monotonic() - began < 5 and pacer.cancel.is_set()


# --- commands and settings

def grade_with(argv, monkeypatch, tmp_path):
    seen = {}

    def scan(targets, profile=None, timeout=8.0, pacer=None):
        seen.update(profile=profile, rate=pacer.rate)
        return []
    monkeypatch.setattr(endpoints, "scan", scan)
    code = cli.main(["grade", "h.example", *argv])
    return code, seen


def test_grade_is_gentle_unless_told_otherwise(monkeypatch, tmp_path, capsys):
    code, seen = grade_with([], monkeypatch, tmp_path)
    assert code == 0 and seen == {"profile": pacing.Profile(2, 4), "rate": 2}
    assert "pacing live probes: at most 2 connections a second to any one host and port; --aggressive removes the limit" in capsys.readouterr().err


@pytest.mark.parametrize("argv,want", [(["--aggressive"], (0, 16)), (["--rate", "0"], (0, 4)), (["--rate", "0.5", "--workers", "1"], (0.5, 1)),
                                      (["--aggressive", "--workers", "3"], (0, 3)), (["--workers", "9"], (2, 9))])
def test_grade_takes_rate_workers_and_aggressive(argv, want, monkeypatch, tmp_path):
    _, seen = grade_with(argv, monkeypatch, tmp_path)
    assert (seen["profile"].rate, seen["profile"].workers) == want and seen["rate"] == want[0]


@pytest.mark.parametrize("argv", [["--rate", "-1"], ["--rate", "fast"], ["--workers", "0"], ["--workers", "1.5"], ["--rate", "nan"]])
def test_grade_refuses_nonsense_rates_and_worker_counts(argv, monkeypatch, tmp_path):
    monkeypatch.setattr(endpoints, "scan", lambda *a, **k: pytest.fail("must not scan"))
    with pytest.raises(SystemExit) as e:
        cli.main(["grade", "h.example", *argv])
    assert e.value.code == 1


def test_aggressive_says_it_is_not_pacing(monkeypatch, tmp_path, capsys):
    grade_with(["--aggressive"], monkeypatch, tmp_path)
    err = capsys.readouterr().err
    assert "pacing live probes" not in err and "without pacing" in err


def test_the_settings_file_sets_rate_workers_and_aggressive(monkeypatch, tmp_path):
    f = tmp_path / "s.toml"
    f.write_text("rate = 1\nworkers = 2\n")
    _, seen = grade_with(["--config", str(f)], monkeypatch, tmp_path)
    assert seen["profile"] == pacing.Profile(1, 2)
    f.write_text("aggressive = true\n")
    _, seen = grade_with(["--config", str(f)], monkeypatch, tmp_path)
    assert seen["profile"] == pacing.Profile(0, 16)
    f.write_text("rate = 1\n")
    _, seen = grade_with(["--config", str(f), "--rate", "3"], monkeypatch, tmp_path)
    assert seen["profile"].rate == 3, "the command line wins over the file"


@pytest.mark.parametrize("line", ['rate = "fast"', "rate = -1", "workers = 0", "workers = true", "workers = 2.5", "aggressive = 1", "rate = true"])
def test_the_settings_file_refuses_nonsense_pacing(line, tmp_path):
    f = tmp_path / "s.toml"
    f.write_text(line + "\n")
    with pytest.raises(SettingsError):
        read_settings(f)


def test_report_targets_and_grade_share_the_flags(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(endpoints, "scan", lambda t, profile=None, timeout=8.0, pacer=None: seen.update(profile=profile) or [])
    cli.main(["report", "--targets", "h.example", "--rate", "1", "--workers", "2", "-o", str(tmp_path / "r")])
    assert seen["profile"] == pacing.Profile(1, 2)


def test_scan_paces_its_live_probes_and_says_how_many_connections_it_opened(request, tmp_path, capsys):
    server = Recorder(request, ssh_handler())
    assert cli.main(["scan", "--ssh", f"127.0.0.1:{server.port}", "-o", str(tmp_path / "out")]) in (0, 2)
    err = capsys.readouterr().err
    assert "pacing live probes: at most 2 connections a second to any one host and port; --aggressive removes the limit" in err
    assert f"opened 1 connection: 127.0.0.1:{server.port} 1" in err


def test_scan_without_live_endpoints_says_nothing_about_pacing(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n")
    cli.main(["scan", str(tmp_path), "-o", str(tmp_path / "out")])
    assert "pacing" not in capsys.readouterr().err


def test_scan_workers_probe_several_endpoints_at_once_and_aggressive_drops_the_pacing(request, tmp_path):
    servers = [Recorder(request, ssh_handler(), hold=0.3) for _ in range(3)]
    argv = ["scan", *[a for s in servers for a in ("--ssh", f"127.0.0.1:{s.port}")], "-o", str(tmp_path / "out"), "-q"]
    began = time.monotonic()
    cli.main(argv + ["--workers", "3", "--rate", "0"])
    assert time.monotonic() - began < 0.8, "three 0.3 second servers, side by side"
    assert all(len(s.stamps) == 1 for s in servers)


def test_pipeline_probes_one_endpoint_after_another_by_default(request, tmp_path):
    servers = [Recorder(request, ssh_handler(), hold=0.3) for _ in range(3)]
    began = time.monotonic()
    pipeline.run(tmp_path, "p", ssh_targets=[f"127.0.0.1:{s.port}" for s in servers], pacer=pacing.Pacer(0))
    assert time.monotonic() - began >= 0.9


def test_the_console_takes_the_same_settings_in_the_request(tmp_path):
    from acxelin_readiness import console as rc
    app = rc.build(tmp_path / "state")
    seen = []

    def scan(targets, profile=None, timeout=8.0, pacer=None):
        seen.append(profile)
        return [{"target": "h:443", "grade": "F", "protocol": "tls", "certificate": None, "error": "x", "accepts": []}]
    with patch("acxelin_readiness.console.endpoints.scan", scan):
        for body in ({}, {"rate": 1, "workers": 2}, {"aggressive": True}):
            app.routes[("POST", "/api/endpoints/scan")]({"targets": "h:443", **body})
            for _ in range(100):
                if not app.routes[("GET", "/api/endpoints/status")]({})[1]["running"]:
                    break
                time.sleep(0.05)
    assert seen == [None, pacing.Profile(1, 2), pacing.Profile(0, 16)], "no settings in the request: the scan's own gentle default"
    for bad in ({"rate": -1}, {"workers": 0}, {"aggressive": "yes"}, {"rate": "x"}):
        with pytest.raises(ValueError):
            app.routes[("POST", "/api/endpoints/scan")]({"targets": "h:443", **bad})
