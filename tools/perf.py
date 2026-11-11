"""The performance harness: measured numbers with the machine, the parameters and every sample, and a comparison with an earlier run.

    python tools/perf.py [--quick] [--runs 3] [--suite ca --suite tls --suite vpn --suite readiness]
                         [--json out.json] [--markdown out.md] [--compare earlier.json --threshold 15 [--fail-over]]

Nothing here is a claim about another machine. Each metric keeps all its samples; the summary (median, minimum, maximum) is computed from them. The
clients load the machine the server runs on, so rates are a floor. A suite whose product is not installed is listed under "skipped" with the reason.
`--compare` marks a change beyond the threshold in the bad direction as a regression; it exits 1 only with `--fail-over`, because shared CI machines are noisy.
"""
import argparse
import datetime as dt
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = ("ca", "tls", "vpn", "readiness")


def median(xs):
    if not xs:
        raise ValueError("no samples")
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def percentile(xs, p):
    """Nearest rank."""
    if not xs:
        raise ValueError("no samples")
    s = sorted(xs)
    return s[max(0, math.ceil(p / 100 * len(s)) - 1)]


def metric(name, unit, better, samples):
    return {"name": name, "unit": unit, "better": better, "samples": [float(x) for x in samples], "median": median(samples),
            "min": min(samples), "max": max(samples)}


def cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def commit():
    r = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def environment():
    try:
        from acxelin_core import openssl
        version = openssl.lib().version
    except Exception as e:  # noqa: BLE001
        version = f"unavailable ({type(e).__name__})"
    return {"cpu": cpu_model(), "cores": os.cpu_count(), "python": platform.python_version(), "openssl": version,
            "platform": f"{platform.system()} {platform.release()}", "commit": commit(),
            "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None}


def timed(fn, *a):
    t = time.perf_counter()
    out = fn(*a)
    return time.perf_counter() - t, out


# ---- suites -------------------------------------------------------------------------------------------------------------

def suite_ca(quick, runs):
    from acxelin_core import pki
    from acxelin_core.pki import CA, Record
    issue_n, revoked = (6, 1000) if quick else (200, 20000)
    m = {"issue_ml_dsa_65_per_s": [], "issue_ml_dsa_87_per_s": [], f"crl_sign_ms_{1000 if quick else 20000}_revoked": [], "crl_check_first_ms": [], "crl_check_cached_us": []}
    if not quick:
        m["crl_sign_ms_1000_revoked"] = []
    with tempfile.TemporaryDirectory() as d:
        for run in range(runs):
            ca = CA.init(Path(d) / f"pki{run}", "Perf Root")
            for algo, key in (("ML-DSA-65", "issue_ml_dsa_65_per_s"), ("ML-DSA-87", "issue_ml_dsa_87_per_s")):
                t, _ = timed(lambda: [ca.issue(f"s{i}", "server", out=Path(d) / f"{run}{algo}{i}", algorithm=algo) for i in range(issue_n)])
                m[key].append(issue_n / t)
            for n in sorted({1000, revoked}):
                recs = [Record(serial=format(i + 1, "040x"), common_name=f"r{i}", kind="server", algorithm="ML-DSA-65", not_after="2030-01-01T00:00:00+00:00", names=[],
                               status="revoked", revoked_at="2026-01-01T00:00:00+00:00", reason="keyCompromise") for i in range(n)]
                ca._save(recs)
                t, crl = timed(ca.crl)
                m[f"crl_sign_ms_{n}_revoked"].append(t * 1000)
            pki._verified.clear()
            t, _ = timed(pki.check_revocation, 0xFFFFFF, crl, ca.cert)
            m["crl_check_first_ms"].append(t * 1000)
            t, _ = timed(lambda: [pki.check_revocation(0xFFFFFF, crl, ca.cert) for _ in range(200)])
            m["crl_check_cached_us"].append(t / 200 * 1e6)
    units = {"per_s": ("1/s", "higher"), "_ms": ("ms", "lower"), "_us": ("us", "lower")}
    out = {}
    for name, samples in m.items():
        if samples:
            unit, better = next(v for k, v in units.items() if name.endswith(k) or k in name)
            out[name] = metric(name, unit, better, samples)
    return {"metrics": out, "notes": [f"{issue_n} certificates per timing; the CRL is signed with the CA's ML-DSA-87 key; the last revoked serial is not on the list"]}


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def hammer(connect, seconds, threads=8):
    """New connections per second from `threads` clients for `seconds`."""
    counts, end = [], time.monotonic() + seconds

    def one():
        n = 0
        while time.monotonic() < end:
            connect().close()
            n += 1
        counts.append(n)
    ts = [threading.Thread(target=one) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return sum(counts) / seconds


def suite_tls(quick, runs):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from acxelin_core import tls
    from acxelin_core.pki import CA
    from acxelin_tls import policies

    class Hello(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello\n")

        def log_message(self, *a):
            pass
    seconds, latencies = (1.5, 40) if quick else (5.0, 200)
    classical = tls.Policy("classical", "X25519", None, policies.CIPHERSUITES)
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        ca = CA.init(d / "pki", "Perf Root")
        srv, _ = ca.issue("localhost", "server", ["127.0.0.1"], algorithm="ML-DSA-65", out=d / "srv")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        import datetime
        key, now = ec.generate_private_key(ec.SECP256R1()), datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        fb = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
              .not_valid_after(now + datetime.timedelta(days=7)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(key, hashes.SHA256()))
        (d / "fb.pem").write_bytes(fb.public_bytes(serialization.Encoding.PEM))
        (d / "fb.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (d / "trust.pem").write_bytes((d / "pki" / "ca.crt").read_bytes() + b"\n" + (d / "fb.pem").read_bytes())
        web = ThreadingHTTPServer(("127.0.0.1", 0), Hello)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        port = free_port()
        edge = subprocess.Popen([sys.executable, "-m", "acxelin_tls", "edge", "--listen", f"127.0.0.1:{port}", "--target", f"127.0.0.1:{web.server_address[1]}", "--policy", "transition",
                                 "--cert", str(srv / "chain.pem"), "--key", str(srv / "key.pem"), "--fallback-cert", str(d / "fb.pem"), "--fallback-key", str(d / "fb.key"),
                                 "--max-rate-per-client", "0", "--max-connections", "4096"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        configs = {"mlkem_mldsa": policies.policy("strict"), "mlkem_ecdsa": policies.policy("transition"), "x25519_ecdsa": classical}
        metrics = {}
        notes = []
        try:
            trust = str(d / "trust.pem")
            for _ in range(60):
                try:
                    tls.connect("127.0.0.1", port, tls.client_context(policies.policy("strict"), trust), "localhost", 2).close()
                    break
                except (tls.TLSError, OSError):
                    time.sleep(0.2)
            for label, policy in configs.items():
                ctx = tls.client_context(policy, trust)
                probe = tls.connect("127.0.0.1", port, ctx, "localhost", 10)
                notes.append(f"{label}: negotiated {probe.group}, {probe.peer_certificate().public_key().__class__.__name__.lstrip('_')}")
                probe.close()
                connect = lambda ctx=ctx: tls.connect("127.0.0.1", port, ctx, "localhost", 10)
                metrics[f"handshakes_per_s_{label}"] = metric(f"handshakes_per_s_{label}", "1/s", "higher", [hammer(connect, seconds) for _ in range(runs)])
                lat = []
                for _ in range(latencies):
                    t, c = timed(connect)
                    lat.append(t * 1000)
                    c.close()
                for p in (50, 95, 99):
                    metrics[f"handshake_ms_p{p}_{label}"] = metric(f"handshake_ms_p{p}_{label}", "ms", "lower", [percentile(lat, p)])
            ctx = tls.client_context(configs["mlkem_mldsa"], trust)
            rates = []
            for _ in range(runs):
                conn, n, end = tls.connect("127.0.0.1", port, ctx, "localhost", 10), 0, time.monotonic() + seconds
                while time.monotonic() < end:
                    conn.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                    reply = b""
                    while not reply.endswith(b"hello\n"):
                        reply += conn.recv(timeout=10)
                    n += 1
                conn.close()
                rates.append(n / seconds)
            metrics["requests_per_s_kept_alive_mlkem_mldsa"] = metric("requests_per_s_kept_alive_mlkem_mldsa", "1/s", "higher", rates)
        finally:
            edge.terminate()
            web.shutdown()
    notes.append(f"{seconds:g} s per rate sample, 8 client threads sharing the machine with the edge and the backend; latency from {latencies} sequential handshakes (one sample per percentile)")
    return {"metrics": metrics, "notes": notes}


def suite_vpn(quick, runs):
    from acxelin_core.pki import CA
    from acxelin_vpn.wireguard import Client, Gateway, GatewayConfig

    class FakeWG:
        def __init__(self):
            self.peers_ = {}

        def set_private_key(self, key, listen_port=None):
            pass

        def set_peer(self, public, psk, allowed_ips, endpoint=None, keepalive=None):
            self.peers_[public] = psk

        def remove_peer(self, public):
            self.peers_.pop(public, None)

        def peers(self):
            return {k: {"latest_handshake": 0, "rx_bytes": 0, "tx_bytes": 0} for k in self.peers_}
    n = 15 if quick else 100
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        ca = CA.init(d / "pki", "VPN Root")
        ca.issue("localhost", "server", out=d / "gw")
        ca.crl()
        ca.issue("alice", "client", out=d / "alice")
        (d / "alice" / "ca.crt").write_bytes((d / "pki" / "ca.crt").read_bytes())
        cfg = GatewayConfig(name="localhost", endpoint="203.0.113.1:51820", keyring_listen="127.0.0.1:0", pool="10.99.0.0/24", cert=str(d / "gw" / "chain.pem"), key=str(d / "gw" / "key.pem"),
                            ca=str(d / "pki" / "ca.crt"), crl=str(d / "pki" / "crl.pem"), private_key=str(d / "gw.key"), state=str(d / "state.json"), routes=["192.168.10.0/24"],
                            users=["alice"], manage_interface=False).validate()
        gw = Gateway(cfg, FakeWG()).start()
        try:
            client = Client(f"127.0.0.1:{gw.server.port}", d / "alice", server_name="localhost", apply=False, config_out=d / "alice.conf")
            client.agree()
            lat = []
            for _ in range(n):
                t, _ = timed(client.agree)
                lat.append(t * 1000)
        finally:
            gw.shutdown()
    return {"metrics": {f"key_agreement_ms_p{p}": metric(f"key_agreement_ms_p{p}", "ms", "lower", [percentile(lat, p)]) for p in (50, 95, 99)},
            "notes": [f"{n} sequential agreements from one laptop to a gateway on the same machine (TLS handshake, one JSON line each way, key export); WireGuard itself is a stand-in"]}


def suite_readiness(quick, runs):
    corpus = ROOT / "products/readiness/bench/corpus"
    files = sum(1 for p in corpus.rglob("*") if p.is_file())
    peak = ("def peak():\n    try:\n        return int(next(l for l in open('/proc/self/status') if l.startswith('VmHWM')).split()[1])  # this process only, since it started\n"
            "    except (OSError, StopIteration):\n        return 0\n")
    code = ("import json, sys, time\n" + peak + "from acxelin_readiness import workspace\nt = time.perf_counter()\nr = workspace.scan(sys.argv[1])\n"
            "print(json.dumps({'seconds': time.perf_counter() - t, 'assets': len(r['assets']), 'rss_kb': peak()}))")
    seconds, rss = [], []
    for _ in range(runs):
        p = subprocess.run([sys.executable, "-c", code, str(corpus)], capture_output=True, text=True, timeout=600)
        if p.returncode:
            raise RuntimeError(f"the scan failed: {p.stderr[-300:]}")
        row = json.loads(p.stdout.strip().splitlines()[-1])
        seconds.append(row["seconds"])
        rss.append(row["rss_kb"] / 1024)
    m = {"corpus_scan_s": metric("corpus_scan_s", "s", "lower", seconds), "corpus_files_per_s": metric("corpus_files_per_s", "1/s", "higher", [files / s for s in seconds])}
    if all(r > 0 for r in rss):  # VmHWM exists on Linux only; elsewhere the figure is left out rather than guessed
        m["scan_peak_rss_mb"] = metric("scan_peak_rss_mb", "MB", "lower", rss)
    return {"metrics": m, "notes": [f"the labelled quality-gate corpus ({files} files) in a fresh process each time; the clock starts after the imports; peak memory is the whole process (imports included), read from VmHWM on Linux"]}


RUNNERS = {"ca": suite_ca, "tls": suite_tls, "vpn": suite_vpn, "readiness": suite_readiness}


def run(suites, quick=False, runs=3):
    for s in suites:
        if s not in RUNNERS:
            raise ValueError(f"unknown suite {s!r}; choose from {', '.join(SUITES)}")
    out = {"schema": 1, "when": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "parameters": {"quick": quick, "runs": runs, "suites": list(suites)},
           "environment": environment(), "suites": {}, "skipped": {}}
    for s in suites:
        try:
            out["suites"][s] = RUNNERS[s](quick, runs)
        except ImportError as e:
            out["skipped"][s] = f"the product is not installed ({e})"
    return out


def compare(baseline, current, threshold):
    rows, warn = [], []
    be, ce = baseline.get("environment", {}), current.get("environment", {})
    for key in ("cpu", "cores", "python", "openssl", "platform"):
        if be.get(key) != ce.get(key):
            warn.append(f"{key} differs ({be.get(key)!r} then, {ce.get(key)!r} now): the comparison may reflect the machine, not the code")
    flat = lambda r: {f"{s}/{n}": m for s, body in r.get("suites", {}).items() for n, m in body["metrics"].items()}
    b, c = flat(baseline), flat(current)
    for name in sorted(set(b) & set(c)):
        old, new = b[name]["median"], c[name]["median"]
        change = (new - old) / old * 100 if old else float("inf")
        worse = -change if c[name]["better"] == "higher" else change
        verdict = "regression" if worse > threshold else "improvement" if worse < -threshold else "within noise"
        rows.append({"metric": name, "unit": c[name]["unit"], "baseline": old, "current": new, "change_percent": round(change, 1), "verdict": verdict})
    return {"rows": rows, "only_in_baseline": sorted(set(b) - set(c)), "only_in_current": sorted(set(c) - set(b)), "warnings": warn, "threshold_percent": threshold}


def markdown(result, comparison=None):
    env = result["environment"]
    lines = ["# Performance", "", f"Measured {result['when']} at commit {env['commit']} on {env['cpu']} ({env['cores']} cores), {env['platform']}, Python {env['python']}, {env['openssl']}; "
             f"{result['parameters']['runs']} run(s) per rate{', quick profile' if result['parameters']['quick'] else ''}. Load average at start: {env['load_average']}.", "",
             "These numbers describe this machine on this day. They are not a claim about any other machine, and the client and server share the CPU, so rates are a floor.", ""]
    for suite, body in result["suites"].items():
        lines += [f"## {suite}", "", "| metric | median | min | max | unit | samples |", "|---|---|---|---|---|---|"]
        for name, m in body["metrics"].items():
            lines.append(f"| {name} | {m['median']:.4g} | {m['min']:.4g} | {m['max']:.4g} | {m['unit']} | {len(m['samples'])} |")
        lines += [""] + [f"- {n}" for n in body.get("notes", [])] + [""]
    for s, why in result.get("skipped", {}).items():
        lines.append(f"- skipped {s}: {why}")
    if comparison:
        lines += ["", f"## Against the earlier run (threshold {comparison['threshold_percent']}%)", ""] + [f"- WARNING: {w}" for w in comparison["warnings"]]
        lines += [f"- {r['metric']}: {r['baseline']:.4g} -> {r['current']:.4g} {r['unit']} ({r['change_percent']:+}%) {r['verdict']}" for r in comparison["rows"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", action="append", choices=SUITES)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--json")
    ap.add_argument("--markdown")
    ap.add_argument("--compare")
    ap.add_argument("--threshold", type=float, default=15.0)
    ap.add_argument("--fail-over", action="store_true")
    a = ap.parse_args(argv)
    result = run(a.suite or list(SUITES), a.quick, a.runs)
    comparison = compare(json.loads(Path(a.compare).read_text(encoding="utf-8")), result, a.threshold) if a.compare else None
    text = markdown(result, comparison)
    print(text)
    if a.json:
        Path(a.json).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    if a.markdown:
        Path(a.markdown).write_text(text, encoding="utf-8")
    return 1 if comparison and a.fail_over and any(r["verdict"] == "regression" for r in comparison["rows"]) else 0


if __name__ == "__main__":
    sys.exit(main())
