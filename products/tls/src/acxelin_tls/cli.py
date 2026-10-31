"""The `acxelin-tls` command."""
import argparse
import json
import logging
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

from acxelin_core import tls
from acxelin_core.cli import JSONFormatter, explain_options
from acxelin_core.http import explain, serve_http
from acxelin_core.pki import CA, CAError

from . import NAME, __version__, ca_commands, checks, edge_commands, policies

HELP = {
    "key_passphrase_env": "the key's passphrase is in this environment variable",
    "passphrase_env": "the key's passphrase is in this environment variable (otherwise you are asked)",
    "json": "print JSON instead of text",
    "timeout": "seconds to wait for each connection",
    "san": "another DNS name or IP address the certificate covers (repeatable)",
    "days": "certificate lifetime in days",
    "algorithm": "the key's algorithm",
    "out": "folder to write to",
    "serial": "from `ca list`; the first 8 or more hex characters are enough",
    "kind": "server or client",
    "common_name": "the name it certifies, e.g. web.corp.example",
    "csr": "the certificate signing request (PEM)",
    "no_passphrase": "leave the private key unencrypted",
    "names": "the DNS names the certificate is for",
    "server_name": "the name in the server's certificate, if not its host",
    "service": "the service to put behind the edge",
    "ca": "the CA certificate to trust",
    "key": "the private key",
    "verbose": "log debugging detail",
}


def cmd_doctor(a):
    print(f"{NAME} {__version__}, Python {sys.version.split()[0]}")
    broken = False
    for r in checks.prerequisites():
        print(f"{'ok  ' if r['level'] == 'ok' else 'FAIL'}  {r['message'].rstrip('.')}" + (f". {r['action']}" if r['action'] else ""))
        broken = broken or r["level"] == "fail"
    results = [r for d in a.ca for r in checks.ca(d)] + [r for f in a.config for r in checks.config(f)]
    mark = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}
    for level, msg in results:
        print(f"{mark[level]}  {msg}")
    fails, warns = sum(r[0] == "fail" for r in results), sum(r[0] == "warn" for r in results)
    if results:
        print(f"\n{fails} problem(s), {warns} warning(s)")
    return 3 if broken else 2 if fails else 1 if warns and a.strict else 0


def cmd_status(a):
    if not a.url.startswith(("http://", "https://")):
        raise ValueError(f"--url must start with http:// or https://, not {a.url!r}")
    try:
        with urllib.request.urlopen(a.url.rstrip("/") + "/status", timeout=a.timeout) as r:
            data = json.loads(r.read())
    except (OSError, ValueError) as e:
        raise ValueError(f"cannot read {a.url}/status: {explain(e) if isinstance(e, OSError) else e}; start the edge with --metrics HOST:PORT") from None
    if a.json:
        print(json.dumps(data, indent=1))
        return 0
    for name, e in data.items():
        print(f"{name}: policy {e.get('policy')}, {e.get('active', 0)} active, " + ", ".join(f"{k} {v}" for k, v in e.items() if k not in ("policy", "active", "groups")))
        for group, n in (e.get("groups") or {}).items():
            print(f"    {group}: {n}")
    return 0


def cmd_try(a):
    """A self-contained tour, nothing to set up: a CA, a plain web server, the post-quantum edge in front of it, a
    post-quantum client that gets through and a classical one that does not. Everything lives in a temporary folder."""
    tls.lib()  # say at once when this machine's OpenSSL cannot do post-quantum TLS, not halfway through the tour
    quiet = {name: logging.getLogger(name).level for name in ("acxelin_tls", "acxelin_core")}  # the tour's own output only
    for name in quiet:
        logging.getLogger(name).setLevel(logging.ERROR)
    try:
        return _tour()
    finally:
        for name, level in quiet.items():
            logging.getLogger(name).setLevel(level)


def _tour():
    from acxelin_core.openssl import Context

    from .edge import Edge, Route
    step = lambda n, text: print(f"\n{n}. {text}")
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        step(1, "A private certificate authority (ML-DSA-87 root) issues the edge an ML-DSA-65 certificate.")
        ca = CA.init(d / "pki", "Try Root")
        ca.issue("localhost", "server", ["127.0.0.1"], out=d / "edge")
        web = serve_http("127.0.0.1:0", {"/": ("text/plain; charset=utf-8", lambda: "Hello from a web server that knows nothing about post-quantum cryptography\n")})
        step(2, f"An ordinary web server starts on 127.0.0.1:{web.server_address[1]}. It has no post-quantum support.")
        edge = Edge(Route("try", "terminate", "127.0.0.1:0", f"127.0.0.1:{web.server_address[1]}", cert=str(d / "edge" / "chain.pem"), key=str(d / "edge" / "key.pem"))).start()
        try:
            step(3, f"The Acxelin TLS edge starts in front of it on 127.0.0.1:{edge.port}, accepting post-quantum clients only.")
            step(4, "A post-quantum client asks for the page through the edge:")
            with tls.connect("127.0.0.1", edge.port, tls.client_context(policies.policy("strict"), d / "pki" / "ca.crt"), "localhost", 10) as c:
                c.sendall(b"GET / HTTP/1.0\r\n\r\n")
                reply = b""
                while chunk := c.recv(timeout=10):
                    reply += chunk
                info = c.info()
            print(f"   key exchange  {info['group']}   (post-quantum: X25519 combined with ML-KEM-768)")
            print(f"   certificate   {info['peer_key']}   (post-quantum signature)")
            page = reply.split(b"\r\n\r\n", 1)[-1].decode().strip()
            print(f"   page          {page}")
            step(5, "A client that only knows classical key exchange (X25519) tries the same:")
            # acxelin:ignore (a classical client on purpose: the tour shows the edge refusing it)
            classical = Context(False, "X25519", None, policies.CIPHERSUITES, None, None, None, str(d / "pki" / "ca.crt"), True)
            try:
                tls.connect("127.0.0.1", edge.port, classical, "localhost", 10).close()
                print("   it got through, which it should not have")
                return 1
            except (tls.TLSError, OSError):
                print("   refused, as it should be: no connection falls back to a key exchange a future quantum computer could break")
            classical.close()
        finally:
            edge.stop(0)
            web.shutdown()
            web.server_close()
    print("\nThat is Acxelin TLS: post-quantum protection in front of a service that did not change.\nNext: acxelin-tls edge --help")
    return 0


START = """Acxelin TLS: post-quantum TLS and mutual TLS in front of the services you run, with your own certificate authority.

Start here:
  acxelin-tls console      your certificate authority, certificates and edges, in your browser
  acxelin-tls try          a one-minute tour: a post-quantum client gets through, a classical one is refused
  acxelin-tls doctor       check that this machine can do post-quantum TLS
  acxelin-tls --help       every command (edge, bundle, connect, ca ...)
New here? `acxelin-tls try` first; `acxelin-tls doctor` if anything fails."""


def parser():
    ap = argparse.ArgumentParser(prog=NAME, description="Acxelin TLS: post-quantum TLS 1.3 and mTLS in front of the services you already run, with its own certificate authority.")
    ap.add_argument("--version", action="version", version=f"{NAME} {__version__}")
    ap.add_argument("--log-json", action="store_true", help="structured JSON logs")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dir", default="pki", help="CA folder (default: pki)")
    p = sub.add_parser("try", help="a one-minute tour: the post-quantum edge in front of a web server")
    p.set_defaults(func=cmd_try)
    p = sub.add_parser("doctor", help="check that this machine can run Acxelin TLS, and check a CA folder or an edge configuration")
    p.set_defaults(func=cmd_doctor)
    p.add_argument("--ca", action="append", default=[], metavar="DIR", help="a CA folder to check (repeatable)")
    p.add_argument("--config", action="append", default=[], metavar="FILE", help="an edge configuration to check (repeatable)")
    p.add_argument("--strict", action="store_true", help="exit 1 on warnings")
    p = sub.add_parser("status", help="what a running edge reports: policy, connections and negotiated groups")
    p.set_defaults(func=cmd_status)
    p.add_argument("--url", default="http://127.0.0.1:9100", help="the edge's --metrics address (default: http://127.0.0.1:9100)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--timeout", type=float, default=5.0)
    edge_commands.add(sub)
    ca_commands.add(sub, common)
    from . import console
    console.add(sub)
    explain_options(ap, HELP)
    return ap


def main(argv=None):
    ap = parser()
    a = ap.parse_args(argv)
    if not a.cmd:
        print(START)
        sys.exit(0)
    h = logging.StreamHandler()
    h.setFormatter(JSONFormatter() if a.log_json else logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, handlers=[h])
    try:
        sys.exit(a.func(a))
    except BrokenPipeError:  # output piped into head, or a pager closed early
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
    except (CAError, tls.TLSError, ValueError, OSError, ImportError) as e:
        print(f"error: {explain(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


