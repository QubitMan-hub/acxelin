"""The `acxelin-vpn` command: site-to-site IPsec, the WireGuard gateway, and people's computers (join, the app, the desktop tray)."""
import argparse
import json
import logging
import os
import sys
import threading
from pathlib import Path

from acxelin_core import tls
from acxelin_core.cli import JSONFormatter, ask, explain_options, positive, run_until_signal
from acxelin_core.config import env_passphrase
from acxelin_core.http import JSON, METRICS, ConfigWatch, explain, restart, serve_http
from acxelin_core.pki import CA, CAError, encrypted

from . import NAME, __version__, audit, ca_commands, checks
from .charon import CharonError
from .platforms import WGError


def cmd_vpn(a):
    from . import load_config
    from .charon import Charon
    if a.cmd in ("gateway", "connect", "disconnect", "install", "uninstall"):
        return cmd_wireguard(a)
    if a.cmd == "up":
        from .controller import Controller
        site = load_config(a.config)
        ctl = Controller(site)
        ctl.start()
        if site.metrics:
            serve_http(site.metrics, {"/metrics": (METRICS, ctl.metrics), "/status": (JSON, lambda: json.dumps(ctl.status(), default=str))})
        again = threading.Event()
        watch = ConfigWatch(a.config, load_config, lambda new: new != site and (again.set(), ctl.shutdown()))
        run_until_signal(ctl.stop.wait, ctl.shutdown, watch.poke)
        if again.is_set():
            restart("acxelin_vpn")
        return 0
    if a.cmd == "status" and not (a.config or a.vici):
        from . import platforms
        path = platforms.folder() / f"{a.interface}.status.json"
        if path.exists():
            return laptop_status(path, a)
    if a.cmd in ("invite", "join", "app", "desktop"):
        return {"invite": cmd_invite, "join": cmd_join, "app": cmd_app, "desktop": cmd_desktop}[a.cmd](a)
    try:
        ch = Charon(load_config(a.config).vici if a.config else a.vici or "unix:///var/run/charon.vici")
    except CharonError:
        if a.cmd != "status" or a.config or a.vici:
            raise
        print("Not connected. No VPN client is running on this machine and no strongSwan site is reachable here.\n"
              "Laptop: acxelin-vpn join YOUR.acxinvite (administrator terminal). Gateway: start strongSwan, or give --config or --vici.")
        return 1
    if a.cmd == "check":
        kems = ch.ml_kem()
        print(f"{ch.version()} at {ch.uri}\nML-KEM key exchanges: {', '.join(kems) or 'none (needs strongSwan 6.0.2+ with OpenSSL 3.5+ or the ml plugin)'}")
        return 0 if kems else 1
    tunnels = ch.tunnels()
    if a.json:
        print(json.dumps(tunnels, indent=1))
    elif not tunnels:
        print("no tunnels")
    for t in [] if a.json else tunnels:
        print(f"{t['peer']:16} {t['state']:12} {t['key_exchange']:32} PPK {'yes' if t['ppk'] else 'NO '}  up {t['established_s']}s")
        for c in t["children"]:
            print(f"  {c['name']:14} {c['state']:12} {c['encryption']:14} in {c['bytes_in']} B / out {c['bytes_out']} B")
    return 0


def laptop_status(path, a):
    import time
    s = json.loads(path.read_text(encoding="utf-8"))
    if s["state"] not in ("disconnected",) and time.time() - s.get("updated", 0) > 30:
        s |= {"state": "stopped", "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.get("updated", 0)))}
    print(json.dumps(s, indent=1) if a.json else describe_vpn(s, a.details))
    return 0 if s["state"] == "protected" else 1


def cmd_invite(a):
    from acxelin_core.files import write
    from . import join
    if not a.enroll.startswith("https://"):
        raise ValueError("--enroll must be the https:// address of `acxelin-vpn ca serve`")
    out = Path(a.out or f"{a.name}.acxinvite")
    if out.exists():
        raise ValueError(f"{out} already exists; choose another --out")
    data, expires = join.make(CA(a.dir), a.name, a.enroll, a.gateway, a.server_name, a.hours)
    write(out, data, secret=True)
    audit.record(a.dir, "invite", name=a.name, expires=expires)
    print(f"wrote {out}: it lets {a.name} enroll once before {expires} and then connect to {a.gateway}.\n"
          f"Send it through a channel you trust (it holds a one-time token and the CA fingerprint the device will trust).\n"
          f"On the device, in an administrator terminal: acxelin-vpn join {out.name}")
    return 0


def cmd_join(a):
    """Enroll from an invitation (if this machine has no certificate yet) and connect, asking only for the device key passphrase."""
    from . import join
    inv = join.read(a.invitation)
    device = join.device_for(a.invitation, a.device)
    if not a.no_apply:
        join.preflight(f"acxelin-vpn join {a.invitation}")
    enroll = join.must_enroll(inv, device)
    passphrase = env_passphrase(a.key_passphrase_env)
    if enroll:
        if passphrase is None:
            passphrase = ask("Choose a passphrase for this device's key: ", "supply --key-passphrase-env with a protected environment variable")
            if not passphrase or passphrase != ask("Repeat it: ", "supply --key-passphrase-env"):
                raise ValueError("the passphrases were empty or did not match; nothing was changed")
        print(f"Enrolling {inv['name']} with {inv['enroll']} (CA pinned by the invitation's fingerprint) ...", flush=True)
        cert = join.enroll(inv, device, a.invitation, passphrase)
        print(f"Enrolled: certificate valid until {cert.not_valid_after_utc.date()}, key encrypted in {device}. The invitation's one-time token is used up.", flush=True)
    elif passphrase is None and encrypted(device / "key.pem"):
        passphrase = ask("Device key passphrase: ", "supply --key-passphrase-env with a protected environment variable")
    return connect(a, inv["gateway"], device, passphrase, inv.get("server_name"))


def cmd_app(a):
    """The VPN window's service: a page on 127.0.0.1 behind a one-time address; this process holds the tunnel until stopped.
    With --session (how `vpn desktop` starts it, with administrator rights) the port and key come from the tray's file,
    output goes to a log next to it, and problems are shown in the window instead of ending the process."""
    import webbrowser
    from acxelin_core.files import write
    from . import app, join
    window = app.App(a.invitation, a.folder, interface=a.interface, apply=not a.no_apply)
    held, running = app.claim(window.folder, f"{a.interface}.app")
    if not held:
        if not running:
            raise ValueError(f"another `acxelin-vpn app` holds {a.interface}; stop it, or use --interface")
        url = f"http://127.0.0.1:{running['port']}/#{app.request(running['port'], running['token'], 'POST', '/api/ticket')['ticket']}"
        print(f"The VPN window for {a.interface} is already running: {url}", flush=True)
        if not a.no_browser:
            webbrowser.open(url)
        return 0
    port, record = 0, window.folder / f"{a.interface}.app.json"
    if a.session:
        session = json.loads(Path(a.session).read_text(encoding="utf-8"))
        window.token, port = session["token"], int(session["port"])
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)  # never follow a link planted in the folder
        log = os.fdopen(os.open(window.folder / f"{a.interface}.service.log", flags, 0o600), "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = log
        for h in logging.getLogger().handlers:
            h.setStream(log)
    elif not a.no_apply:
        join.preflight("acxelin-vpn app" + (f" {a.invitation}" if a.invitation else ""))
    srv = app.serve(window, ("127.0.0.1", port))
    window.on_quit = lambda: threading.Thread(target=srv.shutdown).start()
    port = srv.server_address[1]
    if not a.session:
        write(record, json.dumps({"port": port, "token": window.token}).encode(), secret=True)
    if a.session:
        logging.getLogger("acxelin_vpn").info("VPN service for the desktop app on 127.0.0.1:%s", port)
    else:
        url = f"http://127.0.0.1:{port}/#{window.ticket()}"
        print(f"VPN window: {url}\nKeep this running; closing the window does not disconnect. Ctrl+C disconnects and stops it.", flush=True)
        if not a.no_browser:
            webbrowser.open(url)
    try:
        run_until_signal(srv.serve_forever, window.on_quit)
    finally:
        window.disconnect()
        srv.server_close()
        if not a.session:
            record.unlink(missing_ok=True)
        held.close()
    return 0


def cmd_desktop(a):
    from . import desktop
    if a.launcher or a.remove_launcher:
        path = desktop.launcher(remove=a.remove_launcher)
        print(f"removed {path}" if a.remove_launcher else f"added {desktop.NAME}: {path}")
        return 0
    if a.start_at_login:
        desktop.autostart(a.start_at_login == "on")
        print(f"{desktop.NAME} {'starts' if a.start_at_login == 'on' else 'no longer starts'} when you log in"
              + (" (the tray icon only; connecting still asks for your passphrase)" if a.start_at_login == "on" else ""))
        return 0
    return desktop.main(a.invitation, a.interface, not a.no_apply, a.background)


def cmd_wireguard(a):
    from . import wireguard as wg
    if a.cmd == "gateway":
        gw = wg.Gateway(wg.load_gateway(a.config)).start()
        print(f"WireGuard gateway {gw.cfg.name} on {gw.cfg.interface}, key agreement on {gw.cfg.keyring_listen}, public key {gw.public}")
        if gw.cfg.metrics:
            serve_http(gw.cfg.metrics, {"/metrics": (METRICS, gw.metrics), "/status": (JSON, lambda: json.dumps(gw.status(), default=str))})
        again = threading.Event()
        watch = ConfigWatch(a.config, wg.load_gateway, lambda new: gw.reconfigure(new) or (again.set(), gw.shutdown()))
        run_until_signal(gw.stop.wait, gw.shutdown, watch.poke)
        if again.is_set():
            restart("acxelin_vpn")
        return 0
    from . import platforms
    if a.cmd == "disconnect":
        from acxelin_core.files import write
        tunnel, kill_switch = platforms.this_machine(a.interface)
        write(tunnel.folder / f"{a.interface}.disconnect", b"")  # a running join, app or service stops instead of reconnecting
        tunnel.down()
        kill_switch.off()
        print(f"{a.interface} is down and nothing is blocked any more")
        return 0
    if a.cmd == "uninstall":
        print(f"removed {platforms.uninstall()}; the VPN no longer starts with this machine (acxelin-vpn disconnect takes it down now)")
        return 0
    if a.cmd == "install":
        if encrypted(Path(a.cert_dir) / 'key.pem'):
            raise ValueError('Built-in startup installation cannot unlock encrypted device keys; use interactive vpn connect or an administrator-managed service with --key-passphrase-env. Keep the key encrypted.')
        argv = [sys.executable, "-m", "acxelin_vpn", "connect", a.keyring, "--cert-dir", str(Path(a.cert_dir).resolve()), "--interface", a.interface]
        argv += [*(["--ca", str(Path(a.ca).resolve())] if a.ca else []), *(["--server-name", a.server_name] if a.server_name else [])]
        wg.Client(a.keyring, a.cert_dir, a.interface, a.server_name, apply=False, ca=a.ca).agree()
        print(f"the gateway accepted this certificate; wrote {platforms.install(argv)}: the VPN now starts with this machine and restarts if it stops")
        return 0
    passphrase = env_passphrase(a.key_passphrase_env)
    if passphrase is None and encrypted(Path(a.cert_dir) / 'key.pem'):
        passphrase = ask('Device key passphrase: ', 'supply --key-passphrase-env with a protected environment variable')
    return connect(a, a.keyring, a.cert_dir, passphrase)


def connect(a, keyring, cert_dir, passphrase, server_name=None):
    from . import wireguard as wg
    c = wg.Client(keyring, cert_dir, a.interface, server_name or getattr(a, "server_name", None), not a.no_apply, getattr(a, "config_out", None),
                  passphrase, ca=getattr(a, "ca", None), on_status=lambda s: print(describe_vpn(s), flush=True))
    if a.once:
        r = c.once()
        print(f"key agreement confirmed for {r['address']} through {r['endpoint']}; routes {', '.join(r['routes'])}; "
              f"{'no tunnel activated (--no-apply)' if a.no_apply else 'tunnel configured; verify a WireGuard handshake'}; "
              f"the PSK expires in about {r['rotate_s'] * 3}s; --once does not keep keys fresh")
        return 0
    print(f"Connecting to {keyring} as {c.name}. Keep this window open; Ctrl+C disconnects.", flush=True)
    run_until_signal(c.run, c.stop.set)
    c.close()
    return 0


def ago(seconds):
    return f"{seconds} s ago" if seconds < 120 else f"{seconds // 60} min ago" if seconds < 7200 else f"{seconds // 3600} h ago"


def describe_vpn(s, details=False):
    """Plain words first (protected or not, and why); the algorithms underneath for anyone who asks."""
    state = s["state"]
    if state == "protected":
        scope = "All traffic (full tunnel, kill switch on)" if s["full_tunnel"] else f"Traffic to {', '.join(s['routes'])} (split tunnel)"
        lines = [f"Protected. {scope} goes through {s['gateway']} as {s['address']}."]
    elif state == "connecting":
        lines = [f"Connecting. Keys agreed with {s['gateway']}; waiting for the tunnel's first handshake."]
    elif state == "agreed":
        lines = [f"Keys agreed with {s['gateway']} for {s['address']}; no tunnel configured (--no-apply), so this machine is not protected."]
    elif state == "disconnected":
        lines = ["Disconnected. The tunnel is down and nothing is blocked."]
    elif state == "stopped":
        lines = [f"Not running. The VPN client last reported at {s['last_seen']}; start it again with `acxelin-vpn join` or `acxelin-vpn connect`."]
    else:
        lines = [f"Not protected. {s.get('error') or 'Not connected yet'}. Retrying automatically; full-tunnel traffic stays blocked meanwhile."]
        if s.get("renewal_failures", 0) > 1:
            lines.append(f"  {s['renewal_failures']} renewals in a row have failed; the next try is in {s.get('retry_in_s', 0)} s"
                         + (f"; the last good key was agreed {ago(s['last_key_s'])}" if s.get("last_key_s") is not None else ""))
    if s.get("overdue"):
        lines.append(f"  Warning: the key has not been renewed for {s['last_key_s'] // 60} min (it should be every "
                     f"{s['key_agreement']['psk_rotation_s'] // 60} min). The last key still protects this computer; if this lasts, "
                     "tell your administrator.")
    k = s.get("key_agreement")
    if k and (details or state == "protected"):
        kind = "Post-quantum" if k["post_quantum"] else "Classical (NOT post-quantum)"
        lines.append(f"  {kind} key agreement: TLS group {k['tls_group']}, gateway certificate {k['gateway_certificate']}; "
                     f"the WireGuard pre-shared key is renewed every {k['psk_rotation_s']} s")
    if details and k:
        age = s.get("handshake_age_s")
        lines.append(f"  key last renewed {s['last_key_s']} s ago; last handshake {'never' if age is None else f'{age} s ago'}; next key in {s['next_key_s']} s; "
                     f"device {s['device']}; routes {', '.join(s['routes'])}")
        if s.get("kill_switch_changed"):
            c = s["kill_switch_changed"]
            lines.append(f"  {c['action']} since {c['time']} (this computer's audit log)")
    return "\n".join(lines)


def cmd_inventory(a):
    from acxelin_core.files import write
    from . import inventory
    text = inventory.cbom(a.config, a.name)
    write(Path(a.cbom), text.encode())
    print(f"wrote {a.cbom}: a CycloneDX 1.6 CBOM of {len(json.loads(text)['components'])} cryptographic assets "
          f"(algorithms, protocols, certificates, and keys by type and size; never a key's value)")
    return 0


def cmd_doctor(a):
    machine = checks.prerequisites()
    results = [r for d in a.ca for r in checks.ca(d)] + [r for f in a.config for r in checks.config(f)]
    broken = any(r["level"] == "fail" for r in machine)
    fails, warns = sum(r[0] == "fail" for r in results), sum(r[0] == "warn" for r in results)
    code = 3 if broken else 2 if fails else 1 if warns and a.strict else 0
    if a.json:
        print(json.dumps({"version": __version__, "checks": machine + [{"product": "deployment", "level": lv, "message": m, "action": ""} for lv, m in results]}, indent=1))
        return code
    print(f"{NAME} {__version__}, Python {sys.version.split()[0]}")
    mark = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}
    for r in machine:
        print(f"{mark[r['level']]}  {r['message'].rstrip('.')}" + (f". {r['action']}" if r["action"] else ""))
    for level, msg in results:
        print(f"{mark[level]}  {msg}")
    if results:
        print(f"\n{fails} problem(s), {warns} warning(s)")
    return code


HELP = {
    "key_passphrase_env": "the key's passphrase is in this environment variable",
    "json": "print JSON instead of text",
    "san": "another DNS name or IP address the certificate covers (repeatable)",
    "days": "certificate lifetime in days",
    "algorithm": "the key's algorithm",
    "serial": "from `ca list`; the first 8 or more hex characters are enough",
    "common_name": "the name it certifies",
    "vici": "strongSwan's control socket (default: unix:///var/run/charon.vici)",
    "interface": "the WireGuard interface (default: wg0)",
    "server_name": "the name in the gateway's certificate, if not its host",
    "ca": "the CA certificate to trust",
    "key": "the private key",
}

START = """Acxelin VPN: post-quantum site-to-site IPsec, and WireGuard remote access for people, with a desktop app.

Start here:
  acxelin-vpn doctor                  check that this machine can run a gateway or join one
  acxelin-vpn ca init --name NAME     the certificate authority for gateways and people
  acxelin-vpn invite NAME ...         administrator: one file that lets a person join
  acxelin-vpn join NAME.acxinvite     on the person's computer: enroll and connect in one step
  acxelin-vpn --help                  every command (up, gateway, app, desktop, status ...)"""


def parser():
    ap = argparse.ArgumentParser(prog=NAME, description="Acxelin VPN: post-quantum site-to-site IPsec (strongSwan) and WireGuard remote access, with a desktop app.")
    ap.add_argument("--version", action="version", version=f"{NAME} {__version__}")
    ap.add_argument("--log-json", action="store_true", help="structured JSON logs")
    ap.add_argument("-v", "--verbose", action="store_true", help="log debugging detail")
    v = ap.add_subparsers(dest="cmd")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dir", default="pki", help="CA folder (default: pki)")
    p = v.add_parser("doctor", help="check that this machine can run Acxelin VPN, and check a CA folder or a configuration")
    p.set_defaults(func=cmd_doctor)
    p.add_argument("--ca", action="append", default=[], metavar="DIR", help="a CA folder to check (repeatable)")
    p.add_argument("--config", action="append", default=[], metavar="FILE", help="a site or gateway configuration to check (repeatable)")
    p.add_argument("--strict", action="store_true", help="exit 1 on warnings")
    p.add_argument("--json", action="store_true")
    p = v.add_parser("up", help="run a site: key agreement, rotation, revocation, metrics")
    p.add_argument("--config", required=True, help="site TOML (see config/site-hq.toml)")
    for name, text in (("status", "is this machine protected? (a person's computer) or tunnels, algorithms and traffic (a site)"),
                       ("check", "is strongSwan reachable and does it have ML-KEM?")):
        p = v.add_parser(name, help=text)
        p.add_argument("--config", help="read the VICI address from a site TOML")
        p.add_argument("--vici")
        p.add_argument("--json", action="store_true")
        if name == "status":
            p.add_argument("--interface", default="wg0", help="the computer's tunnel to report on (default: wg0)")
            p.add_argument("--details", action="store_true", help="also show algorithms, handshake and key timing")
    p = v.add_parser("invite", parents=[common], help="administrator: one file that lets a person enroll and connect with `join`")
    p.add_argument("name", help="the person's or device's certificate name (also add it to the gateway's users list, if it has one)")
    p.add_argument("--enroll", required=True, metavar="URL", help="the enrollment service, https://host:9443 (see `ca serve`)")
    p.add_argument("--gateway", required=True, metavar="HOST:PORT", help="the WireGuard gateway's key agreement address")
    p.add_argument("--server-name", help="the gateway's certificate name, if it differs from HOST")
    p.add_argument("--hours", type=positive(float), default=24, help="how long the invitation can be used (default: 24)")
    p.add_argument("--out", help="the invitation file (default: NAME.acxinvite)")
    p = v.add_parser("join", help="enroll this computer from an invitation file and connect it, in one step")
    p.add_argument("invitation", help="the .acxinvite file from your administrator")
    p.add_argument("--device", help="folder for this computer's certificate and key (default: next to the invitation, named after it)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--key-passphrase-env", help="read the device key passphrase from this environment variable instead of asking")
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p.add_argument("--once", action="store_true", help="agree once and exit")
    p = v.add_parser("app", help="a window in the browser to join, connect, disconnect and see whether this computer is protected")
    p.add_argument("invitation", nargs="?", help="the .acxinvite file (default: the newest in ~/.acxelin-vpn; the window can also open one)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--no-browser", action="store_true", help="print the address instead of opening it")
    p.add_argument("--folder", help="where invitations and this computer's keys are kept (default: ~/.acxelin-vpn)")
    p.add_argument("--session", help=argparse.SUPPRESS)
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p = v.add_parser("desktop", help="the desktop app: a tray icon that shows whether this computer is protected, and the VPN window")
    p.add_argument("invitation", nargs="?", help="the .acxinvite file (the window can also open one)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p.add_argument("--launcher", action="store_true", help="add Acxelin VPN to the Start menu, Applications or the application list")
    p.add_argument("--remove-launcher", action="store_true", help="remove what --launcher added")
    p.add_argument("--start-at-login", choices=("on", "off"), help="show the tray icon when you log in (it connects only when you ask)")
    p.add_argument("--background", action="store_true", help="start in the tray without opening the window")
    p = v.add_parser("gateway", help="WireGuard remote-access gateway: address pool, PSK from ML-DSA mutual TLS, rotation, revocation")
    p.add_argument("--config", required=True, help="TOML with a [wireguard] section (see config/gateway.toml)")
    for name, text in (("connect", "connect this computer (Linux, Windows or macOS) to a WireGuard gateway and keep its PSK fresh"),
                       ("install", "check gateway access and install a service that connects at machine startup")):
        p = v.add_parser(name, help=text)
        p.add_argument("keyring", help="the gateway's key agreement address, host:port")
        p.add_argument("--cert-dir", required=True, help="folder with cert.pem, chain.pem, key.pem and ca.crt (as enrollment writes them)")
        p.add_argument("--ca", help="trust this CA file instead of CERT_DIR/ca.crt")
        p.add_argument("--interface", default="wg0")
        p.add_argument("--server-name")
        if name == "connect":
            p.add_argument("--no-apply", action="store_true", help="do not configure the tunnel (use with --config-out)")
            p.add_argument("--config-out", help="also write a wg-quick configuration here after every key agreement")
            p.add_argument("--key-passphrase-env")
            p.add_argument("--once", action="store_true", help="agree once and exit")
    p = v.add_parser("disconnect", help="take the tunnel down and lift the kill switch")
    p.add_argument("--interface", default="wg0")
    v.add_parser("uninstall", help="stop starting the VPN with this machine")
    p = v.add_parser("inventory", help="the VPN's cryptography as a CycloneDX 1.6 CBOM, for Acxelin Readiness or any CBOM tool")
    p.add_argument("--config", action="append", required=True, metavar="FILE", help="a site or gateway configuration (repeatable)")
    p.add_argument("--cbom", default="cbom.json", metavar="FILE", help="where to write it (default: cbom.json)")
    p.add_argument("--name", default="Acxelin VPN", help="what the CBOM is about, e.g. \"Acme VPN\" (default: Acxelin VPN)")
    for name, c in v.choices.items():
        if name not in ("doctor", "inventory"):
            c.set_defaults(func=cmd_vpn)
    v.choices["inventory"].set_defaults(func=cmd_inventory)
    ca_commands.add(v, common)
    from . import console
    console.add(v)
    for sub in (v, next(a for a in v.choices["ca"]._actions if a.dest == "ca_cmd")):
        for a in sub._choices_actions:  # each command's own --help starts with what it does
            sub.choices[a.dest].description = sub.choices[a.dest].description or a.help
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
    except (CAError, CharonError, WGError, tls.TLSError, ValueError, OSError, ImportError) as e:
        print(f"error: {explain(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
