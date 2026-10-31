"""The client's WireGuard tunnel on its own machine, through that platform's official WireGuard tools, and the kill switch.

Linux and macOS use `wg-quick` (wireguard-tools; on macOS from Homebrew, which brings wireguard-go). Windows uses WireGuard for
Windows as a tunnel service. On all three, the first PSK goes into the tunnel's configuration file (owner-only) and every later
one is set in place with `wg set`, so a rotation never drops the tunnel.

Kill switch, in full-tunnel mode only: nothing leaves the machine except through the tunnel, WireGuard's own packets to the
gateway, the key agreement with the gateway, loopback and DHCP. Linux: an iptables chain. macOS: a pf anchor inside Apple's.
Windows: WireGuard for Windows' own "block untunneled traffic", which it switches on for a full-tunnel configuration. The Linux
and macOS rules stay while the tunnel is briefly down to agree new keys (after a long sleep); the Windows ones go with the tunnel.
"""
import html
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from acxelin_core.files import protected_location, write


FULL = ["0.0.0.0/0", "::/0"]
SECRET = object()
INSTALL = {"Linux": "install wireguard-tools (apt install wireguard-tools)", "Darwin": "install wireguard-tools (brew install wireguard-tools)",
           "Windows": "install WireGuard for Windows from https://www.wireguard.com/install/"}
EXTRA_PATH = {"Darwin": ["/opt/homebrew/bin", "/usr/local/bin"],
              "Windows": [str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WireGuard")]}


class WGError(Exception):
    pass


def system():
    return platform.system()


def find(tool):
    """A tool on PATH, or where the platform's WireGuard installer puts it (services start with a short PATH)."""
    extra = EXTRA_PATH.get(system(), [])
    return shutil.which(tool) or shutil.which(tool, path=os.pathsep.join(extra)) or tool


def run(cmd, secret=None, env=None):
    """Run a tool; a secret goes through an owner-only temporary file named where SECRET stands. Returns stdout and stderr."""
    name = None
    try:
        if secret:
            fd, name = tempfile.mkstemp()
            with os.fdopen(fd, "w") as f:
                f.write(secret + "\n")
        full = os.environ | {"PATH": os.pathsep.join(EXTRA_PATH.get(system(), []) + [os.environ.get("PATH", "")])} | (env or {})
        r = subprocess.run([name if a is SECRET else a for a in cmd], capture_output=True, text=True, timeout=60, env=full)
    except FileNotFoundError:
        raise WGError(f"{Path(cmd[0]).name} is not installed: {INSTALL.get(system(), 'install wireguard-tools')}") from None
    except subprocess.TimeoutExpired:
        raise WGError(f"{Path(cmd[0]).name} {cmd[1] if len(cmd) > 1 else ''} gave no answer within 60 s") from None
    finally:
        if name:
            os.unlink(name)
    if r.returncode:
        raise WGError(f"{Path(cmd[0]).name} {cmd[1] if len(cmd) > 1 else ''}: {(r.stderr or r.stdout).strip() or r.returncode}")
    return r.stdout + r.stderr


class WG:
    """The `wg` tool, which drives the Linux kernel module, wireguard-go and WireGuard for Windows alike."""

    def __init__(self, interface, tool="wg", runner=run):
        self.interface, self.tool, self.runner = interface, tool, runner

    def run(self, *args, secret=None):
        return self.runner([self.tool, *args], secret)

    def set_private_key(self, key, listen_port=None):
        self.run("set", self.interface, "private-key", SECRET, *(["listen-port", str(listen_port)] if listen_port else []), secret=key)

    def set_peer(self, public, psk, allowed_ips, endpoint=None, keepalive=None):
        extra = (["endpoint", endpoint] if endpoint else []) + (["persistent-keepalive", str(keepalive)] if keepalive else [])
        self.run("set", self.interface, "peer", public, "preshared-key", SECRET, "allowed-ips", ",".join(allowed_ips), *extra, secret=psk)

    def set_psk(self, public, psk):
        self.run("set", self.interface, "peer", public, "preshared-key", SECRET, secret=psk)

    def remove_peer(self, public):
        self.run("set", self.interface, "peer", public, "remove")

    def peers(self):
        out = {}
        for line in self.run("show", self.interface, "dump").splitlines()[1:]:
            pub, psk, endpoint, allowed, handshake, rx, tx, _ = line.split("\t")
            out[pub] = {"endpoint": None if endpoint == "(none)" else endpoint, "allowed_ips": allowed.split(","), "psk": psk != "(none)",
                        "latest_handshake": int(handshake), "rx_bytes": int(rx), "tx_bytes": int(tx)}
        return out


def ipv6():
    """False on a Linux kernel built or booted without IPv6, where there is nothing to route or to block."""
    return system() != "Linux" or Path("/proc/net/if_inet6").exists()


def addresses(host):
    return sorted({a[4][0] for a in socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)})


class Tunnel:
    """wg-quick on Linux and macOS. `folder` holds the tunnel's configuration file, which is owner-only and holds its keys."""

    def __init__(self, name, folder, runner=run):
        self.name, self.folder, self.runner = name, Path(folder), runner
        self.up_ = False

    @property
    def config(self):
        return self.folder / f"{self.name}.conf"

    def env(self):
        go = os.environ.get("ACXELIN_WIREGUARD_GO")
        return {"WG_QUICK_USERSPACE_IMPLEMENTATION": go, "WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD": "1"} if go else {}

    def device(self):
        return self.name

    def routes(self, routes):
        return [r for r in routes if ipv6() or ":" not in r]

    def wg(self):
        return WG(self.device(), find("wg"), self.runner)

    def up(self, text):
        if self.up_:
            self.down()
        write(self.config, text.encode(), secret=True)
        self.runner([find("wg-quick"), "up", str(self.config)], None, self.env())
        self.up_ = True

    def down(self):
        if self.config.exists():
            try:
                self.runner([find("wg-quick"), "down", str(self.config)], None, self.env())
            except WGError:
                pass  # already down
        self.up_ = False

    def handshake_age(self, peer):
        """Seconds since WireGuard last completed a handshake with `peer`, or None before the first one."""
        for line in self.wg().run("show", self.device(), "latest-handshakes").splitlines():
            pub, _, ts = line.partition("\t")
            if pub == peer and int(ts or 0):
                return time.time() - int(ts)
        return None


class MacTunnel(Tunnel):
    def device(self):
        """wg-quick on macOS runs the tunnel on a utun interface and records which one."""
        return Path(f"/var/run/wireguard/{self.name}.name").read_text().strip()


class WindowsTunnel(Tunnel):
    """WireGuard for Windows: the configuration becomes a tunnel service, which `wg.exe` then drives by name."""

    def up(self, text):
        if self.up_:
            self.down()
        write(self.config, text.encode(), secret=True)
        self.runner(["icacls", str(self.config), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
        self.runner([find("wireguard"), "/installtunnelservice", str(self.config)])
        deadline = time.monotonic() + 20
        while True:
            try:
                self.wg().run("show", self.name)
                break
            except WGError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        self.up_ = True

    def down(self):
        try:
            self.runner([find("wireguard"), "/uninstalltunnelservice", self.name])
        except WGError:
            pass  # not installed
        self.up_ = False


class KillSwitch:
    """No kill switch of our own: used on Windows, where WireGuard for Windows blocks untunneled traffic itself."""

    def __init__(self, folder, runner=run):
        self.folder, self.runner = Path(folder), runner

    def on(self, device, endpoint, keyring):
        pass

    def off(self):
        pass


class LinuxKillSwitch(KillSwitch):
    CHAIN = "ACXELIN-KILLSWITCH"

    def rules(self, device, endpoint, keyring, v6):
        keep = lambda ip: (":" in ip) == v6
        return ([["-o", "lo", "-j", "ACCEPT"], ["-o", device, "-j", "ACCEPT"],
                 ["-p", "udp", "--dport", "546:547" if v6 else "67:68", "-j", "ACCEPT"]]
                + [["-d", ip, "-p", "udp", "--dport", str(endpoint[1]), "-j", "ACCEPT"] for ip in endpoint[0] if keep(ip)]
                + [["-d", ip, "-p", "tcp", "--dport", str(keyring[1]), "-j", "ACCEPT"] for ip in keyring[0] if keep(ip)]
                + [["-j", "REJECT"]])

    def on(self, device, endpoint, keyring):
        """Fail closed at every instant: the new rules go into a second chain that OUTPUT jumps to before the old one is removed."""
        if getattr(self, "applied", None) == (device, endpoint, keyring):
            return
        new = self.CHAIN + "-NEW"
        for tool, v6 in (("iptables", False), ("ip6tables", True))[:2 if ipv6() else 1]:
            self.drop(tool, new)
            self.runner([tool, "-N", new])
            for rule in self.rules(device, endpoint, keyring, v6):
                self.runner([tool, "-A", new, *rule])
            self.runner([tool, "-I", "OUTPUT", "1", "-j", new])
            self.drop(tool, self.CHAIN)
            self.runner([tool, "-E", new, self.CHAIN])
        self.applied = (device, endpoint, keyring)

    def drop(self, tool, chain):
        try:
            while True:
                self.runner([tool, "-D", "OUTPUT", "-j", chain])
        except WGError:
            pass
        for step in ("-F", "-X"):
            try:
                self.runner([tool, step, chain])
            except WGError:
                pass

    def off(self):
        for tool in ("iptables", "ip6tables"):
            self.drop(tool, self.CHAIN)
        self.applied = None


class MacKillSwitch(KillSwitch):
    """A pf anchor under Apple's own `com.apple/*`, which the stock /etc/pf.conf already evaluates."""
    ANCHOR = "com.apple/acxelin-vpn"

    @property
    def token(self):
        return self.folder / "killswitch.token"

    def release(self, anchor, token):
        """Flush an anchor and drop the pf reference its token holds; pf stays enabled while another token holds it."""
        try:
            self.runner(["pfctl", "-a", anchor, "-F", "all"])
        except WGError:
            pass
        if token.exists():
            value = token.read_text().strip()
            try:
                if value:
                    self.runner(["pfctl", "-X", value])
            except WGError:
                pass
            token.unlink()

    def rules(self, device, endpoint, keyring):
        return "\n".join(["pass out quick on lo0 all", f"pass out quick on {device} all",
                          "pass out quick proto udp from any port 68 to any port 67",
                          *(f"pass out quick proto udp to {ip} port {endpoint[1]}" for ip in endpoint[0]),
                          *(f"pass out quick proto tcp to {ip} port {keyring[1]}" for ip in keyring[0]),
                          "block drop out quick all"]) + "\n"

    def on(self, device, endpoint, keyring):
        rules = self.folder / "killswitch.pf"
        write(rules, self.rules(device, endpoint, keyring).encode(), secret=True)
        self.runner(["pfctl", "-a", self.ANCHOR, "-f", str(rules)])
        if not self.token.exists():
            out = self.runner(["pfctl", "-E"])
            token = next((line.split(":", 1)[1].strip() for line in out.splitlines() if line.startswith("Token")), "")
            write(self.token, token.encode(), secret=True)

    def off(self):
        self.release(self.ANCHOR, self.token)


def folder():
    """Where this machine keeps tunnel configurations: root-only, and not in the user's home."""
    if system() == "Windows":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Acxelin" / "vpn"
    return Path("/var/run/acxelin-vpn" if system() == "Darwin" else "/run/acxelin-vpn")


def this_machine(name, where=None, runner=run):
    """(tunnel, kill switch) for this operating system."""
    where = Path(where or folder())
    kind = system()
    if kind == "Windows":
        return WindowsTunnel(name, where, runner), KillSwitch(where, runner)
    if kind == "Darwin":
        return MacTunnel(name, where, runner), MacKillSwitch(where, runner)
    return Tunnel(name, where, runner), LinuxKillSwitch(where, runner)


SERVICE = "acxelin-vpn"


def service(argv, kind=None, name=SERVICE):
    """(path, contents, commands to start it, commands to remove it) that keep `argv` running from boot, restarted if it stops."""
    kind = kind or system()
    if kind == "Windows":
        base = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Acxelin" / "vpn"  # administrators only; ProgramData lets users make folders
        script = base / "connect.cmd"
        line = subprocess.list2cmdline(argv)
        return (script, f"@echo off\r\n:again\r\n{line}\r\ntimeout /t 10 /nobreak >nul\r\ngoto again\r\n",
                [["schtasks", "/create", "/tn", name, "/tr", f'"{script}"', "/sc", "onstart", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"],
                 ["schtasks", "/run", "/tn", name]],
                [["schtasks", "/end", "/tn", name], ["schtasks", "/delete", "/tn", name, "/f"]])
    if kind == "Darwin":
        label = "com.acxelin.vpn"
        path = Path(f"/Library/LaunchDaemons/{label}.plist")
        args = "".join(f"<string>{html.escape(a)}</string>" for a in argv)
        plist = (f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                 f'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n<key>Label</key><string>{label}</string>\n'
                 f"<key>ProgramArguments</key><array>{args}</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n"
                 f"<key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>\n"
                 f"<key>StandardErrorPath</key><string>/var/log/{name}.log</string>\n</dict></plist>\n")
        return path, plist, [["launchctl", "bootstrap", "system", str(path)]], [["launchctl", "bootout", f"system/{label}"]]
    path = Path(f"/etc/systemd/system/{name}.service")
    unit = (f"[Unit]\nDescription=Acxelin VPN client (WireGuard with a PSK from ML-DSA mutual TLS)\nAfter=network-online.target\n"
            f"Wants=network-online.target\n\n[Service]\nExecStart={subprocess.list2cmdline(argv)}\nRestart=always\nRestartSec=5\n\n"
            f"[Install]\nWantedBy=multi-user.target\n")
    return (path, unit, [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", name]],
            [["systemctl", "disable", "--now", name]])


def isolated(command):
    """The interpreter started with -I: it ignores PYTHONPATH and every other PYTHON* variable, the person's user-site folder and the
    current folder. A packaged app is a single program and is left as it is."""
    return command if getattr(sys, "frozen", False) else [command[0], "-I", *command[1:]]


def elevation_problem(interpreter=None):
    """None, or why code started with administrator rights here could be changed by an ordinary user: the interpreter, every folder
    it imports from (checked as directories and their parents, not file by file) and the folder OpenSSL is loaded from must be where
    only administrators can write. A packaged app is one program, so only it and its OpenSSL folder are checked. On Windows OpenSSL
    must come from the folder ACXELIN_OPENSSL names, because the alternative is PATH."""
    exe = interpreter or sys.executable
    openssl = os.environ.get("ACXELIN_OPENSSL")
    if os.name == "nt" and not openssl:
        return "OpenSSL would be searched for on PATH, which any user can change; set ACXELIN_OPENSSL to a folder only administrators can write"
    code = [exe] if getattr(sys, "frozen", False) else [exe, *(p for p in sys.path if p and os.path.isdir(p))]
    return protected_location([*code, *([openssl] if openssl else [])])


def require_protected_code(what, interpreter=None):
    why = elevation_problem(interpreter)
    if why:
        raise ValueError(f"{what} would run code with administrator rights that an ordinary user can change ({why}). Anyone who can run "
                         "programs as this user could use that to become the administrator. Use a copy of Acxelin VPN installed where only "
                         "administrators can write: the Windows Setup or the Linux package from the release page, or a copy an administrator "
                         "installed under /opt (the manual shows how), and run this again from there."
                         + (" On a Mac, Applications can be changed by any administrator account, so the tray cannot start the service "
                            "from there: run sudo acxelin-vpn app in Terminal instead." if sys.platform == "darwin" else ""))


def install(argv, runner=run):
    require_protected_code("Starting the VPN when this computer starts", argv[0])
    path, text, start, _ = service(argv)
    write(path, text.encode())
    for cmd in start:
        runner(cmd)
    return path


def uninstall(runner=run):
    return remove(SERVICE, runner)


def remove(name, runner=run):
    path, _, _, stop = service([sys.executable], name=name)
    for cmd in stop:
        try:
            runner(cmd)
        except WGError:
            pass
    if path.exists():
        path.unlink()
    return path
