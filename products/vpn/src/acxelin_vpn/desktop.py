"""Acxelin VPN on the desktop: a tray icon that shows whether this computer is protected, and the VPN window.

The tray runs as the person. The part that changes the network is `acxelin-vpn app`, which the tray starts with
administrator rights through the system's own prompt (UAC, polkit, the macOS password dialog) and then talks to over the
window's loopback API with a key only this account can read. Closing the window or the tray leaves the VPN as it is;
"Quit" disconnects and stops it. Needs the `desktop` extra (pystray, Pillow)."""
import json
import os
import plistlib
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

from acxelin_core.files import write
from . import app, platforms

NAME = "Acxelin VPN"
TONES = {"protected": "#26734d", "connecting": "#c98a00", "agreed": "#c98a00", "not_protected": "#b3431f"}
WORDS = {"protected": "Protected", "connecting": "Connecting", "agreed": "Keys agreed, not protected", "not_protected": "Not protected",
         "disconnected": "Disconnected", "none": "Not set up", "stopped": "VPN service not running"}


def folder():
    return Path.home() / ".acxelin-vpn"


def summary(state):
    """The tray's word for a window state, or "stopped" when the service cannot be reached."""
    if state is None:
        return "stopped"
    s = state.get("status", {}).get("state", "disconnected")
    return "none" if s == "disconnected" and not state.get("invitation") else s


def headline(state):
    word = summary(state)
    status = (state or {}).get("status", {})
    return f"{WORDS.get(word, word)}" + (f" · {status['address'].split('/')[0]}" if word == "protected" and status.get("address") else "")


def image(word, size=64):
    """A shield in the state's colour with a mark (check, clock, exclamation or dash), drawn large and scaled down for clean edges."""
    from PIL import Image, ImageDraw
    k = 4
    n = size * k
    im = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    w = lambda *p: [(x * n / 24, y * n / 24) for x, y in p]
    d.polygon(w((12, 1.5), (21, 5), (21, 11.5), (19.6, 16.4), (16.3, 20), (12, 22.5), (7.7, 20), (4.4, 16.4), (3, 11.5), (3, 5)),
              fill=TONES.get(word, "#636e78"))
    line = dict(fill="white", width=int(2.4 * n / 24), joint="curve")
    if word == "protected":
        d.line(w((8, 12), (11, 15), (16.5, 9)), **line)
    elif word in ("connecting", "agreed"):
        d.line(w((12, 7.5), (12, 12.5), (15, 14.5)), **line)
    elif word == "not_protected":
        d.line(w((12, 7), (12, 13)), **line)
        d.ellipse(w((10.6, 15.6), (13.4, 18.4)), fill="white")
    else:
        d.line(w((8.5, 12), (15.5, 12)), **line)
    return im.resize((size, size), Image.LANCZOS)


def browser():
    """A Chromium-family browser to show the window without an address bar (an app window), or None for the default browser."""
    if os.name == "nt":
        roots = [os.environ.get(v) for v in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA")]
        found = [Path(r) / p for r in roots if r for p in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe")]
    elif sys.platform == "darwin":
        found = [Path(f"/Applications/{a}.app/Contents/MacOS/{a}") for a in ("Microsoft Edge", "Google Chrome", "Chromium", "Brave Browser")]
    else:
        found = [Path(p) for p in map(shutil.which, ("microsoft-edge", "google-chrome", "chromium", "chromium-browser", "brave-browser")) if p]
    return next((str(p) for p in found if p.is_file()), None)


def open_window(url, profile):
    exe = browser()
    if not exe:
        return webbrowser.open(url)
    prefs = Path(profile) / "Default" / "Preferences"
    try:
        current = json.loads(prefs.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = {}
    current |= {"credentials_enable_service": False, "autofill": {"profile_enabled": False}}  # never offer to save the passphrase
    current["profile"] = current.get("profile", {}) | {"password_manager_enabled": False}
    prefs.parent.mkdir(parents=True, exist_ok=True)
    prefs.write_text(json.dumps(current), encoding="utf-8")
    subprocess.Popen([exe, f"--app={url}", f"--user-data-dir={profile}", "--window-size=540,780", "--no-first-run", "--no-default-browser-check"],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **detached())
    return True


def detached():
    if os.name == "nt":
        return {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}


def python():
    """The interpreter for background processes: pythonw on Windows, so no console window opens."""
    exe = Path(sys.executable)
    quiet = exe.with_name("pythonw.exe")
    return str(quiet if os.name == "nt" and quiet.exists() else exe)


def entry():
    """How to start Acxelin VPN: the packaged app's own program, or this Python with `-m acxelin_vpn`."""
    return [sys.executable] if getattr(sys, "frozen", False) else [python(), "-m", "acxelin_vpn"]


def isolated(command):
    """The interpreter started with -I: it ignores PYTHONPATH and every other PYTHON* variable, the person's user-site folder and the
    current folder. A packaged app is a single program and is left as it is."""
    return command if getattr(sys, "frozen", False) else [command[0], "-I", *command[1:]]


def elevated(command):
    """How to run `command` (a list) with administrator rights on this system, as a list to start without waiting. Nothing of this
    person's import path or environment goes with it: it loads only what the interpreter itself finds."""
    command = isolated(command)
    if sys.platform == "darwin":
        script = shlex.join(command) + " >/dev/null 2>&1 &"
        return ["osascript", "-e", f'do shell script "{script.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}" with administrator privileges']
    if not shutil.which("pkexec"):
        raise ValueError("this desktop has no administrator prompt (polkit's pkexec); start the VPN service with `sudo acxelin-vpn app` instead")
    return ["pkexec", *command]


def start_service(command, apply):
    """Start `acxelin-vpn app` in the background, through the administrator prompt when it will change the network. That prompt is
    only used for code an ordinary user cannot change (`platforms.require_protected_code`), checked before any prompt appears."""
    from .join import administrator
    if not apply or administrator():
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **detached())
    platforms.require_protected_code("Starting the VPN service from the tray", command[0])
    if os.name == "nt":
        import ctypes
        command = isolated(command)
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", command[0], subprocess.list2cmdline(command[1:]), None, 0)
        if r <= 32:
            raise ValueError("administrator rights were not given, so the VPN cannot change this computer's network")
        return None
    return subprocess.Popen(elevated(command), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **detached())


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Tray:
    """The tray icon and the VPN service behind it. The icon and menu follow the service's state every few seconds."""

    def __init__(self, invitation=None, interface="wg0", apply=True, home=None):
        self.folder = Path(home or folder())
        self.invitation, self.interface, self.apply = invitation, interface, apply
        self.session_file = self.folder / f"{interface}.desktop.json"
        self.state, self.icon, self.problem, self.stop = None, None, None, threading.Event()
        self.session = self.load(self.session_file)

    @staticmethod
    def load(path):
        try:
            s = json.loads(Path(path).read_text(encoding="utf-8"))
            return s if isinstance(s.get("token"), str) and isinstance(s.get("port"), int) else None
        except (OSError, ValueError):
            return None

    def call(self, method, path):
        if not self.session:
            raise ConnectionError("not started")
        return app.request(self.session["port"], self.session["token"], method, path)

    def refresh(self):
        try:
            self.state = self.call("GET", "/api/state")
        except (OSError, ValueError):
            self.state = None
        return self.state

    def command(self):
        cmd = [*entry(), "app", "--no-browser", "--session", str(self.session_file), "--folder", str(self.folder),
               "--interface", self.interface]
        return cmd + (["--no-apply"] if not self.apply else []) + ([str(Path(self.invitation).resolve())] if self.invitation else [])

    def start(self, wait=90):
        """Reuse a running service (this tray's, or a `vpn app` started in a terminal), or start one with a fresh key and
        port; True once it answers."""
        for session in (self.session, self.load(self.folder / f"{self.interface}.app.json")):
            self.session = session
            if session and self.refresh() is not None:
                return True
        self.session = {"port": free_port(), "token": secrets.token_urlsafe(24)}
        write(self.session_file, json.dumps(self.session).encode(), secret=True)
        start_service(self.command(), self.apply)
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline and not self.stop.is_set():
            if self.refresh() is not None:
                return True
            time.sleep(0.5)
        return False

    def open(self, *_):
        try:
            started = self.refresh() is not None or self.start()
        except (OSError, ValueError) as e:
            started, self.problem = False, str(e)
        if not started:
            self.problem = self.problem or "it did not answer; choose Start VPN service to try again"
            self.show()
            return self.notify(f"The VPN service did not start: {self.problem}")
        self.problem = None
        url = f"http://127.0.0.1:{self.session['port']}/#{self.call('POST', '/api/ticket')['ticket']}"
        open_window(url, self.folder / "window-profile")

    def disconnect(self, *_):
        try:
            self.state = self.call("POST", "/api/disconnect")
        except (OSError, ValueError) as e:
            self.notify(str(e))
        self.show()

    def opening(self, *_):
        threading.Thread(target=self.open, daemon=True).start()

    def quit(self, *_):
        try:
            self.call("POST", "/api/quit")
        except (OSError, ValueError):
            pass
        self.stop.set()
        if self.icon:
            self.icon.stop()

    def notify(self, message):
        try:
            self.icon.notify(message, NAME)
        except Exception:  # not every tray host shows notifications; the icon and menu still say it
            pass

    def show(self):
        if self.icon:
            word = summary(self.state)
            self.icon.icon, self.icon.title = image(word), f"{NAME}: {headline(self.state)}"
            self.icon.update_menu()

    def watch(self):
        last = None
        while not self.stop.wait(3):
            word = summary(self.refresh())
            self.show()
            if last and word != last and word in ("protected", "not_protected", "disconnected", "stopped"):
                self.notify(headline(self.state) + ("" if word != "not_protected" else f": {self.state['status'].get('error') or 'retrying'}"))
            last = word

    def menu(self):
        import pystray
        running = lambda _: summary(self.state) not in ("stopped", "none", "disconnected")
        return pystray.Menu(
            pystray.MenuItem(lambda _: headline(self.state), None, enabled=False),
            pystray.MenuItem(lambda _: self.problem, None, enabled=False, visible=lambda _: bool(self.problem) and self.state is None),
            pystray.MenuItem(f"Open {NAME}", self.opening, default=True),
            pystray.MenuItem("Disconnect", self.disconnect, visible=running),
            pystray.MenuItem("Start VPN service", self.opening, visible=lambda _: self.state is None),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Start at login", self.toggle_login, checked=lambda _: autostart()),
            pystray.MenuItem("Quit and disconnect", self.quit))

    def toggle_login(self, *_):
        try:
            autostart(not autostart())
        except OSError as e:
            self.notify(f"Start at login could not be changed: {e}")
        self.show()

    def run(self, open_window=True):
        import pystray
        self.icon = pystray.Icon("acxelin-vpn", image(summary(self.state)), NAME, self.menu())

        def setup(icon):
            icon.visible = True
            if open_window:
                self.open()
            self.show()
            threading.Thread(target=self.watch, daemon=True).start()
        self.icon.run(setup)


def desktop_entry(command, extra=""):
    """A freedesktop.org launcher; its Exec line quotes arguments with double quotes, as the specification requires."""
    quote = lambda a: a if a and not any(c in a for c in ' \t"\'\\><~|&;$*?#()`') else '"' + "".join("\\" + c if c in '"`$\\' else c for c in a) + '"'
    icon = folder() / "acxelin-vpn.png"
    icon.parent.mkdir(parents=True, exist_ok=True)
    image("protected", 256).save(icon)
    return (f"[Desktop Entry]\nType=Application\nName={NAME}\nComment=Post-quantum VPN: connect, and see whether this computer is protected\n"
            f"Exec={' '.join(map(quote, command))}\nIcon={icon}\nTerminal=false\nCategories=Network;Security;\n{extra}")


def autostart(enable=None):
    """Start the tray when this account logs in: the icon only, without opening the window or asking for administrator
    rights (that happens when the person opens it to connect). With `enable` None, say whether it is on."""
    command = [*entry(), "desktop", "--background"]
    if os.name == "nt":
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            try:
                current = winreg.QueryValueEx(key, NAME)[0]
            except FileNotFoundError:
                current = None
            if enable is None:
                return current is not None
            if enable:
                winreg.SetValueEx(key, NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(command))
            elif current is not None:
                winreg.DeleteValue(key, NAME)
        return enable
    if sys.platform == "darwin":
        path = Path.home() / "Library" / "LaunchAgents" / "com.acxelin.vpn.plist"
        content = plistlib.dumps({"Label": "com.acxelin.vpn", "ProgramArguments": command, "RunAtLoad": True, "ProcessType": "Interactive"})
    else:
        path = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "autostart" / "acxelin-vpn.desktop"
        if enable is None:
            return path.exists()
        content = desktop_entry(command, "X-GNOME-Autostart-enabled=true\n").encode()
    if enable is None:
        return path.exists()
    if enable:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    else:
        path.unlink(missing_ok=True)
    return enable


def launcher(remove=False):
    """Add Acxelin VPN to the Start menu, Applications or the desktop's application list (or remove it); returns its path."""
    command = [*entry(), "desktop"]
    exe, args = command[0], subprocess.list2cmdline(command[1:]) if os.name == "nt" else shlex.join(command[1:])
    icons = folder()
    icons.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        path = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / f"{NAME}.lnk"
        if remove:
            path.unlink(missing_ok=True)
            return path
        image("protected", 256).save(icons / "acxelin-vpn.ico", sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
        q = lambda v: "'" + str(v).replace("'", "''") + "'"
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut({q(path)}); $s.TargetPath={q(exe)}; $s.Arguments={q(args)}; "
                        f"$s.IconLocation={q(icons / 'acxelin-vpn.ico')}; $s.Description={q('Post-quantum VPN')}; $s.Save()"], check=True, capture_output=True)
        return path
    if sys.platform == "darwin":
        path = Path.home() / "Applications" / f"{NAME}.app"
        if remove:
            shutil.rmtree(path, ignore_errors=True)
            return path
        (path / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
        (path / "Contents" / "Resources").mkdir(exist_ok=True)
        image("protected", 512).save(path / "Contents" / "Resources" / "acxelin-vpn.icns")
        run = path / "Contents" / "MacOS" / "acxelin-vpn"
        run.write_text(f"#!/bin/sh\nexec {shlex.quote(exe)} {args}\n", encoding="utf-8")
        run.chmod(0o755)
        (path / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleName": NAME, "CFBundleIdentifier": "com.acxelin.vpn", "CFBundleExecutable": "acxelin-vpn",
            "CFBundleIconFile": "acxelin-vpn", "CFBundlePackageType": "APPL", "LSUIElement": True}))
        return path
    path = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "applications" / "acxelin-vpn.desktop"
    if remove:
        path.unlink(missing_ok=True)
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(desktop_entry(command), encoding="utf-8")
    return path


def main(invitation=None, interface="wg0", apply=True, background=False):
    """The tray, once per account and interface; launching it again opens the window of the one already running."""
    try:
        import PIL, pystray  # noqa: F401
    except ImportError:
        raise ImportError('the desktop app needs its extra: pip install "acxelin-vpn[desktop]" (or use `acxelin-vpn app` for the window in your browser)') from None
    tray = Tray(invitation, interface, apply)
    held, _ = app.claim(tray.folder, f"{interface}.desktop")
    if not held:
        tray.open()
        return 0
    with held:
        tray.run(open_window=not background)
    return 0
