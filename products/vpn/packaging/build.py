"""Build the Acxelin VPN installer for this operating system, or check an installed one.

    python products/vpn/packaging/build.py --openssl DIR    Windows: DIR holds libssl-3-x64.dll; macOS: openssl@3's lib folder
    LD_LIBRARY_PATH=DIR python products/vpn/packaging/build.py    Linux: DIR is OpenSSL 3.5's lib folder
    python products/vpn/packaging/build.py smoke PROGRAM     check an installed acxelin-vpn

Writes dist/installers/ (at the repository root): : Acxelin-VPN-VERSION-Setup.exe (Inno Setup), Acxelin-VPN-VERSION.dmg, or acxelin-vpn_VERSION_ARCH.deb.
Needs PyInstaller and the desktop extra; on Windows, Inno Setup 6. The installers are not code-signed."""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from acxelin_vpn import __version__

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DIST, BUILD = ROOT / "dist", ROOT / "build" / "installer"
NAME = "Acxelin VPN"
CHECK = "from acxelin_core import openssl; print(openssl.lib().version)"


def run(*cmd, **kw):
    """Run a step, echoing its output; a failure ends the build with the step's last lines as the reason."""
    print("+", " ".join(map(str, cmd)), flush=True)
    r = subprocess.run([str(c) for c in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", **kw)
    print(r.stdout, flush=True)
    if r.returncode:
        raise SystemExit(f"{Path(str(cmd[0])).name} failed ({r.returncode}): " + " | ".join(r.stdout.strip().splitlines()[-12:]))
    return r


def icon():
    from acxelin_vpn.desktop import image
    BUILD.mkdir(parents=True, exist_ok=True)
    big = image("protected", 1024 if sys.platform == "darwin" else 256)
    if os.name == "nt":
        path = BUILD / "acxelin-vpn.ico"
        big.save(path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    elif sys.platform == "darwin":
        path = BUILD / "acxelin-vpn.icns"
        big.save(path)
    else:
        path = BUILD / "acxelin-vpn.png"
        big.save(path)
    return path


def openssl(folder):
    """The OpenSSL 3.5 libraries to ship, refused unless they really are 3.5 or newer. On macOS they are rewired to load
    each other from inside the app instead of from Homebrew's folder."""
    if not folder:
        return None
    src, out = Path(folder), BUILD / "openssl"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    names = ("libcrypto-3-x64.dll", "libssl-3-x64.dll") if os.name == "nt" else ("libcrypto.3.dylib", "libssl.3.dylib")
    for n in names:
        shutil.copy2(src / n, out / n)
        os.chmod(out / n, 0o644)  # Homebrew's copies are read-only; install_name_tool and codesign need to write
    if sys.platform == "darwin":
        run("install_name_tool", "-id", "@loader_path/libcrypto.3.dylib", out / "libcrypto.3.dylib")
        run("install_name_tool", "-id", "@loader_path/libssl.3.dylib", out / "libssl.3.dylib")
        deps = subprocess.run(["otool", "-L", str(out / "libssl.3.dylib")], capture_output=True, text=True, check=True).stdout
        for line in deps.splitlines()[1:]:
            dep = line.strip().split(" ")[0]
            if dep.endswith("libcrypto.3.dylib"):
                run("install_name_tool", "-change", dep, "@loader_path/libcrypto.3.dylib", out / "libssl.3.dylib")
        for n in names:
            run("codesign", "--force", "--sign", "-", out / n)
    version = subprocess.run([sys.executable, "-c", CHECK], env=os.environ | {"ACXELIN_OPENSSL": str(out)}, capture_output=True, text=True)
    if version.returncode:
        raise SystemExit(f"the OpenSSL in {src} is not usable for post-quantum TLS: {version.stderr.strip()[-400:]}")
    print("bundling", version.stdout.strip(), flush=True)
    return out


def bundle(libs):
    env = os.environ | {"ACXELIN_ICON": str(icon()), "ACXELIN_VERSION": __version__}
    if libs:
        env["ACXELIN_OPENSSL"] = str(libs)
    elif sys.platform.startswith("linux"):
        check = subprocess.run([sys.executable, "-c", CHECK], capture_output=True, text=True)
        if check.returncode:
            raise SystemExit("run this with LD_LIBRARY_PATH pointing at OpenSSL 3.5's lib folder, so the package carries it: "
                             + check.stderr.strip()[-300:])
        print("bundling", check.stdout.strip(), flush=True)
    run(sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", DIST / "bundle", "--workpath", BUILD / "pyinstaller",
        HERE / "acxelin-vpn.spec", env=env)
    return DIST / "bundle"


ISS = r'''#define Version "{version}"
[Setup]
AppId={{{{6B0F3C1E-5A7D-4E2B-9C8A-ACE1A1B00001}}
AppName=Acxelin VPN
AppVersion={{#Version}}
AppPublisher=Acxelin Quantum
AppPublisherURL=https://acxelinquantum.github.io/AQPQCSuite/
DefaultDirName={{autopf}}\Acxelin VPN
DisableProgramGroupPage=yes
OutputDir={out}
OutputBaseFilename=Acxelin-VPN-{{#Version}}-Setup
SetupIconFile={icon}
UninstallDisplayIcon={{app}}\Acxelin VPN.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Tasks]
Name: "startatlogin"; Description: "Show Acxelin VPN in the tray when I log in"
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{bundle}\*"; DestDir: "{{app}}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{{autoprograms}}\Acxelin VPN"; Filename: "{{app}}\Acxelin VPN.exe"
Name: "{{autodesktop}}\Acxelin VPN"; Filename: "{{app}}\Acxelin VPN.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Acxelin VPN"; ValueData: """{{app}}\Acxelin VPN.exe"" desktop --background"; Tasks: startatlogin; Flags: uninsdeletevalue

[Run]
Filename: "{{app}}\Acxelin VPN.exe"; Description: "Open Acxelin VPN"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{{sys}}\taskkill.exe"; Parameters: "/F /IM ""Acxelin VPN.exe"""; Flags: runhidden; RunOnceId: "StopAcxelinVPN"

[Code]
procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and not FileExists(ExpandConstant('{{commonpf64}}\WireGuard\wireguard.exe')) then
    WizardForm.FinishedLabel.Caption := WizardForm.FinishedLabel.Caption + #13#10#13#10 +
      'Acxelin VPN uses WireGuard for the tunnel. Install WireGuard for Windows from https://www.wireguard.com/install/ before you connect.';
end;
'''


def windows(folder, out):
    iscc = shutil.which("iscc") or next((str(p) for p in (Path(os.environ.get(v, "")) / "Inno Setup 6" / "ISCC.exe"
                                                          for v in ("PROGRAMFILES(X86)", "PROGRAMFILES")) if p.is_file()), None)
    if not iscc:
        raise SystemExit("Inno Setup 6 is needed to build the Windows installer (choco install innosetup)")
    script = BUILD / "acxelin-vpn.iss"
    script.write_text(ISS.format(version=__version__, out=out, icon=BUILD / "acxelin-vpn.ico", bundle=folder / NAME), encoding="utf-8")
    run(iscc, "/Q", script)
    return out / f"Acxelin-VPN-{__version__}-Setup.exe"


def macos(folder, out):
    stage = BUILD / "dmg"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    run("ditto", folder / f"{NAME}.app", stage / f"{NAME}.app")
    (stage / "Applications").symlink_to("/Applications")
    dmg = out / f"Acxelin-VPN-{__version__}.dmg"
    dmg.unlink(missing_ok=True)
    run("hdiutil", "create", "-volname", NAME, "-srcfolder", stage, "-ov", "-format", "UDZO", dmg)
    return dmg


def linux(folder, out):
    arch = subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True, check=True).stdout.strip()
    stage = BUILD / "deb"
    shutil.rmtree(stage, ignore_errors=True)
    app = stage / "opt" / "acxelin-vpn"
    shutil.copytree(folder / NAME, app, symlinks=True)
    (stage / "usr" / "bin").mkdir(parents=True)
    (stage / "usr" / "bin" / "acxelin-vpn").symlink_to("/opt/acxelin-vpn/acxelin-vpn")
    icons = stage / "usr" / "share" / "icons" / "hicolor" / "256x256" / "apps"
    icons.mkdir(parents=True)
    shutil.copy2(BUILD / "acxelin-vpn.png", icons / "acxelin-vpn.png")
    apps = stage / "usr" / "share" / "applications"
    apps.mkdir(parents=True)
    (apps / "acxelin-vpn.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=Acxelin VPN\nComment=Post-quantum VPN: connect, and see whether this computer is protected\n"
        'Exec="/opt/acxelin-vpn/Acxelin VPN"\nIcon=acxelin-vpn\nTerminal=false\nCategories=Network;Security;\n', encoding="utf-8")
    (stage / "DEBIAN").mkdir()
    size = sum(f.stat().st_size for f in stage.rglob("*") if f.is_file() and not f.is_symlink()) // 1024
    (stage / "DEBIAN" / "control").write_text(
        f"Package: acxelin-vpn\nVersion: {__version__}\nArchitecture: {arch}\nMaintainer: Acxelin Quantum <noreply@acxelin.example>\n"
        f"Installed-Size: {size}\nDepends: wireguard-tools, pkexec | policykit-1\nSection: net\nPriority: optional\n"
        "Homepage: https://acxelinquantum.github.io/AQPQCSuite/\nDescription: Acxelin VPN, the post-quantum VPN client\n"
        " A tray icon that shows whether this computer is protected, and a window to join from an\n"
        " invitation file, connect and disconnect. OpenSSL 3.5 is included.\n", encoding="utf-8")
    deb = out / f"acxelin-vpn_{__version__}_{arch}.deb"
    run("dpkg-deb", "--root-owner-group", "--build", stage, deb)
    return deb


def smoke(program):
    """An installed package works: post-quantum TLS loads from the OpenSSL inside it, and its VPN service starts, answers on
    its loopback API, and stops when asked."""
    from acxelin_vpn import app, desktop
    doctor = subprocess.run([program, "doctor", "--json"], capture_output=True, text=True, timeout=180)
    try:
        report = json.loads(doctor.stdout)
    except ValueError:
        raise SystemExit(f"{program} doctor --json gave no report ({doctor.returncode}): {(doctor.stdout + doctor.stderr)[-1500:]}") from None
    tls = [c for c in report["checks"] if c["product"] == "key agreement"]
    if not tls or tls[0]["level"] != "ok":
        raise SystemExit(f"post-quantum TLS is not available in the package: {tls}")
    print("key agreement:", tls[0]["message"], flush=True)
    with tempfile.TemporaryDirectory() as d:
        session = Path(d) / "wg0.desktop.json"
        port = desktop.free_port()
        session.write_text(json.dumps({"port": port, "token": "smoke-test-key-0123456789abcdef"}))
        service = subprocess.Popen([program, "app", "--no-apply", "--no-browser", "--session", str(session), "--folder", d])
        try:
            for _ in range(120):
                try:
                    state = app.request(port, "smoke-test-key-0123456789abcdef", "GET", "/api/state")
                    break
                except OSError:
                    time.sleep(0.5)
            else:
                raise SystemExit("the packaged VPN service did not answer: " + (Path(d) / "wg0.service.log").read_text(errors="replace")[-2000:])
            print("service:", state["status"]["state"], flush=True)
            app.request(port, "smoke-test-key-0123456789abcdef", "POST", "/api/quit")
            service.wait(60)
        finally:
            if service.poll() is None:
                service.kill()
    if service.returncode:
        raise SystemExit(f"the packaged VPN service exited with {service.returncode}")
    print("smoke test passed", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("action", nargs="?", choices=("build", "smoke"), default="build")
    ap.add_argument("program", nargs="?", help="smoke: the installed acxelin-vpn program")
    ap.add_argument("--openssl", help="Windows/macOS: the folder with OpenSSL 3.5's libraries to bundle")
    a = ap.parse_args()
    if a.action == "smoke":
        return smoke(a.program)
    out = DIST / "installers"
    out.mkdir(parents=True, exist_ok=True)
    folder = bundle(openssl(a.openssl))
    made = windows(folder, out) if os.name == "nt" else macos(folder, out) if sys.platform == "darwin" else linux(folder, out)
    print(f"built {made} ({made.stat().st_size // (1 << 20)} MB) for {platform.system()} {platform.machine()}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (SystemExit, Exception) as e:
        reason = e.code if isinstance(e, SystemExit) else f"{e.__class__.__name__}: {e}"
        if reason not in (None, 0) and os.environ.get("GITHUB_ACTIONS") == "true":  # the reason, where CI shows it
            print("::error title=Acxelin VPN installer::" + str(reason).replace("%", "%25").replace("\r", "").replace("\n", "%0A"), flush=True)
        raise
