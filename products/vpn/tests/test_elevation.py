"""Nothing the VPN starts with administrator rights loads code that an ordinary user can change."""
import os
import sys
from unittest import mock

import pytest

os.environ.setdefault("PYSTRAY_BACKEND", "dummy")
pytest.importorskip("pystray", reason="needs the desktop extra")

from acxelin_vpn import desktop, platforms  # noqa: E402

posix = pytest.mark.skipif(os.name == "nt", reason="the unsafe folder is made with POSIX mode bits")


@pytest.fixture
def user_writable(tmp_path, monkeypatch):
    """An interpreter and an import path in a folder anyone can write: what a per-user install looks like to root."""
    folder = tmp_path / "home" / "ada" / ".acxelin" / "vpn"
    folder.mkdir(parents=True)
    folder.chmod(0o777)
    python = folder / "python"
    python.write_text("")
    monkeypatch.setattr(sys, "executable", str(python))
    monkeypatch.setattr(sys, "path", [str(folder)])
    monkeypatch.delattr(sys, "frozen", raising=False)
    return folder


@posix
def test_an_interpreter_or_import_folder_that_users_can_write_is_named_as_the_problem(user_writable):
    why = platforms.elevation_problem()
    assert why and str(user_writable) in why


@posix
def test_the_tray_will_not_start_the_service_with_administrator_rights_from_such_code(user_writable):
    with mock.patch.object(sys, "platform", "linux"), mock.patch("shutil.which", return_value="/usr/bin/pkexec"), \
            mock.patch("acxelin_vpn.join.administrator", return_value=False), mock.patch.object(desktop.subprocess, "Popen") as popen:
        with pytest.raises(ValueError, match="ordinary user.*install"):
            desktop.start_service([sys.executable, "-m", "acxelin_vpn", "app"], True)
    popen.assert_not_called()


@posix
def test_the_same_refusal_covers_the_macos_prompt(user_writable):
    with mock.patch.object(sys, "platform", "darwin"), mock.patch("acxelin_vpn.join.administrator", return_value=False), \
            mock.patch.object(desktop.subprocess, "Popen") as popen:
        with pytest.raises(ValueError, match="ordinary user"):
            desktop.start_service([sys.executable, "-m", "acxelin_vpn", "app"], True)
    popen.assert_not_called()


def test_the_windows_prompt_is_never_shown_for_code_that_users_can_change():
    import ctypes
    shell = mock.Mock()
    with mock.patch.object(desktop.os, "name", "nt"), mock.patch.object(ctypes, "windll", mock.Mock(shell32=shell), create=True), \
            mock.patch("acxelin_vpn.join.administrator", return_value=False), \
            mock.patch.object(platforms, "elevation_problem", return_value="C:/Users/ada/py is not inside Program Files"):
        with pytest.raises(ValueError, match="ordinary user"):
            desktop.start_service(["C:/Users/ada/py/pythonw.exe", "-m", "acxelin_vpn", "app"], True)
    shell.ShellExecuteW.assert_not_called()


def test_a_person_who_is_already_an_administrator_is_not_asked_again_or_blocked():
    with mock.patch("acxelin_vpn.join.administrator", return_value=True), mock.patch.object(desktop.subprocess, "Popen") as popen, \
            mock.patch.object(platforms, "elevation_problem", return_value="unsafe"):
        desktop.start_service([sys.executable, "-m", "acxelin_vpn", "app"], True)
    popen.assert_called_once()


def test_nothing_of_the_users_import_path_or_environment_reaches_the_elevated_process():
    command = [sys.executable, "-m", "acxelin_vpn", "app", "--folder", "/home/ada/vpn"]
    with mock.patch.object(sys, "platform", "linux"), mock.patch("shutil.which", return_value="/usr/bin/pkexec"), \
            mock.patch.object(sys, "frozen", False, create=True):
        linux = desktop.elevated(command)
    assert linux == ["pkexec", sys.executable, "-I", "-m", "acxelin_vpn", "app", "--folder", "/home/ada/vpn"]
    with mock.patch.object(sys, "platform", "darwin"), mock.patch.object(sys, "frozen", False, create=True):
        assert " -I -m acxelin_vpn " in desktop.elevated(command)[2]
    assert "PYTHONPATH" not in " ".join(linux)


def test_a_packaged_app_is_started_as_it_is_and_only_its_own_program_is_checked():
    seen = []
    with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(sys, "path", ["/home/ada/anything"]), \
            mock.patch.object(platforms, "protected_location", lambda paths, **k: seen.append(list(paths))):
        assert platforms.elevation_problem() is None
        with mock.patch.object(sys, "platform", "linux"), mock.patch("shutil.which", return_value="/usr/bin/pkexec"):
            assert desktop.elevated([sys.executable, "app"]) == ["pkexec", sys.executable, "app"]
    assert seen == [[sys.executable]]


@posix
def test_installing_the_boot_service_refuses_user_writable_code_and_writes_and_runs_nothing(user_writable, tmp_path):
    unit = tmp_path / "etc" / "acxelin-vpn.service"
    calls = []
    with mock.patch.object(platforms, "service", return_value=(unit, "[Unit]\n", [["systemctl", "enable"]], [])):
        with pytest.raises(ValueError, match="ordinary user.*install"):
            platforms.install([sys.executable, "-m", "acxelin_vpn", "connect", "gw:7443"], runner=calls.append)
    assert calls == [] and not unit.exists()


def test_the_interpreter_the_service_will_run_is_checked_even_when_it_is_not_this_one():
    flag = lambda paths, **k: next((f"{p} is writable" for p in paths if "unsafe" in str(p)), None)
    with mock.patch.object(platforms, "protected_location", flag), mock.patch.object(sys, "frozen", False, create=True):
        assert "unsafe/python" in platforms.elevation_problem("/unsafe/python")
        assert platforms.elevation_problem("/usr/bin/python3") is None


def test_the_boot_units_that_run_as_root_start_programs_under_opt():
    from pathlib import Path
    folder = Path(__file__).resolve().parents[1] / "deploy" / "systemd"
    for unit in folder.glob("*.service"):
        text = unit.read_text(encoding="utf-8")
        run = next(line for line in text.splitlines() if line.startswith("ExecStart="))
        user = next((line.split("=", 1)[1] for line in text.splitlines() if line.startswith("User=")), "root")
        assert user != "root" or run.split("=", 1)[1].startswith("/opt/"), f"{unit.name} runs as root from {run}"



@posix
def test_on_a_mac_the_refusal_says_applications_is_not_safe_and_what_to_do(user_writable):
    with mock.patch.object(sys, "platform", "darwin"):
        with pytest.raises(ValueError, match=r"Applications.*any administrator.*sudo acxelin-vpn app"):
            platforms.require_protected_code("Starting the VPN service from the tray")


def fake_protection(paths, **k):
    return next((f"{p} can be changed by users" for p in paths if "unsafe" in str(p)), None)


def test_an_openssl_folder_that_users_can_write_is_refused_because_the_elevated_process_would_load_it(monkeypatch):
    monkeypatch.setenv("ACXELIN_OPENSSL", "/home/ada/unsafe-openssl")
    with mock.patch.object(platforms, "protected_location", fake_protection), mock.patch.object(sys, "frozen", False, create=True):
        assert "unsafe-openssl" in platforms.elevation_problem("/usr/bin/python3")
    monkeypatch.setenv("ACXELIN_OPENSSL", "/opt/openssl/lib")
    with mock.patch.object(platforms, "protected_location", fake_protection), mock.patch.object(sys, "frozen", False, create=True):
        assert platforms.elevation_problem("/usr/bin/python3") is None


def test_on_windows_openssl_must_come_from_a_named_folder_not_from_path(monkeypatch):
    monkeypatch.delenv("ACXELIN_OPENSSL", raising=False)
    with mock.patch.object(platforms.os, "name", "nt"), mock.patch.object(platforms, "protected_location", fake_protection):
        assert "PATH" in platforms.elevation_problem("C:/Program Files/Acxelin VPN/acxelin-vpn.exe")
        monkeypatch.setenv("ACXELIN_OPENSSL", "C:/Program Files/Acxelin VPN/openssl")
        assert platforms.elevation_problem("C:/Program Files/Acxelin VPN/acxelin-vpn.exe") is None


def test_the_packaged_launcher_replaces_a_planted_openssl_folder_instead_of_keeping_it():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "packaging" / "launcher.py").read_text(encoding="utf-8")
    assert 'os.environ["ACXELIN_OPENSSL"] = str(bundled)' in text and "setdefault" not in text


def test_the_windows_boot_script_lives_in_program_files_not_in_program_data(monkeypatch):
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    path = platforms.service([r"C:\Program Files\Acxelin VPN\acxelin-vpn.exe", "connect"], "Windows")[0]
    assert path.parts[0] == r"C:\Program Files" and "ProgramData" not in str(path)


def test_the_interpreter_of_the_boot_service_is_isolated_and_a_packaged_app_is_left_alone():
    with mock.patch.object(sys, "frozen", False, create=True):
        assert platforms.isolated(["/usr/bin/python3", "-m", "acxelin_vpn", "connect"]) == ["/usr/bin/python3", "-I", "-m", "acxelin_vpn", "connect"]
    with mock.patch.object(sys, "frozen", True, create=True):
        assert platforms.isolated(["/opt/acxelin-vpn/acxelin-vpn", "connect"]) == ["/opt/acxelin-vpn/acxelin-vpn", "connect"]


def test_the_install_command_hands_the_boot_service_an_isolated_interpreter(tmp_path):
    import contextlib
    import io

    from acxelin_vpn import cli
    device = tmp_path / "device"
    device.mkdir()
    (device / "key.pem").write_text("not encrypted\n")
    out = io.StringIO()
    with mock.patch("acxelin_vpn.platforms.install", return_value=tmp_path / "unit") as install, mock.patch("acxelin_vpn.wireguard.Client"), \
            mock.patch.object(sys, "frozen", False, create=True), contextlib.redirect_stdout(out), pytest.raises(SystemExit):
        cli.main(["install", "gw.example:7443", "--cert-dir", str(device)])
    argv = install.call_args.args[0]
    assert argv[:3] == [sys.executable, "-I", "-m"]
