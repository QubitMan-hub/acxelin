"""Problems found by using Acxelin VPN as a first-time customer would; each test shows the problem fixed."""
import os
import shlex
import subprocess
import sys
from pathlib import Path

from acxelin_vpn import setup


def test_the_printed_next_steps_survive_a_folder_with_spaces(tmp_path):
    folder = tmp_path / "VPN Ops Ünï" / "acxelin-vpn"
    text = setup.next_steps(folder / "gateway.toml", "vpn.acme.example")
    commands = [line.strip() for line in text.splitlines() if line.strip().startswith("acxelin-vpn ")]
    assert len(commands) == 3, text
    for line in commands:
        args = shlex.split(line) if os.name != "nt" else line
        if os.name != "nt":
            paths = [args[i + 1] for i, a in enumerate(args) if a in ("--dir", "--cert", "--key", "--config")]
            assert paths and all(p.startswith(str(folder)) for p in paths), (line, paths)
    assert f"--ca {shlex.quote(str(folder / 'pki'))}" in text.replace("\n", " ") if os.name != "nt" else True


def test_access_without_an_action_shows_who_is_limited(tmp_path):
    conf = Path(__file__).resolve().parents[1] / "config" / "gateway.toml"
    r = subprocess.run([sys.executable, "-m", "acxelin_vpn", "access", "--config", str(conf)], capture_output=True, text=True, timeout=60)
    assert "required" not in r.stderr, r.stderr
    shown = subprocess.run([sys.executable, "-m", "acxelin_vpn", "access", "show", "--config", str(conf)], capture_output=True, text=True, timeout=60)
    assert (r.returncode, r.stdout) == (shown.returncode, shown.stdout), (r.stdout + r.stderr, shown.stdout + shown.stderr)
