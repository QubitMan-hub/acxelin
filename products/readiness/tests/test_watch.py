"""Scheduled scans: `watch` scans again and says what appeared and what disappeared since its last scan, and can run a command when anything changed."""
import json
import sys

from acxelin_readiness import cli

RSA = "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=2048)\n"


def watch(repo, out, *more):
    assert cli.main(["watch", str(repo), "-o", str(out), "--once", *more]) == 0
    return json.loads((out / "changes.json").read_text())


def test_watch_reports_new_and_gone_findings_between_scans(tmp_path):
    repo, out = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    (repo / "keys.py").write_text(RSA)
    first = watch(repo, out)
    assert first["first"] and first["new"] == [] and first["gone"] == []
    (repo / "legacy.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    second = watch(repo, out)
    assert not second["first"] and ["MD5", "legacy.py"] in second["new"] and second["gone"] == []
    (repo / "legacy.py").unlink()
    third = watch(repo, out)
    assert third["new"] == [] and ["MD5", "legacy.py"] in third["gone"]
    assert (out / "cbom.json").exists() and (out / "report.html").exists()


def test_the_change_command_runs_only_when_something_changed_and_is_told_where_the_changes_are(tmp_path):
    repo, out, mark = tmp_path / "repo", tmp_path / "out", tmp_path / "ran.txt"
    repo.mkdir()
    (repo / "keys.py").write_text(RSA)
    command = f'"{sys.executable}" -c "import os,pathlib; pathlib.Path(r\'{mark}\').write_text(os.environ[\'ACXELIN_READINESS_CHANGES\'])"'
    watch(repo, out, "--on-change", command)
    watch(repo, out, "--on-change", command)
    assert not mark.exists()
    (repo / "legacy.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    watch(repo, out, "--on-change", command)
    assert mark.read_text() == str(out / "changes.json")
