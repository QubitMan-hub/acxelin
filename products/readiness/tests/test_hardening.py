"""Inputs that broke the command line in review: hostile git refs, other tools' CBOMs, odd servers and unwritable paths."""
import datetime as dt
import json
import os
import socket
import struct
import subprocess
import threading
import time

import pytest

from acxelin_readiness import cli, endpoints, evidence, workspace


def git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.email=a@b", "-c", "user.name=a", *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / "a.py").write_text("x = 1\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "1")
    return root


def test_a_ref_that_looks_like_an_option_is_refused_and_writes_nothing(repo, tmp_path):
    with pytest.raises(SystemExit) as e:
        cli.main(["scan", str(repo), "--out", str(tmp_path / "out"), "--quiet", f"--changed-since=--output={tmp_path / 'pwned.txt'}"])
    assert e.value.code != 0 and not (tmp_path / "pwned.txt").exists()


def test_a_changed_file_with_a_non_ascii_name_is_scanned(repo, tmp_path):
    (repo / "café.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "2")
    with pytest.raises(SystemExit) as e:
        cli.main(["scan", str(repo), "--out", str(tmp_path / "out"), "--quiet", "--changed-since", "HEAD~1", "--fail-on", "high"])
    assert e.value.code == 2


def bom(**over):
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "metadata": {"component": {"name": "billing"}},
            "components": [{"type": "cryptographic-asset", "name": "RSA-2048", "cryptoProperties": {"assetType": "algorithm"}}]} | over


@pytest.mark.parametrize("doc", [
    bom(metadata={"tools": [{"name": "other-scanner", "version": "2"}], "component": {"name": "billing"}}),
    bom(components=[{"type": "cryptographic-asset", "name": None, "cryptoProperties": {"assetType": "algorithm"}}]),
    bom(components=[{"type": "cryptographic-asset", "name": 7, "cryptoProperties": {"assetType": "algorithm"}}, "junk"]),
])
def test_other_tools_cboms_merge_without_a_traceback(tmp_path, doc):
    (tmp_path / "x.json").write_text(json.dumps(doc))
    assert cli.main(["merge", str(tmp_path / "x.json"), "-o", str(tmp_path / "inv"), "-q"]) == 0


@pytest.mark.parametrize("text", ["[1, 2]", "{\"bomFormat\": \"CycloneDX\", \"components\": 5}", "not json"])
def test_a_file_that_is_not_a_cbom_is_a_message(tmp_path, text):
    (tmp_path / "x.json").write_text(text)
    with pytest.raises(SystemExit) as e:
        cli.main(["merge", str(tmp_path / "x.json"), "-o", str(tmp_path / "inv"), "-q"])
    assert "x.json" in str(e.value)


def test_old_wolfpack_properties_are_read_with_one_warning_per_file(tmp_path, capsys):
    c = {"type": "cryptographic-asset", "name": "RSA-2048", "cryptoProperties": {"assetType": "algorithm"},
         "properties": [{"name": "wolfpack:tier", "value": "high"}, {"name": "wolfpack:recommendation", "value": "ML-KEM"}]}
    (tmp_path / "old.json").write_text(json.dumps(bom(components=[c])))
    assert cli.main(["merge", str(tmp_path / "old.json"), "-o", str(tmp_path / "inv"), "-q"]) == 0
    err = capsys.readouterr().err
    assert err.count("wolfpack:") == 1 and "old.json" in err
    evidence.code(tmp_path / "old.json")
    assert capsys.readouterr().err.count("wolfpack:") == 1


def test_merging_a_folder_twice_never_counts_its_own_inventory(tmp_path, monkeypatch):
    (tmp_path / "scans/billing").mkdir(parents=True)
    (tmp_path / "scans/billing/cbom.json").write_text(json.dumps(bom()))
    monkeypatch.chdir(tmp_path / "scans")
    for _ in range(2):
        assert cli.main(["merge", ".", "-q"]) == 0
    assert json.loads((tmp_path / "scans/inventory/inventory.json").read_text())["systems"] == 1


def test_a_merge_history_with_odd_rows_is_skipped_and_its_values_escaped(tmp_path):
    (tmp_path / "b.json").write_text(json.dumps(bom()))
    hist = tmp_path / "h.jsonl"
    hist.write_text('[1]\n{"date": "2026-01-01"}\n{"date": "2026-01-02", "systems": 1, "pq_ready_percent": 5, "critical": "<script>x</script>", "high": 0, "breaches": 0}\n')
    assert cli.main(["merge", str(tmp_path / "b.json"), "-o", str(tmp_path / "inv"), "--history", str(hist), "-q"]) == 0
    assert "<script>x" not in (tmp_path / "inv/inventory.html").read_text()


def test_an_ssh_server_announcing_an_empty_packet_is_refused_without_reading_on(monkeypatch):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.sendall(b"SSH-2.0-evil\r\n" + struct.pack(">IB", 0, 0) + b"\0" * 65536)
        time.sleep(3)  # and keep the connection open, as a server feeding data forever would
        c.close()
    threading.Thread(target=serve, daemon=True).start()
    start = time.monotonic()
    with pytest.raises(OSError):
        endpoints.ssh_kexinit("127.0.0.1", srv.getsockname()[1], 5)
    assert time.monotonic() - start < 1.5, "refused at the length, without reading what follows"
    srv.close()


def test_a_certificate_with_a_key_type_this_library_cannot_load_is_still_a_row(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "odd")])
    now = dt.datetime.now(dt.timezone.utc)
    der = bytearray(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
                    .not_valid_before(now).not_valid_after(now + dt.timedelta(days=9)).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    at = der.index(bytes([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]))
    der[at + 8] = 0x7F
    import base64
    (tmp_path / "odd.pem").write_text("-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bytes(der)).decode() + "-----END CERTIFICATE-----\n")
    rows = evidence.certificates(tmp_path)
    assert rows[0]["name"] == "odd" and "1.2.840.10045.2.127" in rows[0]["detail"]


def test_a_workspace_retires_its_oldest_missing_findings_instead_of_locking_up(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace.ProjectStore, "FINDINGS", 30)
    store = workspace.ProjectStore(tmp_path / "w.json")
    asset = lambda f: {"name": "MD5", "algorithm": "MD5", "tier": "high", "test_only": False, "declared": False, "locations": [[f, 1]]}
    for i in range(40):
        store.save(tmp_path, {"project": "p", "finished": float(i), "assets": [asset(f"f{i}.py")], "summary": {}, "notes": []})
    data = store.read()["projects"][store.key(tmp_path)]
    assert len(data["missing"]) == 29 and data["missing"][-1]["locations"] == [["f38.py", 1]]


def test_sarif_locations_are_uri_references(tmp_path):
    from acxelin_readiness import cbom
    from acxelin_readiness.model import Asset, Detection
    d = Detection(algo="MD5", file="dir/a #1%20b.py", line=3, evidence="call", detector="t")
    a = Asset(ref="r", algo="MD5", variant="MD5", params={}, detections=[d], confidence=1, tier="high", why="w", action="x")
    uri = cbom.sarif([a], [], [])["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "dir/a%20%231%2520b.py"


@pytest.mark.parametrize("args", [["grade", "127.0.0.1:1", "--timeout", "1", "--json"], ["grade", "127.0.0.1:1", "--timeout", "1", "--html"]])
def test_an_unwritable_output_is_a_message(tmp_path, args):
    (tmp_path / "file").write_text("")
    with pytest.raises(SystemExit) as e:
        cli.main(args + [str(tmp_path / "file/out")])
    assert "cannot write" in str(e.value)


def test_the_action_does_not_expand_globs_in_its_args(tmp_path):
    from pathlib import Path
    script = (Path(__file__).resolve().parents[1] / "action.yml").read_text().split("run: |\n", 1)[1].split("\n    - ", 1)[0]
    (tmp_path / "b.min.js").write_text("")
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "acxelin-readiness").write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n')
    (fake / "acxelin-readiness").chmod(0o755)
    # a Windows drive letter has a colon, so the folders are joined with the system's separator and Git Bash keeps its own tools
    path = os.pathsep.join([str(fake), os.environ["PATH"]]) if os.name == "nt" else f"{fake}:/usr/bin:/bin"
    env = ({k: v for k, v in os.environ.items() if k != "PATH"} if os.name == "nt" else {}) | {
        "PATH": path, "SCAN_PATH": ".", "OUT": "out", "ARGS": "--exclude *.min.js", "GITHUB_OUTPUT": str(tmp_path / "o"), "CAPTURE": str(tmp_path / "argv")}
    subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=True)
    assert (tmp_path / "argv").read_text().split("\n")[-3:-1] == ["--exclude", "*.min.js"]


def test_the_windows_installer_writes_its_wrapper_in_the_console_code_page():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "install.ps1").read_text()
    assert "-Encoding ASCII" not in text, "a user name such as José would become Jos? in the wrapper's path"
