"""An evidence bundle is a zip whose manifest lists every file with its SHA-256, optionally signed with an ML-DSA key whose
certificate chains to the customer's CA. Verifying never unpacks it. Every change after signing is caught, a private key never
goes in, and a crafted zip cannot reach outside it."""
import io
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from acxelin_core import evidence
from acxelin_core.pki import CA, key_pem


@pytest.fixture
def pki(tmp_path):
    ca = CA.init(tmp_path / "pki", "Evidence Root")
    ca.issue("auditor.acme", "client", out=tmp_path / "signer")
    other = CA.init(tmp_path / "other", "Another Root")
    other.issue("auditor.acme", "client", out=tmp_path / "stranger")
    return tmp_path


def signer(d, who="signer"):
    return evidence.Signer.load(d / who / "chain.pem", d / who / "key.pem")


PARTS = {"build.json": {"product": "acxelin-test", "version": "1.0"}, "config.toml": "listen = \"127.0.0.1:443\"\n"}


def make(d, parts=PARTS, sign=True):
    return evidence.create("acxelin-test", parts, signer(d) if sign else None)


def rezip(data, change):
    """The bundle's entries after `change(entries)`, written back into a zip."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        entries = {n: z.read(n) for n in z.namelist()}
    change(entries)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for n, b in entries.items():
            z.writestr(n, b)
    return out.getvalue()


def test_a_signed_bundle_verifies_against_its_ca(pki):
    data = make(pki)
    r = evidence.verify(data, (pki / "pki" / "ca.crt").read_bytes())
    assert r["ok"], r["problems"]
    assert r["signed_by"].startswith("CN=auditor.acme") and r["product"] == "acxelin-test"
    assert set(r["files"]) == {"build.json", "config.toml"}
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("manifest.json"))
    assert manifest["format"] == evidence.FORMAT and len(manifest["files"]["config.toml"]) == 64


@pytest.mark.parametrize("change,says", [
    (lambda e: e.update({"config.toml": e["config.toml"].replace(b"443", b"8443")}), "config.toml"),
    (lambda e: e.update({"extra.txt": b"added later"}), "extra.txt"),
    (lambda e: e.pop("build.json"), "build.json"),
])
def test_any_change_after_signing_is_caught(pki, change, says):
    r = evidence.verify(rezip(make(pki), change), (pki / "pki" / "ca.crt").read_bytes())
    assert not r["ok"] and any(says in p for p in r["problems"]), r


def test_a_manifest_rewritten_to_match_a_changed_file_breaks_the_signature(pki):
    def forge(e):
        e["config.toml"] = b"listen = \"0.0.0.0:443\"\n"
        m = json.loads(e["manifest.json"])
        m["files"]["config.toml"] = evidence.sha256(e["config.toml"])
        e["manifest.json"] = json.dumps(m).encode()
    r = evidence.verify(rezip(make(pki), forge), (pki / "pki" / "ca.crt").read_bytes())
    assert not r["ok"] and any("signature" in p for p in r["problems"]), r


def test_a_signer_from_another_ca_is_refused(pki):
    data = evidence.create("acxelin-test", PARTS, signer(pki, "stranger"))
    r = evidence.verify(data, (pki / "pki" / "ca.crt").read_bytes())
    assert not r["ok"] and any("does not chain" in p for p in r["problems"]), r


def test_an_unsigned_bundle_fails_when_a_ca_is_given_and_says_so_without_one(pki):
    data = make(pki, sign=False)
    assert not evidence.verify(data, (pki / "pki" / "ca.crt").read_bytes())["ok"]
    r = evidence.verify(data)
    assert r["ok"] and r["signed_by"] is None and any("not signed" in n for n in r["notes"]), r


def test_stripping_the_signature_from_a_signed_bundle_is_caught_when_a_ca_is_given(pki):
    stripped = rezip(make(pki), lambda e: [e.pop(n) for n in ("manifest.sig", "signer.pem")])
    assert not evidence.verify(stripped, (pki / "pki" / "ca.crt").read_bytes())["ok"]


def test_a_private_key_never_goes_into_a_bundle(pki):
    key = (pki / "signer" / "key.pem").read_text()
    for part in ({"notes.txt": key}, {"status.json": {"leak": key}}, {"raw.bin": key.encode()}):
        with pytest.raises(ValueError, match="private key"):
            evidence.create("acxelin-test", part, None)


def test_only_ml_dsa_keys_sign_bundles(pki):
    classical = pki / "ec.pem"
    classical.write_bytes(key_pem(ec.generate_private_key(ec.SECP384R1())))
    with pytest.raises(ValueError, match="ML-DSA"):
        evidence.Signer.load(pki / "signer" / "chain.pem", classical)


@pytest.mark.parametrize("name", ["../escape.txt", "/etc/passwd", "a/b.txt", "C:\\x.txt", ""])
def test_unsafe_names_are_refused_when_making_and_when_checking(pki, name):
    with pytest.raises(ValueError, match="name"):
        evidence.create("acxelin-test", {name: "x"}, None)
    if not name:  # Python 3.11's zipfile cannot write an entry with an empty name, so there is no such bundle to check
        return
    r = evidence.verify(rezip(make(pki, sign=False), lambda e: e.update({name: b"x"})))
    assert not r["ok"] and any("name" in p for p in r["problems"]), r


def test_an_oversized_bundle_is_refused_before_it_is_read(pki, monkeypatch):
    monkeypatch.setattr(evidence, "LIMIT", 1000)
    big = rezip(make(pki, sign=False), lambda e: e.update({"build.json": b"x" * 5000}))
    r = evidence.verify(big)
    assert not r["ok"] and any("too large" in p for p in r["problems"]), r


def test_not_a_zip_is_a_clear_problem():
    r = evidence.verify(b"this is not a zip")
    assert not r["ok"] and r["problems"] == ["not an evidence bundle: not a zip file"]


def fake_dist(root, files):
    """An installed distribution in `root`: its files and a RECORD with their hashes as a wheel writes them."""
    import base64
    import hashlib
    info = root / "demo-1.0.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
    rows = []
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
        digest = base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).rstrip(b"=").decode()
        rows.append(f"{name},sha256={digest},{len(text)}")
    (info / "RECORD").write_text("\n".join(rows + ["demo-1.0.dist-info/RECORD,,"]) + "\n")
    from importlib.metadata import PathDistribution
    return PathDistribution(info)


def test_installed_files_are_checked_against_the_wheels_record(tmp_path):
    dist = fake_dist(tmp_path, {"demo/__init__.py": "x = 1\n", "demo/core.py": "y = 2\n"})
    r = evidence.installed(dist)
    assert (r["name"], r["version"], r["files"], r["modified"], r["missing"]) == ("demo", "1.0", 2, [], [])
    (tmp_path / "demo/core.py").write_text("y = 3  # patched on the server\n")
    (tmp_path / "demo/__init__.py").unlink()
    r = evidence.installed(dist)
    assert r["modified"] == ["demo/core.py"] and r["missing"] == ["demo/__init__.py"]


def test_the_environment_names_python_the_platform_and_openssl():
    env = evidence.environment()
    assert env["python"] and env["platform"] and "openssl" in env


def test_a_bundle_written_to_disk_verifies_from_disk(pki):
    out = pki / "out" / "evidence.zip"
    evidence.write(out, make(pki))
    assert evidence.verify(Path(out).read_bytes(), (pki / "pki" / "ca.crt").read_bytes())["ok"]
