"""Upgrade and rollback: the released code and the code in this tree read and extend each other's files.

Each baseline is the commit a released version was built from (tools/baselines.json). Its source is extracted with `git archive` and run
in a separate process, so the old code really is the old code. A CA folder is created by one side, read and extended by the other, then
read by the first again. Needs the full git history (CI checks out with fetch-depth 0); without it these fail, they do not skip.
"""
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name("upgrade_driver.py")
BASELINES = json.loads((ROOT / "tools" / "baselines.json").read_text(encoding="utf-8"))
PRODUCTS = {"core": "core", "tls": "products/tls", "vpn": "products/vpn", "readiness": "products/readiness"}


def extract(commit, folder, into):
    out = subprocess.run(["git", "archive", commit, f"{folder}/src"], cwd=ROOT, capture_output=True)
    if out.returncode:
        pytest.fail(f"cannot read {commit} from git ({out.stderr.decode().strip()}); fetch the full history: git fetch --unshallow")
    into.mkdir(parents=True, exist_ok=True)
    archive = into / "a.tar"
    archive.write_bytes(out.stdout)
    with tarfile.open(archive) as t:
        t.extractall(into, filter="data")
    return into / folder / "src"


def run(paths, *args):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(p) for p in paths))
    r = subprocess.run([sys.executable, str(DRIVER), *map(str, args)], capture_output=True, text=True, env=env, cwd=args[1])
    assert r.returncode == 0, f"{args[0]} failed under {paths[0]}:\n{r.stdout}\n{r.stderr}"
    return json.loads(r.stdout)


@pytest.fixture(scope="module", params=["core-1.1.0", "core-1.0.0"])
def old_core(request, tmp_path_factory):
    return [extract(BASELINES[request.param], "core", tmp_path_factory.mktemp("old"))]


NEW_CORE = [ROOT / "core" / "src"]


def test_a_ca_made_by_the_old_release_is_read_and_extended_by_this_one(old_core, tmp_path):
    made = run(old_core, "create", tmp_path)
    seen = run(NEW_CORE, "inspect", tmp_path)
    assert seen["records"] == made["records"]
    assert seen["verdicts"] == {"good": "accepted", "bad": "refused: revoked"}
    assert seen["crl_number"] == made["crl_number"]
    grown = run(NEW_CORE, "extend", tmp_path)
    assert grown["crl_number"] > made["crl_number"]
    assert grown["verdicts"] == {"good": "accepted", "bad": "refused: revoked", "later": "refused: revoked"}


def test_a_ca_extended_by_this_release_still_works_when_rolled_back(old_core, tmp_path):
    run(old_core, "create", tmp_path)
    grown = run(NEW_CORE, "extend", tmp_path)
    back = run(old_core, "inspect", tmp_path)
    assert back["records"] == grown["records"]
    assert back["verdicts"] == grown["verdicts"]
    again = run(old_core, "extend2", tmp_path)
    assert again["crl_number"] > grown["crl_number"], "a rolled-back CA must never reuse a CRL number"
    assert again["verdicts"]["later"] == "refused: revoked"
    final = run(NEW_CORE, "inspect", tmp_path)
    assert final["records"] == again["records"]


def test_an_old_crl_is_still_enforced_by_this_release(old_core, tmp_path):
    run(old_core, "create", tmp_path)
    assert run(NEW_CORE, "inspect", tmp_path)["verdicts"]["bad"] == "refused: revoked"


def code(paths, source, *args, cwd=None):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(p) for p in paths))
    r = subprocess.run([sys.executable, "-c", source, *map(str, args)], capture_output=True, text=True, env=env, cwd=cwd)
    return r.returncode, r.stdout, r.stderr


def released(product, version, tmp_path_factory):
    """The product and the core built in the same commit as it."""
    base = tmp_path_factory.mktemp(f"old-{product}")
    commit = BASELINES[f"{product}-{version}"]
    return [extract(commit, "core", base), extract(commit, PRODUCTS[product], base)]


def current(product):
    return [ROOT / "core" / "src", ROOT / PRODUCTS[product] / "src"]


EDGE = """
[[edge]]
name = "web"
mode = "terminate"
listen = "0.0.0.0:8443"
target = "127.0.0.1:8080"
policy = "strict"
cert = "{d}/server/cert.pem"
key = "{d}/server/key.pem"
ca = "{d}/ca.crt"
require_client_cert = true
crl = "{d}/crl.pem"
"""
LOAD = "import json, sys\nfrom acxelin_tls.edge import load_config\nr, m = load_config(sys.argv[1])\nprint(json.dumps([vars(x) for x in r]))"


@pytest.fixture(scope="module")
def old_tls(tmp_path_factory):
    return released("tls", "1.0.2", tmp_path_factory)


def test_an_edge_config_written_for_the_old_release_loads_the_same_here(old_tls, tmp_path):
    f = tmp_path / "edge.toml"
    f.write_text(EDGE.format(d=tmp_path.as_posix()), encoding="utf-8")
    rc, before, err = code(old_tls, LOAD, f)
    assert rc == 0, err
    rc, after, err = code(current("tls"), LOAD, f)
    assert rc == 0, err
    old, new = json.loads(before), json.loads(after)
    assert [{k: v for k, v in r.items() if k != "shadow"} for r in new] == old
    assert all(r["shadow"] is False for r in new), "an existing route must not become a shadow route"


def test_relative_paths_in_an_old_config_now_follow_the_file_not_the_working_folder(old_tls, tmp_path):
    """A behaviour change since 1.0.2 (recorded in the TLS CHANGELOG): an edge started from another folder used to look for these files there."""
    f = tmp_path / "edge.toml"
    f.write_text(EDGE.format(d=".").replace('"./', '"'), encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    old = json.loads(code(old_tls, LOAD, f, cwd=elsewhere)[1])[0]
    new = json.loads(code(current("tls"), LOAD, f, cwd=elsewhere)[1])[0]
    assert Path(old["cert"]) == Path("server/cert.pem")
    assert Path(new["cert"]) == tmp_path.resolve() / "server" / "cert.pem"


def test_a_config_using_shadow_is_refused_by_the_old_release_not_silently_ignored(old_tls, tmp_path):
    f = tmp_path / "edge.toml"
    f.write_text(EDGE.format(d=tmp_path.as_posix()) + "shadow = true\n", encoding="utf-8")
    assert code(current("tls"), LOAD, f)[0] == 0
    rc, out, err = code(old_tls, LOAD, f)
    assert rc != 0 and "shadow" in err, "rolling back must stop on the key it does not know, so nobody believes shadow mode is on"


INVITE = {"acxelin_invite": 1, "name": "laptop", "enroll": "https://gw.example:7444/enroll?t=x", "ca_fingerprint": "ab" * 32, "gateway": "gw.example:7443",
          "server_name": "gw.example", "expires": "2030-01-01T00:00:00+00:00"}
READ = "import json, sys\nfrom acxelin_vpn import join\nprint(json.dumps(join.parse(open(sys.argv[1]).read())))"


@pytest.fixture(scope="module")
def old_vpn(tmp_path_factory):
    return released("vpn", "1.0.2", tmp_path_factory)


@pytest.mark.parametrize("extra", [{}, {"keep_minutes": 15}], ids=["as-issued", "with-a-field-from-a-later-release"])
def test_an_invitation_is_read_the_same_by_the_old_and_the_new_release(old_vpn, tmp_path, extra):
    f = tmp_path / "x.acxinvite"
    f.write_text(json.dumps(INVITE | extra), encoding="utf-8")
    seen = []
    for paths in (old_vpn, current("vpn")):
        rc, out, err = code(paths, READ, f)
        assert rc == 0, err
        seen.append(json.loads(out))
    assert seen[0]["gateway"] == seen[1]["gateway"] and seen[0]["ca_fingerprint"] == seen[1]["ca_fingerprint"]


SCAN = [sys.executable, "-m", "acxelin_readiness", "scan"]


def scan(paths, src, out, *more):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(p) for p in paths), NO_COLOR="1")
    return subprocess.run([*SCAN, str(src), "-o", str(out), *more], capture_output=True, text=True, env=env, cwd=src)


@pytest.fixture(scope="module")
def old_readiness(request, tmp_path_factory):
    return released("readiness", request.param, tmp_path_factory)


@pytest.mark.parametrize("old_readiness", ["1.0.2"], indirect=True)
def test_an_old_cbom_is_a_working_baseline_for_this_release_and_back(old_readiness, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n"
                              "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\nhashlib.md5(b'x')\n", encoding="utf-8")
    first = scan(old_readiness, src, tmp_path / "old")
    assert first.returncode == 0, first.stderr
    new_on_old = scan(current("readiness"), src, tmp_path / "new", "--baseline", tmp_path / "old" / "cbom.json", "--fail-on", "high")
    assert new_on_old.returncode == 0, "nothing changed, so nothing is new:\n" + new_on_old.stdout + new_on_old.stderr
    assert scan(current("readiness"), src, tmp_path / "bare", "--fail-on", "high").returncode != 0, "the gate itself works without a baseline"
    old_on_new = scan(old_readiness, src, tmp_path / "back", "--baseline", tmp_path / "new" / "cbom.json", "--fail-on", "high")
    assert old_on_new.returncode == 0, "rolled back, the new CBOM still works as a baseline:\n" + old_on_new.stdout + old_on_new.stderr
