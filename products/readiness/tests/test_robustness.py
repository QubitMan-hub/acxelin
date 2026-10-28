"""One odd file never ends a scan: deep Python, malformed manifests and cut-off captures are skipped with the rest still scanned."""
from pathlib import Path

import pytest

from acxelin_readiness import pipeline, workspace
from acxelin_readiness.detectors import capture
from acxelin_readiness.detectors.deps import parse_manifest

PCAPS = sorted((Path(__file__).parent / "fixtures/pcap").glob("*.pcap"))


@pytest.mark.parametrize("deep", ["x = " + " if c else ".join(["a"] * 7000) + "\n", "y = " + "-" * 7000 + "1\n", "z = " + "(" * 5000 + ")" * 5000 + "\n"])
def test_a_python_file_too_deep_to_parse_does_not_stop_the_scan(tmp_path, deep):
    (tmp_path / "deep.py").write_text(deep)
    (tmp_path / "legacy.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    assert "MD5" in {a["name"] for a in workspace.scan(tmp_path)["assets"]}


@pytest.mark.parametrize("name,text", [
    ("package.json", "[1,2]"), ("package.json", '{"dependencies": ["node-forge"]}'), ("package.json", '"x"'),
    ("pyproject.toml", '[tool.poetry]\ndependencies = ["x"]\n'), ("pyproject.toml", "[project]\ndependencies = [{a=1}]\n"),
    ("pyproject.toml", "project = 1\n"), ("Cargo.toml", "[dependencies]\nopenssl = 5\n"), ("Cargo.toml", "dependencies = 3\n"),
])
def test_a_malformed_manifest_is_skipped(name, text):
    out = []
    parse_manifest(Path(name), name, text, out)
    assert isinstance(out, list)


def test_well_formed_manifests_still_name_their_libraries():
    out = []
    parse_manifest(Path("pyproject.toml"), "pyproject.toml", '[project]\ndependencies = ["cryptography>=43", {a=1}]\n', out)
    parse_manifest(Path("Cargo.toml"), "Cargo.toml", '[dependencies]\nring = "0.17"\nopenssl = {version = "0.10"}\nodd = 5\n', out)
    assert {lib.name for lib in out} >= {"cryptography", "ring", "openssl"}


@pytest.mark.parametrize("pcap", PCAPS, ids=[p.name for p in PCAPS])
def test_a_cut_off_or_damaged_capture_is_read_as_far_as_it_goes(pcap):
    capture.scan(pcap)


def test_a_scan_with_damaged_captures_still_reports_the_code(tmp_path):
    (tmp_path / "legacy.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    r = pipeline.run(tmp_path, "p", captures=[str(p) for p in PCAPS])
    assert any(a.algo == "MD5" for a in r.assets)


def test_a_long_dotted_line_is_scanned_in_linear_time(tmp_path):
    import time
    (tmp_path / "Gen.java").write_text("class Gen { String s = " + "a." * 20000 + "a; }\n")
    start = time.monotonic()
    workspace.scan(tmp_path)
    assert time.monotonic() - start < 5
