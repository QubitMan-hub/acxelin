"""The SBOM that ships with each release, and the offline check a customer runs on a downloaded release.

Both tools are stdlib-only: a customer's machine may have nothing else installed.
"""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

TOOLS = Path(__file__).resolve().parents[1]
SCHEMAS = Path(__file__).resolve().parents[2] / "products/readiness/tests/fixtures/cyclonedx"
sys.path.insert(0, str(TOOLS))

import sbom  # noqa: E402
import verify_release  # noqa: E402


def wheel(folder, name, version, requires=(), license_="MIT", tag="py3-none-any"):
    path = folder / f"{name}-{version}-{tag}.whl"
    meta = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}", *([f"License-Expression: {license_}"] if license_ else []),
            *(f"Requires-Dist: {r}" for r in requires)]
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{name}-{version}.dist-info/METADATA", "\n".join(meta) + "\n")
    return path


@pytest.fixture
def house(tmp_path):
    folder = tmp_path / "acxelin-tls-1.0.3-wheelhouse"
    folder.mkdir()
    wheel(folder, "acxelin_core", "1.1.1", ["cryptography>=45"], license_="LicenseRef-Proprietary")
    wheel(folder, "acxelin_tls", "1.0.3", ["acxelin-core>=1.1.1,<2", "tomli>=2; python_version < '3.11'"], license_="LicenseRef-Proprietary")
    wheel(folder, "cryptography", "46.0.1", ["cffi>=2"], license_="Apache-2.0 OR BSD-3-Clause", tag="cp311-abi3-manylinux2014_x86_64")
    wheel(folder, "cryptography", "46.0.1", ["cffi>=2"], license_="Apache-2.0 OR BSD-3-Clause", tag="cp311-abi3-win_amd64")
    wheel(folder, "cffi", "2.0.0", [], license_=None, tag="cp313-cp313-manylinux2014_x86_64")
    return folder


def problems(bom):
    load = lambda n: json.loads((SCHEMAS / n).read_text(encoding="utf-8"))
    registry = Registry().with_resources([(s["$id"], Resource.from_contents(s)) for s in map(load, ("spdx.schema.json", "jsf-0.82.schema.json"))])
    return [e.message[:200] for e in jsonschema.Draft7Validator(load("bom-1.6.schema.json"), registry=registry).iter_errors(bom)]


def test_the_sbom_is_valid_cyclonedx_1_6(house):
    assert problems(sbom.generate(house, "tls", "1.0.3")) == []


def test_every_wheel_is_listed_with_the_sha256_of_its_bytes(house):
    bom = sbom.generate(house, "tls", "1.0.3")
    listed = {c["properties"][0]["value"]: c["hashes"][0]["content"] for c in bom["components"]}
    assert listed == {w.name: hashlib.sha256(w.read_bytes()).hexdigest() for w in house.glob("*.whl")}


def test_the_product_is_the_subject_and_its_dependencies_are_edges(house):
    bom = sbom.generate(house, "tls", "1.0.3")
    assert bom["metadata"]["component"]["purl"] == "pkg:pypi/acxelin-tls@1.0.3"
    edges = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    names = {c["bom-ref"]: c["name"] for c in bom["components"]}
    assert sorted({names[r] for r in edges[bom["metadata"]["component"]["bom-ref"]]}) == ["acxelin-core"], "an environment-marked dependency not in the folder is not an edge"
    core = next(r for r, n in names.items() if n == "acxelin-core")
    assert sorted({names[r] for r in edges[core]}) == ["cryptography"]


def test_licences_are_reported_as_given_and_missing_ones_are_not_invented(house):
    bom = sbom.generate(house, "tls", "1.0.3")
    by = {c["properties"][0]["value"]: c for c in bom["components"]}
    assert by["cryptography-46.0.1-cp311-abi3-win_amd64.whl"]["licenses"] == [{"expression": "Apache-2.0 OR BSD-3-Clause"}]
    assert "licenses" not in by["cffi-2.0.0-cp313-cp313-manylinux2014_x86_64.whl"]


def test_the_same_folder_gives_the_same_bytes(house):
    assert sbom.dumps(sbom.generate(house, "tls", "1.0.3")) == sbom.dumps(sbom.generate(house, "tls", "1.0.3"))


def test_a_wheel_without_metadata_is_refused_not_skipped(house):
    with zipfile.ZipFile(house / "broken-1.0-py3-none-any.whl", "w") as z:
        z.writestr("x.txt", "nothing")
    with pytest.raises(ValueError, match="broken-1.0-py3-none-any.whl"):
        sbom.generate(house, "tls", "1.0.3")


def sums(folder):
    files = sorted(p for p in folder.rglob("*") if p.is_file())
    (folder.parent / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {folder.name}/{p.relative_to(folder).as_posix()}\n" for p in files),
                                              encoding="utf-8")
    return folder.parent / "SHA256SUMS"


def test_an_untouched_release_verifies(house):
    assert verify_release.verify(sums(house), house.parent) == []


def test_a_changed_file_is_named(house):
    s = sums(house)
    (house / "cffi-2.0.0-cp313-cp313-manylinux2014_x86_64.whl").write_bytes(b"swapped")
    assert any("cffi-2.0.0" in p and "does not match" in p for p in verify_release.verify(s, house.parent))


def test_a_missing_file_is_named(house):
    s = sums(house)
    (house / "acxelin_tls-1.0.3-py3-none-any.whl").unlink()
    assert any("acxelin_tls" in p and "missing" in p for p in verify_release.verify(s, house.parent))


def test_a_file_that_is_not_in_the_list_is_reported(house):
    s = sums(house)
    wheel(house, "extra", "1.0")
    assert any("extra-1.0" in p and "not listed" in p for p in verify_release.verify(s, house.parent))


def test_a_path_that_climbs_out_of_the_release_is_refused(tmp_path):
    (tmp_path / "rel").mkdir()
    (tmp_path / "outside.txt").write_text("x")
    s = tmp_path / "rel" / "SHA256SUMS"
    s.write_text(f"{hashlib.sha256(b'x').hexdigest()}  ../outside.txt\n")
    assert any("outside the release" in p for p in verify_release.verify(s, tmp_path / "rel"))


def test_a_damaged_checksum_line_is_reported(tmp_path):
    s = tmp_path / "SHA256SUMS"
    s.write_text("not a checksum line\n")
    assert verify_release.verify(s, tmp_path)


ROOT = Path(__file__).resolve().parents[2]


def test_the_release_workflow_ships_and_attests_the_sbom_and_the_checksums():
    text = (ROOT / ".github/workflows/release-products.yml").read_text(encoding="utf-8")
    for needed in ("tools/sbom.py", "tools/verify_release.py", "verify-a-release.md", "acxelin-*.cdx.json", "SHA256SUMS\n"):
        assert needed in text, f"release-products.yml does not mention {needed!r}"
    attest = text[text.index("attest-build-provenance"):text.index("GitHub release")]
    assert "SHA256SUMS" in attest and "cdx.json" in attest, "the checksums and the SBOM are attested, not only the tarball"
    assert text.count("cdx.json\" --") >= 2, "both the create and the rebuild-in-place paths upload the SBOM"


def test_the_customer_guide_names_only_commands_and_files_that_exist():
    guide = (ROOT / "documents/verify-a-release.md").read_text(encoding="utf-8")
    assert (ROOT / "tools/verify_release.py").is_file() and "verify_release.py" in guide
    assert "gh attestation verify" in guide and "--owner AcxelinQuantum" in guide
    for manual in ("tls", "vpn", "readiness"):
        assert "--owner AcxelinQuantum" in (ROOT / f"products/{manual}/docs/manual.md").read_text(encoding="utf-8"), "same owner as the manuals say"
    assert "info@acxelinquantum.com" in guide and "info@acxelinquantum.com" in (ROOT / "SECURITY.md").read_text(encoding="utf-8")
