import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_check import FOLDERS, check, parse_tag  # noqa: E402

VERSION = {p: tomllib.loads((FOLDERS[p] / "pyproject.toml").read_text())["project"]["version"] for p in ("core", "tls", "vpn", "readiness")}


def test_tags_name_a_product_and_a_version():
    assert parse_tag("tls-v1.0.0") == ("tls", "1.0.0")
    assert parse_tag("refs/tags/readiness-v1.2.3") == ("readiness", "1.2.3")
    assert parse_tag("vpn-v1.0.0") == ("vpn", "1.0.0")
    for bad in ("v1.0.0", "tls-1.0.0", "storage-v1.0.0", "tls-v1.0", "tls-v1.0.0-rc1;rm"):
        with pytest.raises(ValueError):
            parse_tag(bad)


def test_the_tag_must_match_the_packaged_version_and_the_changelog():
    with pytest.raises(ValueError, match="pyproject"):
        check("tls", "9.9.9", tags=["core-v1.0.0"])


def test_a_product_needs_a_released_core_in_its_range():
    assert check("tls", VERSION["tls"], tags=["core-v1.0.0"]) == "acxelin-core 1.0.0"
    assert check("vpn", VERSION["vpn"], tags=["core-v1.0.0"]) == "acxelin-core 1.0.0"
    with pytest.raises(ValueError, match="no released acxelin-core"):
        check("tls", VERSION["tls"], tags=[])
    with pytest.raises(ValueError, match="no released acxelin-core"):
        check("readiness", VERSION["readiness"], tags=["core-v2.0.0"])


def test_core_releases_need_no_core_tag():
    assert check("core", VERSION["core"], tags=[]) == f"acxelin-core {VERSION['core']}"
