"""Every systemd unit the products ship stays sandboxed: no new privileges, an explicit capability set, and an exposure score of
at most 4.0 from `systemd-analyze security` (0 is fully locked down, 10 is none). strongSwan's own daemon is upstream's unit."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UNITS = [p for p in sorted(ROOT.glob("products/*/deploy/systemd/*.service")) if p.name != "strongswan-pqc.service"]


@pytest.mark.parametrize("unit", UNITS, ids=lambda p: p.name)
def test_each_unit_keeps_only_what_its_service_needs(unit):
    text = unit.read_text()
    assert "NoNewPrivileges=yes" in text and "CapabilityBoundingSet=" in text and "SystemCallFilter=" in text and "UMask=0077" in text
    if not shutil.which("systemd-analyze"):
        pytest.skip("systemd-analyze is not installed")
    out = subprocess.run(["systemd-analyze", "security", "--offline=true", str(unit)], capture_output=True, text=True).stdout
    score = float(out.rsplit("exposure level for", 1)[1].split(":")[1].split()[0])
    assert score <= 4.0, f"{unit.name} scores {score}"
