"""Another tool's CBOM, named the way CycloneDX's own published examples name things: each gets the priority its algorithm earns."""
import json

import pytest

from acxelin_readiness import workspace


def rate(tmp_path, *components, tools=None):
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"tools": tools} if tools else {},
           "components": [{"type": "cryptographic-asset", "name": n, "cryptoProperties": {"assetType": kind}} for n, kind in components]}
    (tmp_path / "bom.json").write_text(json.dumps(bom))
    r = workspace.imported(tmp_path / "bom.json", "x")
    return {a["name"]: a["tier"] for a in r["assets"]}, r["notes"][0]


@pytest.mark.parametrize("name,tier", [("RSA-PKCS1-1.5-SHA512-2048", "high"), ("RSA-PKCS1-1.5-SHA256-1024", "critical"), ("RSA-1024", "critical"),
                                       ("AES-256-GCM", "ok"), ("AES-128-GCM-128-12", "low"), ("SHA512withRSA", "high"), ("MD5withRSA", "critical"),
                                       ("SHA-384", "ok"), ("ML-KEM-1024", "ok")])
def test_names_from_cyclonedx_examples_get_the_priority_their_algorithm_earns(tmp_path, name, tier):
    assert rate(tmp_path, (name, "algorithm"))[0] == {name: tier}


def test_a_known_protocol_is_rated_and_a_tool_without_a_name_is_called_another_tool(tmp_path):
    tiers, note = rate(tmp_path, ("TLSv1.2", "protocol"), ("TLSv1.0", "protocol"), ("google.com", "certificate"), ("my-protocol", "protocol"))
    assert tiers == {"TLSv1.0": "critical", "TLSv1.2": "high"} and note.startswith("Imported from another tool")
    assert rate(tmp_path, ("SHA-256", "algorithm"), tools={"components": [{"name": "cbomkit", "version": "1.2"}]})[1].startswith("Imported from cbomkit 1.2")
