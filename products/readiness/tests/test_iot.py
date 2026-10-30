"""IoT and industrial protocols: TLS endpoints written as mqtts://, amqps://, ldaps:// and the like get their protocol's port; CoAP
over DTLS is pointed at a packet capture; OPC UA security policies in code and configuration are read as the algorithms they use."""
import json

import pytest

from acxelin_readiness import cli, endpoints
from acxelin_readiness.detectors import tls
from acxelin_readiness.detectors.suites import opcua_policy


@pytest.mark.parametrize("target,port", [("mqtts://broker.example", 8883), ("amqps://mq.example", 5671), ("ldaps://dc.example", 636),
                                         ("imaps://mail.example", 993), ("smtps://mail.example", 465), ("https://web.example/path", 443),
                                         ("mqtts://broker.example:9883", 9883), ("broker.example", 443)])
def test_a_tls_protocols_scheme_gives_its_port(target, port):
    assert endpoints.endpoint(target) == ("tls", target.split("://")[-1].split("/")[0].split(":")[0], port)
    assert tls._split(target, 443)[1] == port


def test_coap_over_dtls_is_sent_to_a_packet_capture_instead():
    for read in (lambda: endpoints.endpoint("coaps://sensor.example"), lambda: tls._split("coaps://sensor.example", 443)):
        with pytest.raises(ValueError, match="--pcap"):
            read()


@pytest.mark.parametrize("policy,expected", [
    ("Basic128Rsa15", {("RSA", "pkcs1v15"), ("SHA-1", None), ("AES", 128)}),
    ("Basic256", {("RSA", "oaep"), ("SHA-1", None), ("AES", 256)}),
    ("Basic256Sha256", {("RSA", "pkcs1v15"), ("SHA-256", None), ("AES", 256)}),
    ("Aes256_Sha256_RsaPss", {("RSA", "pss"), ("SHA-256", None), ("AES", 256)}),
    ("ECC_nistP384", {("ECDSA", "P-384"), ("ECDH", "P-384"), ("SHA-384", None), ("AES", 256)}),
    ("ECC_curve25519", {("Ed25519", None), ("X25519", None)}),
])
def test_an_opc_ua_security_policy_names_the_algorithms_it_uses(policy, expected):
    got = {(a, p.get("padding") or p.get("curve") or p.get("key_size")) for a, p in opcua_policy(policy)}
    assert got == expected
    assert opcua_policy("http://opcfoundation.org/UA/SecurityPolicy#" + policy) == opcua_policy(policy)
    assert opcua_policy("None") == [] and opcua_policy("Basic512") == []


def test_opc_ua_policies_in_code_and_configuration_are_found_and_ranked(tmp_path):
    (tmp_path / "plc.py").write_text('POLICY = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"\nclient.set_security_string(POLICY)\n')
    (tmp_path / "server.yaml").write_text("opcua:\n  securityPolicy: Basic256Sha256\n")
    (tmp_path / "server.xml").write_text("<SecurityPolicyUri>http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256</SecurityPolicyUri>\n")
    assert cli.main(["scan", str(tmp_path), "-o", str(tmp_path / "out"), "-q"]) == 0
    found = {}
    for c in json.loads((tmp_path / "out/cbom.json").read_text())["components"]:
        if c.get("type") == "cryptographic-asset":
            tier = {p["name"]: p["value"] for p in c.get("properties", [])}.get("acxelin:tier")
            for o in c["evidence"]["occurrences"]:
                found.setdefault(o["location"].split("/")[-1], {})[c["name"]] = tier
    assert found["plc.py"].get("SHA-1") in ("critical", "high") and "RSA" in "".join(found["plc.py"])
    assert any(n.startswith("RSA") for n in found["server.yaml"]) and any(n.startswith("ECDSA") for n in found["server.xml"])
