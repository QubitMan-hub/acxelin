"""QUIC and IKEv2 in captures: what each side offered and agreed, read from the handshake packets only."""

import pcapgen
import pytest

from acxelin_readiness.detectors import capture, quic


def scan(tmp_path, frames):
    f = tmp_path / "c.pcap"
    f.write_bytes(pcapgen.pcap(frames))
    return capture.scan(f)


def test_initial_keys_follow_rfc_9001_appendix_a():
    dcid = bytes.fromhex("8394c8f03e515708")
    assert [k.hex() for k in quic.keys(dcid, "client")] == ["1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"]
    assert [k.hex() for k in quic.keys(dcid, "server")] == ["cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314"]


def test_a_quic_handshake_split_over_two_initial_packets_shows_its_hybrid_group(tmp_path):
    sights, eps, notes = scan(tmp_path, pcapgen.quic_capture([0x11EC, 0x001D], 0x11EC))
    (ep,) = eps
    assert ep["kind"] == "quic" and ep["groups"] == ["X25519MLKEM768"] and ep["pq_groups"] == ["X25519MLKEM768"]
    assert ep["sni"] == ["quic.example"] and ep["clients_offering_pq"] == 1 and ep["target"].startswith("pcap://c.pcap/quic/")
    assert ("X25519MLKEM768", "key-exchange") in {(s.algo, s.params.get("role")) for s in sights}


def test_a_classical_quic_handshake_is_reported_as_classical(tmp_path):
    sights, eps, _ = scan(tmp_path, pcapgen.quic_capture([0x001D], 0x001D, split=False))
    assert eps[0]["groups"] == ["X25519"] and eps[0]["pq_groups"] == [] and eps[0]["clients_offering_pq"] == 0


def test_a_quic_packet_that_does_not_decrypt_is_skipped(tmp_path):
    frames = pcapgen.quic_capture([0x001D], 0x001D, split=False)
    damaged = bytearray(frames[0])
    damaged[-5] ^= 0xFF
    sights, eps, _ = scan(tmp_path, [bytes(damaged)] + frames[1:])
    assert eps == [] or eps[0]["clients_offering_pq"] == 0


HYBRID = [(1, 20, 256), (2, 5, None), (4, 31, None), (6, 36, None)]  # AES-GCM-16-256, PRF SHA2-256, X25519 + ML-KEM-768


@pytest.mark.parametrize("port", [500, 4500])
def test_an_ikev2_exchange_with_an_ml_kem_additional_key_exchange_is_hybrid(tmp_path, port):
    sights, eps, _ = scan(tmp_path, pcapgen.ike_capture(HYBRID, 31, HYBRID, 31, port))
    (ep,) = eps
    assert ep["kind"] == "ike" and ep["version"] == "IKEv2" and ep["pq_groups"] == ["ML-KEM-768"] and ep["clients_offering_pq"] == 1
    seen = {(s.algo, tuple(sorted((k, v) for k, v in s.params.items() if k in ("key_size", "mode", "hash", "curve")))) for s in sights}
    assert ("ML-KEM-768", ()) in seen and ("X25519", ()) in seen
    assert ("AES", (("key_size", 256), ("mode", "GCM"))) in seen and ("HMAC", (("hash", "SHA-256"),)) in seen


def test_an_ikev2_exchange_that_settles_on_legacy_choices_says_so(tmp_path):
    offer = HYBRID + [(1, 3, None), (2, 2, None), (3, 2, None), (4, 2, None)]
    sights, eps, _ = scan(tmp_path, pcapgen.ike_capture(offer, 31, [(1, 3, None), (2, 2, None), (3, 2, None), (4, 2, None)], 2))
    algos = {(s.algo, s.params.get("key_size")) for s in sights}
    assert {("3DES", None), ("DH", 1024)} <= algos and any(s.algo == "HMAC" and s.params.get("hash") == "SHA-1" for s in sights)
    assert eps[0]["pq_groups"] == [] and eps[0]["clients_offering_pq"] == 1, "the client offered ML-KEM; the server chose classical"


def test_cut_off_ike_and_quic_packets_never_end_the_scan(tmp_path):
    frames = pcapgen.ike_capture(HYBRID, 31, HYBRID, 31) + pcapgen.quic_capture([0x11EC], 0x11EC)
    sights, eps, notes = scan(tmp_path, [f[:60] for f in frames])
    assert isinstance(eps, list)
