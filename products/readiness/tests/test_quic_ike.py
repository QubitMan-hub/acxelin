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


def test_a_dtls_handshake_split_over_datagrams_is_read_like_tls(tmp_path):
    (tmp_path / "d.pcap").write_bytes(pcapgen.pcap(pcapgen.dtls_capture([0x001D, 0x0017], 0xC02B, group=None)))
    sights, eps, notes = capture.scan(tmp_path / "d.pcap")
    algos = {s.algo for s in sights}
    assert {"TLS 1.2", "ECDH", "ECDSA", "AES"} <= algos and eps[0]["target"] == "pcap://d.pcap/dtls/vpn.example:4433"
    assert eps[0]["version"] == "DTLS 1.2" and "1 handshake(s)" in notes[0]


@pytest.mark.parametrize("exchange", [2, 4])
def test_an_ikev1_main_or_aggressive_mode_exchange_shows_what_the_responder_chose(tmp_path, exchange):
    aes_sha256_modp2048_rsa = [(1, 7), (14, 256), (2, 4), (3, 3), (4, 14)]
    des3_md5_modp1024_psk = [(1, 5), (2, 1), (3, 1), (4, 2)]
    (tmp_path / "v1.pcap").write_bytes(pcapgen.pcap(pcapgen.ikev1_capture([des3_md5_modp1024_psk, aes_sha256_modp2048_rsa], [des3_md5_modp1024_psk], exchange)))
    sights, eps, notes = capture.scan(tmp_path / "v1.pcap")
    found = {(s.algo, s.params.get("key_size") or s.params.get("hash")) for s in sights}
    assert {("3DES", None), ("HMAC", "MD5"), ("DH", 1024)} <= found and ("AES", 256) not in found, "what was chosen, not what was offered"
    assert eps[0]["kind"] == "ike" and "IKEv1" in sights[0].snippet and "1 handshake(s)" in notes[0]
    (tmp_path / "v1.pcap").write_bytes(pcapgen.pcap(pcapgen.ikev1_capture([aes_sha256_modp2048_rsa], [aes_sha256_modp2048_rsa], exchange)))
    found = {(s.algo, s.params.get("key_size") or s.params.get("hash")) for s in capture.scan(tmp_path / "v1.pcap")[0]}
    assert {("AES", 256), ("HMAC", "SHA-256"), ("DH", 2048), ("RSA", None)} <= found


def test_two_sites_on_one_address_stay_apart_by_server_name_and_a_dhe_prime_size_is_read(tmp_path):
    import struct
    c, s = [10, 0, 0, 5], [10, 0, 0, 9]
    dhe = pcapgen._record(12, struct.pack(">H", 128) + b"\xff" * 128 + struct.pack(">H", 1) + b"\x02" + struct.pack(">H", 128) + b"\x01" * 128)
    frames = [pcapgen._eth_ip_tcp(c, s, 50000, 443, 1, pcapgen.client_hello("dh1024.example", [0x001D])),
              pcapgen._eth_ip_tcp(s, c, 443, 50000, 1, pcapgen.server_hello(0x0033, version=0x0303) + dhe),
              pcapgen._eth_ip_tcp(c, s, 50001, 443, 1, pcapgen.client_hello("pq.example", [0x11EC])),
              pcapgen._eth_ip_tcp(s, c, 443, 50001, 1, pcapgen.server_hello(0x1301, group=0x11EC))]
    (tmp_path / "two.pcap").write_bytes(pcapgen.pcap(frames))
    sights, eps, notes = capture.scan(tmp_path / "two.pcap")
    assert sorted(e["target"] for e in eps) == ["pcap://two.pcap/dh1024.example:443", "pcap://two.pcap/pq.example:443"]
    assert any(s.algo == "DH" and s.params.get("key_size") == 1024 and "dh1024" in s.file for s in sights)
    assert not any(s.algo == "X25519MLKEM768" and "dh1024" in s.file for s in sights)


def test_conversations_in_a_protocol_not_recognised_are_named_not_passed_over(tmp_path):
    a, b = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    frames = [pcapgen._eth_ip_udp(a, b, 40000, 29029, b"S29" + bytes(range(200)))] * 3 + [pcapgen._eth_ip_tcp(a, b, 41000, 7000, 1, b"\x01proprietary")]
    (tmp_path / "vendor.pcap").write_bytes(pcapgen.pcap(frames))
    sights, eps, notes = capture.scan(tmp_path / "vendor.pcap")
    assert not sights and not eps
    assert any("2 other conversation(s)" in n and "udp 10.0.0.2:29029" in n and "tcp 10.0.0.2:7000" in n for n in notes), notes
