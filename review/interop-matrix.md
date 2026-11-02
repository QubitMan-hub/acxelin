# Interop: what talks to Acxelin, and what was checked against an independent implementation

Rerun: `python products/tls/tests/interop/matrix.py --write review/interop-matrix.md` (TLS), `python -m pytest products/vpn/tests/test_exporter_interop.py` (VPN keys).
The CI job `interop` (Debian 13, system OpenSSL 3.5) is set to run the matrix on every push and fail if a cell differs from what the peer's library predicts; **it has not run on GitHub yet**.

**This copy was produced in the development container, not in CI.** Node, curl and nginx there load the OpenSSL 3.5.9 that `LD_LIBRARY_PATH` points to (the
rows say which library each one actually ran on), so they behave like OpenSSL 3.5 peers; on a machine where they run on OpenSSL 3.0 they are classical peers and their
`strict` cells are `refused`. The CI job's own run is the one to quote.

## VPN key derivation against Go's crypto/tls

For the VPN, interoperability is the keys: the WireGuard pre-shared key and the IPsec keys come from the TLS exporter (RFC 8446 section 7.5, labels
`EXPORTER-pqcsuite-wireguard-v1` and `EXPORTER-pqcsuite-ipsec-v1`, with the pinned context). `products/vpn/tests/test_exporter_interop.py` connects the Acxelin client to a Go server and
compares the exported bytes: both labels, with their real contexts, match. A mutation that ignores the context made the comparison fail. Not covered: a second *VPN*
implementation (strongSwan or a WireGuard peer) - those need root, a kernel and two machines, which the outage drill covers.

## TLS matrix

Generated 2026-10-31 22:54 UTC by `products/tls/tests/interop/matrix.py` on linux, Python 3.13.18, OpenSSL via acxelin-core. A cell reads `pass, <group negotiated>` or `refused`; `!=` marks a cell that differs from what the peer's library predicts.

## Real clients against the Acxelin TLS edge

| Client | strict | transition | cnsa2 |
|---|---|---|---|
| openssl s_client 3.5.9, default groups | pass, X25519MLKEM768 | pass, X25519MLKEM768 | refused |
| openssl s_client 3.5.9, -groups SecP384r1MLKEM1024 | pass, SecP384r1MLKEM1024 | pass, SecP384r1MLKEM1024 | pass, SecP384r1MLKEM1024 |
| node v22.23.4 (OpenSSL 3.5.9) | pass, X25519MLKEM768 | pass, X25519MLKEM768 | refused |
| curl 8.5 (OpenSSL 3.5.9) | pass, X25519MLKEM768 | pass, X25519MLKEM768 | refused |
| go 1.24.7 | refused | pass, X25519MLKEM768 | refused |

## The Acxelin client against real servers

| Server | strict | transition | cnsa2 |
|---|---|---|---|
| openssl s_server 3.5.9, ML-DSA-87 certificate | pass, X25519MLKEM768 | pass, X25519MLKEM768 | pass, SecP384r1MLKEM1024 |
| go 1.24.7 server, ECDSA certificate | refused | pass, X25519MLKEM768 | refused |
| nginx 1.24 (OpenSSL 3.5.9) server, ECDSA certificate | refused | pass, X25519MLKEM768 | refused |

## How to read it

- `strict` needs a post-quantum key exchange and ML-DSA certificates: only peers on OpenSSL 3.5+ can pass. `transition` serves everyone, post-quantum where the peer can, with a classical fallback certificate. `cnsa2` needs SecP384r1MLKEM1024 or MLKEM1024 and an ML-DSA-87 certificate, which no default client offers.
- The group in the edge rows is read from the edge's own counters. The group in the server rows is what the Acxelin client reports for the connection.
- Not covered: Chromium/BoringSSL, strongSwan and WireGuard peers (IPsec needs root and a second machine), and any peer not installed here.
