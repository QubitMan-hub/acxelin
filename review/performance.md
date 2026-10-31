# Performance (measured, reproducible, with its limits)

Rerun everything: `python tools/perf.py --runs 3 --json perf.json --markdown perf.md` (about four minutes; `--quick` is a smoke profile). Compare with an earlier run on the same
machine: `python tools/perf.py --compare perf.json --threshold 15` (add `--fail-over` to make a regression an exit status; it is off by default because shared CI machines are noisy).
The GitHub workflow `performance` runs it on demand (`workflow_dispatch`) and writes the table to the job summary.

PRODUCT.md says no benchmarks may be shown on public pages. These numbers are for the review pack and for regression tracking, not for the website.

## What this run says (development container, one session)

- A server certificate signed with ML-DSA-65 costs about 18% of handshake throughput against an ECDSA P-256 certificate, with the same ML-KEM key exchange (550 against 669 handshakes a second; median
  handshake 2.9 ms against 1.9 ms).
- ML-KEM-768 hybrid against plain X25519, both with ECDSA, is about 3% (669 against 689 a second; 1.9 ms against 1.7 ms).
- Issuing a certificate: 162 a second for ML-DSA-65 and 132 for ML-DSA-87, from a CA holding a few hundred certificates. An earlier run that issued 1,000 per timing measured 111 a second, which is
  consistent with `index.json` being rewritten in full on every issue (the cost grows with the number of certificates the CA holds). That cause was **not isolated**; the first thing to measure
  before anyone relies on the CA for tens of thousands of certificates.
- Signing a CRL with 20,000 revoked entries takes 0.88 s; checking one serial against it takes 39 ms the first time (the CRL is parsed and its signature verified) and 0.76 ms once it is cached.
- A key agreement from a laptop to the gateway takes a median 8 ms on the same machine (no network latency, WireGuard stubbed).

## What it does not say

- Nothing about a production machine, a network, many cores, or hardware acceleration. The client and the server share four virtual CPUs, so the rates are a floor.
- Each rate has three samples, each latency percentile one: the min and max columns show the spread, and two runs a few minutes apart differed by more than 10% in places (signing the 20,000-entry CRL took 705 ms in one and 880 ms in the other). Treat a difference under about 15% as noise.
- WireGuard throughput, IPsec throughput and tunnel rekey times need two machines and are not measured here (that is the outage drill's machinery).
- Memory is the peak of one scan process (imports included); nothing was measured for the TLS edge's memory under load.
- Readiness is timed on its 84-file labelled corpus only. It says nothing about a repository of a million files.

## The run

Measured 2026-10-31T23:16:47+00:00 at commit 0298f79 on Intel(R) Xeon(R) Processor @ 2.10GHz (4 cores), Linux 6.18.44-fc-v185, Python 3.13.18, OpenSSL 3.5.9 29 Sep 2026; 3 run(s) per rate. Load average at start: (1.3984375, 0.9775390625, 0.5859375).

These numbers describe this machine on this day. They are not a claim about any other machine, and the client and server share the CPU, so rates are a floor.

## ca

| metric | median | min | max | unit | samples |
|---|---|---|---|---|---|
| issue_ml_dsa_65_per_s | 161.6 | 145.7 | 164.1 | 1/s | 3 |
| issue_ml_dsa_87_per_s | 132.4 | 120.6 | 141.3 | 1/s | 3 |
| crl_sign_ms_20000_revoked | 880.3 | 748.8 | 943.2 | ms | 3 |
| crl_check_first_ms | 38.99 | 32.19 | 39.98 | ms | 3 |
| crl_check_cached_us | 758.7 | 627.1 | 796.7 | us | 3 |
| crl_sign_ms_1000_revoked | 17.29 | 12.61 | 18.2 | ms | 3 |

- 200 certificates per timing; the CRL is signed with the CA's ML-DSA-87 key; the last revoked serial is not on the list

## tls

| metric | median | min | max | unit | samples |
|---|---|---|---|---|---|
| handshakes_per_s_mlkem_mldsa | 550.4 | 530 | 557.4 | 1/s | 3 |
| handshake_ms_p50_mlkem_mldsa | 2.942 | 2.942 | 2.942 | ms | 1 |
| handshake_ms_p95_mlkem_mldsa | 4.374 | 4.374 | 4.374 | ms | 1 |
| handshake_ms_p99_mlkem_mldsa | 5.117 | 5.117 | 5.117 | ms | 1 |
| handshakes_per_s_mlkem_ecdsa | 668.6 | 658.2 | 673.4 | 1/s | 3 |
| handshake_ms_p50_mlkem_ecdsa | 1.925 | 1.925 | 1.925 | ms | 1 |
| handshake_ms_p95_mlkem_ecdsa | 2.319 | 2.319 | 2.319 | ms | 1 |
| handshake_ms_p99_mlkem_ecdsa | 3.212 | 3.212 | 3.212 | ms | 1 |
| handshakes_per_s_x25519_ecdsa | 689.4 | 679.4 | 728.2 | 1/s | 3 |
| handshake_ms_p50_x25519_ecdsa | 1.672 | 1.672 | 1.672 | ms | 1 |
| handshake_ms_p95_x25519_ecdsa | 2.388 | 2.388 | 2.388 | ms | 1 |
| handshake_ms_p99_x25519_ecdsa | 5.422 | 5.422 | 5.422 | ms | 1 |
| requests_per_s_kept_alive_mlkem_mldsa | 6485 | 6228 | 6688 | 1/s | 3 |

- mlkem_mldsa: negotiated X25519MLKEM768, MLDSA65PublicKey
- mlkem_ecdsa: negotiated X25519MLKEM768, ECPublicKey
- x25519_ecdsa: negotiated x25519, ECPublicKey
- 5 s per rate sample, 8 client threads sharing the machine with the edge and the backend; latency from 200 sequential handshakes (one sample per percentile)

## vpn

| metric | median | min | max | unit | samples |
|---|---|---|---|---|---|
| key_agreement_ms_p50 | 7.765 | 7.765 | 7.765 | ms | 1 |
| key_agreement_ms_p95 | 10.28 | 10.28 | 10.28 | ms | 1 |
| key_agreement_ms_p99 | 11.06 | 11.06 | 11.06 | ms | 1 |

- 100 sequential agreements from one laptop to a gateway on the same machine (TLS handshake, one JSON line each way, key export); WireGuard itself is a stand-in

## readiness

| metric | median | min | max | unit | samples |
|---|---|---|---|---|---|
| corpus_scan_s | 0.2248 | 0.1808 | 0.2637 | s | 3 |
| corpus_files_per_s | 373.7 | 318.5 | 464.6 | 1/s | 3 |
| scan_peak_rss_mb | 40.89 | 40.89 | 40.91 | MB | 3 |

- the labelled quality-gate corpus (84 files) in a fresh process each time; the clock starts after the imports; peak memory is the whole process (imports included), read from VmHWM on Linux

