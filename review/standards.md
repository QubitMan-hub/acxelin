# Standards status

Read from official sources on 2026-10-31: the IETF datatracker and RFC Editor, NIST CSRC and NVLPubs, and the OpenSSL 3.5.9
source and binary. Nothing here is from memory or from trade press. One source could not be read (see the end).

## What each standard is today

| Item | State | Source |
|---|---|---|
| Hybrid ML-KEM groups in TLS 1.3 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) | **RFC 10024, Standards Track, August 2026.** Code points 0x11EC (X25519MLKEM768), 0x11EB (SecP256r1MLKEM768), 0x11ED (SecP384r1MLKEM1024) | rfc-editor.org/rfc/rfc10024.txt; datatracker state "RFC Published" |
| Hybrid key exchange design for TLS 1.3 | **RFC 9954, Informational, July 2026** | rfc-editor.org/rfc/rfc9954.txt |
| Pure ML-KEM in TLS 1.3 (`draft-ietf-tls-mlkem`, rev 11) | Approved, in the RFC Editor queue; no RFC number yet | datatracker.ietf.org, state "RFC Ed Queue" |
| ML-DSA signatures in TLS 1.3 (`draft-ietf-tls-mldsa`, rev 06) | Approved, in the RFC Editor queue | datatracker.ietf.org, state "RFC Ed Queue" |
| ML-DSA in X.509 certificates and CRLs | **RFC 9881, Standards Track, October 2025.** Pure ML-DSA only | rfc-editor.org/rfc/rfc9881.txt |
| IKEv2 multiple key exchanges | **RFC 9370, Standards Track, May 2023** | rfc-editor.org/rfc/rfc9370.txt |
| IKEv2 post-quantum preshared keys | **RFC 8784, Standards Track, June 2020** | rfc-editor.org/rfc/rfc8784.txt |
| ML-KEM in IKEv2 (`draft-ietf-ipsecme-ikev2-mlkem`, rev 09) | Approved, in the RFC Editor queue | datatracker.ietf.org, state "RFC Ed Queue" |
| ML-DSA authentication in IKEv2 (`draft-ietf-ipsecme-ikev2-pqc-auth`, rev 12) | Approved, in the RFC Editor queue | datatracker.ietf.org, state "RFC Ed Queue" |
| FIPS 203, 204, 205 | Final, published August 13, 2024 | csrc.nist.gov/pubs/fips/203/final, `/204/final`, `/205/final` |
| NIST IR 8547, Transition to Post-Quantum Cryptography Standards | **Final, published October 2026** (history entry 10/27/26). NIST "will deprecate quantum-vulnerable public-key cryptography after 2030 and disallow its use under NIST standards and guidelines after 2035". Federal high-value and high-impact systems: post-quantum key establishment by December 31, 2030 and signatures by December 31, 2031 (from the report, citing EO 14412 and OMB M-26-15) | csrc.nist.gov/pubs/ir/8547/final; nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf |

What this changes for us:

- The hybrid TLS groups our TLS and VPN products offer are now an RFC with fixed code points, so the earlier statement that
  we implement a draft that could still change is **out of date for the hybrids**. The pure ML-KEM groups (`MLKEM768`,
  `MLKEM1024`, used by the `cnsa2` policy) and ML-DSA in TLS have approved drafts waiting for RFC numbers. Approved drafts
  can still get editorial changes in the queue, but the IANA actions are done. Re-read each when it publishes.
- The IKEv2 ML-DSA authentication draft is approved, so the limit "IKE does not sign with ML-DSA certificates" is a
  strongSwan limit (6.1 cannot load them, `products/vpn/deploy/mldsa_ike_check.py`), not a missing standard. Revisit it
  when strongSwan ships support.
- Readiness's `nist-ir-8547` dates (deprecated after 2030, disallowed after 2035) match the final report's wording.
- RFC 10024 says: "For all groups, the server MUST perform the encapsulation key check described in Section 7.2 of
  [NIST-FIPS-203] on the client's encapsulation key and abort with an illegal_parameter alert if it fails."

## Does OpenSSL 3.5 perform that check?

At the library level, yes:

- **Source** (openssl-3.5.9, `crypto/ml_kem/ml_kem.c`): `ossl_ml_kem_parse_public_key` decodes the coefficient vector with
  `vector_decode_12` → `scalar_decode_12`, which sets `outOfRange` when a coefficient is `>= kPrime` (3329); the parse then
  fails. That is the FIPS 203 section 7.2 modulus check.
- **Behaviour** (3.5.9 built from the hash-pinned tarball): an ML-KEM-768 public key with its first coefficient set to 4095
  is refused (`openssl pkey -pubin` fails to load it); the unmodified key loads.
- **Not tested**: that the TLS 1.3 server aborts with `illegal_parameter` when a hybrid ClientHello carries such a key share.
  The library rejects the key, but this was not shown end to end. Readiness already builds raw ClientHellos
  (`detectors/probe.py`), which is the starting point for that test.

Repeat the library check on any machine with OpenSSL 3.5 (Linux shell):

```bash
openssl genpkey -algorithm ML-KEM-768 -out k.pem
openssl pkey -in k.pem -pubout -outform DER -out ok.der
python3 -c "d=bytearray(open('ok.der','rb').read()); o=len(d)-1184; d[o]=0xff; d[o+1]|=0x0f; open('bad.der','wb').write(d)"
openssl pkey -pubin -inform DER -in ok.der -noout && echo accepted
openssl pkey -pubin -inform DER -in bad.der -noout; echo "exit=$?"
```

## FIPS 140-3 validation

No product here is FIPS validated, and none claims to be. CMVP, read from csrc.nist.gov:

- Validated modules: certificate **4985**, "OpenSSL FIPS Provider", The OpenSSL Project, FIPS 140-3, Software, Active,
  validated 03/11/2025, sunset 3/10/2030. The certificate page text I read does not name the OpenSSL version it covers, so
  **I have not established that it covers any 3.5 release**, and our products load whatever OpenSSL the customer provides,
  not necessarily a FIPS provider.
- The modules-in-process page I read lists vendor modules based on the OpenSSL FIPS provider (Canonical, Oracle, Red Hat, and
  others) and no module from The OpenSSL Project or OpenSSL Corporation. A page I read is not proof of absence.
- Rule for wording: "implements FIPS 203/204/205 algorithms" is accurate; anything that says validated, certified or compliant
  is not.

## Not read: CNSA 2.0

`www.nsa.gov` and `media.defense.gov` answered HTTP 403 from this environment, with the same request that reached the
other hosts. I did not try to get around it. So the CNSA 2.0 milestone dates and algorithm list are **unverified**. Readiness's
`cnsa-2.0` policy and the `cnsa2` profiles name ML-KEM-1024, ML-DSA-87 and AES-256; check them against NSA's CNSA 2.0
advisory and FAQ before quoting dates anywhere. To read it yourself: the CNSA 2.0 FAQ PDF on media.defense.gov and the
NSA cybersecurity advisory page for CNSA 2.0.
