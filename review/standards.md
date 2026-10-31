# Standards status

Only official sources count here: the IETF datatracker and RFC Editor, NIST CSRC, NSA, and the library's own source.
Nothing below is taken from memory or from trade press.

## Checked

### Does OpenSSL 3.5 perform the FIPS 203 encapsulation-key check?

`draft-ietf-tls-ecdhe-mlkem` revision 05 is reported to add a requirement that the server perform the check in FIPS 203
section 7.2 on the client's encapsulation key. (That description comes from a search summary of the draft's change list, not
from a page this pack could read: see "Not checked".) What the library does, from its source and behaviour:

- **Source** (openssl-3.5.9, `crypto/ml_kem/ml_kem.c`): `ossl_ml_kem_parse_public_key` decodes the 12-bit coefficient vector
  with `vector_decode_12`, which calls `scalar_decode_12`; that function sets `outOfRange` when a coefficient is `>= kPrime`
  (3329) and the parse fails. That is the FIPS 203 section 7.2 modulus check. The public key's hash is stored with the key.
- **Behaviour**, OpenSSL 3.5.9 built from the tarball whose SHA-256 the workflows pin: an ML-KEM-768 public key whose first
  coefficient was set to 4095 is refused (`openssl pkey -pubin` fails to load it), and the unmodified key loads.
- **Not tested**: that the TLS 1.3 server path rejects a hybrid ClientHello carrying such a key share. The library-level
  rejection is the same function the TLS code calls to import the share, but this pack did not craft such a ClientHello.
  `products/readiness` already builds raw ClientHellos (`detectors/probe.py`), which is the starting point for that test.

How to repeat the behavioural check on any machine with OpenSSL 3.5 (Linux shell):

```bash
openssl genpkey -algorithm ML-KEM-768 -out k.pem
openssl pkey -in k.pem -pubout -outform DER -out ok.der
python3 -c "d=bytearray(open('ok.der','rb').read()); o=len(d)-1184; d[o]=0xff; d[o+1]|=0x0f; open('bad.der','wb').write(d)"
openssl pkey -pubin -inform DER -in ok.der -noout && echo accepted
openssl pkey -pubin -inform DER -in bad.der -noout; echo "exit=$?"
```

### FIPS

No product here claims FIPS validation. The OpenSSL 3.5 FIPS provider's CMVP status was not read from NIST's list. Until it
is, any wording that implies validation is wrong; the repository's text should keep saying "FIPS 203/204 algorithms", never
"FIPS validated".

## Not checked: the session's network policy blocked the official hosts

The environment this pack was written in could not reach `datatracker.ietf.org`, `www.rfc-editor.org`, `csrc.nist.gov` or
`www.nsa.gov`. These items are therefore **unverified** and must be read from the source before anyone relies on them:

| Item | Where to read it | What matters to us |
|---|---|---|
| `draft-ietf-tls-ecdhe-mlkem` state and latest revision | datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/ | The code points for X25519MLKEM768 and the other hybrids; whether they can still change |
| Pure ML-KEM and ML-DSA in TLS 1.3 | datatracker.ietf.org/doc/draft-ietf-tls-mlkem/ and the TLS ML-DSA draft | Our policies name `MLKEM1024` and ML-DSA signature schemes |
| ML-DSA in X.509 | rfc-editor.org/info/rfc9881 | Our CA's certificate and CRL format |
| IKEv2: RFC 9370, RFC 8784, ML-KEM and ML-DSA drafts | rfc-editor.org and datatracker.ietf.org/wg/ipsecme/ | The VPN's IKE profile and the PPK |
| NIST IR 8547 (draft or final), FIPS 203/204/205 | csrc.nist.gov/pubs/ir/8547/ | Readiness's `nist-ir-8547` policy dates (2030, 2035) |
| CNSA 2.0 dates | nsa.gov (the CNSA 2.0 advisory and FAQ) | Readiness's `cnsa-2.0` policy and the `cnsa2` profiles |
| OpenSSL FIPS provider validation | csrc.nist.gov CMVP validated and in-process lists | That nothing we ship implies validation |

Unresolved: which of the above are still drafts that could change, and the upgrade path if one does. The code points and the
exporter labels are the two wire facts that must not change under a deployed customer (CLAUDE.md rule 5). The TLS group
names live in one place per product (`policies.py` in TLS and VPN), and the exporter labels are pinned by
`test_agreement::test_labels_and_contexts_are_pinned`, so a code-point change would be a one-file edit plus a changelog entry
and a compatibility window in which both are offered.
