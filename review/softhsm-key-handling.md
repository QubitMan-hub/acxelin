# CA key in a PKCS#11 token (SoftHSM2 tested)

| Claim | Evidence |
|---|---|
| The CA signs certificates and CRLs with an ML-DSA key that lives in the token, and the results verify with standard ML-DSA | `core/tests/test_pkcs11_signer.py::test_a_ca_whose_key_lives_in_the_token_signs_certificates_and_crls` (root self-signature, a leaf, and a CRL with a revoked entry, each verified with `cryptography`) |
| The private key is never written next to the CA and never readable from the token | `core/tests/test_pkcs11_signer.py::test_no_private_key_is_ever_written_where_the_ca_lives` (no `ca.key`, no file containing a private key, no PIN in `signer.json`); `core/tests/test_pkcs11_signer.py::test_the_token_refuses_to_reveal_the_private_key` (the key is made sensitive and not extractable; making it extractable in `generate` fails the test) |
| A corrupted signature is caught | mutation: flipping a bit in what the token returns made three tests fail |
| A wrong PIN is refused in words and is never printed | `core/tests/test_pkcs11_signer.py::test_a_wrong_pin_is_refused_in_words_without_printing_it`; a PIN in the configuration file is refused; the PIN comes from an environment variable only |
| A missing token or key is named | `core/tests/test_pkcs11_signer.py::test_a_token_or_key_that_is_not_there_is_named` |
| A reopened CA signs with the same key | `core/tests/test_pkcs11_signer.py::test_a_ca_reopened_later_signs_with_the_same_key` |
| The command line works end to end | `products/tls/tests/test_pkcs11_cli.py`: `ca init --pkcs11-generate`, then `ca issue`, the leaf verifies |

**Versions.** SoftHSM2 release 2.7.0 (2026-01-20) has no ML-DSA in its `SoftHSM.cpp`; the development branch does (`--enable-mldsa`, OpenSSL 3.5). Ubuntu 24.04 ships 2.6.1, which offers
RSA, DSA, ECDSA and EdDSA only. These tests ran against the development branch at commit `9ad87341c94ffdf1364ecf27b715475e0d80b0dd`, built against OpenSSL 3.5.9. The CI job `pkcs11` builds that commit and fails
(does not skip) if the module is missing.

**Limits.**
- Not run against a hardware HSM, a smart card or a cloud HSM. A real token must offer `CKM_ML_DSA` (PKCS#11 3.2); whether the HSMs a bank owns do is something to ask the vendor. I did not research which do.
- The PKCS#11 structures are laid out for Linux and macOS (8-byte `CK_ULONG`, natural alignment) and, by the rules of the standard, for Windows (4-byte `CK_ULONG`, 1-byte packing). The Windows layout was
  not run.
- One session per token, one signature at a time (a lock). Throughput was not measured; that is the performance stage.
- SoftHSM lists the tokens that exist when the module starts in a process. A token created later in the same process is not seen; the CLI starts a new process per command, so this does not matter there.
- The leaf keys of issued certificates are ordinary files; only the CA key is in the token.
- TLS's new flags need the next core release (they import `acxelin_core.pki.pkcs11`). Raise TLS's `acxelin-core` lower bound when that core is tagged.
