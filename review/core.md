# acxelin-core

Mechanisms only, no product policy. Every product imports it; it imports no product (`core/tests/test_acxelin_core.py::test_core_imports_no_product_and_loads_no_openssl_on_import`).

## Data flow

```
admin ──CLI/console──> CA (core/pki) ──signs──> leaf certificates, CRLs        (files under the CA folder)
                         │  signer: key file | SLH-DSA via OpenSSL | AWS KMS | external command
enrolling machine ──TLS 1.3 PQ-only──> EST service ──> CA.sign          (one-time token, or mutual TLS to renew)
ACME client ───────HTTP or TLS 1.3───> ACME service ──> CA.sign          (TLS-only variant lives in products/tls)
CRL publisher ──HTTP──> follow_crl on an edge/gateway ──> verified copy on disk ──> Revocation checks in Server
```

## Trust boundaries

| Boundary | What crosses | Enforced by |
|---|---|---|
| Network → EST | CSRs, tokens, client certificates | PQ-only TLS profile; tokens are single-use and bound to one name |
| Network → console | HTTP on loopback only | Host and Origin checks, single-use launch ticket, session token in `sessionStorage`, lockout |
| Downloaded CRL → disk | A CRL from a URL | Only a CRL signed by the issuing CA, unexpired and newer than the kept copy replaces it |
| CA process → signer | TBS bytes | In-process key, OpenSSL, KMS API, or an external command (stdin/stdout) |
| Host loader → OpenSSL | The library file | `ACXELIN_OPENSSL`, then `PATH` on Windows (an attacker who can write there wins) |

## Keys: where they are made, kept, used and destroyed

| Key or secret | Created | Stored | Used | Destroyed | Passes through Python memory? |
|---|---|---|---|---|---|
| CA private key (ML-DSA) | `pki.generate` (pyca/cryptography) | `ca.key`, PKCS#8, encrypted with the passphrase unless `--no-encrypt`; owner-only file | `signers.KeySigner` holds the loaded key for the life of the `CA` object | Deleting the file; memory is not wiped | **Yes**: PEM bytes, the passphrase and the key object |
| CA private key (SLH-DSA) | OpenSSL `EVP_PKEY_generate` | `ca.key`, as above | `OpenSSLSigner` keeps an `EVP_PKEY`; signs in OpenSSL | Freed when the signer is collected (`weakref`); not cleansed by Python | PEM bytes pass through Python when loading |
| CA key in AWS KMS | KMS | KMS | `Sign` with external mu | KMS key deletion | No: only the public key and signatures |
| CA key in an HSM | The HSM | The HSM | `CommandSigner` runs the customer's command | HSM | No. **Not tested against a real device or any emulation** |
| Leaf private keys | `pki.generate` | `key.pem`, owner-only, optionally encrypted | OpenSSL reads the file (`openssl.Context._use_key`) | Deleting the file | **Yes**: the file bytes sit in a Python `bytes` while loaded |
| EST enrollment token | `secrets.token_urlsafe` | Only a SHA-256 hash in `tokens.json` (owner-only) | Compared with `hmac.compare_digest` | Marked spent on disk **before** signing | The secret is shown once to the operator |
| Console session token | `secrets.token_urlsafe(32)` | Browser `sessionStorage`; the automation token is an owner-only file | Constant-time compare | Session end / file deletion | Yes (it is a bearer token) |
| CA passphrase in the console | Typed by the operator | Memory of the console process only | Unlocks the CA key | Process exit | Yes |

Finding: no key bytes are wiped. Moving leaf-key loading to a file BIO (so the PEM never becomes a Python object) and
cleansing the buffers is stage 6; loading an ML-DSA CA key inside OpenSSL as `OpenSSLSigner` already does for SLH-DSA is the
route for the CA key.

## Security claims and the tests that show them

| Claim | Test | What the test does |
|---|---|---|
| A recorded session sent again does nothing | `test_replay::test_a_recorded_session_sent_again_is_refused_and_does_nothing` | Replays a captured handshake |
| No early data is accepted | `test_replay::test_no_early_data_so_nothing_is_accepted_before_the_handshake_completes` | Sends data before the handshake ends |
| A CRL from another CA cannot clear a certificate | `test_revocation_chain::test_a_crl_from_another_ca_cannot_clear_a_certificate` | The root's CRL does not clear an intermediate's revocation |
| Revocation covers an intermediate and its certificates | `test_revocation_chain::test_both_lists_in_one_file_revoke_the_leaf_and_the_intermediate` | Two CRLs in one file |
| A resumed session is still checked | `test_revocation_chain::test_a_resumed_session_without_a_chain_is_still_checked` | Resumption after revocation |
| A forged, stale or replayed CRL download changes nothing | `test_changes::test_forged_replayed_and_wrong_downloads_change_nothing` | Bad downloads leave the copy as it was |
| An outage keeps the last CRL; an expired one refuses everyone | `test_changes::test_an_outage_keeps_the_last_copy_and_an_expired_copy_refuses_everyone` | Server gone, then CRL expired |
| Enrollment tokens cannot be guessed or stretched | `test_est::test_tokens_cannot_be_stretched_or_guessed` | Wrong, reused and altered tokens |
| A token is bound to one name | `test_est::test_enroll_once_with_a_token_bound_to_one_name` | A request for another name is refused |
| A classical key does not burn the token | `test_est::test_a_classical_key_does_not_burn_the_token` | Refusal before the token is spent |
| A crash while signing leaves the token spent | `test_est::test_a_crash_while_signing_leaves_the_token_spent` | Failure injected after the token is marked |
| A renewal cannot become someone else | `test_est::test_renewal_cannot_become_someone_else` | New name in a renewal CSR |
| A slow request is cut off | `test_est::test_a_request_trickled_a_byte_at_a_time_runs_out_of_time` | Trickled bytes |
| The audit log never holds a token secret | `test_est_secrets::test_enrollment_audit_never_records_a_token_secret` | Greps the log |
| The console refuses foreign Hosts, Origins and cross-site requests | `test_acxelin_core::test_request_checks_refuse_foreign_hosts_origins_and_cross_site` | Bad headers |
| A launch ticket is single use and expires | `test_acxelin_core::test_ticket_is_single_use_and_expires` | Second redeem fails |
| Lockout after ten wrong tokens per address | `test_acxelin_core::test_lockout_after_ten_wrong_tokens_per_address` | Eleven attempts |
| A page on another local port cannot lock the real user out | `test_acxelin_core::test_requests_without_a_credential_never_lock_out_the_real_user` | Credential-less requests |
| No cookies; secrets stay out of logs | `test_acxelin_core::test_console_page_flow_issues_no_cookie_and_keeps_secrets_out_of_logs` | Full page flow |
| Secret files are owner-only before the first byte | `test_acxelin_core::test_a_secret_is_made_owner_only_before_any_byte_is_written` | Checks mode at write |
| The same on Windows (ACLs) | `test_acxelin_core::test_secret_files_on_windows_get_an_owner_only_acl` | Windows CI only |
| A policy has no defaults; core names no policy | `test_tls_policy::test_a_policy_has_no_defaults`, `test_tls_policy::test_core_defines_no_named_policy` | Mechanism/policy split |
| No shared group means no connection | `test_tls_policy::test_no_shared_group_means_no_connection` | Disjoint group lists |

## Claims with no test found

- The signing-command and KMS paths work against a real HSM or a KMS account. `test_signers_external` checks them against a
  stand-in and AWS's request model; `signers-live.yml` runs only on request and needs a secret account.
- Windows loads OpenSSL only from a trusted folder. Documented in SECURITY.md; no test.
- An external signing command that hangs does not block the CA beyond its 120 s timeout: the timeout exists, no test.

## Limits

Python cannot wipe keys from memory. The host that runs a CA or an edge must be trusted like any server that holds keys.
