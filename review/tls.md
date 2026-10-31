# Acxelin TLS

## Data flow

```
terminate:  client ──TLS 1.3 (policy)──> edge ──plain TCP (loopback/private)──> service        [optional PROXY protocol header]
originate:  local client ──plain TCP (127.0.0.1)──> edge ──TLS 1.3 PQ──> remote edge
CA:         admin ──CLI/console──> CA folder ──> leaf certs, chain, CRL (7-day validity)
            ca publish ──HTTP──> edges/gateways (crl_url, polled every crl_every s, minimum 5)
            ca serve  ──EST (PQ-only TLS 1.3)──> machines          ca acme ──ACME (HTTP, or TLS 1.3 only)──> ACME clients
metrics:    edge ──plain HTTP /healthz /metrics /status (no login)──> monitoring
```

## Trust boundaries

| Boundary | Crosses | Held by |
|---|---|---|
| Client → edge | TLS handshake and application bytes | Policy (`strict`, `transition`, `cnsa2`), CRL check, per-address rate and slot limits, handshake and idle timeouts |
| Edge → service | **Plaintext** | Not protected by the product. Keep the service on loopback or a private network |
| Edge → CRL source | CRL over HTTP(S) | Signature, expiry and replay checks before replacing the copy |
| ACME client → CA | JWS requests, CSRs, http-01 validation | Nonces, EAB, `allow` patterns, validation address checks (below) |
| ACME validator → the internet | The CA connects out to a client's HTTP port | Refuses loopback, link-local, multicast and reserved addresses; resolves once; does not follow redirects |
| Browser → console | Loopback HTTP | Core console rules |
| Monitoring → `/metrics` | Plain HTTP, lists routes and upstreams | A firewall; the edge logs a warning when it is not on loopback |

## Keys

Same table as [core.md](core.md) for the CA, leaf keys and EST tokens. Specific to this product:

| Secret | Where | Note |
|---|---|---|
| Edge private key | `key.pem` named in the route, optionally encrypted with a passphrase taken from an environment variable the route names | Read by OpenSSL via a Python `bytes` copy; reloaded on file change |
| Fallback (classical) key | `fallback_key`, `transition` routes only | Protects browsers only as well as classical TLS does |
| ACME external-account-binding keys | `acme/eab.json`, owner-only, **plaintext HMAC keys** | Not hashed, unlike EST tokens. Anyone who can read the file can register accounts |
| ACME account keys | Public JWKs in `acme/state.json` | |
| Console CA passphrase | Memory only | The console asks again after a restart |

## Claims and tests

| Claim | Test | What it shows |
|---|---|---|
| `strict` refuses classical key exchange | `test_tls::test_strict_server_refuses_classical_key_exchange`, `test_downgrade::test_policy_matrix` | A classical-only client fails; the matrix covers all three policies |
| `cnsa2` accepts only ML-DSA-87 client certificates | `test_downgrade::test_cnsa2_client_certificates_must_be_ml_dsa_87` | A different certificate is refused |
| Certificates only work in their own role | `test_downgrade::test_certificates_only_work_in_their_own_role` | A server certificate used as a client is refused |
| `transition` serves classical clients | `test_tls::test_transition_server_still_serves_classical_clients` | The behaviour that keeps legacy clients working |
| A revoked client is refused, and its open connections are closed | `test_tls::test_revoked_client_is_refused`, `test_tls::test_revoking_a_client_closes_its_open_connection_and_no_other` | |
| Resumption does not bypass revocation | `test_tls::test_mutual_tls_clients_can_resume_and_a_revoked_one_still_cannot` | |
| A damaged or expired CRL refuses everyone, with the reason logged | `test_tls::test_a_damaged_crl_refuses_everyone_and_says_why`, `test_changes::test_an_outage_keeps_the_last_copy_and_an_expired_copy_refuses_everyone` (core) | |
| A CRL replayed to restore a revoked certificate is rejected | `test_security_regressions::test_same_second_crl_replay_cannot_restore_a_revoked_certificate` | |
| A revocation reaches a running edge | `test_edge_reload::test_a_revocation_at_the_ca_reaches_the_edge` | |
| Silent or slow clients cannot hold connections | `test_tls::test_silent_client_times_out`, `test_tls::test_one_host_opening_silent_sockets_cannot_lock_others_out` | |
| One address cannot take the CPU or the slots | `test_tls::test_one_address_cannot_take_the_cpu_or_the_slots_and_floods_are_not_logged_line_by_line` | |
| A renewed certificate is picked up without restart | `test_tls::test_renewed_certificate_is_picked_up_without_restart` | Availability, not security |
| The first TLS flight fits TCP's initial window | `test_tls::test_the_root_is_not_sent_so_the_first_flight_fits_tcps_initial_window` | Addresses part of the large-handshake concern (the server's flight, not the client's) |
| Passphrases and token secrets never reach output, logs or files at rest | `test_secrets::test_passphrases_and_token_secrets_never_leave_where_they_belong`, `test_console::test_secrets_never_reach_responses_logs_or_files` | |
| The CA can be lost and restored | `test_recovery::test_lose_the_ca_machine_and_restore_it` | |
| The console download never hands out a revoked or encrypted key | `test_console::test_download_gives_the_key_only_when_asked_and_never_for_a_revoked_certificate`, `test_console::test_an_encrypted_key_is_not_handed_out` | |
| ACME: forged and replayed requests, classical keys, EAB | `test_acme::test_forged_and_replayed_requests`, `test_acme::test_classical_keys_are_refused`, `test_acme::test_external_account_binding` | |
| ACME validation cannot reach loopback or metadata addresses, nor follow redirects | `test_acme::test_validation_never_reaches_loopback_or_metadata_addresses_by_default`, `test_acme::test_http01_does_not_follow_redirects_to_other_addresses` | SSRF defence |
| ACME finalisation re-checks authorisation; deactivated authorisations stay dead | `test_security_regressions::test_acme_finalization_rechecks_authorization`, `test_security_regressions::test_acme_validation_cannot_reactivate_a_deactivated_authorization` | |
| A stalled ACME TLS handshake does not block others | `test_security_regressions::test_acme_https_stalled_handshake_does_not_block_other_clients` | |
| Settings that would check nothing are refused (e.g. `crl` without `require_client_cert`) | `test_hardening::test_settings_that_would_check_nothing_or_stop_everything_are_refused` | |
| Real clients (Node, curl, Go) interoperate | `tests/interop/run.sh` (CI job `interop`) | A shell script, not a pytest test; loopback only |

## Claims with no test found

- A **large post-quantum ClientHello** passes load balancers, proxies and inspection devices. Nothing is tested over a real
  network path.
- Behaviour of **many workers** under a revocation: `test_tls::test_workers_share_the_port_and_the_metrics_add_up` covers metrics, not
  that every worker applies a new CRL at the same moment.
- An **edge restart** under load drops its connections after the grace period; no test measures the effect on clients.
- **Upgrading** a running edge from the previous release.
- ACME `eab.json` being plaintext is documented nowhere in the manual.

## Limits

Browsers cannot verify ML-DSA. A revoked client works until the edge has the new CRL (`crl_every`, 60 s by default). The
service behind the edge sees plaintext. The threat model's statement that everything was exercised "on Linux" is out of date:
CI runs the product tests on Linux, macOS and Windows (OpenSSL pinned to 3.5 from the pinned-line change onward).
