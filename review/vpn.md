# Acxelin VPN

## Data flow

```
Sites (IPsec)
  initiating site ──mutual TLS 1.3, hybrid ML-KEM, ML-DSA certs (keyring, port 7443)──> responding site
        both sides export 64 bytes from that session (RFC 5705 / RFC 8446 §7.5):  IKE PSK + PPK + PPK id
        [optional: QKD key ID sent; both mix the key from their own KME with HKDF-SHA384]
        each side loads the keys into strongSwan (charon) through VICI ──> IKEv2 with hybrid ML-KEM (RFC 9370) + PPK (RFC 8784) ──> ESP
        repeat every rotate_minutes (60); a peer that stops re-agreeing is cut after 3 periods + 120 s

People (WireGuard)
  invitation (one-time token, 24 h) ──EST over PQ TLS──> device ML-DSA certificate
  laptop ──mutual TLS 1.3 to the gateway's keyring──> 32-byte PSK from the session exporter, bound to both WireGuard public keys
        gateway sets the peer's preshared-key through `wg` (secret on stdin); laptop does the same; repeat every 2 minutes
        a laptop silent for 3 periods + 30 s is removed; a revoked one is removed by the expiry loop
        WireGuard's own handshake (X25519) is classical; the PSK is what makes recorded traffic safe
```

The control plane is the gateway's own keyring service. The CA is not in the data path: it is needed for enrollment, renewal
and CRLs.

## Trust boundaries

| Boundary | Crosses | Held by |
|---|---|---|
| Peer → keyring (port 7443) | TLS handshake, one JSON line each way | PQ-only TLS policy, ML-DSA mutual authentication against your CA, CRL, max connections, message size limit (4096 bytes) |
| Gateway → strongSwan | VICI over a unix socket: connections and shared secrets | Local only; one request at a time; reconnect without replaying mutations |
| Gateway/laptop → `wg` | Private key and PSK on stdin | Never on a command line |
| Laptop → administrator rights | The app starts the service as root/administrator | Only from code ordinary users cannot change (finding 1, fixed) |
| Browser or app window → local service | Loopback HTTP | Host/Origin checks, ticket exchanged once for a session key, lockout |
| Invitation file → laptop | CA fingerprint and a one-time enrollment token | A channel you trust; whoever uses it first enrolls |
| Site → key server (QKD) | ETSI GS QKD 014 over mutual TLS 1.3 | The QKD key only adds to the TLS-derived keys |

## Keys

| Key or secret | Created | Stored | Used | Destroyed | Python memory? |
|---|---|---|---|---|---|
| CA, gateway and site keys (ML-DSA) | pyca/cryptography | owner-only `key.pem`, optionally encrypted | Loaded into an OpenSSL context | Deleting the file | Yes (see core.md) |
| Device key (laptop) | On the laptop during enrollment | `key.pem`, passphrase required by the app | Mutual TLS to the gateway | Never leaves the device | Yes |
| IKE PSK, PPK, PPK id | `SSL_export_keying_material` (OpenSSL) | strongSwan memory; only the two newest are loaded | IKE authentication | `unload_key` on rotation, cut or revocation | Yes: returned to Python as `bytes` before VICI |
| WireGuard PSK | Same exporter, 32 bytes | `wg` / kernel; client config only if `--config-out` is used (owner-only) | Mixed into every WireGuard handshake | Replaced every 2 minutes; peer removal | Yes |
| WireGuard X25519 key | pyca `X25519PrivateKey.generate` | `wireguard.key`, base64, owner-only, unencrypted | Passed to `wg` on stdin | Deleting the file | Yes |
| QKD key | The key server | Not stored | HKDF input | Garbage-collected | Yes |
| Enrollment token | CA | SHA-256 hash only | Redeemed once | Marked spent before signing | Shown once |

## Claims and tests

| Claim | Test | What it shows |
|---|---|---|
| Every exchange is hybrid ML-KEM except the strict profile, which uses ML-KEM-1024 alone | `test_vpn::test_every_exchange_is_post_quantum_and_hybrid_except_the_strict_profile`, `test_cnsa2::test_ike_and_esp_use_ml_kem_1024_alone_with_aes_256_and_sha_384` | Generated strongSwan configuration |
| A PPK is required and pinned per peer | `test_vpn::test_conn_requires_a_ppk_and_pins_it_per_peer` | |
| Both ends derive the same keys from one session; labels and contexts are pinned | `test_agreement::test_one_session_gives_both_sides_the_same_keys`, `test_agreement::test_labels_and_contexts_are_pinned` | Today's constants; no previous release is run against this one |
| A wrong peer, a revoked peer or a refusal loads no keys | `test_vpn::test_the_wrong_peer_a_revoked_peer_and_a_refusal_load_no_keys`, `test_vpn::test_the_responder_refuses_what_it_should_not_accept` | |
| Keys are cut when agreement stops | `test_vpn::test_tunnels_without_fresh_key_agreement_are_cut` | |
| A revoked peer is cut, but a broken CRL keeps tunnels | `test_vpn::test_a_revoked_peer_is_cut_but_a_broken_crl_keeps_tunnels` | The intended behaviour for a *broken* CRL; an *expired* one refuses new agreements |
| Only the two newest keys stay loaded | `test_vpn::test_only_the_two_newest_keys_stay_loaded` | |
| IKE without an installed child is not "protected" | `test_vpn::test_ike_without_installed_child_is_not_protected_and_is_retried` | |
| A strongSwan without ML-KEM is refused at start | `test_vpn::test_a_strongswan_without_ml_kem_is_refused_at_start` | |
| Real tunnels rotate and a revoked site is cut | `test_vpn::test_quantum_safe_tunnel_rotation_and_revocation` | **CI only**: network namespaces, strongSwan 6.1, root |
| WireGuard traffic flows, rotates, and a revoked laptop is cut | `test_wireguard::test_traffic_rotation_and_revocation` | **CI only** |
| Users outside the list are refused; one person cannot take another's key | `test_wireguard::test_users_outside_the_list_are_refused`, `test_wireguard::test_one_person_cannot_take_over_anothers_wireguard_key` | |
| Revoked and silent clients are removed; a broken CRL still removes silent ones | `test_wireguard::test_revoked_and_silent_clients_are_removed`, `test_wireguard::test_a_broken_crl_still_removes_laptops_that_stopped_renewing` | |
| The kill switch holds traffic while a full tunnel is down and recovers | `test_wireguard::test_all_traffic_through_the_tunnel_recovery_and_kill_switch` | **CI only** |
| The Linux kill switch fails closed while its rules change | `test_vpn_platforms::KillSwitchTest::test_linux_fails_closed_while_the_rules_change` | Command order against a recorder, not a live firewall |
| The CBOM holds no secret in any encoding | `test_inventory::test_no_secret_reaches_the_cbom_in_any_encoding`, `test_inventory::test_keys_and_shared_secrets_are_listed_by_type_and_size_only` | |
| The CBOM validates against CycloneDX 1.6 | `test_inventory::test_the_cbom_validates_against_cyclonedx_1_6` | |
| The console and app refuse foreign requests and lock out guessers | `test_console::test_the_console_refuses_requests_it_should_not_answer`, `test_console::test_wrong_tokens_lock_the_address_out` | |
| A QKD failure stops the agreement instead of weakening it | `test_qkd::test_a_failing_key_server_stops_the_agreement_instead_of_weakening_it`, `test_qkd::test_a_peer_configured_for_qkd_that_sends_no_qkd_key_is_refused` | Against a simulated key server only |
| CNSA 2.0-only profile refuses other certificates | `test_cnsa2::test_a_certificate_that_is_not_ml_dsa_87_is_refused_before_any_connection` | |

## Claims with no test found

- **Replaying a recorded key agreement is refused.** The tag and the exporter binding make it fail in theory; no test replays
  a recorded agreement and shows the refusal.
- **Revocation takes effect within 15 seconds.** The watcher runs every 15 s; no test asserts the bound.
- **A control-plane outage:** what happens when the keyring is down, slow or partitioned (stage 4 adds this).
- **IKE fragmentation and MTU** with post-quantum payloads, and **dead-peer detection** against a real peer.
- **Upgrading** a running gateway or laptop from the previous release; the kill switch on macOS is checked by the rules it
  writes, not on a live system.
- The **desktop app**: `test_vpn_desktop` exercises the tray on Windows and macOS runners. The elevation rule is unit tested
  (`test_elevation`), not exercised through a real UAC, polkit or macOS prompt.

## Findings from reading the code

1. **Fixed in stage 1b: the tray app ran user-writable code as root or administrator.** (`acxelin-vpn install` did the same for its boot service.) Both now refuse unless the code is where only administrators can write; tests are `test_elevation` and core's `test_protected_location`. The text below is the finding as first written. `desktop.elevated()` and `start_service()` run
   `pkexec env PYTHONPATH=<package folder> <python> -m acxelin_vpn app` (Linux), an `osascript … with administrator
   privileges` equivalent (macOS), or `ShellExecuteW … "runas"` (Windows). For a per-user install (the default of
   `install.sh`/`install.ps1`) that interpreter and package folder are writable by the person, so malware running as that
   person can edit the code and wait for the administrator prompt. The packaged installers (`sys.frozen`) install under
   protected folders and are not affected. The prompt does not tell the person what code will run. Not fixed; needs a
   decision (refuse to elevate from a user-writable install, or elevate only a fixed helper).
2. **A control-plane outage disconnects people by design** after `3 × rotate_minutes + 30 s`: 6.5 minutes at the default.
   Stage 4 addresses this.
3. Cleartext WireGuard private keys on the gateway and laptop are owner-only files, not encrypted.

## Limits

WireGuard's handshake is classical. IKE does not authenticate with ML-DSA certificates (strongSwan 6.1 cannot load them);
it uses a PSK and PPK derived from ML-DSA mutual TLS. Phones are not supported. A peer without RFC 9370 support cannot connect
(a design for an opt-in fallback is in `review/vpn-classical-fallback.md`). Desktop installers are not code-signed yet.
