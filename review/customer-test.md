# First-time and difficult customer test

All three products were installed and used as a customer would, from the READMEs and the website only, on Linux (Python 3.13, OpenSSL 3.5.9 through `ACXELIN_OPENSSL`), with folders whose names hold spaces and non-English letters. Where reading the source was needed to understand a message, that is a finding below.

Nothing here was run on Windows, macOS, real hardware, several machines or real middleboxes. Those parts are listed at the end with the steps to run them. A scenario is marked **ran** only when it ran here.

## What was found and fixed

Every finding has a test that failed before the fix.

| | Found | Fix | Test |
|---|---|---|---|
| Core | A passphrase typed where a serial goes was repeated in the error ("…not 'correct horse 9!'") | The error never repeats what was typed | `test_customer_findings_core.py::test_a_passphrase_pasted_where_a_serial_goes_is_never_repeated` |
| Core | A misspelled setting (`require_client_certs`) was refused without naming the right one | "did you mean require_client_cert?" | `test_customer_findings_core.py::test_a_misspelled_setting_names_the_one_that_was_meant` |
| Core | A full disk while issuing said only "No space left on device"; the certificate was recorded and its folder had no `chain.pem` | The message names the certificate and the command that finishes or withdraws it | `test_customer_findings_core.py::test_a_disk_that_fills_mid_issue_says_the_certificate_was_recorded_and_how_to_finish` |
| TLS | `doctor` said a configuration loads when the edge then refused it (cnsa2 with an ML-DSA-65 certificate) | `doctor` fails that route with the edge's own message | `test_customer_findings_tls.py::test_doctor_fails_a_route_whose_certificate_its_policy_cannot_use` |
| TLS | "needs a ML-DSA-87 certificate" | "an" | `test_customer_findings_tls.py::test_the_policy_message_reads_an_ml_dsa` |
| TLS | `ca renew` put the new certificate in a new folder and did not say that the edge keeps serving the old one | It says so and gives the renew-in-place command | `test_customer_findings_tls.py::test_renew_says_where_the_new_certificate_is_and_that_the_old_folder_still_holds_the_old_one` |
| TLS | A name no route serves gave "handshake failed: handshake failed (peer closed the connection)" | Said once, with a hint about the server name | `test_customer_findings_tls.py::test_a_name_no_route_serves_is_described_once_with_a_hint` |
| TLS | No way to see the stapled OCSP answer as a customer | `connect` shows it | `test_customer_findings_tls.py::test_connect_shows_the_stapled_ocsp_answer` |
| TLS | No warning before a stapled answer runs out (a long weekend) | `doctor` warns a day ahead, and when it is missing | `test_customer_findings_tls.py::test_doctor_says_when_the_stapled_answer_is_missing_or_about_to_end` |
| TLS | A route on a shared port did not log which port | It logs the address and the names it serves | `test_customer_findings_tls.py::test_a_route_on_a_shared_port_says_which_port` |
| VPN | The commands `setup` prints broke when copied from a folder with spaces | Paths are quoted | `test_customer_findings_vpn.py::test_the_printed_next_steps_survive_a_folder_with_spaces` |
| VPN | `access` without `show` said "required: action" | `show` is the default | `test_customer_findings_vpn.py::test_access_without_an_action_shows_who_is_limited` |
| VPN, website | Output, comments and docs said "her" for any person | They/them, or the person's name; a repository test keeps it so | `test_wording.py::test_no_gendered_pronouns_for_people` |
| Readiness | `scan --tls` used only Python's TLS library, so it never read the certificate of a post-quantum-only server, which the README says it does | It completes the handshake through OpenSSL 3.5 | `test_customer_findings_readiness.py::test_scan_reads_the_certificate_of_a_post_quantum_only_server` |
| Readiness | A quiet scan that failed its `--fail-on` gate exited 2 and printed nothing | It says why on stderr | `test_customer_findings_readiness.py::test_a_quiet_scan_that_fails_its_gate_still_says_why` |
| Readiness | The README did not mention the held-out evaluation, or that probing by IP address sends no server name | Both are in the README's limits | (documentation) |

Also seen and left as they are: in `acxelin-tls try`, when its output goes to a pipe, the edge's log line can land at the end of the "refused" line (on a terminal they are separate lines); Ctrl+C in `ca maintain` exits 130 with nothing printed, and the CA stays consistent.

## Scenarios

| Scenario | Ran here | Outcome |
|---|---|---|
| TLS tour (`try`) | ran | post-quantum client served, classical client refused |
| Bank CA: three edges, one port shared by name, cnsa2 route, mutual TLS tellers, OCSP staple | ran | worked once the cnsa2 certificate was ML-DSA-87 (the finding above); unknown name closed |
| Employee leaves (revoke a teller) | ran | refused from the next connection; the other teller still served |
| Renewal, short-lived 8-hour certificate, `maintain` | ran | renewed in place by `maintain`; `ca renew` finding above |
| Shadow, then strict | ran | classical client served and reported with its reason in status and log |
| CA host dies, restore from a copy of the folder | ran | revoke and issue work on the restored CA |
| Long weekend: 3-day certificate | ran | `doctor` says how often `maintain` must run; OCSP warning added |
| 100 EST enrolments, 20 at once | ran | 1.6 s in all, p95 0.32 s; every replayed token refused |
| 12 certificates issued at the same moment | ran | 12 records, 12 serials, index intact |
| Ctrl+C in `ca maintain` with 150 renewals | ran | index intact, no temporary files, the next run finishes |
| Full disk while issuing | ran | finding above |
| Old OpenSSL (3.0) | ran | `doctor` refuses it and says what to install |
| Malformed, empty, missing, misspelled configuration; port already in use; revoke twice | ran | each says what is wrong |
| VPN setup and invitation from a folder with spaces | ran | finding above |
| VPN real tunnels in network namespaces (userspace WireGuard): traffic, key rotation, a revoked laptop cut off; all traffic through the tunnel, recovery and kill switch | ran | passed |
| VPN control-plane outage grace and its cap; a revoked laptop removed inside the grace | ran (gateway tests) | passed |
| VPN 50 people at 9am | ran (key agreement benchmark) | p50 10.6 ms, p95 15.6 ms each on 4 cores |
| Readiness scan of a 240 MB repository (OWASP Benchmark for Java) with live endpoints | ran | 52 s; finding above for the cnsa2 edge |
| Readiness merge with another tool's CBOM (CBOMkit) | ran | one inventory for both systems |
| Readiness rescan a month later with `--baseline` | ran | the new DES use is the only one flagged; finding above for `-q` |
| Readiness grade of edges by IP and by name | ran | by name A; by IP the shared port refuses (limit stated) |

## What could not run here, and how to run it

**Windows, PowerShell (all three products).** On a clean Windows 11 with Python 3.12 and `choco install openssl`, from a folder such as `C:\Users\First Last\Acxelin Test`:
1. Follow each README's Install steps with the release wheelhouse; `acxelin-tls doctor`, `acxelin-vpn doctor`, `acxelin-readiness doctor`.
2. `acxelin-tls try`; then the bank CA steps above with `acxelin-tls console` (issue, revoke, renew in the browser).
3. `acxelin-vpn setup vpn.example --route 192.168.10.0/24`, copy each printed command into PowerShell as printed, and check it runs.
4. Install the VPN desktop app, open an invitation, connect; move the laptop between Wi-Fi networks and a phone hotspot; confirm the window says Protected again within a minute.
5. `acxelin-readiness scan "C:\Users\First Last\source\repo" --tls host:443`, then open the report.

**macOS.** The same as Windows with `brew install openssl@3`; for the VPN, `sudo acxelin-vpn app` (README limit).

**Head office and three branches.** Four Linux machines with strongSwan 6.1: `config/` holds a headquarters and a branch site; copy the branch file three times with its own `name`, `subnet` and certificate. Bring all up, ping across every pair, revoke one branch and confirm only it drops within 15 seconds.

**Poor link.** On a branch gateway: `tc qdisc add dev eth0 root netem delay 300ms loss 5%`; run traffic for an hour and read `acxelin-vpn status` for renewals and drops.

**UDP blocked (hotel).** Block UDP 51820 at the laptop's router. WireGuard runs over UDP only and the product has no TCP fallback, so the laptop cannot connect; note exactly what the desktop app window says, since that is what a person in a hotel sees.

**Partner's classical IKEv2 gateway.** Today such a peer is refused: every site must do hybrid ML-KEM (RFC 9370) and the post-quantum key agreement. A per-peer classical fallback is a proposal waiting for your decision (`review/vpn-classical-fallback.md`). Configure a site against a partner strongSwan without ML-KEM and confirm the tunnel stays down and the log says why.

**Gateway upgrade and rollback while connected.** Install the next VPN wheelhouse over a running gateway with two laptops connected; restart; confirm they reconnect; reinstall the previous one; confirm again. `tools/tests/test_upgrade_rollback.py` covers the files, not the running service.

**Load balancer and an inspecting firewall.** Put HAProxy in TCP mode in front of an edge with `proxy_protocol = true`; then a TLS-inspecting firewall that offers only classical groups; the edge must refuse it under strict and name the reason.

**Real HSM, real IdP, real DNS.** `review/softhsm-key-handling.md` (the token), the manual's OIDC section with your Entra ID or Okta tenant, and `ca acme --dns-command` with your DNS provider's CLI.

**Offline install and a cautious genuineness check.** On a machine with no network: copy the wheelhouse, `SHA256SUMS`, the SBOM and `verify_release.py`; follow `documents/verify-a-release.md`; then install one product only and confirm the others are not present.

**Wrong clock.** Set a client's clock two days ahead with `date -s`; `acxelin-tls connect` to an edge with a 24-hour staple should show the stapled answer as out of date; set the clock two days back and it should say the answer is not valid yet and to check the clock. Set it right again.
