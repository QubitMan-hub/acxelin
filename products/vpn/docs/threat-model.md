# Threat model

## What Acxelin VPN protects

Traffic between your sites, and between people's computers and your network, against an attacker who records it now and
decrypts it later with a quantum computer (harvest now, decrypt later), against one who sits in the middle of a key agreement,
and against one who holds a certificate you have revoked.

## What is tested

| Threat | Defence, and the test that shows it |
|---|---|
| Recording IPsec traffic to break it later | the IKE key exchange is hybrid ML-KEM, and a PPK from ML-DSA mutual TLS is mixed in (`test_vpn`, real tunnels in network namespaces in CI) |
| Recording WireGuard traffic to break it later | each computer's pre-shared key comes from a post-quantum key agreement and is replaced every two minutes (`test_wireguard`) |
| A man in the middle of the key agreement | TLS 1.3 with a hybrid ML-KEM group and ML-DSA certificates from your CA on both sides; a classical or wrong-role peer is refused |
| Replaying a key agreement | keys come from that session's TLS exporter, bound to both names and a fresh tag (WireGuard also to both public keys) |
| A revoked site or person | no new keys, and the tunnel is cut within 15 seconds of the CRL reaching the gateway; an expired CRL refuses everyone |
| Traffic leaking while a full tunnel is down | the kill switch blocks it, and on Linux it fails closed at every instant while its rules change: the new chain is in place before the old one goes (`test_vpn_platforms::test_linux_fails_closed_while_the_rules_change`). The macOS anchor is checked by what it writes, not on a live system; Windows can lift for a moment (below). No test installs a new release over a running one yet |
| Secrets in an export | the CBOM records PSK and PPK type and size only; a test searches it for every key, token and passphrase as bytes, hex, base64 and PEM (`test_inventory`) |
| A web page attacking the console or the app window | loopback host names and same-origin requests only, no cookies, one-time launch links, lockout after ten wrong attempts (`test_console`, core console tests) |
| A user changing code that the VPN runs with administrator rights | the tray and `acxelin-vpn install` refuse to start anything as root or administrator unless the interpreter, every folder it imports from and the folder OpenSSL loads from can be written only by administrators, and what they start ignores `PYTHONPATH`, the user-site folder and the current folder; on Windows OpenSSL must come from a named folder, never `PATH` (`test_elevation`, `test_protected_location` in core) |
| An old gateway during an upgrade | the exporter labels and contexts are pinned, and both ends of one session derive the same keys (`test_agreement::test_labels_and_contexts_are_pinned`, `test_agreement::test_one_session_gives_both_sides_the_same_keys`). This pins today's constants; no test runs a gateway from the previous release against this one yet |
| A key agreement outage dropping everyone, and the opt-in grace that rides it out being used to keep a revoked device connected | `outage_grace_minutes` is off by default and capped at 24 hours; the cap is hard however long the outage lasts (`test_wireguard::test_the_cap_is_hard_however_long_the_control_plane_stays_away`, `test_vpn::test_the_cap_is_hard_however_long_the_control_plane_stays_away`); someone revoked inside the grace is removed or cut at the next pass (`test_wireguard::test_a_client_revoked_inside_the_grace_window_is_removed_at_the_next_pass`, `test_vpn::test_a_peer_revoked_inside_the_grace_window_is_cut_at_the_next_pass`); a missing, damaged or expired CRL cancels it (`test_wireguard::test_a_crl_that_cannot_be_used_cancels_the_grace`, `test_vpn::test_a_crl_that_cannot_be_used_cancels_the_grace`) |
| An old gateway during an upgrade | old and new agree the same keys from the same session (`tools/tests/test_vpn_wire.py`) |

## What is not covered

- **WireGuard's own handshake** is classical. The post-quantum protection is the pre-shared key mixed into it.
- **The CA machine.** Whoever holds the CA key can issue certificates and join the VPN. Keep it encrypted, off the gateways.
- **Invitations in transit.** An invitation holds a one-time token for 24 hours. Send it through a channel you trust; whoever
  uses it first enrolls.
- **The computers themselves.** Malware on a laptop or gateway sees traffic before it is encrypted.
- **The outage grace** (`outage_grace_minutes`, off by default) keeps a silent person or peer on keys older than designed. It does not make recorded traffic easier to decrypt without the old pre-shared key, and it never delays a revocation the gateway knows about, but a certificate revoked while the new CRL cannot reach the gateway stays connected until the CRL arrives or the cap ends. It ends when the CRL expires. For remote access it is held by the gateway only: the computer's own software still takes its tunnel down when its key agreement fails. Tested with stand-ins for `wg` and charon; the real-machine drill (`docs/outage-drill.md`) has not been run.
- **The Windows kill switch** can lift for a moment while the tunnel is recreated.
- **Phones** are not supported.
- **Validation on your network.** Tunnels were exercised in Linux network namespaces with strongSwan 6.1 and OpenSSL 3.5.9, and
  on GitHub's Windows and macOS runners, not on customer networks or hardware.
- **Running the VPN as root from a per-user install.** `sudo acxelin-vpn gateway` or `up`, started by an administrator, runs
  whatever that install contains with root's rights, and nothing stops it: install gateways as root under `/opt/acxelin-vpn`
  (the manual shows how), as the systemd units expect. The product's own elevation (the tray, the boot service) is the part
  that refuses.
- **The elevation rules on Windows and macOS** are tested with their folder and ownership rules in unit tests, not on those
  systems. On Windows the rule is "inside Program Files or the Windows folder", a rule about default permissions: some folders
  there are writable by users, and a path that does not exist yet passes. On macOS the tray refuses to elevate at all from
  Applications, because any administrator account can rename an app there. Posix ACLs, mount options and network file systems
  are not checked. The check is made before the prompt, not again when the process starts.
