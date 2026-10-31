# Proposal: an opt-in, per-peer classical fallback for IKEv2 peers without RFC 9370

Status: design only, for the owner's decision. Nothing here is implemented, and no number in it comes from a measurement.

## The problem

Every IPsec peer today has to do hybrid ML-KEM in IKEv2 (RFC 9370) and take part in the post-quantum key agreement: `conn_config`
(`charon.py`) offers only the proposals in `PROFILES` (`...ke1_mlkem768`, `...ke1_mlkem1024` or `mlkem1024`), requires a PPK
(`ppk_required = yes`), and `protected()` reports a tunnel as protected only with a PPK, an ML-KEM exchange and an installed child.
A router or appliance that speaks IKEv2 but not RFC 9370 is refused, in the strict sense. That is the right default. During a
migration an administrator may nevertheless have a few such devices they cannot replace yet, and today the only answers are "do
not connect it" or "connect it outside Acxelin VPN, where nothing says it is not protected".

The proposal is a way to connect such a peer on purpose, in the open, for a limited time, without ever weakening a peer that can do
better.

## The setting

Per peer, mirroring how the TLS product's `policy` works (`strict` by default, `transition` to let classical clients in), and
because a peer already carries its own `profile` and `rotate_minutes`:

```toml
[[peer]]
name = "legacy-router.acme.example"
address = "198.51.100.40"
local_subnets = ["10.1.0.0/16"]
remote_subnets = ["10.7.0.0/16"]
policy = "transition"                      # NOT QUANTUM SAFE: classical IKEv2 for this peer only. Default: "strict"
transition_until = "2027-03-31"            # required; at most 12 months ahead; the fallback stops on that date
transition_psk_file = "/etc/acxelin-vpn/legacy-router.psk"   # owner-only; the peer has no Acxelin key agreement to derive one
```

- `policy` is `strict` (the default, today's behaviour, byte for byte) or `transition`. `cnsa2` stays a `profile`; a site with any
  `cnsa2` peer refuses `transition` anywhere, because a CNSA 2.0 site must contain nothing classical.
- `transition` without a future `transition_until`, or without the PSK file, is a configuration error. There is no
  "transition forever": the date forces a review, and after it the controller unloads the classical connection and the peer is
  refused again. (Open question 3: whether the TLS product should get the same date.)
- The setting is per peer and has no site-wide form. There is deliberately no way to say "allow classical for everyone".

## What it would and would not change

It changes the local strongSwan configuration for that one peer, nothing on the wire that Acxelin defines:

| | Changes? |
|---|---|
| The key agreement over ML-DSA mutual TLS: messages, exporter labels, contexts, the `ipsec_keys` derivation | No. A legacy peer has no Acxelin controller, so it does not take part in it. |
| IKE proposals and PPK use for every `strict` peer | No. Their `conn_config` is the same bytes as today (a test compares them). |
| The VICI `load-conn` for the `transition` peer | Yes: a classical proposal (for example `aes256gcm16-prfsha384-x25519` for IKE, `aes256gcm16-x25519` for ESP), PSK authentication from the file, no `ppk_required`, `rekey_time` as for other peers. Standard IKEv2 on the wire. |
| `protected()` | Stays as it is: a classical tunnel is never "protected". Status says `classical`, and a new `quantum_safe: false`. |
| Configuration schema | Additive: three optional keys on `[[peer]]`. |
| CBOM | Additive: the tunnel component gets a property saying it is not quantum safe, and its proposals are listed as they are, so Readiness grades it as classical rather than hiding it. |

Rotation for the legacy peer is manual (a static PSK in a file), because rotation by key agreement needs the peer's cooperation. That is
a weaker position than a `strict` peer's, not only because of the missing ML-KEM: say so in the manual.

## "NOT QUANTUM SAFE", everywhere it can be seen

The same two words, in capitals, wherever the peer shows up:

- **Config.** The example file and `doctor` print them next to `policy = "transition"`; `doctor` warns (not fails), as the TLS
  product's `doctor` does for `transition`, and `doctor --strict` exits 1 while any such peer exists.
- **Logs.** One `WARNING` at start and each time the tunnel is established or rekeyed: `NOT QUANTUM SAFE: tunnel to X uses classical
  IKEv2 until 2027-03-31`. No per-pass lines.
- **Status.** `/status` per peer: `quantum_safe: false`, `classical_fallback: {"until": ...}`. `acxelin-vpn status` prints the tunnel in
  the warning colour with the words.
- **Metrics.** `acxelin_vpn_tunnel_quantum_safe{peer}` is 0 or 1 for every peer, and `acxelin_vpn_classical_fallback_expiry_seconds{peer}`
  counts down.
- **CBOM.** An Acxelin property on the tunnel, alongside the real classical algorithms.
- **Console.** A red badge on the peer, the end date, and a note that recorded traffic is open to a future quantum computer.

## Warning before a legacy peer is refused: the "would be refused" report

Today the first sign is charon's `NO_PROPOSAL_CHOSEN` in a log nobody reads. The proposal adds a report, in three layers, each useful on its own:

1. **Static.** `acxelin-vpn doctor --config site.toml` lists each peer with its policy and whether it has a PSK file, with a line for every
   peer an administrator has marked `expects_legacy = true` but left `strict`. (The administrator knows which devices are old; this is a
   reminder, not detection.)
2. **Observed.** The controller subscribes to charon's VICI log events and counts IKE_SA_INIT exchanges that failed with no acceptable
   proposal, keyed by remote address and mapped to a configured peer. The count and the peer's *offered* proposals go in `/status` as
   `refused_no_pq: {"count": 12, "last": ..., "offered": ["AES_GCM_16_256/.../CURVE_25519"]}` and the metric
   `acxelin_vpn_ike_refused_total{peer,reason="no_pq_proposal"}`. This tells the customer a peer *tried* and was refused.
3. **Report.** `acxelin-vpn report-legacy --config site.toml` prints the peers that were refused, since when, and the one setting to change if
   they decide to allow it, with the warning text above. It changes nothing.

Whether the VICI log event carries the peer's offered proposals reliably across strongSwan 6.x is not verified (open question 4);
layer 2 may have to count refusals only.

## Risks

- **Downgrade by an active attacker.** If a `strict` peer's connection ever offered a classical proposal, an on-path attacker could strip
  the ML-KEM proposal. So `strict` peers never get one: their `conn_config` contains only PQ proposals and `ppk_required = yes`, and
  the `transition` connection exists only under the legacy peer's name. Per-peer, not per-site, is the whole defence.
- **Pinning.** A peer that has completed an Acxelin key agreement is a PQ peer. The controller records (in an owner-only state file)
  the names that have agreed PQ keys; `policy = "transition"` for such a name is refused at load, and a classical connection
  for it is never loaded, even if someone edits the configuration or the peer's identity is spoofed. Removing the pin takes an explicit
  command (`acxelin-vpn forget-pq PEER`), logged and written to the audit log. This makes "a PQ peer can never be downgraded" a rule
  the software enforces rather than a convention.
- **Spoofing the legacy peer's name.** A legacy connection authenticates by a static PSK. Anyone who learns the PSK can impersonate
  the peer. Mitigation: owner-only file, a PSK per peer (never shared), a length floor on generation (`acxelin-vpn ca`-style helper),
  and the end date.
- **Harvest now, decrypt later.** Traffic over the classical tunnel is exactly what the product exists to protect against. The fallback
  moves it outside that protection; it does not make it safe. The warning text says this plainly, and the manual's Limits section says
  the VPN as a whole is quantum safe only for `strict` peers.
- **Config drift.** A date that is renewed forever defeats the purpose. The doctor warning and a metric on the remaining time are
  the only brakes; making renewal require a changed `transition_reason` field is one option (open question 3).
- **Weakest link.** A site with one classical peer is not "post-quantum" in an audit. Readiness's grading of the CBOM should lower the
  site's grade; whether it does depends on how the property is read.

## Tests that would prove it

Written first, in the existing places (`test_vpn.py`, `test_inventory.py`, `test_console.py`, the namespaces tests in CI):

1. Default: no `policy` means `strict`; `conn_config` for it is byte-identical to today's; a peer offering no ML-KEM is refused (the existing behaviour).
2. Validation: `transition` needs `transition_until` (future, at most 12 months) and a readable owner-only PSK file; unknown values, `cnsa2` sites and a
   world-readable PSK file are refused with a clear message.
3. The `transition` `conn_config` has a classical proposal and no `ppk_required`; every other peer's `conn_config` is unchanged when one peer is
   `transition` (isolation).
4. The attack refused, in strongSwan namespaces (CI only): a `strict` peer and an on-path attacker that strips the ML-KEM
   transform from IKE_SA_INIT gets `NO_PROPOSAL_CHOSEN`, never a classical tunnel.
5. Pinning: a name that has agreed PQ keys cannot be loaded as `transition`; the refusal is audited; `forget-pq` lifts it and is audited.
6. Expiry: past `transition_until` the classical connection is unloaded, the tunnel cut, and the peer refused, as with `enforce_freshness`.
7. Labels: log line, `/status`, metrics, CBOM property, console badge and `doctor` output all contain the words, and none contains the PSK
   (extending the CBOM secret-search test).
8. The report: a peer that offers only classical proposals shows in `refused_no_pq` and in `report-legacy`; one that is PQ never does.
9. `protected()` is false for a classical tunnel even when ESTABLISHED with an installed child.

## Consistency with the TLS product

Same words and the same shape: `strict` default, `transition` opt-in, a `doctor` warning, "fine while you migrate, not for everything".
Differences, on purpose: the VPN setting is per peer and time-limited, and its fallback is not "also accept classical clients" but
"this named device, this date". The TLS `transition` has neither limit, so a decision on 3 below would make the two behave the same way.

## Open questions for the owner

1. **Is the feature wanted at all?** Refusing is a clean position ("nothing connects that is not post-quantum"). A fallback is the first
   thing that makes the product's headline conditional.
2. **A middle tier.** A peer with RFC 8784 (PPK) but not RFC 9370 would be quantum-resistant with a strong, secret PPK, though without a
   hybrid key exchange. Delivering a rotating PPK needs our controller on the peer, which is the thing it lacks, so it would be a static PPK. Is a
   `ppk-only` policy worth specifying separately from `transition`, and what would it be called in the audit language?
3. **Time limits.** Is a mandatory end date acceptable, and should TLS `transition` get the same? What stops a renewal every year?
4. **Detection.** Is it acceptable to ship the "observed" layer only if the VICI log carries the offered proposals (to be checked on strongSwan
   6.1), and otherwise count refusals without proposals?
5. **Authentication.** Static PSK only, or classical certificates from the customer's own CA as well? (Acxelin's CA issues ML-DSA only and
   strongSwan 6.1 cannot load those for IKE.)
6. **Grading.** Should Readiness grade a site with one `transition` peer as classical for the whole site, or per tunnel?
7. **Breaking change.** Additive, so no 1.x break; confirm that an additive CBOM property and `/status` field fit the "wire formats do not
   change" rule as the owner reads it.
