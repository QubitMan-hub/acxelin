# VPN client: keep the last good key when a key agreement fails (design, not built)

Status: proposal for the owner. Nothing here is implemented. It follows stage 4, where the gateway and the sites gained an
opt-in outage grace (`outage_grace_minutes`). That grace is no use to a laptop if the laptop takes its own tunnel down first.

## The question

Can a laptop keep its tunnel on the last good pre-shared key when a key agreement fails, **with no change to anything on the
wire**? CLAUDE.md rule 5: wire and cryptographic formats do not change.

## The answer: yes. The client change is one condition. The gateway sees nothing different.

### What the shipped client does

`Client.step` (`products/vpn/src/acxelin_vpn/wireguard.py`, lines 497–506) runs, after any failed agreement:

```python
if self.apply_ and self.tunnel.up_:
    log.warning("taking the tunnel down to reach the gateway directly")
    self.tunnel.down()
    retry = 1
```

The reason is written in the class docstring: "a tunnel that stopped working is taken down so the gateway can be reached
directly". It is right when the tunnel is broken. It is wrong when only the key agreement port (TCP 7443 by default) is
blocked, slow or down while WireGuard (UDP) still handshakes: the tunnel was healthy and the client kills it.

### Evidence (run on this machine, real `Client`, real CA and device certificate, a stand-in tunnel that records calls)

The script is `review/evidence/vpn_client_grace.py` (run `python review/evidence/vpn_client_grace.py` from the repository root with the VPN installed); its output is pasted unedited. "Handshake 12 s old" means WireGuard is working.

```
== 1. shipped step(): agreement fails, WireGuard handshake is 12 s old (tunnel healthy)
key agreement failed: cannot reach the keyring (partition); retrying in 5s
taking the tunnel down to reach the gateway directly
   tunnel calls: ['down'] | tunnel up: False | retry in: 1 s
== 2. the same step() with one changed condition: tear down only when the tunnel itself looks dead
key agreement failed: cannot reach the keyring (partition); retrying in 5s
   handshake 12 s old (healthy): tunnel calls: [] | tunnel up: True | status: not_protected, error: 'cannot reach the keyring (partition)'
key agreement failed: cannot reach the keyring (partition); retrying in 5s
taking the tunnel down to reach the gateway directly
   handshake 200 s old (gateway no longer answers): tunnel calls: ['down'] | tunnel up: False | status: not_protected, error: 'cannot reach the keyring (partition)'
```

Run 2 changes only `if self.apply_ and self.tunnel.up_:` to `if self.apply_ and self.tunnel.up_ and self.quiet():`.
`quiet()` already exists: true when the WireGuard handshake is older than 180 seconds. `agree()`, the messages it sends and
everything the gateway receives are untouched. What the run does **not** show: a real WireGuard tunnel across a real
partition. That is what the two-VM drill (`products/vpn/docs/outage-drill.md`, Run 1) is for.

### Why no wire change is needed

The gateway is already the authority. It decides how long a silent laptop keeps its place (`3 × rotate + 30 s` plus the
customer's `outage_grace_minutes`, never beyond the cap) and it removes a revoked one within 15 seconds. The laptop learns the
outcome from WireGuard itself: once the gateway removes the peer, handshakes stop, `quiet()` turns true within about three
minutes, and the client takes the tunnel down as it does today. So:

| Situation | Today | With the change |
|---|---|---|
| Key agreement port blocked, WireGuard fine, gateway grace 0 | Laptop drops its tunnel within seconds | Laptop keeps working about 6.5 minutes, until the gateway removes it, then drops within about 3 more |
| The same, gateway grace 30 min | Laptop drops within seconds, the gateway's grace is wasted | Laptop keeps working while the gateway keeps it, then drops |
| Laptop revoked during the outage | Laptop already dropped | Gateway removes it within 15 s; handshakes stop; laptop drops within about 3 min |
| Tunnel broken (gateway restarted, route gone) | Torn down in seconds, direct retry | Unchanged: handshake goes stale, torn down |

## Compatibility with 1.x

No gateway needs to change, and no client needs to learn anything from a gateway.

| Gateway | Client | Result |
|---|---|---|
| 1.x (any) | with the change | Works. The gateway still removes a silent laptop after `3 × rotate + 30 s`; the client keeps its tunnel until then |
| with grace | 1.x as shipped | Gateway grace is wasted: the laptop drops itself (today's behaviour, unchanged) |
| with grace | with the change | The pair rides out the outage up to the customer's cap |

## Proposed change (client only)

1. `Client.step`: tear the tunnel down after a failed agreement only if it looks dead (`quiet()`), or if a client-side bound
   has passed (next point). Otherwise keep it and retry the agreement with the existing back-off (5, 10, 20, 40, 60 s).
2. **A client-side bound**, so a half-broken tunnel (fresh handshakes but no data, which also blocks the agreement that
   travels through it in full-tunnel mode) cannot hold the laptop forever. Proposal: `keep_minutes`, default 15, 0 meaning
   today's behaviour, set per computer with `--keep-minutes` and, for the administrator who wants one value for everyone, as
   an **optional** field `keep_minutes` in the invitation. The invitation parser (`join.parse`) ignores unknown keys and
   `join.py` rewrites only the fields it knows (`FIELDS`), so an older client reading a newer invitation drops the field and
   behaves as today; a newer client reading an older invitation uses its default. No version bump of `acxelin_invite: 1`.
3. Status wording: with an error and a healthy tunnel the client says "protected on the last key; renewal failing since
   HH:MM, N minutes of M left" instead of "not protected". Today `status()` reports `not_protected` whenever `error` is set.
4. Metrics and log: `client_on_last_key` gauge and one warning line on entering and one on leaving, like the gateway's grace.
5. Documentation: manual sections on the app and on outages; CHANGELOG entry as a **behaviour change**, since a 1.x laptop
   will now stay up where it used to drop.

## Tests that would prove it

- The shipped drop is gone: failed agreement + fresh handshake → no `down()` (the run above, as a test).
- Stale handshake → `down()` and a retry in 1 s, as today.
- `keep_minutes` bound honoured, including 0 (old behaviour) and a value in the invitation; an older-format invitation and one
  with an unknown field both parse.
- Revocation: a revoked laptop (agreement answers `revoked`) drops at once, never "kept on the last key".
- A reason of `crl` from the gateway (it cannot read its revocation list) is also not kept on the last key.
- Kill switch stays on while the tunnel is kept, and stays on after the drop.

## Risks and limits

- A laptop stays on a key older than designed for up to the bound. The same trade-off was accepted for the gateway grace;
  nothing is weakened for revocation, because the gateway ends the session.
- The 180-second handshake threshold means a laptop can believe a dead tunnel is alive for up to three minutes after the gateway
  removes it. Today it recovers in seconds. A shorter threshold would need WireGuard handshake data the client does not have.
- The agreement in full-tunnel mode travels through the tunnel. If the tunnel is healthy but the keyring is unreachable *through
  it*, the bound is what ends the stalemate. Routing the agreement outside the tunnel is a second option (a host route for
  the keyring address per platform); it is larger and platform-specific, and is not needed for this proposal.
- Sites are separate: strongSwan has its own SA lifetimes (see the outage drill and `review/vpn.md`).

## For the owner

1. Is a default `keep_minutes` of 15 right, or should the client keep until the gateway ends it (no client bound), or be off
   by default?
2. Is a behaviour change in a 1.x patch acceptable, or should this wait for 1.1.0?
3. Should the administrator's invitation carry the value (optional field, backward compatible), or only the computer?
