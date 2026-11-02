# Upgrade and rollback

`tools/tests/test_upgrade_rollback.py` runs the released code and the code in this tree against the same files, in both directions.
Baselines are the commits the released versions were built from (`tools/baselines.json`; this repository has no tags). Their source is
extracted with `git archive` and run in a separate process, so the old code is the old code. CI checks out the full history for it.

| State | Old creates, new reads and extends | New extends, old reads and extends again |
|---|---|---|
| CA folder (index, CRL, CRL number) with core 1.0.0 and 1.1.0 | records identical, revoked still refused, CRL number rises | records identical, revoked still refused, CRL number never reused |
| TLS edge config (TLS 1.0.2) | same routes, `shadow` off | a config with `shadow = true` is refused by 1.0.2 naming the key, never silently ignored |
| VPN invitation (VPN 1.0.2) | read the same | an unknown field is ignored |
| Readiness CBOM as `--baseline` (1.0.2) | nothing new, gate passes | same the other way |

**Found while writing it:** relative paths in an edge config are read from the file's folder since TLS 1.1.0 (developed as 1.0.3, never released), not the working folder.
That was listed as a fix; the CHANGELOG now calls it a behaviour change, and a test pins it.

**Found on the merged tree:** the EST-renewal revocation change added a `replaces` field to every CA record, so a CA written by this tree could not be read by 1.1.0 or 1.0.0 at all (the first CA test failed exactly that way). The field is now written only for an EST renewal. A CA that holds one still cannot be read by the older releases: stated in the core CHANGELOG.

**Not covered:** VPN leases and key agreement across versions (needs two machines: the outage drill), the Windows and macOS installers
over an older install, Readiness project stores and the console, TLS ACME account state, CAs on KMS or an HSM. Each needs its own baseline
fixture; none was run here.
