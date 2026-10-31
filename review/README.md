# Review pack

For an outside auditor or penetration tester. One file per component:

| File | Covers |
|---|---|
| [core.md](core.md) | The shared mechanisms: files, console, OpenSSL binding, TLS contexts, CA, CRLs, signers, EST |
| [tls.md](tls.md) | Acxelin TLS: the edge, the CA commands, ACME, console |
| [vpn.md](vpn.md) | Acxelin VPN: key agreement, IPsec and WireGuard control planes, the desktop app |
| [readiness.md](readiness.md) | Acxelin Readiness: scanners, endpoint probes, remote repositories, console |
| [standards.md](standards.md) | What was checked against official sources and what could not be |

Each file has the same parts: data flow, trust boundaries, where each key is created, stored, used and destroyed, every
security claim with the test that shows it (the attack refused, not only the good path), the claims that have no test, and the
limits next to them.

## How to read it

- A test is written file::function. `tools/tests/test_threat_model_citations.py` fails when a test named in a threat model
  or in this folder does not exist, so a rename cannot leave a stale claim behind. It checks that the test exists, not that it
  proves the claim: that judgement is the reviewer's, and the tables say what each test does.
- "Not tested" means no test was found when this pack was written. It is not a statement that the behaviour is wrong.
- "CI only" means the test needs root, a second network namespace or another operating system, so it runs in the workflows in
  `.github/workflows` and is skipped on a laptop.

## Run the tests

```
pip install -e ./core -e "./products/readiness[crawler,test]" -e "./products/tls[test]" -e "./products/vpn[vpn,test]" ruff==0.14.0
export ACXELIN_OPENSSL=/path/to/openssl-3.5/lib LD_LIBRARY_PATH=/path/to/openssl-3.5/lib ACXELIN_REQUIRE_OPENSSL=3.5
python -m pytest -q core/tests products/tls/tests tools/tests
python -m pytest -q products/readiness/tests website/tests
python -m pytest -q products/vpn/tests
```

With `ACXELIN_REQUIRE_OPENSSL=3.5` set, an OpenSSL that is not 3.5 stops the run. Without it, tests that need OpenSSL 3.5 are
skipped and the run still passes, which proves nothing about the line customers run.

## What this pack does not establish

- Behaviour on a customer network: middleboxes, load balancers, real HSMs or cloud KMS accounts, commercial IKEv2 peers.
- Anything about FIPS validation. No product here is FIPS validated and none claims to be. The OpenSSL 3.5 FIPS provider's
  validation status has not been confirmed from NIST's own list (see [standards.md](standards.md)).
- Performance. No benchmark has been published or should be quoted.

## Where anything runs with administrator rights

Audited in stage 1b across core and the three products. Only the VPN starts anything with elevated rights itself.

| Where | What runs elevated | Code location it needs | Guard |
|---|---|---|---|
| VPN tray (`desktop.start_service`) | `acxelin-vpn app` through pkexec, osascript or UAC | Interpreter and every import folder writable only by administrators; a packaged app only its own program | `platforms.require_protected_code`, before any prompt; the process starts with `-I`; `test_elevation` |
| `acxelin-vpn install` (`platforms.install`) | A systemd, launchd or SYSTEM scheduled-task service running `connect` at boot | The same | The same guard, before the unit is written; `test_elevation` |
| VPN systemd units (`deploy/systemd`) | `up`, `gateway` and strongSwan as root; `ca serve` and `ca maintain` as `acxelin` | Under `/opt/acxelin-vpn` and `/opt/strongswan`, which an administrator creates (manual section 3) | `test_elevation::test_the_boot_units_that_run_as_root_start_programs_under_opt`. A check on the machine itself is not made: an administrator who points a unit at a per-user install defeats it |
| `sudo acxelin-vpn ...` typed by an administrator | Whatever that install contains | Not checked: it is the administrator's own act | Documented in the VPN threat model |
| TLS and Readiness | Nothing: their systemd units run as `acxelin`, the Docker images as `acxelin` and `scanner` | | |
| VPN Docker image | The gateway as root in the container, from the system Python | Root-owned | |
