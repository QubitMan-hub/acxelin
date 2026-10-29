# CLAUDE.md

Acxelin Quantum's post-quantum products, each standalone. The owner develops on Windows with PowerShell, prefers minimal code
with few comments, wants limits stated honestly and pushes back on overclaiming.

## Layout

- `core/` (acxelin-core): mechanisms only: config, safe file writes (owner-only secrets, Windows ACLs), loopback HTTP, the
  console access contract and shell, the OpenSSL 3.5 binding, TLS contexts, CA, CRLs, signers (KMS, signing command), EST.
  No product names, policies or commands.
- `products/readiness/` (acxelin-readiness): Readiness + CBOM: scan, grade, report, merge, doctor, console.
- `products/tls/` (acxelin-tls): TLS/mTLS edge, the CA commands, ACME, console, Docker, systemd.
- `website/`: the shared home page and one section per product (`tools/build_site.py`); demo content is real product output.
- `products/vpn/` (acxelin-vpn): site-to-site IPsec, WireGuard remote access, the desktop app and its installers, the VPN's
  CA subset, console and CBOM export, the gateway image and systemd units.
- `documents/`: plain-language "How It Works" guides per product, Markdown plus PDF, exported from the owner's docs.
- `tools/`: the site build, release gate, wheelhouse, browser test kit, and the repository checks in `tools/tests`.

## Rules

1. No product imports another; core works with nothing else installed. Tests enforce both.
2. Python only. Runtime cryptography is `cryptography` plus OpenSSL 3.5 through core's binding; never the `openssl` command.
3. Must work on Windows: pathlib, UTF-8, no POSIX-only code outside the VPN and signal handling.
4. Tests for intended behaviour first; every security behaviour has a test that shows the attack refused. Never weaken or
   delete a test to pass.
5. Wire and cryptographic formats do not change. Readiness reads Wolf Pack's old names (`wolfpack:ignore`, `.wolfpack.toml`,
   `wolfpack:*` CBOM properties) through its 1.x line with a warning; new names win. Breaking changes go in
   the product's CHANGELOG. Wolf Pack is otherwise gone: no product, page, command or path uses its name.
6. Readiness's labelled corpus is a CI quality gate: precision and recall must not drop; `truth.json` changes only in
   commits titled `truth:` that the owner approves.
7. Consoles: loopback only (`--container` in Docker), single-use launch tickets in the URL fragment, session tokens in
   sessionStorage, no cookies, Host and Origin checks, lockout after 10 wrong attempts a minute, no secrets in URLs or logs.
8. Customer-facing pages use Acxelin's style. Proprietary licence: "© 2026 Acxelin Quantum, all rights reserved".
9. Releases are per product by tag, core first (`core-vX.Y.Z`, then `tls-vX.Y.Z`, `vpn-vX.Y.Z`, `readiness-vX.Y.Z`); the owner decides
   when. PyPI uploads are blocked on purpose.
10. The mentor's AcxelinPQC repository is a feature reference only; never copy its code.
11. A stage is done only on executed evidence; report failures and skips with their causes.

## Commands

```
pip install -e ./core -e "./products/readiness[crawler,test]" -e "./products/tls[test]" -e "./products/vpn[vpn,test]" ruff==0.14.0
ruff check .
python -m pytest -q core/tests products/tls/tests tools/tests
python -m pytest -q products/readiness/tests website/tests
python -m pytest -q products/vpn/tests          # run each product's tests separately (same-named test files clash)
```

On Linux set `ACXELIN_OPENSSL` and `LD_LIBRARY_PATH` to an OpenSSL 3.5+ lib folder.
