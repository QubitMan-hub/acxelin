# Acxelin Quantum products

Post-quantum security products, each standalone: its own package, command, console, documentation, installer, tests and
release. A customer installs only the product that fits their problem.

| Product | Folder | Command | Status |
|---|---|---|---|
| **Acxelin Readiness + CBOM**: find the cryptography in code, configuration, keys and endpoints, write a CycloneDX 1.6 CBOM, and rank what to migrate | [`products/readiness`](products/readiness/README.md) | `acxelin-readiness` | 1.0.0 |
| **Acxelin TLS/mTLS + CA**: post-quantum TLS 1.3 in front of any TCP service, mutual TLS, and an ML-DSA certificate authority | [`products/tls`](products/tls/README.md) | `acxelin-tls` | 1.0.0 |
| **Acxelin VPN**: site-to-site IPsec with hybrid ML-KEM, WireGuard remote access and the desktop app | [`products/vpn`](products/vpn/README.md) | `acxelin-vpn` | 1.0.0 |

Start with a product's own README: install (one command: `products/*/install.sh`, or `install.ps1` on Windows), first
steps, the console and the manual. The website is https://acxelinquantum.github.io/AQPQCSuite/.

## Repository layout

```
core/                 acxelin-core: shared mechanisms only (config, safe files, OpenSSL 3.5 binding, TLS contexts, CA, CRLs,
                      signers, EST, the console shell); no product names or policies
products/readiness/   Acxelin Readiness + CBOM: src, tests, docs, examples, deploy (Docker), action.yml, installers
products/tls/         Acxelin TLS/mTLS + CA: src, tests, docs, examples, deploy (Docker, systemd), installers
products/vpn/         Acxelin VPN: src, tests, docs, config, deploy (gateway image, systemd), packaging (desktop installers), installers
website/              the shared home page and one section per product, built by tools/build_site.py
tools/                repository tooling: the site build, release gate, wheelhouse, browser test kit
```

No product imports another, and core works with nothing else installed; tests enforce both.

## Working on this repository

[CONTRIBUTING.md](CONTRIBUTING.md): the test commands per product, how releases work (one tag per product, core first),
and the rules every change follows. Security reports: [SECURITY.md](SECURITY.md).

© 2026 Acxelin Quantum, all rights reserved. See [LICENSE](LICENSE).
