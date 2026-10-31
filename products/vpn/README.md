# Acxelin VPN

Post-quantum site-to-site IPsec and WireGuard remote access, with a desktop app. Each tunnel's keys are agreed over TLS 1.3 with
hybrid ML-KEM and ML-DSA certificates from your own certificate authority, and rotated; a revoked site or person is cut off
within 15 seconds.

- **Sites:** strongSwan between Linux gateways, hybrid ML-KEM in IKE plus a post-quantum PPK.
- **People:** a WireGuard gateway, an invitation file per person, and the desktop app for Windows, macOS and Linux.
- **Administrators:** the certificate authority, a local console, health checks and a CBOM of what the VPN uses.

## Install

The administrator's command line needs Python 3.11 to 3.14 and OpenSSL 3.5 or newer. It installs for your user only, without
internet access, on Linux (x86-64, ARM), Windows (x64) and Apple-silicon Macs:

1. Download `acxelin-vpn-1.0.2-wheelhouse.tar.gz` and `SHA256SUMS` from the [release page](https://github.com/AcxelinQuantum/AQPQCSuite/releases/tag/vpn-v1.0.2).
2. Check the download: `sha256sum -c SHA256SUMS --ignore-missing` should print `OK` (on macOS and Windows, compare the fingerprint by hand; the manual shows how).
3. Unpack it: `tar xzf acxelin-vpn-1.0.2-wheelhouse.tar.gz`, then `cd acxelin-vpn-1.0.2-wheelhouse`.
4. Install: `sh install.sh`, which puts `acxelin-vpn` on your PATH. On Windows, `Unblock-File .\install.ps1`, then `powershell -ExecutionPolicy RemoteSigned -File .\install.ps1`.

Gateways use the gateway image or systemd, and people use the desktop app; the manual covers both.

## First steps

```
acxelin-vpn doctor
acxelin-vpn setup vpn.acme.example --route 192.168.10.0/24
```

`setup` creates the certificate authority, the gateway's certificate and a checked `gateway.toml`, then prints the commands
that start enrollment and the gateway and invite the first person.

The manual (`docs/manual.md`) covers two sites and a laptop in fifteen minutes, the console, the app and production.
`docs/threat-model.md` says what is and is not protected.

| In this folder | |
|---|---|
| `config/` | a headquarters site, a branch site and a WireGuard gateway, every setting explained |
| `deploy/` | the gateway image's Dockerfile and the systemd units |
| `packaging/` | how the desktop installers are built |

© 2026 Acxelin Quantum, all rights reserved.
