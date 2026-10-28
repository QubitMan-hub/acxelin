# Changelog

## Unreleased

- Windows: `install.ps1` writes its command wrapper in the console code page, so a user name such as José keeps its
  path. ASCII turned it into `Jos?`.

## 1.0.2

- Console: create the certificate authority in the console instead of the command line. The People tab asks where
  invitations point first, before the invite form. Errors scroll into view.

## 1.0.1

- Windows: `install.ps1` no longer stops at Python's `>>>` prompt on computers with the `py` launcher (Python from
  python.org or the Microsoft Store). It passed `py` its `-3` one character at a time.

## 1.0.0

First release of Acxelin VPN.

- Site-to-site IPsec and WireGuard remote access, with the certificate authority commands the VPN needs:
  `ca init`, `issue`, `revoke`, `crl`, `maintain`, `list` and `serve` (the enrollment service invitations use).
- An administrator console for sites, people and health: see each tunnel and its algorithms, invite a person and download their
  invitation, see who is connected, and revoke someone.
- `acxelin-vpn inventory --cbom` writes the VPN's cryptography as a CycloneDX 1.6 CBOM, without any key or secret in it.
- The key agreement uses TLS 1.3 only, hybrid ML-KEM key exchange (X25519MLKEM768, SecP384r1MLKEM1024 or
  SecP256r1MLKEM768) and ML-DSA certificates.
- Deploys with the gateway Docker image (strongSwan 6.1, OpenSSL 3.5), systemd units, or the installers. The desktop app ships as
  a Windows Setup, a macOS disk image and a Linux package.
- `doctor --json`, for scripts and the installer check.
- The app and `status` say when the key was last renewed, warn in words when renewals stop, and count failed renewals.
- One audit log beside the CA for invitations and revocations from the console and the command line; the People tab merges in
  enrollments and renewals. Each laptop logs its own kill-switch changes.
- A full manual (`docs/manual.md`), shipped in the release folder with the README, licence, example settings and systemd units.
