# Changelog

## Unreleased

- Security fix: the tray app and `acxelin-vpn install` no longer run code that an ordinary user can change with administrator
  rights. When the VPN was installed for one user (the default of `install.sh` and `install.ps1`, or `pip install --user`), the
  tray started the VPN service as root or administrator from that user's own Python and folders, and passed it the user's
  import path, and `acxelin-vpn install` made a boot service that ran them as root or SYSTEM. Anything running as that user
  could change those files, then wait for the administrator prompt or the next boot, and become the administrator. Now both
  refuse, and say why, unless the interpreter, every folder it imports from and the folder OpenSSL is loaded from can be
  written only by administrators; the elevated process and the boot service start with `-I`, so they ignore `PYTHONPATH`, the
  user-site folder and the current folder. Affected: every earlier release with the desktop app or `acxelin-vpn install`, when
  installed for one user. Also fixed: on Windows the elevated process took OpenSSL from `ACXELIN_OPENSSL` or `PATH`, which the
  user controls, so the Windows Setup was affected too (the packaged launcher now replaces `ACXELIN_OPENSSL` instead of keeping
  a value already set, and elevation needs it set); the Windows boot script moved from `ProgramData`, where users can make
  folders, to `Program Files` (run `acxelin-vpn install` again to move it). The Linux package (`/opt/acxelin-vpn`) installs
  where users cannot write. On macOS the tray no longer starts the service from Applications, which any administrator account
  can change: run `sudo acxelin-vpn app`. The Windows and macOS rules are checked by unit tests, not on those systems.
  `sudo acxelin-vpn app`, run by an administrator on purpose, is unchanged.
- `acxelin-vpn setup NAME`: a remote-access gateway in one step: the CA (or the existing one), the gateway's certificate, the
  CRL and a checked `gateway.toml`, then the commands that start enrollment and the gateway and invite the first person.
- Console, People: traffic, when each person's key was last renewed (and the last handshake), gateway uptime, and an access
  history from each gateway (connected, new device, refused and why, cut off, disconnected) beside the administrator's own
  actions. Gateways keep that history in an owner-only `audit.jsonl` next to their leases; key renewals are not logged.
- Site-to-site keys from quantum key distribution: with `qkd_kme` and the other `qkd_` settings in `[site]` and `qkd_sae_id`
  on a peer, a key from the site's QKD key server (ETSI GS QKD 014, over mutual TLS) is mixed into the IPsec PSK and PPK with
  HKDF-SHA384. It adds to the post-quantum keys and never replaces them; a missing QKD key stops the agreement instead of
  weakening it. Tested against a simulated key server, not real QKD hardware.
- A new invitation now replaces a revoked or expired device certificate, in `join` and in the app. Before, it was ignored once
  the device had a certificate.
- Laptops renew their own certificate within 30 days of its end, so they keep working past a year.
- Security: a gateway whose CRL cannot be used still removes laptops that stopped renewing their key. Before, they kept their
  last key until the CRL was fixed.
- Security: one person can no longer take over another's WireGuard key, and the service log of the desktop app never follows
  a link planted in its folder.
- A revoked laptop is told it was revoked (the app and `status` say so) instead of "key agreement message missing".
- A gateway whose `name` differs from its certificate refuses to start: the laptops would derive a different key.
- `acxelin-vpn disconnect` stops a running `join`, app or service instead of being undone at the next rotation.
- Under the kill switch, reconnecting uses the gateway's addresses resolved before DNS was blocked.
- Revoked people's addresses return to the pool; new `sites` subnets get routes on a live reload; the console uses `./pki`
  when it exists; a container without forwarding says to add `--sysctl net.ipv4.ip_forward=1`.

- A strict profile, `profile = "cnsa2"`: only the NSA's CNSA 2.0 suite. IKE and ESP use ML-KEM-1024 alone with AES-256-GCM
  and SHA-384, and the gateways' key agreement allows only ML-KEM-1024, ML-DSA-87 certificates and AES-256; a gateway whose
  certificate is not ML-DSA-87 refuses to start. Every peer of a site uses it or none. The CBOM lists the strict key agreement
  separately. Checked by unit tests; not yet run against strongSwan in the two-site test.
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
