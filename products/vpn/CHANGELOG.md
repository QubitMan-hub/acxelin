# Changelog

## 1.2.0

- `acxelin-vpn kme`: a key server for gateways that ask for keys over ETSI GS QKD 014 (Juniper SRX and MX, Fortinet FortiGate,
  Palo Alto and others). The key servers of two sites agree a new shared secret over post-quantum mutual TLS every
  `rotate_minutes`; a gateway gets keys by `enc_keys`, the gateway at the other site gets the same keys by ID with `dec_keys`,
  each once. Keys of 128 to 1024 bits, up to 16 per request. Tested with this product's own ETSI 014 client, not yet with a
  vendor's gateway. See the manual, "Keys for the gateways you already have".
- Fixed: a full-tunnel laptop renews its keys with DNS blocked by its kill switch; before, it used fresh name lookups and lost
  the tunnel for good when its DNS server was unreachable.
- Fixed: when the address pool is full, the address of someone not connected (revoked or gone) is reused, so people who left
  cannot keep the pool full; a laptop refused for a full pool is told so.
- Fixed: `config/gateway.toml` uses ports 7444 and 9102, so it runs beside the headquarters site (7443, 9101) as the manual
  describes; the manual's invitation uses 7444.
- Fixed: `doctor` no longer fails a gateway `setup` just made because its WireGuard key does not exist yet (it is created on
  first start); `setup` checks the pool, routes and DNS before writing anything; `rotate_minutes` is limited to 1440, the
  most a laptop accepts; a tunnel that stays silent after new keys is rebuilt instead of re-agreeing keys every 5 seconds.
- `evidence create` and `evidence verify`: one signed zip with a site's or gateway's build, configuration, `doctor`'s findings, certificates (public parts), its CBOM and what it reports while running (`--status`). Keys, passphrases and a partner's pre-shared keys never go in.

## 1.1.1

- New profile `cnsa2-rfc9370`, the form NSA's CNSA 2.0 FAQ (ver. 2.2, October 2026) gives for IKEv2: a P-384 exchange, then ML-KEM-1024 (RFC 9370), with AES-256-GCM and SHA-384. The older `cnsa2` (ML-KEM-1024 alone) is not NSA's IKEv2 form; it still loads and works unchanged in 1.x so running tunnels stay up, and the gateway warns at start. Move both gateways of a tunnel to `cnsa2-rfc9370` together: the two profiles do not negotiate with each other.

## 1.1.0

- On Windows the client waits until the tunnel service has loaded the gateway as its peer before it carries on. The service answers before it has applied its configuration, so a key set at once could find no peer (seen in CI as an empty `wg show`).
- Classical fallback for a partner gateway that cannot do hybrid ML-KEM: `classical_fallback = true` on that one `[[peer]]` (off by default, no site-wide form) with a static `fallback_psk_file` and an optional `fallback_ppk_file`. It offers hybrid ML-KEM first, then classical with the RFC 8784 PPK, then plain classical. Anything below hybrid is labelled NOT QUANTUM SAFE in the log, `/status` (`quantum_safe`, `tier`), the metrics (`acxelin_vpn_tunnel_quantum_safe`, `acxelin_vpn_tunnel_tier`), the CBOM (`acxelin:quantum-safe`) and the console. Every other peer's strongSwan configuration is unchanged byte for byte.
- **Behaviour change:** when a laptop's key renewal fails while its tunnel still works, it stays on its last key, shown as **Degraded** in the tray, the window and `status`, for at most `keep_minutes` (15 by default, 0 to 1440; set per person with `invite --keep-minutes` or per computer with `connect --keep-minutes`; 0 restores dropping at once). Before, it dropped a working tunnel within seconds. A revoked computer, or a gateway that cannot read its revocation list, is cut off at once; with a full tunnel, a timed-out agreement drops at once (the tunnel is dead). Client only: nothing on the wire changed; `keep_minutes` is an optional invitation field older apps ignore.
- Found in a first-time customer test: the commands `setup` prints quote paths with spaces, so they work when copied (a folder such as `C:\Users\First Last` broke them); `access` shows who is limited when no action is given; messages, comments and the manual no longer assume a person's gender.
- Per-user route sets: `[wireguard.access]` limits a person to some of the gateway's `routes`. The person is told only those networks, and a Linux gateway that manages its interface loads nftables rules that drop everything else from their tunnel address (forwarded traffic and traffic to the gateway itself) before they hear their address; if the rules cannot be loaded they are refused, and the gateway will not start without `nft`. `acxelin-vpn access show` and `access rules` show who is limited and print the rules for a firewall you run yourself. Changes apply while running; one whose rules cannot be loaded is not applied. People with no entry are unchanged. The refusal a laptop sees when the gateway says no now lists the usual reasons.

- A revoked laptop is told it was revoked on Windows too: the gateway now reads the laptop's request before it refuses, because closing with it unread makes Windows reset the connection and drop the refusal (the laptop saw "key agreement message missing").
- The tray's app window is opened through the owner-only launch page too, so no launch ticket is on any command line.
- Security: the console and `acxelin-vpn app` open the browser through an owner-only page, so the launch ticket is not on
  the browser's command line, where other users of the machine could read it.
- Security: everything a gateway sends that goes into the laptop's WireGuard configuration (address, routes, DNS, endpoint,
  rotation) is checked to be exactly what it claims to be. A newline there used to add a command that wg-quick runs as root, so
  whoever could answer as the gateway could run code on the laptop.
- Security: revoking a person in the console happens under the CA lock that renewals take, so a renewal racing the revocation
  cannot leave a valid certificate behind.
- Security: `sudo acxelin-vpn join` hands the device folder back to the person without following links planted in it; before,
  a link let a local user take ownership of any file.
- A key agreement message must arrive within 5 seconds in all, so peers that send a byte at a time cannot hold the key
  agreement service.
- A failed call to the QKD key server no longer ends a site's key agreement for good; it is retried like any other failure.
- Status and metrics on an address other than this machine's log a warning: they answer without a login and list every person.
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
- Outage grace, opt-in: `outage_grace_minutes` (0 to 1440, default 0, which behaves exactly as before) in `[wireguard]` and on a
  site's `[[peer]]` keeps a person or peer that has stopped agreeing keys on its last keys for up to that long past the normal
  limit, instead of removing them after 6.5 minutes (remote access) or cutting the tunnel after three rotations plus two
  minutes (sites). The cap is hard; the grace applies only while the CRL is present, signed by your CA and not expired (it needs
  `crl`); revocation is checked first and is never delayed. `/status` and the metrics show who is in grace and for how long
  (`in_grace`, `acxelin_vpn_wireguard_client_in_grace`, `acxelin_vpn_tunnel_in_grace`, `events_total{event="grace_used"}`),
  and the log has one warning line on entering and one on leaving. A running gateway applies a changed value without a restart.
  Limits: for remote access the computer's own software still takes its tunnel down when its key agreement fails, and a gateway
  restart is not covered. Tested with stand-ins for `wg` and charon; `docs/outage-drill.md` and `tools/outage_drill.sh` are how
  to try it on two real machines (not yet run).
- A CRL file that disappears while the gateway or a site is running is now treated like any unusable CRL: laptops and peers that
  stopped renewing are still removed or cut. Before, the check failed with a file error and removed no one in that pass.
- `/status` of a site gains `in_grace` for every peer (false unless the outage grace is in use).
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
