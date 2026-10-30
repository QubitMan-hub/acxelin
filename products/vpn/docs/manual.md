# Acxelin VPN manual

Acxelin VPN connects your sites over IPsec and your people over WireGuard. Each tunnel's keys are agreed over post-quantum mutual TLS (hybrid ML-KEM key exchange, ML-DSA certificates from your own certificate authority) and rotated. Traffic recorded today cannot be decrypted later by a quantum computer that breaks the classical half alone.

This manual covers installing it, two sites and a laptop in fifteen minutes, the everyday work, the console and the desktop app, running it in production, and what to do when something goes wrong. Acxelin VPN installs and runs on its own; it needs no other Acxelin product.

## 1. What you get

| Part | What it does |
|---|---|
| **Site-to-site IPsec** | strongSwan between Linux gateways. The IKE key exchange is hybrid (X25519 + ML-KEM-768, or P-384 + ML-KEM-1024), and a post-quantum pre-shared key (PPK, RFC 8784) agreed over ML-DSA mutual TLS is mixed in. |
| **Remote access** | A WireGuard gateway for people's computers. Each computer's pre-shared key is agreed over ML-DSA mutual TLS and replaced every two minutes. Revoking a person cuts their tunnel. |
| **The desktop app** | A tray icon on Windows, macOS and Linux that says whether this computer is protected, and a window to join from an invitation file, connect and disconnect. |
| **The certificate authority** | Issues and revokes the ML-DSA certificates gateways, sites and people use, keeps the revocation list fresh, and runs the enrollment service invitations use. |
| **The console** | A local web page for the administrator: each site's tunnels, invitations, who is connected, revocation, and health checks. |

A key agreement that cannot meet the VPN's policy (TLS 1.3, hybrid ML-KEM, ML-DSA) fails. Nothing falls back silently to a key exchange a quantum computer could break.

## 2. Before you start

- **Gateways:** Linux, with strongSwan 6.0.2 or newer built against OpenSSL 3.5, iproute2, and WireGuard's tools for remote access. The gateway Docker image has all of them.
- **People's computers:** Windows 10 or 11 (x64), macOS on Apple silicon, or Ubuntu and Debian (x64), with WireGuard installed. The desktop installers carry everything else, OpenSSL 3.5 included.
- **The command line** (for administrators): Python 3.11 to 3.14 and OpenSSL 3.5 or newer. Debian 13 and Ubuntu 25.04 have it. On macOS run `brew install openssl@3`; on Windows, `choco install openssl`.
- **A network plan:** the gateways' public addresses, the subnets behind each site, the address pool for remote access, and firewall openings for UDP 500 and 4500 (IPsec), UDP 51820 (WireGuard), TCP 7443 (key agreement) and TCP 9443 (enrollment).

## 3. Install

### The command line, for administrators

The release folder installs on Linux (x86-64 and ARM), Windows (x64) and Macs with Apple silicon, with Python 3.11 to 3.14. On an Intel Mac, use the Docker image.

Get two files from the [release page](https://github.com/AcxelinQuantum/AQPQCSuite/releases/tag/vpn-v1.0.2) and save them in one folder:

- `acxelin-vpn-1.0.2-wheelhouse.tar.gz`: the program, with everything it needs, so it installs without internet access
- `SHA256SUMS`: a fingerprint of every file in the release

The desktop installers for people's computers are on the same page; section "The desktop app, for people" below covers them.

Then open a terminal in that folder. On Windows, use PowerShell.

**Step 1: check the download.** This confirms the file is exactly the one we published, not damaged or changed on the way. It only reads the file.

On Linux:

```
sha256sum -c SHA256SUMS --ignore-missing
```

You should see the file's name followed by `OK`.

On macOS:

```
shasum -a 256 acxelin-vpn-1.0.2-wheelhouse.tar.gz
```

On Windows:

```
Get-FileHash .\acxelin-vpn-1.0.2-wheelhouse.tar.gz
```

On macOS and Windows this prints the file's fingerprint, a long string of letters and numbers. It should match the one next to the file's name in `SHA256SUMS` (capital or small letters do not matter). If the check fails, delete the file and download it again. Do not install it.

Optional: if you use the GitHub command line, `gh attestation verify acxelin-vpn-1.0.2-wheelhouse.tar.gz --owner AcxelinQuantum` shows that our release workflow built the file. You should see `Verification succeeded`.

**Step 2: unpack it.** The same two lines work in PowerShell:

```
tar xzf acxelin-vpn-1.0.2-wheelhouse.tar.gz
cd acxelin-vpn-1.0.2-wheelhouse
```

**Step 3: install.** Still in that folder:

| System | Run |
|---|---|
| Linux, macOS | `sh install.sh` |
| Windows | `Unblock-File .\install.ps1`, then `powershell -ExecutionPolicy RemoteSigned -File .\install.ps1` |

On Windows, the first command tells Windows you trust this downloaded script, and the second runs it.

The installer checks your Python, finds OpenSSL 3.5, puts `acxelin-vpn` on your PATH and runs a health check. A laptop prints:

```
acxelin-vpn 1.0.2, Python 3.11.15
ok    OpenSSL 3.5.9 29 Sep 2026 can agree keys over post-quantum mutual TLS
WARN  This machine is not set up as an IPsec gateway (fine for a laptop)
```

If OpenSSL 3.5 is in a folder of its own, run `ACXELIN_OPENSSL=/path/to/openssl-3.5/lib sh install.sh`. To remove it, run `sh install.sh --uninstall` (or `install.ps1 -Uninstall`). Your certificates and settings stay where you put them.

### A gateway

**With Docker (recommended):** each release publishes a gateway image with strongSwan 6.1, OpenSSL 3.5 and WireGuard's tools. IPsec and WireGuard live in the host's kernel, so the container shares the host's network:

```
docker pull ghcr.io/acxelinquantum/acxelin-vpn:1.0.2
docker tag ghcr.io/acxelinquantum/acxelin-vpn:1.0.2 acxelin-vpn
docker run --rm acxelin-vpn doctor
```

**On the host, with systemd:** install strongSwan 6.0.2+ built against OpenSSL 3.5 into `/opt/strongswan` (the gateway image's Dockerfile, `deploy/Dockerfile`, shows the build), then install Acxelin VPN with its gateway option from the release folder:

```
sudo python3 -m venv /opt/acxelin-vpn
sudo /opt/acxelin-vpn/bin/pip install --no-index --find-links . "acxelin-vpn[vpn]"
sudo cp deploy/systemd/* /etc/systemd/system/
```

Section 8 says which unit runs what.

### The desktop app, for people

| System | File | How to install |
|---|---|---|
| Windows 10/11 (x64) | `Acxelin-VPN-1.0.2-Setup.exe` | Run it and follow the steps. Leave **Show Acxelin VPN in the tray when I log in** ticked to start it at login. Install [WireGuard for Windows](https://www.wireguard.com/install/) too; the installer reminds you if it is missing. |
| macOS (Apple silicon) | `Acxelin-VPN-1.0.2.dmg` | Open it and drag Acxelin VPN to Applications. Install WireGuard's tools with `brew install wireguard-tools`. |
| Ubuntu, Debian (x64) | `acxelin-vpn_1.0.2_amd64.deb` | `sudo apt install ./acxelin-vpn_1.0.2_amd64.deb`, which also installs WireGuard's tools. |

The installers are not code-signed yet, so the first launch shows a warning. Check the installer first, the same way as in Step 1 above, with its own file name. On Windows, SmartScreen says "Windows protected your PC": choose **More info**, then **Run anyway**. On macOS, open **System Settings > Privacy & Security** and choose **Open Anyway**.

## 4. Two sites and a laptop in fifteen minutes

These steps connect headquarters (`hq.acme.example`, 203.0.113.10, subnet 10.1.0.2/16) to a branch (`branch1.acme.example`, 198.51.100.7, subnet 10.2.0.0/16), and give Alice's laptop access through a WireGuard gateway at headquarters (`vpn.acme.example`). Replace the names and addresses with yours. `config/` in the release folder has the three configurations used here, with every setting explained.

### Step 1: create the certificate authority

Choose a passphrase for its key; you need it whenever you issue, invite or revoke. Keep it in `ACXELIN_VPN_CA_PASSPHRASE` for the session, or let each command ask.

```
acxelin-vpn ca init --name "Acme VPN Root" --dir pki
```

It prints `created ML-DSA-87 root 'Acme VPN Root' in pki; gateways and people trust pki/ca.crt, gateways check pki/crl.pem`. Keep the `pki` folder safe: `pki/ca.key` is the key every certificate depends on.

### Step 2: issue the gateways' certificates

A `site` certificate for each IPsec gateway, named as in its configuration, with its public address:

```
acxelin-vpn ca issue site hq.acme.example --san 203.0.113.10 --dir pki --out pki/issued/hq
acxelin-vpn ca issue site branch1.acme.example --san 198.51.100.7 --dir pki --out pki/issued/branch1
acxelin-vpn ca issue server vpn.acme.example --san vpn.acme.example --dir pki --out pki/issued/vpn
acxelin-vpn ca issue server ca.acme.example --san ca.acme.example --dir pki --out pki/issued/enroll
```

The last two are for the WireGuard gateway and the enrollment service. Each folder gets `chain.pem` (the certificate with the CA, what a gateway presents) and `key.pem`. Copy each gateway's folder, `pki/ca.crt` and `pki/crl.pem` to that gateway; the CA key stays where it is.

### Step 3: start both sites

On each gateway, put its configuration (`config/site-hq.toml`, `config/site-branch.toml`) in `/etc/acxelin-vpn/site.toml` with your paths, and start it:

```
docker run -d --name vpn --network host --cap-add NET_ADMIN -v /etc/acxelin-vpn:/etc/acxelin-vpn:ro acxelin-vpn
```

The container starts strongSwan, then `acxelin-vpn up`. The branch connects to headquarters' key agreement service on port 7443, both sides load the agreed keys into strongSwan, and the tunnel comes up. On either gateway:

```
docker exec vpn acxelin-vpn status --config /etc/acxelin-vpn/site.toml
```

On headquarters it lists one line per peer, then each child tunnel, in this form:

```
branch1.acme.example ESTABLISHED  CURVE_25519 + ML_KEM_768         PPK yes  up 41s
  net            INSTALLED    AES_GCM_16_256 in 5880 B / out 5880 B
```

An established IKE session is not proof on its own. Send real traffic between the subnets, and check that the byte counters move.

### Step 4: start the enrollment service and the WireGuard gateway

The enrollment service is where invitations enroll, next to the CA:

```
acxelin-vpn ca serve --dir pki --cert pki/issued/enroll/chain.pem --key pki/issued/enroll/key.pem
```

On the headquarters gateway, put `config/gateway.toml` in `/etc/acxelin-vpn/gateway.toml` with your pool, routes and DNS, and start the WireGuard gateway:

```
docker run -d --name wg --network host --cap-add NET_ADMIN -v /etc/acxelin-vpn:/etc/acxelin-vpn \
  acxelin-vpn gateway --config /etc/acxelin-vpn/gateway.toml
```

### Step 5: invite Alice

```
acxelin-vpn invite alice --dir pki --enroll https://ca.acme.example:9443 --gateway vpn.acme.example:7443
```

```
wrote alice.acxinvite: it lets alice enroll once before 2026-10-20T15:04:40+00:00 and then connect to vpn.acme.example:7443.
Send it through a channel you trust (it holds a one-time token and the CA fingerprint the device will trust).
```

The file holds the enrollment address, the CA fingerprint the laptop will trust, the gateway and a one-time token, so Alice does not copy four values by hand. It is valid for 24 hours (`--hours` changes that). If the gateway's `users` list is not empty, add `alice` to it.

### Step 6: Alice connects

Alice installs the desktop app (section 3), opens it, chooses **Choose the invitation file**, picks `alice.acxinvite`, chooses a passphrase for this computer's key, and presses **Connect**. Her system asks once for administrator approval, because the VPN changes the computer's network. The window then says **Protected**, and the tray shield turns green.

Without the app, in an administrator terminal: `acxelin-vpn join alice.acxinvite`. It enrolls (the key is made on the laptop, never leaves it, and is stored encrypted) and connects.

## 5. Everyday tasks

| Task | Command |
|---|---|
| Open the console | `acxelin-vpn console` |
| Invite a person | `acxelin-vpn invite NAME --dir pki --enroll URL --gateway HOST:PORT` |
| Revoke a person or a site | `acxelin-vpn ca revoke SERIAL --dir pki` (serials from `ca list`) |
| List what the CA issued | `acxelin-vpn ca list --dir pki` |
| Renew what expires soon and refresh the CRL | `acxelin-vpn ca maintain --dir pki` (daily) |
| See a site's tunnels | `acxelin-vpn status --config site.toml` (add `--json`) |
| Check strongSwan supports ML-KEM | `acxelin-vpn check` |
| See whether this computer is protected | `acxelin-vpn status` (add `--details` for algorithms and key timing) |
| Disconnect this computer | `acxelin-vpn disconnect` |
| Check a CA folder or a configuration | `acxelin-vpn doctor --ca pki --config site.toml` |
| Export the VPN's cryptography for an audit | `acxelin-vpn inventory --config site.toml --config gateway.toml --cbom vpn-cbom.json` |

Passphrases come from `ACXELIN_VPN_CA_PASSPHRASE` or a prompt, never from the command line.

### Revoke someone

```
acxelin-vpn ca revoke 763320879c3df003 --dir pki
```

The CA re-signs `pki/crl.pem`. A gateway that reads that file cuts the revoked site's tunnel, or removes the revoked person from WireGuard, within 15 seconds. A gateway on another machine needs the new CRL: set `crl_url` in its configuration, and it fetches the list every `crl_every` seconds (60 by default).

### Split tunnel or full tunnel

By default only the gateway's `routes` go through the tunnel, and other internet traffic uses the normal network. With `full_tunnel = true` in the gateway's `[wireguard]`, all of the laptops' traffic goes through the gateway, which forwards it with NAT, and laptops get a kill switch. The kill switch blocks traffic outside the tunnel while protection is down: on Linux and macOS it stays in place while the app reconnects, while on Windows the block follows the tunnel and can lift for a moment while the tunnel is recreated.

### Profiles

| Profile | IKE key exchange | Encryption |
|---|---|---|
| `standard` (default) | X25519 + ML-KEM-768 | AES-256-GCM |
| `high` | P-384 + ML-KEM-1024 | AES-256-GCM |
| `cnsa2` (strict, government grade) | ML-KEM-1024 only | AES-256-GCM, SHA-384 |

Set `profile` per `[[peer]]`. Both sides of a tunnel must use the same one.

`cnsa2` keeps to the NSA's CNSA 2.0 suite on every layer: no classical key exchange in IKE or ESP, and the key agreement
between gateways allows only ML-KEM-1024, ML-DSA-87 certificates and AES-256. Every peer of the site must use it (they share
one key agreement service), and both gateways need ML-DSA-87 certificates: `acxelin-vpn ca issue site NAME --algorithm ML-DSA-87`.
A gateway with another certificate refuses to start and says why. WireGuard remote access cannot meet CNSA 2.0 (Curve25519
and ChaCha20 are outside the suite), so a CNSA 2.0 network leaves it off.

### For an audit

`acxelin-vpn inventory` writes what the VPN uses as a CycloneDX 1.6 CBOM: tunnels, key exchanges, ciphers, certificates, and whether a PSK and a PPK are present (type and size only, never a value). Any CBOM tool reads it.

## 6. The console

```
acxelin-vpn console
```

Your browser opens, already signed in. If there is no certificate authority yet, the console creates one for you. It asks for the CA key's passphrase and keeps it in memory only, so it asks again after a restart.

| Tab | What you do there |
|---|---|
| **Sites** | Add each site gateway by its status address (`metrics` in its `[site]`) to see its tunnels: state, key exchange, encryption, whether the PPK is in use, the last key rotation, traffic and the peer's certificate. |
| **People** | The first time, say where invitations point: the enrollment service and the gateway. Then invite a person and download their invitation file. Add the WireGuard gateway by its status address to see who is connected now and since when. Revoke a person in two clicks; their session ends at the gateway's next check. |
| **Health** | Whether this computer can run Acxelin VPN, whether the CA, its CRL and its certificates are in good shape, and whether every site and gateway answers, each with what to do. |

Invitations and revocations, from the console or the command line, are written to `audit.jsonl` in the CA folder, which only you can read. The People tab shows the latest of them together with enrollments, refused enrollments and renewals from the enrollment service's log beside it. No token, key or passphrase is written. Each laptop keeps its own `audit.jsonl` of kill-switch changes in its tunnel folder; the app's connection details and `acxelin-vpn status --details` show the last one.

The console listens only on the machine it runs on. For a remote server, forward a port and ask the running console for a fresh link:

```
ssh -L 8901:127.0.0.1:8901 server
acxelin-vpn console link --port 8901
```

Run the second command in that SSH session, then open the address it prints on your laptop.

## 7. The desktop app

1. A shield appears in the system tray (the Windows taskbar corner, the macOS menu bar, the Linux panel). Green with a tick is **Protected**, amber is **Connecting**, red is **Not protected**, grey is disconnected or not set up. Hover over it for the words.
2. The Acxelin VPN window opens. The first time, open the invitation file, choose a passphrase for this computer, and press **Connect**. Next time, enter only the passphrase.
3. The tray menu has **Open Acxelin VPN**, **Disconnect**, **Start at login** and **Quit and disconnect**. Closing the window leaves the VPN connected.

| The window says | Meaning |
|---|---|
| **Protected** | The tunnel has completed a handshake with a key from the latest post-quantum key agreement. The next line names the key exchange, the gateway's certificate algorithm and how often the key is renewed. |
| **Connecting** | Keys are agreed; the tunnel has not completed its first handshake yet. |
| **Not protected** | The gateway could not be reached or refused this computer; the reason follows. It retries on its own; with a full tunnel, internet traffic stays blocked meanwhile. |

Connection details say when the key was last renewed. If renewals stop, the window says so in words: when the key is more than twice its renewal period old ("has not been renewed for 62 min"), and, when the gateway cannot be reached, how many tries in a row have failed and when the last good key was agreed. `acxelin-vpn status --details` prints the same.

Only the background VPN service runs with administrator rights; the tray and the window run as you. The window is served only on 127.0.0.1 and opens only from a one-time address. It never offers to save your passphrase. On Linux, the tray menu needs a desktop with AppIndicator support (GNOME with its AppIndicator extension, KDE and most others); without it, clicking the shield opens the window, and Disconnect is in the window.

**Without the installer:** `acxelin-vpn app`, in an administrator terminal, serves the same window in your browser.

## 8. Running it in production

**Docker.** Run the gateway image with `--network host --cap-add NET_ADMIN` and `/etc/acxelin-vpn` mounted. With no command it runs the site in `/etc/acxelin-vpn/site.toml`; `gateway --config /etc/acxelin-vpn/gateway.toml` runs the WireGuard gateway instead. Add `--restart unless-stopped`.

**systemd.** `deploy/systemd` has:

| Unit | Runs | Reads |
|---|---|---|
| `strongswan-pqc.service` | strongSwan's charon from `/opt/strongswan` | |
| `acxelin-vpn-ipsec.service` | `acxelin-vpn up`, after strongSwan | `/etc/acxelin-vpn/site.toml` |
| `acxelin-vpn-wireguard.service` | `acxelin-vpn gateway` | `/etc/acxelin-vpn/gateway.toml` |
| `acxelin-vpn-enroll.service` | `acxelin-vpn ca serve`, as user `acxelin` | `/var/lib/acxelin-vpn/ca`, `/etc/acxelin-vpn/enroll` |
| `acxelin-vpn-ca-maintain.timer` | `acxelin-vpn ca maintain` daily, as user `acxelin` | `/var/lib/acxelin-vpn/ca` |

The CA's passphrase for the last two goes in `/etc/acxelin-vpn/ca.env` as `ACXELIN_VPN_CA_PASSPHRASE=...`, readable by root only. Each unit starts only when the file it reads exists, so enable all of them and only the right ones run.

**Before going live**, run `acxelin-vpn doctor --strict --ca pki --config /etc/acxelin-vpn/site.toml`. It exits 0 only when nothing needs attention. Then test on the real network: sleep and wake, a Wi-Fi change, a gateway restart, DNS and IPv6, a revocation and the kill switch, on the laptops and systems you actually use.

### Keeping the CA safe

- The CA key is encrypted by default. Keep the passphrase in your password manager, not on a gateway.
- Run the CA and the enrollment service on a machine of their own, not on a gateway. Gateways need only `ca.crt`, the CRL (or `crl_url`) and their own certificate.
- `ca maintain` must run daily: a gateway whose CRL has expired refuses every peer.

### Monitoring

With `metrics = "HOST:PORT"`, a site serves `/metrics` (Prometheus) and `/status` (JSON); so does the WireGuard gateway.

| Metric | Meaning |
|---|---|
| `acxelin_vpn_tunnel_up{peer}` | 1 while the site's tunnel to that peer is installed |
| `acxelin_vpn_bytes_total{peer,direction}` | traffic through the tunnel |
| `acxelin_vpn_events_total{event}` | key agreements, rotations, refusals and revoked peers |
| `acxelin_vpn_wireguard_client_up{user}` | 1 while that person's computer has completed a handshake in the last three minutes |
| `acxelin_vpn_wireguard_bytes_total`, `acxelin_vpn_wireguard_events_total` | the same for remote access |

## 9. How keys are agreed

1. **Mutual TLS.** One side connects to the other's key agreement service (port 7443) over TLS 1.3 with a hybrid ML-KEM group (X25519MLKEM768, SecP384r1MLKEM1024 or SecP256r1MLKEM768). Both present ML-DSA certificates from your CA, checked against the CRL. Anything else is refused.
2. **Keys from the session.** Both sides derive the same secrets from that TLS session (an RFC 5705 exporter): for IPsec the IKE PSK, the PPK and its id; for WireGuard the pre-shared key. Nothing secret crosses the network.
3. **Rotation.** Sites agree new keys every `rotate_minutes` (60 by default), people's computers every two minutes. A side that stops re-agreeing is removed after three missed rotations.
4. **Revocation.** A revoked certificate gets no new keys, and its tunnel is cut.

## 10. When something goes wrong

| You see | What it means | What to do |
|---|---|---|
| `this machine's OpenSSL ... is too old` | The key agreement needs OpenSSL 3.5 or newer. | Install it (section 2), or use the gateway image or the desktop installers, which include it. |
| `cannot reach charon at unix:///var/run/charon.vici` | strongSwan is not running, or `vici` points elsewhere. | Start `strongswan-pqc`, or use the gateway image, which starts it. |
| `ML-KEM key exchanges: none` from `check` | strongSwan was built without OpenSSL 3.5 or its `ml` plugin. | Use strongSwan 6.0.2+ built as in `deploy/Dockerfile`. |
| `charon did not start; run the container with --network host --cap-add NET_ADMIN` | The container cannot reach the host's IPsec. | Add both options. |
| A tunnel stays `CONNECTING` | The key agreement port or IPsec's UDP 500 and 4500 are blocked, or the names in the configuration differ from the certificates. | Open the ports; `name` must equal the certificate's name. `doctor --config` checks the files. |
| **Not protected** with `revoked` in the app | This computer's certificate was revoked. | Ask the administrator for a new invitation. |
| Every peer is refused after a week | The CRL has expired, and the VPN fails closed. | Run `acxelin-vpn ca maintain --dir pki` now, and schedule it daily. |
| `The CA key is locked` in the console | The console restarted and forgot the passphrase. | Enter the passphrase again. |
| `doctor` exits 2 | A check failed. | The line marked `FAIL` names the problem and the fix. |

### Exit codes

`doctor` exits 0 when everything passes, 1 on warnings with `--strict`, 2 when a check fails, and 3 when this machine cannot run Acxelin VPN. `status` exits 0 only when protected. Other commands exit 1 with one line on stderr when they fail.

## 11. Questions

**Is WireGuard itself post-quantum?** WireGuard's own handshake stays classical. What Acxelin VPN adds is the pre-shared key: it comes from a post-quantum key agreement and is mixed into every WireGuard handshake, so recorded traffic stays protected even if the classical handshake is broken later.

**Do phones work?** Not yet. Phones and the IKEv2 clients built into operating systems cannot do the post-quantum key agreement.

**Can I keep my existing strongSwan?** Yes, if it is 6.0.2 or newer and built against OpenSSL 3.5. `acxelin-vpn check` says whether it offers ML-KEM.

**How fast does a revocation take effect?** Within 15 seconds on a gateway that reads the CRL file, for sites and people alike, plus up to `crl_every` seconds (60 by default) where the gateway fetches the CRL with `crl_url`.

**Does it contact the internet?** Only the addresses you configure: peers, gateways, the enrollment service and a `crl_url`. It never contacts Acxelin Quantum.

**Does it need any other Acxelin product?** No. It installs and runs on its own, from its own release folder.

## 12. Limits

- WireGuard's handshake is classical; the post-quantum part is the pre-shared key (see Questions).
- IKE does not sign with ML-DSA certificates: strongSwan 6.1 cannot load them (checked with `deploy/mldsa_ike_check.py`). IKE authenticates with a PSK, and mixes in a PPK, both derived from ML-DSA mutual TLS between the gateways.
- Phones are not supported.
- On Windows, the kill switch can lift for a moment while the tunnel is recreated.
- The desktop installers are not code-signed yet.
- A revoked site or person keeps access until their gateway has the new CRL: up to 15 seconds, plus `crl_every` when it is fetched.
- The tunnels have been tested in Linux network namespaces and on GitHub's Windows and macOS runners, not on your network. Test on your own laptops and gateways before a wide rollout.
