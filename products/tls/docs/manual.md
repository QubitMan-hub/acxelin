# Acxelin TLS manual

Acxelin TLS puts post-quantum TLS 1.3 and mutual TLS in front of the services you already run, and issues the ML-DSA certificates they need from your own certificate authority. The service behind it does not change.

This manual covers installing it, a first edge in ten minutes, the everyday work, running it in production, and what to do when something goes wrong. Acxelin TLS installs and runs on its own; it needs no other Acxelin product.

## 1. What you get

| Part | What it does |
|---|---|
| **The edge** | A proxy that accepts only post-quantum clients in front of any TCP service (web apps, PostgreSQL, MQTT, anything), or a tunnel that lets a plain local client reach a remote edge. |
| **The certificate authority** | Issues, renews and revokes ML-DSA certificates, keeps the revocation list fresh, and enrolls machines over EST and ACME. |
| **The console** | A local web page for the routine work: create the CA; issue, download, renew and revoke certificates; check edges; test a connection. |

A connection that cannot meet your policy ends. Nothing falls back silently to a key exchange a quantum computer could break.

## 2. Before you start

- **Python 3.11 to 3.14**, on Linux, macOS or Windows.
- **OpenSSL 3.5 or newer.** Debian 13 and Ubuntu 25.04 have it. On macOS run `brew install openssl@3`; on Windows, `choco install openssl`. The Docker image includes it.
- For the console: a web browser on the same machine, or an SSH connection to it.

## 3. Install

The release folder installs on Linux (x86-64 and ARM), Windows (x64) and Macs with Apple silicon, with Python 3.11 to 3.14. On an Intel Mac, use the Docker image.

Get two files from the [release page](https://github.com/AcxelinQuantum/AQPQCSuite/releases/tag/tls-v1.0.2) and save them in one folder:

- `acxelin-tls-1.0.2-wheelhouse.tar.gz`: the program, with everything it needs, so it installs without internet access
- `SHA256SUMS`: a fingerprint of every file in the release

Then open a terminal in that folder. On Windows, use PowerShell.

**Step 1: check the download.** This confirms the file is exactly the one we published, not damaged or changed on the way. It only reads the file.

On Linux:

```
sha256sum -c SHA256SUMS --ignore-missing
```

You should see the file's name followed by `OK`.

On macOS:

```
shasum -a 256 acxelin-tls-1.0.2-wheelhouse.tar.gz
```

On Windows:

```
Get-FileHash .\acxelin-tls-1.0.2-wheelhouse.tar.gz
```

On macOS and Windows this prints the file's fingerprint, a long string of letters and numbers. It should match the one next to the file's name in `SHA256SUMS` (capital or small letters do not matter). If the check fails, delete the file and download it again. Do not install it.

Optional: if you use the GitHub command line, `gh attestation verify acxelin-tls-1.0.2-wheelhouse.tar.gz --owner AcxelinQuantum` shows that our release workflow built the file. You should see `Verification succeeded`.

**Step 2: unpack it.** The same two lines work in PowerShell:

```
tar xzf acxelin-tls-1.0.2-wheelhouse.tar.gz
cd acxelin-tls-1.0.2-wheelhouse
```

**Step 3: install.** Still in that folder:

| System | Run |
|---|---|
| Linux, macOS | `sh install.sh` |
| Windows | `Unblock-File .\install.ps1`, then `powershell -ExecutionPolicy RemoteSigned -File .\install.ps1` |

On Windows, the first command tells Windows you trust this downloaded script, and the second runs it.

The installer checks your Python, finds OpenSSL 3.5, puts `acxelin-tls` on your PATH and runs a health check. A ready machine prints:

```
acxelin-tls 1.0.2, Python 3.11.15
ok    cryptography 50.0.2 issues ML-DSA certificates
ok    OpenSSL 3.5.4 30 Sep 2025 can do post-quantum TLS 1.3
```

If OpenSSL 3.5 is in a folder of its own, run `ACXELIN_OPENSSL=/path/to/openssl-3.5/lib sh install.sh`. On Windows, set `ACXELIN_OPENSSL` to the folder that holds its DLLs before running `install.ps1`.

To remove it, run `sh install.sh --uninstall` (or `install.ps1 -Uninstall`). Your certificates and settings stay where you put them.

**With Docker instead:** each release publishes an image with OpenSSL 3.5 included. Pull it and give it a short name, which the rest of this manual uses:

```
docker pull ghcr.io/acxelinquantum/acxelin-tls:1.0.2
docker tag ghcr.io/acxelinquantum/acxelin-tls:1.0.2 acxelin-tls
docker run --rm acxelin-tls doctor
```

## 4. See it work in one minute

```
acxelin-tls try
```

The tour sets up a CA, an ordinary web server and an edge in front of it, then shows a post-quantum client getting through and a classical client being refused. It needs nothing else and leaves nothing behind.

## 5. Your first edge in ten minutes

These steps put post-quantum TLS in front of a web app listening on `127.0.0.1:8080`.

### Step 1: create the certificate authority

Choose a passphrase for its key; you need it whenever you issue or revoke.

```
acxelin-tls ca init --name "Example Root CA" --dir pki
```

It prints `created ML-DSA-87 root 'Example Root CA' in pki`. Keep the `pki` folder safe: `pki/ca.key` is the key every certificate depends on.

### Step 2: issue the edge's certificate

Use the name your clients will connect to:

```
acxelin-tls ca issue server web.example.com --dir pki --out web
```

`web/chain.pem` is the certificate with the CA, and `web/key.pem` is its private key.

### Step 3: start the edge in front of the app

```
acxelin-tls edge --listen 0.0.0.0:8443 --target 127.0.0.1:8080 --cert web/chain.pem --key web/key.pem --metrics 127.0.0.1:9100
```

### Step 4: test it

From any machine that has `pki/ca.crt`:

```
acxelin-tls connect web.example.com:8443 --ca pki/ca.crt --send "GET / HTTP/1.0\r\n\r\n"
```

You see what was negotiated, then the app's reply:

```
    version  TLSv1.3
      group  X25519MLKEM768
       peer  CN=web.example.com
   peer_key  ML-DSA-65
      reply  HTTP/1.0 200 OK
```

### Step 5: check the edge's counters

`acxelin-tls status --url http://127.0.0.1:9100` prints the policy, the open connections and the key exchanges clients negotiated.

A client that cannot do post-quantum key exchange is refused, and the edge's log says why: `the client offers none of the key exchanges this policy allows`.

## 6. Everyday tasks

| Task | Command |
|---|---|
| Open the console | `acxelin-tls console` |
| Issue a server certificate | `acxelin-tls ca issue server NAME --dir pki --out FOLDER` |
| Issue a client certificate (mutual TLS) | `acxelin-tls ca issue client NAME --dir pki --out FOLDER` |
| List what the CA issued | `acxelin-tls ca list --dir pki` |
| Renew a certificate | `acxelin-tls ca renew SERIAL --dir pki` |
| Certify a key made elsewhere | `acxelin-tls ca sign-csr request.csr --kind server --dir pki --out FOLDER` |
| Revoke a certificate | `acxelin-tls ca revoke SERIAL --dir pki` |
| Renew what expires soon and refresh the CRL | `acxelin-tls ca maintain --dir pki` (daily) |
| Check a CA folder or an edge configuration | `acxelin-tls doctor --ca pki --config edge.toml` |
| nginx, PostgreSQL, pgvector or MQTT behind an edge | `acxelin-tls bundle nginx --host web.example.com` |

Passphrases come from `ACXELIN_TLS_CA_PASSPHRASE` or a prompt, never from the command line.

### Require client certificates (mutual TLS)

Add three options to the edge. Then only machines holding a certificate from your CA, and not revoked, get through.

```
acxelin-tls edge --listen 0.0.0.0:8443 --target 127.0.0.1:8080 --cert web/chain.pem --key web/key.pem \
  --require-client-cert --ca pki/ca.crt --crl pki/crl.pem
```

Give each client its own certificate (`acxelin-tls ca issue client laptop-01 --dir pki --out laptop`). It connects with `--cert laptop/chain.pem --key laptop/key.pem`. A client without one is refused, and the edge logs `peer did not return a certificate`.

### Revoke a certificate

```
acxelin-tls ca revoke 775089c0ad0f5832 --dir pki
```

The CA re-signs `pki/crl.pem`. An edge that reads that file refuses the certificate from its next connection, without a restart. An edge on another machine needs the new CRL: run `acxelin-tls ca publish` next to the CA and set `crl_url` on the edge, which then fetches it every minute.

### Several routes in one edge

Write the routes in a file and start the edge with `acxelin-tls edge --config edge.toml`. Each `[[edge]]` table is one route:

```
[metrics]
listen = "127.0.0.1:9100"

[[edge]]
name = "web"
mode = "terminate"                  # post-quantum TLS in front of a plain service
listen = "0.0.0.0:8443"
target = "127.0.0.1:8080"
policy = "strict"
cert = "web/chain.pem"
key = "web/key.pem"

[[edge]]
name = "to-datacenter"
mode = "originate"                  # a plain local client reaches a remote edge
listen = "127.0.0.1:5432"
target = "db.example.com:8443"
server_name = "db.example.com"
ca = "pki/ca.crt"
```

`config/example.toml` lists every setting. Saving the file reloads it without a restart, and certificates are re-read when their files change.

### Policies

| Policy | Allows |
|---|---|
| `strict` (default) | post-quantum key exchange and ML-DSA certificates only |
| `transition` | also classical clients while you migrate; use it with `fallback_cert` for browsers, which cannot verify ML-DSA yet |
| `cnsa2` | NSA CNSA 2.0: ML-KEM-1024, ML-DSA-87 and AES-256 only |

## 7. The console

```
acxelin-tls console
```

Your browser opens, already signed in. The first time, create the certificate authority. The console asks for the key's passphrase and keeps it in memory only, so it asks again after a restart.

| Tab | What you do there |
|---|---|
| **Certificates** | Issue, download, renew and revoke. A private key reaches the browser only when you choose With key, and never for a revoked certificate or an encrypted key. |
| **Edges** | Add a running edge by its metrics address to see its policy and negotiated key exchanges. Test a connection to any host, with a client certificate for mutual TLS. |
| **Health** | Whether this computer can run Acxelin TLS, and whether the CA, its CRL and its certificates are in good shape. |

Every action is written to an audit log that only you can read.

The console listens only on the machine it runs on. For a remote server, forward a port and ask the running console for a fresh link:

```
ssh -L 8900:127.0.0.1:8900 server
acxelin-tls console link --port 8900
```

Run the second command in that SSH session, then open the address it prints on your laptop.

## 8. Running it in production

**Docker.** One image, with OpenSSL 3.5 included. It runs as user 10001 and keeps its files in `/data`:

```
docker run -d --name edge -v /etc/acxelin-tls:/data:ro -p 8443:8443 acxelin-tls edge --config /data/edge.toml
docker run -d --name console -v acxelin-tls:/data -p 127.0.0.1:8900:8900 acxelin-tls console --container
docker exec -it console acxelin-tls console link
```

The files in `/etc/acxelin-tls` must be readable by user 10001. Publish the console's port on `127.0.0.1` only, as above.

**systemd.** `deploy/systemd` has `acxelin-tls-edge.service` for the edge, and `acxelin-tls-maintain.service` with a daily timer that runs `ca maintain`. They use `/etc/acxelin-tls`, `/var/lib/acxelin-tls` and the service user `acxelin`.

**Before going live**, run `acxelin-tls doctor --strict --ca pki --config edge.toml`. It exits 0 only when nothing needs attention.

### Keeping the CA safe

- The CA key is encrypted by default. Keep the passphrase in your password manager, not on the server.
- Keep the root offline and issue from an intermediate: `acxelin-tls ca init --name "Example Issuing CA" --parent ROOT_DIR --dir issuing`. If the issuing CA is compromised, the root revokes it and makes a new one. A certificate is only checked against the CRL of the CA that issued it, so give an edge the intermediate's CRL; to let the root's revocation of the intermediate count too, put both in one file: `cat issuing/crl.pem pki/crl.pem > crls.pem`, and use `issuing/chain.pem` as `ca`.
- An `originate` edge listens on 127.0.0.1 unless you give `--listen`: anyone who can reach its port is tunnelled in with its client certificate, so keep it local or firewalled.
- The CA key can stay in a hardware security module: `--kms KEY_ID` keeps it in AWS KMS (install the `kms` extra), and `--signer-command` hands each signature to your HSM's own tool. Neither has been run against a real HSM or cloud account here, so test it with yours first.

### Monitoring

With `--metrics HOST:PORT`, an edge serves `/healthz`, `/metrics` (Prometheus) and `/status` (JSON).

| Metric | Meaning |
|---|---|
| `acxelin_tls_connections_active{edge}` | open connections |
| `acxelin_tls_events_total{edge,event}` | handshakes accepted and refused, by reason |
| `acxelin_tls_group_total{edge,group}` | connections by negotiated key-exchange group |

## 9. Enrolling many machines

| Service | Command | For |
|---|---|---|
| EST (RFC 7030) | `acxelin-tls ca serve` | Machines enroll with a one-time token from `ca token` over post-quantum TLS, and renew with `ca enroll`. The key never leaves the machine. |
| ACME (RFC 8555) | `acxelin-tls ca acme` | Standard ACME clients, such as certbot with `--csr`. `ca eab` makes an external account binding key; `ca csr` makes a key and CSR. |
| CRL publishing | `acxelin-tls ca publish` | Serves `ca.crt` and `crl.pem` over HTTP, so edges can follow revocations (`crl_url`). |

Every enrollment attempt is written to an owner-only audit log that never contains the token's secret.

## 10. How a connection is decided

1. **Key exchange.** Under `strict`, the client must offer a post-quantum group: X25519MLKEM768, SecP384r1MLKEM1024 or SecP256r1MLKEM768. A client that offers only classical groups is refused.
2. **Certificates.** Under `strict`, certificates must use ML-DSA. A client that cannot verify ML-DSA is refused.
3. **Client certificate.** With `require_client_cert`, the client must present a certificate that chains to the CA and is not on the CRL. The CRL is valid for 7 days by default, and an edge whose CRL has expired refuses every client, so keep `ca maintain` running.

## 11. When something goes wrong

| You see | What it means | What to do |
|---|---|---|
| `this machine's OpenSSL ... is too old` | Post-quantum TLS needs OpenSSL 3.5 or newer. | Install it (section 2), or use the Docker image. If OpenSSL 3.5 is in a folder of its own, point `ACXELIN_OPENSSL` (Windows, macOS) or `LD_LIBRARY_PATH` (Linux) at it. |
| `no suitable key share` in the edge's log | The client offers no post-quantum key exchange. | Use a client built on OpenSSL 3.5 or newer, or the `transition` policy while you migrate. |
| `peer did not return a certificate` | Mutual TLS is on, and the client sent no certificate. | Give the client a certificate from your CA, and point it at its `chain.pem` and `key.pem`. |
| `the server closed the connection right after the handshake` | The edge refused the client certificate (missing, untrusted or revoked), or the service behind the edge is down. | Read the edge's log, which says which one. Check that the target is listening. |
| Every client is refused after a week | The CRL has expired, and mutual TLS fails closed. | Run `acxelin-tls ca maintain --dir pki` now, and schedule it daily. |
| `The CA key is locked` in the console | The console restarted and forgot the passphrase. | Enter the passphrase again. |
| `doctor` exits 2 | A check failed. | The line marked `FAIL` names the problem and the fix. |

### Exit codes

`doctor` exits 0 when everything passes, 1 on warnings with `--strict`, 2 when a check fails, and 3 when this machine cannot run Acxelin TLS. Other commands exit 1 with one line on stderr when they fail.

## 12. Questions

**Do browsers work?** Not with ML-DSA certificates, which no browser verifies yet. Use the `transition` policy with a classical `fallback_cert` for browser traffic, and `strict` for your own clients and services.

**Do I have to change my application?** No. The edge sits in front of it, and the application keeps speaking plain TCP on a local port.

**How fast does a revocation take effect?** At the next connection on an edge that reads the CRL file directly. Within `crl_every` seconds (60 by default) on an edge that fetches it with `crl_url`.

**Does it contact the internet?** Only the addresses you configure: targets, remote edges and a `crl_url`. It never contacts Acxelin Quantum.

**Does it need any other Acxelin product?** No. It installs and runs on its own, from its own release folder.

## 13. Limits

- Browsers cannot verify ML-DSA certificates yet (see Questions).
- A revoked client keeps access until its edge has the new CRL.
- KMS and HSM signing are implemented, but they have not been tested against real HSMs or cloud accounts here.
