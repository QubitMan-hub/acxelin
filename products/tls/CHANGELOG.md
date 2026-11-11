# Changelog

## 1.0.3

- Fixed: `doctor --config` reads relative paths from the configuration file's folder, as the edge does; `connect --send`
  understands `\r`, `\n` and `\t`, so the manual's example works; `ca acme --days`, `ca maintain --renew-within` and `ca list
  --expiring` refuse 0 and negative numbers; `ca serve` asks for the CA passphrase once; a bundle made with `--ca` names the
  real CA file in its README; changing the `[metrics]` address while the edge runs says that it needs a restart.
- Security: ACME http-01 never fetches from cloud metadata addresses (AWS, GCP and Alibaba, IPv4 and IPv6), even with
  `--allow-local-validation`; a challenge fetch has 15 seconds in all, so a server trickling its answer cannot hold it; at
  most 32 validations run at once; an account holds at most 300 unfinished orders, and orders and authorizations 30 days
  past their expiry are dropped from `state.json`.
- Security (with core 1.1.1): revoking a certificate revokes its EST renewals; revoked clients are cut off after a
  configuration reload; one /24 or /64 holds at most `max_per_client` connections at any load; a connection where neither
  side sends anything within `first_data_timeout` (30 seconds, new) after the handshake is closed, so idle connections cannot
  hold every slot for the hour of `idle_timeout`.
- Security: the ACME server allows 16 connections from one network and closes each 60 seconds after it opened, so one machine
  trickling requests can no longer shut out every ACME client.
- Security: the console removes `ACXELIN_TLS_CA_PASSPHRASE` from its environment once read, so the browser it opens and
  everything that browser starts do not inherit it, and the launch ticket is no longer on the browser's command line.
- Shadow mode: `shadow = true` (or `--shadow`) on a `strict` or `cnsa2` route serves every client as `transition` would and logs which
  ones the policy would refuse, with their address and what they offered (key exchange groups and signature schemes), so you can
  see who enforcing would break before it does. Counters in `/metrics`, `"shadow": true` in `/status`. It reads only the client's
  first message and keeps no name, certificate, key share or data. It enforces nothing. Off by default; nothing changes unless set.
- Security: `edge --mode originate` listens on 127.0.0.1 by default, and warns when told to listen elsewhere: anyone who
  reaches an originate port is tunnelled in with the edge's client certificate. It listened on every interface before.
- Security: revocation follows core: a certificate an intermediate CA revoked is refused even when the root's CRL is the one
  configured, and the root's CRL can revoke the intermediate (concatenate both CRLs into the `crl` file).
- A route with `crl` needs `ca` and `require_client_cert = true`; without them the CRL checked nothing. `idle_timeout`,
  `handshake_timeout`, `max_connections`, `max_per_client` and `max_rate_per_client` are range-checked.
- Relative paths in a configuration file are read from the file's folder, so the systemd unit finds them.
- Renewing a certificate whose key is encrypted needs `--key-passphrase-env` (the console refuses it), so the new key stays
  encrypted.
- `connect` reports a server that refused the client certificate instead of a successful handshake.
- The PROXY header names an IPv4 client of a dual-stack listener as TCP4 with its plain IPv4 address.
- `serve --crl` without `--ca` says what is missing instead of a traceback.

- Windows: `install.ps1` writes its command wrapper in the console code page, so a user name such as José keeps its
  path. ASCII turned it into `Jos?`.

## 1.0.2

- Console: type the CA passphrase twice, so a typo is caught before the CA exists. An issued server certificate shows where its
  files are and the `acxelin-tls edge` command that uses them, with a Copy button. Errors scroll into view.

## 1.0.1

- Windows: `install.ps1` no longer stops at Python's `>>>` prompt on computers with the `py` launcher (Python from
  python.org or the Microsoft Store). It passed `py` its `-3` one character at a time.

## 1.0.0

First release of Acxelin TLS.

- Post-quantum TLS 1.3 and mutual TLS in front of any TCP service (`acxelin-tls edge`), with an ML-DSA certificate authority
  (`acxelin-tls ca ...`), EST and ACME enrollment.
- A console for the CA, edges and health.
- Metrics are named `acxelin_tls_*`.
- No outbound contact with GitHub or Acxelin Quantum.
- Deploys with Docker, systemd or the installers.
- A full manual (`docs/manual.md`), shipped in the release folder with the README, licence, example settings and systemd units.
