# Changelog

## Unreleased

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
