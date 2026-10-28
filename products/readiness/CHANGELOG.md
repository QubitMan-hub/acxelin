# Changelog

## Unreleased

- A 0-100 readiness score for each project scan and endpoint check, with its trend in the console (the last 30, as a line
  and a table). Projects average their listed findings' priorities; endpoints count A 100, B 50, C 0 and leave out F.
  Console assessment summaries gain `score`; endpoint checks are kept in `endpoints-history.json` in the console's folder.
- Scan a GitHub repository by link, in the console (**Add from GitHub**, no folder needed) or with `scan https://github.com/OWNER/REPO`.
  Private repositories use a read-only token: saved owner-only by the console, or `GITHUB_TOKEN` on the command line, and
  sent only to `api.github.com`. Downloads and unpacking are size-limited and keep regular files only. A downloaded
  repository's `.acxelin-readiness.toml` is not read.
- Console, Endpoints: below the grades, **What can happen** (if nothing changes) and **What we recommend** (most urgent first),
  each naming the endpoints it applies to. They are rules from what the check observed, not forecasts: expired and expiring
  certificates, classical-only key exchange, classical fallback, TLS 1.0 and 1.1, untrusted certificates, unreachable hosts
  and classical certificate keys.
- Console fixes: the priority counts and the asset total no longer include test-only findings the table does not list; after a
  restart, the highlighted repository is the one whose results show; choosing a folder keeps its registered repositories and
  never shows another folder's results (it is refused while a scan runs); SSH host keys no longer show "9999 days left", and an
  expired certificate says so.
- A bare IPv6 address such as `::1` is the address on the default port; it was read as host `:` on port 1. A port on IPv6
  needs brackets: `[::1]:8443`.
- An endpoint that fails unexpectedly keeps its `host:port` name, so the next check compares it.

## 1.0.2

- Console: the Endpoints tab works before you choose a folder. **Add and scan** adds a repository and scans it in one step.
  Choose an asset to see each file and line it was found on; choose a priority to show only those. Track a finding as
  accepted risk with a reason and an end date. Due dates use a date picker, and errors scroll into view.

## 1.0.1

- Windows: `install.ps1` no longer stops at Python's `>>>` prompt on computers with the `py` launcher (Python from
  python.org or the Microsoft Store). It passed `py` its `-3` one character at a time.

## 1.0.0

First release of Acxelin Readiness, from Wolf Pack CBOM 1.4.1 (its history is in `CHANGELOG-history.md`). See
`docs/upgrade.md`.

- One product: `scan`, `grade`, `report`, `merge`, `doctor` and a console for projects and endpoints.
- CBOM merges keep each system's observations; certificates match by fingerprint; secrets never merge.
- CNSA 2.0 reports AES of unknown key size as unverified instead of compliant.
- The GitHub Action lives at `products/readiness`; the old `wolf-pack` path is removed.
- A full manual (`docs/manual.md`), shipped in the release folder with the README, licence and example settings.
