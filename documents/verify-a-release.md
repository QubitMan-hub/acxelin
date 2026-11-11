# Verifying an Acxelin release

This page is for the person who receives an Acxelin release (a `-wheelhouse.tar.gz`, a container image, or the VPN's desktop installers) and
wants to be sure it came from Acxelin's release process and was not changed on the way. It takes about five minutes and needs no account
with us. It ships inside every release folder as `VERIFY.md`.

## What you can check, and what each check proves

| Check | Proves | Does not prove |
|---|---|---|
| Build attestation (`gh attestation verify`) | GitHub's release workflow in the Acxelin repository built this exact file from a tagged commit | That the code has no bugs, or that the repository itself is trustworthy |
| Checksums (`verify_release.py`) | Every file in the folder is byte for byte what was attested, and nothing was added | Anything about a file that is not listed |
| The SBOM (`acxelin-<product>-<version>.cdx.json`) | Which third-party wheels are inside, with the SHA-256 of each | That those packages are free of vulnerabilities: feed the SBOM to your own scanner |
| Container image digest | The image you pulled is the one the workflow pushed | Anything about images you built yourself |

The trust anchor is GitHub's attestation service and the Acxelin repository's release workflow. If you do not accept that, none of these
checks help you; ask us for a source review instead. Code signing of the Windows Setup and the macOS disk image is a separate matter and is
not covered on this page.

## 1. Download

From the release page, get `acxelin-<product>-<version>-wheelhouse.tar.gz`, `SHA256SUMS` and `acxelin-<product>-<version>.cdx.json`.

## 2. Check that Acxelin's workflow built them

You need the GitHub command line (`gh`), signed in to any GitHub account.

```bash
gh attestation verify acxelin-tls-1.2.0-wheelhouse.tar.gz --owner AcxelinQuantum
gh attestation verify SHA256SUMS --owner AcxelinQuantum
gh attestation verify acxelin-tls-1.2.0.cdx.json --owner AcxelinQuantum
```

Each must print `Verification succeeded`. Anything else: stop and do not install.

## 3. Check every file against the list

Linux and macOS:

```bash
tar xzf acxelin-tls-1.2.0-wheelhouse.tar.gz
python3 acxelin-tls-1.2.0-wheelhouse/verify_release.py SHA256SUMS
```

Windows (PowerShell):

```powershell
tar xzf acxelin-tls-1.2.0-wheelhouse.tar.gz
python acxelin-tls-1.2.0-wheelhouse\verify_release.py SHA256SUMS
```

It must print `every file matches its checksum, and nothing else is in the release folder` and exit with status 0. It names each file that is
missing, changed, or present but not listed. Without Python, `sha256sum -c SHA256SUMS` (Linux) or `Get-FileHash -Algorithm SHA256 <file>` (PowerShell)
checks files one at a time but does not notice extra files.

## 4. Read the SBOM

`acxelin-<product>-<version>.cdx.json` is a CycloneDX 1.6 document: one component per wheel in the folder (name, version, SHA-256, and the licence the
wheel declares; none is invented when a wheel declares none) and the dependency edges between them. Give it to your software composition scanner, for example:

```bash
python3 -c "import json; [print(c['name'], c['version']) for c in json.load(open('acxelin-tls-1.2.0.cdx.json'))['components']]"
```

## 5. Container images

```bash
docker pull ghcr.io/acxelinquantum/acxelin-tls:1.2.0
gh attestation verify oci://ghcr.io/acxelinquantum/acxelin-tls:1.2.0 --owner AcxelinQuantum
```

Deploy by digest (`ghcr.io/acxelinquantum/acxelin-tls@sha256:...`) so a tag cannot later point at a different image.

## If a check fails

Do not install. Email info@acxelinquantum.com with "security" in the subject, the exact output, and where you downloaded the file from.

© 2026 Acxelin Quantum, all rights reserved.
