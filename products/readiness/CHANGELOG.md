# Changelog

## Unreleased

- Captures: DTLS 1.0, 1.2 and 1.3 handshakes (WebRTC, VPN clients, CoAP) are read, their fragments put back together, and
  graded with the cryptography of the TLS each is built on. Captures of raw IP frames (link types 228 and 229, as taken on
  tunnel and VPN interfaces) are read. A TLS 1.2 suite with RSA key transport (`TLS_RSA_WITH_AES_128_CBC_SHA`) now names
  RSA, and a cipher suite's MAC or PRF hash is not rated as broken. IKEv2 HMAC-SHA1-160 and HMAC-MD5-128 integrity are named.
- Import a CBOM: names from CycloneDX's published examples are rated as their algorithm earns: `RSA-PKCS1-1.5-SHA512-2048`
  is not read as 512-bit RSA, AES with a 192- or 256-bit key is ok, `SHA512withRSA` is recognised and `MD5withRSA` is
  critical, and known protocols (`TLSv1.2`) are rated. A CBOM whose tool has no name says "another tool".
- Endpoints: on a machine whose OpenSSL is older than 3.5, a server that speaks TLS 1.3 was graded C ("classical only")
  because the check fell back to TLS 1.2. It is now graded from raw ClientHello messages, which need no new OpenSSL, and
  says so; a server with no TLS 1.3 is still graded C.
- SHA-1 (or MD5) used only inside HMAC, PBKDF2, RSA-OAEP or MGF1 is rated low, not broken: these need no collision
  resistance. RSA with OAEP over SHA-1 is no longer called a signature over SHA-1. SHA-1 anywhere else is unchanged.
- Java's `RSA/ECB/...` transformation no longer counts as ECB mode (Java's name for a single RSA block), so RSA is not
  told to switch to AES-GCM. `AES/ECB/...` is still critical.
- A finding lists its places in real code before its places in tests. `regress/`, `regression/` and `test-*` folders
  count as tests. Deprecated DSA keys no longer print warnings during a scan.
- Console: results now read as four analyses, each named on the page and reachable from an "At a glance" summary:
  Descriptive (what was found: a priority or grade bar and the table), Diagnostic (why: what each priority or grade means,
  what puts findings at risk, how they were seen, score, coverage and trend), Predictive (what can happen if nothing
  changes) and Prescriptive (what we recommend). Projects gain the predictive and prescriptive lists that endpoints had:
  broken today, recordable now and readable later, forgeable later, the NIST IR 8547 dates, Grover-weakened, fixes that did
  not land, overdue or expired items and unread files; recommendations are grouped by the change to make, worst first.
- Owners: a finding suggests its owner from the repository's CODEOWNERS file, read as GitHub reads it, or from a CMDB
  export (a CSV of path patterns and owners) loaded per project. The CMDB export comes first, and an owner set by hand
  always wins. A finding with no owner reads "No owner · review needed". The CSV export names the owner's source.
- Coverage beside the score: for a project, the share of source and configuration files fully analysed (files over 2 MB and
  Python that could not be parsed are not); for endpoints, the share that could be graded. It is shown in the console, kept
  in the score history and printed by `scan`. When coverage falls by 10 points or more, the console says the score rests
  on less than the scan before.
- Console: each finding says how it was seen (negotiated, offered, in code, configured, or supported only), how sure the scan
  is (high, medium, low), and what it could not see (a key size, a curve, a mode, a hash, or any observed use). The CSV
  export carries the same three columns.
- Console: **Import a CBOM** turns another tool's CycloneDX CBOM (CodeQL's, for one) into a project with priorities, tracking,
  history and a score. Tiers come from its `acxelin:*` properties or are estimated from the algorithm; unknown names are
  counted, not rated. Imports are kept owner-only in the console's folder.
- Console: findings move through To do, Planned, In progress, Fixed and Accepted risk. Each change of status, owner or due date
  is kept in the finding's history (the last 50). A finding marked Fixed that a later scan still finds is flagged, and the
  page counts findings by status. Workspaces from earlier versions keep their statuses.
- Encrypted volumes: LUKS 1 and 2 (also inside qcow2), qcow2's built-in AES, BitLocker, encrypted macOS disk images and
  `/etc/crypttab` plain-mode entries report their cipher, key size and key derivation, read from the header without a
  passphrase. AES-128 volumes and qcow2's own AES show up for migration.
- Files over 256 MB, which no detector reads in full, no longer count towards the scan's size limit, so a folder with a
  disk image still scans. A finding in a large file no longer makes the scan read the whole file to look for an ignore
  comment: a 3 GB image took 50 s.
- Packet captures: QUIC and IKEv2 handshakes are read alongside TLS and SSH. For QUIC, the TLS handshake inside the
  Initial packets (protected only by keys anyone can derive, RFC 9001) gives the negotiated group, suite and SNI. For
  IKEv2, the IKE_SA_INIT exchange gives the chosen cipher, PRF, integrity and key exchange, including ML-KEM as an RFC 9370
  additional key exchange, and whether the initiator offered it. These endpoints are named `pcap://FILE/quic/HOST:PORT`
  and `pcap://FILE/ike/HOST:PORT`.
- Fixes from a review:
  - `--changed-since` refuses a ref that starts with `-`. Such a ref could pass options to git and write a file.
  - `--changed-since` no longer misses changed files with non-ASCII names. Missing them let `--fail-on` pass.
  - `merge` reads other tools' CBOMs: the CycloneDX 1.4 tools list, missing or numeric names, and non-object entries. A file
    that is not a CBOM gets a message instead of a traceback.
  - `merge DIR` skips its own earlier output.
  - Old `wolfpack:*` properties print their one-line warning, as `docs/upgrade.md` says.
  - A damaged `--history` line is dropped, and history values are escaped in the page.
  - An SSH server announcing a zero-length packet is refused at once. Before, the reader read until the server stopped.
  - `report --certs` lists certificates whose key type the library cannot load.
  - The workspace retires the oldest findings no longer observed, instead of refusing every save after 5,000.
  - SARIF locations are percent-encoded URIs.
  - The GitHub Action passes `args` such as `--exclude *.min.js` unexpanded.
  - `grade` and `report` say when they cannot write their output.
  - The Windows installer writes its wrapper in the console code page, so a user name such as José keeps its path.
  - Temporary copies, including downloaded private repositories, are removed when a scan stops early.
  - Container images: a layer can no longer delete or write outside the unpack folder. Whiteouts such as `.wh..`, and on
    Windows names with backslashes or drive letters, did. A truncated layer becomes a note, and a tar whose
    `manifest.json` is not from `docker save` is scanned as a plain archive.
  - One file never ends a scan: a Python file nested too deeply to parse, a malformed `package.json`, `pyproject.toml`
    or `Cargo.toml`, and a capture cut short by its snap length are each skipped, the capture with a note.
  - A `cache_size` or similar next to an algorithm is no longer read as an RSA key size, which had raised a false
    critical. `size: 2048` (as cert-manager writes it) is still read.
  - NIST IR 8547 deadlines apply after their year, as the draft says. RSA-2048 is deprecated from 2031, not 2030.
  - A certificate signed with its own key type keeps its signature algorithm in the CBOM. The same certificate in two
    files is one component with two occurrences, so bom-refs stay unique.
  - Certificates signed with SHA-224 (RSA or ECDSA), MD2 with RSA, or SLH-DSA name their signature.
  - SHA-512/224 and SHA-512/256 are their own algorithms, rated by their output. SHA-512/224 is quantum-weakened, like
    SHA-224; it was reported as quantum-safe SHA-512. CBOMs name them `SHA-512/224` and `SHA-512/256` instead of `SHA-512`.
  - A reference such as `a/server.key` marks only that key as deployed. Before, another `server.key` elsewhere in the
    repository could be marked instead.
  - JavaScript key generation reads only its own call's options: a neighbouring call's `modulusLength` or `namedCurve`
    no longer attaches to the wrong key. RSA gets a size and EC a curve, never the other way round.
  - Java classes written with their package (`new java.security.spec.ECGenParameterSpec(...)`) are read like imported
    ones.
  - String literals are found in one pass. An opening quote followed by many escaped quotes took 5 s per line.
  - Large repositories scan in linear time: 400 Java files took 44 s and now take 6 s, and one file with 8,000 hash
    calls went from 10 s to under 2 s. A 40 KB line of dotted names no longer takes 20 s.
- Exports: `report` also writes `assessment.csv`, and the console has **Download CSV** for findings and endpoint grades.
  Formula-like cells are neutralised. Every HTML report and the console print cleanly to PDF through the browser.
- Evidence rows name the NIST CSF 2.0, DORA (Delegated Regulation (EU) 2024/1774) and NIS2 Art. 21(2)(h) controls they
  support, in `assessment.json` (`frameworks`), the CSV and the report. They are not a compliance verdict.
- Keystores: PKCS#12 (`.p12`, `.pfx`) and Java keystores (`.jks`, `.jceks`, `.keystore`, `.truststore`) are read without a
  password. Findings show what protects them (40-bit RC2, 3DES, RC4, SHA-1, MD5, or PBKDF2 with AES), the certificates they
  hold in the clear, and private-key entries named by their certificate. The CBOM gives such keys the format `PKCS#12`, `JKS`
  or `JCEKS` instead of `PEM`.
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
