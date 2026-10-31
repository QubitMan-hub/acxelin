# Changelog

## Unreleased

- Breaking: live probes (`scan --tls` and `--ssh`, `watch`, `grade`, `report --targets`, the console's endpoint scans) are paced by
  default. Each host and port gets at most 2 new connections in any second and one at a time, and `grade`, `report` and the console
  probe 4 endpoints at once (was 16, unpaced). Grading one TLS endpoint opens about twenty connections, so it now takes about ten
  seconds, and many endpoints on one host take proportionally longer. Grades are unchanged. For the old behaviour pass
  `--aggressive` (16 workers, no pacing; `aggressive = true` in the settings file; `"aggressive": true` in a console request), or
  set `--rate N` (0 for no limit) and `--workers N`. A scan prints how it is pacing and, when it finishes, how many connections
  it opened to each host and port. An endpoint that waits more than five minutes for its turn is graded F with that reason.
- `grade` and `report` take `--config FILE`; `rate`, `workers` and `aggressive` are new settings.

- The console follows the repository's `.acxelin-readiness.toml` (exclusions, years of secrecy, migration years, threshold),
  as `scan` does; a GitHub download's own file is not trusted.
- Board summary: the trend compares the same projects then and now, and "nothing to change" is never listed as an action.
- Third-party libraries are listed per version, so an old version is not hidden behind a newer one.
- A file whose name merely contains "test" (attestation.py, latest/) is not treated as a test.
- `report --certs` names ECDSA, DSA and EdDSA keys correctly (DSA and RSA under 2048 bits need action now) and reads DER files.
- Owners spreadsheets: a UTF-8 byte order mark, Windows-1252 text, ServiceNow criticality ("1 - most critical"),
  backslashes and `./` in paths all work. A CODEOWNERS `dir/*` rule matches only that folder's own files.
- Findings only in tests are not counted as new or gone after a rescan.
- A damaged workspace is kept aside and the console starts with an empty one; a damaged settings file asks for the folder again.
- Line numbers such as "12-14" in another tool's CBOM are read; a GitHub organisation import stops at 200 and says how many
  it left out; a project with an RC2 finding no longer stops the console from opening.

## 1.1.0

- IoT and industrial systems: OPC UA security policies (Basic128Rsa15 to ECC_curve448) are read from code, by their URI, and from
  configuration (`securityPolicy: Basic256Sha256`, `<SecurityPolicyUri>`) as the algorithms each uses; endpoints can be written
  as `mqtts://`, `amqps://`, `ldaps://` and other TLS schemes, which give their usual port, and `coaps://` is pointed at a capture.
- `report --cbom` rates another tool's CBOM: a component without Readiness's own priority gets one estimated from its algorithm,
  with its NIST IR 8547 status, as `merge` and the console already did. It gave an empty report before.
- A packet capture's notes name the conversations that were not TLS, DTLS, QUIC, SSH or IKE, so a capture of a protocol the
  reader does not know no longer reads as "0 handshakes" alone.
- Scheduled scans: `acxelin-readiness watch` scans again every few hours (or once, from cron, a systemd timer or Windows
  Task Scheduler), writes `changes.json` with the findings that appeared and disappeared, and can run a command when anything
  changed. The console says what is new since the last scan.
- AWS: `scan --aws REGION` reads KMS keys and ACM certificates with the caller's credentials, list and describe calls only, and
  ranks them like any other finding (the new `aws` extra, included in the release folder and the Docker image).
- Services: a CMDB export may name each path's business service; findings show it, the console filters by it, and the CSV
  carries it.
- How long data stays secret: a CMDB export's `keep secret (years)` column sets, per path, the years used for harvest-now risk
  (default 10), in the console from the next scan and with `scan --owners`. Its `importance` column weighs services in the ranking.
- How hard each change is: every finding says whether fixing it means changing a setting, reissuing a key or certificate,
  upgrading a library, changing code or replacing a vendor component, and "Why it matters" counts them.
- Third-party libraries: the Overview lists the cryptography libraries each project depends on and whether they support
  post-quantum algorithms.
- `--policy india-dst`: India's DST roadmap, quantum-vulnerable cryptography due by the end of 2029 (`india_deadline` to change it).
- Console: a start page with three clear choices, summary cards for the numbers that matter, sections named by the question they
  answer instead of "descriptive" and "prescriptive", a quieter owner prompt, the downloads grouped, and the endpoint grades
  explained before the first check.
- Console Overview: every project side by side, one button to scan them all, every repository of a GitHub organisation added at
  once, business services ranked across projects, and the results of scheduled scans (`watch --home`).
- Board summary: one printable page for directors from every project's latest scan (level and trend, findings that need action,
  harvest-now and 2030 exposure, progress, the first five actions, the services most at risk), marked provisional when projects
  are unscanned or coverage is under 80%.
- Deadlines that apply to you: choose countries (US, UK, EU, Canada, India) and sectors on the Overview; their dated milestones
  are listed with sources and the next one goes on the board summary. The board also gives the weakest project and the share of
  remaining changes that need no code (crypto-agility).
- Endpoints: publicly trusted TLS certificates are checked against the CA/Browser Forum's shorter lifetimes (200 days from
  15 March 2026, 100 from 15 March 2027, 47 from 15 March 2029); certificates over the limit, or that renewal by hand will not
  keep up with, are named, with automated renewal (ACME) as the action. Certificates now record their issue date and lifetime.
- Before and after: a rescan lists the findings no longer found and the new ones, by name and priority.
- Fix examples: findings in Python, Java, Go, JavaScript, TypeScript and nginx show a short before and after in that language.
- Console polish: a search box for findings (`/`), confirmation before removing a token or an owner list, a message when
  something is saved, numbers aligned in tables, and the GitHub and import forms tucked under one heading.
- Owners loaded from a CMDB export are kept when the project is scanned again; they were dropped before.
- Endpoints: RC4, 3DES and Diffie-Hellman under 2048 bits are offered by raw ClientHello and named with their suite and size
  ("DHE 1024-bit (DHE-RSA-AES128-SHA)"), with a risk and a recommendation of their own; a server that speaks TLS 1.2 only with
  such suites is graded C, not F, and no longer described as TLS 1.0 or 1.1 only. The probe now sends key shares for
  X25519MLKEM768 and X25519 as browsers do, so the negotiated group is the one a browser gets (an OpenSSL that cannot read the
  key-share marks is offered the plain list). An SSH server that still offers a DSA host key says so.
- Captures: connections are kept apart by the name the client asked for (SNI), so sites sharing an address no longer merge,
  and the size of a DHE prime is read from the ServerKeyExchange.
- Fewer false alarms, each found scanning a real project: `arc4random` is a random generator, not RC4 (Go); `des.NewTripleDESCipher`
  is 3DES and not also DES (Vault); a TLS version named next to `SSL_OP_NO_TLSv1` is being switched off (OpenSSL); a constant
  ending in `_PREFIX` is not a secret (Django); `testing/` packages and `testing.go` or `testutil` files are tests (Kubernetes,
  Vault); a folder of one-root-per-file certificates is a trust store (`/usr/share/ca-certificates`); the hash of a
  self-signature is not asked to be re-signed. A finding weak in only some places says how many ("at 1 of 9 places").
- Memory: the project-wide Python index keeps function bodies only in files that name a crypto library and keeps call sites
  cut down to what values need; over 5,000 Python files it indexes only crypto files and their direct imports and importers,
  and the scan says so. Home Assistant's 20,000 files no longer run out of memory. Scans no longer print Python's warnings
  about other projects' code or cryptography's about unusual certificates.
- Endpoints, from a run against real servers: a server that speaks only TLS 1.0 or 1.1 is graded C with those versions named
  (it was graded F, "handshake failed"); when the TLS 1.0 and 1.1 check gets no answer the result says it could not be
  checked instead of reporting none (a hang-up is asked once more before it counts as a refusal); negotiated group names
  match the accepted list (`X25519`, not OpenSSL's `x25519`); a TLS 1.2-only server no longer lists its protocol version
  as an accepted group; SSH host keys carry no made-up expiry (`days_left` is empty, not 9999).
- Ruby: the OpenSSL and Digest libraries are read (RSA, EC and Ed25519 keys, HMAC, ciphers, TLS versions, PBKDF2), and
  quoted strings in Ruby, shell and PowerShell files are now checked like those in other languages.
- PHP: the openssl extension (key types, curves, signature hashes, ciphers) and `hash`, `hash_hmac` and `hash_pbkdf2`.
- Shell scripts: `openssl genrsa`, `genpkey`, `req -newkey`, `ecparam`, digest flags and `enc` ciphers, and `ssh-keygen`.
- Terraform: a curve on the line after a key (`ecdsa_curve = "P384"`) belongs to that key; ACM's `EC_prime256v1` is read.
- Captures: IKEv1 Main and Aggressive Mode exchanges are read: the responder's chosen cipher, hash (as the HMAC-based PRF),
  Diffie-Hellman group and authentication method (RSA or ECDSA signatures; pre-shared keys name no algorithm).
- A TLS cipher suite's trailing hash is reported as HMAC with that hash (the record MAC or the PRF), with the hash beside it.
- Console, calmer results: findings with nothing to change fold behind one button; progress shows as a bar that fills as
  fixes and accepted risks land ("3 of 27 findings that need work are done"); long lists of findings under a risk or a
  recommendation show the first eight and the rest on request; what a finding could not see moves into its details.
  An endpoint graded from raw ClientHello messages says so under its negotiated group.
- Binary (DER) private keys in PKCS#1, PKCS#8 or SEC1 form, encrypted ones included, DER public keys, and certificate
  requests in DER or PEM are found like PEM keys; before, only DER certificates were. Files ending `.p8` and `.pk8` are read.
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
