# Acxelin Readiness manual

Acxelin Readiness finds every piece of cryptography your organisation depends on, shows which of it a quantum computer breaks, and ranks what to migrate first. It writes a CycloneDX 1.6 cryptographic bill of materials (CBOM), SARIF for code scanning, and a report a manager can read.

This manual covers installing it, a first scan in five minutes, the everyday work, running it in CI, and what to do when something goes wrong. Acxelin Readiness installs and runs on its own; it needs no other Acxelin product.

## 1. What you get

| Output | What it is for |
|---|---|
| `report.html` | One self-contained page: every asset ranked from critical to ok, why, and the fix for each. A button downloads the migration plan as `migration.csv`. |
| `cbom.json` | The CycloneDX 1.6 CBOM: the inventory auditors and other tools read. |
| `readiness.sarif` | Findings for GitHub code scanning and other SARIF viewers, on the exact lines. |
| `findings.json` | Every detection and its verdict, for your own analysis. |
| `relationships.json` | Which code calls which cryptography. |

It never changes the files it scans and never sends them anywhere.

## 2. Before you start

- **Python 3.11 to 3.14**, on Linux, macOS or Windows. Nothing else is needed for scanning code, configuration, keys, binaries and dependency files.
- **OpenSSL 3.5 or newer** only to read the certificate of a server that offers nothing but post-quantum key exchange (section 7). Without it, everything else still works.

## 3. Install

The release folder installs on Linux (x86-64 and ARM), Windows (x64) and Macs with Apple silicon, with Python 3.11 to 3.14. On an Intel Mac, use the Docker image.

Get two files from the [release page](https://github.com/AcxelinQuantum/AQPQCSuite/releases/tag/readiness-v1.0.2) and save them in one folder:

- `acxelin-readiness-1.0.2-wheelhouse.tar.gz`: the program, with everything it needs, so it installs without internet access, including the code crawler that follows values through JavaScript, TypeScript, Java and Go
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
shasum -a 256 acxelin-readiness-1.0.2-wheelhouse.tar.gz
```

On Windows:

```
Get-FileHash .\acxelin-readiness-1.0.2-wheelhouse.tar.gz
```

On macOS and Windows this prints the file's fingerprint, a long string of letters and numbers. It should match the one next to the file's name in `SHA256SUMS` (capital or small letters do not matter). If the check fails, delete the file and download it again. Do not install it.

Optional: if you use the GitHub command line, `gh attestation verify acxelin-readiness-1.0.2-wheelhouse.tar.gz --owner AcxelinQuantum` shows that our release workflow built the file. You should see `Verification succeeded`.

**Step 2: unpack it.** The same two lines work in PowerShell:

```
tar xzf acxelin-readiness-1.0.2-wheelhouse.tar.gz
cd acxelin-readiness-1.0.2-wheelhouse
```

**Step 3: install.** Still in that folder:

| System | Run |
|---|---|
| Linux, macOS | `sh install.sh` |
| Windows | `Unblock-File .\install.ps1`, then `powershell -ExecutionPolicy RemoteSigned -File .\install.ps1` |

On Windows, the first command tells Windows you trust this downloaded script, and the second runs it.

The installer checks your Python, puts `acxelin-readiness` on your PATH, runs `acxelin-readiness doctor` and says what to do next. To remove it, run `sh install.sh --uninstall` (or `install.ps1 -Uninstall`). Your scan results stay where they were written.

**With Docker instead:** each release publishes an image. Pull it and give it a short name:

```
docker pull ghcr.io/acxelinquantum/acxelin-readiness:1.0.2
docker tag ghcr.io/acxelinquantum/acxelin-readiness:1.0.2 acxelin-readiness
```

## 4. Your first scan in five minutes

### Step 1: scan a folder

```
acxelin-readiness scan path/to/your/project
```

The terminal shows the ranking at once:

```
acxelin-readiness 1.0.2  payments-api
detectors 49 raw  ->  verify 26 verified, 0 held, 0 rejected, 0 suppressed  ->  rank 0 promoted, 1 trails  ->  16 assets
quantum-safe asymmetric: 1/6 (17%)   hybrid KEX: yes

  ■■■■  critical TLS 1.1                          deployed configuration         1x  TLS 1.3 with X25519MLKEM768
  ■■■□  high     RSA-2048                         deployed key or certificate    2x  ML-KEM-768 for encryption, ML-DSA-65 for signatures
  ■■■□  high     AES-ECB                          application code               2x  Switch to AES-256-GCM (authenticated, randomized)
  ■■□□  medium   ECDSA-P-256                      application code               2x  ML-DSA-65 (or hybrid ECDSA+ML-DSA during transition)
  □□□□  ok       X25519MLKEM768                   deployed configuration         1x
```

### Step 2: open the report

Open `readiness-out/report.html` in a browser. Start with the critical and high rows: each names the file and line, why it ranks there, and what to replace it with.

### Step 3: add your live servers

```
acxelin-readiness scan path/to/your/project --tls api.example.com:443 --ssh bastion.example.com
```

Live endpoints show what your servers actually negotiate, which configuration files alone cannot.

### Step 4: keep the CBOM

`readiness-out/cbom.json` is your inventory. Keep it: the next scan compares against it (section 6).

## 5. Everyday tasks

| Task | Command |
|---|---|
| Scan a repository | `acxelin-readiness scan PATH` |
| Scan a GitHub repository | `acxelin-readiness scan https://github.com/OWNER/REPO` (a branch: `…/tree/BRANCH`) |
| Scan a container image | `docker save IMAGE -o image.tar`, then `acxelin-readiness scan image.tar` |
| Include live endpoints | `acxelin-readiness scan PATH --tls HOST:443 --ssh HOST` |
| Read handshakes from a packet capture | `acxelin-readiness scan PATH --pcap traffic.pcapng` |
| Grade endpoints A to F | `acxelin-readiness grade hosts.txt --html grades.html` |
| Evidence for an audit | `acxelin-readiness report --certs certs/ --targets hosts.txt --cbom readiness-out` |
| Check against standards | `acxelin-readiness scan PATH --policy nist-ir-8547 --policy cnsa-2.0` |
| One view of many systems | `acxelin-readiness merge out-a out-b other.cbom.json --name "Example Bank"` |
| Leave out folders | `acxelin-readiness scan PATH --exclude generated --exclude "*.min.js"` |
| See what this machine can scan | `acxelin-readiness doctor` |

### Mark a line that is not about security

A hash used as a cache key or a checksum is not a security risk. Add `acxelin:ignore` with the reason in a comment on that line or the line above:

```
digest = hashlib.md5(body).hexdigest()  # acxelin:ignore cache key, not security
```

The finding is kept as *suppressed* in `findings.json`, so the decision stays visible.

### Grade endpoints

`acxelin-readiness grade hosts.txt` grades each TLS and SSH endpoint in the file (one `host:port` per line):

| Grade | Means |
|---|---|
| **A** | post-quantum key exchange only |
| **B** | post-quantum key exchange, with a classical fallback |
| **C** | classical TLS 1.3, or TLS 1.2 |
| **F** | nothing answered, or no TLS |

### The evidence report

`acxelin-readiness report` maps what you give it to NIST IR 8547 and CNSA 2.0 on one page, ordered by what to do first:

- `--certs DIR`: every certificate in a folder of PEM files (algorithm, expiry, whether it needs ML-DSA-87)
- `--targets HOST ...`: endpoints, graded now
- `--cbom PATH` (repeatable): a scan's output folder, or any CycloneDX CBOM, including the exported inventory of another system

It writes `report.html` and `assessment.json` to the folder given with `-o` (default `readiness-report`).

## 6. Running it in CI

Scan on every pull request, and fail only when someone adds new cryptography at a tier you care about:

```
acxelin-readiness scan . --baseline cbom.json --fail-on high
```

`--baseline` compares with the CBOM you kept, so old findings do not block new work. `--changed-since origin/main` scans only the files a pull request changes.

**GitHub Actions:**

```
- uses: AcxelinQuantum/AQPQCSuite/products/readiness@<tag>
  with:
    path: .
    fail-on: high
    baseline: cbom.json
    upload-sarif: true
```

**Docker** (any CI): `docker run --rm -v "$PWD:/scan" acxelin-readiness`. On Linux, add `--user "$(id -u):$(id -g)"` so the scan can write `readiness-out` into your folder.

### Settings

Put settings in `.acxelin-readiness.toml` at the root of the scanned folder, so every scan of it uses the same ones. The keys are the long option names with underscores:

```
exclude = ["generated", "*.min.js"]
tls = ["api.example.com:443"]
shelf_life = 10                       # years the protected data must stay secret
migration = 5                         # years your migration will take
crqc_year = 2035                      # assumed year a quantum computer can break today's keys
fail_on = "high"

[policy]
profiles = ["nist-ir-8547", "cnsa-2.0"]
forbid = ["MD5", "SHA-1"]
min_bits = {RSA = 3072}
require_hybrid = true
```

`config/example.toml` lists every setting.

## 7. The console

```
acxelin-readiness console
```

Your browser opens, already signed in, with two parts:

| Part | What you do there |
|---|---|
| **Projects** | Add a folder or a GitHub link, scan it, cancel a running scan (the previous result is kept), and see priorities and history. |
| **Endpoints** | Scan hosts, see what changed since the last scan, what can happen if nothing changes and what to do first, and export the CBOM. |

The console listens only on this machine. From a remote server, forward a port and ask for a fresh link:

```
ssh -L 8900:127.0.0.1:8900 server
acxelin-readiness console link --port 8900
```

In Docker, start it with `--container` and publish the port on loopback only:

```
docker run -d --name readiness -v readiness:/data -p 127.0.0.1:8900:8900 acxelin-readiness console --container
docker exec -it readiness acxelin-readiness console link
```

### GitHub repositories

Paste a link such as `https://github.com/OWNER/REPO` under **Add from GitHub**. You don't need a folder for it. Each scan
downloads the repository again through GitHub's API, so the results always describe what is on GitHub now, and nothing in it
is run. The download is limited to 256 MB, and the unpacked files to 512 MB and 50,000 files. Links, absolute paths and paths
that leave the folder are left out.

For a private repository, create a fine-grained token with read-only **Contents** access to it and save it under **Private
repositories**. The token is stored on this computer, readable only by you. It is sent only to `api.github.com`, never to
the host GitHub redirects the download to, and never shown again. **Remove token** deletes it. On the command line, set
`GITHUB_TOKEN` instead. There is deliberately no flag, because flags are visible to other users of the machine.

A downloaded repository's own `.acxelin-readiness.toml` is ignored, so a stranger's repository cannot choose which hosts
your computer probes. Pass `--config` to use settings you trust.

### Full TLS handshakes

Grades, accepted groups and SSH algorithms need nothing extra. To read the certificate of a server that offers only post-quantum key exchange, Acxelin Readiness completes a real TLS 1.3 handshake through OpenSSL 3.5 or newer. Point `ACXELIN_OPENSSL` at the folder that holds it; `doctor` says whether it is found. Without it, the report says those certificates were not observed. It never marks them as passing.

## 8. How a finding becomes a result

1. **Detectors** report everything they see, noisily: calls, imports, constants, names, configuration, keys, certificates, binaries, dependencies and live endpoints.
2. **Verification** gives each detection a confidence from its evidence (a call outweighs a name, and corroboration raises it). Above the threshold (0.6 by default) it is *accepted*; below, *quarantined*. Known false patterns are *rejected*, and lines marked `acxelin:ignore` are *suppressed*.
3. **Ranking** groups accepted detections into assets and gives each a tier (critical, high, medium, low, ok) from the algorithm, its key size, whether it protects data that must stay secret, and your timeline.

### What it reads

| Source | What is read |
|---|---|
| Code | Python, JavaScript, TypeScript, Java, Go, C and C++, Rust, C#, Swift, PHP, Ruby, shell, Dockerfiles and more: calls, imports, constants, names and parameters |
| Configuration | YAML, JSON, TOML, INI, nginx, Apache, sshd, Kubernetes, Terraform: algorithm and cipher lists |
| Keys and certificates | PEM and DER certificates, keys, keystores, SSH keys and known hosts |
| Binaries and images | Library versions and algorithm strings in compiled files; container images saved with `docker save` or as OCI archives |
| Dependencies | Package manifests and lockfiles of the common ecosystems |
| Live | TLS endpoints (accepted groups, certificate, grade) and SSH servers (algorithm lists, host keys) |
| Captures | Handshakes in `.pcap` and `.pcapng` files: what clients and servers actually negotiated |

### Tiers and the timeline

The tier follows Mosca's inequality: an asset is urgent when the years its data must stay secret, plus the years your migration takes, exceed the years until a quantum computer can break it. Set the three numbers with `--shelf-life`, `--migration` and `--crqc-year`, or in the settings file.

### Standards

`--policy nist-ir-8547` flags quantum-vulnerable public-key cryptography with NIST's deprecation (2030) and disallowance (2035) dates, and anything below 112 bits now. `--policy cnsa-2.0` checks the CNSA 2.0 suite (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87). A key size that was not observed is reported as unverified, never as compliant.

## 9. When something goes wrong

| You see | What it means | What to do |
|---|---|---|
| A finding you know is not a security use | A checksum or cache key, for example. | Mark the line with `acxelin:ignore` and the reason (section 5). |
| Too many findings from generated or vendored code | Those folders are scanned like your own code. | Add them to `exclude` in `.acxelin-readiness.toml`. `vendor/` and `node_modules/` are skipped unless you pass `--include-vendor`. |
| `certificates ... not observed` in the report | The server offers only post-quantum key exchange, and this machine has no OpenSSL 3.5. | Point `ACXELIN_OPENSSL` at OpenSSL 3.5, or run the scan from the Docker image. |
| `Permission denied` writing `readiness-out` in Docker | The image runs as user 10001. | Add `--user "$(id -u):$(id -g)"` on Linux. |
| `The project scan failed` in the console | The folder could not be read. | Check its permissions; `acxelin-readiness scan` on the same folder shows details. |
| CI fails on old findings | No baseline was given. | Keep `cbom.json` from a scan of your main branch and pass it with `--baseline`. |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Finished |
| 1 | Bad usage or unreadable input |
| 2 | A gate fired: the `--fail-on` tier was reached, or `--fail-on-policy` found a broken rule |

## 10. Questions

**Does it change or upload my code?** No. It only reads the files you point it at, and its outputs stay on your machine.

**Can I scan servers I do not own?** Only with written permission from their owner. Live scans connect to the endpoints you name.

**Is a clean report proof there is no weak cryptography?** No. A missing finding is not proof of absence (see Limits).

**Which other tools read the CBOM?** Any tool that reads CycloneDX 1.6. `merge` also combines CBOMs from other tools into one view.

**Does it need any other Acxelin product?** No. It installs and runs on its own, from its own release folder.

## 11. Limits

- A missing finding is not proof that cryptography is absent. Code that builds algorithm names at run time, or loads them from outside the scanned files, can be missed.
- The quality gate's precision and recall come from a labelled corpus that was tuned on, so they guard against regressions. They are not a claim about unseen code.
- An algorithm listed in configuration is offered, not necessarily used. Live endpoints and packet captures show what is actually negotiated.
