# Acxelin Readiness

## Data flow

```
folder / repository / image / capture ─┐
GitHub link or organisation (API, token)┤──> detectors (source, config, keys, binaries, dependencies, volumes, captures)
named TLS and SSH endpoints (--tls, --ssh)┘        │ detections (noisy)
                                                   ▼
                            verification (confidence, accepted / quarantined / rejected / suppressed)
                                                   ▼
                            ranking (tier by Mosca's inequality, policies: NIST IR 8547, CNSA 2.0, India DST)
                                                   ▼
        cbom.json (CycloneDX 1.6)  readiness.sarif  findings.json  relationships.json  report.html  migration.csv
console (loopback) keeps workspaces, history and imported CBOMs in owner-only files under the user's home
```

## Trust boundaries

| Boundary | Crosses | Held by |
|---|---|---|
| Scanned content → parsers | Hostile files, archives, images, captures | Size, count and time limits; path checks on unpacking; parser failures become notes |
| Scanner → endpoints you name | TLS handshakes and an SSH key exchange | Handshake only: no application data, no credentials. **No rate limit; about 25 connections per TLS endpoint, 16 in parallel** (stage 2) |
| Scanner → GitHub | Archive download with an optional token | The token goes to the API host only; HTTPS to HTTP downgrade refused; no path escapes the folder; size limits |
| Output folder → readers | Snippets of scanned code in `findings.json` | The folder is as sensitive as the code |
| Browser → console | Loopback HTTP | Core console rules |

## Keys and secrets

Readiness creates no keys. It does read them: `detectors/artifacts.py` parses unencrypted PEM and OpenSSH private keys found in
the scanned tree with `load_pem_private_key` to name the algorithm, so key material is held in the scanner's memory while the
file is processed. Reports record the kind, algorithm and size, never the key (tests below). The GitHub token is read from
the environment or the console and kept in an owner-only file when the console stores it (`token_file`).

## Claims and tests

| Claim | Test | What it shows |
|---|---|---|
| Files over 2 MB are skipped and named | `test_engine::test_files_too_large_to_read_are_named_in_the_notes` | |
| A Python file too deeply nested does not stop the scan | `test_robustness::test_a_python_file_too_deep_to_parse_does_not_stop_the_scan` | |
| A malformed manifest or damaged capture does not stop the scan | `test_robustness::test_a_malformed_manifest_is_skipped`, `test_robustness::test_a_cut_off_or_damaged_capture_is_read_as_far_as_it_goes` | |
| Long lines are scanned in linear time | `test_robustness::test_a_long_dotted_line_is_scanned_in_linear_time` | A regex-backtracking defence |
| An image whiteout or path cannot touch anything outside the image | `test_image_safety::test_a_whiteout_never_removes_anything_outside_the_image`, `test_image_safety::test_windows_style_names_are_left_out` | |
| A truncated layer is a note, not a crash | `test_image_safety::test_a_truncated_layer_is_a_note_and_the_rest_is_scanned` | |
| Nothing from a downloaded archive lands outside its folder | `test_remote::test_nothing_in_the_archive_lands_outside_its_folder_or_links_out` | |
| Size limits stop a download and an unpacking | `test_remote::test_size_limits_stop_a_download_and_an_unpacking` | |
| The GitHub token goes only to the API host; HTTPS→HTTP is refused; errors never echo the token | `test_remote::test_the_token_goes_to_the_api_host_only_never_to_where_it_redirects`, `test_remote::test_a_download_that_switches_from_https_to_http_is_refused`, `test_remote::test_errors_say_what_to_do_and_never_echo_the_token` | |
| A ref that looks like an option is refused | `test_hardening::test_a_ref_that_looks_like_an_option_is_refused_and_writes_nothing` | Argument-injection defence |
| An SSH server announcing an empty packet is refused without reading on | `test_hardening::test_an_ssh_server_announcing_an_empty_packet_is_refused_without_reading_on` | |
| Unobserved key sizes never pass CNSA 2.0 | `test_assessment` / `test_evidence` (see `docs/upgrade.md`) | Behaviour is documented; the exact test should be named in the next pass |
| The CBOM validates against CycloneDX 1.6 | `test_keystores`, `tools/validate_cbom.py` in CI `real-world` | Four cloned repositories plus the unit tests; not every emitted shape (merge, imports) is validated |
| Precision and recall do not drop | `test_quality_gate::test_precision_and_recall_hold_the_floor` | On a corpus that was tuned on: a regression guard, not a claim about unseen code |
| Old Wolf Pack names are read with a warning | `test_compat`, `test_hardening::test_old_wolfpack_properties_are_read_with_one_warning_per_file` | |
| Console rules | `test_console` | Same contract as core |

## Claims with no test found

- **Running against production is safe**: no test counts connections per host, and nothing limits them (stage 2).
- The **whole-scan limits** (50,000 files, 512 MB, 300 s) stop a project scan with a clear message; the byte limit has a test
  (`test_volumes`), the file-count and time limits were not found.
- Reports "never include the key itself" for **every** key format: tested per format, not by a sweep like the VPN CBOM's
  `test_inventory::test_no_secret_reaches_the_cbom_in_any_encoding` (VPN).
- Behaviour on a **live IDS**: unknowable from tests.

## Limits

A missing finding is not proof cryptography is absent. An algorithm listed in configuration is offered, not necessarily used.
The quality gate is not a claim about unseen code.
