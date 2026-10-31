# Contributing

How to work on this repository. Using a product is in its own README under `products/`.

## Layout

| Folder | What it is |
|---|---|
| `core/` | acxelin-core: shared mechanisms, no product policy. Works with nothing else installed |
| `products/readiness/`, `products/tls/`, `products/vpn/` | One product each: `src/`, `tests/`, `docs/`, `examples/`, `deploy/`, `install.sh`, `install.ps1`, its own CHANGELOG |
| `website/` | The shared home page and one section per product; `python tools/build_site.py` builds it into `build/site` |
| `tools/` | Repository tooling: site build, `release_check.py`, `wheelhouse.py`, the browser test kit, repository checks in `tools/tests` |

A product never imports another product, and core never names one; the import tests in each product fail if that changes.

## Set up and test

Python 3.11+ and OpenSSL 3.5+ (`ACXELIN_OPENSSL` set to its lib folder, `bin` on Windows; on Linux also `LD_LIBRARY_PATH`).

```
pip install -e ./core -e "./products/readiness[crawler,test]" -e "./products/tls[test]" -e "./products/vpn[vpn,desktop,test]" ruff==0.14.0 playwright==1.56.0
npm ci --prefix tools/browser
ruff check .
python -m pytest -q core/tests products/tls/tests tools/tests
python -m pytest -q products/readiness/tests website/tests
python -m pytest -q products/vpn/tests
```

Run the pytest commands separately: the products each have a `test_install.py`, which clash in one run. Installer tests
run with `ACXELIN_INSTALL_TEST=1`. CI pins OpenSSL 3.5 (the LTS line customers run) with `ACXELIN_REQUIRE_OPENSSL=3.5`: a different or
unloadable OpenSSL stops the run instead of skipping the tests that need 3.5; set it yourself to get the same on your machine. Readiness's labelled corpus (`products/readiness/bench`) is a quality gate: precision and
recall must not drop, and `truth.json` changes only in commits titled `truth:` that the owner approves.

## Releases

One tag per product, core first: `core-vX.Y.Z`, then `tls-vX.Y.Z`, `vpn-vX.Y.Z` or `readiness-vX.Y.Z`. Set the version in that package's
`pyproject.toml` and add `## X.Y.Z` to its CHANGELOG first. `.github/workflows/release-products.yml` gates the tag with
`tools/release_check.py` and publishes a wheelhouse with the installers, SHA-256 checksums, build provenance and the GHCR
image; a VPN release also attaches the desktop installers. Nothing is uploaded to PyPI.

## Rules

- Tests for intended behaviour come first; never weaken or delete a test to make something pass.
- Every security behaviour has a test showing the attack refused.
- Python only; the runtime cryptography is `cryptography` and OpenSSL 3.5 through core's binding, never the `openssl` command.
- Everything must work on Windows.
- Readiness still reads Wolf Pack's old names (`wolfpack:ignore`, `.wolfpack.toml`, `wolfpack:*` CBOM properties) through
  its 1.x line, with a warning. Breaking changes go in the product's CHANGELOG.
