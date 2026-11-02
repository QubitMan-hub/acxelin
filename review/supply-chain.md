# Supply chain: what a customer can verify, and what is not claimed

| Claim | Evidence | Where |
|---|---|---|
| Each release carries an SBOM listing every wheel with its SHA-256 | `tools/sbom.py`, run in `release-products.yml`; output validated against CycloneDX 1.6 in tests, and run once on a real core wheelhouse | `tools/tests/test_supply_chain.py` |
| The SBOM does not invent licences or skip a wheel | A wheel with no declared licence has none listed; a wheel without metadata stops the build | same |
| The tarball, the checksums and the SBOM are attested by the release workflow | `attest-build-provenance` subject list; a test reads the workflow | same |
| A customer can check a release offline | `tools/verify_release.py` (stdlib only) names a changed, missing or unlisted file and a path that leaves the folder; the guide ships inside the release as `VERIFY.md` | same; `documents/verify-a-release.md` |
| Every CBOM shape Readiness emits is valid CycloneDX 1.6 | A scan that emits all four asset types and libraries, the merged CBOM of two systems, and a guard that fails when a new asset type has no validated sample; mutations (a wrong asset type, an extra property) made the tests fail | `products/readiness/tests/test_cbom_schema.py` |
| The VPN's CBOM validates | existing | `products/vpn/tests/test_inventory.py` |
| Readiness reads other tools' CBOMs without loss | CBOMkit's three example CBOMs (unmodified, Apache-2.0, commit recorded): each is valid, every algorithm is rated or counted as unrecognised, and the merge keeps all key material | `products/readiness/tests/fixtures/cbomkit/` |

**Limits.**
- The attestation proves GitHub's release workflow built the file from the tagged commit. It does not prove the code is free of bugs. Neither the
  workflow's first run nor an attestation verification has happened yet (no release was cut from this change); the first `core-v*` tag will be
  the first real run. The guide's commands are the standard `gh attestation verify` forms and have not been run by me here (no `gh` credentials).
- Sonar Cryptography Plugin output was not obtained directly: running it needs SonarQube. CBOMkit's README states that its scanning is that plugin, so its
  examples are what the plugin writes, but that is CBOMkit's statement, not something checked here.
- The SBOM lists the Python wheels in the folder. It does not list the operating-system libraries inside the container images, the
  OpenSSL 3.5 build the Windows and macOS installers bundle, or the installers themselves.
- The Windows Setup, macOS disk image and Linux package are attested by the workflow's installer job, not listed in the SBOM, and not code-signed here.
