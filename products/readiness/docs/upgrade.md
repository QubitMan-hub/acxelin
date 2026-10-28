# Upgrading to Acxelin Readiness 1.0

Acxelin Readiness replaces Wolf Pack CBOM 1.x.

## Commands

| Before | Now |
|---|---|
| `wolfpack scan PATH` | `acxelin-readiness scan PATH` |
| `wolfpack merge ...` | `acxelin-readiness merge ...` |
| `wolfpack bench` | removed; the quality gate runs in the product's tests |
| `wolfpack scan --without ROLE` | removed; every detector always runs |

## Names read through every 1.x release

Each old name still works and prints a one-line warning naming the new one. Old names are removed no earlier than 2.0.0.

| Old | New | When both exist |
|---|---|---|
| `wolfpack:ignore` comments | `acxelin:ignore` | both are honoured (each applies to its own line) |
| `.wolfpack.toml` | `.acxelin-readiness.toml` | the new file is used and the old one is ignored, with a warning |
| `wolfpack:*` properties in CBOMs given to `merge` | `acxelin:*` | the new property wins |

## Changed results

- **CNSA 2.0:** AES whose key size wasn't observed is now reported as "unverified" and fails `--fail-on-policy`. Before, it passed. This is a deliberate fix, because compliance that wasn't observed isn't proven.
- **`merge`:** assets are now matched by what they are. Algorithms match by name and parameters, certificates and public keys by fingerprint. Secret material and protocol instances are never merged across systems.
  - When systems disagree about a field, every system's value is kept in `acxelin:observations`, and the field is named in `acxelin:conflict`.
  - `bom-ref` values are now `<asset type>/<hash>`.
- **GitHub Action path:** the Action is now `AcxelinQuantum/AQPQCSuite/products/readiness`. Change `uses:` to it; the inputs are the same.
- **Output names:** the folder is `readiness-out/` (was `wolfpack-out/`), the SARIF file `readiness.sarif` (was `wolfpack.sarif`), and the report's CSV download `migration.csv` (was `wolfpack-migration.csv`). In `findings.json`, `sightings` is now `detections`.

## Rolling back

Reinstall the previous release. Scan outputs are files you keep; Acxelin Readiness has no state to restore. Baselines written by 1.0 still name every asset and its locations, so Wolf Pack 1.x can read them.
