# Competitor features: what exists elsewhere, what Acxelin lacks, what to build first

Status: research and proposal. Nothing here is built. Written 2026-10-31 from public pages found by web search; most of what the search
returned was vendor documentation and secondary blogs, so each row says how well it is sourced. "Acxelin today" was checked against the
code in this repository (a search for the feature in `core/src` and `products/*/src`), not against our own marketing.

Rules that bind every item (CLAUDE.md): features are taken as ideas, never as code (rule 10 states it for one reference; it is the
policy for all); wire and cryptographic formats do not change (rule 5); a test for each security behaviour, written first (rule 4);
nothing is claimed without a stated limit.

## What the competitors do that we do not (checked in our code)

### TLS / CA

| Feature | Seen at | Source quality | Acxelin today | Size | Notes |
|---|---|---|---|---|---|
| ALPN and SNI-based routing to different backends on one port | HAProxy, nginx, Envoy (standard proxy behaviour) | Common knowledge; not re-verified this session | `server_name` per route, no ALPN match | Medium | Banks put many services behind one edge port |
| ACME `dns-01` challenge (wildcards, hosts not reachable from the internet) | step-ca and certbot list it | [step-ca docs](https://SmallStep.com/docs/step-ca/), third-party listing | `http-01` only; no `dns-01` | Medium | A command hook (like certbot's manual hook) avoids writing a driver per DNS provider |
| ACME Renewal Information (ARI, RFC 9773): the CA tells clients when to renew | Let's Encrypt, step-ca not confirmed | Not found by the search; check the RFC | None | Small | Needs a primary source before it is built |
| OCSP responder and stapling | Smallstep lists it as a limit of the free step-ca; commercial CAs have it | [step-ca docs](https://SmallStep.com/docs/step-ca/) | None; CRLs only, fail-closed | Large | OpenSSL 3.5 supports it; our ctypes binding would need the callbacks. Short-lived certificates (below) cover much of the same need |
| Short-lived certificates as the revocation answer | step-ca | [step-ca docs](https://SmallStep.com/docs/step-ca/) | Lifetimes are settable (397 days default), `maintain` renews | Small | A documented profile (for example 24 hours with automatic renewal) plus a test, not new code |
| Hybrid group on by default, TLS 1.3 only, ML-DSA certificates accepted | nginx, HAProxy 3.2+/3.3+, Cloudflare | [HAProxy](https://cdn.haproxy.com/blog/how-to-enable-post-quantum-cryptography-and-tls-termination-with-haproxy), [NGINXaaS](https://docs.nginx.com/nginxaas/aws/quickstart/pqc/) | Present | Done | Parity, and our policy is stricter (`strict`, `cnsa2`, `transition`, shadow) |

### VPN

| Feature | Seen at | Source quality | Acxelin today | Size | Notes |
|---|---|---|---|---|---|
| ML-KEM-derived pre-shared key on WireGuard | Mullvad (ephemeral peers, ML-KEM and Classic McEliece/HQC), ExpressVPN, Tailscale plans it | [Mullvad](https://mullvad.net/blog/2025/1/9/quantum-resistant-tunnels-are-now-the-default-on-desktop), [Tailscale](https://tailscale.com/docs/concepts/post-quantum-cryptography) | Present (TLS exporter PSK) | Done | Parity. Tailscale says its own is not post-quantum yet |
| Per-user access rules (which networks each person reaches) | Tailscale ACLs, NetBird and Firezone policies | Known product category; not re-fetched | `users` allow-list and per-site routes; no per-user route sets | Medium | The most requested thing in a bank VPN review |
| Enrolment by QR code for phones | WireGuard apps in general | Common knowledge | None | Small | Needs a mobile client story first; we ship desktop and gateway only |
| Single sign-on at enrolment (OIDC) | Firezone, NetBird, Tailscale | Known; not fetched | Invitation token only | Large | Adds an identity provider dependency; opt-in |
| Multi-hop / obfuscation | Mullvad | Known; not fetched | None | Large | Not a bank need; skip |

### Readiness / CBOM

| Feature | Seen at | Source quality | Acxelin today | Size | Notes |
|---|---|---|---|---|---|
| CBOM generation from source via a code-analysis plugin | IBM/PQCA CBOMkit with the Sonar Cryptography plugin | [PQCA CBOM Kit](https://medium.com/@chmodshubham/pqca-cbom-kit-formerly-ibm-74d21bf46e12), [IBM](https://researcher.ibm.com/blog/cryptographic-cbom-linux-foundation) | Present, multi-language, with a labelled corpus | Done | We also probe live endpoints, which a source plugin does not |
| Ingest others' CBOMs (CycloneDX 1.4 and 1.6) | SandboxAQ AQtive Guard | [AQtive Guard](https://docs.aqtiveguard.com/data-sources/cbom/) | `merge` and baseline exist; cross-tool import is not tested against CBOMkit or Sonar output | Small | Test with real CBOMkit/Sonar samples before claiming it |
| CBOM validated against the CycloneDX 1.6 JSON schema in CI | Expected by consumers such as AQtive Guard | Same | Not checked here | Small | Cheap, and a customer will ask |
| Crypto assets linked to the software components that use them | CycloneDX 1.6 dependency graph | Spec | `relationships.json` exists | Medium | Check what it holds against the schema |
| Pre-commit hook | Common among scanners | Common knowledge | GitHub Action only | Small | |
| Compliance views (CNSA 2.0, NIST IR 8547 dates) | AQtive Guard is described as US-centric compliance | Vendor comparison, marketing-influenced | Deadlines by country and sector exist | Small | Waiting for the CNSA 2.0 PDF you will send |

## PARKED (owner decision, 2026-10-31): not started, no PR. Bank-readiness stages come first

Order agreed: upgrade and rollback, supply chain (now including CBOM schema validation of every emitted shape and CBOMkit and Sonar import
samples), interop matrix, SoftHSM key handling, performance harness, held-out Readiness evaluation. Then, in this order: short-lived
certificate profile with an automatic renewal test; ACME dns-01 via a command hook; per-user VPN route sets; ALPN/SNI routing; OIDC enrolment;
OCSP stapling last, and only if ML-DSA OCSP signing is confirmed working in OpenSSL 3.5.

When this list is revisited, compare against what a bank evaluates: VPN: Palo Alto, Cisco, Fortinet, Zscaler, strongSwan. Readiness:
Keyfactor, CyberArk/Venafi, Entrust, QuSecure. Primary sources only (vendor documentation, RFCs); anything unconfirmed is marked so.
The tables below are the first scan with the wrong competitor set and secondary sources; treat them as a starting point only.

## Earlier proposed order (superseded by the order above)

1. Short-lived-certificate profile with an automatic-renewal test (TLS/CA). Small, and answers the revocation question without OCSP.
2. CBOM checks: schema validation in CI, import tests with CBOMkit and Sonar samples (Readiness). Small, and removes a claim we cannot show.
3. ACME `dns-01` through a command hook (TLS). Medium.
4. Per-user route sets in the VPN gateway (VPN). Medium; the wire format stays, the gateway decides which routes it hands out.
5. ALPN/SNI routing (TLS). Medium.
6. OCSP stapling. Large; only if the first item does not satisfy the reviewer.
7. OIDC enrolment. Large; opt-in, last.

## Limits of this document

- Three of the four searches returned secondary pages. Features marked "common knowledge" or "known" were not re-verified here; each gets
  a primary source (the vendor's documentation or the RFC) before it is built, and the link goes into the PR.
- Envoy, Caddy, Rosenpass, NetBird and strongSwan were not confirmed by the search at all.
- "Competitor" here means products a bank reviewer would compare us with. It is not a market ranking; I did not find popularity data.
