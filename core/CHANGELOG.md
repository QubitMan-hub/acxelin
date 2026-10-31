# Changelog

## Unreleased

- Security: a certificate is cleared only by a CRL from the CA that issued it. Before, a root's CRL also cleared a certificate
  an intermediate CA had revoked. `Revocation.check` and `check_revocation` take the certificate's issuer for this.
- A CRL file may hold several CRLs (an intermediate's and the root's), so the root's list revokes an intermediate and every
  certificate under it.
- TLS sessions resumed without a verified chain are checked against the issuing CAs seen in earlier full handshakes, so
  clients of an intermediate CA are no longer refused on resumption.
- When a CRL comes from a CA that is not in the CA file, the error names it and says to give the chain.
- Day and hour counts on the command line are limited to 36,500, so `inf` or a huge number is refused instead of crashing.

## 1.1.0

- Consoles read a request's body only after its session is checked (sign-in excepted), so an unauthenticated request never
  has a body parsed or awaited. A route can take a larger body than the default (`App(..., limits=...)`).
- Consoles: requests without a credential no longer count towards the lockout, and a signed-in session keeps working while
  wrong tokens from the same address are locked out. Before, a page on another local port could lock the real user out with
  ten image loads. Fetches marked `Sec-Fetch-Site: same-site` (another local port) are refused like cross-site ones.
- `console link` never sends the automation token through an HTTP proxy.
- A deeply nested JSON body answers 400, and an unexpected error in a route answers 500 with a generic message (the log gets
  the error type only). Before, the connection dropped with a traceback.
- Windows: a secret file is made owner-only before its first byte is written. Before, it briefly had the folder's
  inherited ACL.

## 1.0.0

First release of the shared mechanisms behind the Acxelin products.
