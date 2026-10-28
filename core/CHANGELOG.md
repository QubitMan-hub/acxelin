# Changelog

## Unreleased

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
