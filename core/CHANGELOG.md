# Changelog

## Unreleased

- OIDC enrolment (`acxelin_core.pki.oidc`): EST accepts `Authorization: Bearer <ID token>` as the credential for a client certificate in the person's own name. The token (RS256 or ES256 only) is checked against the provider's keys, issuer, audience, expiry, verified email, allowed domains and groups; the name in the request must be the name the token vouches for; a token works once (a hash is kept until it would have expired). Without `oidc.json` a bearer token is refused. Tested with a stand-in provider; no real provider has been used.
- `Router`, `client_names` and `Server(bind=False)` / `Server.adopt`: several servers behind one listening address, chosen per connection by the server name and application protocol in the ClientHello (read without consuming it). Used by Acxelin TLS for routes that share a port. `Server.adopt` is the part of the accept loop that applies the connection limits and starts the handshake.

## 1.1.1

- Consoles open from the owner-only launch page (`console.launch_page`): opening the page itself (GET /, a top-level
  navigation) is accepted from another site, since the browser calls a file:// redirect cross-site. Every API call still
  has to be same-origin with a session token, and the page is still refused inside another site's frame.
- Security: revoking a certificate also revokes every certificate renewed from it over EST, and the one it was renewed from.
  Before, a thief with a client's key could renew it, and revoking the stolen certificate left the renewed copy valid. A
  renewal now records the serial it replaces in `index.json` (the `replaces` field); certificates renewed before 1.1.1 carry
  no link. A renewal keeps the presented certificate's lifetime, and only a certificate this CA issued can renew.
- Security: EST refuses a request whose common name is over 64 characters, or with names over 253 characters or more than 100
  of them, before anything is written to the audit log; strangers could fill the CA's disk through it without a token.
- Security: connections still open when a server stops accepting (an edge route changed by a configuration reload) are
  checked against the CRL until they end; before, a revoked client stayed connected.
- Security: connection caps count a whole /24 (IPv4) or /64 (IPv6) as one client, and apply at all times to other machines,
  not only once half the connections are taken. This machine's own connections are held to them only from half full.
- Security: `serve_http` (CRL publishing, metrics, status) and `GuardedHTTPServer` allow 128 connections, 16 from one
  network, and close each 30 seconds after it opened, so a few machines trickling requests cannot take every thread or file.
- Security: console launch tickets reach the browser through an owner-only page (`console.open_in_browser`), not on its
  command line, where other users of the machine could read them.
- The accept loop survives an unexpected error, and a connection that cannot get a thread gives its slot back; the CRL caches
  shared by connection threads are locked.
- Security: an EST renewal checks the presented certificate and signs its replacement in one step under the CA lock, so a
  revocation can no longer fall between the check and the signature and leave a freshly signed certificate valid.
- `files.protected_location` says whether code is where only administrators can write it, with `files.windows_protected` for the
  Windows rule (Program Files and the Windows folder). Products use it before starting anything with administrator rights.
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
