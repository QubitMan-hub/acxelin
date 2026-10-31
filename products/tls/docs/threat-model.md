# Threat model

## What Acxelin TLS protects

Traffic between clients and the services behind an edge, against an attacker who records it now and decrypts it later with a quantum computer (harvest now, decrypt later), and against one who forces a weaker negotiation.

## What is tested

| Threat | Defence, and the test that shows it |
|---|---|
| Forced downgrade to classical key exchange or certificates | `strict` refuses classical clients (`test_downgrade`) |
| Replay of a recorded session | the server does nothing on a replay (core `test_replay`) |
| A revoked client | the edge follows the CRL and refuses the client; an expired or damaged CRL refuses everyone, with the reason logged |
| Slow or silent clients holding connections | handshake and idle timeouts, and a connection limit per route |
| Guessing an enrollment token | tokens are one-time with a secret part; failures are audited without the secret (core `test_est_secrets`) |
| Secrets in output | CA and key passphrases and token secrets never appear in command output, logs or files at rest (`test_secrets`) |
| Reporting who `strict` would refuse leaking something about a client | shadow mode keeps the address, the offered groups and signature schemes and nothing else, names come from fixed tables, lists are cut at a fixed length, and a failing report never stops a connection (`test_shadow`) |
| A web page attacking the console | the console accepts only loopback host names and same-origin requests, uses no cookies, and locks out an address after ten wrong attempts (core console tests) |

## What is not covered

- **The CA machine.** Whoever holds the CA key can issue certificates. Keep a root offline and use an issuing CA, or put the key in KMS or an HSM (untested here against real devices).
- **Revocation latency.** A revoked certificate works until the edge next fetches the CRL.
- **The service behind the edge.** It sees plain traffic on the local network. Keep it on loopback or a private network.
- **Browsers.** They cannot verify ML-DSA yet, so a `transition` policy with a classical fallback certificate is the only way to serve them. That protects them only as well as classical TLS does.
- **Validation on other platforms.** Everything here was exercised on Linux with OpenSSL 3.5.9.
- **Shadow mode enforces nothing.** A route in shadow mode serves classical clients exactly as `transition` does.
