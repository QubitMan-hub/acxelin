# OCSP stapling: the check that came first

The decision was: build it only if OpenSSL 3.5 can sign and verify an OCSP response with an ML-DSA key. It can.

**Experiment (OpenSSL 3.5.9, rerunnable):** an ML-DSA-65 CA certificate and key, a leaf signed by it, an index file with the leaf valid, then
`openssl ocsp -index … -rsigner ca.pem -rkey ca.key -CA ca.pem -reqin req.der -respout resp.der` and
`openssl ocsp -respin resp.der -CAfile ca.pem -issuer ca.pem -cert leaf.pem -no_nonce` gave `Response verify OK`, `Signature Algorithm: ML-DSA-65`, `Cert Status: good`.
The product does not use the `openssl` command at run time; this was only the feasibility check. Python's `cryptography` 50.0.1 builds and
parses the same answers, and the tests send one through a real handshake.

**What was built:** `acxelin_core.pki.ocsp` (sign, check, follow a file), `Context.set_staple` / `Connection.staple` in core's OpenSSL binding,
`ca ocsp`, and `ocsp_staple` on an edge route. Tests: `core/tests/test_ocsp.py`, `products/tls/tests/test_ocsp_edge.py`.

**Limits:**
- The answer is signed with a CA key held in a file. KMS and signing-command CAs are refused with a message saying so.
- There is no responder service (no OCSP over HTTP): the operator refreshes a file.
- A stapled answer is only as fresh as its `next_update`; the edge never sends an expired one, and a client that requires a staple fails closed if the file is not renewed in time.
- Only the interoperability of OpenSSL 3.5 and this product's client was tested. Browsers, Go, Java and others have not been tried with ML-DSA staples.
- It covers the edge's own certificate. Client certificates are still checked against the CRL.
