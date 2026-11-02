# Interop

| Script | What it checks | Run by |
|---|---|---|
| `run.sh` | Real clients against the edge: Node and curl on OpenSSL 3.5, Go, and what each must be refused | the TLS workflow's interop job |
| `matrix.py` | Every policy against independent clients and servers; writes `review/interop-matrix.md` | the TLS workflow, with `ACXELIN_INTEROP=1` |
| `bench.py` | Handshakes and requests per second on this machine | the TLS workflow ("How fast the edge is") |
| `internet.sh` | Acxelin TLS's client against public servers that offer post-quantum key exchange today | by hand: it needs the internet |
| `client.go`, `client.js`, `server.go` | The Go and Node peers the scripts use | `run.sh`, `matrix.py` |
