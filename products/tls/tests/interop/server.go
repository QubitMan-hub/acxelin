// A Go HTTPS server with a classical certificate (Go 1.24+ offers X25519MLKEM768 by default but has no ML-DSA certificates).
// usage: server ADDR CERT KEY
package main

import (
	"fmt"
	"net/http"
	"os"
	"crypto/tls"
)

func main() {
	cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	srv := &http.Server{Addr: os.Args[1], TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello\n") })}
	fmt.Println("error:", srv.ListenAndServeTLS("", ""))
	os.Exit(1)
}
