// A Go TLS 1.3 server that prints what crypto/tls exports (RFC 8446 section 7.5) for one connection: an independent implementation to compare
// the VPN's key derivation against. usage: export_server ADDR CERT KEY LABEL CONTEXT LENGTH   (prints one hex line, then "ok" to the client)
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

func main() {
	cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	n, _ := strconv.Atoi(os.Args[6])
	l, err := tls.Listen("tcp", os.Args[1], &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("listening")
	c, err := l.Accept()
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	tc := c.(*tls.Conn)
	if _, err := bufio.NewReader(tc).ReadString('\n'); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	state := tc.ConnectionState()
	out, err := state.ExportKeyingMaterial(os.Args[4], []byte(os.Args[5]), n)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(out))
	fmt.Fprintln(tc, "ok")
	tc.Close()
}
