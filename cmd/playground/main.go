// Command playground serves the attestation policy playground web UI
// and JSON API on :8080.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/PeaceXXX/attestation-policy-playground/internal/server"
)

func main() {
	addr := os.Getenv("PLAYGROUND_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	s, err := server.New()
	if err != nil {
		log.Fatalf("load bundled policies: %v", err)
	}
	fmt.Printf("attestation-policy-playground listening on %s\n", addr)
	fmt.Printf("bundled policies: %v\n", s.PolicyNames())
	fmt.Printf("bundled evidence: %v\n", s.ExampleNames())
	log.Fatal(http.ListenAndServe(addr, s.Handler()))
}
