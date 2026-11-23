// Command policycheck evaluates one attestation evidence file against
// one .rego policy file and prints the verdict.
//
// Exit codes: 0 = allowed, 1 = denied, 2 = usage / parse error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PeaceXXX/attestation-policy-playground/internal/policy"
)

func main() {
	policyPath := flag.String("policy", "", "path to a .rego policy file")
	evidencePath := flag.String("evidence", "", "path to a JSON evidence file")
	trace := flag.Bool("trace", false, "print the per-rule trace")
	flag.Parse()
	if *policyPath == "" || *evidencePath == "" {
		fmt.Fprintln(os.Stderr, "usage: policycheck -policy policies/strict.rego -evidence examples/evidence/good-tdx.json [-trace]")
		os.Exit(2)
	}
	policyData, err := os.ReadFile(*policyPath)
	if err != nil {
		fatalf("read policy: %v", err)
	}
	p, err := policy.Parse(filepath.Base(*policyPath), string(policyData))
	if err != nil {
		fatalf("parse policy: %v", err)
	}
	evData, err := os.ReadFile(*evidencePath)
	if err != nil {
		fatalf("read evidence: %v", err)
	}
	ev, err := policy.ParseEvidence(evData)
	if err != nil {
		fatalf("parse evidence: %v", err)
	}
	v := policy.Evaluate(p, ev)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if *trace {
		_ = enc.Encode(v)
	} else {
		_ = enc.Encode(struct {
			Allowed bool     `json:"allowed"`
			Policy  string   `json:"policy"`
			Reasons []string `json:"reasons"`
		}{v.Allowed, v.Policy, v.Reasons})
	}
	if v.Allowed {
		os.Exit(0)
	}
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "policycheck: "+format+"\n", args...)
	os.Exit(2)
}
