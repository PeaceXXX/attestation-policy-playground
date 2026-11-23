package policy

import (
	"strings"
	"testing"
)

const samplePolicy = `# Standard policy: production TDX workloads
package attestation

default allow = false

allow if {
    input.platform == "tdx"
    input.tcb.svn >= 5
    input.evidence.age_seconds < 300
}

deny["TCB SVN is below the minimum (5)"] if {
    input.tcb.svn < 5
}

deny[msg] if {
    input.measurements.mrtd == "0000000000000000000000000000000000000000000000000000000000000000"
    msg := "MRTD is all zeros; measurement was never populated"
}
`

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse("test.rego", src)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return p
}

func evidence(t *testing.T, jsonDoc string) map[string]any {
	t.Helper()
	m, err := ParseEvidence([]byte(jsonDoc))
	if err != nil {
		t.Fatalf("ParseEvidence failed: %v", err)
	}
	return m
}

func TestParseRules(t *testing.T) {
	p := mustParse(t, samplePolicy)
	if len(p.Rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(p.Rules))
	}
	if p.Rules[0].Effect != "allow" || len(p.Rules[0].Conditions) != 3 {
		t.Fatalf("allow rule wrong: %+v", p.Rules[0])
	}
	if p.Rules[1].Message != "TCB SVN is below the minimum (5)" {
		t.Fatalf("deny message wrong: %q", p.Rules[1].Message)
	}
	if !p.Rules[2].MsgVar || p.Rules[2].Message != "MRTD is all zeros; measurement was never populated" {
		t.Fatalf("deny[msg] rule wrong: %+v", p.Rules[2])
	}
}

func TestParseRejectsUnknownSyntax(t *testing.T) {
	bad := []string{
		"package x\n\nallow if {\n    input.a ~= 1\n}\n",
		"package x\n\nallow if {\n    foo(input.a)\n}\n",
		"package x\n\nallow if {\n    input.a == 1\n",           // unclosed body
		"package x\n\npermit if {\n    input.a == 1\n}\n", // bad header
		"package x\n\nallow if {\n    input.a = 1\n}\n", // single = must be ==
	}
	for _, src := range bad {
		if _, err := Parse("bad.rego", src); err == nil {
			t.Errorf("expected Parse to fail for:\n%s", src)
		}
	}
}

func TestEvaluateAllow(t *testing.T) {
	p := mustParse(t, samplePolicy)
	v := Evaluate(p, evidence(t, `{
		"platform": "tdx",
		"tcb": {"svn": 7},
		"evidence": {"age_seconds": 42},
		"measurements": {"mrtd": "aabbcc"}
	}`))
	if !v.Allowed {
		t.Fatalf("expected allow, got deny: %v", v.Reasons)
	}
}

func TestEvaluateDenyWinsOverAllow(t *testing.T) {
	p := mustParse(t, samplePolicy)
	v := Evaluate(p, evidence(t, `{
		"platform": "tdx",
		"tcb": {"svn": 3},
		"evidence": {"age_seconds": 42},
		"measurements": {"mrtd": "aabbcc"}
	}`))
	if v.Allowed {
		t.Fatal("expected deny (old TCB), got allow")
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "TCB SVN") {
		t.Fatalf("expected TCB reason, got %v", v.Reasons)
	}
}

func TestEvaluateDefaultDeny(t *testing.T) {
	p := mustParse(t, samplePolicy)
	v := Evaluate(p, evidence(t, `{
		"platform": "sgx",
		"tcb": {"svn": 9},
		"evidence": {"age_seconds": 10},
		"measurements": {"mrtd": "aabbcc"}
	}`))
	if v.Allowed {
		t.Fatal("expected default deny for non-TDX platform, got allow")
	}
}

func TestEvaluateStaleEvidence(t *testing.T) {
	p := mustParse(t, samplePolicy)
	v := Evaluate(p, evidence(t, `{
		"platform": "tdx",
		"tcb": {"svn": 7},
		"evidence": {"age_seconds": 3600},
		"measurements": {"mrtd": "aabbcc"}
	}`))
	if v.Allowed {
		t.Fatal("expected deny for stale evidence, got allow")
	}
}

func TestEvaluateZeroMRTDDenyMessage(t *testing.T) {
	p := mustParse(t, samplePolicy)
	v := Evaluate(p, evidence(t, `{
		"platform": "tdx",
		"tcb": {"svn": 7},
		"evidence": {"age_seconds": 42},
		"measurements": {"mrtd": "0000000000000000000000000000000000000000000000000000000000000000"}
	}`))
	if v.Allowed {
		t.Fatal("expected deny for zero MRTD, got allow")
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "never populated") {
		t.Fatalf("expected zero-MRTD reason, got %v", v.Reasons)
	}
}

func TestOperatorsAndFunctions(t *testing.T) {
	src := `package attestation

allow if {
    input.platform in ["tdx", "sev-snp"]
    input.vendor not in ["untrusted-vendor"]
    count(input.measurements.allowed) >= 2
    startswith(input.workload.image, "ghcr.io/peacexxx/")
    input.debug == false
}
`
	p := mustParse(t, src)
	good := evidence(t, `{
		"platform": "sev-snp",
		"vendor": "acme",
		"measurements": {"allowed": ["a", "b", "c"]},
		"workload": {"image": "ghcr.io/peacexxx/worker:1.2.3"},
		"debug": false
	}`)
	if v := Evaluate(p, good); !v.Allowed {
		t.Fatalf("expected allow, got %v", v.Reasons)
	}
	badVendor := evidence(t, `{
		"platform": "tdx",
		"vendor": "untrusted-vendor",
		"measurements": {"allowed": ["a", "b"]},
		"workload": {"image": "ghcr.io/peacexxx/worker:1.2.3"},
		"debug": false
	}`)
	if v := Evaluate(p, badVendor); v.Allowed {
		t.Fatal("expected deny for banned vendor, got allow")
	}
}

func TestFieldToFieldComparison(t *testing.T) {
	src := `package attestation

allow if {
    input.platform == "tdx"
    input.gpu.job_id == input.workload.job_id
}
`
	p := mustParse(t, src)
	bound := evidence(t, `{
		"platform": "tdx",
		"gpu": {"job_id": "job-1"},
		"workload": {"job_id": "job-1"}
	}`)
	if v := Evaluate(p, bound); !v.Allowed {
		t.Fatalf("expected allow when GPU claim is bound to the same job, got %v", v.Reasons)
	}
	mismatched := evidence(t, `{
		"platform": "tdx",
		"gpu": {"job_id": "job-2"},
		"workload": {"job_id": "job-1"}
	}`)
	if v := Evaluate(p, mismatched); v.Allowed {
		t.Fatal("expected deny when GPU claim is bound to a different job, got allow")
	}
}

func TestNegationAndMissingField(t *testing.T) {
	src := `package attestation

allow if {
    not input.debug == true
    input.tcb.svn >= 1
}
`
	p := mustParse(t, src)
	v := Evaluate(p, evidence(t, `{"tcb": {"svn": 2}}`))
	if !v.Allowed {
		t.Fatalf("expected allow (debug missing, negated true check), got %v", v.Reasons)
	}
}

func TestLookupPathIndex(t *testing.T) {
	m := evidence(t, `{"measurements": {"list": [{"value": "a"}, {"value": "b"}]}}`)
	v, ok := lookupPath(m, "input.measurements.list[1].value")
	if !ok || v != "b" {
		t.Fatalf("index lookup failed: %v %v", v, ok)
	}
	if _, ok := lookupPath(m, "input.measurements.list[5].value"); ok {
		t.Fatal("out-of-range index should fail lookup")
	}
}

func TestParseEvidenceRejectsNonObject(t *testing.T) {
	if _, err := ParseEvidence([]byte(`[1,2]`)); err == nil {
		t.Fatal("expected error for non-object evidence")
	}
	if _, err := ParseEvidence([]byte(`{bad json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
