package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBundledAssetsMatchCanonicalFiles guards the sync-assets step:
// the embedded copies must be byte-identical to policies/ and
// examples/evidence/ at the repo root, so the playground can never
// drift from the policies a reader sees in the repo.
func TestBundledAssetsMatchCanonicalFiles(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	check := func(canonical, embedded string) {
		t.Helper()
		a, err := os.ReadFile(filepath.Join(root, canonical))
		if err != nil {
			t.Fatalf("read canonical %s: %v", canonical, err)
		}
		b, err := assets.ReadFile(embedded)
		if err != nil {
			t.Fatalf("read embedded %s: %v", embedded, err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("embedded %s differs from canonical %s (run: make sync-assets)", embedded, canonical)
		}
	}
	for _, name := range []string{"strict.rego", "standard.rego", "dev.rego", "gpu-workload.rego"} {
		check("policies/"+name, "assets/policies/"+name)
	}
	for _, name := range []string{"good-tdx.json", "stale-evidence.json", "old-tcb.json", "sgx-legacy.json", "gpu-job-mismatch.json", "zero-mrtd.json"} {
		check("examples/evidence/"+name, "assets/evidence/"+name)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return s
}

func TestEvaluateEndpoint(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	good, _ := os.ReadFile("../../examples/evidence/good-tdx.json")
	body, _ := json.Marshal(map[string]any{
		"policy":   "strict.rego",
		"evidence": json.RawMessage(good),
	})
	resp, err := http.Post(ts.URL+"/api/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, data)
	}
	var v struct {
		Allowed bool     `json:"allowed"`
		Reasons []string `json:"reasons"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if !v.Allowed {
		t.Fatalf("expected good-tdx to be allowed by strict.rego, got %v", v.Reasons)
	}

	stale, _ := os.ReadFile("../../examples/evidence/stale-evidence.json")
	body, _ = json.Marshal(map[string]any{
		"policy":   "strict.rego",
		"evidence": json.RawMessage(stale),
	})
	resp, err = http.Post(ts.URL+"/api/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v2 struct {
		Allowed bool     `json:"allowed"`
		Reasons []string `json:"reasons"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v2); err != nil {
		t.Fatal(err)
	}
	if v2.Allowed {
		t.Fatal("expected stale evidence to be denied")
	}
	if !strings.Contains(strings.Join(v2.Reasons, " "), "stale") {
		t.Fatalf("expected stale reason, got %v", v2.Reasons)
	}
}

func TestEvaluateEndpointRejectsUnknownPolicy(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	body, _ := json.Marshal(map[string]any{
		"policy":   "nope.rego",
		"evidence": json.RawMessage(`{"platform":"tdx"}`),
	})
	resp, err := http.Post(ts.URL+"/api/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestUIEndpoint(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "Attestation Policy Playground") {
		t.Fatal("UI page does not contain expected title")
	}
}
