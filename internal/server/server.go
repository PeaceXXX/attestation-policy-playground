// Package server is the HTTP front end of the playground: it serves the
// bundled policies and example evidence, evaluates evidence against a
// chosen policy, and serves a small dependency-free web UI.
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strings"

	"github.com/PeaceXXX/attestation-policy-playground/internal/policy"
)

//go:embed all:assets
var assets embed.FS

// Server holds the parsed policies and example evidence bundles.
type Server struct {
	policies map[string]*policy.Policy
	examples map[string][]byte
	mux      *http.ServeMux
}

// New loads every bundled policy and evidence file from the embedded assets.
func New() (*Server, error) {
	s := &Server{
		policies: map[string]*policy.Policy{},
		examples: map[string][]byte{},
		mux:      http.NewServeMux(),
	}
	policyFiles, err := fs.ReadDir(assets, "assets/policies")
	if err != nil {
		return nil, fmt.Errorf("read bundled policies: %w", err)
	}
	for _, f := range policyFiles {
		if !strings.HasSuffix(f.Name(), ".rego") {
			continue
		}
		data, err := assets.ReadFile("assets/policies/" + f.Name())
		if err != nil {
			return nil, err
		}
		p, err := policy.Parse(f.Name(), string(data))
		if err != nil {
			return nil, fmt.Errorf("parse bundled policy %s: %w", f.Name(), err)
		}
		s.policies[f.Name()] = p
	}
	evFiles, err := fs.ReadDir(assets, "assets/evidence")
	if err != nil {
		return nil, fmt.Errorf("read bundled evidence: %w", err)
	}
	for _, f := range evFiles {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		data, err := assets.ReadFile("assets/evidence/" + f.Name())
		if err != nil {
			return nil, err
		}
		s.examples[f.Name()] = data
	}
	s.mux.HandleFunc("/", s.handleUI)
	s.mux.HandleFunc("/api/policies", s.handlePolicies)
	s.mux.HandleFunc("/api/evidence", s.handleEvidence)
	s.mux.HandleFunc("/api/evaluate", s.handleEvaluate)
	return s, nil
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// PolicyNames returns the bundled policy file names, sorted.
func (s *Server) PolicyNames() []string {
	names := make([]string, 0, len(s.policies))
	for n := range s.policies {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ExampleNames returns the bundled evidence file names, sorted.
func (s *Server) ExampleNames() []string {
	names := make([]string, 0, len(s.examples))
	for n := range s.examples {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/ui.html")
	if err != nil {
		http.Error(w, "ui missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

type policyInfo struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	Rules int    `json:"rules"`
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// ?name=strict.rego returns the raw policy source.
	if name := r.URL.Query().Get("name"); name != "" {
		p, ok := s.policies[name]
		if !ok {
			http.Error(w, "unknown policy", http.StatusNotFound)
			return
		}
		_ = p
		data, err := assets.ReadFile("assets/policies/" + name)
		if err != nil {
			http.Error(w, "policy missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
		return
	}
	out := []policyInfo{}
	for _, name := range s.PolicyNames() {
		p := s.policies[name]
		out = append(out, policyInfo{Name: name, Title: p.Title, Rules: len(p.Rules)})
	}
	writeJSON(w, out)
}

type exampleInfo struct {
	Name string          `json:"name"`
	Data json.RawMessage `json:"data"`
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := []exampleInfo{}
	for _, name := range s.ExampleNames() {
		out = append(out, exampleInfo{Name: name, Data: s.examples[name]})
	}
	writeJSON(w, out)
}

type evaluateRequest struct {
	Policy   string          `json:"policy"`
	Evidence json.RawMessage `json:"evidence"`
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req evaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "request body must be JSON: "+err.Error())
		return
	}
	p, ok := s.policies[req.Policy]
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown policy: "+req.Policy)
		return
	}
	ev, err := policy.ParseEvidence(req.Evidence)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, policy.Evaluate(p, ev))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
