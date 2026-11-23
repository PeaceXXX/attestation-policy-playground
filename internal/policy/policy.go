// Package policy implements a small, self-contained evaluator for a
// Rego-inspired policy language for attestation evidence.
//
// The language is deliberately a SUBSET of Rego, not a Rego engine:
// policies are written in real .rego files using the constructs this
// package understands (allow / deny rules, comparisons, membership,
// count(), startswith()/endswith()/contains()), and the parser rejects
// anything outside that subset with a clear error instead of silently
// mis-evaluating it. That fail-closed behaviour is itself the point of
// the demo: a policy that cannot be understood must never silently
// admit a workload.
package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// Policy is a parsed .rego policy file.
type Policy struct {
	Name  string // file base name, e.g. "strict.rego"
	Title string // from the leading comment block, if any
	Rules []Rule
}

// Rule is one allow or deny rule.
type Rule struct {
	ID         string // e.g. "allow-1", "deny-2" (stable, in file order)
	Effect     string // "allow" or "deny"
	Message    string // fixed deny message, from deny["..."] header; "" if none
	MsgVar     bool   // deny[msg] form: message comes from a msg := "..." line
	Conditions []Condition
}

// Condition is one predicate inside a rule body.
type Condition struct {
	Raw    string // original source line, for traces
	Negate bool
	// Exactly one of the following shapes is set:
	Path  string // dotted path, e.g. "input.tcb.svn" (empty for Func-only forms)
	Op    string // "==", "!=", ">=", "<=", ">", "<", "in", "not in", "truthy"
	Value any    // scalar or []any for "in" / "not in"
	// ValuePath, when non-empty, means the right-hand side is another
	// field path (field-to-field comparison, e.g. binding a GPU claim
	// to the workload's job id) instead of a literal Value.
	ValuePath string
	Func      string // "count", "startswith", "endswith", "contains"; "" if plain
	FuncArg   any    // second argument for startswith/endswith/contains
}

// Parse parses a .rego policy file in the supported subset.
func Parse(name, src string) (*Policy, error) {
	p := &Policy{Name: name}
	lines := strings.Split(src, "\n")
	allowN, denyN := 0, 0
	var cur *Rule
	inBody := false

	for i, raw := range lines {
		ln := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			if cur == nil && inBody == false && strings.HasPrefix(line, "#") && p.Title == "" {
				// Keep the first comment line as a human title when it
				// looks like one ("# Strict policy ...").
				t := strings.TrimSpace(strings.TrimPrefix(line, "#"))
				if t != "" {
					p.Title = t
				}
			}
			continue
		}
		if strings.HasPrefix(line, "package ") {
			continue
		}
		if strings.HasPrefix(line, "default ") {
			continue // e.g. "default allow = false" — our semantics already default-deny
		}
		if strings.HasSuffix(line, "{") && !inBody {
			hdr := strings.TrimSpace(strings.TrimSuffix(line, "{"))
			r, err := parseRuleHeader(hdr, ln)
			if err != nil {
				return nil, err
			}
			if r.Effect == "allow" {
				allowN++
				r.ID = fmt.Sprintf("allow-%d", allowN)
			} else {
				denyN++
				r.ID = fmt.Sprintf("deny-%d", denyN)
			}
			p.Rules = append(p.Rules, *r)
			cur = &p.Rules[len(p.Rules)-1]
			inBody = true
			continue
		}
		if line == "}" && inBody {
			cur = nil
			inBody = false
			continue
		}
		if !inBody || cur == nil {
			return nil, fmt.Errorf("line %d: unexpected content outside a rule body: %q", ln, line)
		}
		// Inside a rule body.
		if strings.HasPrefix(line, "msg :=") {
			if cur.Effect != "deny" || !cur.MsgVar {
				return nil, fmt.Errorf("line %d: msg := is only allowed in deny[msg] rules", ln)
			}
			v, err := parseValue(strings.TrimSpace(strings.TrimPrefix(line, "msg :=")), ln)
			if err != nil {
				return nil, err
			}
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("line %d: msg must be a string literal", ln)
			}
			cur.Message = s
			continue
		}
		c, err := parseCondition(strings.TrimSuffix(line, ";"), ln)
		if err != nil {
			return nil, err
		}
		cur.Conditions = append(cur.Conditions, *c)
	}
	if inBody {
		return nil, fmt.Errorf("unclosed rule body at end of file")
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("policy has no rules")
	}
	return p, nil
}

func parseRuleHeader(hdr string, ln int) (*Rule, error) {
	// Forms: "allow if", "deny if", `deny["reason"] if`, "deny[msg] if"
	hdr = strings.TrimSpace(hdr)
	if !strings.HasSuffix(hdr, " if") {
		return nil, fmt.Errorf("line %d: rule header must end with 'if': %q", ln, hdr)
	}
	head := strings.TrimSpace(strings.TrimSuffix(hdr, " if"))
	switch {
	case head == "allow":
		return &Rule{Effect: "allow"}, nil
	case head == "deny":
		return &Rule{Effect: "deny"}, nil
	case strings.HasPrefix(head, `deny["`) && strings.HasSuffix(head, `"]`):
		msg := head[len(`deny["`) : len(head)-len(`"]`)]
		if msg == "" {
			return nil, fmt.Errorf("line %d: deny message must not be empty", ln)
		}
		return &Rule{Effect: "deny", Message: msg}, nil
	case head == "deny[msg]":
		return &Rule{Effect: "deny", MsgVar: true}, nil
	default:
		return nil, fmt.Errorf("line %d: unsupported rule header %q (want 'allow if', 'deny if', 'deny[\"msg\"] if' or 'deny[msg] if')", ln, hdr)
	}
}

// parseCondition parses one body line into a Condition.
func parseCondition(line string, ln int) (*Condition, error) {
	orig := strings.TrimSpace(line)
	line = orig
	c := &Condition{Raw: orig}
	if strings.HasPrefix(line, "not ") {
		c.Negate = true
		line = strings.TrimSpace(strings.TrimPrefix(line, "not "))
	}
	toks, err := tokenize(line, ln)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("line %d: empty condition", ln)
	}
	// Function call: startswith(path, "x") / count(path) >= 3
	if len(toks) >= 2 && toks[1].typ == tokLParen && toks[0].typ == tokIdent {
		fn := toks[0].val
		switch fn {
		case "startswith", "endswith", "contains":
			if len(toks) != 6 || toks[2].typ != tokIdent || toks[3].typ != tokComma ||
				toks[4].typ != tokString || toks[5].typ != tokRParen {
				return nil, fmt.Errorf("line %d: %s(path, \"...\") expected", ln, fn)
			}
			c.Func = fn
			c.Path = toks[2].val
			c.FuncArg = toks[4].val
			c.Op = "truthy"
			return c, nil
		case "count":
			if len(toks) < 6 || toks[2].typ != tokIdent || toks[3].typ != tokRParen {
				return nil, fmt.Errorf("line %d: count(path) <op> <n> expected", ln)
			}
			c.Func = "count"
			c.Path = toks[2].val
			rest := toks[4:]
			if len(rest) != 2 || rest[0].typ != tokOp || rest[1].typ != tokNumber {
				return nil, fmt.Errorf("line %d: count(path) needs a numeric comparison", ln)
			}
			c.Op = rest[0].val
			n, _ := strconv.ParseFloat(rest[1].val, 64)
			c.Value = n
			return c, nil
		default:
			return nil, fmt.Errorf("line %d: unsupported function %q (want startswith, endswith, contains, count)", ln, fn)
		}
	}
	// Bare path = truthiness check.
	if len(toks) == 1 && toks[0].typ == tokIdent {
		c.Path = toks[0].val
		c.Op = "truthy"
		return c, nil
	}
	// path <op> value | path in [...] | path not in [...]
	if toks[0].typ != tokIdent {
		return nil, fmt.Errorf("line %d: condition must start with a field path: %q", ln, orig)
	}
	c.Path = toks[0].val
	rest := toks[1:]
	if len(rest) == 2 && rest[0].typ == tokIdent && rest[0].val == "in" && rest[1].typ == tokList {
		v, err := parseListLiteral(rest[1].val, ln)
		if err != nil {
			return nil, err
		}
		c.Op = "in"
		c.Value = v
		return c, nil
	}
	if len(rest) == 3 && rest[0].typ == tokIdent && rest[0].val == "not" &&
		rest[1].typ == tokIdent && rest[1].val == "in" && rest[2].typ == tokList {
		v, err := parseListLiteral(rest[2].val, ln)
		if err != nil {
			return nil, err
		}
		c.Op = "not in"
		c.Value = v
		return c, nil
	}
	if len(rest) == 2 && rest[0].typ == tokOp {
		if rest[1].typ == tokIdent {
			// Field-to-field comparison: input.a == input.b
			c.Op = rest[0].val
			c.ValuePath = rest[1].val
			return c, nil
		}
		v, err := tokenValue(rest[1], ln)
		if err != nil {
			return nil, err
		}
		c.Op = rest[0].val
		c.Value = v
		return c, nil
	}
	return nil, fmt.Errorf("line %d: unsupported condition %q", ln, orig)
}

// ---- tiny tokenizer -------------------------------------------------

type tokKind int

const (
	tokIdent tokKind = iota
	tokString
	tokNumber
	tokBool
	tokOp
	tokComma
	tokLParen
	tokRParen
	tokList
)

type token struct {
	typ tokKind
	val string
}

func tokenize(s string, ln int) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		ch := s[i]
		switch {
		case ch == ' ' || ch == '\t':
			i++
		case ch == '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
					switch s[j] {
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					case '"':
						b.WriteByte('"')
					case '\\':
						b.WriteByte('\\')
					default:
						b.WriteByte(s[j])
					}
					j++
					continue
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("line %d: unterminated string", ln)
			}
			out = append(out, token{tokString, b.String()})
			i = j + 1
		case ch == '[':
			// Consume a whole [...] list literal (strings/numbers/bools, no nesting).
			depth := 0
			j := i
			for j < len(s) {
				if s[j] == '[' {
					depth++
				}
				if s[j] == ']' {
					depth--
					if depth == 0 {
						break
					}
				}
				j++
			}
			if j >= len(s) || depth != 0 {
				return nil, fmt.Errorf("line %d: unterminated list", ln)
			}
			out = append(out, token{tokList, s[i : j+1]})
			i = j + 1
		case ch == '(':
			out = append(out, token{tokLParen, "("})
			i++
		case ch == ')':
			out = append(out, token{tokRParen, ")"})
			i++
		case ch == ',':
			out = append(out, token{tokComma, ","})
			i++
		case ch == '=' || ch == '!' || ch == '>' || ch == '<':
			if i+1 < len(s) && s[i+1] == '=' {
				out = append(out, token{tokOp, s[i : i+2]})
				i += 2
			} else if ch == '>' || ch == '<' {
				out = append(out, token{tokOp, string(ch)})
				i++
			} else {
				return nil, fmt.Errorf("line %d: unexpected %q (did you mean == ?)", ln, string(ch))
			}
		case isDigit(ch) || (ch == '-' && i+1 < len(s) && isDigit(s[i+1])):
			j := i
			for j < len(s) && (isDigit(s[j]) || s[j] == '.' || s[j] == '-') {
				j++
			}
			out = append(out, token{tokNumber, s[i:j]})
			i = j
		case isIdentStart(ch):
			j := i
			for j < len(s) && (isIdentChar(s[j])) {
				j++
			}
			w := s[i:j]
			if w == "true" || w == "false" {
				out = append(out, token{tokBool, w})
			} else {
				out = append(out, token{tokIdent, w})
			}
			i = j
		default:
			return nil, fmt.Errorf("line %d: unexpected character %q", ln, string(ch))
		}
	}
	return out, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || isDigit(c) || c == '.' || c == '[' || c == ']'
}

func tokenValue(t token, ln int) (any, error) {
	switch t.typ {
	case tokString:
		return t.val, nil
	case tokNumber:
		n, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad number %q", ln, t.val)
		}
		return n, nil
	case tokBool:
		return t.val == "true", nil
	default:
		return nil, fmt.Errorf("line %d: expected a literal value, got %q", ln, t.val)
	}
}

func parseValue(s string, ln int) (any, error) {
	toks, err := tokenize(s, ln)
	if err != nil {
		return nil, err
	}
	if len(toks) != 1 {
		return nil, fmt.Errorf("line %d: expected a single value, got %q", ln, s)
	}
	return tokenValue(toks[0], ln)
}

func parseListLiteral(s string, ln int) ([]any, error) {
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return []any{}, nil
	}
	// Split on commas outside strings.
	var parts []string
	var b strings.Builder
	inStr := false
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '"' && (i == 0 || inner[i-1] != '\\') {
			inStr = !inStr
		}
		if c == ',' && !inStr {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	parts = append(parts, b.String())
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		v, err := parseValue(strings.TrimSpace(p), ln)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
