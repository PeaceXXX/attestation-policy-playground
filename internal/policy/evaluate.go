package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Verdict is the result of evaluating a Policy against one evidence bundle.
type Verdict struct {
	Allowed bool        `json:"allowed"`
	Policy  string      `json:"policy"`
	Reasons []string    `json:"reasons"`
	Trace   []RuleTrace `json:"trace"`
}

// RuleTrace records, per rule, whether it fired and why.
type RuleTrace struct {
	RuleID    string           `json:"rule_id"`
	Effect    string           `json:"effect"`
	Fired     bool             `json:"fired"`
	Condition []ConditionTrace `json:"conditions"`
}

// ConditionTrace records one condition's outcome.
type ConditionTrace struct {
	Condition string `json:"condition"`
	Passed    bool   `json:"passed"`
	Detail    string `json:"detail"`
}

// Evaluate runs a parsed policy against evidence decoded from JSON.
// Evidence is a map; policies address it through the "input" prefix,
// e.g. input.tcb.svn reads evidence["tcb"]["svn"].
func Evaluate(p *Policy, evidence map[string]any) Verdict {
	v := Verdict{Policy: p.Name}
	var denyReasons []string
	allowed := false

	for _, r := range p.Rules {
		rt := RuleTrace{RuleID: r.ID, Effect: r.Effect}
		allPass := true
		for _, c := range r.Conditions {
			passed, detail := evalCondition(c, evidence)
			if c.Negate {
				passed = !passed
				detail = "negated: " + detail
			}
			rt.Condition = append(rt.Condition, ConditionTrace{
				Condition: c.Raw, Passed: passed, Detail: detail,
			})
			if !passed {
				allPass = false
			}
		}
		rt.Fired = allPass && len(r.Conditions) > 0
		v.Trace = append(v.Trace, rt)
		if !rt.Fired {
			continue
		}
		switch r.Effect {
		case "allow":
			allowed = true
		case "deny":
			msg := r.Message
			if msg == "" {
				msg = "denied by " + r.ID
			}
			denyReasons = append(denyReasons, msg)
		}
	}

	if len(denyReasons) > 0 {
		// Deny wins over allow: a workload that trips any deny rule is
		// rejected even if an allow rule also matched. This mirrors how
		// real attestation verifiers treat explicit denials.
		v.Allowed = false
		v.Reasons = denyReasons
		return v
	}
	v.Allowed = allowed
	if allowed {
		v.Reasons = []string{"allowed by policy " + p.Name}
	} else {
		v.Reasons = []string{"no allow rule matched (default deny)"}
	}
	return v
}

// ParseEvidence decodes a JSON evidence document.
func ParseEvidence(data []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("evidence is not valid JSON: %w", err)
	}
	if m == nil {
		return nil, fmt.Errorf("evidence must be a JSON object")
	}
	return m, nil
}

// evalCondition evaluates one condition against the evidence.
func evalCondition(c Condition, evidence map[string]any) (bool, string) {
	if c.Func != "" {
		return evalFunc(c, evidence)
	}
	val, ok := lookupPath(evidence, c.Path)
	if !ok {
		return false, fmt.Sprintf("field %s is missing", c.Path)
	}
	// Field-to-field comparison: resolve the right-hand side first.
	rhs := c.Value
	if c.ValuePath != "" {
		v, ok := lookupPath(evidence, c.ValuePath)
		if !ok {
			return false, fmt.Sprintf("field %s is missing", c.ValuePath)
		}
		rhs = v
	}
	switch c.Op {
	case "truthy":
		return isTruthy(val), fmt.Sprintf("%s = %s", c.Path, short(val))
	case "==":
		return looseEqual(val, rhs), fmt.Sprintf("%s = %s, want %s", c.Path, short(val), short(rhs))
	case "!=":
		return !looseEqual(val, rhs), fmt.Sprintf("%s = %s, want != %s", c.Path, short(val), short(rhs))
	case ">=", "<=", ">", "<":
		got, ok1 := toFloat(val)
		want, ok2 := toFloat(rhs)
		if !ok1 || !ok2 {
			return false, fmt.Sprintf("%s = %s is not numeric, cannot compare with %s", c.Path, short(val), short(rhs))
		}
		switch c.Op {
		case ">=":
			return got >= want, fmt.Sprintf("%s = %v, want >= %v", c.Path, got, want)
		case "<=":
			return got <= want, fmt.Sprintf("%s = %v, want <= %v", c.Path, got, want)
		case ">":
			return got > want, fmt.Sprintf("%s = %v, want > %v", c.Path, got, want)
		default:
			return got < want, fmt.Sprintf("%s = %v, want < %v", c.Path, got, want)
		}
	case "in", "not in":
		list, _ := c.Value.([]any)
		found := false
		for _, item := range list {
			if looseEqual(val, item) {
				found = true
				break
			}
		}
		if c.Op == "in" {
			return found, fmt.Sprintf("%s = %s, want one of %s", c.Path, short(val), short(list))
		}
		return !found, fmt.Sprintf("%s = %s, want none of %s", c.Path, short(val), short(list))
	}
	return false, "unsupported operator " + c.Op
}

func evalFunc(c Condition, evidence map[string]any) (bool, string) {
	switch c.Func {
	case "count":
		val, ok := lookupPath(evidence, c.Path)
		if !ok {
			return false, fmt.Sprintf("field %s is missing", c.Path)
		}
		n := -1
		switch t := val.(type) {
		case []any:
			n = len(t)
		case string:
			n = len(t)
		case map[string]any:
			n = len(t)
		default:
			return false, fmt.Sprintf("count(%s): not a list, string or object", c.Path)
		}
		want, _ := toFloat(c.Value)
		f := float64(n)
		switch c.Op {
		case ">=":
			return f >= want, fmt.Sprintf("count(%s) = %d, want >= %v", c.Path, n, want)
		case "<=":
			return f <= want, fmt.Sprintf("count(%s) = %d, want <= %v", c.Path, n, want)
		case ">":
			return f > want, fmt.Sprintf("count(%s) = %d, want > %v", c.Path, n, want)
		case "<":
			return f < want, fmt.Sprintf("count(%s) = %d, want < %v", c.Path, n, want)
		case "==":
			return f == want, fmt.Sprintf("count(%s) = %d, want == %v", c.Path, n, want)
		case "!=":
			return f != want, fmt.Sprintf("count(%s) = %d, want != %v", c.Path, n, want)
		}
		return false, "bad count operator " + c.Op
	case "startswith", "endswith", "contains":
		val, ok := lookupPath(evidence, c.Path)
		if !ok {
			return false, fmt.Sprintf("field %s is missing", c.Path)
		}
		s, isStr := val.(string)
		if !isStr {
			return false, fmt.Sprintf("%s = %s is not a string", c.Path, short(val))
		}
		needle, _ := c.FuncArg.(string)
		switch c.Func {
		case "startswith":
			return strings.HasPrefix(s, needle), fmt.Sprintf("%s = %q, want prefix %q", c.Path, s, needle)
		case "endswith":
			return strings.HasSuffix(s, needle), fmt.Sprintf("%s = %q, want suffix %q", c.Path, s, needle)
		default:
			return strings.Contains(s, needle), fmt.Sprintf("%s = %q, want it to contain %q", c.Path, s, needle)
		}
	}
	return false, "unsupported function " + c.Func
}

// lookupPath resolves "input.a.b[0].c" against the evidence map.
// The leading "input." prefix is stripped; a bare path is resolved as-is.
func lookupPath(evidence map[string]any, path string) (any, bool) {
	p := strings.TrimPrefix(path, "input.")
	cur := any(evidence)
	for _, seg := range strings.Split(p, ".") {
		if seg == "" {
			return nil, false
		}
		// Segment may carry an index: measurements[0]
		name, idx, hasIdx := seg, -1, false
		if open := strings.Index(seg, "["); open >= 0 {
			if !strings.HasSuffix(seg, "]") {
				return nil, false
			}
			name = seg[:open]
			n, err := strconv.Atoi(seg[open+1 : len(seg)-1])
			if err != nil {
				return nil, false
			}
			idx, hasIdx = n, true
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[name]
		if !ok {
			return nil, false
		}
		cur = v
		if hasIdx {
			arr, ok := cur.([]any)
			if !ok || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
		}
	}
	return cur, true
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func looseEqual(a, b any) bool {
	if af, ok1 := toFloat(a); ok1 {
		if bf, ok2 := toFloat(b); ok2 {
			return af == bf
		}
	}
	return reflect.DeepEqual(a, b)
}

func isTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

func short(v any) string {
	s := fmt.Sprintf("%v", v)
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
