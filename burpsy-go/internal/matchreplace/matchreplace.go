// Package matchreplace implements ordered rewrite rules for proxied requests
// and responses. Mirrors the Rust burpsy-tools matchreplace module: compiled
// regex rules applied on the proxy hot path, with per-rule scope and the
// Burp-compatible rule_type taxonomy.
package matchreplace

import (
	"bytes"
	"regexp"
	"sync"
)

// Target names match Burp's rule_type config values.
type Target int

const (
	TargetRequestHeader Target = iota
	TargetRequestBody
	TargetRequestFirstLine
	TargetRequestParamName
	TargetRequestParamValue
	TargetResponseHeader
	TargetResponseBody
)

// Category is how string_match is interpreted.
type Category int

const (
	CategoryLiteral Category = iota
	CategoryRegex
)

// Rule is a compiled, runnable rewrite rule.
type Rule struct {
	Enabled       bool
	Target        Target
	Category      Category
	StringMatch   string
	StringReplace string
	Comment       string
	re            *regexp.Regexp
}

// NewRule compiles a rule. For CategoryRegex the pattern is compiled.
func NewRule(target Target, cat Category, match, replace, comment string) (*Rule, error) {
	r := &Rule{
		Enabled:       true,
		Target:        target,
		Category:      cat,
		StringMatch:   match,
		StringReplace: replace,
		Comment:       comment,
	}
	if cat == CategoryRegex {
		re, err := regexp.Compile(match)
		if err != nil {
			return nil, err
		}
		r.re = re
	}
	return r, nil
}

// Direction is which half of the exchange we are rewriting.
type Direction int

const (
	DirRequest Direction = iota
	DirResponse
)

// RuleSet is an ordered set of compiled rules.
type RuleSet struct {
	mu    sync.RWMutex
	rules []*Rule
}

func NewRuleSet() *RuleSet { return &RuleSet{} }

// SetRules replaces the entire rule set (atomic from the caller's perspective).
func (rs *RuleSet) SetRules(rules []*Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = rules
}

// AddRule appends a rule.
func (rs *RuleSet) AddRule(r *Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = append(rs.rules, r)
}

// Rules returns a snapshot of the current rules.
func (rs *RuleSet) Rules() []*Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]*Rule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// Affects returns true if any enabled rule targets this direction.
func (rs *RuleSet) Affects(dir Direction) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	for _, r := range rs.rules {
		if !r.Enabled {
			continue
		}
		if dir == DirRequest && (r.Target == TargetRequestHeader || r.Target == TargetRequestBody || r.Target == TargetRequestFirstLine || r.Target == TargetRequestParamName || r.Target == TargetRequestParamValue) {
			return true
		}
		if dir == DirResponse && (r.Target == TargetResponseHeader || r.Target == TargetResponseBody) {
			return true
		}
	}
	return false
}

// Apply runs all enabled rules that match the direction over raw,
// returning the rewritten bytes. If no rule fires, raw is returned
// unchanged (no copy).
func (rs *RuleSet) Apply(dir Direction, raw []byte) []byte {
	rs.mu.RLock()
	rules := rs.rules
	rs.mu.RUnlock()
	if len(rules) == 0 {
		return raw
	}
	out := raw
	changed := false
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if !targetsDir(r.Target, dir) {
			continue
		}
		applied := applyOne(r, out)
		if applied != nil {
			out = applied
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return out
}

func targetsDir(t Target, dir Direction) bool {
	if dir == DirRequest {
		return t == TargetRequestHeader || t == TargetRequestBody || t == TargetRequestFirstLine || t == TargetRequestParamName || t == TargetRequestParamValue
	}
	return t == TargetResponseHeader || t == TargetResponseBody
}

func applyOne(r *Rule, raw []byte) []byte {
	switch r.Target {
	case TargetRequestBody, TargetResponseBody:
		return applyBody(r, raw)
	case TargetRequestHeader, TargetResponseHeader:
		return applyHeaders(r, raw)
	case TargetRequestFirstLine:
		return applyFirstLine(r, raw)
	default:
		return applyBody(r, raw)
	}
}

func applyBody(r *Rule, raw []byte) []byte {
	if r.Category == CategoryLiteral {
		if !bytes.Contains(raw, []byte(r.StringMatch)) {
			return nil
		}
		return bytes.ReplaceAll(raw, []byte(r.StringMatch), []byte(r.StringReplace))
	}
	if r.re == nil {
		return nil
	}
	if !r.re.Match(raw) {
		return nil
	}
	return r.re.ReplaceAll(raw, []byte(r.StringReplace))
}

func applyHeaders(r *Rule, raw []byte) []byte {
	// Split at the first blank line: headers end, body starts.
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	var headers, body []byte
	if idx >= 0 {
		headers = raw[:idx]
		body = raw[idx:]
	} else {
		headers = raw
	}
	lines := bytes.Split(headers, []byte("\r\n"))
	changed := false
	for i, line := range lines {
		if i == 0 {
			continue // request/status line
		}
		var rewritten []byte
		if r.Category == CategoryLiteral {
			if bytes.Contains(line, []byte(r.StringMatch)) {
				rewritten = bytes.ReplaceAll(line, []byte(r.StringMatch), []byte(r.StringReplace))
			}
		} else if r.re != nil && r.re.Match(line) {
			rewritten = r.re.ReplaceAll(line, []byte(r.StringReplace))
		}
		if rewritten != nil {
			if len(rewritten) == 0 {
				lines[i] = nil // drop line; rebuilt without nils
			} else {
				lines[i] = rewritten
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	var out bytes.Buffer
	for i, line := range lines {
		if line == nil {
			continue
		}
		if i > 0 {
			out.WriteString("\r\n")
		}
		out.Write(line)
	}
	if body != nil {
		out.Write(body)
	}
	return out.Bytes()
}

func applyFirstLine(r *Rule, raw []byte) []byte {
	idx := bytes.Index(raw, []byte("\r\n"))
	if idx < 0 {
		return nil
	}
	firstLine := raw[:idx]
	rest := raw[idx:]
	var rewritten []byte
	if r.Category == CategoryLiteral {
		if !bytes.Contains(firstLine, []byte(r.StringMatch)) {
			return nil
		}
		rewritten = bytes.ReplaceAll(firstLine, []byte(r.StringMatch), []byte(r.StringReplace))
	} else if r.re != nil {
		if !r.re.Match(firstLine) {
			return nil
		}
		rewritten = r.re.ReplaceAll(firstLine, []byte(r.StringReplace))
	}
	if rewritten == nil {
		return nil
	}
	return append(rewritten, rest...)
}
