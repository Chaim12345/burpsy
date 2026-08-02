package scope

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

type RuleKind string

const (
	Include RuleKind = "include"
	Exclude RuleKind = "exclude"
)

type ScopeRule struct {
	ID         uint64   `json:"id"`
	Kind       RuleKind `json:"kind"`
	Host       *string  `json:"host"`
	Port       *uint16  `json:"port"`
	PathPrefix *string  `json:"path_prefix"`
	TLS        *bool    `json:"tls"`
}

func NewIncludeRule(host string) ScopeRule {
	h := host
	return ScopeRule{
		Kind: Include,
		Host: &h,
	}
}

func NewExcludeRule(host string) ScopeRule {
	h := host
	return ScopeRule{
		Kind: Exclude,
		Host: &h,
	}
}

func (r ScopeRule) MatchesHost(host string, port uint16, tls bool) bool {
	if r.TLS != nil && *r.TLS != tls {
		return false
	}
	if r.Port != nil && *r.Port != port {
		return false
	}
	if r.Host != nil && !hostMatches(*r.Host, host) {
		return false
	}
	return true
}

func (r ScopeRule) Matches(host string, port uint16, path string, tls bool) bool {
	if !r.MatchesHost(host, port, tls) {
		return false
	}
	if r.PathPrefix != nil && !strings.HasPrefix(path, *r.PathPrefix) {
		return false
	}
	return true
}

type Scope struct {
	mu         sync.RWMutex
	Rules      []ScopeRule `json:"rules"`
	AllowAll   bool        `json:"allow_all"`
	NextRuleID uint64      `json:"next_rule_id"`
}

func NewScope() *Scope {
	return &Scope{
		Rules: make([]ScopeRule, 0),
	}
}

func NewAllowEverythingScope() *Scope {
	return &Scope{
		Rules:    make([]ScopeRule, 0),
		AllowAll: true,
	}
}

func (s *Scope) AddRule(r ScopeRule) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.NextRuleID++
	r.ID = s.NextRuleID
	s.Rules = append(s.Rules, r)
	return r.ID
}

func (s *Scope) RemoveRule(id uint64) (ScopeRule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.Rules {
		if r.ID == id {
			s.Rules = append(s.Rules[:i], s.Rules[i+1:]...)
			return r, true
		}
	}
	return ScopeRule{}, false
}

func (s *Scope) Contains(host string, port uint16, path string, tls bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.AllowAll {
		return true
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	verdict := false
	for _, r := range s.Rules {
		if r.Matches(h, port, path, tls) {
			verdict = r.Kind == Include
		}
	}
	return verdict
}

func (s *Scope) MayContainHost(host string, port uint16, tls bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.AllowAll {
		return true
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	possible := false
	for _, r := range s.Rules {
		if !r.MatchesHost(h, port, tls) {
			continue
		}
		switch r.Kind {
		case Include:
			possible = true
		case Exclude:
			if r.PathPrefix == nil {
				possible = false
			}
		}
	}
	return possible
}

func (s *Scope) AuthorisesWholeHost(host string, port uint16, tls bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.AllowAll {
		return true
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	hostWideInclude := false
	for _, r := range s.Rules {
		if !r.MatchesHost(h, port, tls) {
			continue
		}
		switch r.Kind {
		case Exclude:
			return false
		case Include:
			if r.PathPrefix == nil {
				hostWideInclude = true
			}
		}
	}
	return hostWideInclude
}

func (s *Scope) AuthoriseRequest(host string, port uint16, tls bool, raw []byte) error {
	path, ok := RequestPath(raw)
	if !ok {
		return fmt.Errorf("refused: request has no readable request line to check scope against")
	}
	if s.Contains(host, port, path, tls) {
		return nil
	}
	return fmt.Errorf("refused: %s — %s", path, s.Explain(host, port, path, tls))
}

func (s *Scope) Explain(host string, port uint16, path string, tls bool) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.AllowAll {
		return "in scope (scope is set to allow everything)"
	}
	if len(s.Rules) == 0 {
		return fmt.Sprintf("out of scope: no scope rules are configured, so nothing is authorised (add an include rule for %s)", host)
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	var last *ScopeRule
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.Matches(h, port, path, tls) {
			last = r
		}
	}
	if last == nil {
		return fmt.Sprintf("out of scope: %s:%d matches no rule", host, port)
	}
	if last.Kind == Include {
		return fmt.Sprintf("in scope via %+v", *last)
	}
	return fmt.Sprintf("out of scope: excluded by %+v", *last)
}

func (s *Scope) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.AllowAll && len(s.Rules) == 0
}

func (s *Scope) GetRules() []ScopeRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScopeRule, len(s.Rules))
	copy(out, s.Rules)
	return out
}

func RequestPath(raw []byte) (string, bool) {
	lineEnd := bytes.IndexAny(raw, "\r\n")
	if lineEnd == -1 {
		lineEnd = len(raw)
	}
	line := string(raw[:lineEnd])
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", false
	}
	target := parts[1]

	rest := target
	if idx := strings.Index(target, "://"); idx != -1 {
		authority := target[idx+3:]
		if slashIdx := strings.IndexByte(authority, '/'); slashIdx != -1 {
			rest = authority[slashIdx:]
		} else {
			rest = "/"
		}
	}

	if qIdx := strings.IndexByte(rest, '?'); qIdx != -1 {
		return rest[:qIdx], true
	}
	return rest, true
}

func ValidateHostPattern(pattern string) error {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return fmt.Errorf("a scope rule needs a host")
	}
	stars := strings.Count(p, "*")
	if stars > 1 || (stars == 1 && !strings.HasPrefix(p, "*.")) {
		return fmt.Errorf("%q is not a host pattern: exactly one leading `*.` is supported and nothing else wildcards, so this rule would match no host at all", pattern)
	}
	if p == "*." {
		return fmt.Errorf("`*.` on its own has no domain to match under")
	}
	if strings.Contains(p, "/") || strings.ContainsAny(p, " \t\r\n") {
		return fmt.Errorf("%q is a host, not a URL — put a path in the rule's path prefix instead", pattern)
	}
	return nil
}

func hostMatches(pattern, host string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if strings.HasPrefix(p, "*.") {
		suffix := p[2:]
		if len(h) > len(suffix) && strings.HasSuffix(h, suffix) {
			return h[len(h)-len(suffix)-1] == '.'
		}
		return false
	}
	return h == p
}
