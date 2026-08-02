package core

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ScopeRuleKind indicates the kind of scope rule.
type ScopeRuleKind int

const (
	ScopeInclude ScopeRuleKind = iota
	ScopeExclude
)

// ScopeRule represents a single scope rule.
type ScopeRule struct {
	Kind    ScopeRuleKind
	Pattern string
	Regex   *regexp.Regexp
	Port    *uint16
}

// NewScopeRule creates a new scope rule from a pattern.
func NewScopeRule(kind ScopeRuleKind, pattern string) *ScopeRule {
	rule := &ScopeRule{
		Kind:    kind,
		Pattern: pattern,
	}

	// Convert wildcard pattern to regex
	regexPattern := "^"
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i == 0 && len(pattern) > 1 && pattern[1] == '.' {
				// *.example.com matches any subdomain (zero or more labels).
				regexPattern += "([a-zA-Z0-9-]+\\.)*"
				i++ // the dot is included in the label group above
			} else {
				regexPattern += ".*"
			}
		case '.':
			regexPattern += "\\."
		default:
			regexPattern += regexp.QuoteMeta(string(c))
		}
	}
	regexPattern += "$"

	rule.Regex = regexp.MustCompile(regexPattern)
	return rule
}

// NewScopeRuleWithPort creates a scope rule with a specific port.
func NewScopeRuleWithPort(kind ScopeRuleKind, pattern string, port uint16) *ScopeRule {
	rule := NewScopeRule(kind, pattern)
	rule.Port = &port
	return rule
}

// Matches checks if a host matches this rule.
func (r *ScopeRule) Matches(host string, port uint16) bool {
	if r.Port != nil && *r.Port != port {
		return false
	}
	return r.Regex.MatchString(host)
}

// Scope represents the URL scope for capture and authorization.
type Scope struct {
	mu       sync.RWMutex
	rules    []*ScopeRule
	allowAll bool
}

// NewScope creates a new empty scope.
func NewScope() *Scope {
	return &Scope{
		rules: make([]*ScopeRule, 0),
	}
}

// NewScopeAllowEverything creates a scope that allows everything.
func NewScopeAllowEverything() *Scope {
	return &Scope{
		allowAll: true,
		rules:    make([]*ScopeRule, 0),
	}
}

// Add adds a rule to the scope.
func (s *Scope) Add(rule *ScopeRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rule)
}

// AddInclude adds an include rule.
func (s *Scope) AddInclude(pattern string) {
	s.Add(NewScopeRule(ScopeInclude, pattern))
}

// AllowAll reports whether the scope allows everything unconditionally.
func (s *Scope) AllowAll() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowAll
}

// Empty reports whether the scope has no rules.
func (s *Scope) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules) == 0
}

// Rules returns a copy of all scope rules.
func (s *Scope) Rules() []*ScopeRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ScopeRule, len(s.rules))
	copy(result, s.rules)
	return result
}

// AddExclude adds an exclude rule.
func (s *Scope) AddExclude(pattern string) {
	s.Add(NewScopeRule(ScopeExclude, pattern))
}

// Remove removes the first rule matching the given kind and pattern.
// It reports whether a rule was removed.
func (s *Scope) Remove(kind ScopeRuleKind, pattern string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, rule := range s.rules {
		if rule.Kind == kind && rule.Pattern == pattern {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			return true
		}
	}
	return false
}

// Clear removes all scope rules.
func (s *Scope) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = s.rules[:0]
}

// Contains checks if a URL is within scope.
func (s *Scope) Contains(host string, port uint16, path string, isTLS bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.allowAll {
		return true
	}

	// Excludes always win: a matching exclude rule takes the host out of scope
	// regardless of any include rules.
	for _, rule := range s.rules {
		if rule.Kind == ScopeExclude && rule.Matches(host, port) {
			return false
		}
	}

	// With no include rules, everything not excluded is in scope (default allow).
	hasIncludeRule := false
	for _, rule := range s.rules {
		if rule.Kind == ScopeInclude {
			hasIncludeRule = true
			if rule.Matches(host, port) {
				return true
			}
		}
	}

	return !hasIncludeRule
}

// AuthoriseRequest checks if a request is authorized to be sent.
func (s *Scope) AuthoriseRequest(host string, port uint16, path string, isTLS bool) bool {
	return s.Contains(host, port, path, isTLS)
}

// SharedScope is a thread-safe shared scope handle.
type SharedScope struct {
	mu    sync.RWMutex
	scope *Scope
}

// NewSharedScope creates a new shared scope.
func NewSharedScope(scope *Scope) *SharedScope {
	return &SharedScope{
		scope: scope,
	}
}

// Contains delegates to the underlying scope.
func (ss *SharedScope) Contains(host string, port uint16, path string, isTLS bool) bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.scope.Contains(host, port, path, isTLS)
}

// Set replaces the underlying scope.
func (ss *SharedScope) Set(scope *Scope) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.scope = scope
}

// Get returns the current scope.
func (ss *SharedScope) Get() *Scope {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.scope
}

// AddRule adds a rule to the current scope.
func (ss *SharedScope) AddRule(rule *ScopeRule) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.scope.Add(rule)
}

// Helper to parse host:port strings
func ParseHostPort(hostPort string) (host string, port uint16) {
	lastColon := strings.LastIndex(hostPort, ":")
	if lastColon == -1 {
		return hostPort, 80
	}
	host = hostPort[:lastColon]
	p, err := strconv.Atoi(hostPort[lastColon+1:])
	if err != nil {
		port = 80
	} else {
		port = uint16(p)
	}
	return host, port
}
