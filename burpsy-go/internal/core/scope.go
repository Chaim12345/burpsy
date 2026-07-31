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
	for i, c := range pattern {
		switch c {
		case '*':
			if i == 0 && len(pattern) > 1 && pattern[1] == '.' {
				// *.example.com matches any subdomain
				regexPattern += "([a-zA-Z0-9-]+\\.)*"
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
	mu     sync.RWMutex
	rules  []*ScopeRule
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

// AddExclude adds an exclude rule.
func (s *Scope) AddExclude(pattern string) {
	s.Add(NewScopeRule(ScopeExclude, pattern))
}

// Contains checks if a URL is within scope.
func (s *Scope) Contains(host string, port uint16, path string, isTLS bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.allowAll {
		return true
	}

	// Check excludes first
	for _, rule := range s.rules {
		if rule.Kind == ScopeExclude && rule.Matches(host, port) {
			return false
		}
	}

	// Then check includes
	hasInclude := false
	for _, rule := range s.rules {
		if rule.Kind == ScopeInclude && rule.Matches(host, port) {
			hasInclude = true
			break
		}
	}

	return hasInclude || len(s.rules) == 0
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
