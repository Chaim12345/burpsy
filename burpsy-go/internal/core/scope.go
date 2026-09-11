package core

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
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
	// PathPrefix, when set, limits the rule to paths starting with it. Nil matches any path,
	// which is what every host-only rule built before this field existed means.
	PathPrefix *string
	// Protocol, when set ("http" or "https"), limits the rule to that scheme. Nil matches either,
	// which is what every rule built before this field existed means.
	Protocol *string
	// Enabled gates this rule's participation in every scope decision: matching, Contains,
	// Explain, and the host-level pre-filter. It defaults to true everywhere a rule is built,
	// so a rule without an explicit flag behaves exactly as every rule always has.
	Enabled bool
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
	// Default enabled: every rule this function ever built behaved as an active rule, and so
	// does every rule built from here on unless a caller says otherwise.
	rule.Enabled = true
	return rule
}

// NewScopeRuleWithPort creates a scope rule with a specific port.
func NewScopeRuleWithPort(kind ScopeRuleKind, pattern string, port uint16) *ScopeRule {
	rule := NewScopeRule(kind, pattern)
	rule.Port = &port
	return rule
}

// NewScopeRuleWithPath creates a scope rule limited to a path prefix, so an operator can exclude
// /admin on an otherwise authorised host without taking the whole host out of scope.
func NewScopeRuleWithPath(kind ScopeRuleKind, pattern string, pathPrefix string) *ScopeRule {
	rule := NewScopeRule(kind, pattern)
	rule.PathPrefix = &pathPrefix
	return rule
}

// Matches checks if a host matches this rule. A disabled rule matches nothing: it is stored,
// shown and togglable, but takes no part in any scope decision — the one-flag equivalent of
// removing the rule and putting it back later.
func (r *ScopeRule) Matches(host string, port uint16) bool {
	if !r.Enabled {
		return false
	}
	if r.Port != nil && *r.Port != port {
		return false
	}
	return r.Regex.MatchString(host)
}

// MatchesRequest checks host, port, path prefix and protocol against one request.
func (r *ScopeRule) MatchesRequest(host string, port uint16, path string, isTLS bool) bool {
	if !r.Matches(host, port) {
		return false
	}
	// The wire decides scheme: https is TLS on the connection the request actually uses, not a
	// property of the URL string. A rule with a protocol arm matches only its own scheme.
	if r.Protocol != nil {
		if (*r.Protocol == "https") != isTLS {
			return false
		}
	}
	if r.PathPrefix != nil && !strings.HasPrefix(path, *r.PathPrefix) {
		return false
	}
	return true
}

// Scope represents the URL scope for capture and authorization.
type Scope struct {
	mu       sync.RWMutex
	rules    []*ScopeRule
	allowAll bool
	// dropOutOfScope is Burp's "Out-of-scope request handling: Drop all out-of-scope requests"
	// (settings/project/scope.html). When set, every scope refusal becomes an egress refusal:
	// Contains keeps its retention meaning, and AuthoriseRequest — the gate the proxy relay paths
	// ask before forwarding — refuses instead of letting the request through unrecorded.
	//
	// It deliberately does NOT reach MayContainHost: that is a host-level pre-filter and cannot
	// carry a per-request decision, for the reasons its own doc comment gives. An earlier version
	// of this comment named MayContainHost as an enforcement point, which contradicted that
	// method and described a fence nothing had built. Seed off: the proxy has
	// always forwarded what the browser asked for, and flipping that on upgrade would break
	// every session mid-flight for operators who never touched the setting. Burp defaults it
	// off for the same reason.
	dropOutOfScope bool
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

// SetDropOutOfScope turns Burp's "Drop all out-of-scope requests" on or off. It is an
// egress-control switch, deliberately separate from every scope decision that reads the rule
// list: Contains answers "is this retained", and this answers "may it be sent at all". The
// separation is what lets dont_log_out_of_scope (a retention choice) and this (an egress
// choice) be configured independently, as Burp's two panels do.
func (s *Scope) SetDropOutOfScope(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropOutOfScope = on
}

// DropOutOfScope reports whether out-of-scope requests are refused at egress.
func (s *Scope) DropOutOfScope() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dropOutOfScope
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

// RemoveScoped removes the rule matching a kind, pattern, path prefix and port exactly.
//
// Remove matches on kind and pattern alone, which was unambiguous while every rule was host-only.
// Once a rule can also carry a path prefix or a port, one host can hold several rules that differ
// only in those — include(h) alongside exclude(h, "/admin") is the ordinary case — and Remove would
// delete whichever came first rather than the one named. Deleting the wrong scope rule silently
// widens or narrows an engagement's authorised surface, so the tuple has to be exact.
//
// Nil path and nil port mean "the rule that also has none", not "any": removing the host-wide rule
// must not take a path-scoped sibling with it.
func (s *Scope) RemoveScoped(kind ScopeRuleKind, pattern string, pathPrefix *string, port *uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, rule := range s.rules {
		if rule.Kind != kind || rule.Pattern != pattern {
			continue
		}
		if !eqStrPtr(rule.PathPrefix, pathPrefix) || !eqPortPtr(rule.Port, port) {
			continue
		}
		s.rules = append(s.rules[:i], s.rules[i+1:]...)
		return true
	}
	return false
}

// SetRuleEnabled flips the enabled flag on the rule matching a kind, pattern, path prefix and
// port exactly — the same tuple identity RemoveScoped matches on, so a toggle cannot touch a
// same-host sibling that differs only in path or port. It reports whether a rule was found and
// changed; false means the caller named a rule that is not there, which the endpoint turns
// into a 404 rather than a silent success.
//
// Enabled does not take part in the identity: toggling twice with the same tuple flips the
// same rule twice, which is exactly what a switch must do.
func (s *Scope) SetRuleEnabled(kind ScopeRuleKind, pattern string, pathPrefix *string, port *uint16, enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rule := range s.rules {
		if rule.Kind != kind || rule.Pattern != pattern {
			continue
		}
		if !eqStrPtr(rule.PathPrefix, pathPrefix) || !eqPortPtr(rule.Port, port) {
			continue
		}
		rule.Enabled = enabled
		return true
	}
	return false
}

func eqStrPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func eqPortPtr(a, b *uint16) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Clear removes all scope rules.
func (s *Scope) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = s.rules[:0]
}

// Contains checks if a URL is within scope. Excludes always win; a matching exclude rule takes
// the host out of scope regardless of any include rules. Rules with a path prefix only apply
// when the request's path falls under that prefix.
func (s *Scope) Contains(host string, port uint16, path string, isTLS bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.allowAll {
		return true
	}

	// Excludes always win: a matching exclude rule takes the host out of scope
	// regardless of any include rules.
	for _, rule := range s.rules {
		if rule.Kind == ScopeExclude && rule.MatchesRequest(host, port, path, isTLS) {
			return false
		}
	}

	// With no include rules, everything not excluded is in scope (default allow).
	hasIncludeRule := false
	for _, rule := range s.rules {
		if rule.Kind == ScopeInclude {
			hasIncludeRule = true
			if rule.MatchesRequest(host, port, path, isTLS) {
				return true
			}
		}
	}

	return !hasIncludeRule
}

// AuthoriseRequest reports whether a request may be ISSUED — a different question from Contains,
// which decides whether it is RETAINED.
//
// The two answers differ exactly when the request is out of scope and the drop switch is off:
// Burp's default out-of-scope handling forwards such a request and simply does not process it,
// which is also what this proxy has always done. Turning the switch on is what collapses the two
// answers into one, and that is the whole content of the setting.
//
// This is the gate for pass-through traffic. Operator-initiated tools go through AuthoriseRaw
// instead, which refuses an out-of-scope target either way — burpsy's own stricter stance for a
// request the operator asked it to compose, where "I did not mean to send that" is not a
// recoverable mistake. The switch changes the wording of that refusal, not the verdict.
//
// It returned a bare Contains for some time, which made the switch inert everywhere it was read
// and left the setting describing an enforcement that did not exist (burpsy-react-ui-ckqx).
func (s *Scope) AuthoriseRequest(host string, port uint16, path string, isTLS bool) bool {
	if s.Contains(host, port, path, isTLS) {
		return true
	}
	return !s.DropOutOfScope()
}

// MayContainHost reports whether *any* path on this host could be in scope. A pre-filter, never an
// authorisation decision, ported from burpsy-core::scope::may_contain_host.
//
// This exists because asking about one arbitrary path cannot answer a question about a host:
// an `include(h).with_path_prefix("/v1/")` makes `Contains(h, p, "/", tls)` false even though the
// /v1/ paths an attack may invent are authorised, while an `include(h)` + path-scoped
// `exclude(h, "/admin")` pair makes `Contains(h, p, "/", tls)` true and a caller taking that as
// permission for the whole host would send a payload right at /admin.
//
// So this answers only "is this host worth considering at all", deliberately permissively about
// *paths*: a path- or protocol-scoped exclude removes requests, not the host, and a path-scoped
// include keeps the host because the paths an attack invents under that prefix are authorised. The
// real per-request decision belongs to AuthoriseRaw, on the bytes actually going on the wire.
//
// It is NOT permissive about the include list itself (burpsy-react-ui-cj7x). It used to be:
// `possible` started true and only a whole-host exclude could flip it, so a host matching no
// include rule came back true. That was not a harmless pre-filter looseness — MayContainHost is the
// only gate /api/repeater/send and /api/intruder/run apply to the target, so with
// `include(elsewhere.invalid)` set, MayContainHost("127.0.0.1") returned true and Repeater sent
// there while Contains and AuthoriseRaw both refused the same host. In a tool used under engagement
// rules, traffic leaving the include list is the one failure that cannot be argued down.
//
// The include semantics now match Contains' exactly, which is the recorded cross-tool decision:
// an empty include list still means "everything" (a scope nobody has narrowed does not stop work),
// but once any include rule exists the list means "only these", and a host named by none of them is
// refused here as it already was there.
//
// dropOutOfScope deliberately does NOT reach this method. A host-level pre-filter cannot carry
// an egress decision without breaking its own contract: with every include disabled and the
// switch on, filtering on Enabled would make hasInclude false and return default-allow — the
// opposite of Contains, which refuses — re-opening the exact cross-tool disagreement cj7x
// closed. The switch's egress enforcement lives in the two places a request is actually issued:
// AuthoriseRaw (the proxy's per-wire-request gate, whose refusal says "dropped") and the send
// endpoints' AuthoriseRequest/AuthoriseRaw paths. A caller holding only MayContainHost's
// answer is holding a "worth considering" verdict, not a permission to send.
func (s *Scope) MayContainHost(host string, port uint16, isTLS bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.allowAll {
		return true
	}
	// A whole-host exclude puts the host beyond reach, whatever the includes say — excludes win
	// here for the same reason they win in Contains. Path- and protocol-scoped excludes are skipped:
	// they remove some requests and leave the rest of the host reachable, and an https-only exclude
	// says nothing about http.
	for _, rule := range s.rules {
		if rule.Kind != ScopeExclude || !rule.Matches(host, port) {
			continue
		}
		if rule.PathPrefix == nil && rule.Protocol == nil {
			return false
		}
	}

	// Then the include list, with Contains' semantics: no include rules at all means default-allow,
	// but any include rule turns the list into an allow-list this host must appear on. Matched at
	// host level (rule.Matches ignores the path), so a path-scoped include still keeps its host --
	// the paths under that prefix are exactly what an attack is authorised to invent.
	hasInclude := false
	for _, rule := range s.rules {
		if rule.Kind != ScopeInclude {
			continue
		}
		hasInclude = true
		if rule.Matches(host, port) {
			return true
		}
	}
	return !hasInclude
}

// requestPath extracts the request target from a raw request line, the way burpsy-core::scope's
// request_path does: both origin-form and absolute-form targets, query string dropped, a
// proxied request with no path at all reading as "/". The second result is false when no path
// can be read — a refusal, never a wave-through, because an unreadable request line is exactly
// what a smuggled payload looks like.
func requestPath(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	lineEnd := len(raw)
	if i := bytesIndexByte(raw, '\n'); i >= 0 {
		lineEnd = i
	}
	line := raw[:lineEnd]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	sp1 := bytesIndexByte(line, ' ')
	if sp1 < 0 {
		return "", false
	}
	target := line[sp1+1:]
	if len(target) == 0 {
		return "", false
	}
	sp2 := bytesIndexByte(target, ' ')
	if sp2 >= 0 {
		target = target[:sp2]
	}
	if len(target) == 0 {
		return "", false
	}
	if bytesHasPrefix(target, "http://") || bytesHasPrefix(target, "https://") {
		// Absolute form: the path is everything after the authority. No slash at all means the
		// request addresses the root, which matters for proxied requests.
		rest := target[len("http://"):]
		if bytesHasPrefix(target, "https://") {
			rest = target[len("https://"):]
		}
		slash := bytesIndexByte(rest, '/')
		if slash < 0 {
			return "/", true
		}
		return dropQuery(rest[slash:])
	}
	return dropQuery(target)
}

func dropQuery(target []byte) (string, bool) {
	q := bytesIndexByte(target, '?')
	if q >= 0 {
		target = target[:q]
	}
	if !utf8.Valid(target) {
		return "", false
	}
	return string(target), true
}

func bytesIndexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func bytesHasPrefix(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// Explain says why a request is or is not in scope, naming the path that decided it. The message
// is what AuthoriseRaw refuses with, so an operator learns which path tripped the rule rather
// than receiving a bare "refused".
func (s *Scope) Explain(host string, port uint16, path string, isTLS bool) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	where := fmt.Sprintf("%s:%d%s", host, port, path)
	if s.allowAll {
		return "allowed: " + where + " (scope allows everything)"
	}
	for _, rule := range s.rules {
		if rule.Kind == ScopeExclude && rule.MatchesRequest(host, port, path, isTLS) {
			return "refused: " + where + " is excluded by scope rule " + rule.Pattern
		}
	}
	hasInclude := false
	for _, rule := range s.rules {
		if rule.Kind == ScopeInclude {
			hasInclude = true
			if rule.MatchesRequest(host, port, path, isTLS) {
				return "allowed: " + where + " matches include rule " + rule.Pattern
			}
		}
	}
	if !hasInclude {
		return "allowed: " + where + " (no rules — default allow)"
	}
	return "refused: " + where + " matches no include rule"
}

// AuthoriseRaw checks the request actually going on the wire, not the target the operator named.
// A payload spliced into a path position rewrites the request line, and only the bytes that will
// be sent can be trusted. The path is read from raw; the host and port come from the bound
// target. A request whose line cannot be read is refused, never waved through.
func (s *Scope) AuthoriseRaw(host string, port uint16, isTLS bool, raw []byte) error {
	path, ok := requestPath(raw)
	if !ok {
		return errors.New("refused: request has no readable request line, so no path could be checked")
	}
	if !s.Contains(host, port, path, isTLS) {
		// With the drop switch on, the refusal is an egress refusal: the message says so,
		// because "your request was retained nowhere and sent nowhere" is a different report
		// from "it was sent but not kept", and a tool used under engagement rules owes the
		// operator that difference.
		if s.DropOutOfScope() {
			return errors.New("dropped: out-of-scope request handling is set to drop; " + s.Explain(host, port, path, isTLS))
		}
		return errors.New(s.Explain(host, port, path, isTLS))
	}
	return nil
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

// AuthoriseRaw delegates the per-request raw-bytes check to the underlying scope.
func (ss *SharedScope) AuthoriseRaw(host string, port uint16, isTLS bool, raw []byte) error {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.scope.AuthoriseRaw(host, port, isTLS, raw)
}

// MayContainHost delegates the host-level pre-filter to the underlying scope.
func (ss *SharedScope) MayContainHost(host string, port uint16, tls bool) bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.scope.MayContainHost(host, port, tls)
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
