package core

import (
	"errors"
	"fmt"
	"net/netip"
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

// Arm tags. A rule's host pattern and path arm are plain strings — a host glob and a path prefix —
// and these two prefixes are how a rule says the string is something else: a regular expression for
// that URL component, or an IP range (burpsy-react-ui-c09). Burp states the same two arms as one
// field each ("Specify a regular expression to match each URL component"; "Host or IP range").
//
// # Why the tag rides inside the string instead of being a new field
//
// The arm has to survive a restart, an export/import round trip and a rule's own identity, and all
// three carry exactly these two strings: persist.Store.SaveScope writes `pattern` and `path_prefix`
// and scanScopeRows rebuilds every rule with NewScopeRule(kind, pattern) plus a direct PathPrefix
// assignment; api_config's bundle carries the same two; and RemoveScoped, ReplaceScoped and
// SetRuleEnabled all identify a rule by (kind, pattern, path, port).
//
// A parallel `host_regex` column would have to land in all four before a regex rule could be
// removed, edited, exported or reloaded — and until it did, a `regex:` rule would come back from
// the database as a *literal glob*. For an include that means a rule that silently matches nothing;
// for an exclude it means traffic the operator excluded being allowed again, which is the one
// failure direction this package exists to prevent. Encoding the arm in the value the store already
// round-trips makes the interpretation a pure function of what is stored, so every reconstruction
// path agrees by construction rather than by four separate patches staying in step.
//
// The tags cannot collide with a host pattern: a host has no colon in it (the port is its own
// field), and a verified sweep of the tree found no existing pattern, fixture or bundle beginning
// with either.
const (
	// ScopeRegexArm marks a host pattern or a path arm as a regular expression.
	ScopeRegexArm = "regex:"
	// ScopeRangeArm marks a host pattern as an IP range in CIDR form (or a bare IP literal).
	ScopeRangeArm = "range:"
)

// ScopeRule represents a single scope rule.
type ScopeRule struct {
	Kind    ScopeRuleKind
	Pattern string
	// Regex is the compiled *glob* form of Pattern — the historical arm, and still the default.
	// It is nil exactly when Pattern carries an arm tag, because a tagged pattern is not a glob and
	// compiling it as one would produce a rule that matches a host nobody wrote.
	Regex *regexp.Regexp
	// HostRegex is the compiled `regex:` host arm: the whole host must match it. Nil means the
	// rule does not use this arm, never "matches anything".
	HostRegex *regexp.Regexp
	// HostRange is the compiled `range:` host arm: the host must be an IP literal inside this
	// prefix. Nil means the rule does not use this arm.
	HostRange *netip.Prefix
	// PathRegex is the compiled `regex:` path arm: the whole request path must match it. Nil means
	// the path arm is the literal prefix in PathPrefix (or, with PathPrefix nil, any path).
	PathRegex *regexp.Regexp
	// Invalid records why this rule's arms could not be interpreted. Every entry point refuses such
	// a rule before it is stored (NewScopeRuleFrom returns the error, and the endpoints answer 400),
	// so a rule reaches this state only from a store written by hand or by an older build. It is not
	// a rule that "matches nothing": see ArmFault and Scope.Validate — a scope holding one authorises
	// nothing and retains nothing, rather than quietly dropping an exclude.
	Invalid error
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
//
// The pattern is a host glob unless it carries an arm tag (ScopeRegexArm / ScopeRangeArm), in which
// case it is compiled as that arm instead. A tag that cannot be compiled leaves the rule Invalid —
// it is never compiled as a glob and it never panics, because this function is on the restore path
// (persist.scanScopeRows) and a MustCompile there would turn one bad database row into a server that
// cannot start. Callers that can report an error should use NewScopeRuleFrom, which does.
func NewScopeRule(kind ScopeRuleKind, pattern string) *ScopeRule {
	rule := &ScopeRule{
		Kind:    kind,
		Pattern: pattern,
	}
	// Default enabled: every rule this function ever built behaved as an active rule, and so
	// does every rule built from here on unless a caller says otherwise. Set before the arm
	// compile so a tagged pattern that fails still produces a rule whose only difference from a
	// working one is Invalid.
	rule.Enabled = true

	if isTaggedArm(pattern) {
		rule.compileHostArm()
		return rule
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

// isTaggedArm reports whether a stored arm string states an arm other than the default one.
func isTaggedArm(arm string) bool {
	return strings.HasPrefix(arm, ScopeRegexArm) || strings.HasPrefix(arm, ScopeRangeArm)
}

// armRegexp compiles a `regex:` arm body, anchored to the whole component.
//
// # Anchoring
//
// The expression is wrapped in \A(?:...)\z, so it must match the entire host or the entire path.
// That is the glob arm's own semantics — NewScopeRule builds ^...$ — and a rule table whose two
// host arms disagreed about whether `example\.com` also covers `example.com.attacker.test` would be
// a trap worse than either choice alone. The Burp idiom `^www\.example\.com$` is unchanged by the
// wrapping, because Go's ^ and $ are text anchors without (?m).
//
// It has a cost, and it is not the safe direction in every case: an operator porting an *unanchored*
// exclude (`admin` meaning "anything containing admin") gets a rule that excludes less than they
// expect, which widens what is authorised. It is stated in the UI hint beside the field for exactly
// that reason — use `.*admin.*` to mean "contains". The alternative, leaving it unanchored, widens
// every *include* instead, silently and for everyone rather than for operators porting one shape.
//
// No implicit (?i): a case-insensitive match is `(?i)` written by the operator, and inserting it
// here would make a rule match hosts its author did not write.
func armRegexp(what, body string) (*regexp.Regexp, error) {
	if strings.TrimSpace(body) == "" {
		// Burp's "leave blank to match any item" is precisely the implicit-widening trap this
		// package refuses: an empty expression here would compile to \A(?:)\z, a rule that looks
		// armed and matches only the empty string. A rule that cannot say what it means is refused
		// where the operator can still fix it.
		return nil, fmt.Errorf("a %s regular expression is empty; write the expression after %q, or drop the tag to match on the host pattern instead", what, ScopeRegexArm)
	}
	re, err := regexp.Compile(`\A(?:` + body + `)\z`)
	if err != nil {
		return nil, fmt.Errorf("the %s regular expression %q does not compile: %w", what, body, err)
	}
	return re, nil
}

// armPrefix parses a `range:` arm body into an IP prefix.
//
// A bare address means that address alone (a /32 or /128), because "range: 10.0.0.5" is the obvious
// way to write one host and refusing it would teach operators to write /32 by hand for no gain.
//
// Host bits are refused rather than masked: `range:10.0.0.5/8` is either a typo for 10.0.0.0/8 — two
// orders of magnitude wider than what is written — or for 10.0.0.5/32. Guessing which one is meant
// is guessing at the size of an authorised network, so it is refused where the operator can see it.
func armPrefix(body string) (*netip.Prefix, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, fmt.Errorf("an IP range is empty; write a CIDR block or an address after %q", ScopeRangeArm)
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		if addr.Zone() != "" {
			return nil, fmt.Errorf("the IP range %q carries a zone; a scope rule cannot decide what a link-local zone means on the host that sent the request", trimmed)
		}
		addr = addr.Unmap()
		p := netip.PrefixFrom(addr, addr.BitLen())
		return &p, nil
	}
	p, err := netip.ParsePrefix(trimmed)
	if err != nil {
		return nil, fmt.Errorf("the IP range %q is neither an address nor a CIDR block: %w", trimmed, err)
	}
	if p.Addr().Is4In6() {
		return nil, fmt.Errorf("the IP range %q is an IPv4 range written in IPv6 form; write it as dotted quads (for example 10.0.0.0/8) so its width reads the way it matches", trimmed)
	}
	if masked := p.Masked(); masked != p {
		return nil, fmt.Errorf("the IP range %q has host bits set; write %q for the network or %q for that one address", trimmed, masked.String(), p.Addr().String())
	}
	return &p, nil
}

// compileHostArm (re)derives the host arm from Pattern, recording the reason on failure. Idempotent,
// so calling it on a rule built by NewScopeRule costs a recompile and changes nothing.
func (r *ScopeRule) compileHostArm() {
	r.Regex, r.HostRegex, r.HostRange, r.Invalid = nil, nil, nil, nil
	switch {
	case strings.HasPrefix(r.Pattern, ScopeRegexArm):
		re, err := armRegexp("host", strings.TrimPrefix(r.Pattern, ScopeRegexArm))
		if err != nil {
			r.Invalid = err
			return
		}
		r.HostRegex = re
	case strings.HasPrefix(r.Pattern, ScopeRangeArm):
		prefix, err := armPrefix(strings.TrimPrefix(r.Pattern, ScopeRangeArm))
		if err != nil {
			r.Invalid = err
			return
		}
		r.HostRange = prefix
	default:
		rebuilt := NewScopeRule(r.Kind, r.Pattern)
		r.Regex = rebuilt.Regex
	}
}

// compilePathArm (re)derives the path arm from PathPrefix. A nil or untagged prefix leaves PathRegex
// nil, which is the literal-prefix arm every rule has always had.
func (r *ScopeRule) compilePathArm() {
	r.PathRegex = nil
	if r.PathPrefix == nil || !strings.HasPrefix(*r.PathPrefix, ScopeRegexArm) {
		return
	}
	re, err := armRegexp("path", strings.TrimPrefix(*r.PathPrefix, ScopeRegexArm))
	if err != nil {
		if r.Invalid == nil {
			r.Invalid = err
		}
		return
	}
	r.PathRegex = re
}

// compileArms derives both arms from the strings the rule stores. Scope.Add and Scope.ReplaceScoped
// call it on every rule they take, which is what makes the restore path safe: persist's scanScopeRows
// assigns PathPrefix directly, so a `regex:` path arm read back from the database has no compiled
// form until something recompiles it, and an uncompiled path arm on an *exclude* would let through
// exactly the requests the operator excluded.
func (r *ScopeRule) compileArms() {
	r.compileHostArm()
	r.compilePathArm()
}

// ArmFault reports why this rule cannot be interpreted, or nil when it can.
//
// It is deliberately more than "is Invalid set": a rule whose stored strings carry an arm tag with no
// compiled form is a rule that was assembled field by field and never compiled, and treating that as
// "no arm, match on the glob" or as "matches nothing" are both ways of quietly changing what the
// operator wrote. Naming it as a fault is what lets Scope refuse instead of guess.
func (r *ScopeRule) ArmFault() error {
	if r.Invalid != nil {
		return r.Invalid
	}
	if strings.HasPrefix(r.Pattern, ScopeRegexArm) && r.HostRegex == nil {
		return fmt.Errorf("host pattern %q states a regular expression that was never compiled", r.Pattern)
	}
	if strings.HasPrefix(r.Pattern, ScopeRangeArm) && r.HostRange == nil {
		return fmt.Errorf("host pattern %q states an IP range that was never parsed", r.Pattern)
	}
	if !isTaggedArm(r.Pattern) && r.Regex == nil {
		return fmt.Errorf("host pattern %q has no compiled form at all", r.Pattern)
	}
	if r.PathPrefix != nil && strings.HasPrefix(*r.PathPrefix, ScopeRegexArm) && r.PathRegex == nil {
		return fmt.Errorf("path arm %q states a regular expression that was never compiled", *r.PathPrefix)
	}
	return nil
}

// NewScopeRuleFrom builds a rule from the arms an endpoint received, refusing loudly what
// NewScopeRule can only record. This is the constructor every caller that can answer 400 should use:
// a bad regular expression or a bad IP range is an operator typo, and the moment it can still be
// fixed is before the rule is stored.
//
// path, port and protocol are the already-normalised optional arms (nil meaning "any"), so the
// endpoint keeps its own vocabulary checks — a path must start with "/", a protocol must be http or
// https — and this owns the arm tags, which are the part no endpoint should re-implement.
func NewScopeRuleFrom(kind ScopeRuleKind, pattern string, path *string, port *uint16, protocol *string) (*ScopeRule, error) {
	rule := NewScopeRule(kind, pattern)
	rule.PathPrefix = path
	rule.Port = port
	rule.Protocol = protocol
	rule.compileArms()
	if err := rule.ArmFault(); err != nil {
		return nil, err
	}
	return rule, nil
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
	// The prefix may itself state a `regex:` arm, and a path arm assigned without being compiled is
	// a rule that does not mean what it says — see compileArms.
	rule.compilePathArm()
	return rule
}

// Matches checks if a host matches this rule. A disabled rule matches nothing: it is stored,
// shown and togglable, but takes no part in any scope decision — the one-flag equivalent of
// removing the rule and putting it back later.
func (r *ScopeRule) Matches(host string, port uint16) bool {
	if !r.Enabled {
		return false
	}
	// A rule whose arms cannot be interpreted matches nothing. It does not therefore *allow*
	// anything: Scope refuses outright when it holds one (see Scope.Validate), because an exclude
	// that matches nothing is an exclude that has quietly lapsed.
	if r.ArmFault() != nil {
		return false
	}
	if r.Port != nil && *r.Port != port {
		return false
	}
	return r.matchesHost(host)
}

// matchesHost applies whichever host arm the rule carries. The final default is the one line this
// package cannot afford to get wrong: a rule with no compiled pattern at all does not match, it does
// not match everything. core.Scope is what internal/sender asks before every dial, so "nothing
// compiled" reading as "matches" would authorise the whole internet from a rule that failed to build.
func (r *ScopeRule) matchesHost(host string) bool {
	switch {
	case r.HostRange != nil:
		return hostInRange(host, *r.HostRange)
	case r.HostRegex != nil:
		return r.HostRegex.MatchString(host)
	case r.Regex != nil:
		return r.Regex.MatchString(host)
	default:
		return false
	}
}

// matchesPath applies whichever path arm the rule carries: the compiled regular expression when it
// has one, otherwise the literal prefix, otherwise any path (a rule with no path arm).
func (r *ScopeRule) matchesPath(path string) bool {
	if r.PathRegex != nil {
		return r.PathRegex.MatchString(path)
	}
	if r.PathPrefix != nil {
		return strings.HasPrefix(path, *r.PathPrefix)
	}
	return true
}

// hostInRange reports whether a request's host is an IP literal inside the prefix.
//
// A host that is not an IP literal never matches an IP-range arm, and the name is deliberately not
// resolved: a scope decision that depended on a DNS answer would be a decision an attacker with a
// resolver could move, and it would leak the target to that resolver before the operator had been
// told the request was authorised. Burp's own arm reads the host component, and so does this.
//
// The address is unmapped first, so an ::ffff:10.0.0.1 literal is inside 10.0.0.0/8 — the same host
// written two ways must not get two answers. A zoned literal (fe80::1%eth0) never matches: the zone
// names an interface on some machine, and this process cannot know it is the same one.
func hostInRange(host string, prefix netip.Prefix) bool {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || addr.Zone() != "" {
		return false
	}
	return prefix.Contains(addr.Unmap())
}

// MatchesRequest checks host, port, path and protocol against one request. The path arm is the
// literal prefix or, when the rule states one, a regular expression over the whole path.
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
	return r.matchesPath(path)
}

// Scope represents the URL scope for capture and authorization.
type Scope struct {
	mu       sync.RWMutex
	rules    []*ScopeRule
	allowAll bool
	// watchers holds the scope-change subscribers (burpsy-react-ui-e05t). Its own lock, never the
	// scope's: a handler runs AFTER the write lock is released (scope_change.go says why), so there
	// is no re-entrancy to protect here — and a separate lock means registering a handler cannot
	// block a Contains() on a request path.
	watchers scopeWatchers
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
	// dropScope is Burp's "Use custom scope" arm of out-of-scope request handling
	// (burpsy-react-ui-47ed): when set, the drop gate asks it instead of the suite scope, so an
	// engagement can drop by a narrower (or different) fence than the one that decides what is kept
	// and audited. It carries rules only; its own drop switch is unused. dropCustom says whether it is
	// in force: "Use suite scope" keeps the custom rules, as Burp's panel does, so choosing the custom
	// scope again does not mean typing them again.
	dropScope  *Scope
	dropCustom bool
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
//
// It compiles the rule's arms first, which matters for one caller in particular: persist's restore
// path rebuilds a rule with NewScopeRule and then assigns PathPrefix directly, so a `regex:` path arm
// read back from the database arrives here with no compiled form. Compiling at the door means a
// restored scope means exactly what the stored one did, rather than depending on which field the
// writer happened to set through a constructor.
func (s *Scope) Add(rule *ScopeRule) {
	if rule == nil {
		return
	}
	rule.compileArms()
	s.mu.Lock()
	before, allowAll := s.changeSnapshot()
	s.rules = append(s.rules, rule)
	s.mu.Unlock()
	// Fired AFTER the unlock (burpsy-react-ui-e05t): every mutator here uses defer-unlock, so a
	// notification from inside the critical section would deadlock the moment a handler called
	// Contains() to see what had changed.
	s.notify(ScopeChange{Before: before, After: before + 1, AllowAllBefore: allowAll,
		AllowAllAfter: allowAll, Operation: "add"})
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

// SetDropScope installs the custom scope's rules (nil for none) and whether the drop gate uses them
// (Burp's "Use custom scope") or the suite scope. The scope passed is owned by this one afterwards.
func (s *Scope) SetDropScope(custom *Scope, use bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropScope = custom
	s.dropCustom = use && custom != nil
}

// DropScope returns the custom drop scope's rules (nil when none were ever set) and whether the drop
// gate uses them.
func (s *Scope) DropScope() (*Scope, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dropScope, s.dropCustom
}

// activeDropScope is the custom scope when the drop gate uses it, else nil.
func (s *Scope) activeDropScope() *Scope {
	custom, use := s.DropScope()
	if !use {
		return nil
	}
	return custom
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

	for i, rule := range s.rules {
		if rule.Kind == kind && rule.Pattern == pattern {
			before, allowAll := s.changeSnapshot()
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			s.mu.Unlock()
			s.notify(ScopeChange{Before: before, After: before - 1, AllowAllBefore: allowAll,
				AllowAllAfter: allowAll, Operation: "remove"})
			return true
		}
	}
	s.mu.Unlock()
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

	for i, rule := range s.rules {
		if rule.Kind != kind || rule.Pattern != pattern {
			continue
		}
		if !eqStrPtr(rule.PathPrefix, pathPrefix) || !eqPortPtr(rule.Port, port) {
			continue
		}
		before, allowAll := s.changeSnapshot()
		s.rules = append(s.rules[:i], s.rules[i+1:]...)
		s.mu.Unlock()
		s.notify(ScopeChange{Before: before, After: before - 1, AllowAllBefore: allowAll,
			AllowAllAfter: allowAll, Operation: "remove"})
		return true
	}
	s.mu.Unlock()
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

	for _, rule := range s.rules {
		if rule.Kind != kind || rule.Pattern != pattern {
			continue
		}
		if !eqStrPtr(rule.PathPrefix, pathPrefix) || !eqPortPtr(rule.Port, port) {
			continue
		}
		before, allowAll := s.changeSnapshot()
		if rule.Enabled == enabled {
			// Setting a rule to the value it already holds changes no answer, so it is not a change
			// and must not wake a subscriber — a handler woken by this re-reads its whole cache for a
			// decision nobody made. Refused-or-accepted is deliberately NOT the question here: the
			// caller gets true (the rule was found and is in the requested state, which it now
			// demonstrably is), and only the notification is suppressed.
			s.mu.Unlock()
			return true
		}
		rule.Enabled = enabled
		s.mu.Unlock()
		// The counts are IDENTICAL either side of a toggle, so ScopeChange.Changed() is false for
		// this one on its own — which is correct for a subscriber deciding "is my cached view still
		// valid" and useless for one that just wants to know something happened. Hence the operation
		// name on the record, and hence this notification firing unconditionally rather than through
		// the Changed() filter.
		s.notifyUnconditional(ScopeChange{Before: before, After: before, AllowAllBefore: allowAll,
			AllowAllAfter: allowAll, Operation: "enable"})
		return true
	}
	s.mu.Unlock()
	return false
}

// ReplaceScoped swaps the rule at a kind/pattern/path/port tuple for a new rule, in place —
// the edit primitive behind Burp's "Edit the selected item" button (k5l). It reports whether a
// rule was found and replaced; false means the caller named a rule that is not there, which the
// endpoint turns into a 404 rather than silently appending.
//
// The old tuple (kind included) is the identity, exactly RemoveScoped's: two rules on one host
// differing only in path or port are the ordinary case, and an identity that dropped any arm
// would let an edit replace a sibling. The replacement takes the old rule's list position, so an
// edit never reorders the document the way remove-then-add does — reordering a scope is a
// semantic change (first-match expectations, persistence layout), not a side effect an edit
// should have. Enabled comes from the new rule, because retyping arms and flipping enabled are
// two decisions; the toggle action owns the flag.
func (s *Scope) ReplaceScoped(kind ScopeRuleKind, pattern string, pathPrefix *string, port *uint16, protocol *string, replacement *ScopeRule) bool {
	if replacement == nil {
		return false
	}
	replacement.compileArms()
	s.mu.Lock()

	for i, rule := range s.rules {
		if rule.Kind != kind || rule.Pattern != pattern {
			continue
		}
		if !eqStrPtr(rule.PathPrefix, pathPrefix) || !eqPortPtr(rule.Port, port) || !eqStrPtr(rule.Protocol, protocol) {
			continue
		}
		before, allowAll := s.changeSnapshot()
		s.rules[i] = replacement
		s.mu.Unlock()
		// An edit is not a count change either — one rule in, one rule out — so it takes the
		// unconditional path for the same reason the toggle does.
		s.notifyUnconditional(ScopeChange{Before: before, After: before, AllowAllBefore: allowAll,
			AllowAllAfter: allowAll, Operation: "replace"})
		return true
	}
	s.mu.Unlock()
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
	before, allowAll := s.changeSnapshot()
	s.rules = s.rules[:0]
	s.mu.Unlock()
	// Fired even when the scope was already empty, for the same reason the toggle is: "clear all"
	// is an operator decision that a subscriber may want to react to (a crawler frontier that drops
	// everything it had queued), and a no-op clear is a statement the operator made.
	s.notifyUnconditional(ScopeChange{Before: before, After: 0, AllowAllBefore: allowAll,
		AllowAllAfter: allowAll, Operation: "clear"})
}

// Validate returns the first rule whose arms cannot be interpreted, naming which rule and why, or
// nil when every rule can be. It is the checkable form of the invariant the scope decisions rely on:
// they refuse everything while it is broken, so an operator needs one call that says which rule to
// fix rather than a proxy that has gone quiet.
//
// Every endpoint refuses an uninterpretable rule before storing it (NewScopeRuleFrom), so a scope
// only fails this after a store was written by hand, edited outside the tool, or produced by a build
// that did not know an arm — which is exactly when the operator needs to be told the offender.
func (s *Scope) Validate() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := s.faultLocked()
	return err
}

// faultLocked finds the first uninterpretable rule. Callers hold at least the read lock.
func (s *Scope) faultLocked() (int, error) {
	for i, rule := range s.rules {
		if err := rule.ArmFault(); err != nil {
			kind := "include"
			if rule.Kind == ScopeExclude {
				kind = "exclude"
			}
			return i, fmt.Errorf("scope rule %d (%s %q) cannot be interpreted: %w", i, kind, rule.Pattern, err)
		}
	}
	return -1, nil
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

	// A scope holding a rule it cannot interpret contains nothing at all.
	//
	// The tempting alternative — skip the broken rule and evaluate the rest — is fail-open by
	// arithmetic: if the unreadable rule is an *exclude*, skipping it hands back "in scope" for
	// precisely the requests the operator wrote that rule to keep out, and nothing in the answer
	// says a rule was dropped. Answering "in scope: no" to everything is loud, is recoverable
	// (Validate names the offending rule, and Explain says so to the operator), and cannot authorise
	// a single request the document did not authorise. It is unreachable through the endpoints,
	// which refuse such a rule before it is stored.
	//
	// It is "authorises nothing and retains nothing", not "refuses every request": pass-through proxy
	// traffic still goes out while the drop switch is off, because AuthoriseRequest forwards whatever
	// Contains refuses in that configuration — the same as for any out-of-scope request, and the
	// whole content of that setting. What stops is every gate that reads Contains: retention,
	// AuthoriseRaw, and the tools that ask before they send.
	if _, err := s.faultLocked(); err != nil {
		return false
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
//
// With a custom drop scope (47ed) and the switch on, the custom scope alone decides: it is the fence
// the operator chose for egress, and a request the suite scope would keep but the custom scope
// leaves out is dropped.
func (s *Scope) AuthoriseRequest(host string, port uint16, path string, isTLS bool) bool {
	if custom := s.activeDropScope(); custom != nil && s.DropOutOfScope() {
		return custom.Contains(host, port, path, isTLS)
	}
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
	// The same refusal Contains makes, for the same reason: the pre-filter must not be the one gate
	// that keeps saying yes while the scope document is unreadable — Repeater and Intruder apply it
	// and nothing else to their target.
	if _, err := s.faultLocked(); err != nil {
		return false
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
	// Named before anything else, because this refusal has a different cause and a different fix
	// from every other one: reporting "matches no include rule" while the real reason is a rule that
	// does not compile sends the operator to edit the wrong thing.
	if _, err := s.faultLocked(); err != nil {
		return "refused: " + where + " — the scope cannot be applied: " + err.Error()
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
	// A custom drop scope (47ed) is a second fence on top of the suite scope for a composed request:
	// in suite scope is required either way, and with the drop switch on the custom scope must agree.
	if custom := s.activeDropScope(); custom != nil && s.DropOutOfScope() && !custom.Contains(host, port, path, isTLS) {
		return errors.New("dropped: out-of-scope request handling uses a custom scope; " +
			custom.Explain(host, port, path, isTLS))
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
