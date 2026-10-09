package core

// Decide answers the same question Contains answers — would this request be retained as in scope —
// and also says WHY: which rule decided it, or that no rule did (burpsy-react-ui-z5z3).
//
// It exists because Contains returns a bare bool, and every caller that wanted to tell an operator or
// an agent "this URL is in scope because include rule X matched" had to re-implement the matcher.
// A second implementation of the include/exclude walk is the drift this package exists to prevent, so
// Decide walks the rules in exactly Contains' order with exactly Contains' predicates, and
// TestDecideAgreesWithContains holds the two to the same answer over a grid of rule sets, hosts,
// ports, paths and schemes.

// Reasons a ScopeDecision can carry.
const (
	ScopeReasonAllowAll       = "allow_all"        // the scope allows everything
	ScopeReasonFault          = "fault"            // a rule cannot be interpreted, so nothing is in scope
	ScopeReasonExcluded       = "excluded"         // an exclude rule matched; excludes win
	ScopeReasonIncluded       = "included"         // an include rule matched
	ScopeReasonNoIncludeRules = "no_include_rules" // no include rules exist: default allow
	ScopeReasonNoIncludeMatch = "no_include_match" // include rules exist and none matched
)

// ScopeRuleRef identifies one rule by the tuple the scope API uses, copied out from under the lock.
type ScopeRuleRef struct {
	Kind       string  `json:"kind"`
	Pattern    string  `json:"pattern"`
	PathPrefix *string `json:"path,omitempty"`
	Port       *uint16 `json:"port,omitempty"`
	Protocol   *string `json:"protocol,omitempty"`
	Enabled    bool    `json:"enabled"`
}

// ScopeDecision is Decide's answer.
type ScopeDecision struct {
	InScope bool
	Reason  string
	// Rule is the rule that decided, for ScopeReasonExcluded and ScopeReasonIncluded; nil otherwise.
	Rule *ScopeRuleRef
	// Fault is the uninterpretable rule's error, for ScopeReasonFault.
	Fault string
}

func refOf(r *ScopeRule) *ScopeRuleRef {
	kind := "include"
	if r.Kind == ScopeExclude {
		kind = "exclude"
	}
	ref := &ScopeRuleRef{Kind: kind, Pattern: r.Pattern, Enabled: r.Enabled}
	if r.PathPrefix != nil {
		p := *r.PathPrefix
		ref.PathPrefix = &p
	}
	if r.Port != nil {
		p := *r.Port
		ref.Port = &p
	}
	if r.Protocol != nil {
		p := *r.Protocol
		ref.Protocol = &p
	}
	return ref
}

// Decide is Contains with its reasoning. Keep the two walks identical.
func (s *Scope) Decide(host string, port uint16, path string, isTLS bool) ScopeDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.allowAll {
		return ScopeDecision{InScope: true, Reason: ScopeReasonAllowAll}
	}
	if _, err := s.faultLocked(); err != nil {
		return ScopeDecision{InScope: false, Reason: ScopeReasonFault, Fault: err.Error()}
	}
	for _, rule := range s.rules {
		if rule.Kind == ScopeExclude && rule.MatchesRequest(host, port, path, isTLS) {
			return ScopeDecision{InScope: false, Reason: ScopeReasonExcluded, Rule: refOf(rule)}
		}
	}
	hasIncludeRule := false
	for _, rule := range s.rules {
		if rule.Kind == ScopeInclude {
			hasIncludeRule = true
			if rule.MatchesRequest(host, port, path, isTLS) {
				return ScopeDecision{InScope: true, Reason: ScopeReasonIncluded, Rule: refOf(rule)}
			}
		}
	}
	if !hasIncludeRule {
		return ScopeDecision{InScope: true, Reason: ScopeReasonNoIncludeRules}
	}
	return ScopeDecision{InScope: false, Reason: ScopeReasonNoIncludeMatch}
}
