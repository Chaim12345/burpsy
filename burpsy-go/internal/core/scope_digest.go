package core

// Canonical scope-rule documents, their content digest, and the digest-checked
// whole-list operations the confirmed scope-library calls run on.
//
// A scope library review binds content, not a name: the operator reviews a
// rendered list, and the call that runs must apply exactly that list or refuse.
// The digest below is what "exactly that list" means: every field a scope
// decision reads (kind, pattern, the path/port/protocol arms, the enabled flag)
// in a fixed field order, in the served list order, so a reorder, a toggle or
// an arm change is a different digest. persist.ScopeLibraryRule carries the
// same field set for storage; the two shapes are kept in lockstep on purpose,
// and the digest is defined over this document so the web layer (minting the
// review) and core (enforcing it under the lock) compute the same bytes without
// core importing its own storage layer.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ScopeRuleDoc is the canonical serialized form of one scope rule. Enabled is
// written always, never omitempty: a disabled rule must hash as disabled, and
// an omitted-then-defaulted field would let "enabled" and "missing" collide.
type ScopeRuleDoc struct {
	Kind       string  `json:"kind"`
	Pattern    string  `json:"pattern"`
	Port       *uint16 `json:"port,omitempty"`
	PathPrefix *string `json:"path_prefix,omitempty"`
	Protocol   *string `json:"protocol,omitempty"`
	Enabled    bool    `json:"enabled"`
}

func scopeRuleKindName(k ScopeRuleKind) string {
	if k == ScopeExclude {
		return "exclude"
	}
	return "include"
}

// scopeRuleDocs projects live rules into their canonical documents, skipping
// nils the way Add does. The order is the served order: it is part of the
// content an operator reviews, so it is part of the digest.
func scopeRuleDocs(rules []*ScopeRule) []ScopeRuleDoc {
	out := make([]ScopeRuleDoc, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, ScopeRuleDoc{
			Kind:       scopeRuleKindName(r.Kind),
			Pattern:    r.Pattern,
			Port:       r.Port,
			PathPrefix: r.PathPrefix,
			Protocol:   r.Protocol,
			Enabled:    r.Enabled,
		})
	}
	return out
}

// ScopeRulesCanonical is the canonical byte form of a rule list: the JSON of
// its documents, fixed field order, nil list marshalling as "[]" so "empty"
// has one digest, not two.
func ScopeRulesCanonical(rules []*ScopeRule) []byte {
	body, _ := json.Marshal(scopeRuleDocs(rules))
	return body
}

// ScopeRulesDigest is the content identity a library review binds: sha256 of
// the canonical bytes. Any change a scope decision could observe — a rule
// added, removed, reordered, toggled or re-armed — is a different digest.
func ScopeRulesDigest(rules []*ScopeRule) string {
	sum := sha256.Sum256(ScopeRulesCanonical(rules))
	return hex.EncodeToString(sum[:])
}

// ReplaceRulesIfUnchanged swaps the whole rule list for rules, but only when
// the list still hashes to expectedDigest; it reports whether the swap
// happened. The compare and the swap run under the one write lock, so a
// concurrent edit cannot land between them (the check-then-act gap a
// digest-then-Clear-then-Add sequence would leave). A refused swap changes
// nothing and notifies nobody.
//
// A successful swap fires exactly ONE change event, after the unlock, and
// unconditionally: a replace can swap equal-count lists — a different scope
// with the same size — which a count-difference filter would drop, and it can
// replace a list with an identical one, which is still an operator decision a
// subscriber may react to (see Clear). Persisting the new list is the caller's
// job, after this returns: no storage runs inside this lock.
func (s *Scope) ReplaceRulesIfUnchanged(expectedDigest string, rules []*ScopeRule) bool {
	clean := make([]*ScopeRule, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		// Compile at the door, before the lock: the same discipline as Add, so a
		// rule built by a path that skipped a constructor still carries its arms.
		rule.compileArms()
		clean = append(clean, rule)
	}
	s.mu.Lock()
	if ScopeRulesDigest(s.rules) != expectedDigest {
		s.mu.Unlock()
		return false
	}
	before, allowAll := s.changeSnapshot()
	s.rules = clean
	s.mu.Unlock()
	s.notifyUnconditional(ScopeChange{Before: before, After: len(clean), AllowAllBefore: allowAll,
		AllowAllAfter: allowAll, Operation: "replace"})
	return true
}

// SnapshotIfUnchanged returns a copy of the current rule list when it still
// hashes to expectedDigest, and (nil, false) when it does not. The compare and
// the copy run under the one read lock, and the copies are VALUE copies: a
// toggle landing after the snapshot must not rewrite the document the operator
// reviewed and the digest bound.
func (s *Scope) SnapshotIfUnchanged(expectedDigest string) ([]*ScopeRule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ScopeRulesDigest(s.rules) != expectedDigest {
		return nil, false
	}
	out := make([]*ScopeRule, 0, len(s.rules))
	for _, r := range s.rules {
		if r == nil {
			continue
		}
		cp := *r
		out = append(out, &cp)
	}
	return out, true
}
