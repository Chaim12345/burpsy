package web

// The scope-library review step (burpsy-react-ui-e365 review binding).
//
// A library call names only a library; what it DOES depends on stored content
// and live state that can move between the review and the run. So the confirm
// step binds content: digests of the stored document and the live rule list
// are computed from server state at mint time, written into the minted call
// body, and re-checked by the API inside the owning lock or transaction at run
// time. The sheet below renders exactly the lists those digests name — the
// incoming stored rules, the current rules a load would discard, or the list a
// save photographs — so the operator reviews content, and any drift after the
// review is a 409 naming which side moved, never a silent apply.

import (
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
)

// ui2ScopeLibraryReview fills the confirm model for one library action and writes the
// server-computed content digests into the payload being minted. It returns "" on success
// or the refusal text the sheet shows as "Not applied".
func (s *Server) ui2ScopeLibraryReview(scopeAction string, payload map[string]any, model map[string]any) string {
	if s.persist == nil {
		// The same condition updateScopeLibrary answers 503 for, caught at the review step
		// rather than after a misleading mint.
		return "No project database is open, so scope libraries cannot be saved or loaded"
	}
	name, _ := payload["name"].(string)
	model["lib_action"] = strings.TrimPrefix(scopeAction, "library-")

	switch scopeAction {
	case "library-save":
		// Bind the live list being photographed, and the current stored state of the name
		// (its content, or its absence) so a save that landed since the review is never
		// silently overwritten.
		live := s.scope.Rules()
		payload["expected_rules"] = core.ScopeRulesDigest(live)
		_, existingDigest, found, err := s.persist.LoadScopeLibraryWithDigest(name)
		if err != nil {
			return err.Error()
		}
		if found {
			payload["expected_library"] = existingDigest
			model["lib_replaces"] = true
		} else {
			payload["expected_library"] = persist.ScopeLibraryAbsent
		}
		model["lib_rules"] = ui2ScopeDisplayRules(live)

	case "library-load":
		stored, digest, found, err := s.persist.LoadScopeLibraryWithDigest(name)
		if err != nil {
			return err.Error()
		}
		if !found {
			return fmt.Sprintf("No scope library called %q; %s", name, s.scopeLibraryNamesInStore())
		}
		payload["expected_library"] = digest
		// Bind the live list being replaced: a rule added between the review and the run is
		// never silently discarded.
		live := s.scope.Rules()
		payload["expected_rules"] = core.ScopeRulesDigest(live)
		model["lib_rules"] = ui2ScopeDisplayStoredRules(stored)
		model["lib_discarded"] = ui2ScopeDisplayRules(live)
		model["lib_policy"] = ui2ScopeLibraryPolicyLine(stored)

	case "library-delete":
		stored, digest, found, err := s.persist.LoadScopeLibraryWithDigest(name)
		if err != nil {
			return err.Error()
		}
		if !found {
			return fmt.Sprintf("No scope library called %q; %s", name, s.scopeLibraryNamesInStore())
		}
		payload["expected_library"] = digest
		model["lib_rules"] = ui2ScopeDisplayStoredRules(stored)
	}
	if v, ok := payload["expected_library"].(string); ok {
		model["expected_library"] = v
	}
	if v, ok := payload["expected_rules"].(string); ok {
		model["expected_rules"] = v
	}
	return ""
}

// ui2ScopeLibraryPolicyLine states what scope decisions will follow from loading a stored
// list, computed from the list itself — the four cases that decide whether a load widens
// or narrows, in the words the review sheet carries:
//
//   - no rules at all: an empty scope allows everything (default allow);
//   - excludes only: default allow except the ENABLED excludes (a disabled exclude is
//     visible but inert and must not be counted as active);
//   - include rules all disabled: nothing in scope (core deliberately does NOT fall back
//     to default-allow here — see the MayContainHost comment in core/scope.go);
//   - at least one enabled include: the enabled includes' matches, minus enabled excludes.
func ui2ScopeLibraryPolicyLine(rules []persist.ScopeLibraryRule) string {
	if len(rules) == 0 {
		return "This library holds no rules: loading it empties the scope, and an empty scope allows EVERYTHING (default allow)."
	}
	hasInclude, hasEnabledInclude, hasEnabledExclude := false, false, false
	for _, r := range rules {
		if strings.EqualFold(r.Kind, "include") {
			hasInclude = true
			if r.Enabled {
				hasEnabledInclude = true
			}
		} else if r.Enabled {
			hasEnabledExclude = true
		}
	}
	switch {
	case !hasInclude && hasEnabledExclude:
		return "This library holds no include rules: EVERYTHING not named by the enabled excludes below will be in scope (default allow)."
	case !hasInclude:
		return "This library holds no include rules, and its excludes are disabled (visible but inert): EVERYTHING will be in scope (default allow)."
	case !hasEnabledInclude:
		return "Every include rule in this library is disabled: NOTHING will be in scope."
	case hasEnabledExclude:
		return "Only requests matching the enabled include rules below will be in scope, minus the enabled excludes."
	default:
		return "Only requests matching the enabled include rules below will be in scope; the excludes are disabled (visible but inert)."
	}
}

// ui2ScopeDisplayRules projects live rules into the rows the review sheet renders, in
// served order. Host patterns and path prefixes are free text an operator can paste a
// credential into, so they go through the URL-carrier mask the session-rule review uses:
// userinfo, secret-named query values and fragment pairs show as the redaction marker and
// everything else shows exactly as stored.
func ui2ScopeDisplayRules(rules []*core.ScopeRule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, ui2ScopeDisplayRow(scopeRuleKindNameForDisplay(r.Kind), r.Pattern, r.PathPrefix, r.Port, r.Protocol, r.Enabled))
	}
	return out
}

// ui2ScopeDisplayStoredRules is ui2ScopeDisplayRules for a stored library document.
func ui2ScopeDisplayStoredRules(rules []persist.ScopeLibraryRule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		out = append(out, ui2ScopeDisplayRow(r.Kind, r.Pattern, r.PathPrefix, r.Port, r.Protocol, r.Enabled))
	}
	return out
}

func scopeRuleKindNameForDisplay(k core.ScopeRuleKind) string {
	if k == core.ScopeExclude {
		return "exclude"
	}
	return "include"
}

func ui2ScopeDisplayRow(kind, pattern string, path *string, port *uint16, protocol *string, enabled bool) map[string]any {
	row := map[string]any{
		"kind":    kind,
		"host":    ui2SessionRuleSanitizeURL(pattern),
		"enabled": enabled,
	}
	if path != nil {
		row["path"] = ui2SessionRuleSanitizeURL(*path)
	}
	if port != nil {
		row["port"] = fmt.Sprintf("%d", *port)
	}
	if protocol != nil {
		row["protocol"] = *protocol
	}
	return row
}
