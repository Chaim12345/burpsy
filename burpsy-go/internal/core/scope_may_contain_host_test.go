package core

import "testing"

// MayContainHost is the only scope gate /api/repeater/send and /api/intruder/run apply to the
// target they were handed, so its include semantics decide whether those tools can send outside
// the include list (burpsy-react-ui-cj7x). It used to start from "possible" and let only a
// whole-host exclude say no, which meant a host named by no include rule was waved through while
// Contains and AuthoriseRaw refused it.
//
// The expectations below are written against Contains' semantics deliberately: the recorded
// decision is that the two must agree about the include list, and disagreement is the bug.

// The exact probe from the issue report: only elsewhere.invalid included, asking about localhost.
func TestMayContainHostRefusesAHostMatchingNoIncludeRule(t *testing.T) {
	s := NewScope()
	s.AddInclude("elsewhere.invalid")

	if s.MayContainHost("127.0.0.1", 8080, false) {
		t.Error("MayContainHost allowed a host that matches no include rule; Repeater and Intruder " +
			"apply this gate and nothing else to their target, so this is traffic leaving the " +
			"engagement's include list")
	}
	// The agreement that makes the fix meaningful: the coarse gate and the real one now say the
	// same thing about this host.
	if s.Contains("127.0.0.1", 8080, "/x", false) {
		t.Error("Contains allowed it too; the fixture no longer reproduces the bug it is pinning")
	}
	if !s.MayContainHost("elsewhere.invalid", 443, true) {
		t.Error("the included host was refused, which would block authorised work")
	}
}

// The other half of the recorded decision: a scope nobody has narrowed must not stop work.
func TestAnEmptyIncludeListStillMeansEverything(t *testing.T) {
	s := NewScope()
	if !s.MayContainHost("anything.test", 80, false) {
		t.Error("an empty scope refused a host; default-allow is the documented behaviour and " +
			"Contains agrees, so this would break every tool on a fresh project")
	}
	// Excludes alone keep default-allow for everything they do not name.
	s.AddExclude("blocked.test")
	if !s.MayContainHost("other.test", 80, false) {
		t.Error("an exclude-only scope refused an unrelated host")
	}
	if s.MayContainHost("blocked.test", 80, false) {
		t.Error("a whole-host exclude did not put the host beyond reach")
	}
}

// The permissiveness that is deliberate and must survive the fix: this is a host-level pre-filter,
// so path-scoped rules must not remove a host. Both directions matter, and the doc comment gives
// the reason for each.
func TestPathScopedRulesStillDoNotRemoveTheHost(t *testing.T) {
	t.Run("a path-scoped include keeps its host", func(t *testing.T) {
		s := NewScope()
		rule := NewScopeRule(ScopeInclude, "api.test")
		rule.PathPrefix = strptr("/v1/")
		s.Add(rule)
		if !s.MayContainHost("api.test", 443, true) {
			t.Error("a path-scoped include lost its host: the /v1/ paths an attack invents are " +
				"authorised, which is the whole reason this gate does not ask about one path")
		}
	})

	t.Run("a path-scoped exclude leaves the rest of the host reachable", func(t *testing.T) {
		s := NewScope()
		s.AddInclude("app.test")
		rule := NewScopeRule(ScopeExclude, "app.test")
		rule.PathPrefix = strptr("/admin")
		s.Add(rule)
		if !s.MayContainHost("app.test", 443, true) {
			t.Error("a path-scoped exclude removed the whole host; it removes requests, and the " +
				"per-request gate is AuthoriseRaw")
		}
	})

	t.Run("a whole-host exclude still beats an include", func(t *testing.T) {
		s := NewScope()
		s.AddInclude("app.test")
		s.AddExclude("app.test")
		if s.MayContainHost("app.test", 443, true) {
			t.Error("an exclude lost to an include; excludes win in Contains and must win here")
		}
	})
}

func strptr(s string) *string { return &s }
