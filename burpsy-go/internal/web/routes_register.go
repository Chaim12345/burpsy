package web

import (
	"net/http"
	"strings"
)

// routeVerbs is the verb universe s.route registers for every route: each declared
// verb gets the handler, each undeclared one gets the 405 fallback. CONNECT is
// deliberately absent — ServeMux treats CONNECT patterns as proxy-form authority
// matching, which has nothing to do with these routes; a CONNECT request falls to
// the UI catch-all, as it always has. The 405 sweep sweeps exactly this set minus
// OPTIONS (which it tolerates either way) plus HEAD (implied by GET in net/http).
var routeVerbs = []string{
	http.MethodGet, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace,
}

// route registers one path with Go 1.22 method-qualified patterns derived from the
// manifest's declared verbs: the handler serves the declared verbs, a 405 fallback
// serves every other verb in routeVerbs (burpsy-react-ui-vnlh).
//
// Two naive shapes do not work, and both failures are structural:
//
//   - Method pattern + NO fallback: a wrong verb falls through to the next matching
//     pattern — the UI catch-all ("/") — and comes back 404-from-the-SPA instead of
//     405 (probe-verified).
//   - Method pattern + a path-ONLY fallback: ServeMux refuses the table outright.
//     "/api/skills/disabled" (all verbs) overlaps "GET /api/skills/" (subtree, one
//     verb) and neither pattern is strictly more general, so registration panics.
//     Method-qualified patterns for DIFFERENT verbs never overlap, and same-verb
//     patterns resolve by path specificity — so a table built ONLY of
//     method-qualified patterns cannot hit the conflict rule.
//
// Methods come from the manifest rather than from another literal at the call site,
// so the route's verb set is declared exactly once. The 405 sweep
// (Test_every_route_rejects_a_verb_it_does_not_implement) is the check that the
// declaration matches what callers experience, and each migrated handler drops its
// hand-written verb guard, which is the drift class behind burpsy-react-ui-0gg5.
// Subtree routes register the same way ("GET /api/datasets/" etc.); the manifest's
// methods list for a subtree is the union over its action paths, which
// Test_every_route_rejects_a_verb_it_does_not_implement sweeps per action path.
//
// Migration is incremental: path-only mux.HandleFunc calls keep working beside this
// helper anywhere no s.route pattern reaches. The AST walk in
// route_manifest_test.go reads both shapes out of server.go.
func (s *Server) route(pattern string, h http.HandlerFunc) {
	spec, ok := manifest[pattern]
	if !ok {
		// Panic at startup, not 404 at request time: a route with no manifest entry
		// has no risk class, and the confirmation gate cannot see it.
		panic("web: route " + pattern + " has no manifest entry")
	}
	declared := make(map[string]bool, len(spec.methods))
	for _, method := range spec.methods {
		declared[method] = true
		s.mux.HandleFunc(method+" "+pattern, h)
	}
	for _, method := range routeVerbs {
		if declared[method] {
			continue
		}
		s.mux.HandleFunc(method+" "+pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", allowFor(spec, pattern, r.URL.Path))
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}))
	}
}

// allowFor renders the fallback's Allow header: the manifest's declared verbs, or —
// under a subtree with named action paths — the one action's verbs when the request
// lands on it. An operator told "POST" for /api/session/rules/1/move learns what the
// action accepts; the union of the whole subtree would send them retrying verbs the
// action never had (the contract TestSessionRuleMoveRejectsOtherMethods pins).
func allowFor(spec route, pattern, urlPath string) string {
	if len(spec.actionPaths) > 0 {
		suffix := strings.TrimPrefix(urlPath, pattern)
		if verbs, ok := spec.actionPaths[suffix]; ok {
			return strings.Join(verbs, ", ")
		}
	}
	return strings.Join(spec.methods, ", ")
}
