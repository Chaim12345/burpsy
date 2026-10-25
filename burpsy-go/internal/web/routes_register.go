package web

import "net/http"

// route registers one path with Go 1.22 method-qualified patterns derived from the
// manifest, plus a path-only fallback that answers 405 to every verb the manifest
// does not declare (burpsy-react-ui-vnlh).
//
// The fallback is load-bearing, not redundant: a path-only catch-all ("/", the SPA)
// matches any method, and ServeMux prefers a matching less-specific pattern over a
// non-matching specific one, so without it a wrong verb falls THROUGH the
// method-qualified pattern to the catch-all and comes back 404-from-the-UI instead
// of 405. Verified by probe: DELETE /api/backup -> "/" -> 404 with no fallback.
//
// Methods come from the manifest rather than from another literal at the call site,
// so the route's verb set is declared exactly once. The 405 sweep
// (Test_every_route_rejects_a_verb_it_does_not_implement) is the check that the
// declaration matches what callers experience, and each migrated handler drops its
// hand-written verb guard, which is the drift class behind burpsy-react-ui-0gg5.
//
// Migration is incremental: path-only mux.HandleFunc calls keep working beside this
// helper. The AST walk in route_manifest_test.go reads both shapes out of server.go.
func (s *Server) route(pattern string, h http.HandlerFunc) {
	spec, ok := manifest[pattern]
	if !ok {
		// Panic at startup, not 404 at request time: a route with no manifest entry
		// has no risk class, and the confirmation gate cannot see it.
		panic("web: route " + pattern + " has no manifest entry")
	}
	for _, method := range spec.methods {
		s.mux.HandleFunc(method+" "+pattern, h)
	}
	s.mux.HandleFunc(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allowHeader(spec.methods))
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}))
}

// allowHeader renders the Allow header for the 405 fallback. GET implies HEAD, as
// net/http serves HEAD through a GET pattern.
func allowHeader(methods []string) string {
	out := ""
	for _, m := range methods {
		if out != "" {
			out += ", "
		}
		out += m
		if m == http.MethodGet {
			out += ", HEAD"
		}
	}
	return out
}
