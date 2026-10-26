package web

// routeRiskFor must resolve {param} patterns the way the mux does (burpsy-react-ui-fxxm): one
// wildcard per segment, literals ahead of wildcards, no partial-segment or extra-segment matches.
// The confirmation gate and the MCP binding both resolve through it, so a miss there is a route
// the gate cannot see.

import "testing"

func TestRouteRiskForResolvesParamPatterns(t *testing.T) {
	cases := []struct {
		path, want string
	}{
		{"/api/message/5", "/api/message/{id}"},
		{"/api/tasks/12", "/api/tasks/{id}"},
		{"/api/tasks/12/cancel", "/api/tasks/{id}/cancel"},
		// The literal suite-wide pause beats the {id} wildcard, as the mux resolves it.
		{"/api/tasks/pause", "/api/tasks/pause"},
		{"/api/intercept/annotate/9", "/api/intercept/annotate/{id}"},
	}
	for _, tc := range cases {
		pattern, _, ok := routeRiskFor(tc.path)
		if !ok || pattern != tc.want {
			t.Errorf("routeRiskFor(%q) = %q, %v; want %q", tc.path, pattern, ok, tc.want)
		}
	}
}

func TestRouteRiskForRefusesParamShapeMisses(t *testing.T) {
	for _, path := range []string{
		"/api/message/",          // an empty wildcard segment is not a match
		"/api/message/5/extra",   // an extra segment is not a match
		"/api/tasks/12/cancel/x", // deeper than the action pattern
	} {
		pattern, _, ok := routeRiskFor(path)
		if ok && pattern == "/api/message/{id}" || ok && pattern == "/api/tasks/{id}/cancel" {
			t.Errorf("routeRiskFor(%q) wrongly resolved to %q", path, pattern)
		}
	}
}

// A trailing {name...} is the mux's remainder wildcard (fxxm): it resolves like the old subtree, for
// the empty remainder and nested paths too, and a literal route still beats it.
func TestRouteRiskForResolvesRemainderPatterns(t *testing.T) {
	cases := []struct {
		path, want string
	}{
		{"/api/report/json", "/api/report/{rest...}"},
		{"/api/report/finding/42", "/api/report/{rest...}"},
		{"/api/report/", "/api/report/{rest...}"},
		{"/api/datasets/history/3", "/api/datasets/{rest...}"},
		{"/api/sequencer/capture/stop", "/api/sequencer/capture/{rest...}"},
		{"/api/intruder/attacks/1/stop/extra", "/api/intruder/attacks/{id}/{action...}"},
		{"/api/skills/disabled", "/api/skills/disabled"},
		{"/api/engagement/clickbandit.js", "/api/engagement/clickbandit.js"},
	}
	for _, tc := range cases {
		pattern, _, ok := routeRiskFor(tc.path)
		if !ok || pattern != tc.want {
			t.Errorf("routeRiskFor(%q) = %q, %v; want %q", tc.path, pattern, ok, tc.want)
		}
	}
}
