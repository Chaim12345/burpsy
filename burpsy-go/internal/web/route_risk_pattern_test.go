package web

// routeRiskFor must resolve {param} patterns the way the mux does (burpsy-react-ui-fxxm): one
// wildcard per segment, literals ahead of wildcards, no partial-segment or extra-segment matches.
// The confirmation gate and the MCP binding both resolve through it, so a miss there is a route
// the gate cannot see.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

// fxxm batch 7: routeRiskFor against the production mux. For every path the manifest can generate
// and each verb, the manifest entry the mux itself matched must carry the risk class the gate
// resolves (mux fallthrough "/" and trailing-slash redirects excluded; double slashes are cleaned
// by the mux before routing). A pattern pair that tie on literal text must not exist.
func TestRouteRiskForAgreesWithTheProductionMux(t *testing.T) {
	s := newTestServer()
	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		if p != "" && !strings.Contains(p, "//") && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for p, r := range manifest {
		base := strings.TrimSuffix(p, "{$}")
		if strings.HasSuffix(p, "/") || strings.Contains(p, "{") {
			for _, sp := range []string{r.subPath, "x", "1", "x/y", "disabled", "x/", "confirm", "resolve"} {
				add(concretePath(p, sp))
			}
		}
		add(base)
		add(strings.TrimSuffix(base, "/"))
		for ap := range r.actionPaths {
			add(concretePath(p, ap))
		}
	}
	for _, path := range paths {
		for _, m := range []string{"GET", "POST", "DELETE"} {
			_, mp := s.mux.Handler(httptest.NewRequest(m, path, nil))
			if i := strings.Index(mp, " "); i >= 0 {
				mp = mp[i+1:]
			}
			mr, mok := manifest[mp]
			if mp == "" || mp == "/" {
				continue
			}
			if !mok {
				t.Errorf("%s %s: the mux matched %q, which has no manifest entry, so the gate cannot classify it", m, path, mp)
				continue
			}
			if strings.HasSuffix(mp, "/") && !strings.HasSuffix(path, "/") && !strings.Contains(mp, "{") {
				continue // the mux answered with a redirect to the subtree
			}
			_, risk, ok := routeRiskFor(path)
			if !ok || risk != mr.risk {
				t.Errorf("%s %s: mux matched %q (%s), routeRiskFor says %q ok=%v", m, path, mp, mr.risk, risk, ok)
			}
		}
	}
}

// The gate runs on the raw request path BEFORE the mux cleans it. A mutation on a confirmation-worthy
// route must therefore never execute through a path spelling the gate classifies differently from
// the mux: double slashes, dot segments and a missing trailing slash. For every such spelling the
// answer without a token must be a refusal (428), a redirect (the mux never runs the handler), or
// a 404/405; and a redirect, when followed with the same verb, must land on a 428.
//
// This pin covers STATUS only, across every gated route: a status is not proof that no handler ran.
// The side-effect proof is TestOddSpellingsOfHistoryRemovalRemoveNothingUnconfirmed (api_history_rows_test.go),
// which counts surviving history rows for one representative destructive route.
func TestCanonicalisedSpellingsOfGatedRoutesNeverExecuteUnconfirmed(t *testing.T) {
	s := newTestServer()
	checked := 0
	for p, r := range manifest {
		if !needsConfirmation(r.risk) {
			continue
		}
		base := concretePath(p, "1")
		if strings.HasSuffix(p, "/{$}") {
			base = strings.TrimSuffix(p, "{$}")
		}
		if base == "" || !strings.HasPrefix(base, "/api/") {
			continue
		}
		spellings := []string{
			strings.Replace(base, "/api/", "/api//", 1),
			strings.Replace(base, "/api/", "/api/./", 1),
			strings.Replace(base, "/api/", "/api/x/../", 1),
			strings.TrimSuffix(base, "/"),
			base + "/",
		}
		for _, sp := range spellings {
			if sp == "" || sp == base {
				continue
			}
			for _, m := range []string{"POST", "PUT", "DELETE"} {
				rec := httptest.NewRecorder()
				s.guarded.ServeHTTP(rec, sameOriginRequest(m, sp))
				checked++
				switch {
				case rec.Code == 428 || rec.Code == 404 || rec.Code == 405:
				case rec.Code >= 300 && rec.Code < 400:
					loc := rec.Header().Get("Location")
					if loc == "" {
						t.Errorf("%s %s: redirect %d with no Location", m, sp, rec.Code)
						continue
					}
					rec2 := httptest.NewRecorder()
					s.guarded.ServeHTTP(rec2, sameOriginRequest(m, loc))
					if rec2.Code >= 200 && rec2.Code < 300 {
						t.Errorf("%s %s -> %s: a redirect target executed unconfirmed (%d)", m, sp, loc, rec2.Code)
					}
				default:
					t.Errorf("%s %s (spelling of gated %q, %s): unconfirmed answer %d, want 428/redirect/404/405", m, sp, p, r.risk, rec.Code)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no gated spelling was exercised")
	}
}

func sameOriginRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	return req
}
