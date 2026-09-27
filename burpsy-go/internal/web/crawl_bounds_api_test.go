package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/crawler"
)

// burpsy-react-ui-qzzy: internal/crawler/limits.go defines 11 bounds and 12 named stops, but only
// three were settable over the wire. Four of the twelve stops could therefore only be reached by a Go
// test or by a default — the honest stopping vocabulary existed and an operator could not use most of
// it, and a bound that fires with no control behind it is indistinguishable from a bug.
//
// Two defects, and the second is the one that would have survived a naive fix:
//
//  1. four bounds had no wire field at all;
//  2. every bound was applied with `if n > 0`, so a bound of 0 meant "unset" and silently ran the
//     DEFAULT. Zero is a real answer for all eleven — zero locations, zero links per page, zero
//     re-logins — and reading it as "unset" means an operator who asked for a bounded-nothing crawl
//     gets five hundred requests and a report naming a stop they never chose.

// A bound the operator sets reaches the crawler, including the four that had no field before.
//
// Read off the crawler's OWN Limits rather than off the run record, because the run's Report is only
// filled in once the crawl finishes and a crawl of an unreachable seed never does. What the
// per-request bound function produced IS the question, and it is the one place a silently-dropped
// field cannot survive.
func TestTheBoundsTheCrawlerHasAndTheWireDidNotAreNowSettable(t *testing.T) {
	for _, tc := range []struct {
		field string
		value int
		read  func(crawlLimitsView) int
	}{
		{"max_locations", 7, func(v crawlLimitsView) int { return v.MaxLocations }},
		{"max_frontier", 11, func(v crawlLimitsView) int { return v.MaxFrontier }},
		{"max_links_per_page", 13, func(v crawlLimitsView) int { return v.MaxLinksPerPage }},
		{"max_template_visits", 17, func(v crawlLimitsView) int { return v.MaxTemplateVisits }},
		{"max_capture_bytes", 4096, func(v crawlLimitsView) int { return v.MaxCaptureBytes }},
		{"max_parse_bytes", 2048, func(v crawlLimitsView) int { return v.MaxParseBytes }},
		{"max_fingerprints", 19, func(v crawlLimitsView) int { return v.MaxFingerprints }},
		{"max_relogins", 23, func(v crawlLimitsView) int { return v.MaxRelogins }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			s := newTestServer()
			got := boundsFromRequest(t, s, map[string]any{
				"seeds": []string{"http://127.0.0.1:1/"}, tc.field: tc.value,
			})
			if v := tc.read(got); v != tc.value {
				def := newCrawlLimitsView(crawler.DefaultLimits())
				t.Errorf("%s = %d on the run's published bounds, want %d; the bound was accepted and "+
					"not applied, so the crawl ran at the default %d and any stop it reported named a "+
					"bound the operator never chose", tc.field, v, tc.value, tc.read(*def))
			}
		})
	}
}

// A bound of 0 is the operator's answer, not a synonym for "unset". This is the test the
// `if n > 0` implementation fails, and it is the reason the eight fields are pointers.
func TestABoundOfZeroIsTheOperatorsAnswerNotTheDefault(t *testing.T) {
	s := newTestServer()
	got := boundsFromRequest(t, s, map[string]any{
		"seeds": []string{"http://127.0.0.1:1/"}, "max_requests": 1, "max_locations": 0,
	})
	if got.MaxLocations != 0 {
		t.Errorf("max_locations = %d on the crawler's bounds, want 0; a zero bound was read as unset "+
			"and the crawl ran with the default %d, so the report would name a location budget nobody "+
			"asked for", got.MaxLocations, crawler.DefaultLimits().MaxLocations)
	}
	// And the three pre-existing bounds keep their documented 0-means-default rule, so nothing that
	// already worked changed shape.
	if got.MaxDepth == 0 {
		t.Error("max_depth = 0 on a request that did not set it; the three legacy fields must keep " +
			"their 0-means-default reading so every existing caller is unaffected")
	}
}

// A negative bound is refused, not clamped. Clamping to the default is the worst of the available
// answers: the crawl runs, stops on the default, and reports a stop the operator never chose.
func TestANegativeBoundIsRefusedRatherThanClampedToTheDefault(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds": []string{"http://127.0.0.1:1/"}, "max_locations": -1,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a negative bound returned %d, want 400; a clamp would run a crawl and report a "+
			"stop nobody chose", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "max_locations") {
		t.Errorf("the refusal does not name the field: %q", rec.Body.String())
	}
	// And no task row was created: a refused configuration must leave nothing behind for a dashboard
	// to show, which is the same rule the login-page-pattern refusal follows.
	if n := countCrawls(t, s); n != 0 {
		t.Errorf("%d crawl run(s) retained after a refused request; a 400 must leave no task row", n)
	}
}

// A request naming several bad bounds is answered with all of them, not one per attempt.
func TestEveryBadBoundIsNamedInOneRefusal(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":            []string{"http://127.0.0.1:1/"},
		"max_locations":    -1,
		"max_relogins":     -5,
		"max_depth":        -2,
		"max_fingerprints": -1,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"max_locations", "max_relogins", "max_depth", "max_fingerprints"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal omits %s: %q", want, body)
		}
	}
}

// Zero is not refused, and neither is an omitted field: the default path is untouched.
func TestAZeroOrOmittedBoundIsNotRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"zero on every optional bound", map[string]any{
			"seeds":         []string{"http://127.0.0.1:1/"},
			"max_locations": 0, "max_frontier": 0, "max_links_per_page": 0,
			"max_parse_bytes": 0, "max_template_visits": 0, "max_capture_bytes": 0,
			"max_fingerprints": 0, "max_relogins": 0,
		}},
		{"nothing set at all", map[string]any{"seeds": []string{"http://127.0.0.1:1/"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer()
			rec := postJSON(t, s, "/api/crawl", tc.body)
			if rec.Code == http.StatusBadRequest {
				t.Errorf("a zero or omitted bound was refused: %s", rec.Body.String())
			}
		})
	}
}

// boundsFromRequest POSTs a crawl start and returns the effective bounds the run publishes.
//
// Read through GET /api/crawl?task=N rather than off the Server's internals, so the test observes the
// same view an operator does: a bound that is applied but not published is applied only in the sense
// that nothing contradicts it, which is the shape of the original defect.
//
// The seed is unreachable on purpose — the crawl is not being observed for what it finds, only for
// what it was configured with.
func boundsFromRequest(t *testing.T, s *Server, body map[string]any) crawlLimitsView {
	t.Helper()
	rec := postJSON(t, s, "/api/crawl", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("crawl start = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		TaskID uint64 `json:"task_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start reply: %v (%s)", err, rec.Body.String())
	}
	view := getCrawlRun(t, s, out.TaskID)
	if view.Limits == nil {
		t.Fatalf("crawl %d publishes no bounds; an operator asking what bounded a running crawl has "+
			"no answer, and a bound that fires with no control behind it is indistinguishable from "+
			"a bug", out.TaskID)
	}
	return *view.Limits
}

// getCrawlRun reads one crawl run through the API, the way a console does.
func getCrawlRun(t *testing.T, s *Server, id uint64) crawlRun {
	t.Helper()
	rec := getJSON(t, s, "/api/crawl?task="+strconv.FormatUint(id, 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/crawl?task=%d = %d: %s", id, rec.Code, rec.Body.String())
	}
	var out crawlRun
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode run: %v (%s)", err, rec.Body.String())
	}
	return out
}

// countCrawls reports how many crawl runs the server retains.
func countCrawls(t *testing.T, s *Server) int {
	t.Helper()
	return len(s.crawls.list())
}

// The run's bounds are published in the endpoint's own convention: snake_case, with the duration in
// seconds.
//
// Found by reading a live run rather than by a test, and it is exactly the kind of defect a test is
// for: `crawler.Limits` carries no json tags, so publishing it directly emitted "MaxLocations" and
// "MaxDuration": 300000000000 while every other field on the same endpoint was snake_case and
// seconds. The values were all correct and the console read every one of them as undefined.
func TestTheRunPublishesItsBoundsInTheEndpointsOwnConvention(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{"http://127.0.0.1:1/"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("crawl start = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		TaskID uint64 `json:"task_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start reply: %v", err)
	}

	// The RAW body, not the decoded view: the whole point is the key spelling on the wire, and a
	// decoder that accepts "MaxLocations" for a field typed "max_locations" would hide the mismatch
	// this is about.
	raw := getJSON(t, s, "/api/crawl?task="+strconv.FormatUint(out.TaskID, 10)).Body.String()
	if !strings.Contains(raw, `"max_locations"`) {
		t.Errorf("the run does not publish max_locations in snake_case: %s", raw)
	}
	if strings.Contains(raw, `"MaxLocations"`) {
		t.Errorf("the run publishes Go field names, which no other field on this endpoint uses: %s", raw)
	}
	// And the duration is seconds, not the engine's nanoseconds: 300000000000 is a number nobody
	// asked for and every console would render it as an overflow.
	if strings.Contains(raw, "300000000000") {
		t.Errorf("the run publishes a duration in nanoseconds: %s", raw)
	}
	if !strings.Contains(raw, `"max_duration_secs"`) {
		t.Errorf("the run does not name its duration bound: %s", raw)
	}
}
