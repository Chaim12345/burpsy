package web

// The /api/tasks family as Go 1.22 patterns (burpsy-react-ui-fxxm, batch 2).
//
// Two contracts are pinned here:
//
//  1. The suite-wide pause/resume are LITERALS beside the {id} patterns. ServeMux resolves a
//     literal segment ahead of a wildcard, so POST /api/tasks/pause must reach the suite-wide
//     gate and never the {id} parse - and a wrong verb on the literal must 405 from the literal's
//     own fallback, not 404 from the {id} GET handler. Before the conversion a single subtree
//     handler switched on the path tail; the mux now owns the same answers.
//  2. Paths the patterns do not describe (unknown actions, deeper segments) fall through to the
//     catch-all 404, the same answer every other unregistered /api path gets. The old subtree
//     answered some of those with a 405 from whichever hand-written guard ran first; that drift
//     is deliberate - one unknown-path answer for the whole API.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestTasksSuiteWidePauseResumeAreLiterals(t *testing.T) {
	s := newTestServer()

	// The literal wins over any {id} reading: POST /api/tasks/pause pauses the suite, it does not
	// 404 on a task named "pause".
	rec := postJSON(t, s, "/api/tasks/pause", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/tasks/pause = %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["paused"] != true {
		t.Fatalf("pause body = %v %v", body, err)
	}
	rec = postJSON(t, s, "/api/tasks/resume", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/tasks/resume = %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["paused"] != false {
		t.Fatalf("resume body = %v %v", body, err)
	}

	// A wrong verb on the literal 405s from the literal's own fallback (Allow: POST) - the {id}
	// GET/DELETE patterns must not answer it with a parse-failure 404.
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		for _, path := range []string{"/api/tasks/pause", "/api/tasks/resume"} {
			rec := doReq(s, method, path, "")
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405 (the literal's fallback, not the {id} patterns)", method, path, rec.Code)
			}
			if allow := rec.Header().Get("Allow"); !strings.Contains(allow, http.MethodPost) {
				t.Errorf("%s %s Allow = %q, want POST named", method, path, allow)
			}
		}
	}
}

func TestTasksActionVerbsArePerPattern(t *testing.T) {
	s := newTestServer()

	// Each action pattern declares POST alone; every other verb 405s with Allow: POST - from the
	// mux now, not from a guard inside the handler.
	for _, action := range []string{"cancel", "again", "pause", "resume"} {
		rec := doReq(s, http.MethodGet, "/api/tasks/1/"+action, "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET /api/tasks/1/%s = %d, want 405", action, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
			t.Errorf("GET /api/tasks/1/%s Allow = %q, want POST", action, allow)
		}
	}

	// A bare POST on the row itself has no action; the 405 names the row's own verbs.
	rec := doReq(s, http.MethodPost, "/api/tasks/1", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/tasks/1 = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, DELETE" {
		t.Errorf("POST /api/tasks/1 Allow = %q, want \"GET, DELETE\"", allow)
	}

	// Malformed and unknown ids keep their 404s through the patterns.
	for _, path := range []string{"/api/tasks/soon/cancel", "/api/tasks/99999999/cancel"} {
		if rec := postJSON(t, s, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", path, rec.Code)
		}
	}
}

func TestTasksUnknownDeepPathsFallThroughTo404(t *testing.T) {
	s := newTestServer()

	// Paths no pattern describes take the catch-all 404 - one unknown-path answer for the whole
	// API. (The old subtree answered these 405 from whichever guard ran first; the drift is the
	// point of the conversion.)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/tasks/5/extra"},
		{http.MethodPost, "/api/tasks/5/frobnicate"},
		{http.MethodGet, "/api/tasks/5/6"},
	} {
		rec := doReq(s, tc.method, tc.path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want the catch-all 404", tc.method, tc.path, rec.Code)
		}
	}
}
