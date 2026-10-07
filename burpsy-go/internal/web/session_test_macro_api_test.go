package web

// POST /api/session/rules/{id}/test — Burp's "Test macro" (burpsy-react-ui-7zdm). These tests pin
// the wire contract: the dry-run reports each step's sent form, response and extraction outcomes;
// it refuses an unknown id; and — the property that separates a dry-run from a run — it writes
// nothing to the login-run memory, because an operator testing a macro is not logging in, and a
// test run that "update macro" could promote is a test with side effects on the rule itself.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionRuleTestMacroReportsStepsAndExtractions(t *testing.T) {
	srv := sessionTestServer()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":    "test me",
		"enabled": true,
		"scope":   map[string]any{"allow_all": true, "rules": []any{}},
		"steps": []any{
			map[string]any{"method": "GET", "url": srvSenderURL(t), "headers": []any{}, "body": ""},
		},
		"validity": map[string]any{"status_is": 200},
	}, &created)
	if code != http.StatusOK {
		t.Fatalf("POST rule = %d, want 200", code)
	}

	req := taskTestPOST(t, srv, "/api/session/rules/"+itoa(uint64(*created.Rule.ID))+"/test")
	if req.Code != http.StatusOK {
		t.Fatalf("POST /test = %d, want 200 (%s)", req.Code, req.Body.String())
	}
	var body struct {
		Status string `json:"status"`
		Steps  []struct {
			Index int `json:"index"`
			Sent  struct {
				URL string `json:"url"`
			} `json:"sent"`
			Response *struct {
				Status int `json:"status"`
			} `json:"response"`
			Skipped string `json:"skipped"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(req.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /test response: %v", err)
	}
	// The casing tripwire: encoding/json matches fields case-insensitively, so this struct would
	// silently decode a Go-untagged "Status" key — and TypeScript would then read undefined. The
	// wire must spell it lowercase.
	var raw map[string]any
	if err := json.Unmarshal(req.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	rawSteps, _ := raw["steps"].([]any)
	if len(rawSteps) == 0 {
		t.Fatalf("steps missing from the wire shape: %v", raw)
	}
	rawStep, _ := rawSteps[0].(map[string]any)
	// The status key lives on the response object; that is where StepResult's missing tags would
	// leak "Status" onto the wire.
	rawResponse, _ := rawStep["response"].(map[string]any)
	if rawResponse == nil {
		t.Fatalf("step wires %v: want a response object to case-check", rawStep)
	}
	if _, has := rawResponse["status"]; !has {
		t.Fatalf("response wires %v: it must carry the lowercase key \"status\"", rawResponse)
	}
	if _, has := rawResponse["Status"]; has {
		t.Fatalf("response wires a Go-untagged \"Status\" key: %v — TypeScript reads it as undefined", rawResponse)
	}
	if len(body.Steps) != 1 || body.Steps[0].Response == nil {
		t.Fatalf("steps = %+v, want one step with a response — nothing reachable answered", body.Steps)
	}
	if body.Status != "valid" {
		t.Fatalf("status = %q, want valid (the probe answered 200 and the rule checks status_is 200)", body.Status)
	}
}

// A dry-run must not pollute the login-run memory: /run records what it sent so "update macro"
// can promote it, /test must not — an operator testing a macro is not logging in.
func TestSessionRuleTestMacroWritesNoLoginRunMemory(t *testing.T) {
	srv := sessionTestServer()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":    "no memory",
		"enabled": true,
		"scope":   map[string]any{"allow_all": true, "rules": []any{}},
		"steps": []any{
			map[string]any{"method": "GET", "url": srvSenderURL(t), "headers": []any{}, "body": ""},
		},
		"validity": map[string]any{"status_is": 200},
	}, &created)
	if code != http.StatusOK {
		t.Fatalf("POST rule = %d, want 200", code)
	}
	id := itoa(uint64(*created.Rule.ID))

	if rec := taskTestPOST(t, srv, "/api/session/rules/"+id+"/test"); rec.Code != http.StatusOK {
		t.Fatalf("POST /test = %d, want 200", rec.Code)
	}
	if remembered := srv.loginRuns.observed(int64(*created.Rule.ID)); len(remembered) != 0 {
		t.Fatalf("a /test wrote %d login-run rows — the dry-run has side effects on what update-macro promotes", len(remembered))
	}
	// The run path still records, so the memory machinery itself works and the distinction is real.
	if rec := taskTestPOST(t, srv, "/api/session/rules/"+id+"/run"); rec.Code != http.StatusOK {
		t.Fatalf("POST /run = %d, want 200", rec.Code)
	}
	if remembered := srv.loginRuns.observed(int64(*created.Rule.ID)); len(remembered) == 0 {
		t.Fatal("/run wrote no login-run rows — the machinery the /test exclusion relies on is broken")
	}
}

func TestSessionRuleTestMacroRefusesAnUnknownRule(t *testing.T) {
	srv := sessionTestServer()
	if rec := taskTestPOST(t, srv, "/api/session/rules/9999/test"); rec.Code != http.StatusNotFound {
		t.Fatalf("POST /test for an unknown rule = %d, want 404", rec.Code)
	}
}

// srvSenderURL is a URL the shared sender can actually deliver to: a throwaway origin this test
// starts, so the dry-run exercises the real send path rather than a fake.
func taskTestPOST(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func srvSenderURL(t *testing.T) string {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(origin.Close)
	return origin.URL
}
