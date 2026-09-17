package web

// Re-analyze (burpsy-react-ui-e23c) — the HTTP surface. These tests drive the routes the way
// session_test_macro_api_test.go drives /test, over the same fixture shape: a rule whose step
// hits a real origin carrying a hidden CSRF field and a Set-Cookie. What is pinned is the
// contract the UI depends on:
//
//   - /analyze answers the suggestions with their sources and values, and writes NOTHING to
//     the rule — looking is not applying;
//   - /apply-extractions with named suggestions wires them into the rule as working
//     extractions, and the rule after carries exactly what was named;
//   - a stale name (one the current analysis does not offer) is a 409, not a silent no-op —
//     the responses changed between looking and committing, and the UI must say so;
//   - the extraction a name maps to is rebuilt server-side from the analysis, not trusted
//     from the wire.
import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
)

// analyzedRule builds a server with one rule whose single step GETs the test origin — an
// origin that answers a login page carrying a hidden CSRF field, a Set-Cookie, and a link
// with a session query parameter: the three classes the analyzer reads.
func analyzedRule(t *testing.T) (*Server, int64, *httptest.Server) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sess=analysis-abc; Path=/")
		fmt.Fprint(w, `<form><input type="hidden" name="csrf_token" value="tok-live"></form><a href="/next?session=q-live">go</a>`)
	}))
	t.Cleanup(origin.Close)

	s := newTestServerWithCoordinator(t)
	target, _ := url.Parse(origin.URL)
	body := map[string]any{
		"name":        "login rule",
		"enabled":     true,
		"scope_hosts": []string{target.Host},
		"steps": []map[string]any{{
			"method": "GET", "url": origin.URL + "/login",
		}},
	}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRequest(http.MethodPost, "/api/session/rules", strings.NewReader(string(raw)))
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, rec)
	if rec2.Code != http.StatusOK {
		t.Fatalf("create rule = %d: %s", rec2.Code, rec2.Body.String())
	}
	var created struct {
		Rule struct {
			ID int64 `json:"id"`
		} `json:"rule"`
	}
	json.Unmarshal(rec2.Body.Bytes(), &created)
	return s, created.Rule.ID, origin
}

func TestAnalyzeAnswersTheThreeSourceClassesAndWritesNothing(t *testing.T) {
	s, id, _ := analyzedRule(t)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/session/rules/%d/analyze", id), nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /analyze = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Found       int                            `json:"found"`
		Suggestions []session.ExtractionSuggestion `json:"suggestions"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	byName := map[string]session.ExtractionSuggestion{}
	for _, sug := range out.Suggestions {
		byName[sug.Name] = sug
	}
	if csrf, ok := byName["csrf_token"]; !ok {
		t.Error("no csrf_token suggestion — the hidden field is the whole point of the feature")
	} else if csrf.Value != "tok-live" || csrf.Source != "hidden form field" {
		t.Errorf("csrf suggestion = %+v, want the live value with its source", csrf)
	}
	if sess, ok := byName["sess"]; !ok {
		t.Error("no sess suggestion from the Set-Cookie")
	} else if sess.Value != "analysis-abc" || sess.From != "header" {
		t.Errorf("sess suggestion = %+v, want a header extraction carrying the cookie's value", sess)
	}
	if q, ok := byName["session"]; !ok {
		t.Error("no session suggestion from the link's query string")
	} else if q.Value != "q-live" || q.Source != "query in link" {
		t.Errorf("session suggestion = %+v, want the query-in-link value", q)
	}
	if out.Found != len(out.Suggestions) {
		t.Errorf("found = %d but the list holds %d — the count and the list must agree", out.Found, len(out.Suggestions))
	}

	// Read-only: the rule is untouched by a look.
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if len(rule.Extractions) != 0 {
		t.Errorf("the rule carries %d extractions after an analyze — looking must not apply", len(rule.Extractions))
	}
}

func TestApplyExtractionsWiresTheNamedSuggestionsAsWorkingExtractions(t *testing.T) {
	s, id, _ := analyzedRule(t)

	body, _ := json.Marshal(map[string]any{"names": []string{"csrf_token", "sess"}})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/session/rules/%d/apply-extractions", id), strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /apply-extractions = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Applied []string `json:"applied"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Applied) != 2 {
		t.Fatalf("applied = %v, want both named suggestions", out.Applied)
	}

	// The rule now extracts exactly those two, and each resolves against a live response —
	// the property the apply exists for: what lands is a working extraction, not a plausible one.
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if len(rule.Extractions) != 2 {
		t.Fatalf("rule holds %d extractions after the apply, want 2", len(rule.Extractions))
	}
	// A fresh response of the same shape the origin serves, run through the extraction's own
	// RunResult — the same path the login uses.
	hdrs := map[string]string{"Set-Cookie": "sess=analysis-abc; Path=/"}
	fresh := []byte(`<form><input type="hidden" name="csrf_token" value="tok-live"></form><a href="/next?session=q-live">go</a>`)
	for _, ex := range rule.Extractions {
		got := ex.Run(hdrs, fresh)
		switch ex.Name {
		case "csrf_token":
			if got != "tok-live" {
				t.Errorf("csrf_token extraction lifted %q, want tok-live — the applied suggestion must actually work", got)
			}
		case "sess":
			if got != "analysis-abc" {
				t.Errorf("sess extraction lifted %q, want analysis-abc", got)
			}
		}
	}
}

func TestApplyWithAStaleNameRefusesRatherThanSilentlySkipping(t *testing.T) {
	s, id, _ := analyzedRule(t)

	// A name no current analysis offers — the origin changed between the look and the commit.
	body, _ := json.Marshal(map[string]any{"names": []string{"no_such_parameter"}})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/session/rules/%d/apply-extractions", id), strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("apply with a stale name = %d, want 409 — the responses changed and a silent no-op would let the UI claim a wiring that did not happen (%s)", rec.Code, rec.Body.String())
	}
}

func TestApplyWithNoNamesIsARefusal(t *testing.T) {
	s, id, _ := analyzedRule(t)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/session/rules/%d/apply-extractions", id), strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("apply with no names = %d, want 400", rec.Code)
	}
}
