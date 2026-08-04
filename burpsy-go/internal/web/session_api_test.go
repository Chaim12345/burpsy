package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// These pin the /api/session contract over HTTP: the handlers are what stand between the UI and the
// coordinator, and the JSON here is what internal/web/ui/src/session.ts parses. The Rust routes they
// mirror are crates/web/src/routes/session.rs (`login`, `run_login`, `outcome_body`).

// ---- wire shapes, as the UI declares them ------------------------------------------------------

type wireSessionExtract struct {
	Name string          `json:"name"`
	From json.RawMessage `json:"from"`
	How  json.RawMessage `json:"how"`
}

type wireSessionStep struct {
	Method  string               `json:"method"`
	URL     string               `json:"url"`
	Headers [][2]string          `json:"headers"`
	Body    string               `json:"body"`
	Extract []wireSessionExtract `json:"extract"`
}

type wireSessionRule struct {
	ID          *int64            `json:"id"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Scope       json.RawMessage   `json:"scope"`
	Steps       []wireSessionStep `json:"steps"`
	Validity    json.RawMessage   `json:"validity"`
	MaxAttempts *int              `json:"max_attempts"`
}

type wireSessionRulesResp struct {
	Wired bool              `json:"wired"`
	Rules []wireSessionRule `json:"rules"`
}

type wireLoginResp struct {
	Outcome       string `json:"outcome"`
	Rule          string `json:"rule"`
	RuleID        *int64 `json:"rule_id"`
	URL           string `json:"url"`
	Rules         *int   `json:"rules"`
	Hint          string `json:"hint"`
	LoginAttempts *int   `json:"login_attempts"`
	Attempt       *int   `json:"attempt"`
	StepIndex     *int   `json:"step_index"`
	Validity      string `json:"validity"`
	Error         string `json:"error"`
	Response      *struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	} `json:"response"`
}

type wireRunResp struct {
	Outcome string `json:"outcome"`
	Steps   []struct {
		Method string `json:"method"`
		URL    string `json:"url"`
		Status *int   `json:"status"`
	} `json:"steps"`
}

// ---- helpers ------------------------------------------------------------------------------------

// sessionTestServer is a server with a live sender, since every interesting session path sends.
func sessionTestServer() *Server {
	return NewServer(core.NewTrafficStore(), core.NewScope()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig()))
}

func putJSONInto(t *testing.T, srv *Server, path string, body any, out any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code >= 200 && rec.Code < 300 && out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %d response %q: %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code
}

// hostScope is the ScopeInfo body the UI sends for "only these hosts".
func hostScope(hosts ...string) map[string]any {
	rules := make([]map[string]any, 0, len(hosts))
	for _, h := range hosts {
		rules = append(rules, map[string]any{"kind": "Include", "host": h})
	}
	return map[string]any{"allow_all": false, "rules": rules}
}

// loginTarget is a target that starts logged out: /account is only "valid" (carries X-Auth) once
// /login has been hit. It counts hits per path so a test can prove whether the login macro actually
// ran, which is the whole point — the handler this exercises used to report "recovered" without
// sending it.
type loginTarget struct {
	mu       sync.Mutex
	hits     map[string]int
	loggedIn bool
	// loginWorks false makes the macro's own final response invalid, so the retry bound is exercised.
	loginWorks bool
	url        string
	csrf       string
	sawCSRF    string
}

func newLoginTarget(t *testing.T, loginWorks bool) *loginTarget {
	t.Helper()
	target := &loginTarget{hits: map[string]int{}, loginWorks: loginWorks, csrf: "tok-9f3a"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target.mu.Lock()
		defer target.mu.Unlock()
		target.hits[r.URL.Path]++
		switch r.URL.Path {
		case "/login":
			if q := r.URL.Query().Get("csrf"); q != "" {
				target.sawCSRF = q
			}
			if target.loginWorks {
				target.loggedIn = true
				w.Header().Set("X-Auth", "1")
				w.Header().Set("Set-Cookie", "session=abc123; Path=/")
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "logged in")
		case "/form":
			fmt.Fprintf(w, `<input name="csrf" value="%s">`, target.csrf)
		default:
			if target.loggedIn {
				w.Header().Set("X-Auth", "1")
				fmt.Fprint(w, "welcome")
				return
			}
			fmt.Fprint(w, "please log in")
		}
	}))
	t.Cleanup(srv.Close)
	target.url = srv.URL
	return target
}

func (lt *loginTarget) hitCount(path string) int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.hits[path]
}

func (lt *loginTarget) seenCSRF() string {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.sawCSRF
}

// ---- scope: nil means everywhere, stated-and-empty is refused -----------------------------------

func TestARuleSubmittedWithAllowAllScopeMatchesEveryHost(t *testing.T) {
	srv := sessionTestServer()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":    "global login",
		"enabled": true,
		// This is what the UI's "allow all" scope serialises to, and it used to produce a rule with no
		// scope hosts that MatchHost answered `false` for — enabled, listed, and silently dead.
		"scope":    map[string]any{"allow_all": true, "rules": []any{}},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	}, &created)
	if code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}
	for _, host := range []string{"target.test", "somewhere.else.test", "127.0.0.1"} {
		if got := srv.sessionCoordinator.MatchingRule(host); got == nil {
			t.Fatalf("MatchingRule(%q) = nil; a rule submitted with allow_all must cover every host", host)
		}
	}
}

func TestARuleSubmittedWithAnEmptyStatedScopeIsRefused(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":    "scoped to nothing",
		"enabled": true,
		// Stated, and empty: the operator asked to restrict the rule to no hosts at all.
		"scope":    map[string]any{"allow_all": false, "rules": []any{}},
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST rules with an empty stated scope = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "matches nothing") {
		t.Fatalf("body = %q, want it to say the scope matches nothing", rec.Body.String())
	}
	if len(srv.sessionCoordinator.AllRules()) != 0 {
		t.Fatal("a refused rule must not be installed")
	}
}

func TestARuleWithNoNameIsRefusedOnceWithTheValidatorsWording(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":     "  ",
		"enabled":  true,
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST rules with no name = %d, want 400", rec.Code)
	}
	// One source of truth: the handler no longer carries its own name check with its own wording.
	if !strings.Contains(rec.Body.String(), "needs a name") || !strings.Contains(rec.Body.String(), "<unnamed>") {
		t.Fatalf("body = %q, want the validator's message naming the rule <unnamed>", rec.Body.String())
	}
}

func TestAnInvalidEditIs400AndAMissingRuleIs404(t *testing.T) {
	srv := sessionTestServer()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	if code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":     "editable",
		"enabled":  true,
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	}, &created); code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}
	badEdit := map[string]any{
		"name":     "editable",
		"enabled":  true,
		"steps":    []any{map[string]any{"method": "POST", "url": "/relative", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	}
	if code := putJSONInto(t, srv, fmt.Sprintf("/api/session/rules/%d", *created.Rule.ID), badEdit, nil); code != http.StatusBadRequest {
		t.Fatalf("PUT with a hostless step = %d, want 400", code)
	}
	goodEdit := map[string]any{
		"name":     "editable",
		"enabled":  true,
		"steps":    []any{map[string]any{"method": "POST", "url": "https://target.test/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"status_is": 200},
	}
	if code := putJSONInto(t, srv, "/api/session/rules/9999", goodEdit, nil); code != http.StatusNotFound {
		t.Fatalf("PUT on an unknown id = %d, want 404", code)
	}
}

// ---- extractions survive the wire and actually fire ---------------------------------------------

func TestAnExtractionSurvivesARoundTripAndFiresDuringAMacroRun(t *testing.T) {
	target := newLoginTarget(t, true)
	srv := sessionTestServer()
	host, _, _, err := targetParts(target.url)
	if err != nil {
		t.Fatalf("targetParts(%q): %v", target.url, err)
	}

	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":    "csrf login",
		"enabled": true,
		"scope":   hostScope(host),
		"steps": []any{
			map[string]any{
				"method":  "GET",
				"url":     fmt.Sprintf("%s/form", target.url),
				"headers": []any{},
				"body":    "",
				// The shape session.ts actually sends: `from` is a union, `how` is a tagged union.
				// dtoToRule never read this field, so every extraction typed in the UI was dropped.
				"extract": []any{map[string]any{
					"name": "csrf",
					"from": "body",
					"how":  map[string]any{"regex": map[string]any{"pattern": `name="csrf" value="([^"]+)"`, "group": 1}},
				}},
			},
			map[string]any{
				"method":  "POST",
				"url":     fmt.Sprintf("%s/login?csrf={{csrf}}", target.url),
				"headers": []any{},
				"body":    "",
			},
		},
		"validity":     map[string]any{"header_present": "X-Auth"},
		"max_attempts": 3,
	}, &created)
	if code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}

	// (a) The create response and a fresh GET both carry the extraction back, attached to the step
	// whose response produces it. Neither did before: ruleToDto never emitted `extract` at all.
	assertCSRFExtraction := func(where string, rule wireSessionRule) {
		t.Helper()
		if len(rule.Steps) != 2 {
			t.Fatalf("%s: %d steps, want 2", where, len(rule.Steps))
		}
		if len(rule.Steps[0].Extract) != 1 {
			t.Fatalf("%s: step 0 extract = %+v, want the csrf extraction", where, rule.Steps[0].Extract)
		}
		if len(rule.Steps[1].Extract) != 0 {
			t.Fatalf("%s: step 1 must own no extraction, got %+v", where, rule.Steps[1].Extract)
		}
		ex := rule.Steps[0].Extract[0]
		if ex.Name != "csrf" {
			t.Fatalf("%s: extraction name = %q", where, ex.Name)
		}
		if string(ex.From) != `"body"` {
			t.Fatalf("%s: extraction from = %s, want \"body\"", where, ex.From)
		}
		var how struct {
			Regex *struct {
				Pattern string `json:"pattern"`
				Group   int    `json:"group"`
			} `json:"regex"`
		}
		if err := json.Unmarshal(ex.How, &how); err != nil || how.Regex == nil {
			t.Fatalf("%s: extraction how = %s, want a regex", where, ex.How)
		}
		if how.Regex.Pattern != `name="csrf" value="([^"]+)"` || how.Regex.Group != 1 {
			t.Fatalf("%s: extraction how = %s, want the submitted pattern and group", where, ex.How)
		}
	}
	assertCSRFExtraction("create response", created.Rule)

	var listed wireSessionRulesResp
	if err := json.Unmarshal(get(t, srv, "/api/session/rules").Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode rules list: %v", err)
	}
	if len(listed.Rules) != 1 {
		t.Fatalf("%d rules listed, want 1", len(listed.Rules))
	}
	assertCSRFExtraction("GET round-trip", listed.Rules[0])

	// (b) It fires: the second step must have gone out with the token the first response carried.
	var run wireRunResp
	if code := postJSONInto(t, srv, fmt.Sprintf("/api/session/rules/%d/run", *created.Rule.ID), map[string]any{}, &run); code != http.StatusOK {
		t.Fatalf("POST run = %d, want 200", code)
	}
	if run.Outcome != "valid" {
		t.Fatalf("run outcome = %q, want valid: %+v", run.Outcome, run.Steps)
	}
	want := fmt.Sprintf("%s/login?csrf=%s", target.url, target.csrf)
	if len(run.Steps) != 2 || run.Steps[1].URL != want {
		t.Fatalf("second step url = %q, want %q (the extracted token interpolated)", run.Steps[1].URL, want)
	}
	if got := target.seenCSRF(); got != target.csrf {
		t.Fatalf("target saw csrf %q, want %q — the extraction must reach the wire, not the placeholder", got, target.csrf)
	}
}

func TestAnExtractionWithAnUnusablePatternIs400NotASilentDrop(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":    "bad regex",
		"enabled": true,
		"steps": []any{map[string]any{
			"method": "GET", "url": "https://target.test/form", "headers": []any{}, "body": "",
			"extract": []any{map[string]any{
				"name": "csrf",
				"from": "body",
				"how":  map[string]any{"regex": map[string]any{"pattern": "([unclosed", "group": 1}},
			}},
		}},
		"validity": map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with an uncompilable pattern = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unusable pattern") {
		t.Fatalf("body = %q, want it to name the unusable pattern", rec.Body.String())
	}
}

func TestAnExtractionByJsonPathIsRefusedAsAStatedDivergence(t *testing.T) {
	srv := sessionTestServer()
	rec := postJSON(t, srv, "/api/session/rules", map[string]any{
		"name":    "json path",
		"enabled": true,
		"steps": []any{map[string]any{
			"method": "POST", "url": "https://target.test/token", "headers": []any{}, "body": "",
			"extract": []any{map[string]any{
				"name": "tok",
				"from": "body",
				"how":  map[string]any{"json_path": "data.token"},
			}},
		}},
		"validity": map[string]any{"status_is": 200},
	})
	// The UI can express json_path; this port's extractor cannot run it. Refused rather than compiled
	// as a regex that would match nothing while looking configured.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with a json path extraction = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "json path") {
		t.Fatalf("body = %q, want it to name json path as unimplemented", rec.Body.String())
	}
}

func TestAHeaderExtractionRoundTripsWithItsHeaderName(t *testing.T) {
	srv := sessionTestServer()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	if code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":    "bearer login",
		"enabled": true,
		"steps": []any{
			map[string]any{
				"method": "POST", "url": "https://target.test/token", "headers": []any{}, "body": "",
				"extract": []any{map[string]any{
					"name": "tok",
					"from": map[string]any{"header": "X-Token"},
					"how":  map[string]any{"regex": map[string]any{"pattern": "(.+)", "group": 1}},
				}},
			},
			map[string]any{"method": "GET", "url": "https://target.test/me", "headers": [][2]string{{"Authorization", "Bearer {{tok}}"}}, "body": ""},
		},
		"validity": map[string]any{"status_is": 200},
	}, &created); code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}
	ex := created.Rule.Steps[0].Extract
	if len(ex) != 1 {
		t.Fatalf("step 0 extract = %+v, want one entry", ex)
	}
	var from struct {
		Header string `json:"header"`
	}
	if err := json.Unmarshal(ex[0].From, &from); err != nil || from.Header != "X-Token" {
		// The header name has nowhere to go in a bare From string, which is what this DTO used to be.
		t.Fatalf("extraction from = %s, want {\"header\":\"X-Token\"}", ex[0].From)
	}
}

// ---- POST /api/session/login actually runs the macro --------------------------------------------

func TestLoginProbeThatIsAlreadyValidDoesNotRunTheMacro(t *testing.T) {
	target := newLoginTarget(t, true)
	srv := sessionTestServer()
	host, _, _, _ := targetParts(target.url)
	installLoginRule(t, srv, target, host, 3)

	// Log the target in out of band so the probe comes back valid on its own.
	http.Get(target.url + "/login")

	var resp wireLoginResp
	if code := postJSONInto(t, srv, "/api/session/login", map[string]any{
		"probe": map[string]any{"method": "GET", "url": target.url + "/account", "headers": []any{}, "body": ""},
	}, &resp); code != http.StatusOK {
		t.Fatalf("POST login = %d, want 200", code)
	}
	if resp.Outcome != "already_valid" {
		t.Fatalf("outcome = %q, want already_valid: %+v", resp.Outcome, resp)
	}
	if got := target.hitCount("/login"); got != 1 {
		t.Fatalf("/login hit %d times, want only the out-of-band one: an already-valid session must not re-login", got)
	}
}

func TestLoginProbeThatIsInvalidRunsTheMacroAndRetriesTheProbe(t *testing.T) {
	target := newLoginTarget(t, true)
	srv := sessionTestServer()
	host, _, _, _ := targetParts(target.url)
	installLoginRule(t, srv, target, host, 3)

	var resp wireLoginResp
	if code := postJSONInto(t, srv, "/api/session/login", map[string]any{
		"probe": map[string]any{"method": "GET", "url": target.url + "/account", "headers": []any{}, "body": ""},
	}, &resp); code != http.StatusOK {
		t.Fatalf("POST login = %d, want 200", code)
	}
	// The bug: this used to answer "recovered" for any non-valid probe *without ever sending the
	// macro*. The hit count is what makes the difference observable.
	if got := target.hitCount("/login"); got != 1 {
		t.Fatalf("/login hit %d times, want exactly 1: the login macro must actually run", got)
	}
	if resp.Outcome != "recovered" {
		t.Fatalf("outcome = %q, want recovered: %+v", resp.Outcome, resp)
	}
	if resp.LoginAttempts == nil || *resp.LoginAttempts != 1 {
		t.Fatalf("login_attempts = %v, want 1", resp.LoginAttempts)
	}
	// The probe is retried once with the fresh session, and its response comes back to the operator.
	if got := target.hitCount("/account"); got != 2 {
		t.Fatalf("/account hit %d times, want 2 (the probe, then the retry)", got)
	}
	if resp.Response == nil || resp.Response.Status != 200 || !strings.Contains(resp.Response.Body, "welcome") {
		t.Fatalf("response = %+v, want the retried probe's authenticated body", resp.Response)
	}
	if resp.Rule != "session login" || resp.RuleID == nil {
		t.Fatalf("outcome must name the rule that produced it, got rule=%q id=%v", resp.Rule, resp.RuleID)
	}
}

func TestLoginGivesUpAtTheStatedAttemptBoundRatherThanReportingSuccess(t *testing.T) {
	// A macro whose own final response never satisfies the validity rule: the coordinator must stop at
	// max_attempts and say so, not loop and not claim recovery.
	target := newLoginTarget(t, false)
	srv := sessionTestServer()
	host, _, _, _ := targetParts(target.url)
	installLoginRule(t, srv, target, host, 2)

	var resp wireLoginResp
	if code := postJSONInto(t, srv, "/api/session/login", map[string]any{
		"probe": map[string]any{"method": "GET", "url": target.url + "/account", "headers": []any{}, "body": ""},
	}, &resp); code != http.StatusOK {
		t.Fatalf("POST login = %d, want 200 (a login that was attempted and failed is an answer, not a transport error)", code)
	}
	if resp.Outcome != "gave_up" {
		t.Fatalf("outcome = %q, want gave_up: %+v", resp.Outcome, resp)
	}
	if resp.LoginAttempts == nil || *resp.LoginAttempts != 2 {
		t.Fatalf("login_attempts = %v, want the stated bound of 2", resp.LoginAttempts)
	}
	if got := target.hitCount("/login"); got != 2 {
		t.Fatalf("/login hit %d times, want the stated bound of 2", got)
	}
	// A login that never succeeded must not have the original retried against it.
	if got := target.hitCount("/account"); got != 1 {
		t.Fatalf("/account hit %d times, want only the probe", got)
	}
}

func TestUpdateMacroAfterALoginPromotesTheMacroTheCoordinatorObservedNotTheProbe(t *testing.T) {
	target := newLoginTarget(t, true)
	srv := sessionTestServer()
	host, _, _, _ := targetParts(target.url)
	// A two-step macro with an extraction, so the promoted steps are distinguishable from the probe and
	// the placeholder has to survive.
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	if code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":    "session login",
		"enabled": true,
		"scope":   hostScope(host),
		"steps": []any{
			map[string]any{
				"method": "GET", "url": target.url + "/form", "headers": []any{}, "body": "",
				"extract": []any{map[string]any{
					"name": "csrf",
					"from": "body",
					"how":  map[string]any{"regex": map[string]any{"pattern": `name="csrf" value="([^"]+)"`, "group": 1}},
				}},
			},
			map[string]any{"method": "POST", "url": target.url + "/login?csrf={{csrf}}", "headers": []any{}, "body": ""},
		},
		"validity":     map[string]any{"header_present": "X-Auth"},
		"max_attempts": 3,
	}, &created); code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}
	id := *created.Rule.ID

	// Nothing observed yet: the button must refuse rather than promote something invented.
	if rec := postJSON(t, srv, fmt.Sprintf("/api/session/rules/%d/update-macro", id), map[string]any{}); rec.Code != http.StatusConflict {
		t.Fatalf("update-macro before any run = %d, want 409", rec.Code)
	}

	var login wireLoginResp
	if code := postJSONInto(t, srv, "/api/session/login", map[string]any{
		"probe": map[string]any{"method": "GET", "url": target.url + "/account", "headers": []any{}, "body": ""},
	}, &login); code != http.StatusOK || login.Outcome != "recovered" {
		t.Fatalf("POST login = %d outcome %q, want 200 recovered", code, login.Outcome)
	}

	var promoted struct {
		Steps []wireSessionStep `json:"steps"`
	}
	if code := postJSONInto(t, srv, fmt.Sprintf("/api/session/rules/%d/update-macro", id), map[string]any{}, &promoted); code != http.StatusOK {
		t.Fatalf("update-macro after a login = %d, want 200", code)
	}
	// The probe was a GET of /account. Promoting it would have replaced the recorded login with it.
	if len(promoted.Steps) != 2 {
		t.Fatalf("promoted %d steps, want the macro's 2, not the probe: %+v", len(promoted.Steps), promoted.Steps)
	}
	// The one-time token this run scraped must come back as its placeholder, not baked in — otherwise
	// the next login replays a stale token and "update macro" is a breakage, not a repair.
	want := target.url + "/login?csrf={{csrf}}"
	if promoted.Steps[1].URL != want {
		t.Fatalf("promoted step 1 url = %q, want %q", promoted.Steps[1].URL, want)
	}
	var stored wireSessionRulesResp
	if err := json.Unmarshal(get(t, srv, "/api/session/rules").Body.Bytes(), &stored); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	if stored.Rules[0].Steps[1].URL != want {
		t.Fatalf("stored step 1 url = %q, want %q", stored.Rules[0].Steps[1].URL, want)
	}
	// And the extraction survived the promotion, still attached to step 0.
	if len(stored.Rules[0].Steps[0].Extract) != 1 {
		t.Fatalf("promotion dropped the extraction: %+v", stored.Rules[0].Steps)
	}
}

func TestLoginForATargetNoRuleCoversSendsNothingAndSaysWhy(t *testing.T) {
	target := newLoginTarget(t, true)
	srv := sessionTestServer()
	installLoginRule(t, srv, target, "elsewhere.test", 3)

	var resp wireLoginResp
	if code := postJSONInto(t, srv, "/api/session/login", map[string]any{
		"probe": map[string]any{"method": "GET", "url": target.url + "/account", "headers": []any{}, "body": ""},
	}, &resp); code != http.StatusOK {
		t.Fatalf("POST login = %d, want 200", code)
	}
	if resp.Outcome != "no_rule_applies" {
		t.Fatalf("outcome = %q, want no_rule_applies", resp.Outcome)
	}
	// Nothing may be sent for a target no rule covers: with no macro to run, the probe would cost the
	// target a request to no purpose.
	if got := target.hitCount("/account"); got != 0 {
		t.Fatalf("/account hit %d times, want 0", got)
	}
	if resp.Rules == nil || *resp.Rules != 1 || resp.Hint == "" {
		t.Fatalf("no_rule_applies must carry the rule count and a hint, got %+v", resp)
	}
}

func TestLoginProbeThatCannotBeSentIsReportedAsProbeFailed(t *testing.T) {
	srv := sessionTestServer()
	// Port 1 on loopback: nothing listens, so the send fails rather than returning a response.
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	if code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":     "dead target",
		"enabled":  true,
		"scope":    hostScope("127.0.0.1"),
		"steps":    []any{map[string]any{"method": "POST", "url": "http://127.0.0.1:1/login", "headers": []any{}, "body": ""}},
		"validity": map[string]any{"header_present": "X-Auth"},
	}, &created); code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}
	rec := postJSON(t, srv, "/api/session/login", map[string]any{
		"probe": map[string]any{"method": "GET", "url": "http://127.0.0.1:1/account", "headers": []any{}, "body": ""},
	})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("POST login against a dead target = %d, want 502 (nothing could be sent)", rec.Code)
	}
	var resp wireLoginResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	// A probe that could not be sent is its own outcome: the operator has a dead target, not a dead
	// session, and no macro was run against it.
	if resp.Outcome != "probe_failed" || resp.Error == "" || resp.Rule != "dead target" {
		t.Fatalf("resp = %+v, want probe_failed naming the rule and the transport error", resp)
	}
}

// installLoginRule installs a one-step login macro scoped to `host`, validated by the X-Auth header
// the target sets once logged in.
func installLoginRule(t *testing.T, srv *Server, target *loginTarget, host string, maxAttempts int) int64 {
	t.Helper()
	var created struct {
		Rule wireSessionRule `json:"rule"`
	}
	code := postJSONInto(t, srv, "/api/session/rules", map[string]any{
		"name":         "session login",
		"enabled":      true,
		"scope":        hostScope(host),
		"steps":        []any{map[string]any{"method": "POST", "url": target.url + "/login", "headers": []any{}, "body": ""}},
		"validity":     map[string]any{"header_present": "X-Auth"},
		"max_attempts": maxAttempts,
	}, &created)
	if code != http.StatusOK {
		t.Fatalf("POST rules = %d, want 200", code)
	}
	return *created.Rule.ID
}
