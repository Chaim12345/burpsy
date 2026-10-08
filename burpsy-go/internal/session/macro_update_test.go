package session

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// The run-macro action's "after the macro" choices (burpsy-react-ui-8gk8), driven through
// HandleRecovery with a runner that sends over the wire to a real origin, and asserted on what the
// origin received.

type updateOrigin struct {
	srv  *httptest.Server
	mu   sync.Mutex
	last *http.Request
	body string
}

func startUpdateOrigin(t *testing.T) *updateOrigin {
	t.Helper()
	o := &updateOrigin{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "new", Path: "/"})
			io.WriteString(w, "logged in")
		case "/form":
			http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><body><form method="post" action="/transfer">`+
				`<input type="hidden" name="csrf" value="NEW"><input name="amount" value="0">`+
				`</form></body></html>`)
		default:
			body, _ := io.ReadAll(r.Body)
			o.mu.Lock()
			o.last, o.body = r, string(body)
			o.mu.Unlock()
			io.WriteString(w, "ok")
		}
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *updateOrigin) received(t *testing.T) (cookie, query, body string) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.last == nil {
		t.Fatal("the current request never reached the origin")
	}
	return o.last.Header.Get("Cookie"), o.last.URL.RawQuery, o.body
}

// wireRunner sends a step over the network, as the production runner does.
func wireRunner(t *testing.T) MacroStepRunner {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(step MacroStep) (*StepResult, error) {
		req, err := http.NewRequest(step.Method, step.URL, strings.NewReader(step.Body))
		if err != nil {
			return nil, err
		}
		for k, v := range step.Headers {
			if strings.EqualFold(k, "Content-Length") {
				continue
			}
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		headers := map[string]string{}
		for k, v := range resp.Header {
			if strings.EqualFold(k, "Set-Cookie") {
				// The origin sets one cookie per step: StepResult carries one value per header name.
				headers[k] = v[0]
				continue
			}
			headers[k] = v[0]
		}
		return &StepResult{Status: resp.StatusCode, Headers: headers, Body: body, FinalURL: step.URL}, nil
	}
}

// runWithAction installs a rule whose only action is the given run-macro action (as stored JSON, so
// the persisted shape is what is tested) and handles one current request.
func runWithAction(t *testing.T, o *updateOrigin, actionJSON string, current MacroStep) {
	t.Helper()
	var action Action
	if err := json.Unmarshal([]byte(actionJSON), &action); err != nil {
		t.Fatalf("action JSON: %v", err)
	}
	c := NewCoordinator(zap.NewNop())
	rule := NewSessionRule("csrf", []string{"127.0.0.1"}, []MacroStep{{Method: "GET", URL: o.srv.URL + "/login"}, {Method: "GET", URL: o.srv.URL + "/form"}})
	rule.Actions = []*Action{&action}
	mustAddRule(t, c, rule)
	out := c.HandleRecovery("", current, nil, wireRunner(t))
	if out.Kind != RecoveryRecovered {
		t.Fatalf("outcome %v, want Recovered; trace %+v", out.Kind, out.Actions)
	}
}

func currentTransfer(o *updateOrigin, path string) MacroStep {
	return MacroStep{Method: "POST", URL: o.srv.URL + path + "?ref=1",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Cookie": "sid=old; pref=mine"},
		Body:    "csrf=OLD&amount=5"}
}

// The first thing to hold: a stored action with none of the new fields behaves exactly as before —
// the whole jar replaces the request's cookies, and no parameter is touched.
func TestAStoredRunMacroActionWithoutTheNewFieldsBehavesAsBefore(t *testing.T) {
	o := startUpdateOrigin(t)
	runWithAction(t, o, `{"kind":0,"enabled":true}`, currentTransfer(o, "/transfer"))
	cookie, _, body := o.received(t)
	if !strings.Contains(cookie, "sid=new") || !strings.Contains(cookie, "theme=dark") || strings.Contains(cookie, "pref=mine") {
		t.Errorf("Cookie = %q, want the whole jar (sid=new, theme=dark) as before", cookie)
	}
	if body != "csrf=OLD&amount=5" {
		t.Errorf("body = %q, want it untouched: parameters were never updated before", body)
	}
}

func TestUpdateWithParamsWritesTheFormsValueIntoTheCurrentRequest(t *testing.T) {
	o := startUpdateOrigin(t)
	runWithAction(t, o, `{"kind":0,"enabled":true,"update_with_params":true,"match_params":"all_params_except","params":["amount"]}`,
		currentTransfer(o, "/transfer"))
	_, query, body := o.received(t)
	if body != "csrf=NEW&amount=5" {
		t.Errorf("body = %q, want csrf=NEW with amount excepted", body)
	}
	if query != "ref=1" {
		t.Errorf("query = %q, a parameter the response does not name must be left alone", query)
	}
}

func TestSpecifiedParamsUpdatesOnlyTheNamedOnes(t *testing.T) {
	o := startUpdateOrigin(t)
	runWithAction(t, o, `{"kind":0,"enabled":true,"update_with_params":true,"match_params":"specified_params","params":["amount"]}`,
		currentTransfer(o, "/transfer"))
	if _, _, body := o.received(t); body != "csrf=OLD&amount=0" {
		t.Errorf("body = %q, want only amount updated", body)
	}
}

func TestAParameterIsMatchedByURLUnlessTheMismatchIsTolerated(t *testing.T) {
	o := startUpdateOrigin(t)
	runWithAction(t, o, `{"kind":0,"enabled":true,"update_with_params":true}`, currentTransfer(o, "/elsewhere"))
	if _, _, body := o.received(t); body != "csrf=OLD&amount=5" {
		t.Errorf("body = %q: the form posts to /transfer, so /elsewhere must not take its values", body)
	}
	runWithAction(t, o, `{"kind":0,"enabled":true,"update_with_params":true,"tolerate_url_mismatch":true,"match_params":"specified_params","params":["csrf"]}`,
		currentTransfer(o, "/elsewhere"))
	if _, _, body := o.received(t); body != "csrf=NEW&amount=5" {
		t.Errorf("body = %q: with the mismatch tolerated the token applies anywhere", body)
	}
}

func TestTheJarCookiesCanBeTurnedOffOrScoped(t *testing.T) {
	o := startUpdateOrigin(t)
	runWithAction(t, o, `{"kind":0,"enabled":true,"update_with_cookies":false}`, currentTransfer(o, "/transfer"))
	if cookie, _, _ := o.received(t); cookie != "sid=old; pref=mine" {
		t.Errorf("cookies off: Cookie = %q, want the request's own header untouched", cookie)
	}
	runWithAction(t, o, `{"kind":0,"enabled":true,"match_cookies":"specified_cookies","cookies":["sid"]}`, currentTransfer(o, "/transfer"))
	if cookie, _, _ := o.received(t); cookie != "sid=new; pref=mine" {
		t.Errorf("only sid: Cookie = %q, want sid from the jar and the request's own pref kept", cookie)
	}
	runWithAction(t, o, `{"kind":0,"enabled":true,"match_cookies":"all_cookies_except","cookies":["sid"]}`, currentTransfer(o, "/transfer"))
	if cookie, _, _ := o.received(t); cookie != "sid=old; pref=mine; theme=dark" {
		t.Errorf("all except sid: Cookie = %q, want theme from the jar and sid left as the request had it", cookie)
	}
}

func TestDeriveParamsReadsFormsSelectsTextareasAndLinks(t *testing.T) {
	page := `<form action="/a"><input name="t" value="1"><textarea name="note">hi</textarea>` +
		`<select name="s"><option value="x">X</option><option value="y" selected>Y</option></select></form>` +
		`<a href="/b?k=v&amp;z=2">link</a><input name="outside" value="no">`
	got := map[string]string{}
	for _, p := range deriveParams([]byte(page), "http://h.test/start") {
		got[p.name+"@"+p.where] = p.value
	}
	want := map[string]string{"t@h.test/a": "1", "note@h.test/a": "hi", "s@h.test/a": "y", "k@h.test/b": "v", "z@h.test/b": "2"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if _, ok := got["outside@"]; ok {
		t.Error("an input outside any form was derived")
	}
}

func TestMacroUpdateFieldsAreValidated(t *testing.T) {
	for _, a := range []*Action{
		{Kind: ActionSetHeader, Enabled: true, Name: "X", UpdateWithParams: true},
		{Kind: ActionRunMacro, Enabled: true, MatchParams: "some_params"},
		{Kind: ActionRunMacro, Enabled: true, MatchCookies: "every"},
		{Kind: ActionRunMacro, Enabled: true, Params: []string{" "}},
	} {
		if err := ValidateAction(a, "action 1"); err == nil {
			t.Errorf("%+v was accepted", a)
		}
	}
}
