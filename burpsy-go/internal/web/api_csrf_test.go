package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- CSRF PoC generation (Burp's Engagement tools → Generate CSRF PoC) --------------------------
//
// Burp turns any captured request into a ready-to-open HTML page that makes a victim's browser
// replay it. burpsy had no equivalent: proving a stored CSRF finding meant hand-writing the form.
// The PoC is generated from the exchange's own bytes — method, scheme, host, path and body params —
// with values HTML-escaped for attribute context, because a value containing `"` or `&` must survive
// into the browser as the operator's value, not as markup.

func seedCSRFExchange(t *testing.T, s *Server, rawRequest string, ex *core.Exchange) uint64 {
	t.Helper()
	reqID, err := s.store.Put([]byte(rawRequest), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex.Request = reqID
	ex.Response = &respID
	s.store.AddExchange(ex)
	return uint64(ex.ID)
}

type csrfTestView struct {
	Method string           `json:"method"`
	Action string           `json:"action"`
	Params []map[string]any `json:"params"`
	HTML   string           `json:"html"`
	Notes  []string         `json:"notes"`
}

func TestCSRFGeneratesAnAutoSubmittingFormForAFormPost(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 21\r\n\r\nuser=admin&pass=x%26y",
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/login"},
	)

	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode csrf view: %v; body %s", err, rec.Body.String())
	}

	if view.Method != "POST" || view.Action != "https://app.test/login" {
		t.Fatalf("method/action = %q/%q; the PoC must replay the captured request against its own origin", view.Method, view.Action)
	}
	if len(view.Params) != 2 {
		t.Fatalf("params = %+v; want user and pass decoded from the urlencoded body", view.Params)
	}
	if got, _ := view.Params[1]["value"].(string); got != "x&y" {
		t.Fatalf("pass param value = %q; %q must arrive URL-decoded so the PoC submits what the client sent", got, "x%26y")
	}
	for _, marker := range []string{
		`<form action="https://app.test/login" method="POST">`,
		`name="user"`, `value="admin"`,
		`name="pass"`, `value="x&amp;y"`,
		`history.pushState`, `document.forms[0].submit()`,
	} {
		if !strings.Contains(view.HTML, marker) {
			t.Errorf("generated PoC is missing %q — an auto-submitting form that does not carry every body parameter proves nothing about CSRF", marker)
		}
	}
	if strings.Contains(view.HTML, "x%26y") {
		t.Error("the PoC embeds the URL-encoded form of a value; the browser would submit double-encoded bytes")
	}
}

func TestCSRFForABodylessGetStillProducesAUsableForm(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"GET /search?q=1 HTTP/1.1\r\nHost: app.test\r\n\r\n",
		&core.Exchange{Host: "app.test", Port: 80, TLS: false, Method: "GET", Path: "/search?q=1"},
	)

	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode csrf view: %v", err)
	}
	if view.Method != "GET" || view.Action != "http://app.test/search?q=1" {
		t.Fatalf("method/action = %q/%q; a GET PoC replays through the query string in the action", view.Method, view.Action)
	}
	if len(view.Params) != 0 {
		t.Fatalf("params = %+v; a bodyless GET has no body parameters to embed", view.Params)
	}
	found := false
	for _, note := range view.Notes {
		if strings.Contains(note, "no form body") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes = %+v; a GET PoC must say honestly that there was no form body to embed", view.Notes)
	}
}

func TestCSRFForAnUnknownExchangeIs404(t *testing.T) {
	s := newTestServer()
	if rec := get(t, s, "/api/exchange/9999/csrf"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown exchange = %d, want 404", rec.Code)
	}
}
