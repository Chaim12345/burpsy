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
	ex.Request = core.MsgPtr(reqID)
	ex.Response = &respID
	s.store.AddExchange(ex)
	return uint64(ex.ID)
}

type csrfTestView struct {
	Technique string           `json:"technique"`
	Method    string           `json:"method"`
	Action    string           `json:"action"`
	Params    []map[string]any `json:"params"`
	HTML      string           `json:"html"`
	Notes     []string         `json:"notes"`
	TestURL   string           `json:"test_url"`
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

// ---- the technique selector and the JSON/XML techniques (burpsy-react-ui-0z10) ------------------
//
// Burp's generator offers a technique choice, and the docs are explicit about the mapping: "Some
// requests have bodies (such as XML or JSON) that can only be generated using either a form with
// plain text encoding, or a cross-domain XHR." These tests pin each technique against each body
// kind, through the real route.

// auto on a multipart body gives the multipart form: the parts parsed out and re-embedded, the
// browser regenerating the boundary when the form submits.
func TestAutoGivesAMultipartFormForAMultipartBody(t *testing.T) {
	s := newTestServer()
	body := "--XBOUND\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nadmin\r\n--XBOUND\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\ntoken\r\n--XBOUND--\r\n"
	id := seedCSRFExchange(t, s,
		"POST /profile HTTP/1.1\r\nHost: app.test\r\nContent-Type: multipart/form-data; boundary=XBOUND\r\nContent-Length: 130\r\n\r\n"+body,
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/profile"},
	)

	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf = %d (%s)", rec.Code, rec.Body.String())
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Technique != "multipart" {
		t.Fatalf("auto picked %q for a multipart body; want multipart", view.Technique)
	}
	for _, marker := range []string{
		"enctype=\"multipart/form-data\"",
		`name="user"`, `value="admin"`,
		`name="csrf"`, `value="token"`,
	} {
		if !strings.Contains(view.HTML, marker) {
			t.Errorf("the multipart PoC is missing %q — without every part the replay proves nothing", marker)
		}
	}
	foundBoundaryNote := false
	for _, note := range view.Notes {
		if strings.Contains(note, "regenerates the multipart boundary") {
			foundBoundaryNote = true
		}
	}
	if !foundBoundaryNote {
		t.Errorf("notes = %v; the boundary difference must be said out loud", view.Notes)
	}
}

// auto on a JSON body with an equals character gives the plain-text form: one hidden input split
// at the first "=", the exact body reproduced, and the documented warning that the browser submits
// Content-Type: text/plain.
func TestAutoGivesAPlainTextFormForAJSONBodyWithAnEquals(t *testing.T) {
	s := newTestServer()
	jsonBody := "{\"pw\": \"a=b\"}"
	id := seedCSRFExchange(t, s,
		"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n"+jsonBody,
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/login"},
	)

	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf = %d (%s)", rec.Code, rec.Body.String())
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Technique != "plain" {
		t.Fatalf("auto picked %q for a JSON body with an equals; want plain", view.Technique)
	}
	// name is everything before the first "=", value everything after: the
	// browser's text/plain submission reassembles name + "=" + value.
	if len(view.Params) != 1 {
		t.Fatalf("params = %+v; the plain technique is exactly one input", view.Params)
	}
	if got, _ := view.Params[0]["name"].(string); got != "{\"pw\": \"a" {
		t.Fatalf("the split name = %q; want the body up to the first equals", got)
	}
	if got, _ := view.Params[0]["value"].(string); got != "b\"}" {
		t.Fatalf("the split value = %q; want the body after the first equals", got)
	}
	for _, marker := range []string{`enctype="text/plain"`, `value="b&#34;}`} {
		if !strings.Contains(view.HTML, marker) {
			t.Errorf("the plain-text PoC is missing %q", marker)
		}
	}
	foundCTNote := false
	for _, note := range view.Notes {
		if strings.Contains(note, "Content-Type: text/plain, not the captured application/json") {
			foundCTNote = true
		}
	}
	if !foundCTNote {
		t.Errorf("notes = %v; the changed Content-Type is the documented risk and must be said", view.Notes)
	}
}

// auto on a JSON body with no equals gives the cross-domain XHR, labelled with the CORS dependency
// — the honest reading of "only works on browsers that support cross-origin resource sharing".
func TestAutoGivesAXHRForAJSONBodyWithNoEquals(t *testing.T) {
	s := newTestServer()
	jsonBody := "{\"user\": \"admin\"}"
	id := seedCSRFExchange(t, s,
		"POST /api/settings HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nX-Custom: thing\r\nContent-Length: 17\r\n\r\n"+jsonBody,
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/api/settings"},
	)

	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf = %d (%s)", rec.Code, rec.Body.String())
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Technique != "xhr" {
		t.Fatalf("auto picked %q for a JSON body with no equals; want xhr", view.Technique)
	}
	for _, marker := range []string{
		"xhr.open('POST', 'https://app.test/api/settings', true)",
		"xhr.withCredentials = true",
		"xhr.setRequestHeader('Content-Type', 'application/json')",
		"xhr.setRequestHeader('X-Custom', 'thing')",
		"xhr.send('{\"user\": \"admin\"}')",
	} {
		if !strings.Contains(view.HTML, marker) {
			t.Errorf("the XHR PoC is missing %q", marker)
		}
	}
	// The browser's own headers are not set by the script — a setRequestHeader
	// the browser ignores would be a PoC lying about what it does.
	for _, forbidden := range []string{"setRequestHeader('Host'", "setRequestHeader('Cookie'", "setRequestHeader('Content-Length'"} {
		if strings.Contains(view.HTML, forbidden) {
			t.Errorf("the XHR PoC sets the browser-owned header %q, which the browser silently ignores", forbidden)
		}
	}
	foundCORS := false
	foundPreflight := false
	for _, note := range view.Notes {
		if strings.Contains(note, "requires CORS") {
			foundCORS = true
		}
		if strings.Contains(note, "preflight") {
			foundPreflight = true
		}
	}
	if !foundCORS || !foundPreflight {
		t.Errorf("notes = %v; the CORS dependency and the application/json preflight must both be said", view.Notes)
	}
}

// A manually selected technique that cannot reproduce the request still generates a best effort
// with a warning — Burp's documented behaviour, and the refusal that would teach nothing.
func TestAManuallySelectedTechniqueThatCannotReproduceWarns(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"a\":\"b\"}",
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/login"},
	)

	// form on a JSON body: warning, and no invented parameters.
	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf?technique=form")
	if rec.Code != http.StatusOK {
		t.Fatalf("technique=form answered %d", rec.Code)
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(view.Params) != 0 {
		t.Errorf("params = %+v; a non-urlencoded body must not be half-parsed into parameters", view.Params)
	}
	found := false
	for _, note := range view.Notes {
		if strings.Contains(note, "was not one, so no body parameters were embedded") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes = %v; the form-on-JSON best effort must say what it could not do", view.Notes)
	}

	// plain without an equals in the body: warning that the exact body cannot be sent.
	rec = get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf?technique=plain")
	if rec.Code != http.StatusOK {
		t.Fatalf("technique=plain answered %d", rec.Code)
	}
	view = csrfTestView{}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found = false
	for _, note := range view.Notes {
		if strings.Contains(note, "needs an equals character") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes = %v; a plain technique with no equals must say the body cannot be reproduced", view.Notes)
	}
}

// The auto-submit script is an option, not a fixture: asked for, it fires the request on load;
// declined, the PoC shows the operator a button and nothing runs by itself.
func TestTheAutoSubmitScriptAppearsOnlyWhenAsked(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nuser=admin",
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/login"},
	)

	decode := func(query string) csrfTestView {
		rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf"+query)
		if rec.Code != http.StatusOK {
			t.Fatalf("csrf%s answered %d (%s)", query, rec.Code, rec.Body.String())
		}
		var view csrfTestView
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return view
	}

	if view := decode(""); !strings.Contains(view.HTML, "document.forms[0].submit()") {
		t.Error("the default PoC must auto-submit, matching the generator's existing behaviour")
	}
	view := decode("?auto_submit=false")
	if strings.Contains(view.HTML, "document.forms[0].submit()") || strings.Contains(view.HTML, "history.pushState") {
		t.Errorf("auto_submit=false still carries the submit script:\n%s", view.HTML)
	}
	if !strings.Contains(view.HTML, `<input type="submit" value="Submit request" />`) {
		t.Error("auto_submit=false must leave the operator a button, not a dead page")
	}
}

// The wire arrays are [], never null — a consumer reading params or notes as a list must not have
// to defend against null, and a bodyless request is the case that used to leave them nil.
func TestCSRFParamsAndNotesAreEmptyArraysNeverJSONNull(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"GET /search?q=1 HTTP/1.1\r\nHost: app.test\r\n\r\n",
		&core.Exchange{Host: "app.test", Port: 80, TLS: false, Method: "GET", Path: "/search?q=1"},
	)
	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf?technique=xhr")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf = %d", rec.Code)
	}
	raw := rec.Body.String()
	for _, want := range []string{`"params":[]`, `"notes":[`, `"technique":"xhr"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("the CSRF view is missing %q; the wire shape must be arrays, not null:\n%s", want, raw)
		}
	}
}

// Unknown technique, auto_submit and test_url values are 400s naming the accepted values — a
// parameter that silently fell back to auto would generate a PoC the operator believes they
// configured and did not.
func TestCSRFUnknownOptionsAreRefused(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nuser=admin",
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/login"},
	)
	for _, tc := range []struct {
		query, wantInMessage string
	}{
		{"?technique=bogus", `unknown technique "bogus"; the accepted values are auto, form, multipart, plain, xhr`},
		{"?auto_submit=maybe", "auto_submit must be true or false"},
		{"?test_url=please", "test_url must be true"},
	} {
		rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf"+tc.query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", tc.query, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.wantInMessage) {
			t.Errorf("%s answered %q, which does not name the accepted values", tc.query, rec.Body.String())
		}
	}
}

// A captured body carrying a script closer must not break out of the PoC's script element: the
// jsString escaper turns "<" into \u003c inside the JS, so "</script>" can never terminate the
// element early and turn request bytes into live markup.
func TestTheXHRPoCEscapesScriptClosersFromTheCapturedBody(t *testing.T) {
	s := newTestServer()
	id := seedCSRFExchange(t, s,
		"POST /x HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nContent-Length: 33\r\n\r\n{\"a\": \"</script><b>x</b>\"}",
		&core.Exchange{Host: "app.test", Port: 443, TLS: true, Method: "POST", Path: "/x"},
	)
	rec := get(t, s, "/api/exchange/"+strconv.FormatUint(id, 10)+"/csrf")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csrf = %d (%s)", rec.Code, rec.Body.String())
	}
	var view csrfTestView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Exactly one "</script>" — the element's own closer — and the body's
	// closer survives only as the \u003c escape inside the JS string.
	if n := strings.Count(view.HTML, "</script>"); n != 1 {
		t.Errorf("the PoC carries %d script closers, want exactly the one real element closer:\n%s", n, view.HTML)
	}
	if !strings.Contains(view.HTML, `\u003c/script>`) {
		t.Errorf("the captured script closer was not escaped into the JS string:\n%s", view.HTML)
	}
}
