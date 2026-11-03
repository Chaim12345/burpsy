package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

func ui2AuthzStoredIDs(t *testing.T, s *Server) []authzIdentity {
	t.Helper()
	var resp authzIdentitiesReq
	if err := json.Unmarshal(get(t, s, "/api/authz/identities").Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Identities
}

func ui2AuthzBase(t *testing.T, s *Server) string {
	t.Helper()
	return ui2HiddenValue(getUI2(t, s, "/ui2/authz").Body.String(), "base")
}

// Save flow: the review and every page render withhold cookie/header values, the held body is
// what gets written, and a blank cookie on a later edit keeps the stored one.
func TestUI2AuthzIdentitiesSaveNeverRendersSecrets(t *testing.T) {
	s := newTestServer()
	const cookie, hdr, low = "sess=COOKIE-SECRET-1", "Bearer HEADER-SECRET-2", "sess=COOKIE-SECRET-3"
	form := url.Values{
		"base": {ui2AuthzBase(t, s)}, "row": {"0", "1"}, "baseline": {"0"},
		"label_0": {"admin"}, "cookie_0": {cookie}, "headers_0": {"Authorization: " + hdr},
		"label_1": {"low"}, "cookie_1": {low},
	}
	rec := postUI2Form(t, s, "/ui2/authz/identities/confirm", form)
	review := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(review, "PUT /api/authz/identities") {
		t.Fatalf("confirm = %d: %s", rec.Code, review)
	}
	for _, secret := range []string{"COOKIE-SECRET-1", "HEADER-SECRET-2", "COOKIE-SECRET-3"} {
		if strings.Contains(review, secret) {
			t.Fatalf("review sheet leaks %s", secret)
		}
	}
	if len(ui2AuthzStoredIDs(t, s)) != 0 {
		t.Fatal("confirm must not write")
	}
	id, token := ui2ReviewFields(t, review)
	page := postUI2Form(t, s, "/ui2/authz/identities/run", url.Values{"review_id": {id}, "token": {token}}).Body.String()
	if !strings.Contains(page, "identities saved") {
		t.Fatalf("run did not save: %s", page)
	}
	if strings.Contains(page, "SECRET") || strings.Contains(getUI2(t, s, "/ui2/authz").Body.String(), "SECRET") {
		t.Fatal("the identities page renders a stored credential")
	}
	ids := ui2AuthzStoredIDs(t, s)
	if len(ids) != 2 || ids[0].Cookie != cookie || ids[0].Headers["Authorization"] != hdr || !ids[0].Baseline || ids[1].Cookie != low {
		t.Fatalf("stored identities = %+v", ids)
	}

	// Rename with blank cookie/headers: the stored values survive without ever reaching the form.
	form = url.Values{
		"base": {ui2AuthzBase(t, s)}, "row": {"0", "1"}, "baseline": {"0"},
		"orig_0": {"0"}, "label_0": {"root"}, "orig_1": {"1"}, "label_1": {"low"}, "remove_1": {"on"},
	}
	id, token = ui2ReviewFields(t, postUI2Form(t, s, "/ui2/authz/identities/confirm", form).Body.String())
	postUI2Form(t, s, "/ui2/authz/identities/run", url.Values{"review_id": {id}, "token": {token}})
	ids = ui2AuthzStoredIDs(t, s)
	if len(ids) != 1 || ids[0].Label != "root" || ids[0].Cookie != cookie || ids[0].Headers["Authorization"] != hdr {
		t.Fatalf("edit lost stored values: %+v", ids)
	}
}

// A review is single-use, bound to its token, and refused once the stored set drifted.
func TestUI2AuthzIdentitiesRunRefusals(t *testing.T) {
	s := newTestServer()
	form := url.Values{"base": {ui2AuthzBase(t, s)}, "row": {"0"}, "baseline": {"0"}, "label_0": {"admin"}}
	id, token := ui2ReviewFields(t, postUI2Form(t, s, "/ui2/authz/identities/confirm", form).Body.String())
	if body := postUI2Form(t, s, "/ui2/authz/identities/run", url.Values{"review_id": {id}, "token": {"wrong"}}).Body.String(); !strings.Contains(body, "Not saved") {
		t.Fatalf("a wrong token was accepted: %s", body)
	}
	if body := postUI2Form(t, s, "/ui2/authz/identities/run", url.Values{"review_id": {id}, "token": {token}}).Body.String(); !strings.Contains(body, "already used") {
		t.Fatalf("a spent review was accepted: %s", body)
	}
	if len(ui2AuthzStoredIDs(t, s)) != 0 {
		t.Fatal("a refused run wrote identities")
	}
	// Drift: the stored set changes between review and run.
	id, token = ui2ReviewFields(t, postUI2Form(t, s, "/ui2/authz/identities/confirm", form).Body.String())
	putJSON(t, s, "/api/authz/identities", map[string]any{"identities": []map[string]any{{"label": "x", "baseline": true}}})
	if body := postUI2Form(t, s, "/ui2/authz/identities/run", url.Values{"review_id": {id}, "token": {token}}).Body.String(); !strings.Contains(body, "changed since the review") {
		t.Fatalf("a drifted review was applied: %s", body)
	}
	if body := postUI2Form(t, s, "/ui2/authz/identities/confirm", form).Body.String(); !strings.Contains(body, "changed since this form opened") {
		t.Fatalf("a stale form was reviewed: %s", body)
	}
}

// The test runs only through review -> token; verdicts link a Comparer diff.
func TestUI2AuthzTestReviewRunAndDiff(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "SECRET admin dashboard")
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	s := newTestServer()
	s.WithSender(sender.NewSender(sender.DefaultSenderConfig()))
	s.scope.AddInclude("*")
	raw := fmt.Sprintf("GET /leak HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", host, port)
	reqID, _ := s.store.Put([]byte(raw), core.DirectionRequest)
	ex := &core.Exchange{Host: host, Port: port, Method: "GET", Path: "/leak", Request: core.MsgPtr(reqID)}
	s.store.AddExchange(ex)
	putJSON(t, s, "/api/authz/identities", map[string]any{"identities": []map[string]any{
		{"label": "admin", "baseline": true, "cookie": "role=COOKIE-SECRET"}, {"label": "low", "strip_cookie": true},
	}})

	form := url.Values{"exchange_id": {fmt.Sprint(ex.ID)}, "samples": {"2"}}
	review := postUI2Form(t, s, "/ui2/authz/test/confirm", form).Body.String()
	if !strings.Contains(review, "POST /api/authz/test") || !strings.Contains(review, "&#34;samples&#34;:2") || strings.Contains(review, "COOKIE-SECRET") {
		t.Fatalf("review sheet: %s", review)
	}
	if hits.Load() != 0 {
		t.Fatal("confirm sent traffic")
	}
	if body := postUI2Form(t, s, "/ui2/authz/test/run", url.Values{"exchange_id": form["exchange_id"], "samples": {"2"}, "token": {"bogus"}}).Body.String(); !strings.Contains(body, "Test failed") || hits.Load() != 0 {
		t.Fatalf("a bogus token ran the test (hits %d): %s", hits.Load(), body)
	}
	token := ui2HiddenValue(review, "token")
	page := postUI2Form(t, s, "/ui2/authz/test/run", url.Values{"exchange_id": form["exchange_id"], "samples": {"2"}, "token": {token}}).Body.String()
	if !strings.Contains(page, `data-verdict="Bypassed"`) || hits.Load() == 0 {
		t.Fatalf("no Bypassed verdict: %s", page)
	}
	i := strings.Index(page, `href="/ui2/authz/diff/`)
	if i < 0 {
		t.Fatalf("no diff link: %s", page)
	}
	link := page[i+len(`href="`):]
	link = link[:strings.Index(link, `"`)]
	diff := getUI2(t, s, link)
	if diff.Code != http.StatusOK || !strings.Contains(diff.Body.String(), "SECRET admin dashboard") {
		t.Fatalf("diff page = %d: %s", diff.Code, diff.Body.String())
	}
}
