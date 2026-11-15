package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// ui2RepeaterVictim is a loopback origin: /r redirects to /final, everything else answers with
// a body that changes on every hit, so change highlighting has something to show.
func ui2RepeaterVictim(t *testing.T) (string, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&hits, 1)
		if r.URL.Path == "/r" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("hit-" + strconv.FormatInt(n, 10) + " path=" + r.URL.Path))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), &hits
}

func ui2RepeaterEditor(tab int, target, raw string) url.Values {
	f := url.Values{"editor": {"1"}, "target": {target}, "raw": {raw}, "opt_unpack": {"1"}, "opt_protocol": {"auto"}}
	if tab > 0 {
		f.Set("tab_id", strconv.Itoa(tab))
	}
	return f
}

func ui2RepeaterTabs(s *Server) []*ui2RepeaterTab {
	st := s.ui2Repeater()
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]*ui2RepeaterTab(nil), st.tabs...)
}

// TestUI2RepeaterWorkspaceSendsAndKeepsTabs drives the tab lifecycle through the page's own
// routes: the first send creates a tab, a second tab sends separately, rename/duplicate/close/
// reopen act on the right tab, a group sends in parallel into each tab's history, and the
// history export downloads the API's JSON file.
func TestUI2RepeaterWorkspaceSendsAndKeepsTabs(t *testing.T) {
	s := newTestServer()
	target, hits := ui2RepeaterVictim(t)
	raw := "GET /one HTTP/1.1\nHost: " + target + "\n\n"

	// GET writes nothing: the empty workspace renders a virtual tab only.
	if rec := getUI2(t, s, "/ui2/repeater"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "unsaved draft") {
		t.Fatalf("empty workspace = %d", rec.Code)
	}
	if n := len(ui2RepeaterTabs(s)); n != 0 {
		t.Fatalf("GET created %d tabs", n)
	}

	rec := postUI2Form(t, s, "/ui2/repeater/send", ui2RepeaterEditor(0, "", raw))
	body := rec.Body.String()
	if !strings.Contains(body, "hit-1 path=/one") || !strings.Contains(body, "stored exchange #") {
		t.Fatalf("first send did not render its response: %s", body)
	}
	tabs := ui2RepeaterTabs(s)
	if len(tabs) != 1 || len(tabs[0].History) != 1 {
		t.Fatalf("first send: %d tabs", len(tabs))
	}
	first := tabs[0].ID

	rec = postUI2Form(t, s, "/ui2/repeater/tabs/new", ui2RepeaterEditor(first, "", raw))
	second := ui2RepeaterTabs(s)[1].ID
	if rec.Header().Get("HX-Push-Url") != "/ui2/repeater?tab="+strconv.Itoa(second) {
		t.Fatalf("new tab not made active: %q", rec.Header().Get("HX-Push-Url"))
	}
	postUI2Form(t, s, "/ui2/repeater/send", ui2RepeaterEditor(second, "", "GET /two HTTP/1.1\nHost: "+target+"\n\n"))
	rename := ui2RepeaterEditor(second, "", "GET /two HTTP/1.1\nHost: "+target+"\n\n")
	rename.Set("name", "login")
	body = postUI2Form(t, s, "/ui2/repeater/tabs/rename", rename).Body.String()
	if !strings.Contains(body, ">login") {
		t.Fatalf("rename not rendered")
	}
	if got := ui2RepeaterTabs(s)[0].History; len(got) != 1 {
		t.Fatalf("second tab's send landed in the first tab's history")
	}

	// Group both tabs and send the group in parallel.
	g := url.Values{"tab_id": {strconv.Itoa(first)}, "group_name": {"race"}}
	postUI2Form(t, s, "/ui2/repeater/tabs/group-new", g)
	groupID := ui2RepeaterTabs(s)[0].Group
	postUI2Form(t, s, "/ui2/repeater/tabs/group-move", url.Values{"tab_id": {strconv.Itoa(second)}, "group": {strconv.Itoa(groupID)}})
	before := atomic.LoadInt64(hits)
	f := url.Values{"tab_id": {strconv.Itoa(first)}, "mode": {"parallel"}}
	body = postUI2Form(t, s, "/ui2/repeater/send-group", f).Body.String()
	if atomic.LoadInt64(hits)-before != 2 || !strings.Contains(body, `id="rp-group-result"`) {
		t.Fatalf("group send: %d hits, body %s", atomic.LoadInt64(hits)-before, body)
	}
	for _, tab := range ui2RepeaterTabs(s) {
		if len(tab.History) != 2 {
			t.Fatalf("tab %d history = %d after the group send, want 2", tab.ID, len(tab.History))
		}
	}

	// Duplicate, close the copy, reopen it.
	postUI2Form(t, s, "/ui2/repeater/tabs/duplicate", url.Values{"tab_id": {strconv.Itoa(first)}})
	tabs = ui2RepeaterTabs(s)
	if len(tabs) != 3 || tabs[1].Name != tabs[0].Name+" (copy)" {
		t.Fatalf("duplicate not placed after its original: %d tabs", len(tabs))
	}
	postUI2Form(t, s, "/ui2/repeater/tabs/close", url.Values{"tab_id": {strconv.Itoa(tabs[1].ID)}})
	postUI2Form(t, s, "/ui2/repeater/tabs/reopen", url.Values{"tab_id": {strconv.Itoa(first)}})
	if n := len(ui2RepeaterTabs(s)); n != 3 {
		t.Fatalf("reopen: %d tabs", n)
	}

	exp := httptest.NewRequest(http.MethodPost, "/ui2/repeater/tabs/export", strings.NewReader("tab_id="+strconv.Itoa(first)))
	exp.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	er := httptest.NewRecorder()
	s.mux.ServeHTTP(er, exp)
	var file historyExportFile
	if er.Code != http.StatusOK || json.Unmarshal(er.Body.Bytes(), &file) != nil || file.Exported != 2 {
		t.Fatalf("export = %d: %s", er.Code, er.Body.String())
	}
	if !strings.Contains(er.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export is not a download")
	}
}

// TestUI2RepeaterRedirectChainAndChangeHighlight: a per-tab redirect override is honoured, the
// chain table offers the followed hop, choosing it shows that hop's response, and a second send
// highlights what changed.
func TestUI2RepeaterRedirectChainAndChangeHighlight(t *testing.T) {
	s := newTestServer()
	target, _ := ui2RepeaterVictim(t)
	f := ui2RepeaterEditor(0, "", "GET /r HTTP/1.1\nHost: "+target+"\n\n")
	f.Set("opt_override", "1")
	f.Set("opt_redirect", "always")
	body := postUI2Form(t, s, "/ui2/repeater/send", f).Body.String()
	if !strings.Contains(body, `id="rp-redirects"`) || !strings.Contains(body, "/final") {
		t.Fatalf("redirect chain not rendered: %s", body)
	}
	id := ui2RepeaterTabs(s)[0].ID
	hop := getUI2(t, s, "/ui2/repeater?tab="+strconv.Itoa(id)+"&hop=1").Body.String()
	if !strings.Contains(hop, "path=/final") || !strings.Contains(hop, "Hop 1 request") {
		t.Fatalf("hop 1 not shown: %s", hop)
	}

	f.Set("tab_id", strconv.Itoa(id))
	f.Set("raw", "GET /plain HTTP/1.1\nHost: "+target+"\n\n")
	postUI2Form(t, s, "/ui2/repeater/send", f)
	postUI2Form(t, s, "/ui2/repeater/send", f)
	diff := getUI2(t, s, "/ui2/repeater?tab="+strconv.Itoa(id)+"&diff=1").Body.String()
	if !strings.Contains(diff, `id="rp-diff"`) || !strings.Contains(diff, `class="d-add"`) {
		t.Fatalf("change highlighting missing: %s", diff)
	}
}

// TestUI2RepeaterRefusals: no write on GET, unknown actions and closed tabs are refused, and a
// request with no target sends nothing.
func TestUI2RepeaterRefusals(t *testing.T) {
	s := newTestServer()
	_, hits := ui2RepeaterVictim(t)
	for _, p := range []string{"/ui2/repeater/send", "/ui2/repeater/send-group", "/ui2/repeater/tabs/new"} {
		if rec := getUI2(t, s, p); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", p, rec.Code)
		}
	}
	if rec := postUI2Form(t, s, "/ui2/repeater/tabs/explode", url.Values{}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown action = %d", rec.Code)
	}
	body := postUI2Form(t, s, "/ui2/repeater/send", ui2RepeaterEditor(0, "", "GET / HTTP/1.1\n\n")).Body.String()
	if !strings.Contains(body, "no target") || atomic.LoadInt64(hits) != 0 {
		t.Errorf("targetless send not refused: %s", body)
	}
	body = postUI2Form(t, s, "/ui2/repeater/tabs/rename", url.Values{"tab_id": {"999"}, "name": {"x"}}).Body.String()
	if !strings.Contains(body, "has been closed") {
		t.Errorf("rename of a closed tab not refused")
	}
	body = postUI2Form(t, s, "/ui2/repeater/send-group", url.Values{"tab_id": {strconv.Itoa(ui2RepeaterTabs(s)[0].ID)}, "mode": {"parallel"}}).Body.String()
	if !strings.Contains(body, "in no group") || atomic.LoadInt64(hits) != 0 {
		t.Errorf("group send without a group not refused")
	}
}

func TestUI2RepeaterRequestFromURL(t *testing.T) {
	cases := []struct{ in, scheme, target, line string }{
		{"shop.test", "https", "https://shop.test", "GET / HTTP/1.1"},
		{"shop.test:8080/a?b=1", "http", "http://shop.test:8080", "GET /a?b=1 HTTP/1.1"},
		{"https://x.test/p", "http", "https://x.test", "GET /p HTTP/1.1"},
	}
	for _, c := range cases {
		target, raw, err := ui2RepeaterRequestFromURL(c.in, c.scheme)
		if err != nil || target != c.target || !strings.HasPrefix(raw, c.line+"\r\n") {
			t.Errorf("%q: target %q raw %q err %v", c.in, target, raw, err)
		}
	}
	if _, _, err := ui2RepeaterRequestFromURL("ftp://x", ""); err == nil {
		t.Errorf("ftp:// accepted")
	}
}
