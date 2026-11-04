package web

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/extscan"
	"os"
	"path/filepath"
)

// seedUI2DiscoveryRun records one finished run with one discovered row.
func seedUI2DiscoveryRun(s *Server) uint64 {
	const id = 4242
	s.discoveries.start(id, discoveryStartReq{Target: "https://disc.test/app/", Wordlist: "/w.txt"}, "https://disc.test/app/")
	s.discoveries.finish(id, "done", extscan.FFUFResult{
		Command: []string{"ffuf", "-u", "https://disc.test/app/FUZZ"},
		Discoveries: []extscan.Discovery{{URL: "https://disc.test/app/admin?x=1", Path: "/app/admin", Status: 403,
			Length: 12, Host: "disc.test", Redirect: "https://disc.test/<login>"}},
	}, nil)
	return id
}

func TestUI2DiscoveryPageSaysToolUnavailable(t *testing.T) {
	s := newTestServer()
	body := getUI2(t, s, "/ui2/discovery").Body.String()
	if !strings.Contains(body, "ffuf not available") || strings.Contains(body, `name="target"`) {
		t.Fatalf("an unallowlisted ffuf must replace the form with the reason: %s", body[:ui2Min(600, len(body))])
	}
}

func TestUI2DiscoveryRunsRowsAndActions(t *testing.T) {
	s := newTestServer()
	id := seedUI2DiscoveryRun(s)
	rec := getUI2(t, s, "/ui2/discovery/runs")
	body := rec.Body.String()
	for _, want := range []string{"#4242", "/app/admin", "ffuf -u https://disc.test/app/FUZZ",
		"/ui2/discovery/repeater?task=4242&amp;idx=0", `data-copy="https://disc.test/app/admin?x=1"`,
		"https://disc.test/&lt;login&gt;", "/ui2/history?q=host"} {
		if !strings.Contains(body, want) {
			t.Errorf("runs fragment lacks %q", want)
		}
	}
	if strings.Contains(body, "<login>") {
		t.Error("a redirect target reached the page unescaped")
	}
	if strings.Contains(body, `hx-trigger="every 2s"`) {
		t.Error("a finished run must not keep polling")
	}
	// Repeater draft: built from the URL, nothing sent.
	rep := getUI2(t, s, "/ui2/discovery/repeater?task=4242&idx=0").Body.String()
	if !strings.Contains(rep, "GET /app/admin?x=1 HTTP/1.1\r\nHost: disc.test") || !strings.Contains(rep, `value="https://disc.test"`) {
		t.Errorf("repeater draft not built from the discovered URL: %s", rep[:ui2Min(800, len(rep))])
	}
	if bad := getUI2(t, s, "/ui2/discovery/repeater?task=4242&idx=9").Body.String(); !strings.Contains(bad, "has no row 9") {
		t.Errorf("an unknown row must be a named refusal")
	}
	_ = id
}

func TestUI2DiscoveryLaunchReviewAndRun(t *testing.T) {
	s := newTestServer()
	s.externalTools = map[string]string{"ffuf": "/bin/true"}
	s.scope.AddInclude("disc.test")
	wl := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(wl, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"op": {"start"}, "target": {"https://disc.test/app/"}, "wordlist": {wl},
		"extensions": {"php,bak"}, "rate": {"7"}, "recurse_depth": {"2"}, "derivations": {"on"}}
	review := postUI2Form(t, s, "/ui2/discovery/review", form).Body.String()
	wantBody := `{"derivations":true,"extensions":"php,bak","rate":7,"recurse_depth":2,"target":"https://disc.test/app/","wordlist":"` + wl + `"}`
	if !strings.Contains(html.UnescapeString(review), "POST /api/discovery\n"+wantBody) || !strings.Contains(review, "gate confirmation") {
		t.Fatalf("review sheet must show the full gated body: %s", review)
	}
	id, tok := ui2ReviewFields(t, review)
	// A wrong token burns the review and dispatches nothing.
	bad := postUI2Form(t, s, "/ui2/discovery/run", url.Values{"review_id": {id}, "token": {tok + "x"}}).Body.String()
	if !strings.Contains(bad, "does not match") || len(s.discoveries.list()) != 0 {
		t.Fatalf("a wrong token must refuse without starting a sweep: %s", bad[:ui2Min(400, len(bad))])
	}
	review = postUI2Form(t, s, "/ui2/discovery/review", form).Body.String()
	id, tok = ui2ReviewFields(t, review)
	out := postUI2Form(t, s, "/ui2/discovery/run", url.Values{"review_id": {id}, "token": {tok}}).Body.String()
	if !strings.Contains(out, "started against https://disc.test/app/") || len(s.discoveries.list()) != 1 {
		t.Fatalf("the reviewed sweep did not start: %s", out[:ui2Min(600, len(out))])
	}
	// Single use: the same review cannot run twice.
	again := postUI2Form(t, s, "/ui2/discovery/run", url.Values{"review_id": {id}, "token": {tok}}).Body.String()
	if !strings.Contains(again, "already used") {
		t.Error("a spent review ran again")
	}
}

func TestUI2DiscoveryBrowserReviewRefusesUnknownRow(t *testing.T) {
	s := newTestServer()
	seedUI2DiscoveryRun(s)
	ok := postUI2Form(t, s, "/ui2/discovery/review", url.Values{"op": {"browser"}, "task": {"4242"}, "idx": {"0"}}).Body.String()
	if !strings.Contains(html.UnescapeString(ok), `POST /api/browser/launch`+"\n"+`{"url":"https://disc.test/app/admin?x=1"}`) {
		t.Fatalf("browser review lacks the exact call: %s", ok)
	}
	bad := postUI2Form(t, s, "/ui2/discovery/review", url.Values{"op": {"browser"}, "task": {"4242"}, "idx": {"3"}}).Body.String()
	if !strings.Contains(bad, "Not reviewed") || strings.Contains(bad, "review_id") {
		t.Fatal("an unknown row must not be held for review")
	}
}

func TestUI2DiscoveryWritesRefuseGET(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/ui2/discovery/review", "/ui2/discovery/run", "/ui2/dominvader/review", "/ui2/dominvader/run"} {
		if code := getUI2(t, s, p).Code; code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", p, code)
		}
	}
}
