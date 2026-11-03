package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

const ui2XAReq = "POST /api/login?next=%2Fhome&x=1 HTTP/1.1\r\nHost: shop.test\r\nCookie: sid=abc; theme=dark\r\nX-Probe: it's $(id)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 17\r\n\r\nuser=bob&pass=p%21"

func ui2XASeed(t *testing.T, s *Server) (core.ExchangeID, string) {
	t.Helper()
	id := seedUI2Exchange(t, s, ui2XAReq, "HTTP/1.1 200 OK\r\nSet-Cookie: session=xyz; HttpOnly\r\nContent-Length: 2\r\n\r\nok")
	return id, "/ui2/exchange/" + strconv.FormatUint(uint64(id), 10)
}

func TestUI2ExchangePageRendersSectionsAndMenu(t *testing.T) {
	s := newTestServer()
	_, base := ui2XASeed(t, s)
	rec := getUI2(t, s, base)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", base, rec.Code, rec.Body.String())
	}
	body := html.UnescapeString(rec.Body.String())
	for _, want := range []string{"<!doctype html", "back to history", "Query parameters", "next", "/home",
		"Body parameters", "pass", "p!", "Request cookies", "theme", "Cookies set by the response", "session",
		"Add to Organizer", "/ui2/repeater?msg_id=", "curl -i -X POST 'http://shop.test/api/login?next=%2Fhome&x=1'"} {
		if !strings.Contains(body, want) {
			t.Errorf("exchange page is missing %q", want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, base, nil)
	req.Header.Set("HX-Request", "true")
	frag := httptest.NewRecorder()
	s.mux.ServeHTTP(frag, req)
	if frag.Code != http.StatusOK || strings.Contains(frag.Body.String(), "<!doctype html") || !strings.Contains(frag.Body.String(), "Query parameters") {
		t.Fatalf("HX GET did not answer the fragment: %d", frag.Code)
	}
	if rec := getUI2(t, s, "/ui2/exchange/999"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown exchange = %d, want 404", rec.Code)
	}
}

func TestUI2ExchangeMenuFragment(t *testing.T) {
	s := newTestServer()
	_, base := ui2XASeed(t, s)
	rec := getUI2(t, s, base+"/menu")
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("menu = %d", rec.Code)
	}
	for _, want := range []string{"scope.confirm", "audit.confirm", "crawl-branch.confirm", "crawl-host.confirm", "/api/exchange/in-browser/", "slot=b", "sqlmap -u"} {
		if !strings.Contains(body, want) {
			t.Errorf("menu is missing %q", want)
		}
	}
	// The history detail pane, Logger and Site map rows are its entry points.
	if detail := getUI2(t, s, strings.Replace(base, "exchange", "history", 1)).Body.String(); !strings.Contains(detail, base+"/menu") {
		t.Errorf("history detail does not load the actions menu")
	}
	if sm := getUI2(t, s, "/ui2/sitemap").Body.String(); !strings.Contains(sm, `href="`+base+`"`) {
		t.Errorf("site map request row has no Actions link")
	}
}

func TestUI2ExchangeCommandsQuoteForTheShell(t *testing.T) {
	curl := ui2RawToCurl(ui2XAReq, "http://shop.test/a'b")
	for _, want := range []string{`'http://shop.test/a'\''b'`, `-H 'X-Probe: it'\''s $(id)'`, `--data-raw 'user=bob&pass=p%21'`} {
		if !strings.Contains(curl, want) {
			t.Errorf("curl %q is missing %q", curl, want)
		}
	}
	if strings.Contains(curl, "Content-Length") {
		t.Errorf("curl kept Content-Length: %s", curl)
	}
	sq := ui2RawToSqlmap(ui2XAReq, "http://shop.test/")
	if strings.Contains(sq, "Host:") || strings.Contains(sq, "--method") || !strings.Contains(sq, `--data='user=bob&pass=p%21'`) {
		t.Errorf("sqlmap command is wrong: %s", sq)
	}
}

func TestUI2ExchangeAnnotate(t *testing.T) {
	s := newTestServer()
	id, base := ui2XASeed(t, s)
	out := postUI2Form(t, s, base+"/annotate", url.Values{"highlight": {"red"}}).Body.String()
	if ex, _ := s.store.GetExchange(id); ex.Highlight != "red" || !strings.Contains(out, "Highlighted red") {
		t.Fatalf("highlight did not land (%q): %s", ex.Highlight, out)
	}
	postUI2Form(t, s, base+"/annotate", url.Values{"notes": {"check the reset flow"}})
	if ex, _ := s.store.GetExchange(id); ex.Notes == nil || *ex.Notes != "check the reset flow" {
		t.Fatalf("comment did not land: %v", ex.Notes)
	}
	// Refused: a colour outside the vocabulary, and a post carrying both fields.
	for _, f := range []url.Values{{"highlight": {"purple"}}, {"highlight": {"blue"}, "notes": {"x"}}} {
		out := postUI2Form(t, s, base+"/annotate", f).Body.String()
		if !strings.Contains(out, "Not applied") {
			t.Errorf("annotate %v was not refused: %s", f, out)
		}
	}
	if ex, _ := s.store.GetExchange(id); ex.Highlight != "red" || *ex.Notes != "check the reset flow" {
		t.Fatalf("a refused annotate changed the exchange: %q %q", ex.Highlight, *ex.Notes)
	}
}

func TestUI2ExchangeOrganizerAndIssue(t *testing.T) {
	s := newTestServer()
	id, base := ui2XASeed(t, s)
	if out := postUI2Form(t, s, base+"/organizer", url.Values{"extra": {"1"}}).Body.String(); !strings.Contains(out, "Not applied") || len(s.organizer.List()) != 0 {
		t.Fatalf("organizer add with a smuggled field was not refused: %s", out)
	}
	out := postUI2Form(t, s, base+"/organizer", url.Values{}).Body.String()
	if items := s.organizer.List(); len(items) != 1 || items[0].Exchange != int(id) || !strings.Contains(out, "added to Organizer") {
		t.Fatalf("organizer add did not land: %v %s", items, out)
	}

	if out := postUI2Form(t, s, base+"/issue", url.Values{"name": {" "}, "severity": {"high"}, "description": {""}}).Body.String(); !strings.Contains(out, "Not applied") || len(s.findings.All()) != 0 {
		t.Fatalf("nameless issue was not refused: %s", out)
	}
	out = postUI2Form(t, s, base+"/issue", url.Values{"name": {"Login CSRF"}, "severity": {"high"}, "description": {"no token"}}).Body.String()
	all := s.findings.All()
	if len(all) != 1 || all[0].Name != "Login CSRF" || !strings.Contains(out, "recorded against exchange") {
		t.Fatalf("issue was not recorded: %s", out)
	}
}

// ui2XAReview drives a gated confirm and returns the sheet and its token.
func ui2XAReview(t *testing.T, s *Server, base, kind string) (string, string) {
	t.Helper()
	sheet := postUI2Form(t, s, base+"/"+kind+".confirm", url.Values{}).Body.String()
	if strings.Contains(sheet, "Not applied") {
		t.Fatalf("%s confirm refused: %s", kind, sheet)
	}
	return html.UnescapeString(sheet), extractHiddenInput(t, sheet, "token")
}

func TestUI2ExchangeScopeIsReviewedThenRun(t *testing.T) {
	s := newTestServer()
	_, base := ui2XASeed(t, s)
	sheet, token := ui2XAReview(t, s, base, "scope")
	if !strings.Contains(sheet, `POST /api/scope`) || !strings.Contains(sheet, `{"action":"include","pattern":"shop.test","port":80,"protocol":"http"}`) || !strings.Contains(sheet, "data-arm-on-load") {
		t.Fatalf("review sheet does not show the full bound call: %s", sheet)
	}
	if len(s.scope.Rules()) != 0 {
		t.Fatal("the confirm step changed scope")
	}
	// Refused: a token that was never minted.
	if out := postUI2Form(t, s, base+"/scope.run", url.Values{"token": {"forged"}}).Body.String(); !strings.Contains(out, "Not applied") || len(s.scope.Rules()) != 0 {
		t.Fatalf("a forged token was not refused: %s", out)
	}
	out := postUI2Form(t, s, base+"/scope.run", url.Values{"token": {token}}).Body.String()
	if strings.Contains(out, "Not applied") || len(s.scope.Rules()) != 1 || !s.scope.Contains("shop.test", 80, "/", false) {
		t.Fatalf("reviewed scope rule did not land: %s", out)
	}
}

func TestUI2ExchangeAuditAndCrawlReviewShowFullBody(t *testing.T) {
	s := newTestServer()
	_, base := ui2XASeed(t, s)
	sheet, token := ui2XAReview(t, s, base, "crawl-branch")
	if !strings.Contains(sheet, `{"retention_query":"path ~ \"/api/\"","seeds":["http://shop.test/api/login?next=%2Fhome\u0026x=1"]}`) {
		t.Fatalf("crawl review does not show the full body: %s", sheet)
	}
	// A token minted for the branch crawl cannot run the host crawl: the body differs.
	if out := postUI2Form(t, s, base+"/crawl-host.run", url.Values{"token": {token}}).Body.String(); !strings.Contains(out, "Not applied") {
		t.Fatalf("a branch-crawl token ran a host crawl: %s", out)
	}
	sheet, _ = ui2XAReview(t, s, base, "audit")
	if !strings.Contains(sheet, "POST /api/audit/") || !strings.Contains(sheet, `{"async":true}`) {
		t.Fatalf("audit review does not show the full call: %s", sheet)
	}
}

func TestUI2ToolPagesAcceptAMsgIDSeed(t *testing.T) {
	s := newTestServer()
	msgID := seedUI2ExchangeMsgID(t, s, "GET /seeded HTTP/1.1\r\nHost: seed.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	seedUI2Exchange(t, s, "GET /newer HTTP/1.1\r\nHost: other.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	q := "?msg_id=" + strconv.FormatUint(msgID, 10)
	for _, p := range []string{"/ui2/repeater", "/ui2/intruder", "/ui2/sequencer", "/ui2/decoder", "/ui2/comparer"} {
		body := getUI2(t, s, p+q+"&slot=b").Body.String()
		if !(strings.Contains(body, "GET /seeded") || strings.Contains(body, `name="msg_id" value="`+strconv.FormatUint(msgID, 10)+`"`)) || !strings.Contains(body, "Loaded request message") {
			t.Errorf("%s did not load the seeded request", p)
		}
	}
	if body := getUI2(t, s, "/ui2/repeater"+q).Body.String(); !strings.Contains(body, `value="http://seed.test:80"`) {
		t.Errorf("repeater seed did not carry the exchange's target")
	}
	if body := getUI2(t, s, "/ui2/repeater?msg_id=1").Body.String(); !strings.Contains(body, "Not loaded") {
		t.Errorf("a response message id was loaded as a request seed")
	}
}
