package crawler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeLogin stands in for the browser replay: each successful call mints a new session token on the
// app and hands back the cookie a browser would hold.
type fakeLogin struct {
	app   *sessionApp
	fail  string
	calls atomic.Int64
}

func (f *fakeLogin) Label() string { return "alice (recorded)" }

func (f *fakeLogin) Login(context.Context) LoginAttempt {
	f.calls.Add(1)
	if f.fail != "" {
		return LoginAttempt{Reason: f.fail, Blocked: []string{"GET https://idp.example/authorize — out of scope"}}
	}
	token := f.app.mint()
	u, _ := url.Parse(f.app.srv.URL)
	return LoginAttempt{
		Succeeded: true, FinalURL: f.app.srv.URL + "/home",
		Cookies: []LoginCookie{
			{Name: "session", Value: token, Domain: u.Hostname(), HostOnly: true, Path: "/", HTTPOnly: true},
			// Path-scoped: must go only to /admin, which this crawl never visits.
			{Name: "admin_only", Value: "x", Domain: u.Hostname(), HostOnly: true, Path: "/admin"},
		},
	}
}

// sessionApp serves an application that is only reachable logged in. /home links to /account, which
// links to /profile; /profile rotates the session token with Set-Cookie and invalidates the old one, so
// /deep is only reachable if the crawl took the rotated cookie. /timeline invalidates every session, so
// /after needs a re-login.
type sessionApp struct {
	srv     *httptest.Server
	mu      sync.Mutex
	valid   map[string]bool
	n       int
	cookies []string // the Cookie header of every request, in order
}

func newSessionApp(t *testing.T) *sessionApp {
	app := &sessionApp{valid: map[string]bool{}}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>" + body + "</body></html>"))
	}
	app.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		app.cookies = append(app.cookies, r.Header.Get("Cookie"))
		app.mu.Unlock()
		// Logged out, every page is the login form at 200 — the shape the status-flip rule cannot
		// see and the login-page pattern exists for.
		c, err := r.Cookie("session")
		if r.URL.Path == "/robots.txt" || err != nil || !app.isValid(c.Value) {
			page(w, `<form action="/login" method="post"><input name="u"><input type="password" name="p"></form>`)
			return
		}
		switch r.URL.Path {
		case "/home":
			page(w, `<h1>Welcome</h1><p>home</p><a href="/account">Account</a>`)
		case "/account":
			page(w, `<table><tr><td>account</td><td><a href="/profile">Profile</a></td></tr></table>`)
		case "/profile":
			fresh := app.mint()
			app.mu.Lock()
			delete(app.valid, c.Value)
			app.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "session", Value: fresh, Path: "/"})
			page(w, `<ul><li>rotated</li><li><a href="/deep">Deep</a></li></ul>`)
		case "/deep":
			page(w, `<section><article><h2>deep</h2><nav><a href="/timeline">Timeline</a></nav></article></section>`)
		case "/timeline":
			app.mu.Lock()
			app.valid = map[string]bool{}
			app.mu.Unlock()
			page(w, `<dl><dt>expired</dt><dd><em>everyone</em></dd><dd><a href="/after">After</a></dd></dl>`)
		case "/after":
			page(w, `<main><h3>after</h3><blockquote>re-login</blockquote><pre>ok</pre></main>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(app.srv.Close)
	return app
}

func (a *sessionApp) mint() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	tok := "tok" + string(rune('A'+a.n))
	a.valid[tok] = true
	return tok
}

func (a *sessionApp) isValid(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.valid[tok]
}

func statusOf(rep Report, path string) int {
	for i := len(rep.Fetches) - 1; i >= 0; i-- {
		if u, _ := url.Parse(rep.Fetches[i].URL); u != nil && u.Path == path {
			return rep.Fetches[i].Status
		}
	}
	return 0
}

// The whole recorded-login story through crawler.Run: logged in before the first fetch, the session
// on every request, a rotated cookie followed, a lost session re-established by a second replay, and
// the report saying all of it — with no cookie value anywhere in it.
func TestARecordedLoginAuthenticatesTheWholeCrawlAndRecoversALostSession(t *testing.T) {
	app := newSessionApp(t)
	login := &fakeLogin{app: app}
	h := newHarness()
	cfg := h.config(app.srv.URL + "/home")
	cfg.BrowserLogin = login
	cfg.LoginPagePattern = `type="password"`
	rep := run(t, cfg)

	for _, path := range []string{"/home", "/account", "/profile", "/deep", "/after"} {
		if got := statusOf(rep, path); got != 200 {
			t.Errorf("%s: last status %d, want 200 (an authenticated page)", path, got)
		}
	}
	if login.calls.Load() != 2 {
		t.Errorf("the login ran %d times, want 2 (before the crawl, and once after /timeline)", login.calls.Load())
	}
	app.mu.Lock()
	for i, c := range app.cookies {
		if strings.Contains(c, "admin_only") {
			t.Errorf("request %d carried the /admin-scoped cookie: %q", i, c)
		}
	}
	app.mu.Unlock()

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Login map[string]any `json:"login"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Login == nil {
		t.Fatalf("no login block on the wire: %v", err)
	}
	want := map[string]any{"method": "recorded", "label": "alice (recorded)", "authenticated": true,
		"attempts": float64(2), "succeeded": float64(2), "failed": float64(0), "relogins": float64(1)}
	for k, v := range want {
		if wire.Login[k] != v {
			t.Errorf("login.%s = %v, want %v", k, wire.Login[k], v)
		}
	}
	if names, _ := wire.Login["cookie_names"].([]any); len(names) != 2 || names[0] != "admin_only" || names[1] != "session" {
		t.Errorf("cookie_names = %v", wire.Login["cookie_names"])
	}
	if blocked, ok := wire.Login["blocked"].([]any); !ok || len(blocked) != 0 {
		t.Errorf("blocked must be [] not null or missing: %v", wire.Login["blocked"])
	}
	if n, _ := wire.Login["pages_found_after_login"].(float64); int(n) != rep.Locations || n < 5 {
		t.Errorf("pages_found_after_login = %v, locations %d", wire.Login["pages_found_after_login"], rep.Locations)
	}
	if rb, ok := wire.Login["render_blocked"].([]any); !ok || len(rb) != 0 {
		t.Errorf("render_blocked must be []: %v", wire.Login["render_blocked"])
	}
	if n, _ := wire.Login["requests_with_session"].(float64); n < 6 {
		t.Errorf("requests_with_session = %v", wire.Login["requests_with_session"])
	}
	if strings.Contains(string(raw), "tokB") || strings.Contains(string(raw), "tokC") {
		t.Fatal("a session token is in the report")
	}
	for _, stop := range rep.Limits.Stops {
		if stop == StopLoginFailed {
			t.Error("a crawl that logged in must not carry login-failed")
		}
	}
}

// Burp: if the recorded login cannot be replayed the scan still runs, unauthenticated. Here it does
// too, and it is a stop — the crawl reads incomplete, never done.
func TestAFailedRecordedLoginIsAStopAndTheCrawlRunsLoggedOut(t *testing.T) {
	app := newSessionApp(t)
	login := &fakeLogin{app: app, fail: "step 3 (Click on #next) failed: no element matched within 10s"}
	h := newHarness()
	cfg := h.config(app.srv.URL + "/home")
	cfg.BrowserLogin = login
	cfg.LoginPagePattern = `type="password"`
	rep := run(t, cfg)

	if rep.Login == nil || rep.Login.Authenticated || rep.Login.Failed < 1 ||
		!strings.Contains(rep.Login.LastFailure, "step 3") || len(rep.Login.Blocked) != 1 {
		t.Fatalf("login block = %+v", rep.Login)
	}
	if rep.Login.PagesFoundAfterLogin != 0 {
		t.Fatalf("a failed login found %d pages after login", rep.Login.PagesFoundAfterLogin)
	}
	if !rep.Limits.Hit(StopLoginFailed) || rep.Complete() {
		t.Fatalf("stops %v: a crawl whose login failed must not be complete", rep.Limits.Stops)
	}
	if statusOf(rep, "/account") == 200 {
		t.Fatal("an unauthenticated crawl reached an authenticated page")
	}
}

// Without a recorded login nothing changes: no login block, and no Cookie header the operator did not
// send.
func TestACrawlWithoutARecordedLoginHasNoLoginBlock(t *testing.T) {
	app := newSessionApp(t)
	h := newHarness()
	rep := run(t, h.config(app.srv.URL+"/home"))
	if rep.Login != nil {
		t.Fatalf("login block on a crawl with no recorded login: %+v", rep.Login)
	}
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), `"login"`) {
		t.Fatal(`"login" is on the wire for a crawl with no recorded login`)
	}
}
