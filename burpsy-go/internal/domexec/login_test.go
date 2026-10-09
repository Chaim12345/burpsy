package domexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/security"
)

// testGate allows exactly one authority and refuses one path prefix on it.
type testGate struct {
	host       string
	port       uint16
	denyPrefix string
}

func (g testGate) AllowURL(u *url.URL) error {
	port, _ := strconv.Atoi(u.Port())
	if u.Hostname() != g.host || uint16(port) != g.port {
		return fmt.Errorf("%s is out of scope", u.Host)
	}
	if g.denyPrefix != "" && strings.HasPrefix(u.Path, g.denyPrefix) {
		return fmt.Errorf("%s is out of scope", u.Path)
	}
	return nil
}

func (g testGate) AllowAuthority(host string, port uint16, _ bool) error {
	if host != g.host || port != g.port {
		return errors.New(host + " is out of scope")
	}
	return nil
}

// loginApp is a three-page login — username, then password, then a one-time code — whose pages also
// try every way a page can reach outside scope: an out-of-scope image, a fetch that 302s to another
// host, a cross-site iframe (out of process under site isolation), a popup, and an in-scope host's
// out-of-scope path.
type loginApp struct {
	srv     *httptest.Server
	outside *httptest.Server
	// outsideHits counts every request the out-of-scope server received. It must stay zero.
	outsideHits atomic.Int64
	privateHits atomic.Int64
	mu          sync.Mutex
	seenOTP     []string
}

func newLoginApp(t *testing.T) *loginApp {
	t.Helper()
	app := &loginApp{}
	app.outside = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.outsideHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<p>outside</p>"))
	}))
	t.Cleanup(app.outside.Close)
	_, outPort, _ := strings.Cut(strings.TrimPrefix(app.outside.URL, "http://"), ":")
	outside := app.outside.URL                   // 127.0.0.1 on another port
	outsideSite := "http://localhost:" + outPort // a different site, so the iframe runs out of process
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>" + body + "</body></html>"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.FormValue("user") != "alice" {
				http.Error(w, "who?", 403)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "stage", Value: "user-ok", Path: "/"})
			http.Redirect(w, r, "/password", http.StatusFound)
			return
		}
		page(w, `<form method="post" action="/login"><input id="username" name="user"><button id="next">Next</button></form>
<img src="`+outside+`/pixel.gif"><img src="/private/pixel.gif">
<iframe src="`+outsideSite+`/frame"></iframe>
<script>fetch("/bounce"); try { window.open("`+outside+`/popup"); } catch (e) {}</script>`)
	})
	mux.HandleFunc("/bounce", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outside+"/bounced", http.StatusFound)
	})
	mux.HandleFunc("/private/", func(w http.ResponseWriter, r *http.Request) { app.privateHits.Add(1) })
	mux.HandleFunc("/password", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("stage"); err != nil || c.Value != "user-ok" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			if r.FormValue("pass") != "hunter2" {
				http.Error(w, "wrong password", 403)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "stage", Value: "pass-ok", Path: "/"})
			// An SSO-shaped hop: the state value is a token, and must not reach a result.
			http.Redirect(w, r, "/mfa?state=s3cr3t-state", http.StatusFound)
			return
		}
		// Rendered from script after load, so a replay that does not wait for its element fails.
		page(w, `<div id="f"></div><script>setTimeout(function(){document.getElementById("f").innerHTML =
'<form method="post" action="/password"><input type="password" name="pass"></form>';}, 400);</script>`)
	})
	mux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("stage"); err != nil || c.Value != "pass-ok" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			app.mu.Lock()
			app.seenOTP = append(app.seenOTP, r.FormValue("otp"))
			app.mu.Unlock()
			if r.FormValue("otp") != "123456" {
				http.Error(w, "bad code", 403)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "authenticated", Path: "/", HttpOnly: true})
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		page(w, `<form method="post" action="/mfa"><input id="otp" name="otp"><button id="verify">Verify</button></form>`)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "authenticated" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		page(w, `<h1>Welcome alice</h1><a href="/account">Account</a> <a href="/logout">Sign out</a>`)
	})
	app.srv = httptest.NewServer(mux)
	t.Cleanup(app.srv.Close)
	return app
}

func (app *loginApp) gate(t *testing.T) testGate {
	u, _ := url.Parse(app.srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return testGate{host: u.Hostname(), port: uint16(port), denyPrefix: "/private/"}
}

func (app *loginApp) actions(code func(context.Context) (string, error)) []LoginAction {
	return []LoginAction{
		{Kind: "goto", URL: app.srv.URL + "/login", Description: "Navigate to /login"},
		{Kind: "type", Selector: "#username", Text: "alice", Description: "Type 'alice' into #username"},
		{Kind: "click", Selector: "#next", Description: "Click on #next"},
		{Kind: "type", Selector: `input[name="pass"]`, Text: "hunter2", Description: "Type a secret value into the password"},
		{Kind: "key", Key: "Enter", Description: "Press Enter key"},
		{Kind: "type", Selector: "#nope", XPath: "/html/body/form/input", Code: code, Description: "Type TOTP code into #otp"},
		{Kind: "click", Selector: "#verify", Description: "Click on #verify"},
	}
}

func TestARecordedLoginReplaysMultiStepWithTOTPAndEarnsTheSessionCookie(t *testing.T) {
	b := newTestBrowser(t)
	app := newLoginApp(t)
	sess, err := b.NewSession(app.gate(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	codes := 0
	rep := sess.ReplayLogin(ctx, app.actions(func(context.Context) (string, error) { codes++; return "123456", nil }),
		&LoginCheck{URL: app.srv.URL + "/home", Text: "Welcome alice"})
	if !rep.Succeeded {
		t.Fatalf("replay failed: %s\nsteps: %+v\nblocked: %v", rep.Reason, rep.Steps, rep.Blocked)
	}
	if !rep.Verified {
		t.Fatal("a replay whose status check found its text must be verified")
	}
	if codes != 1 {
		t.Errorf("the TOTP code function ran %d times, want once", codes)
	}
	if !strings.HasSuffix(rep.FinalURL, "/home") || rep.Check == nil || !rep.Check.Found {
		t.Errorf("final %q check %+v", rep.FinalURL, rep.Check)
	}
	var got string
	for _, c := range rep.Cookies {
		if c.Name == "session" {
			got = c.Value
		}
	}
	if got != "authenticated" {
		t.Fatalf("the session cookie was not earned: %+v", rep.Cookies)
	}
	if len(rep.Screenshot) == 0 {
		t.Error("no final screenshot")
	}
	for _, s := range rep.Steps {
		if strings.Contains(s.Description+s.Error, "hunter2") {
			t.Fatalf("a step result carries the password: %+v", s)
		}
	}
	// The redirect's token is redacted from the per-step URLs, its parameter name kept.
	if raw, _ := json.Marshal(rep); strings.Contains(string(raw), "s3cr3t-state") || !strings.Contains(string(raw), "state=…") {
		t.Fatalf("step URLs must keep the parameter name and drop its value: %s", raw)
	}

	// The scope gate, positive-controlled: every way the login page reached outside scope was tried,
	// and the out-of-scope server saw none of it.
	if n := app.outsideHits.Load(); n != 0 {
		t.Fatalf("the out-of-scope server received %d request(s) during the replay", n)
	}
	if n := app.privateHits.Load(); n != 0 {
		t.Fatalf("the in-scope host's out-of-scope path received %d request(s)", n)
	}
	blocked := strings.Join(rep.Blocked, "\n")
	for _, want := range []string{"/pixel.gif", "/private/pixel.gif", "/bounced"} {
		if !strings.Contains(blocked, want) {
			t.Errorf("blocked list does not name %s:\n%s", want, blocked)
		}
	}
}

func TestAReplayThatFailsNamesTheStepAndTheReason(t *testing.T) {
	b := newTestBrowser(t)
	app := newLoginApp(t)
	sess, err := b.NewSession(app.gate(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// The wrong code: every step runs, the server refuses it, and only the status check can tell.
	rep := sess.ReplayLogin(ctx, app.actions(func(context.Context) (string, error) { return "000000", nil }),
		&LoginCheck{URL: app.srv.URL + "/home", Text: "Welcome alice"})
	if rep.Succeeded || !strings.Contains(rep.Reason, "confirmation text") {
		t.Fatalf("a refused code must fail the status check, got succeeded=%v reason=%q", rep.Succeeded, rep.Reason)
	}
	// A missing element fails on its own step, named.
	acts := app.actions(nil)[:2]
	acts[1].Selector = "#not-there"
	rep = sess.ReplayLogin(ctx, acts, nil)
	if rep.Succeeded || !strings.Contains(rep.Reason, "step 2") || !strings.Contains(rep.Reason, "no element matched") {
		t.Fatalf("got %q", rep.Reason)
	}
}

// Two sessions do not share a jar, and neither shares the default context's: the login's cookie must
// not leak into the browser the DOM checks use.
func TestSessionsAreIsolatedFromEachOtherAndFromTheDefaultContext(t *testing.T) {
	b := newTestBrowser(t)
	app := newLoginApp(t)
	one, err := b.NewSession(app.gate(t))
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rep := one.ReplayLogin(ctx, app.actions(func(context.Context) (string, error) { return "123456", nil }), nil)
	if !rep.Succeeded {
		t.Fatalf("replay failed: %s", rep.Reason)
	}
	if rep.Verified {
		t.Fatal("a replay with no status check is not verified — nothing checked that it logged in")
	}
	// The logged-in session renders /home; a second session and the default context are sent to the
	// login page.
	html, _, err := one.RenderedDOMWithOptions(ctx, app.srv.URL+"/home", RenderOptions{})
	if err != nil || !strings.Contains(html, "Welcome alice") {
		t.Fatalf("the session's own render is not logged in: %v %q", err, html)
	}
	two, err := b.NewSession(app.gate(t))
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	html, _, err = two.RenderedDOMWithOptions(ctx, app.srv.URL+"/home", RenderOptions{})
	if err != nil || strings.Contains(html, "Welcome alice") {
		t.Fatalf("a second session saw the first one's login: %v", err)
	}
	html, err = b.RenderedDOM(ctx, app.srv.URL+"/home")
	if err != nil || strings.Contains(html, "Welcome alice") {
		t.Fatalf("the default context saw the session's login: %v", err)
	}
}

// Over HTTPS the proxy sees only CONNECT host:port, so the in-scope host's out-of-scope PATH is
// stopped by the Fetch gate alone — this is the test that fails if that gate continues everything.
func TestOverHTTPSTheFetchGateStopsAnOutOfScopePathOnAnInScopeHost(t *testing.T) {
	b := newTestBrowser(t)
	var private, public atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/private/"):
			private.Add(1)
		case r.URL.Path == "/":
			public.Add(1)
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><h1>hello</h1><img src="/private/pixel.gif"><script>fetch("/private/api")</script></body></html>`))
		}
	}))
	defer srv.Close()
	// The test server's certificate is self-signed; trusting it is a test-only knob on the test's own
	// browser, never set by production code.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ex, err := b.browserExecutor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := security.SetIgnoreCertificateErrors(true).Do(ex); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = security.SetIgnoreCertificateErrors(false).Do(ex) }()

	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	sess, err := b.NewSession(testGate{host: u.Hostname(), port: uint16(port), denyPrefix: "/private/"})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	rep := sess.ReplayLogin(ctx, []LoginAction{{Kind: "goto", URL: srv.URL + "/", Description: "Navigate to /"}}, nil)
	if !rep.Succeeded {
		t.Fatalf("replay failed: %s %v", rep.Reason, rep.Blocked)
	}
	if public.Load() == 0 {
		t.Fatal("positive control: the in-scope page itself was never loaded, so nothing was tested")
	}
	if n := private.Load(); n != 0 {
		t.Fatalf("the out-of-scope path received %d request(s) over HTTPS", n)
	}
	if !strings.Contains(strings.Join(rep.Blocked, "\n"), "/private/pixel.gif") {
		t.Fatalf("blocked list: %v", rep.Blocked)
	}
}

// twoNameGate allows one server under two names — 127.0.0.1 and localhost are different SITES, so a
// frame from one inside a page from the other runs out of process.
type twoNameGate struct{ port uint16 }

func (g twoNameGate) AllowURL(u *url.URL) error {
	return g.AllowAuthority(u.Hostname(), func() uint16 { p, _ := strconv.Atoi(u.Port()); return uint16(p) }(), false)
}

func (g twoNameGate) AllowAuthority(host string, port uint16, _ bool) error {
	if (host == "127.0.0.1" || host == "localhost") && port == g.port {
		return nil
	}
	return errors.New(host + " is out of scope")
}

// An in-scope cross-site iframe runs in its own renderer, and the page's Fetch interception does not
// see that renderer's requests. Its out-of-scope image is stopped by the session's proxy alone — this
// is the test that fails if the proxy lets everything through.
func TestTheSessionProxyStopsWhatAnOutOfProcessFrameLoads(t *testing.T) {
	b := newTestBrowser(t)
	var outside, framed atomic.Int64
	out := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outside.Add(1) }))
	defer out.Close()
	var srvPort string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><body><h1>top</h1><iframe src="http://localhost:` + srvPort + `/frame"></iframe></body></html>`))
		case "/frame":
			framed.Add(1)
			_, _ = w.Write([]byte(`<html><body><img src="` + out.URL + `/pixel.gif"><script>fetch("` + out.URL + `/api")</script></body></html>`))
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	srvPort = u.Port()
	port, _ := strconv.Atoi(srvPort)
	sess, err := b.NewSession(twoNameGate{port: uint16(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep := sess.ReplayLogin(ctx, []LoginAction{
		{Kind: "goto", URL: srv.URL + "/", Description: "Navigate to /"},
		{Kind: "wait", Wait: 1500 * time.Millisecond, Description: "Wait"},
	}, nil)
	if !rep.Succeeded {
		t.Fatalf("replay failed: %s %v", rep.Reason, rep.Blocked)
	}
	if framed.Load() == 0 {
		t.Fatal("positive control: the cross-site frame never loaded, so nothing was tested")
	}
	if n := outside.Load(); n != 0 {
		t.Fatalf("the out-of-scope server received %d request(s) from the out-of-process frame", n)
	}
}

func TestRedactURLKeepsTheShapeAndDropsTheTokens(t *testing.T) {
	for in, want := range map[string]string{
		"https://idp.example/cb?code=SplxlOBeZQ&state=af0ifjsldkj":    "https://idp.example/cb?code=…&state=…",
		"https://app.example/#access_token=eyJ.x.y&token_type=bearer": "https://app.example/#…",
		"https://u:p@app.example/home":                                "https://app.example/home",
		"https://app.example/home":                                    "https://app.example/home",
		"https://app.example/search?flag&q=secret":                    "https://app.example/search?flag&q=…",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// A self-signed target fails on its certificate, named — unless the session was told to accept it,
// and that permission stays inside the session: the shared browser's own tabs keep verifying.
func TestIgnoringCertificateErrorsIsScopedToTheSession(t *testing.T) {
	b := newTestBrowser(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h1>staging</h1></body></html>`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	gate := testGate{host: u.Hostname(), port: uint16(port)}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	steps := []LoginAction{{Kind: "goto", URL: srv.URL + "/", Description: "Navigate to /"}}

	strict, err := b.NewSession(gate)
	if err != nil {
		t.Fatal(err)
	}
	rep := strict.ReplayLogin(ctx, steps, nil)
	strict.Close()
	if rep.Succeeded || !strings.Contains(rep.Reason, "certificate is not trusted") {
		t.Fatalf("an untrusted certificate must fail step 1, named: %q", rep.Reason)
	}

	relaxed, err := b.NewSession(gate)
	if err != nil {
		t.Fatal(err)
	}
	defer relaxed.Close()
	relaxed.IgnoreCertificateErrors(true)
	rep = relaxed.ReplayLogin(ctx, steps, nil)
	if !rep.Succeeded {
		t.Fatalf("a session told to accept the certificate failed: %q", rep.Reason)
	}
	// The default context — the DOM checks' — still refuses it.
	if html, err := b.RenderedDOM(ctx, srv.URL+"/"); err == nil && strings.Contains(html, "staging") {
		t.Fatal("the session's certificate relaxation leaked into the shared browser")
	}
}
