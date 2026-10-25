package crawler

// burpsy-react-ui-crediso: per-credential frontier isolation. Burp re-crawls per credential set
// with phased frontier isolation: the unauthenticated phase runs first, then each credential in
// turn gets its own crawl behind its own login — per-phase state, no cross-credential leakage.
// uzil shipped sequential per-credential LOGIN sessions inside one shared frontier, which both
// under-covers (content behind the first login is invisible to the second) and leaks (a page one
// credential discovered is fetched under another's session).

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// isolationApp has one login form and two accounts whose post-login content differs:
// alice's account links /alice-only, bob's links /bob-only, and each private page answers only
// its owner's session. /account is linked from the login page too, so the unauthenticated phase
// bounces off it (403) — Burp's per-credential phases are what reach it authenticated.
type isolationApp struct {
	srv *httptest.Server
	mu  sync.Mutex
	// fetches are "PATH cookie=" entries, one per GET the app saw.
	fetches []string
}

func newIsolationApp(t *testing.T) *isolationApp {
	t.Helper()
	app := &isolationApp{}
	mux := http.NewServeMux()
	record := func(r *http.Request) string {
		c, _ := r.Cookie("session")
		cv := ""
		if c != nil {
			cv = c.Value
		}
		app.mu.Lock()
		app.fetches = append(app.fetches, r.URL.Path+" cookie="+cv)
		app.mu.Unlock()
		return cv
	}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>` + body + `</body></html>`))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		page(w, `<a href="/login">sign in</a>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			vals, _ := url.ParseQuery(string(body))
			switch vals.Get("user") + "/" + vals.Get("pass") {
			case "alice/s3cret":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "aaa", Path: "/"})
			case "bob/hunter2":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "bbb", Path: "/"})
			}
			page(w, `<a href="/account">my account</a>`)
			return
		}
		// The login page links the account page as well: the unauthenticated phase discovers it,
		// bounces (403), and only a credential phase's session reaches it.
		page(w, `<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			</form><a href="/account">account</a>`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		cv := record(r)
		switch cv {
		case "aaa":
			page(w, `<p>alice</p><a href="/alice-only">alice only</a>`)
		case "bbb":
			page(w, `<p>bob</p><a href="/bob-only">bob only</a>`)
		default:
			w.WriteHeader(http.StatusForbidden)
			page(w, `<p>forbidden</p>`)
		}
	})
	private := func(owner string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			cv := record(r)
			if cv != owner {
				w.WriteHeader(http.StatusForbidden)
				page(w, `<p>forbidden</p>`)
				return
			}
			page(w, `<p>private</p>`)
		}
	}
	mux.HandleFunc("/alice-only", private("aaa"))
	mux.HandleFunc("/bob-only", private("bbb"))
	app.srv = httptest.NewServer(mux)
	t.Cleanup(app.srv.Close)
	return app
}

func (a *isolationApp) fetchedWith(path, cookie string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, f := range a.fetches {
		if f == path+" cookie="+cookie {
			return true
		}
	}
	return false
}

// The isolation invariant: each credential's crawl reaches the content behind ITS login, under
// ITS session, and no page one credential's crawl discovered is fetched under the other's.
func TestEachCredentialCrawlsBehindItsOwnLogin(t *testing.T) {
	app := newIsolationApp(t)
	h := newHarness()
	cfg := h.config(app.srv.URL + "/")
	cfg.SubmitForms = true
	cfg.LoginCredentials = []LoginCredential{
		{Username: "alice", Password: "s3cret"},
		{Username: "bob", Password: "hunter2"},
	}
	rep := run(t, cfg)

	// Coverage: each credential's private content is reached, under its own session.
	if !app.fetchedWith("/alice-only", "aaa") {
		t.Errorf("/alice-only was never fetched with alice's session; fetches: %v", app.fetches)
	}
	if !app.fetchedWith("/bob-only", "bbb") {
		t.Errorf("/bob-only was never fetched with bob's session; fetches: %v", app.fetches)
	}
	// Isolation: never under the other credential's session.
	if app.fetchedWith("/alice-only", "bbb") {
		t.Errorf("/alice-only was fetched under bob's session — cross-credential leakage; fetches: %v", app.fetches)
	}
	if app.fetchedWith("/bob-only", "aaa") {
		t.Errorf("/bob-only was fetched under alice's session — cross-credential leakage; fetches: %v", app.fetches)
	}
	// The phased re-crawl: the page the unauthenticated phase bounced off is re-fetched WITH each
	// session — under both credentials, because each phase crawls behind its own login.
	if !app.fetchedWith("/account", "") {
		t.Errorf("/account was never probed unauthenticated; fetches: %v", app.fetches)
	}
	if !app.fetchedWith("/account", "aaa") || !app.fetchedWith("/account", "bbb") {
		t.Errorf("/account must be crawled under EACH credential's session; fetches: %v", app.fetches)
	}
	if rep.Login == nil || rep.Login.Attempts != 2 || rep.Login.Succeeded != 2 {
		t.Errorf("login block = %+v, want one successful login per credential", rep.Login)
	}
}

// ---- Pre-review round: a phase boundary is a WHOLE-session boundary ---------------------------------

// A failed credential phase is UNAUTHENTICATED. Nothing from the previous phase's session may
// leak into it: not the jar, not the report's Authenticated flag, and not the re-login closure,
// which belongs to the phase whose login built it.
func TestAFailedCredentialPhaseStaysUnauthenticated(t *testing.T) {
	var mu sync.Mutex
	var fetches []string
	var loginPosts []string
	record := func(r *http.Request) string {
		c, _ := r.Cookie("session")
		cv := ""
		if c != nil {
			cv = c.Value
		}
		mu.Lock()
		fetches = append(fetches, r.URL.Path+" cookie="+cv)
		mu.Unlock()
		return cv
	}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>` + body + `</body></html>`))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		page(w, `<a href="/login">sign in</a>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			mu.Lock()
			loginPosts = append(loginPosts, string(body))
			mu.Unlock()
			if vals, _ := url.ParseQuery(string(body)); vals.Get("user") == "alice" && vals.Get("pass") == "s3cret" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "aaa", Path: "/"})
				page(w, `<a href="/account">my account</a>`)
				return
			}
			// The failure page: no session, and the text the operator's login-page pattern names.
			page(w, `<p>bad credentials</p><a href="/recover">recover</a>`)
			return
		}
		page(w, `<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			</form><a href="/account">account</a>`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if cv := record(r); cv != "aaa" {
			w.WriteHeader(http.StatusForbidden)
			page(w, `<p>forbidden</p>`)
			return
		}
		page(w, `<p>alice</p>`)
	})
	// Every page the failed phase reaches carries the failure text: the expiry detector fires on
	// it, and the re-login path must not answer with the previous phase's login.
	mux.HandleFunc("/recover", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		page(w, `<p>bad credentials</p>`)
	})
	mux.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		if cv := record(r); cv != "aaa" {
			w.WriteHeader(http.StatusForbidden)
			page(w, `<p>forbidden</p>`)
			return
		}
		page(w, `<p>secret</p>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	// /private is reached only as a seed: the unauthenticated phase bounces off it (403), and the
	// challenged re-fetch is the only way a credential phase reaches it.
	cfg := h.config(srv.URL+"/", srv.URL+"/private")
	cfg.SubmitForms = true
	cfg.LoginPagePattern = "bad credentials"
	cfg.LoginCredentials = []LoginCredential{
		{Username: "alice", Password: "s3cret"},
		{Username: "bob", Password: "wrong"},
	}
	rep := run(t, cfg)

	count := func(want string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, f := range fetches {
			if f == want {
				n++
			}
		}
		return n
	}
	// The unauthenticated phase bounced off both pages; alice's phase re-fetched both WITH her
	// session. Bob's phase failed its login, so nothing was re-fetched for it: a failed phase is
	// unauthenticated, not "the previous phase's session, continued".
	if n := count("/account cookie="); n != 1 {
		t.Errorf("/account unauthenticated fetches = %d, want 1 (phase 0 only)", n)
	}
	if n := count("/account cookie=aaa"); n != 1 {
		t.Errorf("/account fetches with alice's session = %d, want 1", n)
	}
	if n := count("/private cookie="); n != 1 {
		t.Errorf("/private unauthenticated fetches = %d, want 1 (phase 0 only)", n)
	}
	if n := count("/private cookie=aaa"); n != 1 {
		t.Errorf("/private fetches with alice's session = %d, want 1", n)
	}
	// The report describes the phase the crawl ENDED in: bob's, which never authenticated.
	if rep.Login == nil || rep.Login.Authenticated {
		t.Errorf("login block = %+v, want the crawl ending unauthenticated: the last phase's login failed", rep.Login)
	}
	// ...but what ALICE's login unlocked is not un-found by bob's failure: /account and /private
	// behind her session are pages found after A login.
	if rep.Login != nil && rep.Login.PagesFoundAfterLogin < 2 {
		t.Errorf("PagesFoundAfterLogin = %d, want >= 2 — the failed final phase does not zero what alice's login unlocked", rep.Login.PagesFoundAfterLogin)
	}
	// Phase 2's expiry-looking page must not re-run phase 1's login: alice's credentials are sent
	// exactly once, in her own phase.
	mu.Lock()
	alicePosts := 0
	for _, p := range loginPosts {
		if vals, _ := url.ParseQuery(p); vals.Get("user") == "alice" {
			alicePosts++
		}
	}
	mu.Unlock()
	if alicePosts != 1 {
		t.Errorf("login submissions carrying alice's credentials = %d, want 1 — a later phase must never invoke an earlier phase's re-login", alicePosts)
	}
	// The refusal is recorded, not silent: the expiry signal inside an unauthenticated phase is a
	// re-login that cannot run, named as one.
	if rep.Skips.Count(SkipReloginFailed) == 0 {
		t.Errorf("no SkipReloginFailed recorded for the expiry signal inside the failed phase")
	}
}

// A phase's first act goes through the same gates as every other send: an exhausted request
// budget refuses the next phase's login outright, and the refusal is the named stop.
func TestAnExhaustedRequestBudgetRefusesTheNextPhaseLogin(t *testing.T) {
	var mu sync.Mutex
	posts := map[string]int{}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>` + body + `</body></html>`))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<a href="/login">sign in</a>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			vals, _ := url.ParseQuery(string(body))
			mu.Lock()
			posts[vals.Get("user")]++
			mu.Unlock()
			switch vals.Get("user") + "/" + vals.Get("pass") {
			case "alice/s3cret":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "aaa", Path: "/"})
			case "bob/hunter2":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "bbb", Path: "/"})
			}
			page(w, `<a href="/account">my account</a>`)
			return
		}
		page(w, `<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			</form><a href="/account">account</a>`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("session")
		cv := ""
		if c != nil {
			cv = c.Value
		}
		switch cv {
		case "aaa":
			page(w, `<p>alice</p><a href="/alice-only">alice only</a>`)
		case "bbb":
			page(w, `<p>bob</p><a href="/bob-only">bob only</a>`)
		default:
			w.WriteHeader(http.StatusForbidden)
			page(w, `<p>forbidden</p>`)
		}
	})
	mux.HandleFunc("/alice-only", func(w http.ResponseWriter, r *http.Request) { page(w, `<p>a</p>`) })
	mux.HandleFunc("/bob-only", func(w http.ResponseWriter, r *http.Request) { page(w, `<p>b</p>`) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.LoginCredentials = []LoginCredential{
		{Username: "alice", Password: "s3cret"},
		{Username: "bob", Password: "hunter2"},
	}
	// The unauthenticated phase spends 4 requests (/, /robots.txt, /login, /account) and alice's
	// phase 3 (the login, the challenged /account re-fetch, /alice-only): the budget runs out
	// exactly as alice's phase drains, so bob's phase begins with nothing left.
	cfg.Limits = Limits{MaxRequests: 7}
	rep := run(t, cfg)

	mu.Lock()
	alicePosts, bobPosts := posts["alice"], posts["bob"]
	mu.Unlock()
	if alicePosts != 1 {
		t.Errorf("alice's login submissions = %d, want 1", alicePosts)
	}
	if bobPosts != 0 {
		t.Errorf("bob's login was sent %d times with the request budget spent — the phase-start login must pass the same budget gate as every other send", bobPosts)
	}
	if !rep.Limits.Hit(StopRequestBudget) {
		t.Errorf("stops = %v, want StopRequestBudget: an exhausted budget refusing the next phase's login is the named stop, not a silent skip", rep.Limits.Stops)
	}
}

// A follow-up retry is the same request sent again under the SAME session. The phase boundary
// retires that session, so a retry its phase never recovered is abandoned with a recorded count —
// never sent under the next phase's.
func TestAFollowUpRetryNeverFiresUnderAnotherPhaseSession(t *testing.T) {
	var mu sync.Mutex
	var fetches []string
	record := func(r *http.Request) string {
		c, _ := r.Cookie("session")
		cv := ""
		if c != nil {
			cv = c.Value
		}
		mu.Lock()
		fetches = append(fetches, r.URL.Path+" cookie="+cv)
		mu.Unlock()
		return cv
	}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>` + body + `</body></html>`))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		page(w, `<a href="/login">sign in</a>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			vals, _ := url.ParseQuery(string(body))
			switch vals.Get("user") + "/" + vals.Get("pass") {
			case "alice/s3cret":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "aaa", Path: "/"})
			case "bob/hunter2":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "bbb", Path: "/"})
			}
			page(w, `<a href="/account">my account</a>`)
			return
		}
		page(w, `<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			</form><a href="/account">account</a>`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		switch cv := record(r); cv {
		case "aaa", "bbb":
			page(w, `<p>account</p><a href="/flaky">flaky</a>`)
		default:
			w.WriteHeader(http.StatusForbidden)
			page(w, `<p>forbidden</p>`)
		}
	})
	mux.HandleFunc("/flaky", func(w http.ResponseWriter, r *http.Request) {
		switch cv := record(r); cv {
		case "aaa":
			// A transport failure, not an HTTP error: the connection is dropped mid-request.
			// Alice's /flaky never recovers, so the retry is still owed when the phase ends.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		case "bbb":
			page(w, `<p>ok</p>`)
		default:
			w.WriteHeader(http.StatusForbidden)
			page(w, `<p>forbidden</p>`)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.ErrorHandling = ErrorHandling{FollowUpPasses: intp(1)}
	cfg.LoginCredentials = []LoginCredential{
		{Username: "alice", Password: "s3cret"},
		{Username: "bob", Password: "hunter2"},
	}
	rep := run(t, cfg)

	count := func(want string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, f := range fetches {
			if f == want {
				n++
			}
		}
		return n
	}
	// Alice's phase fetched /flaky and retried it once — both under HER session.
	if n := count("/flaky cookie=aaa"); n != 2 {
		t.Errorf("/flaky fetches with alice's session = %d, want 2 (the original + one retry inside her phase)", n)
	}
	// Bob's phase fetched /flaky once, successfully. Alice's owed retry must never carry his
	// session: re-issuing her request under his session is a different request.
	if n := count("/flaky cookie=bbb"); n != 1 {
		t.Errorf("/flaky fetches with bob's session = %d, want 1 — alice's owed retry must never fire under bob's session", n)
	}
	// Abandoned, and the abandonment is counted: the retry alice's phase never recovered did not
	// vanish from the report.
	if rep.Limits.PhaseDropped != 1 {
		t.Errorf("PhaseDropped = %d, want 1 (alice's unrecovered retry abandoned at the phase boundary)", rep.Limits.PhaseDropped)
	}
	if rep.Skips.Count(SkipPhaseAbandoned) != 1 {
		t.Errorf("SkipPhaseAbandoned count = %d, want 1", rep.Skips.Count(SkipPhaseAbandoned))
	}
}

// A login that NEVER succeeds unlocked nothing: the pages-found-after-login baseline is the first
// SUCCESS, not the first attempt — a failed-only crawl reports zero.
func TestNoSuccessfulLoginMeansNoPagesFoundAfterLogin(t *testing.T) {
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>` + body + `</body></html>`))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<a href="/login">sign in</a><a href="/about">about</a>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			page(w, `<p>bad credentials</p>`)
			return
		}
		page(w, `<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			</form>`)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) { page(w, `<p>about</p>`) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.LoginCredentials = []LoginCredential{{Username: "alice", Password: "wrong"}}
	rep := run(t, cfg)

	if rep.Login == nil {
		t.Fatal("no login block: the attempt happened and must be reported")
	}
	if rep.Login.Authenticated {
		t.Errorf("Authenticated = true after a failed-only crawl")
	}
	if rep.Login.PagesFoundAfterLogin != 0 {
		t.Errorf("PagesFoundAfterLogin = %d, want 0 — no login ever succeeded, so no page was found after one", rep.Login.PagesFoundAfterLogin)
	}
}

// A retry that RECOVERS during a phase's follow-up pass admits links to the frontier — and those
// links belong to THAT phase: the phase is not drained until its post-retry frontier is drained,
// so a recovered discovery executes under its own phase's session, never the next credential's.
func TestRecoveredRetryLinksStayInTheirPhase(t *testing.T) {
	var mu sync.Mutex
	var fetches []string
	record := func(r *http.Request) string {
		c, _ := r.Cookie("session")
		cv := ""
		if c != nil {
			cv = c.Value
		}
		mu.Lock()
		fetches = append(fetches, r.URL.Path+" cookie="+cv)
		mu.Unlock()
		return cv
	}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>` + body + `</body></html>`))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		page(w, `<a href="/login">sign in</a>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			vals, _ := url.ParseQuery(string(body))
			switch vals.Get("user") + "/" + vals.Get("pass") {
			case "alice/s3cret":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "aaa", Path: "/"})
			case "bob/hunter2":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "bbb", Path: "/"})
			}
			page(w, `<a href="/account">my account</a>`)
			return
		}
		page(w, `<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			</form><a href="/account">account</a>`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		switch cv := record(r); cv {
		case "aaa", "bbb":
			page(w, `<p>account</p><a href="/flaky">flaky</a>`)
		default:
			w.WriteHeader(http.StatusForbidden)
			page(w, `<p>forbidden</p>`)
		}
	})
	var flakyMu sync.Mutex
	flakyCalls := 0
	mux.HandleFunc("/flaky", func(w http.ResponseWriter, r *http.Request) {
		cv := record(r)
		if cv == "aaa" {
			// Fails once at transport level, recovers on the retry — and the recovered page is
			// where /late is discovered.
			flakyMu.Lock()
			flakyCalls++
			first := flakyCalls == 1
			flakyMu.Unlock()
			if first {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
		}
		page(w, `<p>flaky</p><a href="/late">late</a>`)
	})
	mux.HandleFunc("/late", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		page(w, `<p>late</p>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.ErrorHandling = ErrorHandling{FollowUpPasses: intp(1)}
	cfg.LoginCredentials = []LoginCredential{
		{Username: "alice", Password: "s3cret"},
		{Username: "bob", Password: "hunter2"},
	}
	run(t, cfg)

	count := func(want string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, f := range fetches {
			if f == want {
				n++
			}
		}
		return n
	}
	// /late is discovered from the page alice's RETRY recovered: it is fetched inside HER phase,
	// under her session...
	if n := count("/late cookie=aaa"); n != 1 {
		t.Errorf("/late fetches with alice's session = %d, want 1 — a recovered retry's discovery belongs to the retry's phase", n)
	}
	// ...and bob's phase discovers it again through his own /flaky — once, under HIS session...
	if n := count("/late cookie=bbb"); n != 1 {
		t.Errorf("/late fetches with bob's session = %d, want 1 (his phase's own discovery)", n)
	}
	// ...and never sessionless: the old-phase item must not outlive the boundary.
	if n := count("/late cookie="); n != 0 {
		t.Errorf("/late fetches with no session = %d, want 0 — a phase-1 item must not execute after the phase-1 jar is dropped", n)
	}
}

// A pause threshold tripped BY a retry inside the follow-up pass ends the crawl: the next phase's
// login is not sent to the target the policy just paused against.
func TestAPauseTrippedByARetryStopsTheNextPhaseLogin(t *testing.T) {
	var mu sync.Mutex
	posts := map[string]int{}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>` + body + `</body></html>`))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<a href="/login">sign in</a>`)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			vals, _ := url.ParseQuery(string(body))
			mu.Lock()
			posts[vals.Get("user")]++
			mu.Unlock()
			switch vals.Get("user") + "/" + vals.Get("pass") {
			case "alice/s3cret":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "aaa", Path: "/"})
			case "bob/hunter2":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "bbb", Path: "/"})
			}
			page(w, `<a href="/account">my account</a>`)
			return
		}
		page(w, `<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			</form><a href="/account">account</a>`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("session")
		cv := ""
		if c != nil {
			cv = c.Value
		}
		if cv == "aaa" || cv == "bbb" {
			page(w, `<p>account</p><a href="/flaky">flaky</a>`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		page(w, `<p>forbidden</p>`)
	})
	mux.HandleFunc("/flaky", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("session")
		cv := ""
		if c != nil {
			cv = c.Value
		}
		if cv == "aaa" {
			// Always slower than the sender timeout: the original send and the retry both time
			// out — the SECOND consecutive timeout is what trips the pause, inside the pass.
			time.Sleep(time.Second)
			return
		}
		page(w, `<p>ok</p>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := fastTimeoutConfig(h, srv.URL+"/")
	cfg.SubmitForms = true
	cfg.ErrorHandling = ErrorHandling{PauseOnTimeoutCount: intp(2), FollowUpPasses: intp(1)}
	cfg.LoginCredentials = []LoginCredential{
		{Username: "alice", Password: "s3cret"},
		{Username: "bob", Password: "hunter2"},
	}
	// runLikeProduction: the sender's real timeout drives the pause threshold; run()'s 30s
	// test context would mask it.
	rep := runLikeProduction(t, cfg)

	mu.Lock()
	bobPosts := posts["bob"]
	mu.Unlock()
	if bobPosts != 0 {
		t.Errorf("bob's login was sent %d times after the retry tripped the pause threshold — the boundary must re-check the policy before the next phase begins", bobPosts)
	}
	if !rep.Limits.Hit(StopPausedTimeouts) {
		t.Errorf("stops = %v, want StopPausedTimeouts recorded", rep.Limits.Stops)
	}
}
