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
