package crawler

// burpsy-react-ui-uzil: application-login credentials. Burp identifies a login form as one
// carrying an input type=password with a non-empty name, and logs in with each provided
// credential in turn, crawling the content behind the login. Before this, the crawler marked
// the form (discover.go's isLoginForm, on type=password alone) and did nothing with the mark:
// an authenticated crawl needed a hand-built macro or static headers.
//
// Every assertion is on what the target saw (the request log) and on the run's own store and
// report: a credential that reached history unmasked, or a session the crawl earned but never
// used, is the failure this file exists to catch.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// loginApp is a one-login-form application: /login's form posts user/pass; a correct pair earns
// a session cookie; /account and everything under it answers 403 without it.
type loginApp struct {
	srv *httptest.Server
	mu  sync.Mutex
	// posts are the urlencoded bodies /login received, exactly as sent.
	posts []string
	// authedPages are the paths fetched carrying the issued session cookie.
	authedPages []string
}

func newLoginApp(t *testing.T) *loginApp {
	t.Helper()
	app := &loginApp{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/login">sign in</a></body></html>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			app.mu.Lock()
			app.posts = append(app.posts, string(body))
			app.mu.Unlock()
			vals, _ := url.ParseQuery(string(body))
			if vals.Get("user") == "alice" && vals.Get("pass") == "s3cret" && vals.Get("token") == "tok1" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/"})
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(`<html><body><p>welcome alice</p><a href="/account">my account</a></body></html>`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<html><body><p>bad credentials</p></body></html>`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="post" action="/login">
			<input type="hidden" name="token" value="tok1">
			<input type="text" name="user" value="">
			<input type="password" name="pass">
			<input type="submit" value="Sign in">
			</form></body></html>`))
	})
	account := func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil || c.Value != "abc123" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><body><p>forbidden</p></body></html>`))
			return
		}
		app.mu.Lock()
		app.authedPages = append(app.authedPages, r.URL.Path)
		app.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/account/settings">settings</a></body></html>`))
	}
	mux.HandleFunc("/account", account)
	mux.HandleFunc("/account/settings", account)
	app.srv = httptest.NewServer(mux)
	t.Cleanup(app.srv.Close)
	return app
}

func (a *loginApp) sawPost(substr string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.posts {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

func (a *loginApp) sawAuthed(path string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.authedPages {
		if p == path {
			return true
		}
	}
	return false
}

// The core: a crawl given credentials finds the login form, submits the CREDENTIAL values (not the
// placeholder fill an ordinary form gets), earns the session, and crawls behind the login with it.
func TestACredentialLoginReachesThePagesBehindTheForm(t *testing.T) {
	app := newLoginApp(t)
	h := newHarness()
	cfg := h.config(app.srv.URL + "/")
	cfg.SubmitForms = true
	cfg.LoginCredentials = []LoginCredential{{Username: "alice", Password: "s3cret"}}
	rep := run(t, cfg)

	if !app.sawPost("user=alice") || !app.sawPost("pass=s3cret") {
		t.Errorf("the login form never saw the configured credential; posts: %v", app.posts)
	}
	if app.sawPost("pass=burpsy") || app.sawPost("pass=password") {
		t.Errorf("the login form was submitted with placeholder fill as if it were an ordinary form; "+
			"posts: %v", app.posts)
	}
	if !app.sawAuthed("/account") {
		t.Errorf("/account was never fetched with the earned session; authenticated fetches: %v",
			app.authedPages)
	}
	if rep.Login == nil {
		t.Fatalf("the report carries no login block for a crawl that logged in")
	}
	if rep.Login.Method != "credentials" || !rep.Login.Authenticated {
		t.Errorf("login block = %+v, want method credentials and authenticated true", rep.Login)
	}
}

// Burp's rule, not a looser one: a password input with no NAME is not a login form
// (identifying-login-forms.html), and no credential is submitted to it.
func TestANamelessPasswordFieldIsNotALoginForm(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			mu.Lock()
			bodies = append(bodies, string(body))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="post" action="/login">
			<input type="text" name="user" value="">
			<input type="password">
			</form></body></html>`))
	}))
	t.Cleanup(srv.Close)

	h := newHarness()
	cfg := h.config(srv.URL + "/")
	cfg.SubmitForms = true
	cfg.LoginCredentials = []LoginCredential{{Username: "alice", Password: "s3cret"}}
	rep := run(t, cfg)

	mu.Lock()
	defer mu.Unlock()
	for _, b := range bodies {
		if strings.Contains(b, "s3cret") {
			t.Errorf("the password reached a form Burp would not identify as login; body: %s", b)
		}
	}
	if rep.Login != nil && rep.Login.Authenticated {
		t.Errorf("the report claims an authenticated crawl against a form Burp would not identify; "+
			"login: %+v", rep.Login)
	}
}

// The exchange-store half of the credential rule: the login POST is captured like every request
// (CRAWL-02), but the credential VALUES must not be what history keeps.
func TestTheLoginExchangeIsStoredWithTheCredentialValuesMasked(t *testing.T) {
	app := newLoginApp(t)
	h := newHarness()
	cfg := h.config(app.srv.URL + "/")
	cfg.SubmitForms = true
	cfg.LoginCredentials = []LoginCredential{{Username: "alice", Password: "s3cret"}}
	rep := run(t, cfg)

	if !app.sawPost("pass=s3cret") {
		t.Fatalf("the login never happened at the target; posts: %v", app.posts)
	}
	var loginExchange []byte
	for _, f := range rep.Fetches {
		if f.Method == "POST" && strings.HasSuffix(f.URL, "/login") {
			ex, err := h.store.GetExchange(f.ExchangeID)
			if err != nil {
				t.Fatalf("the login POST has no stored exchange: %v", err)
			}
			msg, err := h.store.Get(core.MsgOrZero(ex.Request))
			if err != nil {
				t.Fatalf("the login POST's request bytes are unreadable: %v", err)
			}
			loginExchange = msg.Raw()
		}
	}
	if loginExchange == nil {
		t.Fatalf("no POST /login in the run's fetches: %v", fetchLog(rep))
	}
	if strings.Contains(string(loginExchange), "s3cret") {
		t.Errorf("the stored login exchange carries the password in history: %s", loginExchange)
	}
}
