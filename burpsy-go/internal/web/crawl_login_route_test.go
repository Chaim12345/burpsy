package web

// Route coverage for the application-login launch path (burpsy-react-ui-uzil): the request's
// logins and a named configuration's login_functions keys must reach the crawler the operator
// launched — the nc9s/tyso defect shape is a parser that says "applied" and a Config literal
// that never sets the field, so every assertion here is on what the TARGET saw and on the
// report the route returns, never on the reply's own claims.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// loginRouteSite is a one-login-form application observed from the target side: the posts /login
// received, and the paths fetched carrying the issued session.
type loginRouteSite struct {
	srv     *httptest.Server
	mu      sync.Mutex
	posts   []string
	cookies []string // "PATH cookievalue" for requests that carried a session cookie
}

func newLoginRouteSite(t *testing.T) *loginRouteSite {
	t.Helper()
	site := &loginRouteSite{}
	site.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/login" {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			site.mu.Lock()
			site.posts = append(site.posts, string(body))
			site.mu.Unlock()
			vals, _ := url.ParseQuery(string(body))
			if vals.Get("user") == "alice" && vals.Get("pass") == "s3cret" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/"})
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/account">my account</a></body></html>`))
			return
		}
		if c, err := r.Cookie("session"); err == nil {
			site.mu.Lock()
			site.cookies = append(site.cookies, r.URL.Path+" "+c.Value)
			site.mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/login":
			_, _ = w.Write([]byte(`<html><body>
				<form method="post" action="/login">
				<input type="text" name="user" value="">
				<input type="password" name="pass">
				</form></body></html>`))
		case "/account":
			c, err := r.Cookie("session")
			if err != nil || c.Value != "abc123" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`<html><body>account</body></html>`))
		default:
			_, _ = w.Write([]byte(`<html><body><a href="/login">sign in</a></body></html>`))
		}
	}))
	t.Cleanup(site.srv.Close)
	return site
}

func TestCrawlLoginsAndLoginFunctionsKeysReachTheLaunchedCrawl(t *testing.T) {
	s, _ := newTestServerWithDB(t)
	site := newLoginRouteSite(t)
	u, _ := url.Parse(site.srv.URL)
	s.scope.AddInclude(u.Hostname())

	doc := `{"crawler":{"login_functions":{
		"attempt_to_self_register_a_user": false,
		"trigger_login_failures": true},
		"crawl_optimization":{"crawl_using_provided_logins_only": false}}}`
	if _, err := s.persist.SaveScanConfigLibrary("logins", doc); err != nil {
		t.Fatalf("save configuration: %v", err)
	}

	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":        []string{site.srv.URL + "/"},
		"config":       "logins",
		"submit_forms": true,
		"logins":       []map[string]string{{"username": "alice", "password": "s3cret"}},
		"max_requests": 50, "max_depth": 5,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: %d %s", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID    uint64   `json:"task_id"`
		Unapplied []string `json:"config_unapplied_keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	for _, k := range start.Unapplied {
		if strings.Contains(k, "login_functions") || strings.Contains(k, "provided_logins") {
			t.Errorf("the start reply lists %q as unapplied; the crawler honours it", k)
		}
	}

	run := waitForCrawl(t, s, start.TaskID)
	if run.State != "done" || run.Report == nil {
		t.Fatalf("crawl state %q (%s), report %v", run.State, run.Error, run.Report != nil)
	}

	site.mu.Lock()
	defer site.mu.Unlock()
	var sawCred, sawBogus, sawAuthedAccount bool
	for _, p := range site.posts {
		vals, _ := url.ParseQuery(p)
		if vals.Get("user") == "alice" && vals.Get("pass") == "s3cret" {
			sawCred = true
		}
		if strings.Contains(vals.Get("user"), "burpsy") {
			sawBogus = true
		}
	}
	for _, c := range site.cookies {
		if c == "/account abc123" {
			sawAuthedAccount = true
		}
	}
	if !sawCred {
		t.Errorf("the login form never saw the launch's credential; posts: %v", site.posts)
	}
	if !sawBogus {
		t.Errorf("trigger_login_failures was applied per the reply, but no invalid-username "+
			"submission reached the target; posts: %v", site.posts)
	}
	if !sawAuthedAccount {
		t.Errorf("/account was never fetched with the earned session; cookies: %v", site.cookies)
	}

	got := get(t, s, "/api/crawl?task="+strconv.FormatUint(start.TaskID, 10))
	var full struct {
		Report struct {
			Login *struct {
				Method        string `json:"method"`
				Authenticated bool   `json:"authenticated"`
			} `json:"login"`
		} `json:"report"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &full); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if full.Report.Login == nil || full.Report.Login.Method != "credentials" || !full.Report.Login.Authenticated {
		t.Errorf("the run's report carries no authenticated credential login: %+v", full.Report.Login)
	}
}
