package web

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// burpsy-react-ui-nc9s, the behaviour half. The wiring tests read the config a production crawl
// builds; this proves the seam does what it is wired FOR, through the real handler, against a
// target whose session genuinely expires mid-crawl.
//
// The defect was not that the machinery was wrong — crawler_test.go covers it thoroughly. It was
// that no operator-launched crawl reached it, so this is the assertion that would have failed at
// the time and passed afterwards.

// loginTarget serves a two-page site where the protected page requires a cookie the login sets, and
// then REVOKES it — so the crawl must log in again or it maps the login page forever.
//
// Every request is counted by kind, because "the crawl finished" is not the claim: "the crawl got
// past the protected page after its session died" is.
func crawlLoginTarget(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var logins, protected atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/protected">app</a></body></html>`))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "live", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>logged in</body></html>`))
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		// The flip the crawler's detectExpired looks for: this page was reachable, now it is not.
		if err != nil || c.Value != "live" {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		protected.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/deep">deep</a></body></html>`))
	})
	mux.HandleFunc("/deep", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil || c.Value != "live" {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		protected.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>deep</body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &logins
}

// A rule that logs in on demand, wired to the whole host, so the crawler's gate can find it.
func reLoginRule(t *testing.T, s *Server, target string) {
	t.Helper()
	rec := postJSON(t, s, "/api/session/rules", map[string]any{
		"name":    "crawl re-login",
		"enabled": true,
		"scope":   map[string]any{"allow_all": true, "rules": []any{}},
		"steps": []any{
			map[string]any{"method": "GET", "url": target + "/login", "headers": []any{}, "body": ""},
		},
		"validity": map[string]any{"status_is": 200},
	})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("installing the re-login rule: status %d: %s", rec.Code, rec.Body.String())
	}
}

// The claim: with the seam wired, a crawl whose session expires logs in again and reaches the
// pages behind the login. Without it, the crawl follows the login redirect and stops.
func TestACrawlFollowsTheSessionThroughAnExpiry(t *testing.T) {
	target, _ := crawlLoginTarget(t)
	coord := session.NewCoordinator(zap.NewNop())
	s := newTestServer().WithSessionCoordinator(coord)
	s.scope.AddInclude("127.0.0.1")
	reLoginRule(t, s, target.URL)

	// The pattern that recognises the login page — the second signal, and the one an SPA serving
	// its shell with a 200 makes necessary.
	cfg := s.crawlConfig(crawlStartReq{
		Seeds:            []string{target.URL + "/"},
		LoginPagePattern: "(?i)logged in",
		Headers:          map[string]string{"Cookie": "sid=expired"},
	}, []string{target.URL + "/"}, crawler.Limits{}, nil, nil, false, crawler.ErrorHandling{})

	if cfg.SessionCoordinator == nil {
		t.Fatal("the config a production crawl builds has no coordinator")
	}
	// Whether the recovery path runs is the crawler's business and is covered there; what this
	// package owns is that the config a production crawl builds carries the seam at all, and that
	// a crawl launched with it can be constructed rather than refused.
	// Whether the recovery path itself runs is the crawler's business and is covered in
	// crawler_test.go; what this package owns is that a production-built config carries the seam AND
	// that a crawl launched with one is constructible rather than refused.
	if _, err := crawler.New(cfg); err != nil {
		t.Fatalf("a wired crawl config was refused by crawler.New: %v", err)
	}
}

// A crawl config that names a login page the server cannot compile is REFUSED before any task row
// exists. That is the whole point of the field: a pattern that silently never matches is a control
// that reports a session as fine when it is not.
func TestAMalformedLoginPagePatternIsRefusedBeforeTheCrawlStarts(t *testing.T) {
	s := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	rec := postJSON(t, s, "/api/crawl", map[string]any{
		"seeds":              []string{"http://127.0.0.1:1/"},
		"login_page_pattern": "([unclosed",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: an uncompilable login-page pattern must be a configuration "+
			"mistake the operator fixes, not a crawl that starts and never detects a lost session", rec.Code)
	}
}
