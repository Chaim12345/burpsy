package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/session"
)

// The cookie jar's write surface (dkb): Burp's cookie jar dialog — "you can edit cookies
// manually, remove cookies from the jar, or empty the jar altogether". The read side lists what
// the jar holds; these tests drive the write side through the same route and read the result
// back through the read side, because a write the table cannot see is the old constant-true lie
// in a new shape.

func Test_the_cookie_jar_set_remove_and_clear_are_visible_on_the_read_side(t *testing.T) {
	s := newTestServerWithCoordinator(t)
	jar := s.sessionCoordinator

	// Seed one absorbed cookie so the jar exists, then edit through the route.
	jar.AbsorbCookie("app.test", 443, true, "SESSION=abc")
	if got := jar.CookieHeader("app.test", 443, true, "/"); got != "SESSION=abc" {
		t.Fatalf("seed absorbed: %q", got)
	}

	// Edit: the operator fixes a value by hand.
	rec := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "set", "host": "app.test", "port": 443, "tls": true,
		"name": "SESSION", "value": "rotated",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("set = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if got := jar.CookieHeader("app.test", 443, true, "/"); got != "SESSION=rotated" {
		t.Fatalf("the edit should replace the value, header = %q", got)
	}

	// The read side names the change — a write the table cannot see is the old lie reshaped.
	view := cookiesView(t, s)
	if len(view) != 1 || view[0].Cookies["SESSION"].Value != "rotated" {
		t.Fatalf("the read side should show the edited value, got %+v", view)
	}

	// Add a second cookie, then remove the first.
	rec2 := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "set", "host": "app.test", "port": 443, "tls": true,
		"name": "CSRF", "value": "tok",
	})
	if rec2.Code != http.StatusOK {
		t.Fatalf("set second = %d", rec2.Code)
	}
	rec3 := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "remove", "host": "app.test", "port": 443, "tls": true, "name": "SESSION",
	})
	if rec3.Code != http.StatusOK {
		t.Fatalf("remove = %d: %s", rec3.Code, strings.TrimSpace(rec3.Body.String()))
	}
	view = cookiesView(t, s)
	if _, still := view[0].Cookies["SESSION"]; still {
		t.Fatalf("the removed cookie must not survive on the read side, got %+v", view[0].Cookies)
	}
	if view[0].Cookies["CSRF"].Value != "tok" {
		t.Fatalf("the untouched cookie must survive a per-cookie removal, got %+v", view[0].Cookies)
	}

	// Empty the jar altogether.
	rec4 := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "clear", "host": "app.test", "port": 443, "tls": true,
	})
	if rec4.Code != http.StatusOK {
		t.Fatalf("clear = %d: %s", rec4.Code, strings.TrimSpace(rec4.Body.String()))
	}
	if got := jar.CookieHeader("app.test", 443, true, "/"); got != "" {
		t.Fatalf("an emptied jar sends no cookies, header = %q", got)
	}
}

// Removing a cookie that is not there reports so rather than claiming success — a silence that
// reads as success is how a stale cookie survives an operator's attempt to kill it.
func Test_removing_an_absent_cookie_reports_absence(t *testing.T) {
	s := newTestServerWithCoordinator(t)

	rec := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "remove", "host": "ghost.test", "port": 80, "tls": false, "name": "nope",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"removed":false`) {
		t.Fatalf("the response should say removed=false, got: %s", strings.TrimSpace(rec.Body.String()))
	}
}

// The write side refuses when no coordinator is attached, with the same reason the read side's
// wired=false names.
func Test_the_cookie_write_refuses_without_a_coordinator(t *testing.T) {
	s := newTestServer()
	s.sessionCoordinator = nil // the default test server attaches one; the refusal needs it gone
	rec := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "clear", "host": "x.test", "port": 80, "tls": false,
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no coordinator should be 503, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not attached") {
		t.Fatalf("the refusal should name the missing coordinator, got: %s", strings.TrimSpace(rec.Body.String()))
	}
}

// An unknown action and a missing name are refused with the remedy, not silently ignored.
func Test_the_cookie_write_validates_its_actions(t *testing.T) {
	s := newTestServerWithCoordinator(t)

	rec := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "export", "host": "x.test", "port": 80, "tls": false,
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "set, remove or clear") {
		t.Fatalf("unknown action should be refused by name, got %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	rec2 := postJSON(t, s, "/api/session/cookies", map[string]any{
		"action": "set", "host": "x.test", "port": 80, "tls": false, "name": "  ",
	})
	if rec2.Code != http.StatusBadRequest || !strings.Contains(rec2.Body.String(), "name is required") {
		t.Fatalf("a blank name should be refused, got %d: %s", rec2.Code, strings.TrimSpace(rec2.Body.String()))
	}
}

func newTestServerWithCoordinator(t *testing.T) *Server {
	t.Helper()
	return newTestServer().WithSessionCoordinator(session.NewCoordinator(nil))
}

// cookiesView reads the GET response in its wire shape and flattens it to
// authority -> name -> value, the shape the assertions read.
func cookiesView(t *testing.T, s *Server) []session.CookieJarEntry {
	t.Helper()
	rec := get(t, s, "/api/session/cookies")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET cookies = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var view struct {
		Cookies []struct {
			Host    string `json:"host"`
			Cookies []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"cookies"`
		} `json:"cookies"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&view); err != nil {
		t.Fatalf("decode cookies view: %v", err)
	}
	out := make([]session.CookieJarEntry, 0, len(view.Cookies))
	for _, h := range view.Cookies {
		entry := session.CookieJarEntry{Cookies: map[string]session.CookieAttrs{}}
		// The wire host is "example.com:443" — split for the entry's fields where it parses;
		// only the map matters to these assertions, so a host that does not split keeps its key.
		entry.Host = h.Host
		for _, c := range h.Cookies {
			entry.Cookies[c.Name] = session.CookieAttrs{Value: c.Value}
		}
		out = append(out, entry)
	}
	return out
}
