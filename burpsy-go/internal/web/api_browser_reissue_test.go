package web

// "Request in browser" (burpsy-react-ui-7rk0): the re-issue's server half, end to end.
//
// A real HTTP target stands in for the origin — one that answers differently depending on the
// Cookie header, because that difference is the whole point of the two variants: an operator
// asks "does the same request behave differently under my session" and the answer needs both
// columns.
//
// What is pinned, in order of how much it would hurt to lose:
//   - the mint returns TWO URLs (the comparison is the deliverable; one URL would make the
//     operator mint twice and see the first outcome without the second's context);
//   - the "original session" fetch re-sends the stored request's own Cookie header verbatim;
//   - the "current session" fetch substitutes the coordinator's jar for the same authority;
//   - both outcomes land in history as their own exchanges, notes naming the variant;
//   - a token is one-shot: a second fetch answers 410, not a silent re-send;
//   - an out-of-scope exchange cannot mint at all.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// cookieEchoTarget answers with the Cookie header it received, so the test can assert which
// cookies each variant actually sent.
func cookieEchoTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("cookies-were: " + r.Header.Get("Cookie")))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mintReissue(t *testing.T, s *Server, exchange core.ExchangeID) (origURL, currURL string) {
	t.Helper()
	// The mint needs the console's own bind to render a URL the operator's browser can open;
	// the test server records one the way main.go does, so the reply is a real URL and not
	// the honest "I do not know my own address" refusal the unset case produces.
	s.webBind = "127.0.0.1:0"
	rec := postJSON(t, s, "/api/repeater/browser-reissue", map[string]any{
		"exchange": uint64(exchange),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/repeater/browser-reissue: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		ExchangeID  uint64 `json:"exchange_id"`
		OriginalURL string `json:"original_url"`
		CurrentURL  string `json:"current_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode mint reply: %v", err)
	}
	return resp.OriginalURL, resp.CurrentURL
}

// A stored exchange with its own Cookie header, in scope.
func storedCookieExchange(t *testing.T, s *Server, target string, cookie string) core.ExchangeID {
	t.Helper()
	u, _ := url.Parse(target)
	reqRaw := "GET / HTTP/1.1\r\nHost: " + u.Host + "\r\n" + "Cookie: " + cookie + "\r\n\r\n"
	reqID, err := s.store.Put([]byte(reqRaw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("store the request: %v", err)
	}
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), core.DirectionResponse)
	portNum, _ := strconv.Atoi(u.Port())
	ex := &core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: u.Hostname(), Port: uint16(portNum), Method: "GET", Path: "/",
	}
	s.store.AddExchange(ex)
	return ex.ID
}

// The "original session" variant re-sends the stored request's own Cookie header, verbatim.
func TestTheOriginalSessionReissueSendsTheStoredCookieHeader(t *testing.T) {
	target := cookieEchoTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	ex := storedCookieExchange(t, s, target.URL, "sid=the-original-session-cookie")
	origURL, _ := mintReissue(t, s, ex)

	parsed, _ := url.Parse(origURL)
	rec := get(t, s, parsed.Path)
	if rec.Code != http.StatusOK {
		t.Fatalf("the original-session fetch: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "In original session") {
		t.Errorf("the answer page does not name its variant: %q", rec.Body.String())
	}
	// The outcome lives in history, so that is where the cookie assertion belongs: the RECORDED
	// request's bytes are what went out, and they are the bytes the page deliberately does not
	// re-render.
	sent := lastReissueExchange(t, s, "original")
	msg, err := s.store.Get(core.MsgOrZero(sent.Request))
	if err != nil {
		t.Fatalf("the recorded request could not be read back: %v", err)
	}
	if !strings.Contains(string(msg.Header("Cookie")), "the-original-session-cookie") {
		t.Errorf("the original-session re-issue sent Cookie %q, want the stored request's own header verbatim",
			string(msg.Header("Cookie")))
	}
}

// lastReissueExchange finds the newest recorded browser re-issue of the named variant.
func lastReissueExchange(t *testing.T, s *Server, variant string) *core.Exchange {
	t.Helper()
	for _, ex := range s.store.Exchanges() {
		if ex.Notes != nil && *ex.Notes == "browser re-issue ("+variant+" session)" {
			return ex
		}
	}
	t.Fatalf("no recorded browser re-issue of the %q variant — the send happened but nothing landed in history", variant)
	return nil
}

// The "current session" variant substitutes the coordinator's jar for the same authority.
func TestTheCurrentSessionReissueSendsTheJarCookieHeader(t *testing.T) {
	target := cookieEchoTarget(t)
	s := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	ex := storedCookieExchange(t, s, target.URL, "sid=the-original-session-cookie")
	// The jar holds a different, current session for this authority.
	portNum, _ := strconv.Atoi(u.Port())
	s.sessionCoordinator.SetCookie(u.Hostname(), uint16(portNum), false, "sid", "the-current-jar-cookie")

	_, currURL := mintReissue(t, s, ex)
	parsed, _ := url.Parse(currURL)
	rec := get(t, s, parsed.Path)
	if rec.Code != http.StatusOK {
		t.Fatalf("the current-session fetch: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "In current session") {
		t.Errorf("the answer page does not name its variant: %q", rec.Body.String())
	}
	sent := lastReissueExchange(t, s, "current")
	msg, err := s.store.Get(core.MsgOrZero(sent.Request))
	if err != nil {
		t.Fatalf("the recorded request could not be read back: %v", err)
	}
	cookie := string(msg.Header("Cookie"))
	if !strings.Contains(cookie, "the-current-jar-cookie") {
		t.Errorf("the current-session re-issue sent Cookie %q, want the jar's header for this authority", cookie)
	}
	if strings.Contains(cookie, "the-original-session-cookie") {
		t.Errorf("the current-session re-issue sent the ORIGINAL cookie too: %q — the two variants must differ "+
			"by exactly their cookies, or the comparison means nothing", cookie)
	}
}

// Both variants land in history as their own exchanges, notes naming the variant — the
// comparison survives the dialog and the page.
func TestBothReissueVariantsLandInHistoryNamingTheirVariant(t *testing.T) {
	target := cookieEchoTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	ex := storedCookieExchange(t, s, target.URL, "sid=abc")
	origURL, currURL := mintReissue(t, s, ex)

	for _, raw := range []string{origURL, currURL} {
		parsed, _ := url.Parse(raw)
		if rec := get(t, s, parsed.Path); rec.Code != http.StatusOK {
			t.Fatalf("variant fetch %s: status = %d", parsed.Path, rec.Code)
		}
	}
	found := map[string]bool{}
	for _, row := range s.store.Exchanges() {
		if row.Notes != nil && strings.HasPrefix(*row.Notes, "browser re-issue") {
			found[*row.Notes] = true
		}
	}
	if !found["browser re-issue (original session)"] || !found["browser re-issue (current session)"] {
		t.Errorf("history carries %v; both variants must be recorded with their own note, or the "+
			"comparison does not survive the dialog", found)
	}
}

// A token is one-shot: the second fetch answers 410, not a silent re-send. A URL that re-issues
// a request N times is a request-forgery surface, and the operator asked for one re-issue.
func TestAReissueURLIsOneShot(t *testing.T) {
	target := cookieEchoTarget(t)
	s := newTestServer()
	u, _ := url.Parse(target.URL)
	s.scope.AddInclude(u.Hostname())

	ex := storedCookieExchange(t, s, target.URL, "sid=abc")
	origURL, _ := mintReissue(t, s, ex)
	parsed, _ := url.Parse(origURL)

	if rec := get(t, s, parsed.Path); rec.Code != http.StatusOK {
		t.Fatalf("first fetch: status = %d", rec.Code)
	}
	rec := get(t, s, parsed.Path)
	if rec.Code != http.StatusGone {
		t.Fatalf("second fetch: status = %d, want 410 — a spent token must say so, not re-send", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already been used") {
		t.Errorf("the 410 must tell the operator what happened and what to do: %q", rec.Body.String())
	}
}

// An out-of-scope exchange cannot mint at all — a re-issue is a send, and the scope that
// constrains outbound traffic constrains it like any other.
func TestAnOutOfScopeExchangeCannotMintAReissue(t *testing.T) {
	target := cookieEchoTarget(t)
	// Scope names someone else, so the stored exchange's authority is not authorised.
	s := newTestServer()
	s.scope.AddInclude("someone-else.test")

	ex := storedCookieExchange(t, s, target.URL, "sid=abc")
	rec := postJSON(t, s, "/api/repeater/browser-reissue", map[string]any{"exchange": uint64(ex)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mint for an out-of-scope exchange: status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	// Both scope gates defend this mint (host-level at mint, AuthoriseRaw on the bytes), and
	// both funnel through Scope.Explain, so their refusals are word-for-word identical — an
	// assertion on the wording could not tell which gate answered, and would be claiming a
	// distinction this codebase's own message funnel makes impossible. What is pinned is the
	// 403: removing EITHER gate alone leaves this green, which is defense in depth working as
	// designed, and a mutation check that removes both fails it.
}

// A token nobody minted answers 410 rather than 404-with-a-side-effect, and the store's own
// exchange-count is what proves nothing was sent.
func TestAnUnknownTokenSendsNothing(t *testing.T) {
	s := newTestServer()
	before := len(s.store.Exchanges())
	rec := get(t, s, "/reissue/00000000000000000000000000000000")
	if rec.Code != http.StatusGone {
		t.Fatalf("unknown token: status = %d, want 410", rec.Code)
	}
	if after := len(s.store.Exchanges()); after != before {
		t.Errorf("the unknown-token fetch created %d exchange(s): a guessable path must have no effect", after-before)
	}
}
