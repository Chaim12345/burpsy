package sender

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Burp's "Allowed redirect types" (burpsy-react-ui-z9zi): which responses count as a redirect to
// follow. Each kind is driven through FollowRedirects against a real listener, on and off.

func followerWithTypes(t *testing.T, port uint16, types *RedirectTypes) *AuthorisedSender {
	t.Helper()
	snd := NewSender(DefaultSenderConfig())
	settings := DefaultNetworkSettings()
	settings.Redirects = RedirectSettings{Mode: RedirectOnSite, MaxHops: 5, Types: types}
	if err := snd.ApplyNetwork(settings); err != nil {
		t.Fatalf("apply redirect settings: %v", err)
	}
	return NewAuthorisedSender(core.NewScopeAllowEverything(), snd, "127.0.0.1", port, false)
}

// followedTo reports whether the chain from /start ended on /landed.
func followedTo(t *testing.T, srv *redirectServer, a *AuthorisedSender) bool {
	t.Helper()
	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", srv.port, "/start"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	for _, p := range srv.seen() {
		if p == "/landed" {
			return res.Complete
		}
	}
	return false
}

func landingServer(t *testing.T, start string) *redirectServer {
	return newRedirectServer(t, func(path string) string {
		switch path {
		case "/start":
			return start
		case "/landed":
			return okResponse
		}
		return ""
	})
}

func with(mut func(*RedirectTypes)) *RedirectTypes {
	types := DefaultRedirectTypes()
	mut(&types)
	return &types
}

func TestTheRefreshHeaderIsARedirectByDefaultAndCanBeTurnedOff(t *testing.T) {
	start := "HTTP/1.1 200 OK\r\nRefresh: 0; url=/landed\r\nContent-Length: 0\r\n\r\n"
	srv := landingServer(t, start)
	if !followedTo(t, srv, followerWithTypes(t, srv.port, nil)) {
		t.Errorf("with Burp's default types a Refresh header was not followed; requests %v", srv.seen())
	}
	off := landingServer(t, start)
	if followedTo(t, off, followerWithTypes(t, off.port, with(func(r *RedirectTypes) { r.UnderstandRefreshHeader = false }))) {
		t.Errorf("understand_refresh_header off, yet the Refresh header was followed: %v", off.seen())
	}
}

func TestTheMetaRefreshTagIsARedirectByDefaultAndCanBeTurnedOff(t *testing.T) {
	body := `<html><head><meta http-equiv="refresh" content="0;URL='/landed'"></head></html>`
	start := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	srv := landingServer(t, start)
	if !followedTo(t, srv, followerWithTypes(t, srv.port, nil)) {
		t.Errorf("with Burp's default types a meta refresh was not followed; requests %v", srv.seen())
	}
	off := landingServer(t, start)
	if followedTo(t, off, followerWithTypes(t, off.port, with(func(r *RedirectTypes) { r.UnderstandMetaRefresh = false }))) {
		t.Errorf("understand_meta_refresh_tag off, yet the meta refresh was followed: %v", off.seen())
	}
	// A meta tag in a body that is not HTML is text, not a page a browser would navigate from.
	plain := landingServer(t, strings.Replace(start, "text/html", "text/plain", 1))
	if followedTo(t, plain, followerWithTypes(t, plain.port, nil)) {
		t.Errorf("a meta refresh in a text/plain body was followed: %v", plain.seen())
	}
}

func TestAnyStatusWithLocationIsOffByDefaultAndCanBeTurnedOn(t *testing.T) {
	start := "HTTP/1.1 201 Created\r\nLocation: /landed\r\nContent-Length: 0\r\n\r\n"
	srv := landingServer(t, start)
	if followedTo(t, srv, followerWithTypes(t, srv.port, nil)) {
		t.Errorf("a 201 with Location was followed under Burp's defaults, which leave this kind off: %v", srv.seen())
	}
	on := landingServer(t, start)
	if !followedTo(t, on, followerWithTypes(t, on.port, with(func(r *RedirectTypes) { r.UnderstandAnyLocation = true }))) {
		t.Errorf("understand_any_status_code_with_location_header on, yet the 201 was not followed: %v", on.seen())
	}
}

func TestA3xxIsNotFollowedWhenThatKindIsOff(t *testing.T) {
	srv := landingServer(t, redirectTo("/landed"))
	if followedTo(t, srv, followerWithTypes(t, srv.port, with(func(r *RedirectTypes) { r.Understand3xx = false }))) {
		t.Errorf("understand_3xx_status_code off, yet a 302 was followed: %v", srv.seen())
	}
}

// A Refresh hop is a browser navigation: a GET with no body, whatever the request that drew it.
func TestARefreshHopIsABodilessGet(t *testing.T) {
	srv := landingServer(t, "HTTP/1.1 200 OK\r\nRefresh: 0; url=/landed\r\nContent-Length: 0\r\n\r\n")
	a := followerWithTypes(t, srv.port, nil)
	req := requestTo("127.0.0.1", srv.port, "/start")
	req.Method = "POST"
	req.Body = []byte("a=1")
	if _, err := a.FollowRedirects(context.Background(), req); err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if last := srv.lastRequest(); !strings.HasPrefix(last, "GET /landed ") {
		t.Errorf("the refresh hop was sent as %q, want a GET", firstLineOf(last))
	}
}

func TestJavaScriptDrivenRedirectsAreRefusedByName(t *testing.T) {
	settings := DefaultNetworkSettings()
	settings.Redirects = RedirectSettings{Mode: RedirectOnSite, MaxHops: 5,
		Types: with(func(r *RedirectTypes) { r.UnderstandJavaScript = true })}
	err := NewSender(DefaultSenderConfig()).ApplyNetwork(settings)
	if err == nil || !strings.Contains(err.Error(), "understand_javascript_driven") {
		t.Errorf("ApplyNetwork = %v, want a refusal naming understand_javascript_driven", err)
	}
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
