package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// Cross-site WebSocket hijacking (checks_ws_hijack.go) and the client-IP header check
// (checks_client_ip.go) against the live vulnapp wsip family, each audited with only its own switch on.
// Every guard has a twin that only it stops:
//
//   - foreign Origin refused:          /wsip/safe/ws/chat (checks Origin)
//   - authentication shown:            /wsip/safe/ws/public (same greeting with or without cookies)
//   - token in the handshake URL:      /wsip/safe/ws/token
//   - random-address control:          /wsip/safe/via-proxy (any X-Forwarded-For opens it)
//   - limit still holds without it:    /wsip/safe/ratelimit-lapsing (stops limiting after two requests)
//   - header actually decides:         /wsip/safe/admin, /wsip/safe/ratelimit, /wsip/safe/whoami
//   - echo control:                    /wsip/safe/echo-headers (echoes every request header)

func wsipAudit(t *testing.T, path string, mod func(*ScanConfig)) ([]*Finding, uint32) {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute,
		CheckWebSocketHijacking: true, CheckClientIPSpoofing: true}
	if mod != nil {
		mod(cfg)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings, outcome.RequestsSent
}

var wsipRows = []string{IssueWebSocketHijacking, IssueClientIPAccessBypass, IssueClientIPRateLimitBypass, spoofableClientIPRow}

func TestWebSocketHijackingAndClientIPFindEachDefect(t *testing.T) {
	cases := []struct {
		path, row, confidence, param, mustSay string
	}{
		{"/wsip/ws/chat", IssueWebSocketHijacking, "firm", "", "refused (HTTP 401)"},
		{"/wsip/ws/feed", IssueWebSocketHijacking, "firm", "", "same first message"},
		{"/wsip/admin", IssueClientIPAccessBypass, "firm", "X-Forwarded-For", "claims the client is 127.0.0.1"},
		{"/wsip/tci/admin", IssueClientIPAccessBypass, "firm", "True-Client-IP", "claims the client is 127.0.0.1"},
		{"/wsip/ratelimit?report=annual", IssueClientIPRateLimitBypass, "firm", "X-Forwarded-For", "still limited"},
		{"/wsip/whoami", spoofableClientIPRow, "firm", "X-Real-IP", "came back as a whole token"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, _ := wsipAudit(t, c.path, nil)
			f := sessFindingIn(fs, c.row)
			if f == nil {
				t.Fatalf("%s: %q was not reported (got %v)", c.path, c.row, sessNames(fs))
			}
			if f.Confidence != c.confidence {
				t.Errorf("confidence %s, want %s: %s", f.Confidence, c.confidence, f.Description)
			}
			if f.Param != c.param {
				t.Errorf("param %q, want the exact header %q", f.Param, c.param)
			}
			if !strings.Contains(f.Description, c.mustSay) {
				t.Errorf("description does not say %q: %s", c.mustSay, f.Description)
			}
			for _, other := range wsipRows {
				if other != c.row && sessFindingIn(fs, other) != nil {
					t.Errorf("%s also reported %q: %s", c.path, other, sessFindingIn(fs, other).Description)
				}
			}
		})
	}
}

func TestWebSocketHijackingAndClientIPStayQuietOnTheSafeTwins(t *testing.T) {
	// Each check must demonstrably work in this run before silence on a twin means anything.
	for path, row := range map[string]string{
		"/wsip/ws/chat":                 IssueWebSocketHijacking,
		"/wsip/admin":                   IssueClientIPAccessBypass,
		"/wsip/ratelimit?report=annual": IssueClientIPRateLimitBypass,
		"/wsip/whoami":                  spoofableClientIPRow,
	} {
		if fs, _ := wsipAudit(t, path, nil); sessFindingIn(fs, row) == nil {
			t.Fatalf("%s did not fire on %s, so the twins' silence proves nothing", row, path)
		}
	}
	for path, c := range map[string]struct {
		why     string
		minSent uint32
	}{
		"/wsip/safe/ws/chat":                             {"refuses a foreign Origin", 2},
		"/wsip/safe/ws/public":                           {"greets everyone alike, so nothing authenticated is reachable", 3},
		"/wsip/safe/ws/token?ticket=Tk7f3a9c2e1b8d4f6a0": {"needs a URL ticket a cross-site page cannot know", 0},
		"/wsip/safe/admin":                               {"decides on the socket address only", 9},
		"/wsip/safe/via-proxy":                           {"opens to any X-Forwarded-For, so the address does not decide", 4},
		"/wsip/safe/ratelimit?report=annual":             {"limits by socket address only", 9},
		"/wsip/safe/ratelimit-lapsing":                   {"stops limiting on its own: the header is not why", 4},
		"/wsip/safe/whoami":                              {"shows the socket address only", 2},
		"/wsip/safe/echo-headers":                        {"echoes every request header", 2},
	} {
		fs, sent := wsipAudit(t, path, nil)
		for _, row := range wsipRows {
			if f := sessFindingIn(fs, row); f != nil {
				t.Errorf("%s %s but %q was reported: %s\n%s", path, c.why, row, f.Description, f.Evidence)
			}
		}
		if sent < c.minSent {
			t.Errorf("%s: only %d requests sent, want at least %d: silence must be a verdict", path, sent, c.minSent)
		}
	}
}

func TestWebSocketHijackingAndClientIPAreOffWithoutTheirSwitches(t *testing.T) {
	for _, path := range []string{"/wsip/ws/chat", "/wsip/admin", "/wsip/whoami"} {
		fs, sent := wsipAudit(t, path, func(c *ScanConfig) {
			c.CheckWebSocketHijacking, c.CheckClientIPSpoofing = false, false
		})
		for _, row := range wsipRows {
			if f := sessFindingIn(fs, row); f != nil {
				t.Errorf("%s: reported with the switches off: %s", path, f.Description)
			}
		}
		if sent != 0 {
			t.Errorf("%s: %d requests sent with the switches off", path, sent)
		}
	}
}

func TestWebSocketHandshakeClassification(t *testing.T) {
	base := "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n"
	for _, c := range []struct {
		raw  string
		want bool
	}{
		{base + "Cookie: s=1\r\n\r\n", true},
		{base + "\r\n", false},
		{base + "Cookie: s=1\r\nAuthorization: Bearer x\r\n\r\n", false},
		{base + "Cookie: s=1\r\nSec-WebSocket-Protocol: chat, graphql-ws\r\n\r\n", true},
		{base + "Cookie: s=1\r\nSec-WebSocket-Protocol: chat, eyJhbGciOiJIUzI1NiJ9abc123\r\n\r\n", false},
		{strings.Replace(base, "/ws", "/ws?room=lobby", 1) + "Cookie: s=1\r\n\r\n", true},
		{strings.Replace(base, "/ws", "/ws?t=a1b2c3d4e5f6a7b8c9", 1) + "Cookie: s=1\r\n\r\n", false},
		{"GET / HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n", false},
	} {
		if got, why := wsCookieOnlyHandshake(c.raw); got != c.want {
			t.Errorf("wsCookieOnlyHandshake(%q) = %v (%s), want %v", c.raw, got, why, c.want)
		}
	}
	if !wsSameMessage(`{"user":"alice","ts":1712}`, `{"user":"alice","ts":1713999}`) ||
		wsSameMessage("welcome alice", "welcome guest") {
		t.Error("message comparison must mask digit runs and nothing else")
	}
}

func TestClientIPTokenMatching(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nX-Client: 203.0.113.7\r\n\r\nfrom 203.0.113.70 and 1203.0.113.8")
	if got := ipReflectedWhere(raw, "203.0.113.7"); got != "header X-Client" {
		t.Errorf("header token: got %q", got)
	}
	for _, ip := range []string{"203.0.113.8", "203.0.113.70x"} {
		if got := ipReflectedWhere(raw, ip); ip == "203.0.113.8" && got != "" {
			t.Errorf("%s is only part of a longer number, got %q", ip, got)
		}
	}
	if got := ipReflectedWhere(raw, "203.0.113.70"); got != "body" {
		t.Errorf("body token: got %q", got)
	}
	if got := rawSetHeader("GET / HTTP/1.1\r\nHost: h\r\nx-forwarded-for: 1.2.3.4\r\n\r\nbody", "X-Forwarded-For", "127.0.0.1"); got !=
		"GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 127.0.0.1\r\n\r\nbody" {
		t.Errorf("rawSetHeader: %q", got)
	}
}
