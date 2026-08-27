package web

// The session cookie jar reaches an Intruder attack.
//
// Before this, Server.cookieHeaderFor had one caller — the Repeater send handler — so every request
// in an attack went out with whatever Cookie header the captured base request happened to hold. An
// attack against an authenticated endpoint therefore reported the login wall, and reported it as
// findings about the endpoint.
//
// These tests assert the Cookie header on the bytes the origin actually received. A test that checked
// the report, or the jar, would pass with no cookie on the wire at all.

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// recordHeadsServer records the full header block of every request it receives, which is what makes
// "the Cookie header the origin saw" assertable. recordServer, in intruder_scope_test.go, keeps only
// request lines.
func recordHeadsServer(t *testing.T) (addr string, heads func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				var head strings.Builder
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if l == "\r\n" || l == "\n" {
						break
					}
					head.WriteString(l)
				}
				mu.Lock()
				seen = append(seen, head.String())
				mu.Unlock()
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(seen))
		copy(out, seen)
		return out
	}
}

// jarServer is a server whose coordinator's jar already holds cookies for the origin, as it would
// after the operator browsed the target through the proxy.
func jarServer(t *testing.T, addr string, setCookies ...string) (*Server, *core.TrafficStore) {
	t.Helper()
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)

	coord := session.NewCoordinator(zap.NewNop())
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	// Absorbed from a response, the way the proxy now feeds it, rather than poked into the jar
	// directly: the whole point is that the two ends of the feature meet.
	resp := "HTTP/1.1 200 OK\r\n"
	for _, sc := range setCookies {
		resp += "Set-Cookie: " + sc + "\r\n"
	}
	coord.AbsorbResponseCookies("127.0.0.1", uint16(port), false, []byte(resp+"\r\n"))
	srv.WithSessionCoordinator(coord)
	return srv, store
}

// cookieHeadersIn pulls the Cookie header value out of each recorded head.
func cookieHeadersIn(heads []string) []string {
	out := make([]string, 0, len(heads))
	for _, head := range heads {
		for _, line := range strings.Split(head, "\r\n") {
			if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "Cookie") {
				out = append(out, strings.TrimSpace(value))
			}
		}
	}
	return out
}

func pointIndex(t *testing.T, srv *Server, msgID uint64, kind, label string) int {
	t.Helper()
	var points []wirePoint
	postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": msgID, "all": false}, &points)
	for i := range points {
		if points[i].Kind == kind && points[i].Label == label {
			return i
		}
	}
	t.Fatalf("no %s point labelled %q in %+v", kind, label, points)
	return -1
}

func TestIntruderAttachesJarCookiesToEveryRequest(t *testing.T) {
	addr, heads := recordHeadsServer(t)
	srv, store := jarServer(t, addr, "sessid=live-token; Path=/", "csrf=xyz")
	// No Cookie header on the base request at all: a hand-built request, or one captured before the
	// operator logged in. This is the case where the attack was previously guaranteed to be
	// unauthenticated.
	id := requestMessage(t, store, "GET /admin?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	qIndex := pointIndex(t, srv, id, "url_param_value", "q")

	var out struct {
		SessionCookies struct {
			Attached []string `json:"attached"`
			Exempt   []string `json:"exempt"`
			JarEmpty bool     `json:"jar_empty"`
		} `json:"session_cookies"`
	}
	if code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{qIndex},
		"payload_sets": [][]string{{"one", "twotwo", "threethree"}},
		"max_requests": 100,
		"rps":          1000,
	}, &out); code != http.StatusOK {
		t.Fatalf("run status = %d, want 200", code)
	}

	got := cookieHeadersIn(heads())
	if len(got) != 3 {
		t.Fatalf("%d of 3 requests carried a Cookie header (%v); an attack against an authenticated "+
			"endpoint sends every request unauthenticated without this", len(got), got)
	}
	for _, h := range got {
		if !strings.Contains(h, "sessid=live-token") || !strings.Contains(h, "csrf=xyz") {
			t.Errorf("Cookie header %q is missing a jar cookie", h)
		}
	}
	if out.SessionCookies.JarEmpty {
		t.Error("report says the jar was empty")
	}
	if len(out.SessionCookies.Attached) != 2 {
		t.Errorf("report attached = %v, want both jar cookie names", out.SessionCookies.Attached)
	}
}

func TestIntruderRefreshesAStaleCookieFromTheJar(t *testing.T) {
	addr, heads := recordHeadsServer(t)
	srv, store := jarServer(t, addr, "sessid=live-token")
	// The realistic case: a capture from history whose session cookie has since rotated. The jar
	// wins — see internal/web/intruder_cookies.go for why this differs from the Repeater's rule.
	id := requestMessage(t, store,
		"GET /admin?q=alpha HTTP/1.1\r\nHost: shop.test\r\nCookie: sessid=stale-token; theme=dark\r\n\r\n")
	qIndex := pointIndex(t, srv, id, "url_param_value", "q")

	postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{qIndex},
		"payload_sets": [][]string{{"one"}},
		"max_requests": 10,
		"rps":          1000,
	}, &struct{}{})

	got := cookieHeadersIn(heads())
	if len(got) != 1 {
		t.Fatalf("cookie headers = %v, want one", got)
	}
	if strings.Contains(got[0], "stale-token") {
		t.Errorf("Cookie header %q still carries the captured stale session token", got[0])
	}
	if !strings.Contains(got[0], "sessid=live-token") {
		t.Errorf("Cookie header %q was not refreshed from the jar", got[0])
	}
	// A cookie the jar knows nothing about is the operator's and survives untouched.
	if !strings.Contains(got[0], "theme=dark") {
		t.Errorf("Cookie header %q dropped a cookie the jar does not hold", got[0])
	}
}

// Burp: "when the Scanner or Intruder makes a request that manipulates a cookie […] that is affected
// by a session handling action, the session handling action is not applied to that request." Without
// the exemption every request in the attack carries the jar's value, the payloads never reach the
// target, and the report is one bucket that says nothing.
func TestIntruderDoesNotOverwriteTheCookieItIsFuzzing(t *testing.T) {
	addr, heads := recordHeadsServer(t)
	srv, store := jarServer(t, addr, "sessid=live-token", "theme=light")
	id := requestMessage(t, store,
		"GET /admin HTTP/1.1\r\nHost: shop.test\r\nCookie: sessid=stale-token; theme=dark\r\n\r\n")
	sessIndex := pointIndex(t, srv, id, "cookie_value", "sessid")

	var out struct {
		SessionCookies struct {
			Attached []string `json:"attached"`
			Exempt   []string `json:"exempt"`
		} `json:"session_cookies"`
	}
	postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{sessIndex},
		"payload_sets": [][]string{{"AAA", "BBBBBB"}},
		"max_requests": 10,
		"rps":          1000,
	}, &out)

	got := cookieHeadersIn(heads())
	if len(got) != 2 {
		t.Fatalf("cookie headers = %v, want two", got)
	}
	payloads := map[string]bool{}
	for _, h := range got {
		for _, p := range parseCookieHeader(h) {
			if p.name == "sessid" {
				payloads[p.value] = true
			}
		}
		// The other cookie is still refreshed from the jar: the exemption is per cookie, not per
		// request.
		if !strings.Contains(h, "theme=light") {
			t.Errorf("Cookie header %q: the non-fuzzed cookie was not refreshed from the jar", h)
		}
	}
	if !payloads["AAA"] || !payloads["BBBBBB"] {
		t.Errorf("sessid values seen = %v, want the two payloads: the jar overwrote the position "+
			"being fuzzed, so every request asked the same question", payloads)
	}
	if payloads["live-token"] {
		t.Error("the jar overwrote a fuzzed cookie value")
	}
	if len(out.SessionCookies.Exempt) != 1 || out.SessionCookies.Exempt[0] != "sessid" {
		t.Errorf("report exempt = %v, want [sessid] stated explicitly", out.SessionCookies.Exempt)
	}
}

func TestIntruderWithAnEmptyJarSendsWhatTheCaptureCarried(t *testing.T) {
	addr, heads := recordHeadsServer(t)
	// A coordinator with nothing in it: the jar must not invent, strip or reorder anything.
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope).WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	id := requestMessage(t, store,
		"GET /admin?q=alpha HTTP/1.1\r\nHost: shop.test\r\nCookie: theme=dark\r\n\r\n")
	qIndex := pointIndex(t, srv, id, "url_param_value", "q")

	var out struct {
		SessionCookies struct {
			Attached []string `json:"attached"`
			JarEmpty bool     `json:"jar_empty"`
		} `json:"session_cookies"`
	}
	postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + addr,
		"mode":         "sniper",
		"points":       []int{qIndex},
		"payload_sets": [][]string{{"one"}},
		"max_requests": 10,
		"rps":          1000,
	}, &out)

	got := cookieHeadersIn(heads())
	if len(got) != 1 || got[0] != "theme=dark" {
		t.Fatalf("cookie headers = %v, want the capture's own header unchanged", got)
	}
	if !out.SessionCookies.JarEmpty {
		t.Error("report must say the jar was empty rather than reporting an empty attachment list " +
			"that could also mean every cookie was exempt")
	}
}

// ---- applyJarCookies, directly -----------------------------------------------------------------

func TestApplyJarCookies(t *testing.T) {
	const body = "\r\n\r\n"
	cases := []struct {
		name   string
		raw    string
		jar    string
		exempt []string
		want   string
	}{{
		name: "no jar leaves the request byte-identical",
		raw:  "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1" + body,
		jar:  "",
		want: "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1" + body,
	}, {
		name: "no cookie header gets one",
		raw:  "GET / HTTP/1.1\r\nHost: h" + body,
		jar:  "a=1; b=2",
		want: "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1; b=2" + body,
	}, {
		name: "jar overwrites and appends, request order first",
		raw:  "GET / HTTP/1.1\r\nHost: h\r\nCookie: b=old; z=keep" + body,
		jar:  "a=1; b=new",
		want: "GET / HTTP/1.1\r\nHost: h\r\nCookie: b=new; z=keep; a=1" + body,
	}, {
		name:   "an exempt cookie keeps its spliced value",
		raw:    "GET / HTTP/1.1\r\nHost: h\r\nCookie: b=PAYLOAD" + body,
		jar:    "a=1; b=new",
		exempt: []string{"b"},
		want:   "GET / HTTP/1.1\r\nHost: h\r\nCookie: b=PAYLOAD; a=1" + body,
	}, {
		name:   "an exempt jar cookie is not appended either",
		raw:    "GET / HTTP/1.1\r\nHost: h" + body,
		jar:    "a=1; b=2",
		exempt: []string{"b"},
		want:   "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1" + body,
	}, {
		name: "header name case is preserved as written",
		raw:  "GET / HTTP/1.1\r\nHost: h\r\ncookie: a=old" + body,
		jar:  "a=new",
		want: "GET / HTTP/1.1\r\nHost: h\r\ncookie: a=new" + body,
	}, {
		name: "a value containing = survives",
		raw:  "GET / HTTP/1.1\r\nHost: h\r\nCookie: t=aa==; a=1" + body,
		jar:  "a=2",
		want: "GET / HTTP/1.1\r\nHost: h\r\nCookie: t=aa==; a=2" + body,
	}, {
		name: "a second cookie header is merged, not sprayed",
		raw:  "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=old\r\nCookie: c=3" + body,
		jar:  "a=new; b=2",
		want: "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=new; b=2\r\nCookie: c=3" + body,
	}, {
		name: "an unterminated head is refused rather than guessed at",
		raw:  "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1",
		jar:  "a=2",
		want: "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1",
	}, {
		name: "a bodied request keeps its body",
		raw:  "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nabcd",
		jar:  "a=1",
		want: "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nCookie: a=1\r\n\r\nabcd",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exempt := map[string]bool{}
			for _, n := range tc.exempt {
				exempt[n] = true
			}
			in := []byte(tc.raw)
			got := string(applyJarCookies(in, tc.jar, exempt))
			if got != tc.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tc.want)
			}
			// bytes.Split hands back views into one array; a merge that appended into a line would
			// corrupt the lines after it, and the input belongs to the caller either way.
			if string(in) != tc.raw {
				t.Errorf("the input was mutated:\n%q", string(in))
			}
		})
	}
}
