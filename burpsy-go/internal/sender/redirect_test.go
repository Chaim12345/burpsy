package sender

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Redirect following ------------------------------------------------------------------------
//
// internal/sender/AGENTS.md states, as a design position rather than an omission, that redirects are
// never followed and there is no knob: a follow inside the transport dials the next hop with no scope
// gate in front of it. These tests hold both halves of the compromise this unit makes — the policy is
// off unless asked for, and every hop it does follow goes through a fresh AuthorisedSender, so a hop
// the scope refuses is refused rather than sent.

// redirectServer is a listener whose responses are decided per path.
//
// Written by hand rather than with httptest because the tests need two distinct authorities on
// 127.0.0.1 and a count of what actually arrived on each; a handler that could not be asked "how many
// requests reached you" would let a test claiming a hop was refused pass while the hop was sent.
type redirectServer struct {
	addr  string
	port  uint16
	mu    sync.Mutex
	paths []string
}

// newRedirectServer answers each request by consulting reply(path). An empty reply is a 404.
func newRedirectServer(t *testing.T, reply func(path string) string) *redirectServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, err := hostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := &redirectServer{addr: ln.Addr().String(), port: port}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				first, rerr := br.ReadString('\n')
				if rerr != nil {
					return
				}
				for {
					line, herr := br.ReadString('\n')
					if herr != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				path := ""
				if fields := strings.Fields(first); len(fields) >= 2 {
					path = fields[1]
				}
				srv.mu.Lock()
				srv.paths = append(srv.paths, path)
				srv.mu.Unlock()

				body := reply(path)
				if body == "" {
					body = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
				}
				c.Write([]byte(body))
			}(conn)
		}
	}()
	return srv
}

func (r *redirectServer) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.paths))
	copy(out, r.paths)
	return out
}

// redirectTo renders a 302 naming location.
func redirectTo(location string) string {
	return "HTTP/1.1 302 Found\r\nLocation: " + location + "\r\nContent-Length: 0\r\n\r\n"
}

const okResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

// followerFor builds a sender in the given redirect mode, bound to one authority.
func followerFor(t *testing.T, scope ScopeChecker, host string, port uint16, mode RedirectMode, hops int) *AuthorisedSender {
	t.Helper()
	snd := NewSender(DefaultSenderConfig())
	settings := DefaultNetworkSettings()
	settings.Redirects = RedirectSettings{Mode: mode, MaxHops: hops}
	if err := snd.ApplyNetwork(settings); err != nil {
		t.Fatalf("apply redirect settings: %v", err)
	}
	return NewAuthorisedSender(scope, snd, host, port, false)
}

// mustURL parses a URL the redirect helpers take as the previous hop's target.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed
}

func requestTo(host string, port uint16, path string) *Request {
	return &Request{
		Method: "GET",
		URL:    "http://" + net.JoinHostPort(host, strconv.Itoa(int(port))) + path,
		Host:   host,
		Port:   port,
	}
}

// The default. A 30x is the response, and the operator sees it — this is what every existing caller
// keeps getting, and it is why adding the policy did not change any of them.
func TestTheDefaultPolicyReportsTheRedirectRatherThanFollowingIt(t *testing.T) {
	srv := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return redirectTo("/moved")
		}
		return okResponse
	})
	a := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", srv.port, RedirectNever, 5)

	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", srv.port, "/start"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("sent %d requests, want 1: the never policy follows nothing", res.Sent)
	}
	if res.Final == nil || res.Final.StatusCode != 302 {
		t.Fatalf("final = %v, want the 302 itself", res.Final)
	}
	// Complete is false and Hops records why. A follower that returned only the final response would
	// make a chain stopped by policy indistinguishable from one that ended in a 200.
	if res.Complete {
		t.Error("Complete = true on a chain that was still redirecting; that is the same class of lie " +
			"as a skipped check reporting as a pass")
	}
	if len(res.Hops) != 1 || res.Hops[0].Followed {
		t.Fatalf("hops = %+v, want one unfollowed hop", res.Hops)
	}
	if !strings.Contains(res.Hops[0].Reason, "never") {
		t.Errorf("hop reason %q does not name the policy that stopped it", res.Hops[0].Reason)
	}
	if got := srv.seen(); len(got) != 1 {
		t.Errorf("the server saw %v, want only /start", got)
	}
}

// The security property this whole unit turns on: a hop to an authority the scope refuses is not sent.
//
// Two listeners, both on 127.0.0.1, distinguished by port — so the scope rule is a port rule and the
// refusal cannot be an accident of the host matching. The second server counts its arrivals, which is
// what makes "refused" a claim about the wire rather than about a struct field.
func TestAnOutOfScopeRedirectHopIsRefusedRatherThanFollowed(t *testing.T) {
	elsewhere := newRedirectServer(t, func(string) string { return okResponse })
	start := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return redirectTo(fmt.Sprintf("http://127.0.0.1:%d/secret", elsewhere.port))
		}
		return okResponse
	})

	// Only the first authority is in scope. The second is a different port on the same host, which is
	// exactly the shape of a hostile Location aimed at an internal service.
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPort(core.ScopeInclude, "127.0.0.1", start.port))

	// RedirectAlways, deliberately: the most permissive mode this sender offers must still not be able
	// to send a request the scope refuses. If the refusal only held under in_scope, "always" would be
	// the documented escape hatch this package exists to not have.
	a := followerFor(t, scope, "127.0.0.1", start.port, RedirectAlways, 5)

	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", start.port, "/start"))
	if err != nil {
		t.Fatalf("FollowRedirects returned an error rather than a refused hop: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("sent %d requests, want 1: only the first request was authorised", res.Sent)
	}
	if len(res.Hops) != 1 {
		t.Fatalf("hops = %+v, want one", res.Hops)
	}
	if res.Hops[0].Followed {
		t.Error("the out-of-scope hop is recorded as followed")
	}
	if res.Complete {
		t.Error("Complete = true on a chain the scope stopped")
	}
	if res.Hops[0].Reason == "" {
		t.Error("a refused hop carries no reason, so the operator cannot tell policy from scope")
	}
	// The claim that matters. Anything on this listener means a hop reached a socket without clearing
	// the gate, which is a security defect rather than a failing assertion about a field.
	if got := elsewhere.seen(); len(got) != 0 {
		t.Fatalf("the out-of-scope authority received %v; a redirect hop escaped the scope check", got)
	}
	if a.Refused() == 0 {
		t.Error("the refusal was not counted, so a chain's refusals do not show up where every other " +
			"refused request's does")
	}
}

// An in-scope hop on another authority is followed, and it is followed by a sender bound to that
// authority. Without this the test above would pass on a follower that refused everything.
func TestAnInScopeRedirectHopIsFollowedThroughItsOwnAuthority(t *testing.T) {
	elsewhere := newRedirectServer(t, func(string) string { return okResponse })
	start := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return redirectTo(fmt.Sprintf("http://127.0.0.1:%d/landed", elsewhere.port))
		}
		return okResponse
	})

	a := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", start.port, RedirectInScope, 5)
	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", start.port, "/start"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if res.Sent != 2 {
		t.Errorf("sent %d requests, want 2", res.Sent)
	}
	if !res.Complete {
		t.Errorf("Complete = false on a chain that reached a 200; hops %+v", res.Hops)
	}
	if res.Final == nil || res.Final.StatusCode != 200 {
		t.Fatalf("final = %v, want the 200 at the end of the chain", res.Final)
	}
	if len(res.Hops) != 1 || !res.Hops[0].Followed {
		t.Fatalf("hops = %+v, want one followed hop", res.Hops)
	}
	if got := elsewhere.seen(); len(got) != 1 || got[0] != "/landed" {
		t.Errorf("the second authority saw %v, want /landed", got)
	}
}

// On-site is the mode that filters by authority rather than by scope, so it must stop a cross-authority
// hop the scope would have allowed — otherwise it is indistinguishable from in_scope.
func TestOnSiteRefusesAHopToAnotherAuthorityTheScopeWouldAllow(t *testing.T) {
	elsewhere := newRedirectServer(t, func(string) string { return okResponse })
	start := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return redirectTo(fmt.Sprintf("http://127.0.0.1:%d/offsite", elsewhere.port))
		}
		return okResponse
	})

	a := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", start.port, RedirectOnSite, 5)
	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", start.port, "/start"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("sent %d, want 1", res.Sent)
	}
	if len(res.Hops) != 1 || res.Hops[0].Followed {
		t.Fatalf("hops = %+v, want one unfollowed hop", res.Hops)
	}
	if !strings.Contains(res.Hops[0].Reason, "same site") {
		t.Errorf("reason %q does not say the hop left the site", res.Hops[0].Reason)
	}
	if got := elsewhere.seen(); len(got) != 0 {
		t.Errorf("the off-site authority received %v", got)
	}
	// A same-site hop under the same policy still goes, or the mode follows nothing at all.
	onSite := newRedirectServer(t, func(path string) string {
		if path == "/a" {
			return redirectTo("/b")
		}
		return okResponse
	})
	sameSite := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", onSite.port, RedirectOnSite, 5)
	res2, err := sameSite.FollowRedirects(context.Background(), requestTo("127.0.0.1", onSite.port, "/a"))
	if err != nil {
		t.Fatalf("same-site follow: %v", err)
	}
	if res2.Sent != 2 || !res2.Complete {
		t.Errorf("same-site chain sent %d and Complete=%v, want 2 and true", res2.Sent, res2.Complete)
	}
}

// A chain is bounded even when the operator asked for a following mode, because a redirect loop is the
// ordinary case rather than the exotic one.
func TestTheHopBudgetBoundsAChainThatKeepsMoving(t *testing.T) {
	// Each path redirects to the next, so the chain never repeats a URL and loop detection cannot be
	// what stops it — the budget has to be.
	srv := newRedirectServer(t, func(path string) string {
		n, err := strconv.Atoi(strings.TrimPrefix(path, "/step"))
		if err != nil {
			return okResponse
		}
		return redirectTo(fmt.Sprintf("/step%d", n+1))
	})
	a := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", srv.port, RedirectOnSite, 3)

	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", srv.port, "/step0"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	// Three hops followed, the fourth refused: 4 requests on the wire for a budget of 3.
	if res.Sent != 4 {
		t.Errorf("sent %d requests for a 3-hop budget, want 4", res.Sent)
	}
	if res.Complete {
		t.Error("Complete = true on a chain the budget stopped")
	}
	last := res.Hops[len(res.Hops)-1]
	if last.Followed || !strings.Contains(last.Reason, "max_hops") {
		t.Errorf("the final hop is %+v, want an unfollowed hop naming the budget", last)
	}
}

// Loop detection is keyed on a canonical authority-and-target, so two spellings of one URL cannot hide
// a cycle. This is the case string comparison misses: `:80` elided on one hop and present on the next
// is the same place, and a hostile Location can alternate them forever.
func TestTwoSpellingsOfOneUrlAreStillALoop(t *testing.T) {
	first := visitKey("Example.test", 80, false, "/a")
	second := visitKey("example.test", 80, false, "/a")
	if first != second {
		t.Errorf("visitKey differs by hostname case:\n  %s\n  %s", first, second)
	}
	// The query is part of the identity, because a paginating chain is not a loop.
	if visitKey("example.test", 80, false, "/a?page=1") == visitKey("example.test", 80, false, "/a?page=2") {
		t.Error("visitKey ignores the query, so a paginating redirect chain would be called a loop")
	}
	// Scheme and port are part of it, so an http->https hop on the same path is a real hop.
	if visitKey("example.test", 80, false, "/a") == visitKey("example.test", 443, true, "/a") {
		t.Error("visitKey ignores the scheme and port")
	}
}

// The live loop check, over the wire: two paths that redirect to each other are named as a loop rather
// than reported as a budget that ran out.
func TestAChainThatCyclesIsNamedAsALoop(t *testing.T) {
	srv := newRedirectServer(t, func(path string) string {
		switch path {
		case "/ping":
			return redirectTo("/pong")
		case "/pong":
			return redirectTo("/ping")
		}
		return okResponse
	})
	a := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", srv.port, RedirectOnSite, 10)

	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", srv.port, "/ping"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if res.Complete {
		t.Error("Complete = true on a looping chain")
	}
	last := res.Hops[len(res.Hops)-1]
	if !strings.Contains(last.Reason, "looping") {
		t.Errorf("the chain stopped for %q; a cycle must be reported as a loop rather than as an "+
			"exhausted budget, or the operator debugs the wrong thing", last.Reason)
	}
	// Caught on the third request at the latest: /ping, /pong, then the hop back to /ping is refused.
	if res.Sent > 3 {
		t.Errorf("sent %d requests before noticing a two-URL cycle", res.Sent)
	}
}

// Credentials do not cross an authority boundary. A target that can emit a Location can choose where
// those headers go, so forwarding them means a redirect is enough to hand an engagement's session
// cookie to a host of the target's choosing.
func TestCredentialHeadersDoNotCrossAnAuthorityBoundary(t *testing.T) {
	prev := &Request{
		Method:  "GET",
		URL:     "http://a.test/one",
		Host:    "a.test",
		Port:    80,
		Headers: map[string]string{"Authorization": "Bearer t", "Cookie": "s=1", "X-Trace": "keep"},
	}
	prevURL := mustURL(t, "http://a.test/one")

	crossed, _, err := redirectRequest(prev, prevURL, 302, "http://b.test/two")
	if err != nil {
		t.Fatalf("redirectRequest: %v", err)
	}
	for _, dropped := range []string{"Authorization", "Cookie"} {
		if _, still := crossed.Headers[dropped]; still {
			t.Errorf("%s survived a hop to another authority; a Location the target controls would be "+
				"enough to hand it out", dropped)
		}
	}
	if crossed.Headers["X-Trace"] != "keep" {
		t.Error("an ordinary header was dropped along with the credentials")
	}

	// The same-authority hop is the ordinary /login -> /dashboard case, and it is where the session
	// cookie is needed.
	same, _, err := redirectRequest(prev, prevURL, 302, "/two")
	if err != nil {
		t.Fatalf("redirectRequest same authority: %v", err)
	}
	if same.Headers["Cookie"] != "s=1" {
		t.Error("the session cookie was dropped on a same-authority hop, which breaks every login flow")
	}
}

// Method and body follow the status rather than convenience: 307/308 exist to mean "same request
// again", and 301/302/303 become a bodiless GET the way every browser and the standard library do.
func TestTheRedirectStatusDecidesWhetherTheMethodAndBodySurvive(t *testing.T) {
	prev := &Request{
		Method:  "POST",
		URL:     "http://a.test/submit",
		Host:    "a.test",
		Port:    80,
		Body:    []byte("name=value"),
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "10"},
	}
	prevURL := mustURL(t, "http://a.test/submit")

	kept, _, err := redirectRequest(prev, prevURL, 307, "/again")
	if err != nil {
		t.Fatalf("307: %v", err)
	}
	if kept.Method != "POST" || string(kept.Body) != "name=value" {
		t.Errorf("307 produced %s with body %q, want the request repeated", kept.Method, kept.Body)
	}

	dropped, _, err := redirectRequest(prev, prevURL, 303, "/elsewhere")
	if err != nil {
		t.Fatalf("303: %v", err)
	}
	if dropped.Method != "GET" || len(dropped.Body) != 0 {
		t.Errorf("303 produced %s with body %q, want a bodiless GET", dropped.Method, dropped.Body)
	}
	// The entity headers go with the body, or the next request describes a body that is not there.
	for _, name := range []string{"Content-Type", "Content-Length"} {
		if _, still := dropped.Headers[name]; still {
			t.Errorf("%s survived the body being dropped, so the next request is malformed", name)
		}
	}
}

// A Location this sender cannot dial stops the chain with a reason rather than erroring out — and a
// 300 or 304 is not treated as a redirect at all.
func TestALocationThatCannotBeDialledStopsTheChainWithAReason(t *testing.T) {
	prevURL := mustURL(t, "http://a.test/one")
	prev := &Request{Method: "GET", URL: "http://a.test/one", Host: "a.test", Port: 80}

	for _, location := range []string{"ftp://a.test/f", "mailto:x@a.test"} {
		if _, _, err := redirectRequest(prev, prevURL, 302, location); err == nil {
			t.Errorf("Location %q was accepted; this sender cannot dial it", location)
		}
	}

	for _, status := range []int{300, 304, 200} {
		if _, isRedirect := redirectLocation(&Response{StatusCode: status}); isRedirect {
			t.Errorf("status %d reads as a redirect; a 300 nominates no resource and a 304 is not a "+
				"redirect at all", status)
		}
	}
}

// A 30x with no Location has no next hop, and that is a stop with a reason rather than a crash or a
// silently-complete chain.
func TestARedirectWithNoLocationStopsTheChain(t *testing.T) {
	srv := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"
		}
		return okResponse
	})
	a := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", srv.port, RedirectOnSite, 5)

	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", srv.port, "/start"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if res.Sent != 1 || res.Complete {
		t.Errorf("sent %d, Complete %v; want one request and an incomplete chain", res.Sent, res.Complete)
	}
	if len(res.Hops) != 1 || !strings.Contains(res.Hops[0].Reason, "no Location") {
		t.Errorf("hops = %+v, want one hop saying there is no Location", res.Hops)
	}
}

// A chain that never redirects is one request and a complete result, so a caller can use
// FollowRedirects unconditionally instead of branching on the policy.
func TestAResponseThatDoesNotRedirectIsOneCompleteHoplessChain(t *testing.T) {
	srv := newRedirectServer(t, func(string) string { return okResponse })
	a := followerFor(t, core.NewScopeAllowEverything(), "127.0.0.1", srv.port, RedirectInScope, 5)

	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", srv.port, "/plain"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if res.Sent != 1 || !res.Complete || len(res.Hops) != 0 {
		t.Errorf("got sent=%d complete=%v hops=%d, want 1/true/0", res.Sent, res.Complete, len(res.Hops))
	}
}
