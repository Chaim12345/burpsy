package sender

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// A login or SSO flow that sets a cookie on its 302 is the single most common redirect shape in an
// authenticated tool. burpsy's follower built each hop from the previous REQUEST only, so the cookie
// never went with it: the destination answered with its login page and the operator saw what looked
// like an application failure. Burp exposes the fix as a setting
// (settings/tools/repeater.html:143-145) and burpsy had the absence documented instead
// (burpsy-react-ui-mr83).
//
// These tests use the same raw-server harness as the rest of this file's redirect tests, and read the
// exact request bytes each hop received. A unit test on the header-building helper would not have
// caught the original defect, which was that nothing called the helper at all.

// recordingJar is a CookieJar that records what it was asked for and what it was told to remember.
//
// It is deliberately not a real cookie store: the point under test is WHICH cookies the follower asks
// for on which authority, and a store that filtered by domain would hide a cross-authority mistake
// behind its own correctness. perAuthority keeps one authority's cookie distinct from another's,
// which is the property a single flat map would not model.
type recordingJar struct {
	mu           sync.Mutex
	askedFor     []string
	absorbed     []string
	perAuthority map[string]string
}

func newRecordingJar() *recordingJar {
	return &recordingJar{perAuthority: map[string]string{}}
}

func (j *recordingJar) CookieHeader(host string, port uint16, tls bool, path string) (string, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	header := j.perAuthority[host]
	if header == "" {
		return "", false
	}
	j.askedFor = append(j.askedFor, host+": "+header)
	return header, true
}

func (j *recordingJar) AbsorbResponseCookies(host string, port uint16, tls bool, setCookie []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	// The value is kept as the target sent it, not reduced to name=1: the test asserts on the wire,
	// and a stub that rewrote the value would let a follower that sent the WRONG cookie pass.
	for _, value := range setCookie {
		cookie := value
		if semi := strings.Index(cookie, ";"); semi >= 0 {
			cookie = strings.TrimSpace(cookie[:semi])
		}
		j.perAuthority[host] = cookie
		j.absorbed = append(j.absorbed, host+": "+strings.SplitN(cookie, "=", 2)[0])
	}
}

func (j *recordingJar) asked() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.askedFor...)
}

func (j *recordingJar) remembered() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.absorbed...)
}

// cookieFollower builds a sender in the given redirect mode with a recording jar attached, and returns
// it with the jar so a test can read what was asked for and remembered.
func cookieFollower(t *testing.T, host string, port uint16, mode RedirectMode, replay bool) (*AuthorisedSender, *recordingJar) {
	t.Helper()
	jar := newRecordingJar()
	snd := NewSender(DefaultSenderConfig()).WithCookieJar(jar)
	settings := DefaultNetworkSettings()
	settings.Redirects = RedirectSettings{Mode: mode, MaxHops: 5, ReplayCookies: replay}
	if err := snd.ApplyNetwork(settings); err != nil {
		t.Fatalf("apply redirect settings: %v", err)
	}
	return NewAuthorisedSender(core.NewScopeAllowEverything(), snd, host, port, false), jar
}

// A chain whose first hop sets a cookie must carry it to the second hop, and the destination's own
// request bytes must show it.
func TestARedirectThatSetsACookieCarriesItToTheDestination(t *testing.T) {
	// The destination, on its own port so the hop is a real cross-authority step.
	destination := newRedirectServer(t, func(string) string { return okResponse })

	entry := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return "HTTP/1.1 302 Found\r\n" +
				"Set-Cookie: sid=abc123; Path=/\r\n" +
				"Location: http://127.0.0.1:" + strconv.Itoa(int(destination.port)) + "/dashboard\r\n" +
				"Content-Length: 0\r\n\r\n"
		}
		return okResponse
	})

	a, jar := cookieFollower(t, "127.0.0.1", entry.port, RedirectAlways, true)
	res, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", entry.port, "/start"))
	if err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}
	if res.Sent != 2 {
		t.Fatalf("sent %d requests, want 2: the chain did not run far enough to prove anything", res.Sent)
	}

	// What the destination actually received. This is the assertion the whole change exists for.
	arrived := destination.lastRequest()
	if !strings.Contains(arrived, "sid=abc123") {
		t.Errorf("the destination's request carries no cookie: %q\n"+
			"the chain was followed and the 302's Set-Cookie was not replayed, which is the shape an "+
			"operator reads as a broken application rather than a missing cookie (mr83)", arrived)
	}
	if remembered := jar.remembered(); len(remembered) == 0 {
		t.Errorf("the jar was never told about the Set-Cookie, so nothing could have been replayed; "+
			"hops=%d finalHeaders=%v", len(res.Hops), res.Final.Headers)
	}
}

// Default is OFF. burpsy sends what an operator wrote, and a cookie the target set mid-chain is not
// something they asked to send.
func TestCookieReplayIsOffUnlessTheOperatorTurnsItOn(t *testing.T) {
	destination := newRedirectServer(t, func(string) string { return okResponse })
	entry := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return "HTTP/1.1 302 Found\r\n" +
				"Set-Cookie: sid=abc123; Path=/\r\n" +
				"Location: http://127.0.0.1:" + strconv.Itoa(int(destination.port)) + "/\r\n" +
				"Content-Length: 0\r\n\r\n"
		}
		return okResponse
	})

	// replay deliberately left false.
	a, jar := cookieFollower(t, "127.0.0.1", entry.port, RedirectAlways, false)
	if _, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", entry.port, "/start")); err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}

	if arrived := destination.lastRequest(); strings.Contains(arrived, "sid=") {
		t.Errorf("the destination received %q with replay off: an operator who did not ask for a "+
			"target-set credential is now sending one", arrived)
	}
	if remembered := jar.remembered(); len(remembered) != 0 {
		t.Errorf("the jar recorded %v with replay off: nothing should have been absorbed, because a "+
			"chain that replayed nothing on hop one has no business replaying on hop three", remembered)
	}
}

// A hop that already carries a Cookie header keeps it. An operator who typed one meant that one, and a
// jar replacing it would be the same silent substitution the proxy's platform-auth rule refuses.
// A same-authority hop, which is where an operator's own cookie SURVIVES the hop: the existing rule
// drops Cookie across a change of authority (redirect.go says why — a Location can choose where a
// credential goes), and this setting must not reopen that on a hop that stayed put. The jar's cookie
// must not replace the operator's, or the request they can see is not the one that goes out.
func TestAHopThatAlreadyCarriesACookieKeepsIt(t *testing.T) {
	srv := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return "HTTP/1.1 302 Found\r\n" +
				"Set-Cookie: from-the-target=1; Path=/\r\n" +
				"Location: /landed\r\n" +
				"Content-Length: 0\r\n\r\n"
		}
		return okResponse
	})

	a, _ := cookieFollower(t, "127.0.0.1", srv.port, RedirectAlways, true)
	req := requestTo("127.0.0.1", srv.port, "/start")
	req.Headers = map[string]string{"Cookie": "typed-by-the-operator=1"}
	if _, err := a.FollowRedirects(context.Background(), req); err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}

	arrived := srv.lastRequest()
	if !strings.Contains(arrived, "typed-by-the-operator") {
		t.Errorf("the hop arrived with %q; the operator's own cookie was replaced by the jar's, so the "+
			"request on screen is not the request that goes out", arrived)
	}
	if strings.Contains(arrived, "from-the-target") {
		t.Errorf("the hop arrived with %q; the jar was added on top of a cookie the operator typed", arrived)
	}
}

// A cookie is scoped to the authority that set it, and the unit is the HOST — not the host:port.
//
// That is RFC 6265's rule and every browser's: a cookie set on example.com is sent to example.com on
// any port, because the cookie header carries no notion of a port at all. Two test servers on
// 127.0.0.1 with different ports are therefore ONE authority, and a follower that scoped them
// separately would be sending LESS than a browser does.
//
// The rule this test pins is the one that matters for safety: the jar is asked about the hop's own
// authority and is never handed a previous hop's answer. That is what stops a Location from choosing
// which host receives a credential, and the assertion is on the QUESTION asked rather than on a
// cross-port case, which is not a case at all.
func TestTheJarIsAskedAboutTheHopsOwnAuthorityAndNothingElse(t *testing.T) {
	destination := newRedirectServer(t, func(string) string { return okResponse })
	entry := newRedirectServer(t, func(path string) string {
		if path == "/start" {
			return "HTTP/1.1 302 Found\r\n" +
				"Set-Cookie: shared-host-cookie=1; Path=/\r\n" +
				"Location: http://127.0.0.1:" + strconv.Itoa(int(destination.port)) + "/\r\n" +
				"Content-Length: 0\r\n\r\n"
		}
		return okResponse
	})

	a, jar := cookieFollower(t, "127.0.0.1", entry.port, RedirectAlways, true)
	if _, err := a.FollowRedirects(context.Background(), requestTo("127.0.0.1", entry.port, "/start")); err != nil {
		t.Fatalf("FollowRedirects: %v", err)
	}

	// The jar was consulted, and it was consulted about the host the hop names.
	asked := jar.asked()
	if len(asked) != 1 {
		t.Fatalf("the jar was asked %d time(s) (%v); a follower that never asked would replay nothing "+
			"at all, which is the original defect", len(asked), asked)
	}
	if !strings.HasPrefix(asked[0], "127.0.0.1:") {
		t.Errorf("the jar was asked about %q, which is not the hop's authority", asked[0])
	}

	// And the cookie the first hop set is on the wire at the destination, because both are the same
	// host and a browser would send it.
	arrived := destination.lastRequest()
	if !strings.Contains(arrived, "shared-host-cookie") {
		t.Errorf("the destination received %q; a cookie scoped to this HOST was not replayed to it, "+
			"which is less than a browser does (RFC 6265 scopes by host, not by port)", arrived)
	}
}

// A sender with no jar replays nothing even with the setting on. The setting governs the store's
// presence as well as the switch, because a chain that has no store has nothing to replay FROM.
func TestASettingWithNoJarReplaysNothing(t *testing.T) {
	if got := cookieHeaderFor(nil, true, "example.test", 443, true, "/"); got != "" {
		t.Errorf("a nil jar produced the header %q; nothing can be replayed from no store", got)
	}
	jar := newRecordingJar()
	jar.perAuthority["example.test"] = "sid=1"
	if got := cookieHeaderFor(jar, false, "example.test", 443, true, "/"); got != "" {
		t.Errorf("the setting being off produced the header %q", got)
	}
	if got := cookieHeaderFor(jar, true, "example.test", 443, true, "/"); got != "sid=1" {
		t.Errorf("header = %q, want the jar's cookie", got)
	}
}

// The insert must not touch the body. Getting the head boundary wrong splices a header into a payload,
// which is why insertHeaderBeforeTerminator is separate from anything that finds where the body starts.
func TestTheCookieInsertLeavesTheBodyAndEveryOtherHeaderUntouched(t *testing.T) {
	raw := "POST /submit HTTP/1.1\r\nHost: a.test\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nname=value"
	out := string(insertHeaderBeforeTerminator([]byte(raw), "Cookie: sid=1"))
	if !strings.HasPrefix(out, "POST /submit HTTP/1.1\r\n") {
		t.Errorf("the request line changed: %q", out[:40])
	}
	if !strings.HasSuffix(out, "\r\n\r\nname=value") {
		t.Errorf("the body moved or changed: %q", out)
	}
	for _, want := range []string{"Host: a.test", "Content-Type: text/plain", "Content-Length: 9"} {
		if !strings.Contains(out, want) {
			t.Errorf("the header %q was lost: %q", want, out)
		}
	}
	if strings.Count(out, "\r\n\r\n") != 1 {
		t.Errorf("the insert produced a second head boundary: %q", out)
	}
}
