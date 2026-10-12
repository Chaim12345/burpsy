package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// The Host header, response-header-injection and SMTP header injection checks, run directly against
// the vulnapp fixtures (and two purpose-built servers) so each guard has a case that fails when the
// guard is removed:
//
//   - URL position: /hh/safe/home prints the Host as text and inside another URL's query string;
//   - the moving control: stickyHost keeps the first host it was ever told and reflects that forever;
//   - parsed headers, not body text: /crlf/safe/body prints the header lines into the body;
//   - the request-header echo control: /crlf/safe/ref echoes every request header back;
//   - the separator-specific control: /mail/safe/validate rejects any punctuation with a mail error;
//   - mail-library evidence only: /mail/safe/dynamic differs from its baseline on every request
//     (the j1mk.41 false positive).

type checkTarget struct {
	rt   *runtimeTarget
	scan *ActiveScanner
}

func newCheckTarget(t *testing.T, h http.Handler, cfg *ScanConfig, endpoints ...vulnapp.Endpoint) *checkTarget {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(), exchanges: map[string]core.ExchangeID{}}
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, e := range endpoints {
		rt.seed(t, client, e)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	return &checkTarget{rt: rt, scan: scan}
}

func (c *checkTarget) run(t *testing.T, path string, check CheckRunner) []*Finding {
	t.Helper()
	ex, err := c.rt.store.GetExchange(c.rt.exchanges[path])
	if err != nil {
		t.Fatalf("%s was not seeded: %v", path, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fs, err := check(ctx, NewCheckContext(c.scan, ex, nil))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return fs
}

func vulnappEndpoint(t *testing.T, path string) vulnapp.Endpoint {
	t.Helper()
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("%s is not in the vulnapp manifest", path)
	return vulnapp.Endpoint{}
}

func vulnappTarget(t *testing.T, cfg *ScanConfig, paths ...string) *checkTarget {
	t.Helper()
	var eps []vulnapp.Endpoint
	for _, p := range paths {
		eps = append(eps, vulnappEndpoint(t, p))
	}
	return newCheckTarget(t, vulnapp.Handler(), cfg, eps...)
}

func TestHostHeaderInjectionNamesTheVehicleAndTheURL(t *testing.T) {
	ct := vulnappTarget(t, &ScanConfig{CheckHostHeader: true}, "/hh/home", "/hh/redirect", "/hh/fwd")
	for path, want := range map[string][]string{
		"/hh/home":     {"Host header:", "body URL", "Host header port"},
		"/hh/redirect": {"Host header: Location: http://"},
		"/hh/fwd":      {"X-Forwarded-Host: body URL"},
	} {
		fs := ct.run(t, path, checkHostHeaderInjection)
		if len(fs) != 1 || fs[0].Name != IssueHostHeaderInjection {
			t.Fatalf("%s: got %v, want one %q finding", path, fs, IssueHostHeaderInjection)
		}
		for _, w := range want {
			if !strings.Contains(fs[0].Evidence, w) {
				t.Errorf("%s: evidence %q lacks %q", path, fs[0].Evidence, w)
			}
		}
		if !strings.Contains(fs[0].Evidence, ".invalid") {
			t.Errorf("%s: evidence %q does not name the canary host", path, fs[0].Evidence)
		}
	}
}

func TestHostHeaderInjectionNeedsAURLAuthorityNotText(t *testing.T) {
	ct := vulnappTarget(t, &ScanConfig{CheckHostHeader: true}, "/hh/safe/home", "/hh/safe/redirect", "/hh/safe/fwd")
	for _, path := range []string{"/hh/safe/home", "/hh/safe/redirect", "/hh/safe/fwd"} {
		if fs := ct.run(t, path, checkHostHeaderInjection); len(fs) != 0 {
			t.Errorf("%s reflects the Host only as text or inside another URL's query, yet: %s", path, fs[0].Evidence)
		}
	}
}

// stickyHost remembers the first non-loopback Host it is sent and links to it forever after: the
// first canary appears as a link host, but a second canary does not move it.
type stickyHost struct {
	mu   sync.Mutex
	host string
}

func (s *stickyHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.host == "" && !strings.HasPrefix(r.Host, "127.0.0.1") {
		s.host = r.Host
	}
	h := s.host
	s.mu.Unlock()
	if h == "" {
		h = "app.example.test"
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<a href="https://%s/home">home</a>`, h)
}

func TestHostHeaderInjectionNeedsTheControlCanaryToMove(t *testing.T) {
	ct := newCheckTarget(t, &stickyHost{}, &ScanConfig{CheckHostHeader: true}, vulnapp.Endpoint{Path: "/sticky"})
	if fs := ct.run(t, "/sticky", checkHostHeaderInjection); len(fs) != 0 {
		t.Errorf("a host that does not move with the control canary was reported: %s", fs[0].Evidence)
	}
}

func TestHostURLSightingsReadsURLsTheWayABrowserDoes(t *testing.T) {
	const base = "http://app.test/x"
	resp := func(head, body string) []byte { return []byte("HTTP/1.1 200 OK\r\n" + head + "\r\n" + body) }
	cases := []struct {
		raw  []byte
		want bool
	}{
		{resp("Location: https://evil.invalid/a\r\n", ""), true},
		{resp("Location: /\\evil.invalid/a\r\n", ""), true},
		{resp("Location: https://app.test/?next=//evil.invalid\r\n", ""), false},
		{resp("", `<script src="//evil.invalid/a.js">`), true},
		{resp("", `{"u":"https:\/\/evil.invalid\/a"}`), true},
		{resp("", `<a href="https://app.test/login?next=//evil.invalid/a">`), false},
		{resp("", `<p>host evil.invalid</p>`), false},
		{resp("", `<a href="https://evil.invalid.app.test/">`), false},
		{resp("", `<meta http-equiv="refresh" content="0;url=//evil.invalid/">`), true},
	}
	for i, c := range cases {
		if got := len(hostURLSightings(base, c.raw, "evil.invalid", false)) > 0; got != c.want {
			t.Errorf("case %d (%q): sighted = %v, want %v", i, c.raw, got, c.want)
		}
	}
}

func TestResponseHeaderInjectionDepthAndSites(t *testing.T) {
	ct := vulnappTarget(t, &ScanConfig{}, "/crlf/r/home", "/crlf/ref", "/crlf/unicode?msg=seed", "/echo?msg=seed")
	for path, want := range map[string]string{
		"/crlf/r/home":           "the URL path",
		"/crlf/ref":              "header Referer",
		"/crlf/unicode?msg=seed": "Unicode %E5%98%8D%E5%98%8A",
		"/echo?msg=seed":         "query msg",
	} {
		fs := ct.run(t, path, checkResponseHeaderInjection)
		if len(fs) != 1 {
			t.Fatalf("%s: got %d findings, want 1", path, len(fs))
		}
		if !strings.Contains(fs[0].Evidence, want) || fs[0].Confidence != "certain" {
			t.Errorf("%s: %s %q, want certain and naming %q", path, fs[0].Confidence, fs[0].Evidence, want)
		}
	}
}

func TestResponseHeaderInjectionNeedsAParsedNewHeader(t *testing.T) {
	ct := vulnappTarget(t, &ScanConfig{}, "/crlf/safe/r/home", "/crlf/safe/ref", "/crlf/safe/unicode?msg=seed",
		"/crlf/safe/body?msg=seed", "/safe/echo?msg=seed")
	for _, path := range []string{"/crlf/safe/r/home", "/crlf/safe/ref", "/crlf/safe/unicode?msg=seed",
		"/crlf/safe/body?msg=seed", "/safe/echo?msg=seed"} {
		if fs := ct.run(t, path, checkResponseHeaderInjection); len(fs) != 0 {
			t.Errorf("%s does not split its headers, yet: %s", path, fs[0].Evidence)
		}
	}
}

func TestCRLFProbeSplitReadsOnlyParsedHeaders(t *testing.T) {
	p := crlfProbe{header: "X-habc", value: "vdef", cookie: "kghi", cookieValue: "wjkl"}
	for raw, want := range map[string]bool{
		"HTTP/1.1 200 OK\r\nX-A: 1\r\nX-habc: vdef\r\n\r\n":          true,
		"HTTP/1.1 200 OK\nX-A: 1\nSet-Cookie: kghi=wjkl; Path=/\n\n": true,
		"HTTP/1.1 200 OK\r\nX-A: 1\rX-habc: vdef\r\n\r\n":            false, // a bare CR does not end a line
		"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nX-habc: vdef\r\n":          false, // body text
		"HTTP/1.1 200 OK\r\nX-A: c%0d%0aX-habc:vdef\r\n\r\n":         false,
		"HTTP/1.1 200 OK\r\nSet-Cookie: kghi=other\r\n\r\nkghi=wjkl": false,
	} {
		if got := p.split([]byte(raw)) != ""; got != want {
			t.Errorf("split(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestSMTPHeaderInjectionNeedsASeparatorSpecificMailError(t *testing.T) {
	cfg := &ScanConfig{CheckExtendedActive: true}
	ct := vulnappTarget(t, cfg, "/mail/contact?subject=hello", "/mail/safe/contact?subject=hello",
		"/mail/safe/validate?email=hello@example.test", "/mail/safe/dynamic?subject=hello")
	fs := ct.run(t, "/mail/contact?subject=hello", checkSMTPHeaderInjection)
	if len(fs) != 1 || fs[0].Confidence != "tentative" || !strings.Contains(fs[0].Description, "subject") {
		t.Fatalf("/mail/contact: got %v, want one tentative finding on subject", fs)
	}
	for _, path := range []string{"/mail/safe/contact?subject=hello", "/mail/safe/validate?email=hello@example.test",
		"/mail/safe/dynamic?subject=hello"} {
		if fs := ct.run(t, path, checkSMTPHeaderInjection); len(fs) != 0 {
			t.Errorf("%s: no line break reaches a mailer, yet: %s", path, fs[0].Description)
		}
	}
}

// The OOB rows plant the collaborator as the request's host: a front end that routes by Host
// contacts it, and the interaction is attributed to the Host vehicle.
func TestRoutingBasedSSRFIsConfirmedByAHostCallback(t *testing.T) {
	ct := newCheckTarget(t, vulnapp.Handler(), &ScanConfig{CheckExtendedActive: true, CheckOutOfBand: true,
		PendingDeadline: time.Minute}, vulnapp.Endpoint{Path: "/hh/route"})
	collab := &vulnappCollaborator{domain: "collab-hostroute.test"}
	ct.scan.WithOOBProvider(&vulnappOOBProvider{ch: collab})
	ex, err := ct.rt.store.GetExchange(ct.rt.exchanges["/hh/route"])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = oobCheck("External service interaction (HTTP)", "http")(ctx, NewCheckContext(ct.scan, ex, nil))
	if err == nil || !strings.Contains(err.Error(), "awaiting callback") {
		t.Fatalf("want an inconclusive 'awaiting callback' result, got %v", err)
	}
	var found *Finding
	findings, _ := ct.scan.Pending().Poll(ctx)
	for _, f := range findings {
		if f != nil {
			found = f
		}
	}
	if found == nil || !strings.Contains(found.Description, "routing-based SSRF") {
		t.Fatalf("the routed Host callback was not settled into a routing-based SSRF finding: %+v", found)
	}
}
