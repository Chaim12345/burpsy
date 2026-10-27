package extscan

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-extscan-egress tests: the argument builders always route the tool through the gate,
// and the gate refuses out-of-scope requests per request while forwarding in-scope ones through the
// configured egress dialer.

func argAfter(args []string, flag string) (string, bool) {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return "", false
	}
	return args[i+1], true
}

func TestNucleiArgsRouteThroughTheGateHTTPOnlyWithADefaultRateLimit(t *testing.T) {
	target := Target{URL: "http://app.test/", Host: "app.test", Port: 80, Path: "/", scoped: true}
	args := nucleiArgs(target, NucleiOptions{}, "http://127.0.0.1:4567")
	if v, ok := argAfter(args, "-proxy"); !ok || v != "http://127.0.0.1:4567" {
		t.Errorf("-proxy = %q (present %v), want the gate's URL: %v", v, ok, args)
	}
	if v, _ := argAfter(args, "-pt"); v != "http" {
		t.Errorf("-pt = %q, want http: non-HTTP protocols would dial around the proxy: %v", v, args)
	}
	if v, _ := argAfter(args, "-rl"); v != strconv.Itoa(DefaultNucleiRateLimit) {
		t.Errorf("-rl = %q, want the default %d when the caller set none", v, DefaultNucleiRateLimit)
	}
	if !slices.Contains(args, "-ni") {
		t.Errorf("interactsh is not disabled by default: %v", args)
	}
	args = nucleiArgs(target, NucleiOptions{RateLimit: 7}, "http://127.0.0.1:4567")
	if v, _ := argAfter(args, "-rl"); v != "7" {
		t.Errorf("-rl = %q, want the caller's 7", v)
	}
	if n := strings.Count(strings.Join(args, " "), "-rl "); n != 1 {
		t.Errorf("-rl appears %d times", n)
	}
}

func TestFFUFArgsRouteThroughTheGate(t *testing.T) {
	target := Target{URL: "http://app.test/dir/", Host: "app.test", Port: 80, Path: "/dir/", scoped: true}
	args := ffufArgs(target, FFUFOptions{Wordlist: "/w.txt"}, "/tmp/o.json", "http://127.0.0.1:4567")
	if v, ok := argAfter(args, "-x"); !ok || v != "http://127.0.0.1:4567" {
		t.Errorf("-x = %q (present %v), want the gate's URL: %v", v, ok, args)
	}
	if v, _ := argAfter(args, "-u"); v != "http://app.test/dir/FUZZ" {
		t.Errorf("-u = %q", v)
	}
}

func countingServer(t *testing.T, h http.Handler) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepts atomic.Int64
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			accepts.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &accepts
}

func authority(t *testing.T, raw string) (string, uint16) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), uint16(p)
}

// The gate a run starts refuses an out-of-scope request and an excluded path without connecting, and
// forwards an in-scope request through Config.EgressDial.
func TestTheEgressGateRefusesOutOfScopeAndForwardsInScopeThroughTheDialer(t *testing.T) {
	inside, insideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "inside "+r.URL.RequestURI())
	}))
	outside, outsideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	host, port := authority(t, inside.URL)
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPort(core.ScopeInclude, host, port))
	excl, err := core.NewScopeRuleFrom(core.ScopeExclude, host, ptr("/admin"), &port, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope.Add(excl)
	target, err := Authorise(scope, inside.URL+"/")
	if err != nil {
		t.Fatal(err)
	}

	var dials atomic.Int64
	cfg := Config{EgressDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	gate, refusals, mode, err := startEgressGate(cfg, scope, target)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if mode != EgressGatePerRequest {
		t.Errorf("mode = %q for a plain-HTTP target", mode)
	}
	proxyURL, _ := url.Parse(gate.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}

	resp, err := client.Get(inside.URL + "/page?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "inside /page?q=1" || dials.Load() != 1 || insideAccepts.Load() == 0 {
		t.Fatalf("in-scope request not forwarded through the dialer: %d %q dials=%d", resp.StatusCode, body, dials.Load())
	}

	insideBefore := insideAccepts.Load()
	for _, u := range []string{outside.URL + "/x", inside.URL + "/admin/panel"} {
		resp, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d, want 403 from the gate", u, resp.StatusCode)
		}
	}
	if n := outsideAccepts.Load(); n != 0 {
		t.Fatalf("the out-of-scope host accepted %d connection(s)", n)
	}
	if insideAccepts.Load() != insideBefore || dials.Load() != 1 {
		t.Errorf("an excluded path was still connected (accepts %d→%d, dials %d)", insideBefore, insideAccepts.Load(), dials.Load())
	}
	if gate.Refused() != 2 || len(refusals.snapshot()) != 2 {
		t.Errorf("refused = %d, sample %v; want 2", gate.Refused(), refusals.snapshot())
	}
}

func ptr[T any](v T) *T { return &v }

// An HTTPS target lets the gate see only each tunnel's host, so a host the scope authorises only in
// part is refused before launch rather than tunnelled into.
func TestAnHTTPSTargetOnAPartlyScopedHostIsRefusedBeforeLaunch(t *testing.T) {
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPath(core.ScopeInclude, "app.test", "/app/"))
	target, err := Authorise(scope, "https://app.test/app/")
	if err != nil {
		t.Fatalf("Authorise refused the subtree it used to allow: %v", err)
	}
	if _, _, _, err := startEgressGate(Config{}, scope, target); err == nil {
		t.Fatal("an HTTPS target on a partly scoped host got a gate; the tunnel could carry any path on it")
	}
	whole := core.NewScope()
	whole.Add(core.NewScopeRule(core.ScopeInclude, "app.test"))
	target, err = Authorise(whole, "https://app.test/")
	if err != nil {
		t.Fatal(err)
	}
	gate, _, mode, err := startEgressGate(Config{}, whole, target)
	if err != nil {
		t.Fatalf("a wholly in-scope HTTPS host was refused: %v", err)
	}
	gate.Close()
	if mode != EgressGatePerAuthority {
		t.Errorf("mode = %q, want the per-tunnel description", mode)
	}
}
