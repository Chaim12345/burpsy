package extscan

// The per-request egress gate for delegated tools (burpsy-react-ui-extscan-egress).
//
// Authorise decides once, up front, whether the subtree a tool may reach is in scope. That is
// necessary and was never sufficient: nuclei templates name their own paths ({{RootURL}} templates go
// to the host root whatever path the target named), a wordlist entry can carry "../", and either tool
// can follow a redirect to another host — and until this file existed, the only scope check after
// launch was a filter over the RESULTS, applied after every request had been sent.
//
// So every run now goes through a burpsy-owned loopback forward proxy (internal/egressgate), passed
// to the tool as its proxy (nuclei -proxy, ffuf -x). The proxy refuses, before anything is dialled,
// every request the engagement scope does not authorise, and dials what it allows through
// Config.EgressDial — the sender's egress route (upstream proxy, SOCKS carrier, resolution table) —
// so a delegated scan leaves the machine the way every other burpsy request does.
//
// What the proxy can see bounds what it enforces, and the result says which applied (EgressGate):
//
//   - plain HTTP: the full request URL, so every request is authorised on its own path;
//   - HTTPS: a CONNECT tunnel whose contents are TLS the tool negotiates end to end, so only the
//     authority is visible. A tunnel is therefore allowed only to a host the scope authorises as a
//     whole (its root and an invented path beneath it, Authorise's own subtree question asked at
//     "/"), and an HTTPS target on a host the scope authorises only in part is refused before
//     launch. Path-scoped EXCLUDES on a host otherwise wholly in scope are not visible inside the
//     tunnel; the result filters still drop anything reported there.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/egressgate"
)

// DefaultNucleiRateLimit is the request rate (nuclei -rl) a run gets when the caller sets none.
// nuclei's own default is 150 requests per second, which is a load test, not an assessment; 50 keeps
// a default run polite while still finishing a template corpus in reasonable time. An engagement with
// a rate agreement sets NucleiOptions.RateLimit explicitly.
const DefaultNucleiRateLimit = 50

// maxRefusalsRecorded bounds the refusal sample a result carries; GateRefused counts them all.
const maxRefusalsRecorded = 50

// Egress-gate descriptions, carried on a result so a reader knows what was enforced per request.
const (
	EgressGatePerRequest   = "per request: every request's URL was authorised by the engagement scope before it was sent"
	EgressGatePerAuthority = "per tunnel: the target is HTTPS, so each CONNECT's host:port was authorised (the whole host must be in scope); paths inside TLS were not visible to burpsy"
)

// rawAuthoriser is *core.Scope's composed-request gate. When the scope offers it the gate uses it, so
// the drop switch and a custom drop scope apply exactly as they do to Repeater.
type rawAuthoriser interface {
	AuthoriseRaw(host string, port uint16, isTLS bool, raw []byte) error
}

// scopeGate adapts the engagement scope to egressgate.Gate.
type scopeGate struct{ scope ScopeAuthoriser }

func (g scopeGate) allow(host string, port uint16, uri string, tls bool) error {
	if g.scope == nil {
		return errors.New("no engagement scope")
	}
	if ra, ok := g.scope.(rawAuthoriser); ok {
		return ra.AuthoriseRaw(host, port, tls, []byte("GET "+uri+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"))
	}
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if !g.scope.Contains(host, port, path, tls) {
		return errors.New("out of scope")
	}
	return nil
}

func (g scopeGate) AllowURL(u *url.URL) error {
	tls := strings.EqualFold(u.Scheme, "https")
	if !tls && !strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("scheme %q is not sent", u.Scheme)
	}
	uri := u.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	if u.RawQuery != "" {
		uri += "?" + u.RawQuery
	}
	return g.allow(u.Hostname(), urlPort(u, tls), uri, tls)
}

// AllowAuthority admits a tunnel only to a host the scope authorises as a whole — see the file doc.
func (g scopeGate) AllowAuthority(host string, port uint16, tls bool) error {
	if err := g.allow(host, port, "/", tls); err != nil {
		return err
	}
	if err := g.allow(host, port, "/"+unauthorisedProbe, tls); err != nil {
		return fmt.Errorf("the scope authorises only part of %s, and a tunnel can carry any path on it: %w", host, err)
	}
	return nil
}

func urlPort(u *url.URL, tls bool) uint16 {
	var n uint64
	if p := u.Port(); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil && n > 0 && n < 65536 {
			return uint16(n)
		}
	}
	if tls {
		return 443
	}
	return 80
}

// refusalLog collects what the gate refused during one run.
type refusalLog struct {
	mu     sync.Mutex
	sample []string
}

func (l *refusalLog) record(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.sample) < maxRefusalsRecorded {
		l.sample = append(l.sample, line)
	}
}

func (l *refusalLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.sample...)
}

// startEgressGate starts the per-run gate for target, refusing up front a target the gate itself
// would refuse — a run whose every request would be refused is not a scan.
func startEgressGate(cfg Config, scope ScopeAuthoriser, target Target) (*egressgate.Proxy, *refusalLog, string, error) {
	if scope == nil {
		return nil, nil, "", fmt.Errorf("%w: no scope was supplied, and a delegated scan is not run unauthorised", ErrUnauthorised)
	}
	g := scopeGate{scope: scope}
	mode := EgressGatePerRequest
	if target.IsTLS {
		mode = EgressGatePerAuthority
		if err := g.AllowAuthority(target.Host, target.Port, true); err != nil {
			return nil, nil, "", fmt.Errorf("%w: %s is HTTPS, so burpsy's egress gate sees only the host of each "+
				"request the tool sends, and the scope does not authorise the whole host (%v) — widen the "+
				"scope to the host, or scan it with burpsy's own checks, which are gated per request",
				ErrUnauthorised, target.URL, err)
		}
	}
	log := &refusalLog{}
	p, err := egressgate.Start(g, log.record, cfg.EgressDial)
	if err != nil {
		return nil, nil, "", err
	}
	return p, log, mode, nil
}
