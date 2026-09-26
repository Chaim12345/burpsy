package upstream

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/core"
)

// This file is the global SOCKS carrier: a TCP layer that sits BENEATH whichever upstream proxy a
// destination rule selects, rather than being one of the kinds a destination rule can name.
//
// # The shape it fixes
//
// Burp's SOCKS setting is a global TCP layer (settings/network/connections.html:177-199): "every
// outbound connection, including requests to upstream HTTP proxies, goes through the SOCKS proxy",
// with per-host bypasses and a remote-DNS choice. burpsy's model makes proxy KIND part of each
// destination rule, and Policy.ForAddr returns exactly one proxy per destination — so there is no
// layer beneath an HTTP upstream proxy.
//
// The shape that costs the operator is the ordinary corporate one: burpsy reaches the internet
// through an HTTP proxy, and that HTTP proxy is itself only reachable through a SOCKS hop. With a
// single-layer rule list they must choose one and lose the other, and the global SOCKS bypass list
// Burp offers is inexpressible for the same reason (burpsy-react-ui-mr83, part 3).
//
// # Why the layering is a dial concern and not a rule-editor one
//
// A destination rule answers "which proxy carries traffic to this host". A carrier answers "what
// opens the socket underneath whatever that answer was". Modelling the second as a rule would mean
// either a second rule list the editor has to explain, or a special destination pattern meaning "the
// proxy itself" — and either way two places would have to agree about which is which. Keeping it in
// the dialer means it composes with every existing path (a direct dial, an HTTP-proxy dial, a SOCKS
// dial) without any of them knowing it exists.
//
// # Why it is a *net.Dialer and not a hook
//
// A carrier composed as a function would need every call site in the tree — sender, proxy, crawler
// — to remember to call it, and one that forgets produces a direct dial that looks like a working
// one. A *net.Dialer cannot be forgotten: it is handed to the same x/net/proxy.SOCKS5 and the same
// net.Dialer the existing SOCKS and direct paths already use, so the carrier is reached by being the
// dialer rather than by being invoked.

// Carrier is the global TCP layer: an optional SOCKS hop every outbound connection is opened
// through, with a bypass list.
//
// It is a holder rather than a value for the same reason Policy is: the operator edits the carrier
// in Settings while traffic flows, and a dialer built from a snapshot would make that edit a lie
// until a restart.
type Carrier struct {
	mu sync.RWMutex
	// socks is the proxy every connection is opened through, or nil for no carrier at all.
	socks *Proxy
	// bypass lists destination host patterns that skip the carrier, checked against the DESTINATION
	// rather than against the proxy address — an operator exempts "my own internal hosts", and the
	// rule is about where traffic is going, not about what it is opened with.
	//
	// The SOCKS server's own address is exempt unconditionally, and matching it here rather than in
	// the dial loop is what stops the carrier from dialling itself.
	bypass []*core.ScopeRule
	// remoteResolve asks the SOCKS server to resolve the destination name, which is what makes a
	// split-horizon or internal-only hostname reachable through it.
	remoteResolve bool
	// attached counts the egress surfaces holding this carrier, for the reason Policy.Attach exists.
	attached map[string]int
}

// NewCarrier returns a carrier with no SOCKS hop configured, which is the behaviour every dial in
// this tree had before the carrier existed: a direct TCP connect.
func NewCarrier() *Carrier { return &Carrier{} }

// SetSocks installs the carrier's SOCKS proxy, with its bypass list and remote-DNS choice.
//
// An empty address clears the carrier, which is the honest reading of an operator removing the
// setting: no hop, rather than a hop to nowhere. The remote-DNS flag is refused for a non-SOCKS
// proxy, because "resolve the name at the proxy" is a statement about the SOCKS protocol and a
// setting that is silently ignored on an HTTP proxy would be a switch that does nothing.
func (c *Carrier) SetSocks(raw string, bypass []string, remoteResolve bool) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		c.mu.Lock()
		c.socks = nil
		c.bypass = nil
		c.remoteResolve = false
		c.mu.Unlock()
		return nil
	}
	proxy, err := Parse(trimmed)
	if err != nil {
		return err
	}
	if remoteResolve && proxy.kind != KindSOCKS4 && proxy.kind != KindSOCKS5 {
		return fmt.Errorf("remote DNS resolution is a SOCKS feature, and %q is a %s proxy: the setting "+
			"would be silently ignored", trimmed, proxy.kind)
	}
	compiled := make([]*core.ScopeRule, 0, len(bypass))
	for _, pattern := range bypass {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		// The same constructor a destination rule uses, so a bypass pattern is written in the same
		// language: exact name, or `*.example.com`. A second pattern dialect here would be a rule the
		// editor accepts and the carrier silently never matches.
		compiled = append(compiled, core.NewScopeRule(core.ScopeInclude, pattern))
	}
	c.mu.Lock()
	c.socks = &proxy
	c.remoteResolve = remoteResolve
	c.bypass = compiled
	c.mu.Unlock()
	return nil
}

// Attach records that one egress surface holds this carrier.
//
// The reason it exists, and the reason it is the same shape as Policy.Attach: a rule or a carrier
// reaches exactly the surfaces that hold the object, and there is no way for the API to know that
// from the object's contents. Reported beside the carrier so an operator can see whether the proxy
// listener's own upstream leg is covered, rather than reading a panel that looks global and is not.
func (c *Carrier) Attach(surface string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.attached == nil {
		c.attached = map[string]int{}
	}
	c.attached[surface]++
}

// Limits names, in the operator's terms, what this carrier does not carry.
//
// It exists so the panel can say it rather than the code saying it in a comment. A carrier that
// silently skips one destination is a setting that looks complete and is not, which is the same
// overclaim AttachedSurfaces exists to prevent one level up.
func (c *Carrier) Limits() []string {
	return []string{
		// crypto/tls calls DialContext on the net.Dialer it is handed, and Go's net.Dialer has no
		// field a carrier can replace — so the hop cannot go underneath an HTTPS upstream proxy
		// without reimplementing the TLS dial here. Every other leg is carried.
		"an https:// upstream proxy is not carried (its TLS dial cannot be placed under a SOCKS hop)",
	}
}

// AttachedSurfaces names every surface holding this carrier, sorted for a stable panel.
func (c *Carrier) AttachedSurfaces() []string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.attached))
	for name, count := range c.attached {
		for i := 0; i < count; i++ {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Configured reports whether a SOCKS hop is installed, and which one with its bypass list — the
// value the settings panel reads so it can show what is in force rather than what was typed.
func (c *Carrier) Configured() (proxy string, bypass []string, remoteResolve bool, ok bool) {
	if c == nil {
		return "", nil, false, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.socks == nil {
		return "", nil, false, false
	}
	out := make([]string, 0, len(c.bypass))
	for _, rule := range c.bypass {
		out = append(out, rule.Pattern)
	}
	return c.socks.String(), out, c.remoteResolve, true
}

// carries reports whether a connection to host should be opened through the SOCKS hop, and returns
// the hop to use.
//
// The SOCKS server's own address is exempt, and that exemption is the difference between a working
// carrier and a hang: a SOCKS hop that dialled itself would wait for a reply from itself, and every
// outbound connection would time out.
func (c *Carrier) carries(host string, port string) (*Proxy, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.socks == nil {
		return nil, false
	}
	// Host AND port, not host alone. A SOCKS server on 127.0.0.1:1080 must not exempt
	// 127.0.0.1:443 — that would silently exempt every other service the operator runs locally, which
	// is a carrier that quietly does nothing for a dev-box operator. The exemption exists to stop the
	// hop dialling ITSELF, and the hop is one specific authority.
	if sameHost(host, c.socks.hostOnly()) && sameHost(port, c.socks.portOnly()) {
		return nil, false
	}
	for _, rule := range c.bypass {
		// Port 0: a bypass is about the HOST, and RFC 6265 scopes cookies the same way — a rule that
		// matched on the destination's port would exempt nothing an operator writing host patterns
		// intended to exempt, because the port is whatever the target happens to serve on.
		if rule.Matches(host, 0) {
			return nil, false
		}
	}
	return c.socks, c.remoteResolve
}

// dialTCP opens a TCP connection to addr, through the SOCKS hop when this carrier carries it and
// through base otherwise.
//
// It is the whole feature, and it is a FUNCTION rather than a *net.Dialer for a reason worth naming:
// Go's net.Dialer exposes Dial and DialContext as METHODS with no field of either name, so a dialer
// cannot be given a different dialer and have its own method used. Returning a *net.Dialer whose
// "dial" someone hoped was overridden would be a dialer that silently ignores the carrier.
//
// So the carrier is applied where a connection is actually opened -- the one seam every path in this
// package goes through, whether the destination is an origin, an HTTP upstream proxy or a SOCKS rule
// proxy -- rather than as a dialer a call site might remember to use. A path that forgets it produces
// a direct dial, which is exactly what an unconfigured carrier produces, so the failure is a missing
// feature rather than a broken one: and there is one caller of this function, not a convention to
// maintain at each of them.
func (c *Carrier) dialTCP(ctx context.Context, base *net.Dialer, network, addr string) (net.Conn, error) {
	if base == nil {
		base = &net.Dialer{}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// An address this cannot split is handed straight to the base dialer rather than refused: the
		// carrier is a layer, not a gate, and refusing here would break a dial the unconfigured proxy
		// makes perfectly well.
		return base.DialContext(ctx, network, addr)
	}
	socks, remote := c.carries(host, port)
	if socks == nil {
		return base.DialContext(ctx, network, addr)
	}
	return socks.dialVia(ctx, network, addr, base, remote)
}

// CarrierSnapshot is the carrier as a value, for the settings row that persists it.
//
// A carrier that came back from disk without its hop would be configured on screen and direct on the
// wire, which is the same class of lie the upstream policy's persistence note warns about: a setting
// that looks saved and stops working.
type CarrierSnapshot struct {
	Socks         string   `json:"socks"`
	Bypass        []string `json:"bypass"`
	RemoteResolve bool     `json:"remote_resolve"`
}

// Snapshot returns the carrier as a value.
func (c *Carrier) Snapshot() CarrierSnapshot {
	proxy, bypass, remote, _ := c.Configured()
	return CarrierSnapshot{Socks: proxy, Bypass: bypass, RemoteResolve: remote}
}

// Restore installs a persisted snapshot.
//
// A refusal is returned rather than swallowed, and the caller decides: a carrier that could not be
// restored is a dial path that will go direct, and the operator has to be told rather than discover it
// as a connection that stopped being carried.
func (c *Carrier) Restore(snap CarrierSnapshot) error {
	return c.SetSocks(snap.Socks, snap.Bypass, snap.RemoteResolve)
}

// installed reports whether a hop is configured, read once so a dial does not take the lock twice.
func (c *Carrier) installed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.socks != nil
}

// sameHost compares two hostnames case-insensitively, which is what every other host comparison in
// this tree does and what a bypass list needs to match on.
func sameHost(a, b string) bool {
	return strings.EqualFold(a, b)
}
