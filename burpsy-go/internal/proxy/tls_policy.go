package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"github.com/burpsy-go/burpsy/internal/alpn"
)

// This file is the proxy leg's upstream TLS policy: whether the certificate the origin presents is
// verified, against which roots, and under which protocol bounds.
//
// # What was wrong
//
// Every intercepted TLS leg opened with alpn.Dialer{InsecureSkipVerify: true}, and nothing anywhere
// could turn that off. The old comment said the choice was deliberate — "the proxy exists to reach
// targets whose certificate an operator cannot fix" — and then pointed at the sender's own TLSVerify
// field as the alternative the proxy did not have. The consequence was concrete rather than
// theoretical: an operator comparing two builds of the same app could not tell from burpsy whether
// the certificate had changed, because a swapped, expired, self-signed or hostname-mismatched
// certificate was indistinguishable from a good one (burpsy-react-ui-f365).
//
// # Why the default is verify, and why the escape hatch stays
//
// Burp's own default is to verify, and so is this. Every assessor meets a self-signed target, and
// the answer to that is a custom CA or the explicit do-not-verify switch — both of which are
// decisions the operator makes and can see. A proxy that cannot verify anything cannot be told to,
// which is a different and much worse tool.
//
// # Why it is a live holder
//
// Same reason StreamingPolicy and Options are: the operator edits this in Settings while traffic is
// flowing, and a value read once at construction would make the edit a lie until a restart.

// TLSPolicy is the live upstream-TLS policy for this proxy's egress leg.
type TLSPolicy struct {
	mu sync.RWMutex
	// verify is whether the origin's certificate is verified. True is the default and Burp's; false is
	// the deliberate opt-out for a self-signed target.
	verify bool
	// roots, when non-nil, replaces the system pool. A custom CA is how an operator reaches a target
	// whose issuer is not in the machine's trust store, without giving up verification entirely —
	// which is the difference between "this one host has a private CA" and "nothing is verified".
	roots *x509.CertPool
	// minVersion is the lowest TLS version accepted, as Burp's protocol selection expresses it.
	// Zero means Go's default, which is the floor Go itself considers safe.
	minVersion uint16
}

// NewTLSPolicy returns the default policy: verification on, the system pool, Go's minimum version.
//
// The default matters. A policy constructed with verification off would be a proxy that cannot detect
// a changed certificate, which is the defect this file exists to close — so the zero value of every
// field is overridden here rather than left to a struct literal somewhere.
func NewTLSPolicy() *TLSPolicy {
	return &TLSPolicy{verify: true}
}

// WithVerify sets whether the origin's certificate is verified.
func (p *TLSPolicy) WithVerify(verify bool) *TLSPolicy {
	p.mu.Lock()
	p.verify = verify
	p.mu.Unlock()
	return p
}

// WithRootCAFile adds a PEM bundle to the pool the origin's certificate is verified against, keeping
// the system pool as well.
//
// A bundle rather than a single certificate because a private CA hierarchy is the normal shape and an
// operator who has one should not have to assemble its leaves in the right order. The file is read
// here rather than held as a path so that an unreadable or malformed bundle is reported at the moment
// it is configured, instead of silently at the first handshake.
func (p *TLSPolicy) WithRootCAFile(path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading the custom CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		// A machine with no system pool is unusual but real — a scratch container, a musl image. The
		// custom CA is then the whole pool, which is what the operator asked for.
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("the custom CA bundle at %s contained no certificates", path)
	}
	p.mu.Lock()
	p.roots = roots
	p.mu.Unlock()
	return nil
}

// WithMinVersion sets the lowest TLS version this proxy will negotiate with an origin.
//
// Burp expresses this as a protocol selection (TLS 1.0 / 1.1 / 1.2 / 1.3) and an operator lowering it
// is usually working around a legacy target, so the value is passed through rather than policed —
// with one floor: a version below TLS 1.0 is refused, because there is no such thing and accepting the
// number would mean a configuration that cannot mean what it says.
func (p *TLSPolicy) WithMinVersion(version uint16) error {
	if version != 0 && version < tls.VersionTLS10 {
		return fmt.Errorf("TLS version 0x%04x is below TLS 1.0; there is no protocol below it to select", version)
	}
	p.mu.Lock()
	p.minVersion = version
	p.mu.Unlock()
	return nil
}

// Verify reports whether the origin's certificate is verified.
func (p *TLSPolicy) Verify() bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.verify
}

// applyTo writes this policy's three settings onto a dialer, leaving everything else it carries —
// the ALPN list, the client certificate source, the upstream proxy carrier, the timeout, the resolver
// — exactly as the caller set it.
//
// It mutates rather than returning a new dialer because those other fields belong to the caller and a
// replacement would silently drop them. The three it does own are read under one lock acquisition, so
// a dial never sees verification from one edit and a root pool from another: an operator turning
// verification off and adding a CA in two clicks should not get a handshake that is half one setting
// and half the other.
func (p *TLSPolicy) applyTo(dialer *alpn.Dialer) {
	if p == nil || dialer == nil {
		return
	}
	p.mu.RLock()
	verify, roots, minVersion := p.verify, p.roots, p.minVersion
	p.mu.RUnlock()

	dialer.InsecureSkipVerify = !verify
	// RootCAs is only consulted when InsecureSkipVerify is false, so setting it while verification is
	// off configures a pool nothing reads. It is set anyway, because an operator who turns verification
	// back on should not have to re-add their CA, and because a pool that looks unconfigured is the
	// kind of thing that gets added twice.
	if roots != nil {
		dialer.RootCAs = roots
	}
	if minVersion != 0 {
		dialer.MinVersion = minVersion
	}
}

// TLS returns the attached upstream-TLS policy, attaching the default one on first use.
//
// Never nil, for the reason ProxyConfig.Streaming is never nil: the dial path consults it on every
// intercepted connection, and a nil check at each of those sites is one of them eventually being
// forgotten. The default verifies, so a proxy built without WithTLS still verifies — which is the
// opposite of what this file's predecessor did unconditionally.
func (c *ProxyConfig) TLS() *TLSPolicy {
	if c.tlsVerify == nil {
		c.tlsVerify = NewTLSPolicy()
	}
	return c.tlsVerify
}

// TLS returns the live upstream-TLS policy, attaching the default one on first use.
//
// The Server-level twin of ProxyConfig.TLS, for the same reason Server.Streaming exists: the web layer
// holds a *Server and pushes operator edits into these policies, and a method that reached into the
// config would be a second way for the answer to differ from the field it reports.
func (s *Server) TLS() *TLSPolicy {
	if s == nil {
		return nil
	}
	return s.config.TLS()
}

// WithUpstreamTLS attaches the upstream-TLS policy the interception leg follows.
//
// The same instance must be handed to the web server so an edit in the console reaches this leg; two
// policies would let the panel describe a verification setting the proxy does not apply, which is the
// same overclaim burpsy-react-ui-f365 records about the missing setting in the first place.
func (c *ProxyConfig) WithUpstreamTLS(policy *TLSPolicy) *ProxyConfig {
	if policy != nil {
		c.tlsVerify = policy
	}
	return c
}

// CarriesUpstreamTLS reports whether this proxy was built with a TLS policy attached.
//
// Exported for the same reason CarriesPlatformAuth is: an operator whose panel says verification is
// on needs to be able to ask whether the leg they are watching applies it, and the answer has to be a
// property of the object rather than a re-derivation from the settings document.
func (c *ProxyConfig) CarriesUpstreamTLS() bool { return c.tlsVerify != nil }
