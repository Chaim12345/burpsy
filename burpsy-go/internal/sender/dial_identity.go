package sender

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// dialIdentity is one send's frozen answer to "what carries this connection": every mutable
// input the dial reads, captured once before the dial begins, in exactly the form the dial
// will consume it, plus the pool stamp computed from those same frozen values.
//
// burpsy-react-ui-o388-predial-vs-dial: the stamp the pools reuse-check against used to be
// captured before the dial while the dial re-read the live stores as it worked — the client
// certificate at the handshake's CertificateRequest, the upstream rule and the carrier
// inside the dial itself. A change landing between the capture and the consumption stamped
// the connection with an identity it did not have, and flipping the store back made the
// mis-stamped connection match again (the ABA the o388 narrow fix left open). Freezing
// closes that by construction: the stamp and the socket come from one read, so a connection
// can no longer be labelled with an identity it never presented.
//
// The resolver, the dial-address override and the TLS policy are not individually hashable;
// they live in NetworkSettings and reach the dial only through ApplyNetwork, so a generation
// counter that ApplyNetwork and WithUpstreamCarrier bump stands in for all of them at once.
// That is also what retires the caller-owned h2 sessions on a settings change: ApplyNetwork
// flushes the h1 pool (closeAll) but cannot flush sessions it does not own, and the stamp
// can.
type dialIdentity struct {
	// gen is the network-settings generation at capture — see the type note.
	gen uint64
	// upstream is the policy frozen to this host's resolution: a single-default policy built
	// from the one locked For read at capture, so the dial consumes what the stamp names
	// however the live policy mutates afterwards. Nil when the sender has no policy at all,
	// which upstream.Dialer already reads as "dial directly".
	upstream *upstream.Policy
	// wrap is the Carry gate's answer at capture: a non-empty policy or a configured carrier
	// routes the dial through upstream.Dialer. Taken from the live policy's emptiness rather
	// than the frozen resolution so the gate keeps its exact dialTLS meaning; the gate and
	// the rule read can straddle a mutation, and then the stamp still names the route the
	// dial consumed, which is the property the pools rely on.
	wrap bool
	// carrier is the global SOCKS layer in force at capture, read under s.mu with the
	// generation: WithUpstreamCarrier writes the pointer and bumps the generation inside one
	// locked section, so the two are always a consistent pair — a capture either precedes a
	// swap or follows it, never straddles it.
	carrier *upstream.Carrier
	// cert is the client certificate the handshake presents: the store's answer at capture,
	// replayed by frozenCerts when the dialer's GetClientCertificate asks. Nil presents none,
	// which is also what a nil store meant at capture.
	cert *tls.Certificate
	// fingerprint is the resolved ClientHello fingerprint at capture (63pf). The bindings
	// mutate without a generation bump, so the resolved value rides the identity and the
	// stamp rather than being re-read at dial time.
	fingerprint alpn.Fingerprint
	// route is the reuse stamp, in the shape routeState established (o388) with the
	// generation prepended and the fingerprint appended: gen, the frozen upstream rule, the
	// frozen certificate's leaf hash, the fingerprint.
	route string
}

// frozenCerts answers the dialer's per-handshake certificate lookup with the capture-time
// answer, so the certificate presented is the one the stamp names even when the store has
// changed since.
type frozenCerts struct{ cert *tls.Certificate }

// For implements alpn.ClientCertSource. The lookup key is ignored: the binding was resolved
// for the dial's own host at capture, and the dialer asks for exactly that host — the SNI
// override changes the extension, not the lookup (see alpn.Dialer).
func (f frozenCerts) For(string) *tls.Certificate { return f.cert }

// certSource returns the frozen store for the alpn dialer, or nil when no certificate was
// bound at capture — a nil source is the dialer's "never present one".
func (id dialIdentity) certSource() alpn.ClientCertSource {
	if id.cert == nil {
		return nil
	}
	return frozenCerts{cert: id.cert}
}

// captureDialIdentity reads every mutable dial input once, immediately before the dial it
// will drive, and derives the pool stamp from the same values. It replaces routeState: the
// stamp's inputs and the dial's inputs are now one read by construction, not two reads hoped
// to land close together.
func (s *Sender) captureDialIdentity(host string, useTLS bool) dialIdentity {
	// The generation, the carrier and the config pointer are read under one RLock so the
	// snapshot the stamp and the dial are built from can never straddle a setter's swap.
	s.mu.RLock()
	id := dialIdentity{gen: s.netGen, carrier: s.carrier}
	cfg := s.config
	s.mu.RUnlock()
	route := "direct"
	if s.upstream != nil {
		// One locked read; Proxy is an immutable value. Raw renders a URL Parse accepts —
		// that round trip is the persistence contract — so rebuilding a single-default policy
		// from it cannot fail.
		proxy := s.upstream.For(host)
		frozen := upstream.NewPolicy()
		_ = frozen.SetDefault(proxy.Raw())
		id.upstream = frozen
		route = proxy.Raw()
	}
	id.wrap = (s.upstream != nil && !s.upstream.Empty()) || id.carrier != nil
	if useTLS && cfg != nil {
		if cfg.ClientCerts != nil {
			if cert := cfg.ClientCerts.For(host); cert != nil {
				id.cert = cert
				if len(cert.Certificate) > 0 {
					sum := sha256.Sum256(cert.Certificate[0])
					route += "\x00" + hex.EncodeToString(sum[:8])
				} else {
					route += "\x00"
				}
			} else {
				route += "\x00"
			}
		}
		if cfg.TLSFingerprints != nil {
			id.fingerprint = cfg.TLSFingerprints.For(host)
		}
	}
	id.route = strconv.FormatUint(id.gen, 10) + "\x00" + route + "\x00" + string(id.fingerprint)
	return id
}
