package sender

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// dialIdentity is one dial decision's frozen answer to "what carries this connection": every
// mutable input the dial reads, captured once at the dial decision point, in exactly the
// form the dial will consume it, plus the pool stamp computed from those same frozen values.
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
// What is frozen, and what is only versioned:
//
//   - settings is the NetworkSettings value at capture: the dial's resolver, dial-address
//     override, timeouts and TLS policy are consumed from it, so the dial reads the same
//     settings the stamp's generation versions. The sub-structs HTTP1/2/3 are pointers
//     shared with the stored settings; nothing in-tree mutates them after ApplyNetwork
//     (both callers pass freshly built values, and Normalise rebuilds the overrides slice),
//     so the generation — bumped by every ApplyNetwork and WithUpstreamCarrier — covers
//     every in-tree mutation path. A future in-place mutation path must bump it too.
//   - upstream is the WHOLE policy as a value at capture (the Snapshot -> Restore
//     persistence round trip), not the one resolved rule: the dial resolves the policy for
//     the address it dials (the override's answer, often an IP literal — ForAddr), and a
//     rule list reduced to the resolved rule would answer isHTTPProxyAddr differently for a
//     target that is itself a configured proxy. wrap answers from the same snapshot, so the
//     gate and the consumed policy cannot disagree about the instant they describe.
//   - cert is a copy of the store's answer at capture (frozenCert), replayed by frozenCerts,
//     and the stamp hashes that copy. In-tree bindings are immutable once loaded
//     (LoadClientCert builds a fresh tls.Certificate; Add/Remove/ReplaceWith swap entries,
//     never edit one); the copy is what keeps an embedder that reassigns a bound
//     tls.Certificate's fields in place from desyncing presentation from stamp. Writes INTO a
//     DER buffer or a key object remain outside what any freeze short of a deep key copy sees.
//   - carrier is a frozen copy of the global SOCKS layer's configuration at capture
//     (upstream.Carrier.Freeze), not the live holder. The holder is edited IN PLACE — the
//     operator's /api/network/proxy edit is Carrier.SetSocks on the one instance every surface
//     shares — so the pointer and the generation never move on an edit, and a stamp that named
//     the carrier only through them let a connection dialled direct answer sends made after
//     the operator configured a hop. The stamp therefore names the carrier's own identity, and
//     the dial consumes the copy that identity was read from.
//   - fingerprint is the resolved ClientHello fingerprint at capture (63pf): a dial input
//     outside the settings generation's reach, populated only at construction in-tree, but
//     freezable for one read, so it rides the identity rather than being re-read at dial
//     time.
//
// The stamp is in-memory only — pooled connections and h2 sessions carry it, nothing logs,
// encodes or dumps it — so the rule's and the carrier hop's Raw forms (credentials included,
// per the persistence contract) never leave the process through it.
type dialIdentity struct {
	// gen is the network-settings generation at capture, read under s.mu with the carrier
	// and the config: WithUpstreamCarrier writes the pointer and bumps the generation inside
	// one locked section, so the pair can never straddle a swap.
	gen uint64
	// settings is the network settings value at capture — see the type note for what the
	// value shares with the stored settings and why that is safe today.
	settings NetworkSettings
	// dialAddr is the address the dial opens: settings.dialAddressFor at capture. It is also
	// the upstream policy's lookup key (ForAddr), so the frozen rule is resolved for exactly
	// what the socket connects to.
	dialAddr string
	// upstream is the whole policy as a value at capture — see the type note. Nil when the
	// sender has no policy, which upstream.Dialer already reads as "dial directly".
	upstream *upstream.Policy
	// wrap is the Carry gate's answer from the SAME snapshot as upstream: a non-empty frozen
	// policy or a configured carrier routes the dial through upstream.Dialer. A policy change
	// after capture cannot tear the gate from the route, because both describe the capture
	// instant; the next dial decision recaptures.
	wrap bool
	// carrier is the global SOCKS layer's configuration at capture, frozen — see the type note.
	// Nil exactly when the sender holds no carrier, so the wrap gate reads as it always did.
	carrier *upstream.Carrier
	// cert is the client certificate the handshake presents — see the type note for the
	// in-place-mutation boundary. Nil presents none, which is also what a nil store meant at
	// capture.
	cert *tls.Certificate
	// fingerprint is the resolved ClientHello fingerprint at capture.
	fingerprint alpn.Fingerprint
	// route is the reuse stamp: the generation, the frozen rule FOR THE DIALLED ADDRESS,
	// the frozen certificate's leaf hash, the frozen carrier's identity and the fingerprint —
	// the o388 shape with the generation prepended and the fingerprint appended, and with the
	// rule resolved for the dialled address rather than the original host (the dial's own
	// lookup key). The generation is what covers the settings-borne dial inputs — resolver,
	// dial-address override, timeouts and TLS policy — because every write to s.net bumps it.
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

// certAnswer reads the client-certificate answer for host from cfg, and whether the question is
// asked at all. Capture and take re-evaluation share it, and both render it with certSuffix, so
// both pin the same answer in the same form.
func certAnswer(cfg *SenderConfig, host string, useTLS bool) (*tls.Certificate, bool) {
	if !useTLS || cfg == nil || cfg.ClientCerts == nil {
		return nil, false
	}
	return cfg.ClientCerts.For(host), true
}

// fingerprintAnswer is the client-fingerprint answer for host, shared by capture and take
// re-evaluation for the same reason.
func fingerprintAnswer(cfg *SenderConfig, host string, useTLS bool) alpn.Fingerprint {
	if !useTLS || cfg == nil || cfg.TLSFingerprints == nil {
		return ""
	}
	return cfg.TLSFingerprints.For(host)
}

// routeStamp assembles the fingerprint both sides of a pool exchange compare. One assembler
// keeps the dial-time capture and the take-time re-evaluation byte-identical in form.
func routeStamp(gen uint64, route, carrier string, fp alpn.Fingerprint) string {
	return strconv.FormatUint(gen, 10) + "\x00" + route + "\x00" + carrier + "\x00" + string(fp)
}

// frozenCert copies the binding the handshake will present, so the bytes the stamp hashes and
// the certificate the dialer later hands to crypto/tls are one value even if the store's entry
// is edited in place after capture. In-tree bindings are never edited (LoadClientCert builds a
// fresh tls.Certificate; the store swaps entries), so this only closes the embedder case the
// type note names. The chain's outer slice is copied, the DER bytes and the key are shared:
// a write INTO a DER buffer or a key object is not seen, and is not something any binding API
// offers.
func frozenCert(cert *tls.Certificate) *tls.Certificate {
	if cert == nil {
		return nil
	}
	c := *cert
	c.Certificate = append([][]byte(nil), cert.Certificate...)
	return &c
}

// certSuffix renders the stamp suffix for a certificate answer already read: nothing when the
// question is never asked, a bare separator for "none", or the leaf's leading-bytes hash.
func certSuffix(cert *tls.Certificate, asked bool) string {
	if !asked {
		return ""
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return "\x00"
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return "\x00" + hex.EncodeToString(sum[:8])
}

// routeForDialAddr re-evaluates, under the configuration live right now, the stamp a
// connection dialled to a given address would carry. Pool takes call it with the candidate's
// OWN stored dial address: ForAddr on an already-resolved address never resolves, so a pool
// hit does no DNS lookup even when a family filter makes resolution live - the one lookup
// stays where it was before the identity capture existed, at dial time
// (burpsy-react-ui-o388-predial-vs-dial). The generation and the config pointer are read once
// under s.mu so a stamp cannot straddle a setter's swap; the upstream policy is read live,
// under its own lock, exactly as routeState read it before the capture existed.
func (s *Sender) routeForDialAddr(host string, useTLS bool) func(dialAddr string) string {
	s.mu.RLock()
	gen := s.netGen
	cfg := s.config
	carrier := s.carrier
	s.mu.RUnlock()
	suffix := certSuffix(certAnswer(cfg, host, useTLS))
	fp := fingerprintAnswer(cfg, host, useTLS)
	// The carrier is read live, like the policy: an in-place edit since the dial must make the
	// candidate's stamp disagree. Unconfigured reads as "" without allocating.
	carried := carrier.Identity()
	return func(dialAddr string) string {
		route := "direct"
		if s.upstream != nil {
			route = s.upstream.ForAddr(dialAddr).Raw()
		}
		return routeStamp(gen, route+suffix, carried, fp)
	}
}

// captureDialIdentity reads every mutable dial input once, at one dial decision point, and
// derives the pool stamp from the same values. It replaces routeState: the stamp's inputs
// and the dial's inputs are one read by construction, not two reads hoped to land close
// together. Each dial decision captures its own — a pool take's comparison and the fresh
// dial after a failed pooled exchange are different decisions and must not share a capture
// (an operator change landing during the failed exchange governs the redial, as it always
// has).
func (s *Sender) captureDialIdentity(ctx context.Context, host string, port uint16, useTLS bool) (dialIdentity, error) {
	// The generation, the settings, the carrier and the config pointer are read under one
	// RLock so the snapshot the stamp and the dial are built from can never straddle a
	// setter's swap.
	s.mu.RLock()
	id := dialIdentity{gen: s.netGen, settings: s.net}
	carrier := s.carrier
	cfg := s.config
	s.mu.RUnlock()
	// The holder pointer was read with the generation; its configuration is frozen here, and the
	// identity the stamp names is read in the same locked section as the copy the dial consumes.
	var carried string
	id.carrier, carried = carrier.Freeze()
	id.dialAddr = id.settings.dialAddressFor(ctx, host, port)
	route := "direct"
	if s.upstream != nil {
		// Snapshot renders and Restore re-parses the same Raw form — the persistence round
		// trip — under one locked read of the live policy. A failure here means the live
		// policy's own Snapshot could not be rebuilt, which the dial must surface rather
		// than route around.
		frozen := upstream.NewPolicy()
		if err := frozen.Restore(s.upstream.Snapshot()); err != nil {
			return dialIdentity{}, fmt.Errorf("freezing the upstream policy: %w", err)
		}
		id.upstream = frozen
		route = frozen.ForAddr(id.dialAddr).Raw()
	}
	id.wrap = (id.upstream != nil && !id.upstream.Empty()) || id.carrier != nil
	cert, asked := certAnswer(cfg, host, useTLS)
	// Copy first, hash the copy: the stamp names exactly the value the handshake presents.
	id.cert = frozenCert(cert)
	route += certSuffix(id.cert, asked)
	id.fingerprint = fingerprintAnswer(cfg, host, useTLS)
	id.route = routeStamp(id.gen, route, carried, id.fingerprint)
	return id, nil
}
