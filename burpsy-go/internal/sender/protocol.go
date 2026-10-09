// Protocol selection on the egress path: which HTTP version a send actually used, why it was not
// HTTP/2 when it was not, and what this tool has learnt about each authority's ALPN.
//
// # The gap this closes (H2-04)
//
// sendH2Raw has existed for a while, and Sender.SendRaw dispatched to it on one condition: the request
// bytes already said `HTTP/2` on their start line. Only the repeater does that, because it replays
// captured h2 bytes. The scanner and the intruder build their own requests, always with an HTTP/1.1
// start line, so against an h2-speaking target they got HTTP/1.1 — and nothing anywhere recorded that
// this had happened.
//
// The silence is the defect, more than the downgrade. A scan that quietly tested a different protocol
// from the one the target speaks is a scan whose *negative* results mean less than they appear to: an
// HTTP/1.1 request-smuggling probe that comes back clean says nothing about the h2 front end the
// target actually runs. So every send now reports the protocol that carried it, and every send that
// went out as HTTP/1.1 carries a Downgrade naming why — the same shape scanner.ScanSkip uses for
// "this check did not run", and for the same reason: a caller must not have to guess whether silence
// means "fine" or "never happened".
//
// # Reporting is not the same as refusing, and this file does neither of the other two
//
// Two things this deliberately does not do. It does not refuse to send: a target that speaks only
// HTTP/1.1 is sent HTTP/1.1, reported as a downgrade, and the probe runs. And it does not authorise:
// AuthorisedSender's gate has already run on the bytes about to go on the wire before anything here
// picks a protocol. Protocol selection changes *how* a request travels, never *where* to — which is
// why a caller pinning HTTP/1.1 (ProtocolPreferenceHTTP1) is a legitimate knob while a caller waiving
// scope is not.
//
// # Why an HTTP/1.1 request is not always re-expressed as h2
//
// Sending an HTTP/1.1 request over h2 is not a transport swap, it is a re-encoding: the start line
// becomes pseudo-headers, field names become lowercase, and the framing headers stop existing. For an
// ordinary request that is invisible. For the probes this tool is built to send it is not — a
// `Transfer-Encoding: chunked` alongside a `Content-Length` *is* the probe, and h2 has nowhere to put
// it. Re-encoding such a request would send something the operator did not write and report a clean
// result for a test that never ran.
//
// So planH2 decides representability construct by construct, and every construct that blocks the
// upgrade has its own DowngradeReason. The two kinds of change that are *not* blocking — a lowercased
// field name, a dropped hop-by-hop header — are reported per send as Rewrites rather than passed over,
// because "sent as h2" and "sent as h2 after dropping the Connection header you wrote" are different
// facts.
//
// # Why the cache distinguishes unknown from HTTP/1.1
//
// ProtocolSupport's zero value is ProtocolSupportUnknown, and a lookup that misses returns it. That is
// the same fail-safe direction as scanner.CheckCoverage's never-dispatched: "we have not asked this
// authority" must not be readable as "this authority speaks HTTP/1.1", because the second is a claim
// about the target and the first is a claim about us. A cache that collapsed them would let a
// discovery bug present as a target-side fact, and every downgrade report built on it would be wrong
// in the direction that looks plausible.
//
// # h2c, on this path, is out of scope
//
// A plaintext target has no ALPN, so there is nothing to negotiate and nothing to discover. Prior
// knowledge (RFC 9113 §3.3) would let us simply write the preface and hope, and RFC 9113 deleted the
// Upgrade: h2c dance outright. Guessing wrong means writing an h2 preface at an HTTP/1.1 server,
// which answers with a 400 that looks like a finding. So a plaintext send is HTTP/1.1, reported with
// DowngradePlaintextTarget, and the operator can see how many of their sends were on that footing.
// The frame-program path (h2program.go) takes the opposite decision, because a frame program carries
// its own preface and so *is* the prior-knowledge case — stated there.
package sender

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/core"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
)

// ProtocolSupport is what this tool knows about one authority's ALPN.
type ProtocolSupport int

const (
	// ProtocolSupportUnknown is the zero value: no handshake with this authority has been observed, so
	// nothing is known. Never read it as HTTP/1.1 — see the file header.
	ProtocolSupportUnknown ProtocolSupport = iota
	// ProtocolSupportHTTP11 means a handshake with this authority did not settle on h2: either its ALPN
	// chose http/1.1, or it carried no ALPN at all. Which of the two it was is carried by
	// AuthorityProtocol.Negotiated, because only one of them means the peer was asked and declined.
	ProtocolSupportHTTP11
	// ProtocolSupportH2 means a handshake with this authority settled on h2.
	ProtocolSupportH2
)

// ProtocolSupportAll is all three, so a caller can build a histogram without hard-coding the set.
var ProtocolSupportAll = [3]ProtocolSupport{
	ProtocolSupportUnknown,
	ProtocolSupportHTTP11,
	ProtocolSupportH2,
}

// String names the state for an operator, spelling out the unknown case rather than rendering it as an
// empty cell that reads as though the question did not apply.
func (p ProtocolSupport) String() string {
	switch p {
	case ProtocolSupportUnknown:
		return "not yet known"
	case ProtocolSupportHTTP11:
		return "http/1.1"
	case ProtocolSupportH2:
		return "h2"
	}
	return "unrecognised protocol support"
}

// ProtocolPreference is what a caller wants of protocol selection for one send.
type ProtocolPreference int

const (
	// ProtocolPreferenceAuto uses h2 when the target negotiates it and the request can be carried over
	// it without being changed. The default, and what every existing call site gets.
	ProtocolPreferenceAuto ProtocolPreference = iota
	// ProtocolPreferenceHTTP1 pins the send to HTTP/1.1 so the bytes go on the wire as written.
	//
	// This exists because h2 has no way to carry a field name's case, a duplicated framing header or a
	// deliberately odd request line, and those are things burpsy is for. It is a protocol choice, not a
	// scope waiver: the request still goes to the authority AuthorisedSender is bound to and still
	// passes the same gate. A pinned send is still reported — DowngradePinnedByCaller — so "we tested
	// this host over HTTP/1.1 only" stays visible in the report rather than being knowable only by
	// whoever set the flag.
	ProtocolPreferenceHTTP1
	// ProtocolPreferenceForceH2 requires the send to go out over h2 when the request can be
	// carried over it at all — the opposite pin to HTTP1, for a target whose h2 behaviour
	// differs from its h1 behaviour (burpsy-react-ui-745). "Can be carried at all" is the same
	// bar Auto applies (planH2's construct-by-construct check): a request h2 has nowhere to put
	// — a smuggled Transfer-Encoding, say — is sent as HTTP/1.1 with its own DowngradeReason
	// rather than mangled onto h2, because re-encoding it would send something the operator did
	// not write. When the request IS carriable and the target declines h2 at ALPN, the send goes
	// out as HTTP/1.1 and is reported as a downgrade like every other "h2 did not happen".
	ProtocolPreferenceForceH2
)

// DowngradeReason names why a send went out as HTTP/1.1 rather than HTTP/2.
//
// One reason per construct, rather than a single "not representable": an operator whose h2 coverage is
// zero needs to know whether that is because the target refused h2 or because every probe they wrote
// carries a Transfer-Encoding. Those call for opposite next actions.
type DowngradeReason int

const (
	// DowngradePlaintextTarget means the target is plaintext HTTP, which has no ALPN; h2c is out of
	// scope on this path (see the file header).
	DowngradePlaintextTarget DowngradeReason = iota
	// DowngradeNegotiatedHTTP11 means h2 was offered and the target's ALPN chose http/1.1.
	DowngradeNegotiatedHTTP11
	// DowngradeNoALPN means the handshake produced no ALPN protocol at all, so the target never agreed
	// to anything. Kept apart from DowngradeNegotiatedHTTP11 because a peer that declined h2 and a peer
	// that has never heard of ALPN are different findings.
	DowngradeNoALPN
	// DowngradePinnedByCaller means the caller asked for HTTP/1.1 with ProtocolPreferenceHTTP1.
	DowngradePinnedByCaller
	// DowngradeHeadersNotTerminated means the request has no blank line ending its header section, so
	// where its headers stop is a guess.
	DowngradeHeadersNotTerminated
	// DowngradeRequestLineUnreadable means the request line is not three space-separated tokens ending
	// in an HTTP/1.x version. Detail carries what was found.
	DowngradeRequestLineUnreadable
	// DowngradeHTTP10RequestLine means the request line names HTTP/1.0. h2 has no version field, so the
	// distinction the probe is making would vanish.
	DowngradeHTTP10RequestLine
	// DowngradeConnectMethod means the method is CONNECT, which over h2 is the extended-CONNECT shape
	// of RFC 9113 §8.5 — a different request, not a re-encoding of this one.
	DowngradeConnectMethod
	// DowngradeNonOriginFormTarget means the request target is absolute-form, authority-form or
	// asterisk-form. h2 splits a target into :scheme, :authority and :path, so re-expressing one of
	// these changes what the origin sees, which is exactly what such a request is testing. Detail
	// carries the target.
	DowngradeNonOriginFormTarget
	// DowngradeNoHostHeader means there is no Host header, so :authority would have to be invented.
	DowngradeNoHostHeader
	// DowngradeDuplicateHostHeader means there is more than one Host header and h2 has one :authority,
	// so one of them would be dropped — and which one is the probe.
	DowngradeDuplicateHostHeader
	// DowngradeHeaderLineUnreadable means a header line has no colon. Detail carries the line.
	DowngradeHeaderLineUnreadable
	// DowngradeForbiddenFieldOctet means a field name or value carries an octet h2 cannot carry
	// verbatim — a control character, a colon in a name, a space in a name. Detail names the field.
	DowngradeForbiddenFieldOctet
	// DowngradeTransferEncoding means the request carries Transfer-Encoding, which RFC 9113 §8.2.2
	// forbids over h2. The archetypal smuggling probe: dropping it would send a different request and
	// report a clean result for a test that never ran.
	DowngradeTransferEncoding
	// DowngradeUpgradeHeader means the request carries Upgrade, which §8.2.2 forbids. Unlike the other
	// connection-specific headers this one is not droppable: an Upgrade request is asking for a
	// protocol switch, and sending it without the header asks for something else entirely.
	DowngradeUpgradeHeader
	// DowngradeTEOtherThanTrailers means TE carries something other than "trailers", which is the only
	// value §8.2.2 permits over h2.
	DowngradeTEOtherThanTrailers
	// DowngradeDuplicateContentLength means there is more than one Content-Length. h2 derives one from
	// the body, so the disagreement — the probe — would disappear.
	DowngradeDuplicateContentLength
	// DowngradeContentLengthUnreadable means Content-Length is not a number. Detail carries the value.
	DowngradeContentLengthUnreadable
	// DowngradeContentLengthDisagreesWithBody means Content-Length disagrees with the body written. h2
	// frames the body itself, so the lie would be corrected on the way out.
	DowngradeContentLengthDisagreesWithBody
	// DowngradeProjectDefaultHTTP1 means the project's "Default to HTTP/2" setting is off and the send
	// named no protocol of its own (burpsy-react-ui-ry5n).
	DowngradeProjectDefaultHTTP1
	// DowngradeConnectionBoundAuth means the send carried a connection-bound platform credential
	// (NTLM), whose handshake authenticates one HTTP/1.1 connection: over h2 the legs would be
	// streams of a multiplexed connection, which NTLM servers refuse (burpsy-react-ui-sel6).
	DowngradeConnectionBoundAuth
)

// DowngradeReasonAll is every reason, in the order the send path tests them: negotiation facts first,
// then the request's own constructs in the order planH2 reads them. A caller iterating this sees
// reasons in the same order the code decides them.
var DowngradeReasonAll = [21]DowngradeReason{
	DowngradePlaintextTarget,
	DowngradeNegotiatedHTTP11,
	DowngradeNoALPN,
	DowngradePinnedByCaller,
	DowngradeHeadersNotTerminated,
	DowngradeRequestLineUnreadable,
	DowngradeHTTP10RequestLine,
	DowngradeConnectMethod,
	DowngradeNonOriginFormTarget,
	DowngradeNoHostHeader,
	DowngradeDuplicateHostHeader,
	DowngradeHeaderLineUnreadable,
	DowngradeForbiddenFieldOctet,
	DowngradeTransferEncoding,
	DowngradeUpgradeHeader,
	DowngradeTEOtherThanTrailers,
	DowngradeDuplicateContentLength,
	DowngradeContentLengthUnreadable,
	DowngradeContentLengthDisagreesWithBody,
	DowngradeProjectDefaultHTTP1,
	DowngradeConnectionBoundAuth,
}

// Explanation is one line an operator can act on.
func (r DowngradeReason) Explanation() string {
	switch r {
	case DowngradePlaintextTarget:
		return "the target is plaintext HTTP, which has no ALPN to negotiate h2 with; h2c is out of scope on the request path"
	case DowngradeNegotiatedHTTP11:
		return "h2 was offered and the target's ALPN chose http/1.1"
	case DowngradeNoALPN:
		return "the TLS handshake carried no ALPN protocol, so the target never agreed to h2"
	case DowngradePinnedByCaller:
		return "the caller pinned this send to HTTP/1.1 so the bytes go on the wire as written"
	case DowngradeProjectDefaultHTTP1:
		return "the project setting \"Default to HTTP/2 if the server supports it\" is off, so a send that names no protocol uses HTTP/1.1"
	case DowngradeConnectionBoundAuth:
		return "the target's platform credential is NTLM, whose handshake authenticates one HTTP/1.1 connection and cannot ride h2"
	case DowngradeHeadersNotTerminated:
		return "the request has no blank line ending its header section"
	case DowngradeRequestLineUnreadable:
		return "the request line is not a method, a target and an HTTP/1.x version"
	case DowngradeHTTP10RequestLine:
		return "the request line names HTTP/1.0, and h2 has no version field to carry that distinction"
	case DowngradeConnectMethod:
		return "the method is CONNECT, which over h2 is the extended-CONNECT shape of RFC 9113 §8.5"
	case DowngradeNonOriginFormTarget:
		return "the request target is not in origin form, and h2 splits a target into :scheme, :authority and :path"
	case DowngradeNoHostHeader:
		return "there is no Host header, so h2's :authority would have to be invented"
	case DowngradeDuplicateHostHeader:
		return "there is more than one Host header, and h2 carries one :authority"
	case DowngradeHeaderLineUnreadable:
		return "a header line has no colon, so its name and value cannot be told apart"
	case DowngradeForbiddenFieldOctet:
		return "a field name or value carries an octet h2 cannot carry verbatim"
	case DowngradeTransferEncoding:
		return "the request carries Transfer-Encoding, which RFC 9113 §8.2.2 forbids over h2"
	case DowngradeUpgradeHeader:
		return "the request carries Upgrade, which RFC 9113 §8.2.2 forbids over h2"
	case DowngradeTEOtherThanTrailers:
		return "the request carries a TE other than \"trailers\", the only value RFC 9113 §8.2.2 permits"
	case DowngradeDuplicateContentLength:
		return "the request carries more than one Content-Length, and h2 derives one from the body"
	case DowngradeContentLengthUnreadable:
		return "the request's Content-Length is not a number"
	case DowngradeContentLengthDisagreesWithBody:
		return "the request's Content-Length disagrees with the body written, and h2 frames the body itself"
	}
	return "unrecognised downgrade reason"
}

// slot is the position in DowngradeReasonAll, and the matching counter slot in ProtocolCache. A switch
// rather than a search, for the reason scanner.ScanSkip.slot gives: the mapping must be total at
// compile time, not discovered at runtime by a search that could come back empty.
func (r DowngradeReason) slot() int {
	if int(r) >= 0 && int(r) < len(DowngradeReasonAll) && DowngradeReasonAll[int(r)] == r {
		return int(r)
	}
	panic(fmt.Sprintf("unrecognised DowngradeReason %d", int(r)))
}

// Downgrade is one send that went out as HTTP/1.1 when the intent was h2 if the target would take it.
//
// Present on every HTTP/1.1 send, including the ones where HTTP/1.1 was obviously going to happen — a
// plaintext target, a caller-pinned send. "Obvious" is the reading of someone who already knows; the
// report has to be readable by someone who does not, and a downgrade that is sometimes recorded and
// sometimes not cannot be counted.
type Downgrade struct {
	Reason DowngradeReason
	// Detail names the construct for the Kinds whose Explanation refers to one: the field name, the
	// unreadable line, the target. Empty for the rest.
	Detail string
	// Forced is true when this DowngradeNegotiatedHTTP11 (or DowngradeNoALPN) came from a send pinned
	// to ProtocolPreferenceForceH2 rather than the default Auto (burpsy-react-ui-57yk). The Reason is
	// deliberately the same either way — Force does not invent a bespoke finding for an ordinary ALPN
	// choice, and force_h2_test.go already pins that a Force send that gets downgraded must still
	// succeed as an unremarkable HTTP/1.1 exchange, not fail or report differently. What Forced adds is
	// the one bit Auto has no use for and Force does: whether *this* target declined a requirement the
	// operator stated, versus one Auto never stated in the first place. Always false for every other
	// Reason — a plaintext target or an unrepresentable construct blocks the same way regardless of
	// preference, so there is nothing for a Force pin to have specifically required and lost.
	Forced bool
}

// String renders the downgrade as a sentence, naming the detail only when this Reason has one.
func (d Downgrade) String() string {
	if d.Detail == "" {
		return d.Reason.Explanation()
	}
	return fmt.Sprintf("%s (%s)", d.Reason.Explanation(), d.Detail)
}

// RewriteKind names a change re-expressing an HTTP/1.1 request as h2 makes that the operator did not
// write, and that does not block the upgrade.
type RewriteKind int

const (
	// RewriteFieldNameLowercased means a field name was lowercased, which RFC 9113 §8.2.1 requires.
	// Not blocking: HTTP/1 field names are case-insensitive by definition (RFC 9110 §5.1), so a peer
	// that treats their case as meaningful is a finding no h2 request can reach — pin HTTP/1.1 to test
	// for it.
	RewriteFieldNameLowercased RewriteKind = iota
	// RewriteFieldValueTrimmed means leading or trailing whitespace was removed from a field value,
	// which §8.2.1 forbids carrying.
	RewriteFieldValueTrimmed
	// RewriteHopFieldDropped means a connection-management header (Connection, Proxy-Connection,
	// Keep-Alive) was dropped, which §8.2.2 requires. Not blocking, because those fields manage an
	// HTTP/1 connection and carry no request semantics — which is why the proxy's h2 relay drops the
	// same set. Transfer-Encoding and Upgrade are *not* in this set: they change what is being asked
	// for, so they refuse the upgrade instead.
	RewriteHopFieldDropped
)

// RewriteKindAll is all three, in the order planH2 can produce them.
var RewriteKindAll = [3]RewriteKind{
	RewriteFieldNameLowercased,
	RewriteFieldValueTrimmed,
	RewriteHopFieldDropped,
}

// Explanation is one line an operator can act on.
func (k RewriteKind) Explanation() string {
	switch k {
	case RewriteFieldNameLowercased:
		return "a field name was lowercased, as RFC 9113 §8.2.1 requires"
	case RewriteFieldValueTrimmed:
		return "leading or trailing whitespace was removed from a field value"
	case RewriteHopFieldDropped:
		return "a connection-management header was dropped, as RFC 9113 §8.2.2 requires"
	}
	return "unrecognised rewrite"
}

func (k RewriteKind) slot() int {
	if int(k) >= 0 && int(k) < len(RewriteKindAll) && RewriteKindAll[int(k)] == k {
		return int(k)
	}
	panic(fmt.Sprintf("unrecognised RewriteKind %d", int(k)))
}

// Rewrite is one such change, naming the field it happened to.
type Rewrite struct {
	Kind RewriteKind
	// Field is the field name as the caller wrote it.
	Field string
}

// String renders the rewrite as a sentence.
func (r Rewrite) String() string {
	return fmt.Sprintf("%s: %s", r.Field, r.Kind.Explanation())
}

// SendOutcome is which protocol carried one send, and what that cost.
//
// Returned alongside the response rather than folded into it, because a caller that wants to *count*
// protocol coverage needs this even for a send whose response it discards.
type SendOutcome struct {
	// Protocol is what actually carried the request.
	Protocol core.Protocol
	// Negotiated is the raw ALPN value the handshake settled on: "h2", "http/1.1", or "" for no ALPN
	// extension and for a plaintext connection that never had one.
	Negotiated string
	// Downgrade is why this went out as HTTP/1.1, and is non-nil exactly when Protocol is
	// core.ProtocolHTTP1. That equivalence is the honesty guarantee — an HTTP/1.1 send with no
	// Downgrade would be a silent one — and newOutcome is the single place that builds either, so it
	// cannot drift.
	Downgrade *Downgrade
	// Rewrites are the changes made to re-express an HTTP/1.1 request as h2; empty unless Protocol is
	// core.ProtocolHTTP2 and the request came in as HTTP/1.1 bytes.
	Rewrites []Rewrite
	// Rendered is the request as it went out when Protocol is core.ProtocolHTTP2, in the HTTP/1-shaped
	// rendering the proxy's h2 relay records (http2.RenderRequest). Nil for an HTTP/1.1 send, where the
	// caller's own bytes are already what went on the wire.
	//
	// Carried because a capture site that stores the caller's HTTP/1.1 bytes alongside an "HTTP/2 200"
	// response has recorded two halves of different exchanges. There is no way to store the *literal*
	// octets of an h2 request — they are HPACK-encoded inside the transport — so this is the same stand-in
	// the proxy already stores, which keeps history holding one shape rather than two.
	Rendered []byte
	// Support is what was known about this authority's ALPN when the send finished.
	//
	// Worth carrying separately from Protocol, and this is where the per-authority cache earns its keep:
	// for a request that *cannot* be carried over h2 the connection offers http/1.1 alone, so the
	// handshake itself says nothing about h2 support. Support answers "the target speaks h2, and this
	// probe could not use it" — the reading an operator needs — and answers
	// ProtocolSupportUnknown rather than guessing when no h2-offering handshake has happened yet.
	Support ProtocolSupport
	// ServerIP is the address the socket this send used actually reached — read off the live
	// connection, not resolved by name, for the same reason the proxy records it that way: the
	// row is a record of one exchange, and re-resolving later answers where the name points now,
	// not where it pointed when this request went out. Empty for a send that failed before any
	// connection existed. Under an upstream proxy it is the hop's address, which is the honest
	// answer to "where did these bytes go" (burpsy-react-ui-gj4f).
	ServerIP string
	// ConnectionReused is true when this send rode an h2 connection an earlier send left open
	// (SendOptions.H2Sessions, adkx) — so it was NOT the first request on its connection. False for
	// every fresh dial, which without H2Sessions is every send.
	ConnectionReused bool
}

// Downgraded reports whether this send went out as HTTP/1.1.
func (o SendOutcome) Downgraded() bool { return o.Downgrade != nil }

// newOutcome is the only constructor for a SendOutcome, so the Protocol/Downgrade equivalence holds by
// construction rather than by every call site remembering it.
func newOutcome(
	negotiated string,
	support ProtocolSupport,
	down *Downgrade,
	rewrites []Rewrite,
	rendered []byte,
) SendOutcome {
	if down != nil {
		return SendOutcome{
			Protocol:   core.ProtocolHTTP1,
			Negotiated: negotiated,
			Downgrade:  down,
			Support:    support,
		}
	}
	return SendOutcome{
		Protocol:   core.ProtocolHTTP2,
		Negotiated: negotiated,
		Rewrites:   rewrites,
		Rendered:   rendered,
		Support:    support,
	}
}

// AuthorityProtocol is what is known about one authority.
type AuthorityProtocol struct {
	Authority string          `json:"authority"`
	Support   ProtocolSupport `json:"-"`
	// State is Support rendered for a report.
	State string `json:"state"`
	// Negotiated is the raw ALPN value observed, "" when the handshake carried none. Tells "declined
	// h2" apart from "never heard of ALPN", which Support alone cannot.
	Negotiated string `json:"negotiated,omitempty"`
}

// DowngradeCount is one downgrade reason and how many sends it explains.
type DowngradeCount struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

// RewriteCount is one rewrite kind and how many fields it was applied to.
type RewriteCount struct {
	Rewrite string `json:"rewrite"`
	Count   uint64 `json:"count"`
}

// ProtocolReport is an owned, point-in-time snapshot of protocol coverage.
//
// Owned rather than a lock guard, for the reason scanner.CoverageReport gives: a reporting caller
// holds this after the call returns instead of holding the cache locked while it renders.
type ProtocolReport struct {
	// Authorities is one entry per authority a handshake has been observed with, sorted by authority so
	// two snapshots of the same state render identically.
	Authorities []AuthorityProtocol `json:"authorities"`
	// SentAsHTTP2, SentAsHTTP1 count sends by the protocol that carried them.
	SentAsHTTP2 uint64 `json:"sent_as_http2"`
	SentAsHTTP1 uint64 `json:"sent_as_http1"`
	// Downgrades is one count per DowngradeReason, in DowngradeReasonAll order. Summing these equals
	// SentAsHTTP1 — a tested invariant, and the reason every HTTP/1.1 send carries a Downgrade even
	// when the reason is obvious.
	Downgrades []DowngradeCount `json:"downgrades"`
	// Rewrites is one count per RewriteKind, in RewriteKindAll order.
	Rewrites []RewriteCount `json:"rewrites"`
	// DiscoveryHandshakes counts handshakes made *only* to find out what an authority speaks, by
	// ProtocolFor. A send never contributes to this: it learns from the connection it was going to open
	// anyway.
	DiscoveryHandshakes uint64 `json:"discovery_handshakes"`
	// CacheHits counts ProtocolFor calls answered from the table without a handshake.
	CacheHits uint64 `json:"cache_hits"`
}

// ProtocolCache remembers what each authority's ALPN said, and counts protocol coverage.
//
// Per authority, not per host: a target can speak h2 on 443 and HTTP/1.1 on 8443, and one entry for
// both would answer whichever was asked last. The key includes the scheme for the same reason.
type ProtocolCache struct {
	mu    sync.RWMutex // guards known
	known map[string]AuthorityProtocol

	sentH2 atomic.Uint64
	sentH1 atomic.Uint64
	// downgrades is indexed by DowngradeReason.slot, rewrites by RewriteKind.slot. Plain atomics
	// rather than a lock: each send increments one counter and nothing else, so there is no batch to
	// fold in the way a per-check table would need.
	downgrades [len(DowngradeReasonAll)]atomic.Uint64
	rewrites   [len(RewriteKindAll)]atomic.Uint64
	handshakes atomic.Uint64
	hits       atomic.Uint64
}

// newProtocolCache builds an empty cache. Every authority starts absent, which Lookup reports as
// ProtocolSupportUnknown.
func newProtocolCache() *ProtocolCache {
	return &ProtocolCache{known: map[string]AuthorityProtocol{}}
}

// Lookup reports what is known about one authority, and ProtocolSupportUnknown when nothing is.
func (c *ProtocolCache) Lookup(host string, port uint16, isTLS bool) ProtocolSupport {
	if !isTLS {
		// Not a cache answer and not a guess: a cleartext connection has no ALPN, so HTTP/1.1 is what
		// it carries. Recording it would fill the table with entries no handshake produced.
		return ProtocolSupportHTTP11
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.known[formatAuthority(host, port, isTLS)].Support
}

// learn records what a handshake with this authority settled on.
//
// Called from the send path as well as from ProtocolFor, because a send's own handshake is evidence
// about the authority whether or not anybody asked for discovery — that is what keeps an intruder run
// from ever handshaking twice for the same answer.
func (c *ProtocolCache) learn(host string, port uint16, isTLS bool, negotiated string) {
	if !isTLS {
		return
	}
	support := ProtocolSupportHTTP11
	if negotiated == alpn.H2 {
		support = ProtocolSupportH2
	}
	authority := formatAuthority(host, port, isTLS)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.known[authority] = AuthorityProtocol{
		Authority:  authority,
		Support:    support,
		State:      support.String(),
		Negotiated: negotiated,
	}
}

// record folds one completed send into the counters.
func (c *ProtocolCache) record(out SendOutcome) {
	if out.Downgrade != nil {
		c.sentH1.Add(1)
		c.downgrades[out.Downgrade.Reason.slot()].Add(1)
		return
	}
	c.sentH2.Add(1)
	for _, rw := range out.Rewrites {
		c.rewrites[rw.Kind.slot()].Add(1)
	}
}

// Report returns an owned snapshot.
func (c *ProtocolCache) Report() ProtocolReport {
	c.mu.RLock()
	authorities := make([]AuthorityProtocol, 0, len(c.known))
	for _, v := range c.known {
		authorities = append(authorities, v)
	}
	c.mu.RUnlock()
	sortAuthorities(authorities)

	downgrades := make([]DowngradeCount, 0, len(DowngradeReasonAll))
	for _, r := range DowngradeReasonAll {
		downgrades = append(downgrades, DowngradeCount{
			Reason: r.Explanation(),
			Count:  c.downgrades[r.slot()].Load(),
		})
	}
	rewrites := make([]RewriteCount, 0, len(RewriteKindAll))
	for _, k := range RewriteKindAll {
		rewrites = append(rewrites, RewriteCount{
			Rewrite: k.Explanation(),
			Count:   c.rewrites[k.slot()].Load(),
		})
	}
	return ProtocolReport{
		Authorities:         authorities,
		SentAsHTTP2:         c.sentH2.Load(),
		SentAsHTTP1:         c.sentH1.Load(),
		Downgrades:          downgrades,
		Rewrites:            rewrites,
		DiscoveryHandshakes: c.handshakes.Load(),
		CacheHits:           c.hits.Load(),
	}
}

// Summary formats protocol coverage for reports and logs.
func (r ProtocolReport) Summary() string {
	total := r.SentAsHTTP2 + r.SentAsHTTP1
	if total == 0 {
		return "no sends yet"
	}
	noun := "authorities"
	if len(r.Authorities) == 1 {
		noun = "authority"
	}
	return fmt.Sprintf("%d sends: %d as h2, %d as http/1.1, over %d known %s",
		total, r.SentAsHTTP2, r.SentAsHTTP1, len(r.Authorities), noun)
}

// sortAuthorities orders a snapshot by authority. Insertion-sorted rather than reaching for sort.Slice
// on a slice that is almost always one or two entries long in a single-target engagement.
func sortAuthorities(in []AuthorityProtocol) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j].Authority < in[j-1].Authority; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

// h2Plan is one HTTP/1.1 request re-expressed as the h2 request it would become, with every change
// made along the way named.
//
// Produced only when the re-expression is faithful. When it is not, planH2 returns a Downgrade instead
// and the bytes go out as HTTP/1.1 unmodified — see the file header.
type h2Plan struct {
	Method    string
	Path      string
	Authority string
	// Headers are in the order the request wrote them, with the Host header removed (it becomes
	// :authority) and hop-by-hop fields dropped. Names are lowercased.
	Headers  []burpsyhttp2.Header
	Body     []byte
	Rewrites []Rewrite
}

// planH2 decides whether these HTTP/1.1 bytes can be carried over h2 without changing what is being
// asked, and returns either the plan or the reason not to.
//
// Every refusal names one construct. The order below is the order a reader of the bytes meets them —
// header section, request line, then fields left to right — so two requests that break the same rule
// first are reported the same way, and a report is reproducible.
func planH2(raw []byte) (h2Plan, *Downgrade) {
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		return h2Plan{}, &Downgrade{Reason: DowngradeHeadersNotTerminated}
	}
	lines := strings.Split(string(head), "\r\n")
	method, target, version, ok := splitRequestLine(lines[0])
	if !ok {
		return h2Plan{}, &Downgrade{Reason: DowngradeRequestLineUnreadable, Detail: lines[0]}
	}
	switch version {
	case "HTTP/1.1":
	case "HTTP/1.0":
		return h2Plan{}, &Downgrade{Reason: DowngradeHTTP10RequestLine}
	default:
		return h2Plan{}, &Downgrade{Reason: DowngradeRequestLineUnreadable, Detail: version}
	}
	if strings.EqualFold(method, "CONNECT") {
		return h2Plan{}, &Downgrade{Reason: DowngradeConnectMethod}
	}
	if !strings.HasPrefix(target, "/") {
		return h2Plan{}, &Downgrade{Reason: DowngradeNonOriginFormTarget, Detail: target}
	}

	plan := h2Plan{Method: method, Path: target, Body: body}
	hosts, contentLengths := 0, 0
	declaredLen := -1
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return h2Plan{}, &Downgrade{Reason: DowngradeHeaderLineUnreadable, Detail: line}
		}
		if !isFieldName(name) {
			return h2Plan{}, &Downgrade{Reason: DowngradeForbiddenFieldOctet, Detail: name}
		}
		trimmed := strings.Trim(value, " \t")
		if !isFieldValue(trimmed) {
			return h2Plan{}, &Downgrade{Reason: DowngradeForbiddenFieldOctet, Detail: name}
		}
		lower := strings.ToLower(name)
		switch lower {
		case "transfer-encoding":
			return h2Plan{}, &Downgrade{Reason: DowngradeTransferEncoding, Detail: trimmed}
		case "upgrade":
			return h2Plan{}, &Downgrade{Reason: DowngradeUpgradeHeader, Detail: trimmed}
		case "te":
			if !strings.EqualFold(trimmed, "trailers") {
				return h2Plan{}, &Downgrade{Reason: DowngradeTEOtherThanTrailers, Detail: trimmed}
			}
		case "host":
			hosts++
			if hosts > 1 {
				return h2Plan{}, &Downgrade{Reason: DowngradeDuplicateHostHeader}
			}
			plan.Authority = trimmed
		case "content-length":
			contentLengths++
			if contentLengths > 1 {
				return h2Plan{}, &Downgrade{Reason: DowngradeDuplicateContentLength}
			}
			n, err := strconv.Atoi(trimmed)
			if err != nil || n < 0 {
				return h2Plan{}, &Downgrade{Reason: DowngradeContentLengthUnreadable, Detail: trimmed}
			}
			declaredLen = n
		}
		if lower != "host" {
			// Recorded before the hop-header drop so a rewrite is reported for a field that is about to
			// disappear too: "we lowercased Connection and then dropped it" is two changes, and the
			// operator wrote one line.
			if lower != name {
				plan.Rewrites = append(plan.Rewrites, Rewrite{Kind: RewriteFieldNameLowercased, Field: name})
			}
			// Reported only when trimming removed something beyond the single conventional space after
			// the colon. Every well-formed "Name: value" carries that space, so reporting it would put a
			// rewrite on every field of every request and drown the ones that mean something.
			if trimmed != strings.TrimPrefix(value, " ") {
				plan.Rewrites = append(plan.Rewrites, Rewrite{Kind: RewriteFieldValueTrimmed, Field: name})
			}
			if isHopField(lower) {
				plan.Rewrites = append(plan.Rewrites, Rewrite{Kind: RewriteHopFieldDropped, Field: name})
				continue
			}
			plan.Headers = append(plan.Headers, burpsyhttp2.Header{Name: lower, Value: trimmed})
		}
	}
	if hosts == 0 {
		return h2Plan{}, &Downgrade{Reason: DowngradeNoHostHeader}
	}
	if declaredLen >= 0 && declaredLen != len(body) {
		return h2Plan{}, &Downgrade{
			Reason: DowngradeContentLengthDisagreesWithBody,
			Detail: fmt.Sprintf("declares %d, writes %d", declaredLen, len(body)),
		}
	}
	return plan, nil
}

// splitRequestLine splits exactly three space-separated tokens. Reports false for anything else,
// including a target containing a space — which is unreadable rather than something to guess at.
func splitRequestLine(line string) (method, target, version string, ok bool) {
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// isHopField reports the connection-management fields RFC 9113 §8.2.2 forbids over h2 and that carry
// no request semantics, so dropping them is a reported rewrite rather than a refused upgrade.
//
// Deliberately narrower than http2.IsHopHeader, which also names transfer-encoding, upgrade, te,
// trailer and host. Those are handled individually above: three of them refuse the upgrade because
// they change what is being asked, and host becomes :authority.
func isHopField(lowerName string) bool {
	switch lowerName {
	case "connection", "proxy-connection", "keep-alive":
		return true
	}
	return false
}

// isFieldName reports whether every octet is an RFC 9110 §5.6.2 token character. A field name with a
// space, a colon or a control character cannot be carried over h2 verbatim, and a leading colon would
// collide with a pseudo-header.
func isFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTokenOctet(name[i]) {
			return false
		}
	}
	return true
}

func isTokenOctet(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// isFieldValue reports whether a field value can go on an h2 wire verbatim: no NUL, CR or LF, which
// RFC 9113 §8.2.1 forbids and which are how a header-injection probe is written.
func isFieldValue(value string) bool {
	return !strings.ContainsAny(value, "\x00\r\n")
}
