package scanner

// Null-byte filter-bypass variants of the reflected-XSS breakout (burpsy-react-ui-nulbyte).
//
// # The bug class
//
// A defence that reads the value as a C string — up to its first NUL byte — while the output uses
// the whole value. Two shapes are common, and OWASP VulnerableApp carries one of each:
//
//   - an ALLOWLIST checked on the part before the NUL (XSSInImgTagAttribute LEVEL_5): `owl.jpg`
//     is allowed, so `owl.jpg<NUL> onerror=…` is too, and the whole value is reflected;
//   - an ESCAPER that stops at the NUL (PersistentXSSInHTMLTagVulnerability LEVEL_6): everything
//     before it is encoded, everything after it reaches the page verbatim.
//
// # Why the variant starts from the seed value
//
// The allowlist shape answers a value it does not recognise with nothing at all, so the ordinary
// observation probe — a bare canary — never sees the point reflect and no payload is ever chosen
// for it. The only value that gets past such a check is one the application already accepts, and
// the one value the scanner knows is accepted is the point's own captured value. Every probe here is
// therefore `<original value><NUL><probe>`: the part a truncating check reads is exactly what the
// application was seen to accept, and only the part it does not read is the scanner's. The NUL and
// the probe are APPENDED to the captured value rather than written after a copy of it, so the value
// reaches the application in its captured wire spelling, whatever escaping that spelling carries.
//
// A point with no captured value has nothing to start from and is not probed: a NUL after an empty
// prefix is a variant of a bare payload, not of a value the application was seen to accept.
//
// # What the probes are, and what bounds them
//
// One observation probe (`seed<NUL>canary`) to learn where the value lands now that it is accepted,
// then at most maxXSSNullByteProbes payloads from the bank that context selects — the same bank and
// the same per-payload confirmation the plain probes use, so a variant can only confirm what a plain
// payload would have confirmed had the defence not existed. The variants run only when the plain
// bank, the decoding variants and the upload variant all failed to confirm and no fragment
// candidate is waiting for the browser: at most 1+maxXSSNullByteProbes requests per such point,
// under the check's insertion-point cap.
//
// The NUL travels percent-escaped (`%00`) on a k=v container, which the target decodes to the byte;
// a container that cannot carry a control byte refuses the send, and a refused send is no evidence,
// never a finding.

import (
	"context"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// maxXSSNullByteProbes bounds the payload probes a point's null-byte variant may send after its
// observation probe.
const maxXSSNullByteProbes = 3

// xssNullByteVariantName is how a finding names the variant that carried its breakout.
const xssNullByteVariantName = "null-byte truncation (original value, NUL, payload)"

// xssNullByteSeparator is what every null-byte probe appends to the point's captured value ahead of
// the probe itself.
const xssNullByteSeparator = "\x00"

// xssNullByteResult is what the null-byte variant established at one point.
type xssNullByteResult struct {
	// evidence is the reflection and breakout evidence gathered on markup responses.
	evidence XSSEvidence
	// landedOn is the followed page a markup breakout was found on, as for the plain probes.
	landedOn string
	// fragmentCands are payloads whose parse-level confirmation held in a non-markup fragment,
	// for the browser to decide (xss_fragment.go). Only gathered when browser confirmation is on.
	fragmentCands []xssFragmentCandidate
}

// xssNullByteVariants sends the null-byte variants at one point. See the file header.
func xssNullByteVariants(ctx context.Context, h *ProbeHarness, point bcheck.InsertionPoint, browserConfirm bool) xssNullByteResult {
	var out xssNullByteResult
	if point.BaseValue == "" {
		return out
	}

	observed := newXSSCanary()
	sent, err := h.SendFollowingAppending(ctx, point, xssNullByteSeparator+observed)
	if err != nil {
		return out
	}
	res := sent.landing()
	if !strings.Contains(res.Body, observed) {
		return out
	}
	out.evidence |= XSSEvidenceReflected
	var contexts []xssContext
	markup := rendersAsMarkup(rawHeaderValue(string(res.Raw), "Content-Type"))
	var site xssFragmentSite
	switch {
	case markup:
		contexts = classifyXSSContexts(res.Body, observed)
	case browserConfirm:
		s, view, ok := xssLocateFragment(res.Body, observed)
		if !ok {
			return out
		}
		site = s
		contexts = classifyXSSContexts(view, observed)
	default:
		// Reflected into something no browser parses, and no browser to render it as a page's
		// script would: nothing here can be decided.
		return out
	}

	bank := xssPayloadsForContexts(contexts)
	if len(bank) > maxXSSNullByteProbes {
		bank = bank[:maxXSSNullByteProbes]
	}
	for _, base := range bank {
		payload := xssNullBytePayload(base)
		canary := newXSSCanary()
		sent, err := h.SendFollowingAppending(ctx, point, payload.build(canary))
		if err != nil {
			continue
		}
		res := sent.landing()
		if !strings.Contains(res.Body, canary) {
			continue
		}
		contentType := rawHeaderValue(string(res.Raw), "Content-Type")
		if !rendersAsMarkup(contentType) {
			out.evidence |= XSSEvidenceReflectedEncoded
			if markup || payload.confirm == nil {
				continue
			}
			if view, ok := site.extract(res.Body); ok && strings.Contains(view, canary) && payload.confirm(view, canary) {
				out.fragmentCands = append(out.fragmentCands, xssFragmentCandidate{payload: payload, canary: canary,
					body: view, site: site, contentType: contentType})
			}
			continue
		}
		if payload.confirm == nil {
			out.evidence |= analyzeXSSReflection(res.Body, canary, contentType,
				xssHTMLBreakoutMarker(canary), xssScriptBreakoutMarker(canary))
		} else if payload.confirm(res.Body, canary) {
			bit := payload.bit
			if bit == 0 {
				bit = XSSEvidenceHTMLBreakout
			}
			out.evidence |= bit
		} else {
			out.evidence |= XSSEvidenceReflectedEncoded
		}
		if xssBreakoutConfirmed(out.evidence) {
			out.landedOn = sent.FollowedTo
			return out
		}
	}
	return out
}

// xssNullBytePayload is base behind the NUL, for appending to the point's captured value. The
// confirmation is base's own: what has to survive into the response is the payload, wherever the
// value ahead of the NUL went.
func xssNullBytePayload(base xssPayload) xssPayload {
	build := base.build
	return xssPayload{
		build:   func(canary string) string { return xssNullByteSeparator + build(canary) },
		note:    base.note + ", appended to the original value behind a NUL byte (" + xssNullByteVariantName + ")",
		confirm: base.confirm,
		bit:     base.bit,
	}
}
