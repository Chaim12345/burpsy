// Insertion points — the places in a request where a payload can be placed.
//
// `given insertion point` runs a check once per point, and `send payload`
// mutates **exactly one** of them per send. That one-at-a-time rule is the whole
// value of the construct: it is what lets a finding say *which parameter* is
// injectable. A run that changed two parameters would report a vulnerability
// without saying where it is, which is not a finding, it is a rumour.
//
// # A point is an offset, not a copy
//
// Each point holds a byte range into one component of the base request — the
// query string, one header's value, or the body. Enumerating every point for a
// request therefore costs a few small labels, not a request clone per position.
// A payload is applied by splicing that one range, so everything else in the
// request is untouched, which is what makes a resulting finding attributable to
// the point's name.
//
// Because the ranges address the **base** request, Apply must always be handed
// the request the point was enumerated from. Applying twice, or applying to an
// already-mutated request, would splice at offsets that no longer mean what they
// meant.
//
// # DSL-addressable and Go-only kinds
//
// `given insertion point` can name query/body/cookie/header. The rest are
// Go-only, named after Burp's own settings (`scanner.insertion_point_types.*`)
// and `scanner.modifying_parameter_locations.*`, not invented: parameter names,
// the entire body, URL path segments, synthesised headers, and six-directional
// parameter relocations (query↔body, query↔cookie, body↔cookie — Burp relocates
// among the URL/body/cookie parameter locations only; header relocation does not
// exist).
//
// **`any` includes headers.** The evidence is `other/tokens/jwt-none-algorithm
// .bcheck`, which is a bare `given insertion point` and carries the author's own
// comment: *"Authorization header is treat differently as the base value may be
// prefixed with 'Bearer'"*. A JWT check whose `any` skipped headers would never
// fire on the one place JWTs live.
//
// **Nested points are enumerated, and can be turned off.** Burp audits inside an
// already-decoded parameter and reports `"Skipped as nested insertion points not
// enabled"` when that is switched off. expandNested does the same here, and
// EnumerateOptions.NoNested is the switch — Burp's
// `scanner.misc_insertion_point_options.use_nested_insertion_points`, whose
// shipped default is true. Turning it off is a miss, never a false positive:
// fewer positions get probed, and every position that does get probed is still
// exactly one. The miss is recorded as a Declined rather than left implicit.
//
// # Encoding: escape the payload, never re-encode the base value
//
// A payload dropped raw into a query parameter can carry `&` or `=` and silently
// become *two* parameters. So the payload is percent-escaped for the byte set
// that decides how the container is parsed, and only that set.
//
// The base value is left byte-identical. The alternative — decode the base
// value, splice, re-encode the whole thing, which is what Burp's insertion
// points do — rewrites bytes the check never asked to change (`a+b` would go
// out as `a%20b`), and a probe that differs from the baseline in ways the check
// did not cause is a false positive waiting to happen.
package bcheck

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
)

// IpKind is an insertion-point family the DSL can name. `any` is a selector in
// the `given` line, not a location, so it never appears on an InsertionPoint.
type IpKind string

const (
	IpQuery  IpKind = "query"
	IpBody   IpKind = "body"
	IpCookie IpKind = "cookie"
	IpHeader IpKind = "header"
	// IpManual is an operator-marked byte span over the raw request (burpsy-react-ui-806w): Burp's
	// MANUAL_INSERTION_POINT. When a request carries manual spans the enumerator audits exactly those
	// and skips its heuristics, so an operator can confirm an injection point the enumerator does not
	// model (a custom body format, a header the parser skips).
	IpManual IpKind = "manual"
	// URL query parameter name, not its value (Montoya PARAM_NAME_URL).
	IpParamNameURL IpKind = "param_name_url"
	// Form body parameter name (Montoya PARAM_NAME_BODY).
	IpParamNameBody IpKind = "param_name_body"
	// Whole body as one point, independent of any structured points.
	IpEntireBody      IpKind = "entire_body"
	IpURLPathFilename IpKind = "url_path_filename"
	IpURLPathFolder   IpKind = "url_path_folder"
	// IpSyntheticHeader is a header that does not exist on the base request and is
	// created fresh by Apply (Java addNewReferHeaderInsertionPoint, config
	// scanner.insertion_point_types.insert_http_headers).
	IpSyntheticHeader IpKind = "synthetic_header"
	// IpRelocateBodyToQuery moves one form body parameter to the query string
	// (Java addSwitchedBodyParameterLocationInsertionPoints: finds parsing
	// inconsistencies between body and query parsers).
	IpRelocateBodyToQuery IpKind = "relocate_body_to_query"
	// IpRelocateQueryToBody moves one query parameter into the form body.
	IpRelocateQueryToBody IpKind = "relocate_query_to_body"
	// IpRelocateQueryToCookie moves one query parameter into a Cookie header
	// (Burp settings key scanner.modifying_parameter_locations.query_to_cookie).
	IpRelocateQueryToCookie IpKind = "relocate_query_to_cookie"
	// IpRelocateCookieToQuery moves one cookie into the query string.
	IpRelocateCookieToQuery IpKind = "relocate_cookie_to_query"
	// IpRelocateBodyToCookie moves one form body parameter into a Cookie header.
	IpRelocateBodyToCookie IpKind = "relocate_body_to_cookie"
	// IpRelocateCookieToBody moves one cookie into the form body.
	IpRelocateCookieToBody IpKind = "relocate_cookie_to_body"
	// IpXML is a value inside an XML body — an element's text or an attribute's value
	// (burpsy-react-ui-75jm). Burp carries these as their own parameter location (PARAM_XML,
	// PARAM_XML_ATTR) rather than as body parameters, and the distinction is what lets an operator
	// tell "this endpoint's XML was tested" from "its form fields were".
	IpXML IpKind = "xml"
	// IpMultipartAttr is a multipart part's `name` or `filename` ATTRIBUTE, which Burp models as
	// PARAM_MULTIPART_ATTR. A part's CONTENT stays IpBody: the content is what the application
	// reads as the parameter's value, and it is a body byte range like any other. The attributes
	// are a different thing — MIME header parameters, with their own escaping — and reporting them
	// as body parameters made a multipart API's fields invisible to insertion-point selection.
	IpMultipartAttr IpKind = "multipart_attr"
)

// InsertionPoint is one place a payload can go, plus the value already there.
type InsertionPoint struct {
	// Kind is never IpAny — `any` is a selector in the `given` line, not a
	// location.
	Kind IpKind
	// Name is the parameter, header or cookie name. For JSON, the key (or
	// `key[i]` inside an array).
	Name string
	// BaseValue is the value as it appears on the wire, still encoded. What
	// `{insertion_point_base_value}` resolves to, and what `appending:` appends
	// to. Burp registers the same thing in the BCheck *variable* map rather
	// than the request map, guarded on both a v1-beta-or-later language and a
	// non-null insertion point — which is why the name is simply absent outside
	// an insertion-point check rather than empty inside one.
	BaseValue string

	loc             loc
	coding          coding
	nested          nestedKind // zero when coding != codingNested
	containerCoding coding     // outer container's escape rule, used for re-encoding
	// refuse is set for containers with no escape: the payload is spliced raw and
	// refused outright when it carries the sequence that would end the container.
	refuse refusal
	// upload is set on a multipart file part's CONTENT point (kzt7): the spans the
	// upload-as-HTML rewrite needs. Nil on every other point.
	upload *multipartUpload
}

// multipartUpload is where a file part's filename and header block sit in the body.
type multipartUpload struct {
	head     [2]int
	fileSpan [2]int
}

// locKind enumerates which component of the base request a point addresses.
type locKind int

const (
	locQuery locKind = iota
	locHeader
	locCookie
	locBody
	// locPath is a byte range within the request path (never the query —
	// RequestEdit.Path is already split from it).
	locPath
	// locSyntheticHeader appends a fresh header named by InsertionPoint.Name
	// rather than splicing an existing range (Java addNewReferHeaderInsertionPoint).
	locSyntheticHeader
	// locSyntheticQueryName appends a bare query parameter name — `?1`, no `=` — Burp's
	// addPhpFileRequestInsertionPoint (burpsy-react-ui-i7i5).
	locSyntheticQueryName
	// locRelocateBodyToQuery removes the body clause [start,end) and appends it
	// to the query as name=<payload> — the parameter now lives in the query ONLY.
	locRelocateBodyToQuery
	// locRelocateQueryToBody removes the query clause [start,end) and appends it
	// to the form body as name=<payload>.
	locRelocateQueryToBody
	// locRelocateQueryToCookie removes the query clause and appends it to the
	// Cookie header as name=<payload>.
	locRelocateQueryToCookie
	// locRelocateCookieToQuery removes one cookie clause and appends it to the
	// query as name=<payload>.
	locRelocateCookieToQuery
	// locRelocateBodyToCookie removes the body clause and appends it to the
	// Cookie header as name=<payload>.
	locRelocateBodyToCookie
	// locRelocateCookieToBody removes one cookie clause and appends it to the
	// form body as name=<payload>.
	locRelocateCookieToBody
	// locManualRaw is a byte range over the WHOLE raw request (not a RequestEdit component): an
	// operator-marked span. Apply splices into the raw bytes directly (burpsy-react-ui-806w).
	locManualRaw
)

// loc is a byte range within one component of the base request: the query
// string, the value of header `index`, a range within that value, or the body.
type loc struct {
	kind  locKind
	index int // header index for locHeader / locCookie
	start int
	end   int
	// innerStart/innerEnd are byte offsets within the decoded inner buffer for
	// nested points (coding == codingNested). Zero for all other points.
	innerStart int
	innerEnd   int
	// wrapOpen and wrapClose surround the payload when it is spliced: a self-closing XML element's
	// point (burpsy-react-ui-lzzz) replaces its "/>" with ">" + payload + "</name>". Empty for every
	// other point.
	wrapOpen, wrapClose string
}

// coding describes how a payload must be escaped so the surrounding container
// still parses.
type coding int

const (
	// codingRaw is a header value or the entire body: no container to break,
	// so the payload goes out verbatim.
	codingRaw coding = iota
	// codingForm is a `k=v` pair (or a bare name) in a query string, a cookie
	// header or a form body.
	codingForm
	// codingJson is inside a JSON string literal.
	codingJson
	// codingPath is one segment of the request path.
	codingPath
	// codingNested signals a nested point whose value is itself encoded as
	// JSON/base64/XML. The `nested` field carries the encoding; `containerCoding`
	// carries the outer container's escape rule.
	codingNested
	// codingXML is inside an XML text node or attribute value. One coding covers
	// both because one escape set is correct in both positions: a document
	// survives `&`, `<`, `>`, and `&quot;` decodes to the same byte in a text node
	// as in an attribute.
	codingXML
	// codingRawSafe splices the payload verbatim, because its container has no
	// escape: a multipart part's content is literal bytes, and the only thing that
	// ends it is the boundary delimiter. A payload that would end the container is
	// refused (see refusal) rather than altered into something that survives.
	codingRawSafe
	// codingCookieValue is the value half of one clause of a Cookie header. It is
	// NOT the form container: RFC 6265 cookie values are opaque octets with no
	// percent-encoding convention — browsers send document.cookie values raw and
	// servers (Go's r.Cookie among them) never percent-decode them. A value needs
	// to preserve only what would end the clause or the header line, so the point
	// escapes nothing and refuses the payloads that would (see refusal). Coding
	// a cookie with the form container hands the server percentEscape's
	// `=`→`%3D` corruption: `<svg onload=alert(1)>` arrives as
	// `<svg onload%3Dalert(1)>`, an event handler no parser sees.
	//
	// The `=` itself is the one character with a split personality here: raw `=`
	// is what makes an event handler work, and it is legal in a cookie value
	// (RFC 6265 §4.1.1 reserves `;` and DQUOTE, not `=`). Refuse DQUOTE rather
	// than escape it — a cookie-value payload carrying a quote is asking to be
	// re-parsed as a quoted value, which is not the injection the check wrote.
	codingCookieValue
	// codingMultipartAttr is inside a quoted parameter value of a part's
	// Content-Disposition header. RFC 2045's quoted-string is the container:
	// `\` and `"` are backslash-escaped, and CR/LF cannot appear in one at all.
	codingMultipartAttr
)

// refusal is the byte sequence a payload must not carry to be spliceable into a
// container that offers no escape: the sequence would end the container, and
// there is no way to write it inside one. The empty value refuses nothing.
//
// Refusing is the honest option for these containers. Escaping a boundary
// delimiter into something else, or dropping it, would hand the application a
// payload the check did not write — and a probe that differs from the payload is
// a result nobody can attribute.
type refusal struct {
	// seq refuses a payload containing it verbatim.
	seq string
	// any refuses a payload containing any of these bytes.
	any string
}

// check returns the byte or byte sequence that makes payload unspliceable for
// this container, or "" when the payload can be written into it.
func (r refusal) check(payload string) string {
	if r.seq != "" && strings.Contains(payload, r.seq) {
		return r.seq
	}
	for i := 0; i < len(payload); i++ {
		if r.any != "" && strings.IndexByte(r.any, payload[i]) >= 0 {
			return string(payload[i])
		}
	}
	return ""
}

// nestedKind describes the encoding inside a parameter value that produced a
// nested insertion point.
type nestedKind int

const (
	// nestedJSON: the param value is JSON text.
	nestedJSON nestedKind = iota
	// nestedBase64JSON: the param value is base64 wrapping JSON text.
	nestedBase64JSON
	// nestedBase64: the param value is base64 wrapping raw text (no
	// further nesting).
	nestedBase64
	// nestedXML: the param value is XML text.
	nestedXML
)

// Describe returns a short human-readable label for a nested encoding kind.
func (k nestedKind) Describe() string {
	switch k {
	case nestedJSON:
		return "json"
	case nestedBase64JSON:
		return "base64→json"
	case nestedBase64:
		return "base64"
	case nestedXML:
		return "xml"
	default:
		return "unknown"
	}
}

// Declined is a place the enumerator refused to build insertion points for, and
// why.
//
// The body case is the one that matters: splicing a payload into a body that is
// not a container this enumerator models (plain text, a non-UTF-8 body, a
// multipart body whose framing cannot be read) produces a request the server
// rejects before the code under test ever sees the payload. Returning nothing in
// that case made the refusal indistinguishable from "this request genuinely has
// nowhere to inject" — so a `given body insertion point` check against an
// unreadable body reported a clean bill of health while testing nothing. That is
// the silent false negative this type exists to prevent: a declined body is
// surfaced as skipped, never as tested.
type Declined struct {
	// What was declined, named for the operator ("request body").
	What string
	// Why no points were built ("plain text: matches no modelled container").
	Reason string
}

// Describe returns one line naming both what was declined and why, for a report
// row or an Unsupported payload. Neither field alone is enough: Reason without
// What reads as an unattributed error, and a check with several `given …
// insertion point` clauses can decline more than one kind of place.
func (d Declined) Describe() string {
	return fmt.Sprintf("%s: %s", d.What, d.Reason)
}

// DefaultMaxInsertionPoints bounds how many insertion points one base request
// yields.
//
// Burp enforces the same ceiling under the setting key
// `scanner.misc_insertion_point_options.max_insertion_points_per_base_request`,
// whose shipped default is 30 and whose UI reads "Limit how many insertion
// points are used in each base request. This helps speed up auditing when
// scanning requests with many parameters." A point past the ceiling is not
// audited, and Burp says so on the point itself: "Burp Scanner didn't audit this
// insertion point, as it reached the maximum limit of insertion points to audit
// per request."
//
// Without a ceiling a param-heavy request multiplied by nested JSON/base64/XML
// expansion has no upper bound on probe count, so one base request can consume
// an audit's whole budget.
const DefaultMaxInsertionPoints = 30

// The two `What` values the enumerator uses for a decline that is a *configured*
// refusal rather than a request it could not read. Named constants because
// internal/scanner classifies a queue row by matching on them, and that match was
// previously a second copy of the literal in another package — a wording change
// here would have silently reclassified every capped row as an ordinary decline.
const (
	// DeclinedPastLimitWhat names the points dropped by the per-request ceiling.
	DeclinedPastLimitWhat = "insertion points past the per-request limit"
	// DeclinedNestedDisabledWhat names the points not built because the run turned
	// nested insertion points off.
	DeclinedNestedDisabledWhat = "nested insertion points inside parameter values"
	// DeclinedSkippedParamWhat names the points dropped because the operator exempted
	// their parameter from testing — Burp's scanner.ignored_insertion_points
	// skip_all_tests_for_parameters (Zwh1). Internal/scanner classifies queue rows by
	// matching these literals, so a wording change here reclassifies rows there.
	DeclinedSkippedParamWhat = "insertion points on operator-skipped parameters"
	// DeclinedIneffectiveWhat names the places the effectiveness gate dropped
	// (burpsy-react-ui-y4om). Distinct from DeclinedSkippedParamWhat — an operator's
	// parameter skip list and an engine-judged ineffective point are two different
	// decisions, and the operator reading the queue needs to know which one applies.
	DeclinedIneffectiveWhat = "insertion points judged ineffective"
	// DeclinedSkippedServerSideWhat names the points a server-side-injection check did not probe
	// because the operator exempted their parameter from those checks — Burp's
	// scanner.ignored_insertion_points skip_server_side_injection_for_parameters (Zwh1). Distinct
	// from DeclinedSkippedParamWhat: the parameter is still tested by every other check.
	DeclinedSkippedServerSideWhat = "insertion points on parameters exempted from server-side injection checks"
)

// EnumerateOptions is the per-run tuning an audit configuration carries into the
// enumerator. The zero value is the engine default — capped at
// DefaultMaxInsertionPoints, nested points enumerated — so a caller that does not
// tune anything gets exactly the behaviour it had before options existed.
//
// It is a struct rather than two more positional arguments because both knobs come
// from one place (the run's AuditConfig) and are read in one place. A third
// max-style parameter on EnumerateWithLimit would eventually be mis-ordered at some
// call site; a named field cannot be.
type EnumerateOptions struct {
	// Max bounds the returned point count: zero takes DefaultMaxInsertionPoints, a
	// negative value lifts the cap entirely. Burp's
	// `scanner.misc_insertion_point_options.max_insertion_points_per_base_request`.
	Max int
	// NoNested suppresses nested expansion — the JSON/base64/XML structure inside a
	// parameter value is left alone and only the flat parameter is probed. Burp's
	// `scanner.misc_insertion_point_options.use_nested_insertion_points` set false.
	//
	// Spelled as the negative so the zero value keeps nested points on, which is
	// both Burp's shipped default (`"use_nested_insertion_points": true`) and what
	// every caller here did before the flag existed.
	//
	// Suppression is never silent: the points that would have been built are counted
	// and recorded as a Declined, because a run that probed only the outer parameter
	// of a base64-wrapped JSON body has not tested that body, and a report that did
	// not say so would be the false negative Declined exists to prevent.
	NoNested bool
	// ManualSpans are operator-marked [start,end) byte ranges over the raw request
	// (burpsy-react-ui-806w). When non-empty, EnumerateWith returns exactly one manual point per span
	// and nothing else — Burp short-circuits heuristic enumeration the moment a manual point exists,
	// because the operator marking a position is a statement that the enumerator's guesses are not
	// what they want tested here. An out-of-range or inverted span is dropped and recorded as Declined.
	ManualSpans [][2]int
	// SkipAllTestsForParameters names parameters an operator exempted from testing
	// entirely — Burp's scanner.ignored_insertion_points.skip_all_tests_for_parameters.
	// A point whose Name matches (case-insensitively; a parameter is an identifier and
	// HTTP identifiers fold) is dropped from every kind, and the drop is counted in a
	// Declined: an audit that skipped a parameter it was told to skip must say so, or
	// the operator's own exemption reads as "nothing to test here".
	//
	// Burp's softer list, skip_server_side_injection_for_parameters, is the field below.
	SkipAllTestsForParameters []string
	// SkipServerSideInjectionForParameters names parameters an operator exempted from the
	// server-side injection checks only — Burp's
	// scanner.ignored_insertion_points.skip_server_side_injection_for_parameters. The scanner
	// sets it ONLY on the enumeration a server-side-injection check makes (CheckDescriptor's
	// ServerSideInjection class), never on the run-wide options, so a reflected-input or
	// redirect check still probes the parameter. Matched like the skip-all list, and the drop is
	// its own Declined.
	SkipServerSideInjectionForParameters []string
	// PointEffective is the per-insertion-point effectiveness oracle behind Burp's
	// `scanner/audit_optimization/skip_ineffective_checks` (burpsy-react-ui-y4om).
	//
	// Burp's gate is PER POINT, not per check: Zfhb.java:81-83 is
	//
	//	return var1 != null && (!this.Z_.Zip() || var1.Zh()) && …
	//
	// where Zip() is skip_ineffective_checks and Zh() is the point's own effectiveness probe
	// (Zcgg.Zw → point.Zp(new Zc3c())). So a point Burp judges ineffective is dropped before
	// its payloads are sent — the largest request saving the key buys, and the reason the key
	// is worth modelling even though the predicate's own body is not recoverable from the tree
	// (Zc3c is two trivial cases; the interestingness is computed inside the point).
	//
	// CheckName names the check this enumeration is for, because the effectiveness prior is
	// keyed per check as well as per place: a parameter one check found nothing at is still
	// worth probing with another (burpsy-react-ui-y4om). Empty outside an audit, which is its
	// own bucket rather than a shared one.
	CheckName string
	//
	// The check name is part of the question because the prior is keyed per check too: a
	// parameter one check found nothing at is still worth probing with another (burpsy-react-ui-y4om).
	//
	// nil means the caller has no oracle, which is NOT the same as "every point is
	// ineffective": a nil predicate skips nothing, so a unit test or a direct call cannot lose
	// points on the strength of a run it never joined.
	PointEffective func(check string, p InsertionPoint) bool
}

// Enumerate returns every insertion point of the requested kinds, capped at
// DefaultMaxInsertionPoints. See EnumerateWith for the cap's semantics.
func Enumerate(req []byte, kinds []string) ([]InsertionPoint, []Declined) {
	return EnumerateWith(req, kinds, EnumerateOptions{Max: DefaultMaxInsertionPoints})
}

// manualPoints builds one insertion point per operator-marked span over the raw request, dropping a
// span that is out of range or inverted and recording it as Declined. Spans are returned in the order
// given, so a check's one-finding-per-point output is stable across runs (burpsy-react-ui-806w).
func manualPoints(req []byte, spans [][2]int) ([]InsertionPoint, []Declined) {
	var out []InsertionPoint
	var declined []Declined
	for i, sp := range spans {
		start, end := sp[0], sp[1]
		if start < 0 || end > len(req) || end < start {
			declined = append(declined, Declined{What: fmt.Sprintf("manual span %d", i+1),
				Reason: fmt.Sprintf("[%d,%d) is out of range for a %d-byte request", start, end, len(req))})
			continue
		}
		out = append(out, InsertionPoint{
			Kind:      IpManual,
			Name:      fmt.Sprintf("manual %d", i+1),
			BaseValue: string(req[start:end]),
			loc:       loc{kind: locManualRaw, start: start, end: end},
			coding:    codingRaw,
		})
	}
	return out, declined
}

// EnumerateWithLimit is EnumerateWith with an explicit cap and nested expansion
// left on. Retained as the spelling Intruder's uncapped body enumeration uses —
// Intruder wants every nested position and no ceiling, which is a property of
// Intruder rather than of any audit configuration.
func EnumerateWithLimit(req []byte, kinds []string, max int) ([]InsertionPoint, []Declined) {
	return EnumerateWith(req, kinds, EnumerateOptions{Max: max})
}

// EnumerateWithLimit returns every insertion point of the requested kinds, in a fixed
// order: query, headers, cookies, body, parameter-name-url, parameter-name-body,
// entire body, url-path filename, url-path folders, synthesised headers,
// body→query relocations and query→body relocations — plus the places that were
// *declined* rather than enumerated.
//
// The order is pinned because it is observable — a check reports one finding
// per point, and a scanner that reordered them between runs would reorder its
// own output.
//
// An empty point list with no declines is normal (a bare `GET /` with no
// interesting headers has nowhere to inject) and means the check simply has
// nothing to do here. An empty point list *with* declines is different: the
// request had somewhere to inject that this enumerator refuses to splice into,
// and the caller must report that as skipped rather than clean.
//
// max bounds the returned point count: zero takes DefaultMaxInsertionPoints, a
// negative value lifts the cap entirely. Points past the cap are dropped from
// the tail of the fixed order and recorded as a Declined naming how many, so a
// capped enumeration can never be mistaken for a request that simply had fewer
// places to inject.
func EnumerateWith(req []byte, kinds []string, opts EnumerateOptions) ([]InsertionPoint, []Declined) {
	if len(opts.ManualSpans) > 0 {
		return manualPoints(req, opts.ManualSpans)
	}
	max := opts.Max
	if max == 0 {
		max = DefaultMaxInsertionPoints
	}
	e, err := core.ParseRequestEdit(req)
	if err != nil {
		// Go's raw-byte model lets an unparseable request reach the enumerator,
		// which the Rust type system prevents. It has nowhere to inject, and the
		// refusal is recorded so the check reads as skipped, not tested.
		return nil, []Declined{{What: "request", Reason: "unparseable request: " + err.Error()}}
	}
	// "any" only reaches the four DSL-addressable kinds; the eight Go-only
	// kinds must be named explicitly.
	want := func(k IpKind) bool {
		for _, kd := range kinds {
			if kd == "any" && dslAddressable(k) {
				return true
			}
			if IpKind(kd) == k {
				return true
			}
		}
		return false
	}

	var out []InsertionPoint
	var declined []Declined

	if want(IpQuery) {
		for _, kv := range kvPairs(e.Query, '&') {
			out = append(out, InsertionPoint{
				Kind:      IpQuery,
				Name:      e.Query[kv.name[0]:kv.name[1]],
				BaseValue: e.Query[kv.value[0]:kv.value[1]],
				loc:       loc{kind: locQuery, start: kv.value[0], end: kv.value[1]},
				coding:    codingForm,
			})
		}
	}

	if want(IpHeader) {
		for i, h := range e.Headers {
			if isReservedHeader(h[0]) {
				continue
			}
			out = append(out, InsertionPoint{
				Kind:      IpHeader,
				Name:      h[0],
				BaseValue: h[1],
				loc:       loc{kind: locHeader, index: i},
				coding:    codingRaw,
			})
		}
	}

	if want(IpCookie) {
		for i, h := range e.Headers {
			if !strings.EqualFold(h[0], "cookie") {
				continue
			}
			for _, kv := range kvPairs(h[1], ';') {
				out = append(out, InsertionPoint{
					Kind:      IpCookie,
					Name:      h[1][kv.name[0]:kv.name[1]],
					BaseValue: h[1][kv.value[0]:kv.value[1]],
					loc:       loc{kind: locCookie, index: i, start: kv.value[0], end: kv.value[1]},
					// A cookie value is an opaque octet run, not a percent-encoded
					// form pair — see codingCookieValue. The codingForm this point
					// used before handed every payload percentEscape's `=`→`%3D`,
					// corruption no cookie reader undoes (Go's r.Cookie does not
					// decode): an `onload=alert(1)` handler arrived as
					// `onload%3Dalert(1)` and the reflection carried no marker.
					coding: codingCookieValue,
					// `;` would end this clause; CRLF/NUL would end the header
					// line; DQUOTE would re-open the value as a quoted-string
					// (RFC 6265 5.2), a container the payload did not ask for.
					refuse: refusal{any: ";\r\n\x00\""},
				})
			}
		}
	}

	if want(IpBody) {
		bodyPoints(e, &out, &declined)
	}

	if want(IpParamNameURL) {
		for _, kv := range kvPairs(e.Query, '&') {
			name := e.Query[kv.name[0]:kv.name[1]]
			out = append(out, InsertionPoint{
				Kind:      IpParamNameURL,
				Name:      name,
				BaseValue: name,
				loc:       loc{kind: locQuery, start: kv.name[0], end: kv.name[1]},
				coding:    codingForm,
			})
		}
	}

	// Burp's PHP file-request point (Zuq.addPhpFileRequestInsertionPoint, called from the
	// new-parameter-name stage when the URL's file extension is php): a bare parameter NAME "1"
	// after the path, `/page.php?1`. PHP reads a bare name as a key with an empty value, so the
	// name is where a payload reaches code that iterates $_GET's keys (burpsy-react-ui-i7i5).
	if want(IpParamNameURL) && strings.EqualFold(path.Ext(e.Path), ".php") {
		out = append(out, InsertionPoint{
			Kind:      IpParamNameURL,
			Name:      "1",
			BaseValue: "1",
			loc:       loc{kind: locSyntheticQueryName},
			coding:    codingForm,
		})
	}

	if want(IpParamNameBody) {
		if kvs, ok := formKVPairs(e); ok {
			for _, kv := range kvs {
				name := string(e.Body[kv.name[0]:kv.name[1]])
				out = append(out, InsertionPoint{
					Kind:      IpParamNameBody,
					Name:      name,
					BaseValue: name,
					loc:       loc{kind: locBody, start: kv.name[0], end: kv.name[1]},
					coding:    codingForm,
				})
			}
		}
	}

	if want(IpEntireBody) && len(e.Body) > 0 {
		out = append(out, InsertionPoint{
			Kind:      IpEntireBody,
			BaseValue: string(e.Body),
			loc:       loc{kind: locBody, start: 0, end: len(e.Body)},
			coding:    codingRaw,
		})
	}

	if want(IpURLPathFilename) || want(IpURLPathFolder) {
		folders, filename := pathSegments(e.Path)
		if want(IpURLPathFilename) {
			out = append(out, InsertionPoint{
				Kind:      IpURLPathFilename,
				Name:      "filename",
				BaseValue: e.Path[filename[0]:filename[1]],
				loc:       loc{kind: locPath, start: filename[0], end: filename[1]},
				coding:    codingPath,
			})
		}
		if want(IpURLPathFolder) {
			for _, seg := range folders {
				out = append(out, InsertionPoint{
					Kind:      IpURLPathFolder,
					Name:      "folder",
					BaseValue: e.Path[seg[0]:seg[1]],
					loc:       loc{kind: locPath, start: seg[0], end: seg[1]},
					coding:    codingPath,
				})
			}
		}
	}

	if want(IpSyntheticHeader) {
		// Java's addNewReferHeaderInsertionPoint synthesises a Referer the
		// request never sent; the same config key (insert_http_headers) also
		// synthesises User-Agent. A header the request already carries is not a
		// spot to probe — a second, identical probe would be indistinguishable
		// from the first and could not be attributed to anything.
		for _, name := range []string{"Referer", "User-Agent"} {
			if hasHeader(e, name) {
				continue
			}
			out = append(out, InsertionPoint{
				Kind:      IpSyntheticHeader,
				Name:      name,
				BaseValue: "",
				loc:       loc{kind: locSyntheticHeader},
				coding:    codingRaw,
			})
		}
	}

	if want(IpRelocateBodyToQuery) {
		// Only a form body is a source of relocatable pairs: formKVPairs
		// refuses JSON, multipart and XML, so a pair lifted out of a container
		// we do not model would be attributed to a parameter the server never
		// saw as k=v at all.
		if kvs, ok := formKVPairs(e); ok {
			for _, kv := range kvs {
				out = append(out, InsertionPoint{
					Kind:      IpRelocateBodyToQuery,
					Name:      string(e.Body[kv.name[0]:kv.name[1]]),
					BaseValue: string(e.Body[kv.value[0]:kv.value[1]]),
					loc:       loc{kind: locRelocateBodyToQuery, start: kv.name[0], end: kv.value[1]},
					coding:    codingForm,
				})
			}
		}
	}

	if want(IpRelocateQueryToBody) {
		// A pair removed from the query lands somewhere the server must read as
		// the same k=v shape it had in the query. A body that cannot take form
		// encoding (multipart, XML, JSON, non-UTF-8, or an empty body without a
		// form Content-Type) is declined — and the decline is recorded because
		// the refusal must not read as "this request had nothing to relocate".
		qkvs := kvPairs(e.Query, '&')
		if len(qkvs) > 0 && !formTargetOK(e) {
			declined = append(declined, Declined{
				What:   "query-to-body relocation",
				Reason: "request body is not a form the relocated parameter can be appended to (multipart, XML, JSON or non-UTF-8)",
			})
		} else {
			for _, kv := range qkvs {
				out = append(out, InsertionPoint{
					Kind:      IpRelocateQueryToBody,
					Name:      e.Query[kv.name[0]:kv.name[1]],
					BaseValue: e.Query[kv.value[0]:kv.value[1]],
					loc:       loc{kind: locRelocateQueryToBody, start: kv.name[0], end: kv.value[1]},
					coding:    codingForm,
				})
			}
		}
	}

	if want(IpRelocateQueryToCookie) {
		for _, kv := range kvPairs(e.Query, '&') {
			out = append(out, InsertionPoint{
				Kind:      IpRelocateQueryToCookie,
				Name:      e.Query[kv.name[0]:kv.name[1]],
				BaseValue: e.Query[kv.value[0]:kv.value[1]],
				loc:       loc{kind: locRelocateQueryToCookie, start: kv.name[0], end: kv.value[1]},
				// The payload lands as a Cookie clause value (addToCookie), so it
				// needs the cookie container, not the form one — see
				// codingCookieValue; a form-coded handler arrives percent-mangled.
				coding: codingCookieValue,
				refuse: refusal{any: ";\r\n\x00\""},
			})
		}
	}

	if want(IpRelocateBodyToCookie) {
		if kvs, ok := formKVPairs(e); ok {
			for _, kv := range kvs {
				out = append(out, InsertionPoint{
					Kind:      IpRelocateBodyToCookie,
					Name:      string(e.Body[kv.name[0]:kv.name[1]]),
					BaseValue: string(e.Body[kv.value[0]:kv.value[1]]),
					// Lands as a Cookie clause value (addToCookie) — cookie
					// container, not the form one; see codingCookieValue.
					loc:    loc{kind: locRelocateBodyToCookie, start: kv.name[0], end: kv.value[1]},
					coding: codingCookieValue,
					refuse: refusal{any: ";\r\n\x00\""},
				})
			}
		}
	}

	if want(IpRelocateCookieToQuery) || want(IpRelocateCookieToBody) {
		for i, h := range e.Headers {
			if !strings.EqualFold(h[0], "cookie") {
				continue
			}
			bodyOK := true
			if want(IpRelocateCookieToBody) && len(kvPairs(h[1], ';')) > 0 && !formTargetOK(e) {
				declined = append(declined, Declined{
					What:   "cookie-to-body relocation",
					Reason: "request body is not a form the relocated cookie can be appended to (multipart, XML, JSON or non-UTF-8)",
				})
				bodyOK = false
			}
			for _, kv := range kvPairs(h[1], ';') {
				if want(IpRelocateCookieToQuery) {
					out = append(out, InsertionPoint{
						Kind:      IpRelocateCookieToQuery,
						Name:      h[1][kv.name[0]:kv.name[1]],
						BaseValue: h[1][kv.value[0]:kv.value[1]],
						loc:       loc{kind: locRelocateCookieToQuery, index: i, start: kv.name[0], end: kv.value[1]},
						coding:    codingForm,
					})
				}
				if want(IpRelocateCookieToBody) && bodyOK {
					out = append(out, InsertionPoint{
						Kind:      IpRelocateCookieToBody,
						Name:      h[1][kv.name[0]:kv.name[1]],
						BaseValue: h[1][kv.value[0]:kv.value[1]],
						loc:       loc{kind: locRelocateCookieToBody, index: i, start: kv.name[0], end: kv.value[1]},
						coding:    codingForm,
					})
				}
			}
		}
	}

	// The cap is applied to the flat points *before* nested expansion so a
	// dropped flat point does not also spend budget on children it can no
	// longer be spliced through, and again afterwards so nested points cannot
	// push the total past the ceiling.
	out, droppedFlat := capPoints(out, max)

	// Nested expansion: for each flat param point whose value decodes to
	// JSON/base64/XML, append nested points that target the inner structure.
	//
	// When the run turned nested points off, the expansion is still *computed* and
	// then discarded, which looks wasteful and is deliberate: the count is the only
	// way to say what was given up. Burp reports the same fact per point as
	// "Skipped as nested insertion points not enabled", and a run that silently
	// probed only the outer parameter of a base64-wrapped JSON body would read as
	// having tested that body. The work is one decode per parameter, which is
	// nothing beside the probe it replaces.
	// The operator's skip list (m97j's neighbour, v9cg): a named parameter is exempted
	// from testing entirely. Applied BEFORE the cap so the cap's "past the limit" count
	// describes what remained after the operator's own exemptions — a point dropped by
	// the operator is not also a point the cap dropped, and the two declines must not
	// double-count one place.
	if skipped := skipNamedPoints(&out, opts.SkipAllTestsForParameters); skipped > 0 {
		declined = append(declined, Declined{
			What: DeclinedSkippedParamWhat,
			Reason: fmt.Sprintf("%d point(s) were not audited: their parameter is on the operator's skip-all-tests list",
				skipped),
		})
	}

	// The server-side-injection exemption (burpsy-react-ui-gmdk), beside the skip-all list for the
	// same before-the-cap reason. Present only when the enumerating check is a server-side
	// injection check; every other check's options leave it empty.
	if skipped := skipNamedPoints(&out, opts.SkipServerSideInjectionForParameters); skipped > 0 {
		declined = append(declined, Declined{
			What: DeclinedSkippedServerSideWhat,
			Reason: fmt.Sprintf("%d point(s) were not probed by this server-side injection check: their parameter is on the operator's skip-server-side-injection list",
				skipped),
		})
	}

	// The per-point effectiveness gate (burpsy-react-ui-y4om, Burp's
	// skip_ineffective_checks). Placed after the operator's skip list and before nested
	// expansion for the same reason the cap sits there: a point the gate drops must not
	// also spend budget on children, and an operator exemption must not read as an engine
	// judgement. The count is returned as one Declined rather than one per point, matching how
	// the cap and the operator list report — a run's coverage line names how many places it
	// gave up, not each of them separately.
	if dropped := dropIneffectivePoints(&out, opts.PointEffective, opts.CheckName); dropped > 0 {
		declined = append(declined, Declined{
			What: DeclinedIneffectiveWhat,
			Reason: fmt.Sprintf("%d point(s) were not probed: the point did not respond to anything the "+
				"effectiveness gate sends, so probing it again would only cost requests",
				dropped),
		})
	}

	nested := expandNested(out)
	var droppedNested int
	if opts.NoNested {
		if len(nested) > 0 {
			declined = append(declined, Declined{
				What: DeclinedNestedDisabledWhat,
				Reason: fmt.Sprintf("%d point(s) inside decoded parameter values were not audited: nested insertion points are turned off for this run",
					len(nested)),
			})
		}
		out, droppedNested = capPoints(out, max)
	} else {
		out, droppedNested = capPoints(append(out, nested...), max)
	}

	if dropped := droppedFlat + droppedNested; dropped > 0 {
		declined = append(declined, Declined{
			What: DeclinedPastLimitWhat,
			Reason: fmt.Sprintf("%d point(s) were not audited: this request reached the maximum of %d insertion points per base request",
				dropped, max),
		})
	}

	return out, declined
}

// skipNamedPoints removes every point whose Name matches one of the operator's skipped
// parameters (case-insensitively — a parameter is an identifier and HTTP identifiers fold),
// returning how many it removed. The removal is in-place over the slice the enumerator built,
// so the fixed order of the survivors is unchanged — order is observable (a check reports
// one finding per point) and an exemption must not reorder what it did not exempt.
func skipNamedPoints(pts *[]InsertionPoint, names []string) int {
	if len(names) == 0 || len(*pts) == 0 {
		return 0
	}
	skip := make(map[string]bool, len(names))
	for _, n := range names {
		skip[strings.ToLower(strings.TrimSpace(n))] = true
	}
	kept := (*pts)[:0]
	removed := 0
	for _, p := range *pts {
		if skip[strings.ToLower(p.Name)] {
			removed++
			continue
		}
		kept = append(kept, p)
	}
	*pts = kept
	return removed
}

// dropIneffectivePoints removes every point the oracle judges ineffective, returning how many it
// dropped. A nil oracle drops nothing: "the caller cannot judge" and "this point is
// ineffective" are different facts, and only one of them is a reason to spend no requests here.
func dropIneffectivePoints(pts *[]InsertionPoint, effective func(string, InsertionPoint) bool, check string) int {
	if effective == nil || len(*pts) == 0 {
		return 0
	}
	kept := (*pts)[:0]
	removed := 0
	for _, p := range *pts {
		if !effective(check, p) {
			removed++
			continue
		}
		kept = append(kept, p)
	}
	*pts = kept
	return removed
}

// capPoints truncates pts to max, returning how many it dropped. A negative max
// is uncapped. The count is returned rather than logged because the caller
// records it as a Declined: a truncation nobody can see is the silent false
// negative the Declined type exists to prevent.
func capPoints(pts []InsertionPoint, max int) ([]InsertionPoint, int) {
	if max < 0 || len(pts) <= max {
		return pts, 0
	}
	return pts[:max], len(pts) - max
}

// dslAddressable reports whether "given insertion point any" reaches k.
func dslAddressable(k IpKind) bool {
	switch k {
	case IpQuery, IpBody, IpCookie, IpHeader:
		return true
	default:
		return false
	}
}

// isReservedHeader reports whether a payload must not be placed in the named
// header.
//
// `Host` selects the virtual host, so a payload there tests a different
// application and the finding would be misattributed. `Content-Length` and
// `Transfer-Encoding` are rewritten on serialisation, so a payload in them is
// discarded before it reaches the wire — a silent no-op probe, which is worse
// than no probe. `Connection` is hop-by-hop. `Cookie` is enumerated as
// individual cookie points instead, because a payload appended to the whole
// cookie blob is not attributable to any one cookie.
func isReservedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "cookie":
		return true
	}
	return false
}

// bodyPoints appends body points for the container this body actually is —
// JSON, multipart, XML or form — or a Declined entry naming a container whose
// framing could not be read.
//
// The dispatch follows what the body *is*, not its Content-Type alone: a JSON
// document sent as text/plain and an XML document with no `application/xml`
// header are still containers whose every value a payload can be spliced into,
// and refusing them would leave those bodies untested while the report read as
// "no place to inject". A body that is no container at all — plain text — is
// still declined, never silently empty.
//
// Multipart and XML are modelled *here* rather than in a parser beside this one
// (burpsy-react-ui-63jg): a scanner check addresses the insertion points this
// enumerator builds, and Intruder addresses the positions derived from them, so
// one container model is one set of escapes and one set of refusals for both.
func bodyPoints(e *core.RequestEdit, out *[]InsertionPoint, declined *[]Declined) {
	if len(e.Body) == 0 {
		return
	}
	if !utf8.Valid(e.Body) {
		*declined = append(*declined, Declined{
			What:   "request body",
			Reason: "non-UTF-8 body: cannot splice without corrupting it",
		})
		return
	}
	body := string(e.Body)
	ctype := strings.ToLower(e.Header("content-type"))
	trimmed := strings.TrimLeft(body, " \t\r\n")

	if strings.Contains(ctype, "multipart/") {
		if multipartBodyPoints(e.Header("Content-Type"), body, out) {
			return
		}
		*declined = append(*declined, Declined{
			What:   "request body",
			Reason: "multipart body whose framing could not be read (no boundary parameter, or a part list that never closes): splicing would invent framing the server rejects before the code under test sees the payload",
		})
		return
	}

	if strings.Contains(ctype, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		for _, jv := range jsonStringValues(body) {
			*out = append(*out, InsertionPoint{
				Kind:      IpBody,
				Name:      jv.name,
				BaseValue: body[jv.value[0]:jv.value[1]],
				loc:       loc{kind: locBody, start: jv.value[0], end: jv.value[1]},
				coding:    codingJson,
			})
		}
		return
	}

	// An XML body is enumerated by structure, not by Content-Type alone: a
	// document posted as text/plain is the same document. An empty element
	// (`<a/>`) is a point of its own, as in Burp: the payload opens the element
	// around itself (burpsy-react-ui-lzzz).
	if strings.Contains(ctype, "xml") || looksLikeXML(trimmed) {
		for _, xp := range xmlPoints(body) {
			if xp.closeTag != "" {
				// A self-closing element (lzzz): no value to keep, and the splice opens the element.
				*out = append(*out, InsertionPoint{
					Kind:      IpXML,
					Name:      xp.name,
					BaseValue: "",
					loc:       loc{kind: locBody, start: xp.start, end: xp.end, wrapOpen: ">", wrapClose: "</" + xp.closeTag + ">"},
					coding:    codingXML,
				})
				continue
			}
			*out = append(*out, InsertionPoint{
				Kind:      IpXML,
				Name:      xp.name,
				BaseValue: body[xp.start:xp.end],
				loc:       loc{kind: locBody, start: xp.start, end: xp.end},
				coding:    codingXML,
			})
		}
		return
	}

	// A missing Content-Type on a `k=v&k=v` body is still a form as far as
	// every server is concerned; requiring the header would leave those bodies
	// untested.
	isForm := strings.Contains(ctype, "x-www-form-urlencoded") ||
		(ctype == "" && strings.Contains(body, "="))
	if isForm {
		for _, kv := range kvPairs(body, '&') {
			*out = append(*out, InsertionPoint{
				Kind:      IpBody,
				Name:      body[kv.name[0]:kv.name[1]],
				BaseValue: body[kv.value[0]:kv.value[1]],
				loc:       loc{kind: locBody, start: kv.value[0], end: kv.value[1]},
				coding:    codingForm,
			})
		}
		return
	}

	*declined = append(*declined, Declined{
		What:   "request body",
		Reason: "body matches no modelled container (plain text): splicing would corrupt framing the server rejects before the code under test sees the payload",
	})
}

// ---------------------------------------------------------------------------
// Multipart bodies — one point per part, per part name and per filename
// ---------------------------------------------------------------------------

// multipartBodyPoints appends the insertion points of a multipart body: each
// part's content (what the application reads as the parameter's value), its
// `name` attribute and its `filename` attribute. It reports false when the body
// does not read as a part list, so the caller declines rather than splicing into
// framing it guessed at.
//
// Every point is named so a finding says which part it came from: `avatar` for
// the content, `avatar name` and `avatar filename` for the attributes, and
// `part[N]` for a part that declares no name. The attributes are body points
// rather than `param_name_body` points because a part's name lives in a header
// this enumerator already addresses as a body byte range, and Burp's own model
// carries multipart attributes as their own parameter location
// (PARAM_MULTIPART_ATTR) rather than as the form-body name location.
func multipartBodyPoints(ctype, body string, out *[]InsertionPoint) bool {
	boundary, ok := multipartBoundary(ctype)
	if !ok {
		return false
	}
	parts, ok := multipartParts(body, boundary)
	if !ok {
		return false
	}
	if len(parts) == 0 {
		// `--B--` alone: a well-formed part list with no parts has nowhere to
		// inject. That is an empty enumeration, not a refusal.
		return true
	}
	// The sequence a content payload must not introduce: a CRLF followed by the
	// delimiter starts the next part, so a payload carrying it would end its own
	// part early and re-frame everything after it. A part's content is literal
	// bytes with no escape, so it is refused rather than rewritten.
	delim := "\r\n--" + boundary
	for i, part := range parts {
		label := part.name
		if label == "" {
			label = "part[" + strconv.Itoa(i) + "]"
		}
		content := InsertionPoint{
			Kind:      IpBody,
			Name:      label,
			BaseValue: body[part.content[0]:part.content[1]],
			loc:       loc{kind: locBody, start: part.content[0], end: part.content[1]},
			coding:    codingRawSafe,
			refuse:    refusal{seq: delim},
		}
		if part.hasFile {
			content.upload = &multipartUpload{head: part.headSpan, fileSpan: part.fileSpan}
		}
		*out = append(*out, content)
		if part.hasName {
			*out = append(*out, InsertionPoint{
				Kind:      IpMultipartAttr,
				Name:      label + " name",
				BaseValue: body[part.nameSpan[0]:part.nameSpan[1]],
				loc:       loc{kind: locBody, start: part.nameSpan[0], end: part.nameSpan[1]},
				coding:    codingMultipartAttr,
				refuse:    refusal{any: "\r\n\x00"},
			})
		}
		if part.hasFile {
			*out = append(*out, InsertionPoint{
				Kind:      IpMultipartAttr,
				Name:      label + " filename",
				BaseValue: body[part.fileSpan[0]:part.fileSpan[1]],
				loc:       loc{kind: locBody, start: part.fileSpan[0], end: part.fileSpan[1]},
				coding:    codingMultipartAttr,
				refuse:    refusal{any: "\r\n\x00"},
			})
		}
	}
	return true
}

// multipartBoundary returns the boundary parameter of a multipart Content-Type,
// unquoted. A multipart body without one cannot be split — the delimiter is the
// whole framing — so the caller declines rather than guessing where parts begin.
func multipartBoundary(ctype string) (string, bool) {
	if !strings.Contains(strings.ToLower(ctype), "multipart/") {
		return "", false
	}
	for _, p := range headerParams(ctype) {
		if strings.EqualFold(p.name, "boundary") && p.value != "" {
			return p.value, true
		}
	}
	return "", false
}

// multipartPart is one part of a multipart body: the byte ranges of its
// Content-Disposition parameters and of its content, all relative to the body so
// they can be spliced into it directly.
type multipartPart struct {
	name     string
	nameSpan [2]int
	hasName  bool
	// fileSpan is the `filename` attribute's value range; the value itself is
	// read off the body when it is needed, so no copy is kept here.
	fileSpan [2]int
	hasFile  bool
	content  [2]int
	// headSpan is the part's header block (no trailing blank line), for the upload-as-HTML
	// rewrite that replaces its Content-Type (burpsy-react-ui-kzt7).
	headSpan [2]int
}

// multipartParts splits a multipart body into its parts. ok is false when the
// body does not read as a part list at all: the delimiter never appears, a
// part's headers are never terminated, or the list never closes. A caller that
// spliced into a half-read part list would be inventing framing.
//
// The walk follows the same shape a server's parser does — delimiter line, part
// headers, blank line, content, CRLF, next delimiter — and takes its ranges from
// the original bytes instead of re-serialising a parsed structure, because every
// offset it reports has to be a byte range of the body the check will send.
func multipartParts(body, boundary string) ([]multipartPart, bool) {
	delim := "--" + boundary
	first := strings.Index(body, delim)
	if first < 0 {
		return nil, false
	}
	var parts []multipartPart
	cursor := first
	for {
		after := cursor + len(delim)
		if after > len(body) {
			return nil, false
		}
		if strings.HasPrefix(body[after:], "--") {
			// The closing delimiter: the part list ended here.
			return parts, true
		}
		lineEnd := after
		for lineEnd < len(body) && (body[lineEnd] == ' ' || body[lineEnd] == '\t') {
			lineEnd++
		}
		var headStart int
		switch {
		case strings.HasPrefix(body[lineEnd:], "\r\n"):
			headStart = lineEnd + 2
		case strings.HasPrefix(body[lineEnd:], "\n"):
			headStart = lineEnd + 1
		default:
			return nil, false
		}
		// Part headers end at the first blank line.
		sep := strings.Index(body[headStart:], "\r\n\r\n")
		sepLen := 4
		if sep < 0 {
			sep = strings.Index(body[headStart:], "\n\n")
			sepLen = 2
		}
		if sep < 0 {
			return nil, false
		}
		headEnd := headStart + sep
		contentStart := headEnd + sepLen
		// Content runs to the CRLF that precedes the next delimiter.
		next, skip := -1, 0
		if i := strings.Index(body[contentStart:], "\r\n"+delim); i >= 0 {
			next, skip = i, 2
		} else if i := strings.Index(body[contentStart:], "\n"+delim); i >= 0 {
			next, skip = i, 1
		}
		if next < 0 {
			return nil, false
		}
		part := multipartPart{content: [2]int{contentStart, contentStart + next}, headSpan: [2]int{headStart, headEnd}}
		readDisposition(body[headStart:headEnd], headStart, &part)
		parts = append(parts, part)
		cursor = contentStart + next + skip
	}
}

// readDisposition fills in a part's `name` and `filename` parameters from its
// header block, with byte ranges relative to the whole body (base is the block's
// own offset within it).
func readDisposition(headers string, base int, part *multipartPart) {
	lineStart := 0
	for lineStart <= len(headers) {
		lineEnd := strings.IndexByte(headers[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(headers)
		} else {
			lineEnd += lineStart
		}
		line := strings.TrimRight(headers[lineStart:lineEnd], "\r")
		if name, _, ok := strings.Cut(line, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "content-disposition") {
			valueStart := lineStart + len(name) + 1
			for _, p := range headerParams(headers[valueStart:lineEnd]) {
				switch {
				case strings.EqualFold(p.name, "name") && !part.hasName:
					part.name, part.hasName = p.value, true
					part.nameSpan = [2]int{base + valueStart + p.span[0], base + valueStart + p.span[1]}
				case strings.EqualFold(p.name, "filename") && !part.hasFile:
					part.hasFile = true
					part.fileSpan = [2]int{base + valueStart + p.span[0], base + valueStart + p.span[1]}
				}
			}
		}
		if lineEnd >= len(headers) {
			break
		}
		lineStart = lineEnd + 1
	}
}

// headerParam is one `name=value` parameter of a header value, with the byte
// range of its value relative to the value it was read from.
type headerParam struct {
	name  string
	value string
	span  [2]int
}

// headerParams returns the parameters of a header value — `multipart/form-data;
// boundary=B`, `form-data; name="f"; filename="a.txt"` — with quotes stripped
// and each value's byte range recorded, so a caller can splice into the value
// where it sits on the wire rather than where a re-serialised copy would put it.
//
// A segment with no `=` (the media type, or a valueless flag) is not a
// parameter: it has no value to splice into.
func headerParams(s string) []headerParam {
	var out []headerParam
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ';' || s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		nameStart := i
		for i < len(s) && s[i] != '=' && s[i] != ';' {
			i++
		}
		name := strings.TrimSpace(s[nameStart:i])
		if i >= len(s) || s[i] != '=' {
			continue
		}
		i++
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' || s[i] == '\'' {
			quote := s[i]
			i++
			valueStart := i
			for i < len(s) && s[i] != quote {
				i++
			}
			out = append(out, headerParam{name: name, value: s[valueStart:i], span: [2]int{valueStart, i}})
			if i < len(s) {
				i++
			}
			continue
		}
		valueStart := i
		for i < len(s) && s[i] != ';' {
			i++
		}
		end := trimTrailingWS(s, valueStart, i)
		out = append(out, headerParam{name: name, value: s[valueStart:end], span: [2]int{valueStart, end}})
	}
	return out
}

// ---------------------------------------------------------------------------
// XML bodies — one point per text node and per attribute value
// ---------------------------------------------------------------------------

// xmlPoint is one spliceable range in an XML document: a text node or an
// attribute value, plus the name a finding reports it by.
type xmlPoint struct {
	name       string
	start, end int
	// closeTag is set for a self-closing element's point (lzzz): the element name to close when
	// the "/>" at [start,end) is opened into ">" + payload + "</name>".
	closeTag string
}

// xmlFrame is one open element during an XML scan: the path a finding reports
// its values by, plus what it needs to tell a repeated sibling from the first.
type xmlFrame struct {
	path string
	// first is this element's first child's name; child counts the names of its
	// children, so a repeated sibling can be given an index like a JSON array
	// element — and is allocated only when there *is* a second child, because a
	// single-child chain (`<a><b>x</b></a>`) is the shape an XML API actually
	// sends and it should allocate nothing per element.
	first string
	child map[string]int
}

// siblingIndex records one more child element of this name and returns how many
// same-named siblings preceded it — 0 for the first, which keeps its plain path,
// and 1, 2, … for the rest, which is what makes `item[1]` unambiguous.
//
// It is a method on the frame so the map stays unallocated for the first child:
// an element with one child (the shape most XML APIs send) never pays for a map.
func (f *xmlFrame) siblingIndex(name string) int {
	if f.first == "" {
		f.first = name
		return 0
	}
	if f.child == nil {
		f.child = map[string]int{f.first: 1}
	}
	n := f.child[name]
	f.child[name] = n + 1
	return n
}

// xmlPoints returns every value an XML document lets a payload be spliced into —
// text nodes and attribute values, named by their element path (`order/item` for
// a text node, `order/item[1]` for a repeated sibling, `order@id` for an
// attribute). The attribute is joined to its element with `@` so a name can never
// be mistaken for an element path that happens to look like it.
//
// The scan is structural rather than a decoder: it needs byte positions in the
// original text, which a decoder hands back values without. It offers only
// ranges whose splice cannot break the document — a tag name, a comment, a
// processing instruction and a DOCTYPE hold no payload — and a document it
// cannot follow to the end still yields the ranges it recognised, because each
// one is a byte range of this body rather than an offset derived from
// re-serialising a parsed tree.
//
// A CDATA section yields nothing: its content is literal, so no escape keeps a
// payload intact inside one, and a payload rewritten into `]]&gt;` would reach
// the application as bytes the check never wrote. That is a miss, never a false
// positive — the same posture the nested-point switch takes.
func xmlPoints(s string) []xmlPoint {
	var out []xmlPoint
	var stack []xmlFrame
	textStart := -1
	flushText := func(end int) {
		if textStart < 0 {
			return
		}
		start := textStart
		textStart = -1
		for start < end && isXMLSpace(s[start]) {
			start++
		}
		end = trimTrailingWS(s, start, end)
		if end <= start || len(stack) == 0 {
			// Whitespace between elements is layout, not a value, and text
			// outside the root element belongs to no element (well-formed XML
			// has none).
			return
		}
		out = append(out, xmlPoint{name: stack[len(stack)-1].path, start: start, end: end})
	}
	for i := 0; i < len(s); {
		if s[i] != '<' {
			if textStart < 0 {
				textStart = i
			}
			i++
			continue
		}
		flushText(i)
		switch {
		case strings.HasPrefix(s[i:], "<!--"):
			i = skipPast(s, i+4, "-->")
		case strings.HasPrefix(s[i:], "<![CDATA["):
			i = skipPast(s, i+9, "]]>")
		case strings.HasPrefix(s[i:], "<?"):
			i = skipPast(s, i+2, "?>")
		case strings.HasPrefix(s[i:], "<!"):
			i = skipPast(s, i+2, ">")
		case strings.HasPrefix(s[i:], "</"):
			name, j := xmlName(s, i+2)
			if name == "" {
				// `</ >` names no element, so nothing can be popped for it — the
				// scan skips the construct rather than emptying the stack and
				// losing the element path of every text node after it.
				i = skipPast(s, j, ">")
				continue
			}
			for len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if lastSegment(top.path) == name {
					break
				}
			}
			i = skipPast(s, j, ">")
		default:
			name, j := xmlName(s, i+1)
			if name == "" {
				// A stray `<` is text, not a tag.
				if textStart < 0 {
					textStart = i
				}
				i++
				continue
			}
			path := name
			if len(stack) > 0 {
				parent := &stack[len(stack)-1]
				path = parent.path + "/" + name
				if n := parent.siblingIndex(name); n > 0 {
					path += "[" + strconv.Itoa(n) + "]"
				}
			}
			end, selfClosing := xmlAttrs(s, j, path, &out)
			if !selfClosing {
				stack = append(stack, xmlFrame{path: path})
			} else if end >= 2 && s[end-1] == '>' && s[end-2] == '/' {
				// Burp's standalone-tag point (Zuq addStandaloneTagInsertionPoint): an empty
				// element has no text node to inject into, so the "/>" — with any spaces before it —
				// is the point, and a payload opens the element around itself.
				slash := end - 2
				for slash > j && isXMLSpace(s[slash-1]) {
					slash--
				}
				out = append(out, xmlPoint{name: path, start: slash, end: end, closeTag: name})
			}
			textStart = end
			i = end
		}
	}
	flushText(len(s))
	return out
}

// xmlName reads an XML name at s[i:], returning it and the offset just past it.
func xmlName(s string, i int) (string, int) {
	start := i
	for i < len(s) && !isXMLSpace(s[i]) && s[i] != '>' && s[i] != '/' && s[i] != '=' {
		i++
	}
	return s[start:i], i
}

// isXMLSpace reports whether c separates XML tokens.
func isXMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// skipPast returns the offset just past the first occurrence of close at or
// after i, or len(s) when the construct is never closed — at which point the scan
// has no further structure to read and stops.
func skipPast(s string, i int, close string) int {
	if j := strings.Index(s[i:], close); j >= 0 {
		return i + j + len(close)
	}
	return len(s)
}

// lastSegment returns the final path component of a path like `order/item[1]`,
// with any sibling index removed, for matching a closing tag to its element.
func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.IndexByte(path, '['); i >= 0 {
		path = path[:i]
	}
	return path
}

// xmlAttrs appends one point per attribute value in the tag whose attributes
// begin at s[i:], and returns the offset just past the tag's `>` plus whether the
// tag closed itself. path is the element's own path, and each attribute is named
// `<path>@<attribute>`.
func xmlAttrs(s string, i int, path string, out *[]xmlPoint) (end int, selfClosing bool) {
	for i < len(s) {
		for i < len(s) && isXMLSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			return i, false
		}
		if s[i] == '>' {
			return i + 1, false
		}
		if s[i] == '/' {
			j := i + 1
			for j < len(s) && isXMLSpace(s[j]) {
				j++
			}
			if j < len(s) && s[j] == '>' {
				return j + 1, true
			}
			i++
			continue
		}
		name, j := xmlName(s, i)
		if name == "" {
			i++
			continue
		}
		i = j
		for i < len(s) && isXMLSpace(s[i]) {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			// A valueless attribute (`<input disabled>`): no value to splice into.
			continue
		}
		i++
		for i < len(s) && isXMLSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			return i, false
		}
		if s[i] == '"' || s[i] == '\'' {
			quote := s[i]
			i++
			valueStart := i
			for i < len(s) && s[i] != quote {
				i++
			}
			*out = append(*out, xmlPoint{name: path + "@" + name, start: valueStart, end: i})
			if i < len(s) {
				i++
			}
			continue
		}
		valueStart := i
		for i < len(s) && !isXMLSpace(s[i]) && s[i] != '>' {
			i++
		}
		*out = append(*out, xmlPoint{name: path + "@" + name, start: valueStart, end: i})
	}
	return i, false
}

// formKVPairs returns the body's k=v pairs when it is a form body, matching
// bodyPoints' own form detection.
func formKVPairs(e *core.RequestEdit) ([]kvPair, bool) {
	if len(e.Body) == 0 || !utf8.Valid(e.Body) {
		return nil, false
	}
	body := string(e.Body)
	ctype := strings.ToLower(e.Header("content-type"))
	isForm := strings.Contains(ctype, "x-www-form-urlencoded") ||
		(ctype == "" && strings.Contains(body, "="))
	if !isForm {
		return nil, false
	}
	return kvPairs(body, '&'), true
}

// hasHeader reports whether the request carries a header of this name,
// case-insensitively. A synthesised-header point must not fire for a header the
// request already sends — duplicating Referer would hand the check a second
// probe that cannot be distinguished from the first.
func hasHeader(e *core.RequestEdit, name string) bool {
	for _, h := range e.Headers {
		if strings.EqualFold(h[0], name) {
			return true
		}
	}
	return false
}

// formTargetOK reports whether the body can accept one more appended `k=v`
// clause: it is a form body as formKVPairs models it, or an empty body under an
// application/x-www-form-urlencoded Content-Type. Anything else (multipart,
// XML, JSON, a non-UTF-8 body, or an empty body with no form Content-Type) is
// not a target, because a pair transported there would lose the k=v shape the
// server read in the query.
func formTargetOK(e *core.RequestEdit) bool {
	if len(e.Body) == 0 {
		return strings.Contains(strings.ToLower(e.Header("content-type")), "x-www-form-urlencoded")
	}
	_, ok := formKVPairs(e)
	return ok
}

// clauseRemovalSep widens the byte range of one `name=value` clause so that
// removing it swallows exactly one adjacent separator, leaving the surviving
// clauses still divided by a single delimiter. s is the container text (query
// string, form body or Cookie value), start/end address the whole clause, and
// sep is the delimiter ('&' for query/body, ';' for cookies). For `a&b&c`
// removing `b` yields `a&c`; for `a; b; c` removing `b` yields `a; c`. The
// leading separator is preferred (so a lone delimiter remains between the
// clauses that were on either side of the removed one); the trailing separator
// is used when the clause is first.
func clauseRemovalSep(s string, start, end int, sep byte) (int, int) {
	s0, s1 := start, end
	for s0 < s1 && (s[s0] == ' ' || s[s0] == '\t') {
		s0++
	}
	for s1 > s0 && (s[s1-1] == ' ' || s[s1-1] == '\t') {
		s1--
	}
	i := s0
	for i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		i--
	}
	if i > 0 && s[i-1] == sep {
		i--
		for i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
			i--
		}
		return i, s1
	}
	j := s1
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	if j < len(s) && s[j] == sep {
		j++
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		return s0, j
	}
	return s0, s1
}

// ApplyOptions tunes how Apply places a payload (burpsy-react-ui-79ld).
//
// Raw is the decoding-variant escape policy: a payload whose bytes ARE the probe — a
// percent-escape the application is meant to decode, an overlong or invalid UTF-8 sequence —
// must reach the wire verbatim, because percentEscape's own `%`→`%25` and non-ASCII escaping
// would hand the application a different payload than the check wrote (the URL-decoding
// variant double-encoded; the UTF-8 variants never arrive as bytes at all). What Raw keeps is
// everything the REQUEST needs to stay parseable: the `k=v` structural separators and the
// request-line-unsafe bytes. A container that re-encodes by design — a JSON string literal, an
// XML text node — is not loosened by Raw: a raw 0xC0 byte inside a JSON string is not a
// "decoding variant", it is a malformed document, and no check asks for it.
type ApplyOptions struct {
	Raw bool
}

// Apply splices payload into this point of req, which must be the request the
// point was enumerated from. appending keeps the existing value and adds to it;
// otherwise it is overwritten. The new raw request is returned.
//
// The appending flag is honoured vacuously for a synthetic-header point — there
// is no value on the wire to keep, so both flags place the escaped payload
// alone in the fresh header. For a relocation point it transports the existing
// wire value along, prefixing it onto the payload at the switched location.
//
// Everything else in the request is untouched, which is what makes a resulting
// finding attributable to the point's name.
func (p *InsertionPoint) Apply(req []byte, payload string, appending bool) ([]byte, error) {
	return p.ApplyOpts(req, payload, appending, ApplyOptions{})
}

// ApplyOpts is Apply with options. See ApplyOptions for what Raw changes.
func (p *InsertionPoint) ApplyOpts(req []byte, payload string, appending bool, opts ApplyOptions) ([]byte, error) {
	// A manual point splices into the RAW request bytes at its marked span, bypassing the component
	// parser entirely — the operator marked a byte range, not a parsed parameter (burpsy-react-ui-806w).
	if p.loc.kind == locManualRaw {
		start, end := p.loc.start, p.loc.end
		if start < 0 || end > len(req) || end < start {
			return nil, fmt.Errorf("manual insertion point [%d,%d) is out of range for a %d-byte request", start, end, len(req))
		}
		newVal := payload
		if appending {
			newVal = p.BaseValue + payload
		}
		out := make([]byte, 0, len(req)-(end-start)+len(newVal))
		out = append(out, req[:start]...)
		out = append(out, newVal...)
		out = append(out, req[end:]...)
		return out, nil
	}
	e, err := core.ParseRequestEdit(req)
	if err != nil {
		return nil, err
	}

	// Nested points take a separate path: decode → splice → re-encode within the
	// decoded inner buffer, then re-encode the outer container.
	if p.coding == codingNested {
		return p.applyNested(e, payload, appending)
	}

	var escaped string
	switch p.coding {
	case codingForm:
		// Raw loosens only THIS escape (79ld): the decoding-variant payloads live in `k=v`
		// containers, and every other coding either splices verbatim already (cookie, raw-safe)
		// or re-encodes by the grammar of its container (JSON, XML), which Raw deliberately
		// does not loosen — see ApplyOptions.
		escaped = percentEscapeOpts(payload, opts.Raw)
	case codingJson:
		escaped = jsonEscape(payload)
	case codingXML:
		escaped = xmlEscape(payload)
	case codingMultipartAttr:
		if err := p.refuseValue(payload); err != nil {
			return nil, err
		}
		escaped = multipartAttrEscape(payload)
	case codingRawSafe:
		if err := p.refuseValue(payload); err != nil {
			return nil, err
		}
		escaped = payload
	case codingCookieValue:
		// Verbatim splice with a refusal, not an escape: see codingCookieValue.
		// The clause terminator and header-line breakers cannot be written inside
		// the value, and percent-escaping them would change what the server reads.
		if err := p.refuseValue(payload); err != nil {
			return nil, err
		}
		escaped = payload
	case codingPath:
		escaped = pathEscape(payload)
	default:
		escaped = payload
	}
	// The base value is already in wire form, so the escaped payload
	// concatenates onto it directly — no decode/re-encode round trip.
	newVal := escaped
	if appending {
		newVal = p.BaseValue + escaped
	}
	if p.loc.wrapClose != "" {
		newVal = p.loc.wrapOpen + newVal + p.loc.wrapClose
	}

	switch p.loc.kind {
	case locQuery:
		e.Query = spliceStr(e.Query, p.loc.start, p.loc.end, newVal)
	case locPath:
		e.Path = spliceStr(e.Path, p.loc.start, p.loc.end, newVal)
	case locHeader:
		if p.loc.index < len(e.Headers) {
			e.Headers[p.loc.index][1] = newVal
		}
	case locCookie:
		if p.loc.index < len(e.Headers) {
			h := &e.Headers[p.loc.index]
			h[1] = spliceStr(h[1], p.loc.start, p.loc.end, newVal)
		}
	case locBody:
		start := p.loc.start
		if start > len(e.Body) {
			start = len(e.Body)
		}
		end := p.loc.end
		if end > len(e.Body) {
			end = len(e.Body)
		}
		if end < start {
			end = start
		}
		b := make([]byte, 0, len(e.Body)+len(newVal))
		b = append(b, e.Body[:start]...)
		b = append(b, newVal...)
		b = append(b, e.Body[end:]...)
		e.Body = b
	case locSyntheticQueryName:
		e.AddQuery(newVal)
	case locSyntheticHeader:
		// The header does not exist on the base request, so there is nothing to
		// splice — a fresh header of the point's name is appended after every
		// existing header.
		e.AddHeader(p.Name, newVal)
	case locRelocateBodyToQuery:
		// The pair exists in the body ONLY at its switched location: it leaves
		// the body and re-enters the request in the query.
		start, end := clampOffsets(p.loc.start, p.loc.end, len(e.Body))
		body := string(e.Body)
		rs, re := clauseRemovalSep(body, start, end, '&')
		e.Body = []byte(spliceStr(body, rs, re, ""))
		e.AddQuery(p.Name + "=" + newVal)
	case locRelocateQueryToBody:
		start, end := clampOffsets(p.loc.start, p.loc.end, len(e.Query))
		rs, re := clauseRemovalSep(e.Query, start, end, '&')
		e.Query = spliceStr(e.Query, rs, re, "")
		clause := p.Name + "=" + newVal
		if len(e.Body) > 0 {
			e.Body = append(e.Body, '&')
		}
		e.Body = append(e.Body, clause...)
	case locRelocateQueryToCookie:
		start, end := clampOffsets(p.loc.start, p.loc.end, len(e.Query))
		rs, re := clauseRemovalSep(e.Query, start, end, '&')
		e.Query = spliceStr(e.Query, rs, re, "")
		addToCookie(e, p.Name+"="+newVal)
	case locRelocateBodyToCookie:
		start, end := clampOffsets(p.loc.start, p.loc.end, len(e.Body))
		rs, re := clauseRemovalSep(string(e.Body), start, end, '&')
		e.Body = []byte(spliceStr(string(e.Body), rs, re, ""))
		addToCookie(e, p.Name+"="+newVal)
	case locRelocateCookieToQuery:
		if p.loc.index < len(e.Headers) {
			h := &e.Headers[p.loc.index]
			start, end := clampOffsets(p.loc.start, p.loc.end, len(h[1]))
			rs, re := clauseRemovalSep(h[1], start, end, ';')
			h[1] = spliceStr(h[1], rs, re, "")
		}
		e.AddQuery(p.Name + "=" + newVal)
	case locRelocateCookieToBody:
		if p.loc.index < len(e.Headers) {
			h := &e.Headers[p.loc.index]
			start, end := clampOffsets(p.loc.start, p.loc.end, len(h[1]))
			rs, re := clauseRemovalSep(h[1], start, end, ';')
			h[1] = spliceStr(h[1], rs, re, "")
		}
		clause := p.Name + "=" + newVal
		if len(e.Body) > 0 {
			e.Body = append(e.Body, '&')
		}
		e.Body = append(e.Body, clause...)
	}

	return e.ToRaw(), nil
}

// spliceStr replaces the byte range [start,end) of s with newVal, flooring
// either end to the nearest char boundary so a range that lands mid-codepoint
// splices at the nearest legal position instead of producing invalid UTF-8.
func spliceStr(s string, start, end int, newVal string) string {
	start = floorBoundary(s, start)
	end = floorBoundary(s, end)
	if end < start {
		end = start
	}
	var sb strings.Builder
	sb.Grow(len(s) + len(newVal))
	sb.WriteString(s[:start])
	sb.WriteString(newVal)
	sb.WriteString(s[end:])
	return sb.String()
}

// floorBoundary moves i down to the nearest UTF-8 character boundary.
//
// A byte is a char boundary when it is not a continuation byte (0x80..0xBF),
// so an index pointing at a continuation byte is inside a multi-byte sequence
// and is floored to the preceding boundary.
func floorBoundary(s string, i int) int {
	if i > len(s) {
		i = len(s)
	}
	for i > 0 && i < len(s) && s[i]&0xC0 == 0x80 {
		i--
	}
	return i
}

// clampOffsets floors a relocation clause's byte range to the container being
// edited. The offsets always fit the request the point was enumerated from;
// the clamps guard the Apply contract against a stray caller, mirroring the
// locBody branch's defensive bounds.
func clampOffsets(start, end, max int) (int, int) {
	if start < 0 {
		start = 0
	}
	if start > max {
		start = max
	}
	if end < start {
		end = start
	}
	if end > max {
		end = max
	}
	return start, end
}

// addToCookie appends one `name=value` clause to the request's Cookie header,
// creating the header if the request carries none. A parameter relocated into a
// cookie must arrive at its new location even when the base request had no
// cookies at all — a relocation that only fired when a cookie already existed
// would silently test nothing on cookie-free requests.
func addToCookie(e *core.RequestEdit, clause string) {
	if existing := e.Header("Cookie"); existing != "" {
		e.SetHeader("Cookie", existing+"; "+clause)
		return
	}
	e.SetHeader("Cookie", clause)
}

// kvPair holds the byte ranges of the name and value of one `k=v` clause.
type kvPair struct {
	name  [2]int
	value [2]int
}

// kvPairs returns the name and value ranges of each `k=v` clause in s, split on
// sep.
//
// A clause with no `=` is skipped. It has no value to append to, and turning
// `?debug` into `?debug=<payload>` invents a parameter the application was
// never sent — a different request, tested under the original's name.
func kvPairs(s string, sep byte) []kvPair {
	b := []byte(s)
	var out []kvPair
	start := 0
	i := 0
	for i <= len(b) {
		if i == len(b) || b[i] == sep {
			// Cookie clauses are `; `-separated, so leading space is part of
			// the delimiter.
			cs := start
			for cs < i && (b[cs] == ' ' || b[cs] == '\t') {
				cs++
			}
			eq := -1
			for k := cs; k < i; k++ {
				if b[k] == '=' {
					eq = k
					break
				}
			}
			if eq >= 0 && eq > cs {
				out = append(out, kvPair{
					name:  [2]int{cs, eq},
					value: [2]int{eq + 1, i},
				})
			}
			start = i + 1
		}
		i++
	}
	return out
}

// jsonValue is one JSON string value: the key that names it and its byte range.
type jsonValue struct {
	name  string
	value [2]int
}

// jsonStringValues returns every JSON **string** value in s, with the key that
// names it.
//
// Only strings. Splicing into a number or a boolean (`{"n":1}` → `{"n":1'}`)
// yields JSON the server rejects at parse time, so the payload never reaches
// the code being tested and the check quietly finds nothing — the exact
// silent-negative this codebase refuses to ship.
//
// The scanner is deliberately structural rather than a full parser: it needs
// positions in the original text, which a value-tree parser throws away.
func jsonStringValues(s string) []jsonValue {
	type frame struct {
		object bool
		// label is the key this container was reached by, for naming values
		// nested inside it.
		label string
		key   string
		index int
		// In an object, whether the next string is a value rather than a key.
		expectValue bool
	}

	b := []byte(s)
	var stack []frame
	var out []jsonValue
	i := 0

	for i < len(b) {
		switch b[i] {
		case '{', '[':
			label := ""
			if len(stack) > 0 {
				f := stack[len(stack)-1]
				if f.object {
					label = f.key
				} else {
					label = f.label + "[" + strconv.Itoa(f.index) + "]"
				}
			}
			stack = append(stack, frame{
				object:      b[i] == '{',
				label:       label,
				expectValue: b[i] == '[', // array elements are always values
			})
			i++
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
		case ':':
			if len(stack) > 0 {
				stack[len(stack)-1].expectValue = true
			}
			i++
		case ',':
			if len(stack) > 0 {
				f := &stack[len(stack)-1]
				if f.object {
					f.expectValue = false
				} else {
					f.index++
				}
			}
			i++
		case '"':
			start := i + 1
			j := start
		scan:
			for j < len(b) {
				switch b[j] {
				case '\\':
					j += 2
				case '"':
					break scan
				default:
					j++
				}
			}
			end := j
			if end > len(b) {
				end = len(b)
			}
			if len(stack) > 0 {
				f := &stack[len(stack)-1]
				if f.object && !f.expectValue {
					f.key = s[start:end]
				} else {
					name := ""
					if f.object {
						name = f.key
					} else {
						name = f.label + "[" + strconv.Itoa(f.index) + "]"
					}
					out = append(out, jsonValue{name: name, value: [2]int{start, end}})
				}
			}
			// A bare top-level string is the whole body, not a parameter.
			i = end + 1
		default:
			i++
		}
	}
	return out
}

// percentEscape escapes the bytes that decide how a `k=v` container is read.
//
// `&`, `=` and `;` are the separators; `+` and `%` change how the value itself
// decodes, so leaving them raw would hand the application a payload other than
// the one the check wrote; `#` truncates a URL; and anything outside printable
// ASCII — space included — cannot appear in a request line at all. Everything
// else is passed through, so an injection payload arrives looking like itself.
func percentEscape(s string) string {
	return percentEscapeOpts(s, false)
}

// percentEscapeOpts is percentEscape with the Raw policy (burpsy-react-ui-79ld).
//
// Raw drops exactly the two escapes that rewrite a decoding-variant payload rather than
// transport it: `%` is left alone, so a variant's own percent-escape (`%3C`) is not turned into
// `%253C` on the wire — one container decode too many, the "double-encoded" payload the
// application never sees as the check wrote it; and bytes >= 0x7f are left alone, so an
// overlong or invalid UTF-8 sequence reaches the target as the bytes it is, not as the ASCII
// text spelling of its hex. What Raw keeps is every escape the REQUEST itself needs: the
// `k=v` separators (`&`, `=`, `+`, `;`, `#`) and the bytes that cannot appear in a request
// line. Control bytes stay escaped even under Raw — a raw 0x01 is not a decoding variant, it
// is a broken request line, and no payload this option exists for needs one.
func percentEscapeOpts(s string, raw bool) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		var escaped bool
		switch {
		case raw:
			// Structural and request-line safety only: `%` and the high bytes pass through.
			escaped = c == '&' || c == '=' || c == '+' || c == ';' || c == '#' || c <= 0x20
		default:
			escaped = c == '&' || c == '=' || c == '+' || c == ';' || c == '#' || c == '%' ||
				c <= 0x20 || c >= 0x7f
		}
		if escaped {
			fmt.Fprintf(&sb, "%%%02X", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// jsonEscape escapes a payload for use inside a JSON string literal.
func jsonEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	return sb.String()
}

// pathSegments splits path on '/' and returns the byte ranges of every
// middle segment (folders) and the last segment (filename). The leading
// segment before the first '/' is always empty and is dropped.
func pathSegments(path string) (folders [][2]int, filename [2]int) {
	if path == "" {
		return nil, [2]int{0, 0}
	}
	var segs [][2]int
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			segs = append(segs, [2]int{start, i})
			start = i + 1
		}
	}
	filename = segs[len(segs)-1]
	if len(segs) > 1 {
		folders = segs[1 : len(segs)-1]
	}
	return folders, filename
}

// pathEscape escapes the bytes that would change how a path segment is
// parsed: '/' starts a new segment, '?' starts the query, '#' the fragment,
// '%' changes decoding.
func pathEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' || c == '?' || c == '#' || c == '%' || c <= 0x20 || c >= 0x7f {
			fmt.Fprintf(&sb, "%%%02X", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Nested insertion points — one level of decode → splice → re-encode
// ---------------------------------------------------------------------------

const (
	maxNestedPoints   = 400
	maxNestedValueLen = 8192
)

// expandNested generates nested insertion points for each flat param point whose
// value decodes to JSON, base64, or XML. The returned points carry a nested
// encoding and inner offsets; Apply routes them to applyNested, which re-encodes
// the decoded inner buffer before splicing back into the request component.
func expandNested(parents []InsertionPoint) []InsertionPoint {
	var nested []InsertionPoint
	for _, p := range parents {
		if len(p.BaseValue) > maxNestedValueLen || !paramLike(p) {
			continue
		}
		lvl1 := containerDecode(p.coding, p.BaseValue)
		inner, kind, ok := tryDecodeNested(lvl1)
		outer := p.coding
		if !ok && p.coding == codingCookieValue {
			// A cookie value is an opaque octet run (no percent layer of its
			// own), but the APPLICATION may percent-encode its cookie params —
			// session=%7B%22id%22%3A%2242%22%7D is common. The wire value then
			// decodes to JSON only after percentDecode. Try that explicitly and,
			// when it nests, keep codingForm as the outer container so the
			// rebuilt value is re-encoded the way the wire form was — matching
			// the round trip the application itself performs. A percent layer
			// whose decoded form does not nest is left alone: decoding it would
			// hand the inner splicer a value the application never sees.
			if dec, kind2, ok2 := tryDecodeNested(percentDecode(p.BaseValue)); ok2 {
				inner, kind, ok = dec, kind2, true
				outer = codingForm
			}
		}
		if !ok {
			continue
		}
		for _, sp := range innerSpans(kind, inner) {
			if len(nested) >= maxNestedPoints {
				return nested
			}
			np := InsertionPoint{
				Kind:            p.Kind,
				Name:            p.Name,
				BaseValue:       p.BaseValue,
				containerCoding: outer,
				nested:          kind,
				// The container's own refusal carries into the rebuilt value: a
				// nested payload whose escape leaves a delimiter intact inside the
				// outer container would end it exactly as a raw one would.
				refuse: p.refuse,
				coding: codingNested,
				loc: loc{
					kind:       p.loc.kind,
					index:      p.loc.index,
					start:      p.loc.start,
					end:        p.loc.end,
					innerStart: sp[0],
					innerEnd:   sp[1],
				},
			}
			// A header's value occupies the entire h[1]; nested header points
			// set start/end to cover the whole value so applyNested can splice
			// within it.
			if p.loc.kind == locHeader {
				np.loc.start = 0
				np.loc.end = len(p.BaseValue)
			}
			nested = append(nested, np)
		}
	}
	return nested
}

// paramLike reports whether the point represents a single named parameter
// value that could contain an encoded payload.
func paramLike(p InsertionPoint) bool {
	switch p.Kind {
	case IpQuery, IpBody, IpCookie, IpHeader:
		return true
	}
	return false
}

// tryDecodeNested inspects a container-decoded param value and returns the
// inner buffer plus encoding kind when the value looks like JSON, base64
// (optionally wrapping JSON), or XML. Returns ok=false when the value does not
// match any supported nested encoding.
func tryDecodeNested(lvl1 string) (inner string, kind nestedKind, ok bool) {
	t := strings.TrimSpace(lvl1)
	if len(t) == 0 {
		return "", 0, false
	}
	// JSON: starts with { or [ and is valid JSON.
	if (t[0] == '{' || t[0] == '[') && json.Valid([]byte(t)) {
		return lvl1, nestedJSON, true
	}
	// Base64: decodes without error, yields valid UTF-8.
	if b, err := base64.StdEncoding.DecodeString(t); err == nil && len(b) > 0 && utf8.Valid(b) {
		dec := string(b)
		dt := strings.TrimSpace(dec)
		if len(dt) > 0 && (dt[0] == '{' || dt[0] == '[') && json.Valid([]byte(dec)) {
			return dec, nestedBase64JSON, true
		}
		if isPrintable(dec) {
			return dec, nestedBase64, true
		}
	}
	// XML: looks like a tag or document.
	if looksLikeXML(t) {
		return lvl1, nestedXML, true
	}
	return "", 0, false
}

// isPrintable reports whether s contains only printable ASCII (including
// space, tab, newline, carriage return). A base64 blob that decodes to
// binary garbage will fail this check and not be treated as text.
func isPrintable(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		return false
	}
	return true
}

// looksLikeXML is a loose heuristic: the trimmed string starts with '<' and
// contains a '>'.
func looksLikeXML(s string) bool {
	t := strings.TrimSpace(s)
	return len(t) > 1 && t[0] == '<' && strings.Contains(t, ">")
}

// innerSpans returns the byte offsets of every string value (JSON), the
// single full span (base64), or text nodes (XML) inside the decoded inner
// buffer. Each [2]int pair is a byte range within inner.
func innerSpans(kind nestedKind, inner string) [][2]int {
	switch kind {
	case nestedJSON, nestedBase64JSON:
		var spans [][2]int
		for _, jv := range jsonStringValues(inner) {
			spans = append(spans, jv.value)
		}
		return spans
	case nestedBase64:
		if len(inner) == 0 {
			return nil
		}
		return [][2]int{{0, len(inner)}}
	case nestedXML:
		var spans [][2]int
		for _, xp := range xmlPoints(inner) {
			spans = append(spans, [2]int{xp.start, xp.end})
		}
		return spans
	}
	return nil
}

// trimTrailingWS walks s[i:end) backwards and returns the first index after
// the last whitespace character, so trailing whitespace is excluded from the
// text node span.
func trimTrailingWS(s string, i, end int) int {
	for end > i && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return end
}

// containerDecode strips the outer container encoding (percent-encoding for
// query/form params, identity for headers, JSON body values and cookie values).
//
// Cookie values are identity on BOTH sides: an opaque octet run carries no
// percent layer (codingCookieValue), so a percent-encoded JSON cookie is already
// the literal characters `{`, `"` and `:` on the wire — tryDecodeNested reads it
// directly, and applyNested re-splices those same literal bytes. Decoding here
// used to mean percentDecode for cookies, which resurrected the form container
// this engine retired: a JSON cookie decoded through percentDecode and was then
// re-encoded through percentEscape on the way back, reintroducing the
// `=`→`%3D` corruption the codec change exists to stop.
func containerDecode(c coding, s string) string {
	if c == codingForm {
		return percentDecode(s)
	}
	return s
}

// containerEncode applies the outer container encoding (percent-encoding for
// query/form params, identity for headers and cookie values).
func containerEncode(c coding, s string) string {
	if c == codingForm {
		return percentEscape(s)
	}
	return s
}

// nestedDecode strips the nested encoding: JSON and XML are identity (their
// text IS the buffer), base64 is decoded — including base64 wrapping JSON,
// whose inner buffer is the decoded JSON text, not the base64 text. Splicing
// JSON-relative offsets into undecoded base64 corrupts both layers, which is
// exactly what the asymmetric encode side (nestedEncode) would otherwise
// re-encode and hand to a server.
func nestedDecode(k nestedKind, s string) (string, error) {
	switch k {
	case nestedJSON, nestedXML:
		return s, nil
	case nestedBase64, nestedBase64JSON:
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return s, nil
}

// nestedEncode applies the nested encoding: JSON and XML are identity, base64
// is encoded.
func nestedEncode(k nestedKind, s string) string {
	switch k {
	case nestedBase64, nestedBase64JSON:
		return base64.StdEncoding.EncodeToString([]byte(s))
	default:
		return s
	}
}

// escapeForNested escapes a payload for insertion into the inner decoded
// buffer: JSON-escaped for JSON values, XML-escaped for XML, raw for base64
// (since base64 contents are opaque to the outer container).
func escapeForNested(k nestedKind, payload string) string {
	switch k {
	case nestedJSON, nestedBase64JSON:
		return jsonEscape(payload)
	case nestedXML:
		return xmlEscape(payload)
	default:
		return payload
	}
}

// xmlEscape escapes the characters that would break XML, whichever value
// position the payload lands in. `&` and `<` end a text node or an attribute
// value; `>` ends a CDATA section's own rule but not a text node — it is escaped
// for symmetry; and the two quote characters end a quoted attribute, so they are
// escaped as the entities that decode back to the same byte. Escaping more than
// one position needs is deliberate: the same escape serves a text node, a
// double-quoted attribute and a single-quoted attribute, and an entity decodes
// to the byte the payload carried in all three.
func xmlEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '"':
			sb.WriteString("&quot;")
		case '\'':
			sb.WriteString("&apos;")
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// multipartAttrEscape escapes a payload for a quoted parameter value in a MIME
// header: RFC 2045's quoted-string reserves its own delimiter and the escape
// character itself, and both are backslash-escaped. CR, LF and NUL cannot appear
// in a quoted-string at all — there is no spelling of a line break inside a
// header line — so the point refuses those payloads instead (refusal), rather
// than emitting a header that ends early.
func multipartAttrEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '"':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// refuseValue reports a value the point's container cannot hold. Apply and
// WireValue both route through it — for a direct splice the value is the payload,
// for a nested point it is the rebuilt wire value — so the scanner and Intruder
// refuse exactly the same inputs, and a payload cannot slip past a refusal by
// arriving through an encoded container inside one.
func (p InsertionPoint) refuseValue(v string) error {
	bad := p.refuse.check(v)
	if bad == "" {
		return nil
	}
	return fmt.Errorf("%s %q: value contains %q, which would end the container it is spliced into", p.Kind, p.Name, bad)
}

// percentDecode reverses percent-encoding using a simple %XX decoder. Unlike
// net/url, this does not translate '+' into space, which matches the project's
// own percentEscape (which escapes '+'). The round-trip is therefore stable.
func percentDecode(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var b byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02X", &b); err == nil {
				sb.WriteByte(b)
				i += 2
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// applyNested handles a nested point: it decodes the parameter value from the
// request, splices the payload into the inner decoded buffer at the recorded
// offsets, re-encodes the inner buffer, then re-encodes the outer container
// and splices the result back into the request component.
func (p *InsertionPoint) applyNested(e *core.RequestEdit, payload string, appending bool) ([]byte, error) {
	lvl1 := containerDecode(p.containerCoding, p.BaseValue)
	inner, err := nestedDecode(p.nested, lvl1)
	if err != nil {
		return nil, err
	}
	innerEscaped := escapeForNested(p.nested, payload)
	var innerNew string
	if appending {
		innerNew = spliceStr(inner, p.loc.innerStart, p.loc.innerEnd,
			inner[p.loc.innerStart:p.loc.innerEnd]+innerEscaped)
	} else {
		innerNew = spliceStr(inner, p.loc.innerStart, p.loc.innerEnd, innerEscaped)
	}
	lvl1New := nestedEncode(p.nested, innerNew)
	newWire := containerEncode(p.containerCoding, lvl1New)
	// The rebuilt value is checked, not the payload: an escape that leaves a
	// delimiter intact inside the rebuilt container ends it just as surely as a
	// raw one would.
	if err := p.refuseValue(newWire); err != nil {
		return nil, err
	}

	switch p.loc.kind {
	case locQuery:
		e.Query = spliceStr(e.Query, p.loc.start, p.loc.end, newWire)
	case locHeader:
		if p.loc.index < len(e.Headers) {
			h := &e.Headers[p.loc.index]
			h[1] = spliceStr(h[1], p.loc.start, p.loc.end, newWire)
		}
	case locCookie:
		if p.loc.index < len(e.Headers) {
			h := &e.Headers[p.loc.index]
			h[1] = spliceStr(h[1], p.loc.start, p.loc.end, newWire)
		}
	case locBody:
		start, end := clampOffsets(p.loc.start, p.loc.end, len(e.Body))
		b := make([]byte, 0, len(e.Body)+len(newWire))
		b = append(b, e.Body[:start]...)
		b = append(b, newWire...)
		b = append(b, e.Body[end:]...)
		e.Body = b
	default:
		return nil, fmt.Errorf("nested point has unsupported location kind %d", p.loc.kind)
	}
	return e.ToRaw(), nil
}

// The exports below exist for Intruder (internal/intruder), which consumes this
// enumerator rather than keeping a second parser (burpsy-react-ui-33t). One
// parser means one container model: JSON fields, base64-wrapped values and the
// refusals behave identically for the Scanner and for Intruder, and an
// improvement to either lands in both. Everything stays read-only here — the
// adapter splices raw bytes itself and asks these accessors where and how.

// ContainerCode names the body container a point splices into. Scanner and
// Intruder must escape a payload the same way for the same container — the
// single-parser rule (burpsy-react-ui-33t) — so the code is exported while the
// internal coding stays private.
type ContainerCode uint8

const (
	// ContainerNone is not a body value window: a query, header, cookie or path
	// point, the entire body, or a form value (which Intruder walks natively,
	// wire-faithful and unescaped).
	ContainerNone ContainerCode = iota
	// ContainerJSON is a JSON string value.
	ContainerJSON
	// ContainerNested is a value inside a JSON/base64/XML-encoded parameter: the
	// payload goes into the decoded inner buffer and the whole outer wire value
	// is rebuilt.
	ContainerNested
	// ContainerXML is an XML text node or attribute value.
	ContainerXML
	// ContainerMultipartValue is a multipart part's content: literal bytes, so
	// the payload is spliced raw and refused when it carries the boundary
	// delimiter.
	ContainerMultipartValue
	// ContainerMultipartAttr is a quoted parameter value of a part's
	// Content-Disposition header.
	ContainerMultipartAttr
)

// BodyWindow reports the byte window — relative to the body — that this point
// replaces, together with the container the payload lands in. It is how Intruder
// addresses every body container the scanner models without keeping a second
// parser of its own.
//
// ok is false for every point that is not a single body value: query, header,
// cookie, path, form values and the entire body all splice elsewhere, and
// Intruder discovers those positions itself.
func (p InsertionPoint) BodyWindow() (start, end int, code ContainerCode, ok bool) {
	if p.loc.kind != locBody {
		return 0, 0, ContainerNone, false
	}
	switch p.coding {
	case codingJson:
		return p.loc.start, p.loc.end, ContainerJSON, true
	case codingNested:
		return p.loc.start, p.loc.end, ContainerNested, true
	case codingXML:
		return p.loc.start, p.loc.end, ContainerXML, true
	case codingRawSafe:
		return p.loc.start, p.loc.end, ContainerMultipartValue, true
	case codingMultipartAttr:
		return p.loc.start, p.loc.end, ContainerMultipartAttr, true
	}
	return 0, 0, ContainerNone, false
}

// WireValue returns the full wire value the point carries once payload has been
// spliced in: the payload escaped for its container (JSON string, XML text node
// or attribute value, MIME quoted-string), or — for a nested point — the whole
// outer wire value rebuilt from decode → splice → re-encode. It replaces the
// window; WireValueAppend is the "Append to base parameter value" form.
//
// A payload the container cannot represent is an error rather than a rewritten
// payload, so Intruder refuses exactly what the scanner's Apply refuses.
func (p InsertionPoint) WireValue(payload string) (string, error) {
	switch p.coding {
	case codingJson:
		return jsonEscape(payload), nil
	case codingXML:
		return xmlEscape(payload), nil
	case codingMultipartAttr:
		if err := p.refuseValue(payload); err != nil {
			return "", err
		}
		return multipartAttrEscape(payload), nil
	case codingCookieValue:
		// Same refusal as Apply's codingCookieValue case — see codingCookieValue.
		if err := p.refuseValue(payload); err != nil {
			return "", err
		}
		return payload, nil
	case codingRawSafe:
		if err := p.refuseValue(payload); err != nil {
			return "", err
		}
		return payload, nil
	case codingNested:
		return p.nestedWireValue(payload, false)
	default:
		return "", fmt.Errorf("intruder point: unsupported coding %d", p.coding)
	}
}

// AppendRebuildsValue reports whether appending a payload to this point's base
// value rebuilds the whole wire value. It does for a nested point only: the base
// value there is decoded, extended in its inner buffer and re-encoded (base64
// cannot be extended by concatenating onto its encoded text), so Intruder must
// replace the full window with WireValueAppend. Every other container keeps its
// base bytes exactly as captured, and appending is the escaped payload
// (WireValue) spliced at the end of the window.
func (p InsertionPoint) AppendRebuildsValue() bool { return p.coding == codingNested }

// WireValueAppend is WireValue for Intruder's "Append to base parameter value"
// (burpsy-react-ui-1krs): the full wire value the point carries once payload is
// appended to its base value. For a nested point this is applyNested's
// appending branch — the payload lands after the inner value, inside the
// decoded buffer, and the outer value is re-encoded. For every other container
// it is the base wire bytes followed by the escaped payload, which is
// byte-for-byte what splicing WireValue(payload) at the end of the window
// produces; the refusals are WireValue's own, so Intruder refuses exactly what
// the scanner's Apply(…, appending=true) refuses.
func (p InsertionPoint) WireValueAppend(payload string) (string, error) {
	if p.coding == codingNested {
		return p.nestedWireValue(payload, true)
	}
	escaped, err := p.WireValue(payload)
	if err != nil {
		return "", err
	}
	return p.BaseValue + escaped, nil
}

// nestedWireValue rebuilds a nested point's outer wire value with payload
// spliced into the decoded inner buffer — over the inner value, or after it when
// appending. The rebuilt value is what the refusal checks, as in applyNested.
func (p InsertionPoint) nestedWireValue(payload string, appending bool) (string, error) {
	lvl1 := containerDecode(p.containerCoding, p.BaseValue)
	inner, err := nestedDecode(p.nested, lvl1)
	if err != nil {
		return "", err
	}
	innerNew := escapeForNested(p.nested, payload)
	if appending {
		innerNew = inner[p.loc.innerStart:p.loc.innerEnd] + innerNew
	}
	innerNew = spliceStr(inner, p.loc.innerStart, p.loc.innerEnd, innerNew)
	wire := containerEncode(p.containerCoding, nestedEncode(p.nested, innerNew))
	if err := p.refuseValue(wire); err != nil {
		return "", err
	}
	return wire, nil
}

// UploadFilename returns the filename of the multipart file part this content point belongs to,
// and whether it is one (burpsy-react-ui-kzt7).
func (p *InsertionPoint) UploadFilename(req []byte) (string, bool) {
	if p.upload == nil {
		return "", false
	}
	e, err := core.ParseRequestEdit(req)
	if err != nil {
		return "", false
	}
	start, end := clampOffsets(p.upload.fileSpan[0], p.upload.fileSpan[1], len(e.Body))
	return string(e.Body[start:end]), true
}

// ApplyHTMLUpload is Burp's file-upload HTML variant (FILE_UPLOAD_FILE_EXTENSION_HTML_*,
// burp.Zc3y): the file part is re-sent as an HTML document — its filename becomes newName, its
// Content-Type text/html, and its content the payload — so an upload the application stores and
// serves back is tested as the HTML page a victim would be sent to. Only a file part's content
// point carries the spans; any other point is refused.
func (p *InsertionPoint) ApplyHTMLUpload(req []byte, payload, newName string) ([]byte, error) {
	if p.upload == nil {
		return nil, fmt.Errorf("%s %q is not a multipart file part", p.Kind, p.Name)
	}
	if err := p.refuseValue(payload); err != nil {
		return nil, err
	}
	if strings.ContainsAny(newName, "\"\r\n\x00") {
		return nil, fmt.Errorf("filename %q cannot be written into a Content-Disposition header", newName)
	}
	e, err := core.ParseRequestEdit(req)
	if err != nil {
		return nil, err
	}
	body := string(e.Body)
	hs, he := clampOffsets(p.upload.head[0], p.upload.head[1], len(body))
	fs, fe := clampOffsets(p.upload.fileSpan[0], p.upload.fileSpan[1], len(body))
	cs, ce := clampOffsets(p.loc.start, p.loc.end, len(body))
	if !(hs <= fs && fe <= he && he <= cs && cs <= ce) {
		return nil, fmt.Errorf("multipart part spans are out of order")
	}
	// The header block with the filename swapped, and its Content-Type replaced (or added).
	head := body[hs:fs] + newName + body[fe:he]
	lines := strings.Split(head, "\n")
	replaced := false
	for i, line := range lines {
		if name, _, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-type") {
			lines[i] = "Content-Type: text/html" + func() string {
				if strings.HasSuffix(line, "\r") {
					return "\r"
				}
				return ""
			}()
			replaced = true
		}
	}
	head = strings.Join(lines, "\n")
	if !replaced {
		eol := "\r\n"
		if !strings.Contains(head, "\r\n") {
			eol = "\n"
		}
		head += eol + "Content-Type: text/html"
	}
	e.Body = []byte(body[:hs] + head + body[he:cs] + payload + body[ce:])
	return e.ToRaw(), nil
}
