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
// **Nested points are not enumerated.** Burp audits inside an already-decoded
// parameter and reports `"Skipped as nested insertion points not enabled"`
// when that is switched off. Not implementing it is a miss, never a false
// positive: fewer positions get probed, and every position that does get probed
// is still exactly one.
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
)

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
// The body case is the one that matters: splicing a payload into a container
// whose framing is not modelled (multipart, XML, a non-UTF-8 body) produces a
// request the server rejects before the code under test ever sees it. Returning
// nothing in that case made the refusal indistinguishable from "this request
// genuinely has nowhere to inject" — so a `given body insertion point` check
// against a multipart form reported a clean bill of health while testing
// nothing. That is the silent false negative this type exists to prevent: a
// declined body is surfaced as skipped, never as tested.
type Declined struct {
	// What was declined, named for the operator ("request body").
	What string
	// Why no points were built ("multipart body: framing not modelled").
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

// Enumerate returns every insertion point of the requested kinds, capped at
// DefaultMaxInsertionPoints. See EnumerateWithLimit for the cap's semantics.
func Enumerate(req []byte, kinds []string) ([]InsertionPoint, []Declined) {
	return EnumerateWithLimit(req, kinds, DefaultMaxInsertionPoints)
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
func EnumerateWithLimit(req []byte, kinds []string, max int) ([]InsertionPoint, []Declined) {
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
					coding:    codingForm,
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
				coding:    codingForm,
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
					loc:       loc{kind: locRelocateBodyToCookie, start: kv.name[0], end: kv.value[1]},
					coding:    codingForm,
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
	out, droppedNested := capPoints(append(out, expandNested(out)...), max)

	if dropped := droppedFlat + droppedNested; dropped > 0 {
		declined = append(declined, Declined{
			What: "insertion points past the per-request limit",
			Reason: fmt.Sprintf("%d point(s) were not audited: this request reached the maximum of %d insertion points per base request",
				dropped, max),
		})
	}

	return out, declined
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

// bodyPoints appends body points, if the body is a container we can splice into
// without corrupting it — otherwise a Declined entry naming what was refused
// and why.
//
// Multipart, XML and plain-text bodies yield nothing. Splicing into a container
// whose framing we do not model would produce a body the server rejects before
// the code under test ever sees the payload, and a check whose probe is
// rejected reports nothing while looking like it ran. The refusal is therefore
// recorded, not swallowed.
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
		Reason: "body matches no modelled container (multipart, XML or plain text): splicing would corrupt framing the server rejects before the code under test sees the payload",
	})
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
		escaped = percentEscape(payload)
	case codingJson:
		escaped = jsonEscape(payload)
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
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '&' || c == '=' || c == '+' || c == ';' || c == '#' || c == '%' ||
			c <= 0x20 || c >= 0x7f {
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
				nested:          kind,
				containerCoding: p.coding,
				coding:          codingNested,
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
		return xmlTextSpans(inner)
	}
	return nil
}

// xmlTextSpans finds non-whitespace text-node spans within an XML string.
// Text nodes live between a '>' and the next '<'. This is a structural scan,
// not a full XML parse — it avoids the fragility of re-serialization.
func xmlTextSpans(s string) [][2]int {
	var out [][2]int
	inTag := false
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '<':
			if start >= 0 {
				end := trimTrailingWS(s, start, i)
				if end > start {
					out = append(out, [2]int{start, end})
				}
				start = -1
			}
			inTag = true
		case c == '>' && inTag:
			inTag = false
			start = i + 1
		}
	}
	if start >= 0 {
		end := trimTrailingWS(s, start, len(s))
		if end > start {
			out = append(out, [2]int{start, end})
		}
	}
	return out
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
// query/form/cookie params, identity for headers and JSON body values).
func containerDecode(c coding, s string) string {
	if c == codingForm {
		return percentDecode(s)
	}
	return s
}

// containerEncode applies the outer container encoding (percent-encoding for
// query/form/cookie params, identity for headers).
func containerEncode(c coding, s string) string {
	if c == codingForm {
		return percentEscape(s)
	}
	return s
}

// nestedDecode strips the nested encoding: JSON and XML are identity (their
// text IS the buffer), base64 is decoded.
func nestedDecode(k nestedKind, s string) (string, error) {
	switch k {
	case nestedJSON, nestedBase64JSON, nestedXML:
		return s, nil
	case nestedBase64:
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

// xmlEscape escapes the characters that would break XML text nodes.
func xmlEscape(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
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
