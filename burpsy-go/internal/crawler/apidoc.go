package crawler

// API-document discovery: an OpenAPI/Swagger definition or a SOAP WSDL met during a crawl becomes
// a source of endpoints, rather than a file that was fetched, stored, scanned and discarded
// (burpsy-react-ui-bwwg).
//
// # Why this is a sibling of ParseJSONLocations, not a replacement for it
//
// ParseJSONLocations (mz1n) reads a JSON document for URL-shaped strings — the narrow inference rule,
// because JSON has no link vocabulary. That is the right rule for an arbitrary API response and the
// WRONG rule for an API definition: an OpenAPI document describes its routes as `paths` entries keyed
// by method, and reading those as URL-shaped strings loses the method, loses the declared parameters,
// and — for a path templated as `/users/{id}` — cannot tell a parameter from a literal segment. So the
// two are siblings over the same input: this one recognises a document by its own grammar and reads it
// exactly, and neither widens the other.
//
// # What is read
//
//   - OpenAPI 3.x (`openapi:`) and Swagger 2.0 (`swagger:`), in JSON or YAML. YAML is the common case
//     for both — an OpenAPI document in the wild is more often YAML than JSON — and a JSON-only parser
//     would find fewer than half of them.
//   - SOAP WSDL, which is XML and had been parsed by nothing.
//
// Each yields a method, a path, and the parameter names the document declares. Those parameter names
// are why this parser exists rather than a URL-shaped string scan: `/users/{id}` has to become a
// location the crawler can instantiate, and only the document knows `id` is a parameter and `users`
// is literal.
//
// # JSON and YAML, and why one decoder serves both
//
// Both are read into map[string]any and then walked through ONE accessor (apiObj/apiStr). yaml.v3
// cannot unmarshal into a json.RawMessage — verified, it answers "cannot unmarshal !!map into
// json.RawMessage" — so a document model built on RawMessage fields would work for JSON and silently
// produce an empty Paths for every YAML definition, which is the majority. Reading both into the same
// shape is also what stops the two grammars from producing two different answers for the same
// document: there is one traversal and one place a field is read.
//
// The cost is that a number in a YAML document arrives as int (and in JSON as float64), so apiStr
// normalises both rather than pretending they are the same type.

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strings"
)

// Bounds on one API document. Named so the numbers appear in one place and a test can assert them.
//
// The document-size bound exists for the reason jsonMaxBytes does — an arbitrarily large definition
// read into memory is a denial of service against the operator running the crawl — but it is separate
// because the two parsers have different per-value costs: this one builds a map per operation, and a
// document with fifty thousand operations is not the same memory as a JSON blob of the same size.
const (
	apiDefMaxBytes     = 8 << 20 // one document
	apiDefMaxLocations = 20_000  // operations admitted from it
	apiDefMaxParams    = 64      // parameter names kept per operation
	apiDefMaxDepth     = 64      // XML nesting depth tolerated in a WSDL
)

// APIDocFormat is which grammar a document turned out to be.
type APIDocFormat string

// The formats this parser recognises. A closed set with an explicit none, because "it was not one of
// ours" and "it was an OpenAPI document we failed to read" are different answers with different
// remedies — the distinction SkipSitemapUnparsed and SkipJSONUnparsed exist to preserve.
const (
	// APIDocNone means the body is not an API definition at all, which is the ordinary case for the
	// overwhelming majority of responses a crawl fetches. NOT a failure.
	APIDocNone APIDocFormat = ""
	// APIDocOpenAPI means an OpenAPI 3.x document.
	APIDocOpenAPI APIDocFormat = "openapi"
	// APIDocSwagger means a Swagger 2.0 document.
	APIDocSwagger APIDocFormat = "swagger"
	// APIDocWSDL means a SOAP WSDL.
	APIDocWSDL APIDocFormat = "wsdl"
)

// APIDocEndpoint is one operation a document declares.
//
// Path is the document's own path template ("/users/{id}"), NOT a URL: the base is whatever the
// document was fetched from, and joining here would resolve a reference against the wrong base and
// outside the scope in force. Parameters are the declared names, so a caller can tell a parameter
// segment from a literal one.
type APIDocEndpoint struct {
	Method     string
	Path       string
	Parameters []string
	// OperationID is the document's own identifier — the one string that is unique within the
	// document and stable across versions, which is what a wordlist or a report keys on when two
	// operations share a path.
	OperationID string
	// Summary is the document's own one-line description, when it has one.
	Summary string
}

// apiMethod reports whether a key names a verb, which is how a path entry is told apart from the
// metadata every document carries (`parameters`, `summary`, `$ref`, `servers`, extensions).
//
// The OpenAPI set, closed. An unlisted method a future document adds is metadata until this says
// otherwise — the same direction of default as confirm_gate.go's methodMutates, because a reader that
// treated an unknown key as a verb would turn a document's own metadata into endpoints.
func apiMethod(key string) bool {
	switch strings.ToUpper(key) {
	case "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE":
		return true
	default:
		return false
	}
}

// ParseAPIDocument recognises an API definition and returns the endpoints it declares.
//
// format is APIDocNone for a body that is not a definition, which is NOT an error: the caller calls
// this on every non-HTML response and must be able to distinguish "not for me" from "for me and
// broken". failure is non-empty only in the second case — the body announced itself as a definition
// and could not be read — and the caller turns that into SkipAPIUnparsed rather than reporting zero
// locations, which is the whole point of the bead.
func ParseAPIDocument(contentType string, body []byte) (format APIDocFormat, eps []APIDocEndpoint, failure string) {
	if len(body) == 0 {
		return APIDocNone, nil, ""
	}
	format = sniffAPIDocument(contentType, body)
	if format == APIDocNone {
		return APIDocNone, nil, ""
	}
	if len(body) > apiDefMaxBytes {
		return format, nil, "the document is larger than the parse bound, so its endpoints were not read"
	}
	if format == APIDocWSDL {
		eps, failure = parseWSDL(body)
		return APIDocWSDL, eps, failure
	}
	eps, failure = parseOpenAPI(body)
	return format, eps, failure
}

// sniffAPIDocument identifies a definition from cheap signals, without parsing it.
//
// Cheap because it runs on every non-HTML response: a version key or a root element name read from
// the head of the body. A hint, not a gate, for the reason LooksLikeJSON is a hint: a target serves
// these as text/plain and application/octet-stream routinely.
func sniffAPIDocument(contentType string, body []byte) APIDocFormat {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	text := strings.ToLower(string(head) + " " + contentType)

	switch {
	case strings.Contains(text, "<wsdl:definitions"), strings.Contains(text, "<definitions"),
		strings.Contains(text, "<soap:schema"), strings.Contains(text, "wsdl"):
		return APIDocWSDL
	case strings.Contains(text, `"openapi"`), strings.Contains(text, "'openapi'"),
		strings.Contains(text, "openapi:"):
		return APIDocOpenAPI
	case strings.Contains(text, `"swagger"`), strings.Contains(text, "'swagger'"),
		strings.Contains(text, "swagger:"):
		return APIDocSwagger
	default:
		return APIDocNone
	}
}

// ---- the one traversal, shared by JSON and YAML --------------------------------------------

// parseOpenAPI reads an OpenAPI 3 or Swagger 2 document and returns its operations.
//
// JSON and YAML are decoded into the same map shape and then read by the same accessor, so a field
// is read in one place and a YAML document cannot take a different code path from a JSON one that
// declares the same thing.
func parseOpenAPI(body []byte) ([]APIDocEndpoint, string) {
	root, err := decodeAPIDocTree(body)
	if err != nil {
		return nil, "the document announced itself as an API definition but is neither JSON nor YAML: " + err.Error()
	}
	raw, present := root["paths"]
	if !present || raw == nil {
		// A document with no `paths` key at all is a legal skeleton. Zero endpoints is the true
		// answer, and reporting it as a failure would tell an operator their API is broken when the
		// file simply declares no routes yet.
		return nil, ""
	}
	paths := apiObj(raw)
	if paths == nil {
		// `paths` is PRESENT and is not a mapping. That is different from absent: the document
		// claims to describe routes in a shape this reader cannot read, so the endpoints it
		// declares are unknown rather than none. Reporting zero here would tell the operator their
		// target published no API — which is the exact failure this bead exists to stop, and the
		// reason SkipAPIUnparsed is a distinct skip rather than a zero.
		return nil, "the document's `paths` is present but is not a mapping of routes"
	}
	// Swagger 2 keeps reusable parameters under `parameters` at the top level; OpenAPI 3 puts them
	// under `components.parameters`. Both are read into one map so a $ref resolves in either.
	components := map[string]any{}
	if comps := apiObj(root["components"]); comps != nil {
		components = apiObj(comps["parameters"])
	}
	if components == nil {
		components = apiObj(root["parameters"])
	}

	out := make([]APIDocEndpoint, 0, len(paths))
	for _, path := range sortedKeys(paths) {
		methods := apiObj(paths[path])
		for _, method := range sortedKeys(methods) {
			if !apiMethod(method) {
				continue
			}
			op := apiObj(methods[method])
			ep := APIDocEndpoint{
				Method:      strings.ToUpper(method),
				Path:        path,
				OperationID: apiStr(op["operationId"]),
				Summary:     apiFirstStr(op, "summary", "description"),
				Parameters:  apiParameterNames(op, components),
			}
			out = append(out, ep)
			if len(out) >= apiDefMaxLocations {
				return out, ""
			}
		}
	}
	return out, ""
}

// apiParameterNames collects one operation's declared parameter names, in a stable order.
//
// Sorted and de-duplicated because the set feeds two consumers that must agree: the caller that
// instantiates a path template, and a report an operator reads. A document declaring `id` twice (as
// a path parameter and again as a query parameter) yields it once — they are the same name to
// substitute.
func apiParameterNames(op, components map[string]any) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 8)
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || len(out) >= apiDefMaxParams {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, raw := range apiArr(op["parameters"]) {
		p := apiObj(raw)
		if p == nil {
			continue
		}
		if name := apiStr(p["name"]); name != "" {
			add(name)
			continue
		}
		// A $ref to a parameter declared elsewhere in this document. An $ref to ANOTHER document is
		// not followed: fetching it is a new request the scope in force has not authorised, so it
		// resolves to nothing rather than to a guess.
		if ref := apiStr(p["$ref"]); strings.HasPrefix(ref, "#/") {
			segments := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
			if resolved := apiObj(apiObj(components)[segments[len(segments)-1]]); resolved != nil {
				add(apiStr(resolved["name"]))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---- WSDL ----------------------------------------------------------------------------------

// parseWSDL returns the endpoints a WSDL declares.
//
// Read as a streaming XML token walk rather than unmarshalled into a struct: a WSDL nests messages,
// ports, bindings and types to arbitrary depth, and a struct modelling one server's layout is wrong
// for the next one. What a crawl needs is small — <operation> elements and their soapAction — and it
// can only get that right by reading elements rather than a shape.
func parseWSDL(body []byte) ([]APIDocEndpoint, string) {
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	dec.Strict = false
	var out []APIDocEndpoint
	seen := map[string]bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// The document is complete, which is not a failure.
				return out, ""
			}
			// The document stopped mid-way. Whatever was read before the break is kept and the
			// remainder reported: a truncated fetch of a real WSDL still names its first operations,
			// and returning those with a reason beats returning nothing.
			return out, "the WSDL ended mid-document: " + err.Error()
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "operation" {
			continue
		}

		// A WSDL nests <soap:operation> INSIDE <wsdl:operation>, and both carry the local name
		// "operation". A walk matching on the local name alone therefore saw every binding operation
		// TWICE and reported the wrapper's name and the nested element's soapAction as two separate
		// endpoints. This is not a theoretical concern: the first version of this parser did exactly
		// that, and the test caught it.
		//
		// The fix is to consume the wrapper's subtree here, so the nested element is read as part of
		// the operation it belongs to instead of being seen again as a top-level one. That also gets
		// the soapAction, which lives on that nested element — the wrapper itself only ever carries
		// `name`, and a document that inlines the action on the wrapper is read too.
		action := wsdlActionInSubtree(dec, apiDefMaxDepth)
		ep := APIDocEndpoint{
			Method: "POST",
			// The soapAction is what a SOAP client actually sends, so it is the better identity; the
			// element name is the fallback for a document that omits one.
			OperationID: firstNonEmpty(action, xmlAttr(start, "name")),
		}
		if ep.OperationID == "" {
			// An operation with no name names nothing, so there is no endpoint to derive from it.
			continue
		}
		// SOAP is POST, and the service path lives in the port's <soap:address> rather than in the
		// operation — so this yields the operation identity and the verb, and the caller joins it to
		// the document's own URL. Guessing a path here would invent endpoints, which is exactly what
		// this module exists to stop.
		if seen[ep.OperationID] {
			continue
		}
		seen[ep.OperationID] = true
		out = append(out, ep)
		if len(out) >= apiDefMaxLocations {
			return out, ""
		}
	}
}

// wsdlActionInSubtree reads forward to the end of the current element and returns the soapAction of
// the first nested element that carries one.
//
// Reading forward to the element's own end is what consumes the nested <soap:operation>, so the outer
// walk never sees it a second time — that single property is what fixes the double-count. `bound` caps
// the walk so a malformed or hostile document cannot make it run away: past the bound it stops, and the
// operation is reported under its element name, which is a narrower read rather than an unbounded one.
//
// The bound counts tokens rather than nesting levels because it is the token stream that is being
// walked, and a document that nests deeply inside one operation is exactly the shape a bound exists
// to survive.
func wsdlActionInSubtree(dec *xml.Decoder, bound int) string {
	for i := 0; i <= bound; i++ {
		tok, err := dec.Token()
		if err != nil {
			// EOF or a malformed tail: whatever was found stands, and the outer walk's next Token()
			// sees the same error and reports it, so nothing is silently swallowed here.
			return ""
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if action := xmlAttr(t, "soapAction"); action != "" {
				return action
			}
		case xml.EndElement:
			// The wrapper's own end token: this element's subtree is finished.
			return ""
		}
	}
	return ""
}

// xmlAttr returns an element's attribute value by local name.
//
// Local name rather than a qualified name because a WSDL declares its attributes unqualified while
// its ELEMENTS are namespaced, and requiring the writer's chosen prefix here would reject documents
// that are perfectly valid.
func xmlAttr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ---- the accessors -------------------------------------------------------------------------

// apiObj coerces a decoded value to an object, or nil when it is not one.
//
// Nil rather than an empty map, because "this field is absent" and "this field is present and empty"
// answer different questions and only the first is worth carrying on.
func apiObj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// apiArr coerces a decoded value to an array, or nil.
func apiArr(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

// apiStr reads a scalar as a string, normalising the numeric types the two decoders disagree on.
//
// json gives float64 for every number and yaml gives int or float64, so a parameter declared
// `version: 1` is an int under YAML and 1.0 under JSON. Without this the same document would yield
// different parameter names depending on which grammar it was written in, which is exactly the
// kind of quiet divergence this traversal exists to prevent.
func apiStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strings.TrimSuffix(fmtFloat(t), ".0")
	case int:
		return itoa(t)
	case int64:
		return itoa64(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// apiFirstStr returns the first of the named fields that holds a non-blank string.
func apiFirstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(apiStr(m[k])); s != "" {
			return s
		}
	}
	return ""
}

// sortedKeys returns a map's keys in order.
//
// Sorted rather than ranged so the same document always yields the same endpoints in the same order,
// which is what makes the apiDefMaxLocations cap truncate deterministically rather than differently on
// every run.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LooksLikeWSDL reports whether a body is a SOAP WSDL.
//
// Exported because the crawler asks the question on its own before choosing which of the two readers
// is switched on: a WSDL handed to the OpenAPI reader finds no paths and reports a definition with
// zero endpoints, which is a wrong answer rather than a missing one.
func LooksLikeWSDL(contentType string, body []byte) bool {
	return sniffAPIDocument(contentType, body) == APIDocWSDL
}
