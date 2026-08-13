package scanner

import (
	"encoding/json"
	"errors"
	"regexp"
)

// GraphQL schema-aware query engine, an infra primitive for the four declined catalog
// rows in check_registry_declined.go: "GraphQL endpoint found" (2098448, burp.Zmzj),
// "GraphQL introspection enabled" (2098450, burp.Zgd9), "GraphQL suggestions enabled"
// (2098451, burp.Zbop), and "GraphQL content type not validated" (2098452, burp.Zx85).
// This file is infra only: it defines pure classifiers over already-fetched probe
// bodies. It registers nothing in NativeCheckRegistry and defines no CheckRunner.
//
// Evidence recovered per class, from /root/burp-re/out/strings/map_root.tsv and
// /root/burp-re/out/clean/root/*.java:
//
//   - Zmzj (endpoint discovery): literal probe body `query{__typename}`, literal
//     content type "application/json; charset=utf-8", and literals "GET"/"POST".
//     checks_discovery.go already ported these as graphQLIntrospectionQuery and
//     graphQLContentType; this file reuses those two consts verbatim (see
//     ContentTypeProbes below) rather than redefining them.
//
//   - Zgd9 (introspection enabled, 2098450): grep of `^burp\.Zgd9\t` against
//     map_root.tsv returns zero literals — Zgd9 itself carries no string constant.
//     Reading Zgd9.java shows why: its actual probe body is delegated to
//     `Zuj2.ZQ(false)`, a separate UI-configuration class (burp.Zu6/Zuj2, the
//     Project Options "Set introspection query" / "Set legacy introspection query"
//     setting), which DOES have two full, genuinely recovered introspection-query
//     literals in map_root.tsv (`query IntrospectionQuery { __schema { queryType
//     { name } mutationType { name } subscriptionType { name } types { ...FullType }
//     directives { name description args { ...InputValue } } } } fragment FullType
//     on __Type { ... }`, at lines 9098-9099 and 9772-9773). Those two literals are
//     real Burp evidence, but they belong to the UI class, not to Zgd9, and they use
//     a `...FullType` fragment indirection the task's required query shape does not.
//     Per this task's explicit spec, FullIntrospectionQuery below returns the
//     smaller, inline (non-fragment) shape the task specifies — the standard
//     documented GraphQL spec introspection subset, not a Burp literal. Said so here
//     explicitly so the distinction is not lost: a fuller, genuinely Burp-sourced
//     query exists in the evidence and deliberately was not the one used.
//
//   - Zbop (suggestions enabled, 2098451): two genuine literals — probe body
//     `query{__type}` and confirmation substring "must have a selection of
//     subfields. Did you mean". Reading Zbop.java confirms the real check sends
//     that exact probe and looks for that exact substring in the response. That
//     substring is graphql-js's message for one specific validation failure
//     (querying an object-typed field, `__type`, without selecting subfields) — but
//     graphql-js renders the *same* "Did you mean ...?" suffix for other validation
//     failures too, most commonly `Cannot query field "x" on type "Y". Did you mean
//     "a" or "b"?` for a misspelled field name. Both are instances of one general
//     signal: a schema-suggestion leak. SuggestionProbe/ExtractSuggestions below
//     implement the general "Did you mean" pattern rather than hardcoding Zbop's own
//     narrower substring, so the primitive also covers the misspelled-field variant
//     that is the more common real-world trigger. This is also the basis for the
//     claim (in ExtractSuggestions' own doc) that suggestions leak schema even with
//     introspection disabled: the message names real field/type identifiers
//     regardless of whether __schema queries are permitted.
//
//   - Zx85 (content type not validated, 2098452): literals "GET", "POST",
//     "Content-Type", and the same `query{__typename}` probe body as Zmzj — no
//     literal beyond what Zmzj already contributed. Zx85.java confirms the real
//     check swaps Content-Type across GET/POST variants of that one probe and
//     compares responses; ContentTypeProbes below builds the equivalent probe set.

// ---------------------------------------------------------------------------
// Introspection query construction
// ---------------------------------------------------------------------------

// FullIntrospectionQuery returns the documented GraphQL spec introspection subset —
// queryType name, every type's name/kind/fields (with each field's args and
// resolved type, one level of ofType deep), and directive names. This is the
// standard shape any GraphQL client uses to introspect a schema; it is not a Burp
// literal (see the file header for the genuine Burp literal this deliberately does
// not use, and why).
func FullIntrospectionQuery() string {
	return "query{__schema{queryType{name} types{name kind fields{name args{name type{name kind ofType{name}}}}} directives{name}}}"
}

// ---------------------------------------------------------------------------
// Schema model
// ---------------------------------------------------------------------------

// Schema is the subset of a GraphQL schema this primitive extracts from an
// introspection response: enough to report exposed operations and surface size,
// not a full re-implementation of the introspection type system (no interfaces,
// enum values, or input-object fields — the four checks this backs only need
// operation/field/directive names, not the full type algebra).
type Schema struct {
	QueryType    string
	MutationType string
	Types        []SchemaType
	Directives   []string
}

// SchemaType is one entry of Schema.Types: a named, kinded GraphQL type (OBJECT,
// INTERFACE, SCALAR, ...) and the fields it exposes, if any.
type SchemaType struct {
	Name   string
	Kind   string
	Fields []SchemaField
}

// SchemaField is one field of a SchemaType: its name, the names of its arguments,
// and the resolved name of its return type (unwrapped one level of NON_NULL/LIST
// via ofType when the field's own type name is null, per the introspection
// wrapping-type convention).
type SchemaField struct {
	Name     string
	Args     []string
	TypeName string
}

// MutationNames returns the field names exposed on the schema's mutation type —
// the set of write operations an attacker could enumerate from a leaked schema —
// or nil if the schema has no mutation type or that type was not itself returned
// in Types (some servers omit unreachable types from the types array).
func (s Schema) MutationNames() []string {
	if s.MutationType == "" {
		return nil
	}
	for _, t := range s.Types {
		if t.Name == s.MutationType {
			names := make([]string, len(t.Fields))
			for i, f := range t.Fields {
				names[i] = f.Name
			}
			return names
		}
	}
	return nil
}

// FieldCount returns the total number of fields across every type in the schema —
// a single number for reporting how large an exposed attack surface an
// introspection leak actually handed over.
func (s Schema) FieldCount() int {
	n := 0
	for _, t := range s.Types {
		n += len(t.Fields)
	}
	return n
}

// ---------------------------------------------------------------------------
// Introspection response parsing
// ---------------------------------------------------------------------------

// ErrIntrospectionDisabled is returned by ParseIntrospectionResponse when the
// response is well-formed GraphQL but carries only an errors array and no data —
// the schema-aware answer for "the server understood the query and refused to
// introspect", which is itself the finding for the "introspection enabled" check
// (a negative one), not a JSON parsing failure. Callers distinguish it with
// errors.Is instead of string-matching a message.
var ErrIntrospectionDisabled = errors.New("graphql: introspection disabled (errors present, no data)")

// rawSchema/rawType/... mirror the introspection response's JSON shape exactly
// (see FullIntrospectionQuery) so ParseIntrospectionResponse can unmarshal
// directly into them before flattening to the public Schema/SchemaType/
// SchemaField model above.
type rawIntrospectionEnvelope struct {
	Data *struct {
		Schema *rawSchema `json:"__schema"`
	} `json:"data"`
	Errors []rawGraphQLError `json:"errors"`
}

type rawGraphQLError struct {
	Message string `json:"message"`
}

type rawSchema struct {
	QueryType    *rawNamedRef  `json:"queryType"`
	MutationType *rawNamedRef  `json:"mutationType"`
	Types        []rawType     `json:"types"`
	Directives   []rawNamedRef `json:"directives"`
}

type rawNamedRef struct {
	Name string `json:"name"`
}

type rawType struct {
	Name   string     `json:"name"`
	Kind   string     `json:"kind"`
	Fields []rawField `json:"fields"`
}

type rawField struct {
	Name string        `json:"name"`
	Args []rawNamedRef `json:"args"`
	Type rawTypeRef    `json:"type"`
}

type rawTypeRef struct {
	Name   string      `json:"name"`
	Kind   string      `json:"kind"`
	OfType *rawTypeRef `json:"ofType"`
}

// resolveTypeName returns a type reference's own name, or its wrapped type's
// name when the reference itself is an unnamed wrapper (NON_NULL/LIST have a
// null name and carry the real type one level down in ofType).
func (r rawTypeRef) resolveTypeName() string {
	if r.Name != "" {
		return r.Name
	}
	if r.OfType != nil {
		return r.OfType.resolveTypeName()
	}
	return ""
}

// ParseIntrospectionResponse parses a GraphQL HTTP response body into a Schema.
// A response with a top-level "errors" array and no "data" is reported as
// ErrIntrospectionDisabled, not a generic parse error — see that var's doc for
// why the distinction matters to callers. Any other unparseable or schema-less
// body is a genuine error.
func ParseIntrospectionResponse(body []byte) (Schema, error) {
	var env rawIntrospectionEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Schema{}, err
	}
	if env.Data == nil || env.Data.Schema == nil {
		if len(env.Errors) > 0 {
			return Schema{}, ErrIntrospectionDisabled
		}
		return Schema{}, errors.New("graphql: response has no data.__schema and no errors")
	}
	return toSchema(env.Data.Schema), nil
}

// toSchema flattens the raw introspection JSON shape into the public Schema
// model, resolving each field's wrapped type name along the way.
func toSchema(raw *rawSchema) Schema {
	s := Schema{}
	if raw.QueryType != nil {
		s.QueryType = raw.QueryType.Name
	}
	if raw.MutationType != nil {
		s.MutationType = raw.MutationType.Name
	}
	for _, rt := range raw.Types {
		st := SchemaType{Name: rt.Name, Kind: rt.Kind}
		for _, rf := range rt.Fields {
			sf := SchemaField{Name: rf.Name, TypeName: rf.Type.resolveTypeName()}
			for _, a := range rf.Args {
				sf.Args = append(sf.Args, a.Name)
			}
			st.Fields = append(st.Fields, sf)
		}
		s.Types = append(s.Types, st)
	}
	for _, d := range raw.Directives {
		s.Directives = append(s.Directives, d.Name)
	}
	return s
}

// IntrospectionEnabled reports whether a probe response actually returned a
// schema — the positive half of the "GraphQL introspection enabled" check
// (2098450, burp.Zgd9). It is a thin, named wrapper over
// ParseIntrospectionResponse's success/failure so a caller doesn't have to spell
// out the error check.
func IntrospectionEnabled(body []byte) bool {
	_, err := ParseIntrospectionResponse(body)
	return err == nil
}

// IntrospectionDisabledReason returns the server's own explanation for refusing
// to introspect (its GraphQL error message(s), joined), or "" when introspection
// was enabled or the body could not be parsed as GraphQL at all — only the
// confirmed-disabled case gets a reason, so a caller can't mistake "unparseable"
// for "confirmed disabled".
func IntrospectionDisabledReason(body []byte) string {
	var env rawIntrospectionEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	if env.Data != nil && env.Data.Schema != nil {
		return ""
	}
	if len(env.Errors) == 0 {
		return ""
	}
	reason := ""
	for i, e := range env.Errors {
		if i > 0 {
			reason += "; "
		}
		reason += e.Message
	}
	return reason
}

// ---------------------------------------------------------------------------
// Field-suggestion leak ("Did you mean ...?")
// ---------------------------------------------------------------------------

// didYouMeanRe extracts the quoted-name list out of graphql-js/Apollo's
// validation-error suffix, e.g. `Did you mean "user" or "users"?`. This exact
// phrasing is the documented graphql-js signal (see the file header's discussion
// of Zbop) — it is emitted by GraphQL's own field-suggestion algorithm whenever a
// query references an unknown or incomplete field, independent of whether
// introspection is enabled, which is why suggestions-enabled is tracked as a
// separate finding from introspection-enabled: a server can lock down __schema
// and still leak real field/type names one typo probe at a time.
var didYouMeanRe = regexp.MustCompile(`(?i)did you mean\s+([^?]*)\?`)

// quotedNameRe pulls each individually quoted name out of the "Did you mean"
// capture, since graphql-js lists 1-5 suggestions as `"a"`, `"a" or "b"`, or
// `"a", "b", or "c"`.
var quotedNameRe = regexp.MustCompile(`"([^"]+)"`)

// SuggestionProbe builds a minimal query naming the given field. The caller
// supplies a field name expected to be absent or misspelled (a deliberate typo of
// a real field, or a field like __type that graphql-js will reject for missing
// subfield selection per Zbop's own literal probe) — this only wraps it in the
// smallest syntactically valid query body, `query{fieldName}`.
func SuggestionProbe(fieldName string) string {
	return "query{" + fieldName + "}"
}

// ExtractSuggestions parses every "Did you mean ...?" field-suggestion list out
// of a GraphQL error response's errors[].message array and returns the flattened,
// order-preserved list of suggested names. Returns nil if the body is not
// GraphQL-shaped or contains no such phrasing.
func ExtractSuggestions(body []byte) []string {
	var env struct {
		Errors []rawGraphQLError `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	var suggestions []string
	for _, e := range env.Errors {
		m := didYouMeanRe.FindStringSubmatch(e.Message)
		if m == nil {
			continue
		}
		for _, q := range quotedNameRe.FindAllStringSubmatch(m[1], -1) {
			suggestions = append(suggestions, q[1])
		}
	}
	return suggestions
}

// ---------------------------------------------------------------------------
// Content-type validation probes
// ---------------------------------------------------------------------------

// ContentTypeProbes returns the probe matrix for "GraphQL content type not
// validated" (2098452, burp.Zx85): one control request using the correct
// Content-Type, plus three variants a spec-compliant GraphQL server should
// reject outright — form-encoded, text/plain, and no Content-Type header at all.
// A server that answers any of the three risky variants with a real GraphQL
// result (see IsGraphQLResponse) is not validating Content-Type before parsing
// the body, which is exactly what makes CSRF-via-GraphQL possible: a browser
// form POST or no-cors fetch can only send those three content types, never
// application/json, so accepting them removes the browser's same-origin
// preflight protection.
//
// The probe body and query, `query{__typename}`, reuse burp.Zmzj's own recovered
// literal (graphQLIntrospectionQuery, defined in checks_discovery.go) rather than
// redefining it; Zx85's own literal evidence contributes no probe body beyond
// that shared one (see file header).
func ContentTypeProbes() []struct{ ContentType, Body string } {
	jsonBody := `{"query":"` + graphQLIntrospectionQuery + `"}`
	return []struct{ ContentType, Body string }{
		{ContentType: graphQLContentType, Body: jsonBody},
		{ContentType: "application/x-www-form-urlencoded", Body: "query=" + graphQLIntrospectionQuery},
		{ContentType: "text/plain", Body: jsonBody},
		{ContentType: "", Body: jsonBody},
	}
}

// ---------------------------------------------------------------------------
// Response classification
// ---------------------------------------------------------------------------

// IsGraphQLResponse reports whether body is a JSON object carrying a top-level
// "data" or "errors" key — the minimal shape every GraphQL response has per the
// GraphQL-over-HTTP spec, regardless of whether the query succeeded. Used by
// ContentTypeProbes' caller to tell "the server parsed this as GraphQL" apart
// from "the server returned its normal non-GraphQL response" (an HTML error
// page, a REST 404, ...).
func IsGraphQLResponse(body []byte) bool {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	_, hasData := env["data"]
	_, hasErrors := env["errors"]
	return hasData || hasErrors
}
