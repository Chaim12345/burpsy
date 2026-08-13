package scanner

import (
	"errors"
	"strings"
	"testing"
)

// realIntrospectionResponse is a realistic (hand-built, structurally accurate)
// GraphQL introspection response: a Query type with a non-null-wrapped and a
// list-wrapped field (exercising ofType resolution), a Mutation type with two
// operations, a leaf User type, and three directives.
const realIntrospectionResponse = `{
	"data": {
		"__schema": {
			"queryType": {"name": "Query"},
			"mutationType": {"name": "Mutation"},
			"types": [
				{
					"name": "Query",
					"kind": "OBJECT",
					"fields": [
						{"name": "user", "args": [{"name": "id"}], "type": {"name": null, "kind": "NON_NULL", "ofType": {"name": "User", "kind": "OBJECT"}}},
						{"name": "users", "args": [], "type": {"name": null, "kind": "LIST", "ofType": {"name": "User", "kind": "OBJECT"}}}
					]
				},
				{
					"name": "Mutation",
					"kind": "OBJECT",
					"fields": [
						{"name": "createUser", "args": [{"name": "input"}], "type": {"name": "User", "kind": "OBJECT"}},
						{"name": "deleteUser", "args": [{"name": "id"}], "type": {"name": "Boolean", "kind": "SCALAR"}}
					]
				},
				{
					"name": "User",
					"kind": "OBJECT",
					"fields": [
						{"name": "id", "args": [], "type": {"name": "ID", "kind": "SCALAR"}},
						{"name": "name", "args": [], "type": {"name": "String", "kind": "SCALAR"}}
					]
				}
			],
			"directives": [{"name": "skip"}, {"name": "include"}, {"name": "deprecated"}]
		}
	}
}`

// TestParseIntrospectionResponseFlattensTypesFieldsAndDirectiveCounts asserts a
// stubbed-to-no-op parser (returning a zero Schema) would be caught: the schema
// must report the exact type/field/directive counts and operation names present
// in the fixture, not just "parsed without error".
func TestParseIntrospectionResponseFlattensTypesFieldsAndDirectiveCounts(t *testing.T) {
	schema, err := ParseIntrospectionResponse([]byte(realIntrospectionResponse))
	if err != nil {
		t.Fatalf("ParseIntrospectionResponse returned an error on a well-formed response: %v", err)
	}
	if schema.QueryType != "Query" {
		t.Errorf("QueryType = %q, want %q", schema.QueryType, "Query")
	}
	if schema.MutationType != "Mutation" {
		t.Errorf("MutationType = %q, want %q", schema.MutationType, "Mutation")
	}
	if len(schema.Types) != 3 {
		t.Fatalf("got %d types, want 3 (Query, Mutation, User)", len(schema.Types))
	}
	if got := schema.FieldCount(); got != 6 {
		t.Errorf("FieldCount() = %d, want 6 (2 Query + 2 Mutation + 2 User fields)", got)
	}
	if len(schema.Directives) != 3 {
		t.Errorf("got %d directives, want 3", len(schema.Directives))
	}

	mutations := schema.MutationNames()
	want := []string{"createUser", "deleteUser"}
	if len(mutations) != len(want) {
		t.Fatalf("MutationNames() = %v, want %v", mutations, want)
	}
	for i, name := range want {
		if mutations[i] != name {
			t.Errorf("MutationNames()[%d] = %q, want %q", i, mutations[i], name)
		}
	}
}

// TestParseIntrospectionResponseResolvesWrappedTypeNamesThroughOfType asserts that
// a field wrapped in NON_NULL or LIST (whose own "name" is null per the
// introspection spec) resolves to the real type name one level down in ofType,
// not to an empty string — an implementation that only reads the top-level name
// would silently lose the type of every non-null/list field, which is most fields
// in a real schema.
func TestParseIntrospectionResponseResolvesWrappedTypeNamesThroughOfType(t *testing.T) {
	schema, err := ParseIntrospectionResponse([]byte(realIntrospectionResponse))
	if err != nil {
		t.Fatalf("ParseIntrospectionResponse returned an error: %v", err)
	}
	var queryType *SchemaType
	for i := range schema.Types {
		if schema.Types[i].Name == "Query" {
			queryType = &schema.Types[i]
		}
	}
	if queryType == nil {
		t.Fatal("Query type missing from parsed schema")
	}
	got := map[string]string{}
	for _, f := range queryType.Fields {
		got[f.Name] = f.TypeName
	}
	if got["user"] != "User" {
		t.Errorf("field \"user\" (NON_NULL-wrapped) TypeName = %q, want %q", got["user"], "User")
	}
	if got["users"] != "User" {
		t.Errorf("field \"users\" (LIST-wrapped) TypeName = %q, want %q", got["users"], "User")
	}
}

// TestParseIntrospectionResponseReportsErrorsOnlyBodyAsDisabledNotAParseFailure
// asserts that a response carrying only an "errors" array (the shape a server
// sends when it refuses to introspect) is reported through the distinguishable
// ErrIntrospectionDisabled sentinel, not folded into the same generic error a
// caller would get from truly malformed JSON — collapsing the two would make
// "introspection is disabled" indistinguishable from "we don't understand this
// response at all", which is a different, unrelated fact.
func TestParseIntrospectionResponseReportsErrorsOnlyBodyAsDisabledNotAParseFailure(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Introspection is not allowed, but the query contained __schema"}]}`)

	schema, err := ParseIntrospectionResponse(body)
	if err == nil {
		t.Fatal("ParseIntrospectionResponse returned no error for an errors-only body; disabled introspection must be reported as an error state")
	}
	if !errors.Is(err, ErrIntrospectionDisabled) {
		t.Errorf("err = %v, want errors.Is(err, ErrIntrospectionDisabled) to be true", err)
	}
	if schema.FieldCount() != 0 {
		t.Errorf("got a non-empty schema (%d fields) alongside the disabled error; disabled means no schema was returned", schema.FieldCount())
	}

	if IntrospectionEnabled(body) {
		t.Error("IntrospectionEnabled(body) = true for an errors-only body")
	}
	reason := IntrospectionDisabledReason(body)
	if reason == "" {
		t.Fatal("IntrospectionDisabledReason returned empty for a genuinely disabled response; the server's own message must be surfaced")
	}
	if !strings.Contains(reason, "Introspection is not allowed") {
		t.Errorf("reason = %q, want it to contain the server's own error message", reason)
	}
}

// TestParseIntrospectionResponseDistinguishesGenuinelyMalformedBodyFromDisabled
// asserts that a body which is neither valid GraphQL-shaped JSON nor a
// data/__schema response does NOT get mistaken for ErrIntrospectionDisabled — a
// truly unparseable body (e.g. an HTML error page returned by a misrouted probe)
// carries no server-authored "disabled" signal at all, and IntrospectionDisabledReason
// must not fabricate one.
func TestParseIntrospectionResponseDistinguishesGenuinelyMalformedBodyFromDisabled(t *testing.T) {
	body := []byte(`<html><body>502 Bad Gateway</body></html>`)

	_, err := ParseIntrospectionResponse(body)
	if err == nil {
		t.Fatal("ParseIntrospectionResponse returned no error for an HTML body")
	}
	if errors.Is(err, ErrIntrospectionDisabled) {
		t.Error("a non-JSON body was reported as ErrIntrospectionDisabled; it carries no server-authored disabled signal, it is just unparseable")
	}
	if reason := IntrospectionDisabledReason(body); reason != "" {
		t.Errorf("IntrospectionDisabledReason(body) = %q, want empty for an unparseable body", reason)
	}
}

// TestExtractSuggestionsPullsTwoNamesOutOfARealGraphqlJsMessage asserts the parser
// handles graphql-js's actual multi-suggestion phrasing (a comma/or-joined quoted
// list), not just a single-suggestion toy case — the real signal this check
// leans on is exactly this "Cannot query field ... Did you mean ...?" message.
func TestExtractSuggestionsPullsTwoNamesOutOfARealGraphqlJsMessage(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Cannot query field \"usr\" on type \"Query\". Did you mean \"user\" or \"users\"?"}]}`)

	got := ExtractSuggestions(body)
	want := []string{"user", "users"}
	if len(got) != len(want) {
		t.Fatalf("ExtractSuggestions(body) = %v, want %v", got, want)
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("ExtractSuggestions(body)[%d] = %q, want %q", i, got[i], name)
		}
	}
}

// TestExtractSuggestionsMatchesZbopsOwnRecoveredConfirmationSubstring asserts the
// general "Did you mean" pattern also matches burp.Zbop's own genuinely recovered
// confirmation literal ("must have a selection of subfields. Did you mean"),
// proving the general extractor subsumes the specific real-world Burp check it
// backs rather than only handling the toy misspelled-field case.
func TestExtractSuggestionsMatchesZbopsOwnRecoveredConfirmationSubstring(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Field \"__type\" of type \"__Type\" must have a selection of subfields. Did you mean \"__typename\"?"}]}`)

	got := ExtractSuggestions(body)
	if len(got) != 1 || got[0] != "__typename" {
		t.Errorf("ExtractSuggestions(body) = %v, want [\"__typename\"]", got)
	}
}

// TestExtractSuggestionsReturnsNilWithoutDidYouMeanPhrasing asserts an unrelated
// GraphQL error (no field-suggestion signal at all) yields no suggestions, so a
// stubbed implementation that always returns some fixed slice would be caught.
func TestExtractSuggestionsReturnsNilWithoutDidYouMeanPhrasing(t *testing.T) {
	body := []byte(`{"errors":[{"message":"Syntax Error: Unexpected Name \"query\""}]}`)
	if got := ExtractSuggestions(body); len(got) != 0 {
		t.Errorf("ExtractSuggestions(body) = %v, want none (message has no \"Did you mean\" phrasing)", got)
	}
}

// TestSuggestionProbeNamesTheGivenFieldInAMinimalQuery asserts the probe body
// actually names the caller-supplied field, since a stubbed implementation
// returning a fixed query string would silently probe the wrong field on every
// call.
func TestSuggestionProbeNamesTheGivenFieldInAMinimalQuery(t *testing.T) {
	got := SuggestionProbe("usr")
	if !strings.Contains(got, "usr") {
		t.Errorf("SuggestionProbe(%q) = %q, does not contain the field name", "usr", got)
	}
	if got != "query{usr}" {
		t.Errorf("SuggestionProbe(%q) = %q, want %q", "usr", got, "query{usr}")
	}
}

// TestContentTypeProbesReturnsAtLeastFourDistinctVariantsIncludingNoContentType
// asserts the probe matrix has the control (application/json) plus the three
// risky non-JSON variants a spec-compliant server should reject, including the
// no-Content-Type-header case — a matrix missing that case would leave the
// content-type-not-validated check blind to the one variant a bare, header-free
// fetch() or curl actually sends.
func TestContentTypeProbesReturnsAtLeastFourDistinctVariantsIncludingNoContentType(t *testing.T) {
	probes := ContentTypeProbes()
	if len(probes) < 4 {
		t.Fatalf("ContentTypeProbes() returned %d probes, want at least 4", len(probes))
	}

	seen := map[string]bool{}
	sawNoContentType := false
	sawJSON := false
	for _, p := range probes {
		if seen[p.ContentType] {
			t.Errorf("Content-Type %q appears more than once; the matrix must not collapse variants", p.ContentType)
		}
		seen[p.ContentType] = true
		if p.Body == "" {
			t.Errorf("probe with Content-Type %q has an empty body", p.ContentType)
		}
		if p.ContentType == "" {
			sawNoContentType = true
		}
		if p.ContentType == graphQLContentType {
			sawJSON = true
		}
	}
	if len(seen) != len(probes) {
		t.Errorf("got %d distinct Content-Type values across %d probes, want them equal (no duplicates)", len(seen), len(probes))
	}
	if !sawNoContentType {
		t.Error("ContentTypeProbes() is missing the no-Content-Type-header variant (empty ContentType)")
	}
	if !sawJSON {
		t.Errorf("ContentTypeProbes() is missing the application/json control variant (%q)", graphQLContentType)
	}
}

// TestIsGraphQLResponseTrueForDataAndErrorsShapedBodies asserts both legitimate
// top-level GraphQL response shapes (a successful "data" body and an "errors"
// body) are recognised, since a real server can answer either depending on the
// probe.
func TestIsGraphQLResponseTrueForDataAndErrorsShapedBodies(t *testing.T) {
	if !IsGraphQLResponse([]byte(`{"data":{"__typename":"Query"}}`)) {
		t.Error("IsGraphQLResponse false for a data-shaped body")
	}
	if !IsGraphQLResponse([]byte(`{"errors":[{"message":"boom"}]}`)) {
		t.Error("IsGraphQLResponse false for an errors-shaped body")
	}
}

// TestIsGraphQLResponseFalseForPlainHTML asserts an ordinary non-GraphQL HTML
// response (what a content-type probe gets back from a server that correctly
// rejected the request before reaching the GraphQL layer) is not mistaken for a
// GraphQL response — this is exactly the negative signal ContentTypeProbes'
// caller relies on to prove content-type validation is absent only when the
// non-JSON variant DID get a real GraphQL answer.
func TestIsGraphQLResponseFalseForPlainHTML(t *testing.T) {
	html := []byte("<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>")
	if IsGraphQLResponse(html) {
		t.Error("IsGraphQLResponse true for a plain HTML body")
	}
}

// TestIsGraphQLResponseFalseForJSONWithoutDataOrErrorsKeys asserts an arbitrary
// JSON object that merely happens to parse (e.g. an unrelated REST payload) is
// not treated as a GraphQL response just because it is valid JSON — only the
// presence of a top-level "data" or "errors" key is the GraphQL-over-HTTP
// signal, not JSON-ness alone.
func TestIsGraphQLResponseFalseForJSONWithoutDataOrErrorsKeys(t *testing.T) {
	if IsGraphQLResponse([]byte(`{"status":"ok","id":42}`)) {
		t.Error("IsGraphQLResponse true for JSON lacking both \"data\" and \"errors\" keys")
	}
}

// TestFullIntrospectionQueryNamesTheDocumentedIntrospectionFields asserts the
// returned document actually requests the fields the task specifies
// (__schema, queryType, types with fields/args/type/ofType, and directives),
// so a stubbed implementation returning an unrelated or empty string is caught.
func TestFullIntrospectionQueryNamesTheDocumentedIntrospectionFields(t *testing.T) {
	q := FullIntrospectionQuery()
	for _, want := range []string{"__schema", "queryType", "types", "fields", "args", "ofType", "directives"} {
		if !strings.Contains(q, want) {
			t.Errorf("FullIntrospectionQuery() = %q, missing %q", q, want)
		}
	}
}
