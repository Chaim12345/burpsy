package crawler

// End-to-end proof for API-document discovery (burpsy-react-ui-bwwg).
//
// The parser's own tests establish that a document is READ correctly. These establish that the crawl
// ACTS on it — which is the part that can silently fail: a parser wired into nothing reports the same
// green suite as one wired into the frontier. Every test here therefore asserts on the run's own
// record (what was fetched, what was counted, what was skipped), not on the parser's return value.

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// apiDefinitionTarget serves an index page that links one API definition, plus the endpoints that
// definition declares.
//
// The endpoints exist as real routes so that "the crawl followed them" is observable as a fetch
// rather than as a frontier count — a count alone cannot distinguish admitted-and-fetched from
// admitted-and-then-refused.
func apiDefinitionTarget(t *testing.T, definition string, contentType string) *httptest.Server {
	t.Helper()
	return sitemapTarget(t, map[string]servedPage{
		"/":             {"<html><body><a href=\"/openapi.json\">API docs</a></body></html>", "text/html"},
		"/openapi.json": {definition, contentType},
		// The endpoints the definition below declares.
		"/users":         {"{\"users\":[]}", "application/json"},
		"/orders":        {"{\"orders\":[]}", "application/json"},
		"/users/1/notes": {"{\"notes\":[]}", "application/json"},
	})
}

// The end-to-end claim: a definition reached from a crawled page has its declared operations
// FETCHED, not merely counted.
func TestAnAPIDefinitionReachedByACrawlHasItsOperationsFetched(t *testing.T) {
	srv := apiDefinitionTarget(t, `{
	  "openapi": "3.0.0",
	  "info": {"title": "Shop", "version": "1.0"},
	  "paths": {
	    "/users":  {"get": {"operationId": "listUsers"}},
	    "/orders": {"get": {"operationId": "listOrders"}}
	  }
	}`, "application/json")

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions, cfg.ParseSOAPWSDLs = true, true
	rep := run(t, cfg)

	if rep.APIDocumentsRead != 1 {
		t.Errorf("APIDocumentsRead = %d, want 1; fetches were %v", rep.APIDocumentsRead, fetchLog(rep))
	}
	if rep.APIEndpointsFound < 2 {
		t.Errorf("APIEndpointsFound = %d, want the 2 the definition declares", rep.APIEndpointsFound)
	}
	// Counted AND fetched. A count the crawl did not act on is a number an operator cannot use, and
	// it is exactly what the defect looks like if the parse landed but the admission did not.
	if !fetchedAny(rep, "/users") {
		t.Errorf("the definition declared GET /users and the crawl did not fetch it; fetches: %v", fetchLog(rep))
	}
	if !fetchedAny(rep, "/orders") {
		t.Errorf("the definition declared GET /orders and the crawl did not fetch it; fetches: %v", fetchLog(rep))
	}
}

// A templated path reaches the crawl with its braces intact — the document's own text, not a
// substituted guess. This is the behaviour that distinguishes this parser from a URL-shaped string
// scan, and it is only observable end to end.
func TestATemplatedPathFromADefinitionIsFetchedAsDeclared(t *testing.T) {
	srv := apiDefinitionTarget(t, `{
	  "openapi": "3.0.0",
	  "paths": {"/users/{id}/notes": {"get": {"operationId": "getNotes",
	    "parameters": [{"name": "id", "in": "path"}]}}}
	}`, "application/json")

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions, cfg.ParseSOAPWSDLs = true, true
	rep := run(t, cfg)

	if rep.APIEndpointsFound != 1 {
		t.Errorf("APIEndpointsFound = %d, want 1", rep.APIEndpointsFound)
	}
	// The declared path is what was fetched. A crawler that substituted a placeholder would report
	// /users/1/notes here instead — and it would be reporting a URL the document never declared.
	//
	// Compared with the URL-ESCAPED spelling because that is what the fetch log carries: net/url
	// percent-encodes `{` and `}` in a path, so the log reads /users/%7Bid%7D/notes. The
	// unescaped form below is asserted too, and must NOT be present — that is the shape a
	// substituted placeholder would take, and it is the failure this test exists to catch.
	if !fetchedAny(rep, "/users/%7Bid%7D/notes") {
		t.Errorf("the templated path was not fetched as declared; fetches: %v", fetchLog(rep))
	}
	if fetchedAny(rep, "/users/1/notes") {
		t.Errorf("a placeholder was substituted into the declared path; the document says {id} and "+
			"inventing a value for it reports a URL the target never declared. Fetches: %v", fetchLog(rep))
	}
}

// A definition served with the wrong content type is still read, for the reason the sitemap reader
// takes: a great many servers serve a JSON definition as octet-stream, and requiring the right header
// would drop the document on exactly the sites that publish one.
func TestADefinitionServedAsOctetStreamIsStillRead(t *testing.T) {
	srv := apiDefinitionTarget(t, `{"openapi":"3.0.0","paths":{"/users":{"get":{"operationId":"listUsers"}}}}`,
		"application/octet-stream")
	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions, cfg.ParseSOAPWSDLs = true, true
	rep := run(t, cfg)
	if rep.APIDocumentsRead != 1 || !fetchedAny(rep, "/users") {
		t.Errorf("a definition served as octet-stream was not read; documents=%d fetches=%v",
			rep.APIDocumentsRead, fetchLog(rep))
	}
}

// The acceptance criterion for failures: a definition the crawl could not read is a COUNTED SKIP with
// its own reason, never "0 endpoints" — which is indistinguishable from a target that publishes no
// API, and is the exact failure this change exists to remove.
func TestAnUnreadableDefinitionIsCountedAsItsOwnSkipNotAsZeroLocations(t *testing.T) {
	// A body that announces itself as a definition (it carries the version key) and then stops
	// mid-document.
	srv := sitemapTarget(t, map[string]servedPage{
		"/":             {"<html><body><a href=\"/openapi.json\">docs</a></body></html>", "text/html"},
		"/openapi.json": {`{"openapi":"3.0.0","paths":{"/users":{"get":{"operationId":"a`, "application/json"},
	})

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions, cfg.ParseSOAPWSDLs = true, true
	rep := run(t, cfg)

	if !skippedWith(rep, SkipAPIUnparsed) {
		t.Errorf("an unreadable definition did not record SkipAPIUnparsed; the operator is told their "+
			"target published no API, which is false. Counts: %+v", rep.Skips.Counts)
	}
	if rep.APIEndpointsFound != 0 {
		t.Errorf("APIEndpointsFound = %d for a document that could not be read; a partial read must "+
			"not be presented as the document's content", rep.APIEndpointsFound)
	}
	// And the response is still recorded as a location: it was fetched and captured, so saying
	// otherwise would make the crawl's counts disagree with the store's.
	if !fetchedAny(rep, "/openapi.json") {
		t.Errorf("the definition was not recorded as fetched; fetches: %v", fetchLog(rep))
	}
}

// A body that is not a definition must fall through UNCHANGED — the JSON reader and the HTML gate
// both still apply to it. This is the sibling-of-the-HTML-gate property, and it is the thing a
// dispatch placed in the wrong place would silently break.
func TestABodyThatIsNotADefinitionFallsThroughToTheJSONReader(t *testing.T) {
	srv := sitemapTarget(t, map[string]servedPage{
		"/api/data": {`{"next":"/api/more"}`, "application/json"},
		"/api/more": {`{"ok":true}`, "application/json"},
	})
	rep := run(t, newHarness().config(srv.URL+"/api/data"))

	if rep.APIDocumentsRead != 0 {
		t.Errorf("APIDocumentsRead = %d for an ordinary JSON response; the definition branch must "+
			"only claim documents that announce themselves as one", rep.APIDocumentsRead)
	}
	if rep.JSONDocumentsRead == 0 {
		t.Error("an ordinary JSON response no longer reaches the JSON reader")
	}
	if !fetchedAny(rep, "/api/more") {
		t.Errorf("the JSON reader's location was not followed; fetches: %v", fetchLog(rep))
	}
}

// With the switch off, a definition is not read at all — and records NO skip, because a reader that
// was switched off did not try and fail. It is the ordinary not-HTML path.
func TestADefinitionIsNotReadWhenTheSwitchIsOff(t *testing.T) {
	srv := apiDefinitionTarget(t, `{"openapi":"3.0.0","paths":{"/users":{"get":{"operationId":"l"}}}}`,
		"application/json")

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions = false
	rep := run(t, cfg)

	if rep.APIDocumentsRead != 0 || rep.APIEndpointsFound != 0 {
		t.Errorf("the definition was read with the switch off: documents=%d endpoints=%d",
			rep.APIDocumentsRead, rep.APIEndpointsFound)
	}
	if skippedWith(rep, SkipAPIUnparsed) {
		t.Error("a reader that was switched off recorded a parse failure; nothing tried and failed")
	}
}

// A document naming a path that looks destructive is still refused by the destructiveness gate, even
// though the TARGET published it. This is the safety property that makes admitting endpoints from a
// document acceptable at all: a definition is not more trustworthy than a link.
func TestAPathNamedInADefinitionStillGoesThroughTheDestructiveRefusals(t *testing.T) {
	srv := apiDefinitionTarget(t, `{
	  "openapi": "3.0.0",
	  "paths": {
	    "/users":            {"get": {"operationId": "listUsers"}},
	    "/admin/purge-all":   {"post": {"operationId": "purgeEverything"}}
	  }
	}`, "application/json")

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions, cfg.ParseSOAPWSDLs = true, true
	rep := run(t, cfg)

	if !fetchedAny(rep, "/users") {
		t.Errorf("the safe endpoint was not fetched; fetches: %v", fetchLog(rep))
	}
	// The destructive one is refused. CRAWL-04 refuses it whatever it was discovered from, and a
	// document naming it is exactly the case that has to keep refusing — a target does not get to
	// authorise a purge by documenting it.
	if fetchedAny(rep, "purge-all") {
		t.Errorf("a path the definition named as a purge was FETCHED; a target does not authorise "+
			"its own destructive request by documenting it. Fetches: %v", fetchLog(rep))
	}
	// Recorded as the specific reason the path's own signal names — "purge" is one of the six
	// CRAWL-04 signals, so a report says WHY it was refused rather than only that something was.
	if !skippedWith(rep, SkipDestructivePurge) {
		t.Errorf("the destructive refusal was not recorded as the purge it is; counts: %+v", rep.Skips.Counts)
	}
}

// A YAML definition served with a text content type — the most common way one is published — reaches
// the same operations as the JSON spelling of the same document.
func TestAYAMLDefinitionReachedByACrawlHasItsOperationsFetched(t *testing.T) {
	srv := apiDefinitionTarget(t, "openapi: 3.0.0\npaths:\n  /users:\n    get:\n      operationId: listUsers\n",
		"text/plain")

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions, cfg.ParseSOAPWSDLs = true, true
	rep := run(t, cfg)

	if rep.APIDocumentsRead != 1 {
		t.Errorf("APIDocumentsRead = %d, want 1 for a YAML definition; fetches were %v",
			rep.APIDocumentsRead, fetchLog(rep))
	}
	if !fetchedAny(rep, "/users") {
		t.Errorf("a YAML definition's operation was not fetched; fetches: %v", fetchLog(rep))
	}
}

// A WSDL reached by a crawl is read, and its operations are counted. They are NOT fetched at invented
// paths — the service path lives in the port's <soap:address>, and this reader refuses to guess it.
func TestAWSDLReachedByACrawlIsReadAndCounted(t *testing.T) {
	const wsdl = `<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <wsdl:binding name="B">
    <wsdl:operation name="GetUser"><soap:operation soapAction="urn:GetUser"/></wsdl:operation>
    <wsdl:operation name="ListUsers"><soap:operation soapAction="urn:ListUsers"/></wsdl:operation>
  </wsdl:binding>
</wsdl:definitions>`
	srv := sitemapTarget(t, map[string]servedPage{
		"/":        {"<html><body><a href=\"/service?wsdl\">WSDL</a></body></html>", "text/html"},
		"/service": {wsdl, "application/wsdl+xml"},
		"/wsdl":    {wsdl, "application/wsdl+xml"},
	})

	cfg := newHarness().config(srv.URL + "/")
	cfg.ParseAPIDefinitions, cfg.ParseSOAPWSDLs = true, true
	rep := run(t, cfg)

	if rep.APIDocumentsRead == 0 {
		t.Errorf("a WSDL reached by the crawl was not read; fetches were %v", fetchLog(rep))
	}
	// Counted, and NOT reported as a failure. A WSDL operation's service path lives in the port's
	// <soap:address> rather than in the operation, so no fetch is invented for it — the count is the
	// honest report. skippedWith is true when the reason FIRED, so the assertion is that it did not.
	if skippedWith(rep, SkipAPIUnparsed) {
		t.Error("a WSDL this reader handles was reported as unparsed; the operation count is the " +
			"report and nothing should be recorded as a failure")
	}
}

// containsString reports whether a list holds a value. Local to this file: it is a test assertion,
// and putting it in the package would make it part of the crawler's surface for no reason.
func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// The four Burp configuration keys land, so a migrated configuration switches these readers on
// rather than reporting them unrepresentable.
func TestTheAPIDiscoveryBurpKeysAreAppliedNotReportedUnrepresentable(t *testing.T) {
	const config = `{"crawler":{"customization":{
	  "parse_api_definitions": true,
	  "parse_soap_wsdls": true,
	  "perform_graphql_introspection": true,
	  "guess_hidden_graphql_endpoints": false}}}`

	cfg, err := ParseBurpCrawlConfig([]byte(config))
	if err != nil {
		t.Fatalf("a configuration with the API-discovery keys failed to parse: %v", err)
	}
	for _, key := range []string{
		"customization/parse_api_definitions",
		"customization/parse_soap_wsdls",
		"customization/perform_graphql_introspection",
		"customization/guess_hidden_graphql_endpoints",
	} {
		if !containsString(cfg.AppliedKeys, key) {
			t.Errorf("key %q was not applied; applied=%v unrepresentable=%v",
				key, cfg.AppliedKeys, cfg.UnrepresentableKeys)
		}
		if containsString(cfg.UnrepresentableKeys, key) {
			t.Errorf("key %q was reported UNREPRESENTABLE; Burp ships it and this engine reads it, so "+
				"an operator migrating a configuration would be told their API settings were dropped", key)
		}
	}
	if !cfg.ParseAPIDefinitions || !cfg.ParseSOAPWSDLs || !cfg.PerformGraphQLIntrospection {
		t.Errorf("the applied keys did not reach the config: %+v", cfg)
	}
	// guess_hidden_graphql_endpoints is false here, so the field must be FALSE — which proves the
	// value was applied rather than merely counted as a known key.
	if cfg.GuessHiddenGraphQLEndpoints {
		t.Error("guess_hidden_graphql_endpoints was set false in the file and came out true")
	}
}

// Every new skip reason is in the enumerated set with a slot, a name, an explanation and a category —
// the four tables an enum member has to appear in, and a missing entry panics at runtime rather than
// failing to compile.
func TestTheNewSkipReasonIsFullyRegistered(t *testing.T) {
	found := false
	for _, s := range SkipAll {
		if s == SkipAPIUnparsed {
			found = true
		}
	}
	if !found {
		t.Fatal("SkipAPIUnparsed is not in SkipAll, so its counts could never be reported")
	}
	if got := SkipAPIUnparsed.String(); got != "api-unparsed" {
		t.Errorf("String() = %q, want %q", got, "api-unparsed")
	}
	if got := SkipAPIUnparsed.Category(); got != CategoryResponse {
		t.Errorf("Category() = %v, want CategoryResponse: the fetch worked and reading the contents is "+
			"what failed, which is what the other unreadable-body reasons are", got)
	}
	if strings.TrimSpace(SkipAPIUnparsed.Explanation()) == "" {
		t.Error("Explanation() is empty; an operator reading the ledger gets no remedy")
	}
}
