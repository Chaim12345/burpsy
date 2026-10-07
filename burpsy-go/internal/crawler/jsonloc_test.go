package crawler

import (
	"strings"
	"testing"
)

// JSON location extraction (burpsy-react-ui-mz1n).
//
// The claim to defend is narrow and testable: a JSON document that names its own endpoints
// contributes those locations to the crawl, and a JSON document that does not name any
// contributes NOTHING — because a crawler that reads arbitrary strings as paths invents URLs
// nobody observed, which is worse than finding nothing.

// --- the parser ---------------------------------------------------------------------------

func TestAJSONDocumentYieldsTheLocationsItNames(t *testing.T) {
	body := []byte(`{
	  "users": "/api/users",
	  "next": "https://api.test/v2/users?page=2",
	  "links": {"self": "/api/v2/self", "href": "docs/index.html"},
	  "count": 42,
	  "enabled": true
	}`)
	locs, failure := ParseJSONLocations(body)
	if failure != "" {
		t.Fatalf("a well-formed document reported a failure: %s", failure)
	}
	got := map[string]bool{}
	for _, l := range locs {
		got[l.Raw] = true
	}
	for _, want := range []string{"/api/users", "https://api.test/v2/users?page=2", "/api/v2/self", "docs/index.html"} {
		if !got[want] {
			t.Errorf("%q was not read as a location; the document names it plainly and a JSON API "+
				"that documents its own endpoints is exactly what this must find", want)
		}
	}
	if got["42"] || got["true"] {
		t.Error("a number or a boolean became a location; only strings can be URLs")
	}
}

func TestABareWordIsNotALocation(t *testing.T) {
	// The refusal that matters most. `{"name": "users"}` is data, not a path: treating it as one
	// would fetch /users on every crawl that touched this API, a URL nobody observed.
	body := []byte(`{"name": "users", "description": "the users collection", "version": "v2"}`)
	locs, failure := ParseJSONLocations(body)
	if failure != "" {
		t.Fatalf("unexpected failure: %s", failure)
	}
	if len(locs) != 0 {
		t.Errorf("a document of plain strings yielded %d location(s) (%v); none of these values is a "+
			"URL or a path, and inventing one is how a crawler fabricates requests", len(locs), locs)
	}
}

func TestARelativeReferenceIsALocationOnlyUnderALinkKey(t *testing.T) {
	// The key name is the only signal a bare relative reference carries. Same value, two keys.
	link := []byte(`{"next": "page/2"}`)
	if locs, _ := ParseJSONLocations(link); len(locs) != 1 {
		t.Errorf("a relative reference under the key \"next\" was not read as a location; "+
			"`next` names a link by any reading (got %v)", locs)
	}
	data := []byte(`{"label": "page/2"}`)
	if locs, _ := ParseJSONLocations(data); len(locs) != 0 {
		t.Errorf("a relative reference under the key \"label\" became a location (%v); the key does "+
			"not name a link, so this is data and not a place to fetch", locs)
	}
}

func TestTemplateSyntaxIsNotALocation(t *testing.T) {
	// "/api/{id}" and "/api/${id}" name an endpoint SHAPE. Fetching either produces a 404 for a
	// URL the server never published, and the crawler would report it as a real location.
	body := []byte(`{"users": "/api/{id}", "orders": "/api/${orderId}", "docs": "/api/<v>/docs"}`)
	locs, failure := ParseJSONLocations(body)
	if failure != "" {
		t.Fatalf("unexpected failure: %s", failure)
	}
	if len(locs) != 0 {
		t.Errorf("%d templated path(s) became locations (%v); a template is not a fetchable URL", len(locs), locs)
	}
}

func TestANonJSONDocumentReportsWhy(t *testing.T) {
	_, failure := ParseJSONLocations([]byte(`<html><body>not json</body></html>`))
	if failure == "" {
		t.Error("an HTML body reported success as JSON; the branch that calls this must be able to " +
			"tell an operator their /api endpoint returned markup rather than silence")
	}
}

func TestTheDocumentBoundsAreHonoured(t *testing.T) {
	// Depth: a deeply nested document is bounded rather than recursed into.
	deep := strings.Repeat(`{"a":`, jsonMaxDepth+10) + `"/x"` + strings.Repeat("}", jsonMaxDepth+10)
	if _, failure := ParseJSONLocations([]byte(deep)); failure != "" {
		t.Errorf("a deep but valid document reported a failure (%s); it must be bounded, not refused", failure)
	}
	// Count: a huge array of URLs cannot contribute unbounded locations.
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < jsonMaxLocations+50; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"/p/` + itoa(i) + `"`)
	}
	b.WriteString("]")
	locs, _ := ParseJSONLocations([]byte(b.String()))
	if len(locs) > jsonMaxLocations {
		t.Errorf("a document contributed %d locations, above the %d bound; one response must not be "+
			"able to dominate the frontier", len(locs), jsonMaxLocations)
	}
	// Size: an oversized document is refused, not scanned.
	big := append([]byte(`{"a": "`), make([]byte, jsonMaxBytes+1)...)
	if _, failure := ParseJSONLocations(big); failure == "" {
		t.Error("an oversized document was scanned; the size bound is what keeps a data dump from " +
			"costing the crawl unbounded time")
	}
}

func TestTheSameDocumentYieldsTheSameOrder(t *testing.T) {
	body := []byte(`{"b": "/b", "a": "/a", "c": "/c"}`)
	first, _ := ParseJSONLocations(body)
	second, _ := ParseJSONLocations(body)
	if len(first) != len(second) {
		t.Fatalf("the same document yielded %d then %d locations", len(first), len(second))
	}
	for i := range first {
		if first[i].Raw != second[i].Raw {
			t.Errorf("location %d differs between runs (%q vs %q); the order must be stable so the "+
				"caps truncate the same way every time", i, first[i].Raw, second[i].Raw)
		}
	}
}

// --- detection ----------------------------------------------------------------------------

func TestJSONIsRecognisedByTypeAndByBody(t *testing.T) {
	for _, ct := range []string{
		"application/json", "application/json; charset=utf-8", "application/vnd.api+json",
		"application/hal+json", "text/json", "application/ld+json",
	} {
		if !LooksLikeJSON(ct, nil) {
			t.Errorf("content type %q was not recognised as JSON", ct)
		}
	}
	// A body that announces itself, under a type that says nothing: APIs are served as
	// text/plain and octet-stream routinely.
	for _, ct := range []string{"", "text/plain", "application/octet-stream"} {
		if !LooksLikeJSON(ct, []byte(`  {"a": 1}`)) {
			t.Errorf("a body opening with { under content type %q was not recognised as JSON", ct)
		}
		if !LooksLikeJSON(ct, []byte(`[1,2]`)) {
			t.Errorf("a body opening with [ under content type %q was not recognised as JSON", ct)
		}
	}
	for _, ct := range []string{"application/pdf", "image/png", "text/html"} {
		if LooksLikeJSON(ct, []byte("%PDF-1.4")) {
			t.Errorf("content type %q was treated as JSON", ct)
		}
	}
}

// --- end to end ---------------------------------------------------------------------------

// The claim the bead makes: a documented API reachable from the crawled HTML contributes
// locations. /index.html links to /api/index.json, which names two more pages.
func TestALinkedJSONDocumentContributesItsLocations(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":               {`<html><body><a href="/api/index.json">api</a></body></html>`, "text/html"},
			"/api/index.json": {`{"users": "` + base + `/api/users", "health": "/health"}`, "application/json"},
			"/api/users":      {`{"ok": true}`, "application/json"},
			"/health":         {`ok`, "text/plain"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !fetchedAny(rep, "/api/users") {
		t.Errorf("the location a JSON document named was not fetched; the API documented its own "+
			"endpoints and the crawl ignored them (fetched: %v)", fetchLog(rep))
	}
	if !fetchedAny(rep, "/health") {
		t.Errorf("/health was not fetched; it is a slash-rooted path in the JSON body "+
			"(fetched: %v)", fetchLog(rep))
	}
}

// A JSON response that names nothing is READ, not skipped — and the old behaviour reported it
// as SkipNotHTML, which told an operator nothing true about it.
func TestAJSONDocumentWithNoLocationsIsReadNotSkippedAsNotHTML(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":               {`<html><body><a href="/api/state.json">s</a></body></html>`, "text/html"},
			"/api/state.json": {`{"count": 3, "enabled": true}`, "application/json"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if skippedWith(rep, SkipNotHTML) {
		t.Error("a JSON document was recorded as not-HTML; it WAS read, and reporting it as " +
			"unreadable is the defect this branch exists to end")
	}
	if rep.JSONDocumentsRead == 0 {
		t.Error("no JSON document was counted as read; the report cannot say what the branch did")
	}
}

// A non-JSON, non-HTML, non-sitemap response still records SkipNotHTML exactly as before: this
// is a sibling of the gate, not a relaxation of it.
func TestAPDFIsStillSkippedAsNotHTML(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":           {`<html><body><a href="/manual.pdf">m</a></body></html>`, "text/html"},
			"/manual.pdf": {"%PDF-1.4 binary", "application/pdf"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !skippedWith(rep, SkipNotHTML) {
		t.Error("a PDF no longer records SkipNotHTML; the HTML gate must be unchanged for " +
			"everything that is neither a sitemap nor JSON")
	}
}

// A JSON body that will not parse records its OWN reason, whose remedy differs from not-HTML.
func TestUnparseableJSONIsReportedAsSuch(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":                {`<html><body><a href="/api/broken.json">b</a></body></html>`, "text/html"},
			"/api/broken.json": {`{"unterminated": `, "application/json"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !skippedWith(rep, SkipJSONUnparsed) {
		t.Error("a truncated JSON document was not recorded as unparseable JSON; an operator " +
			"seeing nothing found has no way to tell a parse failure from an empty document")
	}
}

// A JSON document's locations go through the SAME gates as any other link. The target
// publishing /logout does not make it safe to fetch.
func TestAJSONLocationIsStillDestructivenessChecked(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":               {`<html><body><a href="/api/index.json">api</a></body></html>`, "text/html"},
			"/api/index.json": {`{"logout": "/logout", "safe": "/ok"}`, "application/json"},
			"/logout":         {`bye`, "text/plain"},
			"/ok":             {`ok`, "text/plain"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	refused := false
	for _, c := range rep.Skips.Counts {
		if c.Count > 0 && c.Reason.Category() == CategoryDestructive {
			refused = true
		}
	}
	if !refused {
		t.Error("a JSON-named logout was not refused; a URL a target wrote down is exactly as " +
			"untrusted as one it linked from a page")
	}
}

// A JSON-named location is admitted through the SAME path as any other link, which is the
// structural claim: it goes through admit(), so destructiveness, scope, the crawl-scope query,
// depth, dedup and capacity all apply without this feature re-implementing any of them.
//
// A refusal test for scope needs a configured scope, which this package's harness does not set
// (Config.Scope defaults to nil, so everything is in scope and SkipOutOfScope cannot fire). The
// destructiveness test above covers the same structural claim with a gate the harness DOES
// exercise; asserting a scope refusal here would be asserting a fixture that cannot fail.
func TestAJSONLocationGoesThroughTheNormalAdmissionPath(t *testing.T) {
	srv := selfNamingTarget(t, func(base string) map[string]servedPage {
		return map[string]servedPage{
			"/":               {`<html><body><a href="/api/index.json">api</a></body></html>`, "text/html"},
			"/api/index.json": {`{"pages": ["` + base + `/json-reached"]}`, "application/json"},
			"/json-reached":   {`ok`, "text/plain"},
		}
	})
	rep := run(t, newHarness().config(srv.URL+"/"))
	if !fetchedAny(rep, "/json-reached") {
		t.Errorf("a location from the JSON body's array was not fetched; admission is the whole "+
			"point of the branch (fetched: %v)", fetchLog(rep))
	}
	if rep.JSONLocationsFound == 0 {
		t.Error("JSONLocationsFound = 0 while a location was fetched; the count and the crawl disagree")
	}
}
