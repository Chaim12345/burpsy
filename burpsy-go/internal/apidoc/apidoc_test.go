package apidoc

import (
	"strings"
	"testing"
)

// The parser's job is to turn a document into requests, and the two things it must never do are invent
// a value without saying so and read one document's meaning into another's shape. The tests below are
// therefore mostly about *provenance* — where each value came from — and about the two document
// flavours staying distinct, because "all values came from the API's own authors" and "this build made
// them up" produce the same list of requests and completely different scans.

func TestAnOpenAPIExampleBeatsADefaultWhichBeatsAnEnumWhichBeatsNothing(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.3",
	  "info": {"title": "T", "version": "1"},
	  "servers": [{"url": "https://api.test/v1"}],
	  "paths": {"/p": {"get": {"parameters": [
	    {"name": "withExample", "in": "query", "example": "explicit",
	     "schema": {"type": "string", "default": "ignored"}},
	    {"name": "withDefault", "in": "query", "schema": {"type": "string", "default": "the-default"}},
	    {"name": "withEnum", "in": "query", "schema": {"type": "string", "enum": ["first", "second"]}},
	    {"name": "withNothing", "in": "query", "schema": {"type": "string"}}
	  ], "responses": {"200": {"description": "ok"}}}}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := map[string]Parameter{}
	for _, p := range doc.Operations[0].Parameters {
		got[p.Name] = p
	}
	want := map[string]struct {
		value  string
		source ValueSource
	}{
		"withExample": {"explicit", ValueExample},
		"withDefault": {"the-default", ValueDefault},
		"withEnum":    {"first", ValueEnum},
		"withNothing": {"withNothing", ValuePlaceholder},
	}
	for name, w := range want {
		p, ok := got[name]
		if !ok {
			t.Errorf("%s produced no parameter at all", name)
			continue
		}
		if p.Value != w.value {
			t.Errorf("%s = %q, want %q", name, p.Value, w.value)
		}
		if p.Source != w.source {
			t.Errorf("%s source = %q, want %q — a value with the wrong provenance is a scan reported as "+
				"document-driven when it was invented", name, p.Source, w.source)
		}
	}
	if doc.PlaceholderValues() != 1 {
		t.Errorf("PlaceholderValues = %d, want 1", doc.PlaceholderValues())
	}
	if doc.DeclaredValues() != 4 {
		t.Errorf("DeclaredValues = %d, want 4", doc.DeclaredValues())
	}
}

// A placeholder must be recognisable rather than plausible: the values are what distinguish a
// document-driven scan from a guessed one when reading captured traffic, and a placeholder that looked
// like real data would make that impossible.
func TestAPlaceholderReadsAsInventedRatherThanPlausible(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "openapi": "3.0.3", "info": {"title": "T", "version": "1"},
	  "servers": [{"url": "https://api.test"}],
	  "paths": {"/{id}/{slug}": {"get": {"parameters": [
	    {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
	    {"name": "slug", "in": "path", "required": true, "schema": {"type": "string"}},
	    {"name": "flag", "in": "query", "schema": {"type": "boolean"}}
	  ], "responses": {"200": {"description": "ok"}}}}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := doc.Operations[0].Path; got != "/1/slug?flag=true" {
		t.Errorf("path = %q, want /1/slug?flag=true — an integer parameter becomes 1, a string one becomes "+
			"its own name, and a boolean becomes true", got)
	}
}

// Two scans of one document must produce byte-identical requests. Go's map iteration order is random,
// and a request whose query string is reordered between runs looks like the API changed.
func TestTwoParsesOfOneDocumentAgreeOnOrder(t *testing.T) {
	body := []byte(`{
	  "openapi": "3.0.3", "info": {"title": "T", "version": "1"},
	  "servers": [{"url": "https://api.test"}],
	  "paths": {
	    "/zeta": {"get": {"responses": {"200": {"description": "ok"}}}},
	    "/alpha": {"post": {"responses": {"200": {"description": "ok"}}},
	               "get": {"responses": {"200": {"description": "ok"}}}}
	  }
	}`)
	first, err := Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for i := 0; i < 8; i++ {
		again, err := Parse(body)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(again.Operations) != len(first.Operations) {
			t.Fatalf("operation count changed between parses")
		}
		for j := range first.Operations {
			a, b := first.Operations[j], again.Operations[j]
			if a.Method != b.Method || a.Path != b.Path {
				t.Fatalf("parse %d produced %s %s where the first produced %s %s", i, b.Method, b.Path, a.Method, a.Path)
			}
		}
	}
	// Alphabetical by path, and by method within a path — the order a reader can predict without
	// running the parser.
	var seen []string
	for _, op := range first.Operations {
		seen = append(seen, op.Method+" "+op.Path)
	}
	want := []string{"GET /alpha", "POST /alpha", "GET /zeta"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", seen, want)
	}
}

// Swagger 2 states the same facts in different places: the host is assembled from three keys, the body
// is a parameter rather than a requestBody, and a form body is a list of formData parameters. Reading
// a 2.0 document with 3.0's shape would find no body and no server, and report an empty API.
func TestASwagger2DocumentIsReadAsItsOwnShape(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "swagger": "2.0",
	  "info": {"title": "T", "version": "1"},
	  "schemes": ["https"], "host": "api.test", "basePath": "/v2",
	  "paths": {"/items": {"post": {"parameters": [
	    {"name": "kind", "in": "formData", "type": "string", "default": "widget"},
	    {"name": "count", "in": "formData", "type": "integer", "default": 3}
	  ], "responses": {"201": {"description": "made"}}}}}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Format != FormatSwagger2 {
		t.Errorf("Format = %q, want %q", doc.Format, FormatSwagger2)
	}
	if len(doc.Servers) != 1 || doc.Servers[0] != "https://api.test/v2" {
		t.Errorf("Servers = %v, want [https://api.test/v2] — a 2.0 server is schemes x host x basePath", doc.Servers)
	}
	op := doc.Operations[0]
	if op.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("ContentType = %q, want a form body", op.ContentType)
	}
	if string(op.Body) != "kind=widget&count=3" {
		t.Errorf("body = %q, want kind=widget&count=3", op.Body)
	}
}

// A bare `swagger: 2.0` is a float in YAML and a string in JSON, and both mean 2.0. Refusing one of them
// would make half the documents in the world unreadable for a formatting reason.
func TestBothDocumentSpellingsOfA2Point0VersionAreAccepted(t *testing.T) {
	for _, body := range []string{
		`{"swagger": "2.0", "info": {"title":"T","version":"1"}, "host": "api.test", "paths": {"/a": {"get": {"responses": {"200": {"description":"ok"}}}}}}`,
		"swagger: 2.0\ninfo: {title: T, version: '1'}\nhost: api.test\npaths:\n  /a:\n    get:\n      responses: {'200': {description: ok}}\n",
	} {
		if _, err := Parse([]byte(body)); err != nil {
			t.Errorf("Parse(%q): %v", body, err)
		}
	}
}

// A local $ref is how a real document shares one schema across forty operations. Not resolving it would
// leave the parameter without a type, and a wrong resolution would attach one operation's declaration
// to another's — which is a scan pointed at the wrong endpoint.
func TestALocalRefIsResolvedAndACycleStops(t *testing.T) {
	src := `{
	  "openapi": "3.0.3", "info": {"title": "T", "version": "1"},
	  "servers": [{"url": "https://api.test"}],
	  "components": {
	    "parameters": {"UserId": {"name": "id", "in": "path", "required": true, "schema": {"$ref": "#/components/schemas/Id"}}},
	    "schemas": {
	      "Id": {"type": "integer", "default": 42},
	      "Self": {"type": "object", "properties": {"next": {"$ref": "#/components/schemas/Self"}}}
	    }
	  },
	  "paths": {"/users/{id}": {"get": {"parameters": [{"$ref": "#/components/parameters/UserId"}],
	    "responses": {"200": {"description": "ok"}}}},
	  "/loop": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Self"}}}},
	    "responses": {"200": {"description": "ok"}}}}}
	}`
	doc, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	byTemplate := map[string]Operation{}
	for _, op := range doc.Operations {
		byTemplate[op.Template] = op
	}
	if got := byTemplate["/users/{id}"].Path; got != "/users/42" {
		t.Errorf("/users/{id} = %q, want /users/42 — a ref to a parameter whose schema is itself a ref", got)
	}
	if body := byTemplate["/loop"].Body; len(body) == 0 {
		t.Error("a schema that references itself produced no body at all; the depth bound must stop the walk " +
			"and keep what it had, not abandon the request")
	}
}

// The refusals name the document rather than the absence of a key: "no openapi or swagger version key"
// is true of all of these and tells the operator nothing about the file in front of them.
func TestAnUnreadableDocumentIsRefusedByWhatItIs(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"asyncapi", `{"asyncapi":"2.0.0","channels":{}}`, "AsyncAPI"},
		{"raml", "#%RAML 1.0\ntitle: T\n/a:\n  get:\n", "RAML"},
		{"postman", `{"info":{"name":"c"},"item":[]}`, "Postman"},
		{"swagger 1", `{"swagger":"1.2","apis":[]}`, "Swagger 1.2"},
		{"openapi 4", `{"openapi":"4.0.0"}`, "OpenAPI 4.0.0"},
		{"openapi with a non-string version", `{"openapi": {"v": 4}}`, "flavour is unknown"},
		{"not a definition", `{"hello":"world"}`, "neither an `openapi` nor a `swagger`"},
		{"not a mapping", `just a string`, "JSON object or a YAML mapping"},
		{"empty", ``, "parsed as empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.body))
			if err == nil {
				t.Fatalf("Parse accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal must contain %q; got: %v", tc.want, err)
			}
		})
	}
}

// A document that describes no operation is refused rather than returned empty, because an empty
// Document and a document nobody could read both send zero requests and only one of them is the
// operator's file being wrong.
func TestADocumentDescribingNoOperationIsRefused(t *testing.T) {
	cases := map[string]string{
		"no paths at all":     `{"openapi":"3.0.3","info":{"title":"T","version":"1"}}`,
		"an empty paths map":  `{"openapi":"3.0.3","info":{"title":"T","version":"1"},"paths":{}}`,
		"a path with no verb": `{"openapi":"3.0.3","info":{"title":"T","version":"1"},"paths":{"/a":{"parameters":[]}}}`,
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s was accepted; a definition sweep of nothing must be a refusal, not an empty scan", name)
		}
	}
}

// A formData override reaches the urlencoded body it is sent in, not only the reported parameter
// (vuw7): the review step showed the operator's value while the wire carried the document's.
func TestAFormDataOverrideIsSentInTheBody(t *testing.T) {
	doc, err := Parse([]byte(`{"swagger":"2.0","info":{"title":"x","version":"1"},"host":"h.example","paths":{"/f":{"post":{` +
		`"consumes":["application/x-www-form-urlencoded"],"parameters":[` +
		`{"name":"a","in":"formData","type":"string","default":"one"},{"name":"b","in":"formData","type":"string","default":"keep"}],` +
		`"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	op := &doc.Operations[0]
	if !op.SetParameter("formData", "a", "two & three") {
		t.Fatal("the formData parameter was not found")
	}
	if got := string(op.Body); got != "a=two+%26+three&b=keep" {
		t.Errorf("body = %q, want the override re-rendered and b untouched", got)
	}
	if op.Parameters[0].Source != ValueOperator {
		t.Errorf("source = %q, want operator", op.Parameters[0].Source)
	}
}
