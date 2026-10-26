package crawler

// Tests for the API-document reader (burpsy-react-ui-bwwg).
//
// # What each test is actually proving
//
// The load-bearing claim is that one traversal serves both grammars. A test that parses a JSON
// definition and a YAML definition separately and checks each one's endpoints cannot tell a shared
// traversal from two that happen to agree, so the YAML/JSON tests here assert EQUALITY on the same
// document — written twice — rather than just asserting each is non-empty. That is the test that fails
// if someone reintroduces a json.RawMessage-based path for JSON and a separate one for YAML.
//
// The other load-bearing claim is that a parse failure is distinguishable from an empty result, since
// the bead's acceptance criterion is that a failure is a counted skip and never "0 locations".

import (
	"strings"
	"testing"
)

// openAPIJSON is one definition written as JSON.
const openAPIJSON = `{
  "openapi": "3.0.0",
  "info": {"title": "Users", "version": "1.0.0"},
  "paths": {
    "/users": {
      "get":  {"operationId": "listUsers", "summary": "List every user",
               "parameters": [{"name": "page", "in": "query"}]},
      "post": {"operationId": "createUser", "description": "Create one",
               "parameters": [{"$ref": "#/components/parameters/Trace"}]}
    },
    "/users/{id}": {
      "get":    {"operationId": "getUser", "parameters": [{"name": "id", "in": "path"}]},
      "delete": {"operationId": "deleteUser", "parameters": [{"name": "id", "in": "path"}]}
    },
    "/users/{id}/notes": {
      "patch": {"operationId": "updateNotes", "parameters": [{"name": "id", "in": "path"}]}
    }
  },
  "components": {
    "parameters": {"Trace": {"name": "x-trace-id", "in": "header"}}
  }
}`

// openAPIYAML is the SAME definition written as YAML, as a Swagger editor emits it.
//
// Same routes, same operations, same parameters — so the two tests can compare their output field by
// field and any difference is the traversal rather than the document.
const openAPIYAML = `openapi: 3.0.0
info:
  title: Users
  version: 1.0.0
paths:
  /users:
    get:
      operationId: listUsers
      summary: List every user
      parameters:
        - name: page
          in: query
    post:
      operationId: createUser
      description: Create one
      parameters:
        - $ref: '#/components/parameters/Trace'
  /users/{id}:
    get:
      operationId: getUser
      parameters:
        - name: id
          in: path
    delete:
      operationId: deleteUser
      parameters:
        - name: id
          in: path
  /users/{id}/notes:
    patch:
      operationId: updateNotes
      parameters:
        - name: id
          in: path
components:
  parameters:
    Trace:
      name: x-trace-id
      in: header
`

// endpointByID finds one endpoint by its operationId.
func endpointByID(t *testing.T, eps []APIDocEndpoint, id string) APIDocEndpoint {
	t.Helper()
	for _, e := range eps {
		if e.OperationID == id {
			return e
		}
	}
	t.Fatalf("no operation %q in the parsed endpoints; got %+v", id, endpointSummary(eps))
	return APIDocEndpoint{}
}

// endpointSummary renders endpoints compactly for a failure message.
func endpointSummary(eps []APIDocEndpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.Method+" "+e.Path+" ("+e.OperationID+")")
	}
	return out
}

func TestAnOpenAPIDocumentInJSONYieldsItsOperations(t *testing.T) {
	format, eps, failure := ParseAPIDocument("application/json", "", []byte(openAPIJSON))
	if format != APIDocOpenAPI {
		t.Errorf("format = %q, want %q", format, APIDocOpenAPI)
	}
	if failure != "" {
		t.Fatalf("a valid OpenAPI document reported a failure: %s", failure)
	}
	if len(eps) != 5 {
		t.Fatalf("parsed %d operations (%v), want 5: the document declares two under /users, two under "+
			"/users/{id} and one under /users/{id}/notes", len(eps), endpointSummary(eps))
	}

	// The point of the parser rather than a URL-shaped string scan: the METHOD survives, and a
	// templated segment is reported as a path with its parameter named rather than as a literal
	// segment that could never be requested.
	list := endpointByID(t, eps, "listUsers")
	if list.Method != "GET" || list.Path != "/users" {
		t.Errorf("listUsers = %s %s, want GET /users", list.Method, list.Path)
	}
	del := endpointByID(t, eps, "deleteUser")
	if del.Method != "DELETE" || del.Path != "/users/{id}" {
		t.Errorf("deleteUser = %s %s, want DELETE /users/{id}", del.Method, del.Path)
	}
	if params := endpointByID(t, eps, "getUser").Parameters; len(params) != 1 || params[0] != "id" {
		t.Errorf("getUser parameters = %v, want [id]: the declared parameter is what makes a "+
			"templated path instantiable", params)
	}
	// A parameter declared behind a $ref resolves within the same document.
	if params := endpointByID(t, eps, "createUser").Parameters; len(params) != 1 || params[0] != "x-trace-id" {
		t.Errorf("createUser parameters = %v, want [x-trace-id]: a $ref to a component in the same "+
			"document must resolve", params)
	}
	// Summary falls back to description, because a definition that has only one of the two still
	// names the operation and dropping it would lose information the document carries.
	if got := endpointByID(t, eps, "createUser").Summary; got != "Create one" {
		t.Errorf("createUser summary = %q, want %q (description is the fallback)", got, "Create one")
	}
}

func TestTheSameDocumentInYAMLYieldsTheSameEndpointsAsJSON(t *testing.T) {
	_, fromJSON, failureJSON := ParseAPIDocument("application/json", "", []byte(openAPIJSON))
	format, fromYAML, failureYAML := ParseAPIDocument("text/yaml", "", []byte(openAPIYAML))

	if format != APIDocOpenAPI {
		t.Errorf("YAML document sniffed as %q, want %q", format, APIDocOpenAPI)
	}
	if failureJSON != "" || failureYAML != "" {
		t.Fatalf("a valid document reported a failure: JSON=%q YAML=%q", failureJSON, failureYAML)
	}
	if len(fromJSON) != len(fromYAML) {
		t.Fatalf("JSON yielded %d operations, YAML yielded %d (%v) — one traversal must serve both",
			len(fromJSON), len(fromYAML), endpointSummary(fromYAML))
	}
	// Field by field, in order. A per-index comparison rather than a set comparison, because ORDER is
	// part of the contract: the caps truncate deterministically only if the traversal is sorted, and
	// a set comparison would not notice an ordering regression.
	for i := range fromJSON {
		j, y := fromJSON[i], fromYAML[i]
		if j.Method != y.Method || j.Path != y.Path || j.OperationID != y.OperationID || j.Summary != y.Summary {
			t.Errorf("operation %d differs between grammars:\n  JSON: %s %s (%s) %q\n  YAML: %s %s (%s) %q",
				i, j.Method, j.Path, j.OperationID, j.Summary, y.Method, y.Path, y.OperationID, y.Summary)
		}
		if strings.Join(j.Parameters, ",") != strings.Join(y.Parameters, ",") {
			t.Errorf("operation %s parameters differ between grammars: JSON %v, YAML %v — the same "+
				"document must not read differently depending on which grammar it was written in",
				j.OperationID, j.Parameters, y.Parameters)
		}
	}
}

func TestASwagger2DocumentIsRecognisedAsSwaggerNotOpenAPI(t *testing.T) {
	const swagger = `{"swagger":"2.0","info":{"title":"Pets","version":"1.0"},
	  "paths":{"/pets":{"get":{"operationId":"listPets","summary":"All the pets",
	  "parameters":[{"name":"limit","in":"query"}]}}}}`
	format, eps, failure := ParseAPIDocument("application/json", "", []byte(swagger))
	if format != APIDocSwagger {
		t.Errorf("format = %q, want %q: a tool that calls a Swagger 2 document OpenAPI is "+
			"reporting something false about a document the operator will rely on", format, APIDocSwagger)
	}
	if failure != "" {
		t.Fatalf("a valid Swagger document reported a failure: %s", failure)
	}
	got := endpointByID(t, eps, "listPets")
	if got.Method != "GET" || got.Path != "/pets" || len(got.Parameters) != 1 {
		t.Errorf("listPets = %s %s params=%v, want GET /pets with one parameter", got.Method, got.Path, got.Parameters)
	}
}

func TestAWSDLDocumentYieldsItsOperations(t *testing.T) {
	const wsdl = `<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <wsdl:binding name="UserServiceBinding">
    <wsdl:operation name="GetUser">
      <soap:operation soapAction="urn:GetUser"/>
    </wsdl:operation>
    <wsdl:operation name="ListUsers">
      <soap:operation soapAction="urn:ListUsers"/>
    </wsdl:operation>
    <!-- A duplicate, which a document may carry across two ports and a crawl must not yield twice. -->
    <wsdl:operation name="GetUser">
      <soap:operation soapAction="urn:GetUser"/>
    </wsdl:operation>
    <wsdl:operation>
      <soap:operation/>
    </wsdl:operation>
  </wsdl:binding>
</wsdl:definitions>`

	format, eps, failure := ParseAPIDocument("application/wsdl+xml", "", []byte(wsdl))
	if format != APIDocWSDL {
		t.Errorf("format = %q, want %q", format, APIDocWSDL)
	}
	if failure != "" {
		t.Fatalf("a valid WSDL reported a failure: %s", failure)
	}
	// Two operations: the duplicate is de-duplicated and the nameless one is refused, because an
	// operation with no name names nothing and deriving an endpoint from it would be inventing one.
	if len(eps) != 2 {
		t.Fatalf("parsed %d operations (%v), want 2 (one duplicate collapsed, one nameless refused)",
			len(eps), endpointSummary(eps))
	}
	if got := endpointByID(t, eps, "urn:GetUser"); got.Method != "POST" {
		t.Errorf("urn:GetUser method = %q, want POST: SOAP is POST", got.Method)
	}
}

func TestABodyThatIsNotAnAPIDocumentIsNotAFailure(t *testing.T) {
	// The ordinary case: a crawl fetches thousands of responses and almost none is a definition.
	// Reporting those as failures would fill the skip ledger with noise and make the real one
	// invisible, which is the opposite of what a counted skip is for.
	for _, tc := range []struct{ name, contentType, body string }{
		{"an ordinary JSON API response", "application/json", `{"users":[{"id":1,"name":"ada"}]}`},
		{"an HTML page", "text/html", `<html><body><a href="/next">next</a></body></html>`},
		{"plain text", "text/plain", "hello"},
		{"empty", "application/json", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			format, eps, failure := ParseAPIDocument(tc.contentType, "", []byte(tc.body))
			if format != APIDocNone {
				t.Errorf("format = %q, want %q", format, APIDocNone)
			}
			if failure != "" {
				t.Errorf("a non-definition reported a failure %q — the caller would count it as a "+
					"skip and hide the real ones", failure)
			}
			if len(eps) != 0 {
				t.Errorf("a non-definition yielded %d endpoints (%v)", len(eps), endpointSummary(eps))
			}
		})
	}
}

func TestADocumentThatAnnouncesItselfAndCannotBeReadIsAFailureNotZeroLocations(t *testing.T) {
	// The acceptance criterion, stated as a test: a parse failure is distinguishable from an empty
	// result, because the caller turns the first into SkipAPIUnparsed and must never report it as
	// "0 locations" — which is indistinguishable from a target that published no API at all.
	for _, tc := range []struct{ name, body string }{
		{"truncated JSON", `{"openapi":"3.0.0","paths":{"/users":{"get":{"operationId":"a`},
		{"YAML that is a list, not a mapping", "openapi: 3.0.0\n- one\n- two\n"},
		{"a mapping whose paths are nonsense", `{"openapi":"3.0.0","paths":"not-an-object"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			format, eps, failure := ParseAPIDocument("application/json", "", []byte(tc.body))
			if format == APIDocNone {
				t.Fatalf("a body that announces itself as a definition sniffed as %q, so the caller "+
					"cannot tell a broken definition from a non-definition", format)
			}
			if failure == "" {
				t.Errorf("a definition that could not be read reported NO failure and %d endpoints "+
					"(%v) — the caller will report this target as having no API", len(eps), endpointSummary(eps))
			}
			if len(eps) != 0 {
				t.Errorf("a failed parse returned %d endpoints (%v); a partial read must not be "+
					"presented as the document's content", len(eps), endpointSummary(eps))
			}
		})
	}
}

func TestAnEmptyPathsObjectIsARealAnswerAndNotAFailure(t *testing.T) {
	// A skeleton definition is legal and common early in a project's life. Zero endpoints is the
	// TRUE answer, and reporting it as a failure would tell an operator their API is broken when the
	// file simply declares no routes yet.
	format, eps, failure := ParseAPIDocument("application/json", "",
		[]byte(`{"openapi":"3.0.0","info":{"title":"New","version":"0.1"},"paths":{}}`))
	if format != APIDocOpenAPI {
		t.Errorf("format = %q, want %q", format, APIDocOpenAPI)
	}
	if failure != "" {
		t.Errorf("an empty paths object reported a failure %q; it is a legal skeleton", failure)
	}
	if len(eps) != 0 {
		t.Errorf("an empty paths object yielded %d endpoints (%v)", len(eps), endpointSummary(eps))
	}
}

func TestDocumentMetadataIsNotMistakenForAnOperation(t *testing.T) {
	// Every path entry carries non-method keys, and `parameters` is one of them. Treating it as a verb
	// would make "PARAMETERS /users" an endpoint the crawler then tries to fetch.
	const doc = `{"openapi":"3.0.0","paths":{"/users":{
	  "summary":"A collection",
	  "description":"Long form",
	  "parameters":[{"name":"page","in":"query"}],
	  "servers":[{"url":"https://api.example.test"}],
	  "x-vendor-note":"ignore me",
	  "get":{"operationId":"listUsers"}}}}`
	_, eps, failure := ParseAPIDocument("application/json", "", []byte(doc))
	if failure != "" {
		t.Fatalf("failure: %s", failure)
	}
	if len(eps) != 1 {
		t.Fatalf("parsed %d operations (%v), want 1: only `get` names a verb", len(eps), endpointSummary(eps))
	}
	if eps[0].Method != "GET" {
		t.Errorf("method = %q, want GET", eps[0].Method)
	}
}

func TestAParameterNameDeclaredTwiceIsReportedOnce(t *testing.T) {
	// A document may declare `id` as both a path and a query parameter. They are the same name to
	// substitute, and a report listing it twice reads as two parameters where there is one.
	const doc = `{"openapi":"3.0.0","paths":{"/users/{id}":{"get":{"operationId":"g",
	  "parameters":[{"name":"id","in":"path"},{"name":"id","in":"query"}]}}}}`
	_, eps, _ := ParseAPIDocument("application/json", "", []byte(doc))
	params := endpointByID(t, eps, "g").Parameters
	if len(params) != 1 || params[0] != "id" {
		t.Errorf("parameters = %v, want [id]", params)
	}
}

func TestAnExternalParameterRefIsNotFollowed(t *testing.T) {
	// A $ref to ANOTHER document means fetching that document. The scope in force has not authorised
	// that request, so the reference resolves to nothing rather than to a guess — the same refusal the
	// crawler makes everywhere else it would invent a URL.
	const doc = `{"openapi":"3.0.0","paths":{"/users":{"get":{"operationId":"g",
	  "parameters":[{"$ref":"https://other.example.test/params.json#/Trace"}]}}}}`
	_, eps, failure := ParseAPIDocument("application/json", "", []byte(doc))
	if failure != "" {
		t.Fatalf("failure: %s", failure)
	}
	if params := endpointByID(t, eps, "g").Parameters; len(params) != 0 {
		t.Errorf("parameters = %v, want none: an external $ref must not be followed from a crawl", params)
	}
}

func TestATruncatedWSDLKeepsWhatItReadAndReportsTheBreak(t *testing.T) {
	// A truncated fetch of a real WSDL still names its first operations. Returning them with a reason
	// beats returning nothing, and the reason is what tells the operator the document was cut short.
	const truncated = `<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:operation name="GetUser" soapAction="urn:GetUser"/>
  <wsdl:operation name="ListUsers"`
	_, eps, failure := ParseAPIDocument("application/wsdl+xml", "", []byte(truncated))
	if len(eps) != 1 {
		t.Errorf("parsed %d operations (%v), want the one the untruncated prefix names", len(eps), endpointSummary(eps))
	}
	if failure == "" {
		t.Error("a truncated WSDL reported no failure; the operator cannot tell a cut fetch from a complete one")
	}
}

func TestADocumentWithAYAMLMarkerIsReadAsYAML(t *testing.T) {
	// A definition pasted out of a Swagger editor routinely carries a leading `---`. That is valid
	// YAML and invalid JSON, so without the marker strip the JSON attempt fails on framing and the
	// document would take the YAML path for the wrong reason.
	const marked = "---\n" + openAPIYAML
	format, eps, failure := ParseAPIDocument("text/yaml", "", []byte(marked))
	if format != APIDocOpenAPI || failure != "" {
		t.Fatalf("format=%q failure=%q, want %q and no failure", format, failure, APIDocOpenAPI)
	}
	if len(eps) != 5 {
		t.Errorf("parsed %d operations (%v), want 5 — the same document as without the marker",
			len(eps), endpointSummary(eps))
	}
}

func TestASchemaVersionReadsTheSameUnderBothGrammars(t *testing.T) {
	// `version: 1.0.0` is a string in JSON and a string in YAML here, but `version: 3` is a NUMBER,
	// and the two decoders disagree about its type (json gives float64, yaml gives int). If the scalar
	// reader did not normalise, the same document would read its own version differently.
	for _, body := range []string{
		`{"openapi":"3.0.0","info":{"version":3},"paths":{}}`,
		"openapi: 3.0.0\ninfo:\n  version: 3\npaths: {}\n",
	} {
		root, err := decodeAPIDocTree([]byte(body))
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		info := apiObj(root["info"])
		if got := apiStr(info["version"]); got != "3" {
			t.Errorf("apiStr(version) = %q, want %q (body %q)", got, "3", body)
		}
	}
}
