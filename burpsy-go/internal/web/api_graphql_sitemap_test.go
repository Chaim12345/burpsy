package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Save GraphQL queries to site map (burpsy-react-ui-7v1e), through POST /api/graphql/sitemap and
// asserted on the marshalled JSON, the stored requests, and the site map that results.

// introspectionFixture is a small but real introspection answer: a Query root with two fields (one
// taking a non-null ID, one an enum and returning a list of objects), a Mutation root with one field
// taking an input object, and the types they reference.
const introspectionFixture = `{"data":{"__schema":{
 "queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":null,
 "types":[
  {"kind":"OBJECT","name":"Query","fields":[
    {"name":"user","args":[{"name":"id","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"ID","ofType":null}},"defaultValue":null}],
     "type":{"kind":"OBJECT","name":"User","ofType":null}},
    {"name":"users","args":[{"name":"role","type":{"kind":"ENUM","name":"Role","ofType":null},"defaultValue":null}],
     "type":{"kind":"LIST","name":null,"ofType":{"kind":"OBJECT","name":"User","ofType":null}}},
    {"name":"__typename","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}]},
  {"kind":"OBJECT","name":"Mutation","fields":[
    {"name":"createUser","args":[{"name":"input","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"INPUT_OBJECT","name":"UserInput","ofType":null}},"defaultValue":null}],
     "type":{"kind":"OBJECT","name":"User","ofType":null}}]},
  {"kind":"OBJECT","name":"User","fields":[
    {"name":"id","args":[],"type":{"kind":"SCALAR","name":"ID","ofType":null}},
    {"name":"email","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}},
    {"name":"role","args":[],"type":{"kind":"ENUM","name":"Role","ofType":null}}]},
  {"kind":"ENUM","name":"Role","fields":null,"enumValues":[{"name":"ADMIN"},{"name":"USER"}]},
  {"kind":"INPUT_OBJECT","name":"UserInput","fields":null,"inputFields":[{"name":"email","type":{"kind":"SCALAR","name":"String","ofType":null},"defaultValue":null}]},
  {"kind":"SCALAR","name":"ID"},{"kind":"SCALAR","name":"String"}]}}}`

// seedExchange stores a request/response pair as one exchange and returns its id.
func seedExchange(t *testing.T, s *Server, request, response string) core.ExchangeID {
	t.Helper()
	reqID, err := s.store.Put([]byte(request), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := s.store.Put([]byte(response), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Host: "api.test", Port: 443, TLS: true, Method: firstLineMethod(request), Path: firstLinePath(request),
		Request: core.MsgPtr(reqID), Response: &respID, Source: core.SourceRepeater}
	s.store.AddExchange(ex)
	return ex.ID
}

func jsonResponse(body string) string {
	return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

type graphqlSitemapWire struct {
	Endpoint   string `json:"endpoint"`
	Placement  string `json:"placement"`
	Truncated  bool   `json:"truncated"`
	Operations []struct {
		Kind       string `json:"kind"`
		Field      string `json:"field"`
		Name       string `json:"name"`
		ExchangeID int    `json:"exchange_id"`
		Path       string `json:"path"`
	} `json:"operations"`
}

func TestSaveGraphQLQueriesToSiteMapWritesOneUnsentRequestPerOperation(t *testing.T) {
	s := newTestServer()
	introspection := `{"query":"query IntrospectionQuery { __schema { queryType { name } } }","variables":{}}`
	request := "POST /graphql HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer t0ken\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(introspection)) + "\r\n\r\n" + introspection
	id := seedExchange(t, s, request, jsonResponse(introspectionFixture))
	before := len(s.store.Exchanges())

	rec := postJSON(t, s, "/api/graphql/sitemap", map[string]any{"exchange_id": id})
	if rec.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", rec.Code, rec.Body.String())
	}
	var out graphqlSitemapWire
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Placement != "body" || out.Truncated || out.Endpoint != "api.test/graphql" {
		t.Fatalf("placement/truncated/endpoint = %q/%v/%q", out.Placement, out.Truncated, out.Endpoint)
	}
	var names []string
	for _, op := range out.Operations {
		names = append(names, op.Kind+":"+op.Field)
	}
	if strings.Join(names, ",") != "query:user,query:users,mutation:createUser" {
		t.Fatalf("operations = %v, want the two queries then the mutation, __typename excluded", names)
	}
	if got := len(s.store.Exchanges()); got != before+3 {
		t.Fatalf("exchanges = %d, want %d (one per operation)", got, before+3)
	}

	// Each generated request: unsent (no response), attributed to the schema, the original's
	// headers kept, the operation in the body with a true Content-Length.
	for _, op := range out.Operations {
		ex, err := s.store.GetExchange(core.ExchangeID(op.ExchangeID))
		if err != nil {
			t.Fatal(err)
		}
		if ex.Response != nil || ex.Status != nil || ex.Source != core.SourceSchema {
			t.Fatalf("exchange %d: response %v status %v source %q — a saved query must be unrequested", ex.ID, ex.Response, ex.Status, ex.Source)
		}
		if ex.ParentID == nil || *ex.ParentID != id {
			t.Fatalf("exchange %d parent = %v, want the introspection exchange %d", ex.ID, ex.ParentID, id)
		}
		msg, _ := s.store.Get(*ex.Request)
		raw := string(msg.Raw())
		if !strings.Contains(raw, "Authorization: Bearer t0ken\r\n") {
			t.Fatalf("generated request lost the original's headers:\n%s", raw)
		}
		head, body, _ := strings.Cut(raw, "\r\n\r\n")
		if !strings.Contains(head, "Content-Length: "+strconv.Itoa(len(body))) {
			t.Fatalf("Content-Length does not match the %d-byte body:\n%s", len(body), head)
		}
		var payload struct {
			Query         string         `json:"query"`
			OperationName string         `json:"operationName"`
			Variables     map[string]any `json:"variables"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("body is not JSON: %v\n%s", err, body)
		}
		if payload.OperationName != op.Name || !strings.Contains(payload.Query, op.Field) {
			t.Fatalf("payload %+v does not carry operation %s", payload, op.Name)
		}
		switch op.Field {
		case "user":
			if !strings.Contains(payload.Query, "query queryUser($id: ID!)") || !strings.Contains(payload.Query, "user(id: $id)") ||
				!strings.Contains(payload.Query, "email") || payload.Variables["id"] != "" {
				t.Fatalf("user operation = %q vars %v", payload.Query, payload.Variables)
			}
		case "users":
			if payload.Variables["role"] != "ADMIN" {
				t.Fatalf("an enum argument's placeholder = %v, want the first enum value", payload.Variables["role"])
			}
		case "createUser":
			if !strings.HasPrefix(payload.Query, "mutation mutationCreateUser($input: UserInput!)") {
				t.Fatalf("mutation document = %q", payload.Query)
			}
			if _, isObject := payload.Variables["input"].(map[string]any); !isObject {
				t.Fatalf("an input-object placeholder = %#v, want {}", payload.Variables["input"])
			}
		}
	}

	// The site map: one node for the endpoint, carrying the three unrequested items.
	s.sitemap.Sync(s.store)
	node := getJSON(t, s, "/api/sitemap")
	if !strings.Contains(node.Body.String(), "/graphql") {
		t.Fatalf("site map does not show the endpoint: %s", node.Body.String())
	}
}

func TestSaveGraphQLQueriesUsesTheQueryParameterWhenTheOriginalDid(t *testing.T) {
	s := newTestServer()
	request := "GET /graphql?query=" + url.QueryEscape("{__schema{types{name}}}") + "&debug=1 HTTP/1.1\r\nHost: api.test\r\n\r\n"
	id := seedExchange(t, s, request, jsonResponse(introspectionFixture))
	rec := postJSON(t, s, "/api/graphql/sitemap", map[string]any{"exchange_id": id})
	var out graphqlSitemapWire
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Placement != "url" || len(out.Operations) != 3 {
		t.Fatalf("= %d placement %q ops %d: %s", rec.Code, out.Placement, len(out.Operations), rec.Body.String())
	}
	ex, _ := s.store.GetExchange(core.ExchangeID(out.Operations[0].ExchangeID))
	msg, _ := s.store.Get(*ex.Request)
	line, _, _ := strings.Cut(string(msg.Raw()), "\r\n")
	target := strings.Fields(line)[1]
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if parsed.Path != "/graphql" || q.Get("debug") != "1" || !strings.HasPrefix(q.Get("query"), "query queryUser") || q.Get("operationName") != "queryUser" {
		t.Fatalf("generated target %q: path %q query %v", target, parsed.Path, q)
	}
	if !strings.HasSuffix(line, " HTTP/1.1") || !strings.HasPrefix(line, "GET ") {
		t.Fatalf("start line %q lost its method or version", line)
	}
}

func TestSaveGraphQLQueriesRefusesANonGraphQLBodyWithAReason(t *testing.T) {
	s := newTestServer()
	cases := map[string]string{
		"not JSON":           "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hi</html>",
		"introspection off":  jsonResponse(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`),
		"JSON but no schema": jsonResponse(`{"data":{"user":{"id":"1"}}}`),
	}
	wants := map[string]string{
		"not JSON":           "not a GraphQL answer",
		"introspection off":  "introspection is not allowed",
		"JSON but no schema": "no __schema",
	}
	for name, response := range cases {
		id := seedExchange(t, s, "POST /graphql HTTP/1.1\r\nHost: api.test\r\n\r\n{}", response)
		before := len(s.store.Exchanges())
		rec := postJSON(t, s, "/api/graphql/sitemap", map[string]any{"exchange_id": id})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), wants[name]) {
			t.Fatalf("%s: = %d %q, want 400 containing %q", name, rec.Code, rec.Body.String(), wants[name])
		}
		if len(s.store.Exchanges()) != before {
			t.Fatalf("%s: a refusal must store nothing", name)
		}
	}
	if rec := postJSON(t, s, "/api/graphql/sitemap", map[string]any{"exchange_id": 4242}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown exchange = %d, want 404", rec.Code)
	}
}

func TestSaveGraphQLQueriesOfAnEmptySchemaIsAnEmptyListNotNull(t *testing.T) {
	s := newTestServer()
	id := seedExchange(t, s, "POST /graphql HTTP/1.1\r\nHost: api.test\r\n\r\n{\"query\":\"x\"}",
		jsonResponse(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"Query","fields":[]}]}}}`))
	rec := postJSON(t, s, "/api/graphql/sitemap", map[string]any{"exchange_id": id})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"operations":[]`) {
		t.Fatalf("= %d %s, want 200 with operations []", rec.Code, rec.Body.String())
	}
}

// A request typed in Repeater is often bare LF. The live drive found the first cut refusing it with
// "no header terminator"; the generated copies must keep the request's own line ending.
func TestSaveGraphQLQueriesKeepsABareLFRequestsLineEndings(t *testing.T) {
	s := newTestServer()
	body := `{"query":"{__schema{types{name}}}"}`
	request := "POST /graphql HTTP/1.1\nHost: api.test\nContent-Type: application/json\nContent-Length: " + strconv.Itoa(len(body)) + "\n\n" + body
	id := seedExchange(t, s, request, jsonResponse(introspectionFixture))
	rec := postJSON(t, s, "/api/graphql/sitemap", map[string]any{"exchange_id": id})
	var out graphqlSitemapWire
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || len(out.Operations) != 3 {
		t.Fatalf("= %d: %s", rec.Code, rec.Body.String())
	}
	ex, _ := s.store.GetExchange(core.ExchangeID(out.Operations[0].ExchangeID))
	msg, _ := s.store.Get(*ex.Request)
	raw := string(msg.Raw())
	if strings.Contains(raw, "\r") {
		t.Fatalf("a bare-LF request came back with CRs:\n%q", raw)
	}
	head, gotBody, found := strings.Cut(raw, "\n\n")
	if !found || !strings.HasPrefix(head, "POST /graphql HTTP/1.1\nHost: api.test\n") ||
		!strings.HasSuffix(head, "\nContent-Length: "+strconv.Itoa(len(gotBody))) || strings.Count(head, "Content-Length") != 1 {
		t.Fatalf("generated request head:\n%q", head)
	}
}
