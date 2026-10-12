package bcheck

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func graphQLPoints(t *testing.T, req string) []InsertionPoint {
	t.Helper()
	ps, _ := Enumerate([]byte(req), []string{"any"})
	var out []InsertionPoint
	for _, p := range ps {
		if p.coding == codingNested && p.nested == nestedGraphQL {
			out = append(out, p)
		}
	}
	return out
}

func jsonPost(body string) string {
	return "POST /graphql HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// Each string-literal argument of a GraphQL document in a JSON body is its own point, and a
// payload spliced there arrives inside that argument after both the JSON and the GraphQL string
// layers are decoded, with every other byte of the document untouched.
func TestGraphQLStringArgumentsAreNestedInsertionPoints(t *testing.T) {
	doc := `query Q { book(title: "Dune", lang: "en") { author } count(n: 3) tagged(tags: ["a"]) @skip(if: false) }`
	body, _ := json.Marshal(map[string]any{"query": doc, "variables": map[string]any{"who": "me"}})
	req := jsonPost(string(body))

	ps := graphQLPoints(t, req)
	var names []string
	for _, p := range ps {
		names = append(names, p.Name)
	}
	want := []string{"query[graphql:title]", "query[graphql:lang]", "query[graphql:tags]"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("GraphQL points = %v, want %v (the Int and Boolean literals are not points)", names, want)
	}

	payload := `x' AND "1"="1` + "\n\\"
	out, err := ps[0].Apply([]byte(req), payload, false)
	if err != nil {
		t.Fatal(err)
	}
	e, err := core.ParseRequestEdit(out)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(e.Body, &got); err != nil {
		t.Fatalf("the probed body is no longer JSON: %v\n%s", err, e.Body)
	}
	wantDoc := strings.Replace(doc, `"Dune"`, `"x' AND \"1\"=\"1\n\\"`, 1)
	if got.Query != wantDoc {
		t.Fatalf("probed document:\n got %s\nwant %s", got.Query, wantDoc)
	}
	if got.Variables["who"] != "me" {
		t.Fatalf("the variables object changed: %v", got.Variables)
	}

	// Appending keeps the base value in front of the payload.
	out, err = ps[1].Apply([]byte(req), "'", true)
	if err != nil {
		t.Fatal(err)
	}
	e, _ = core.ParseRequestEdit(out)
	_ = json.Unmarshal(e.Body, &got)
	if !strings.Contains(got.Query, `lang: "en'"`) {
		t.Fatalf("appended document: %s", got.Query)
	}
}

// A GET query string carries the document percent-encoded; the point re-encodes it that way.
func TestGraphQLArgumentPointsInAQueryString(t *testing.T) {
	doc := `{user(name:"bob"){id}}`
	req := "GET /graphql?query=" + url.QueryEscape(doc) + " HTTP/1.1\r\nHost: t\r\n\r\n"
	ps := graphQLPoints(t, req)
	if len(ps) != 1 || ps[0].Name != "query[graphql:name]" {
		t.Fatalf("points = %+v", ps)
	}
	out, err := ps[0].Apply([]byte(req), `b&o"b`, false)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := core.ParseRequestEdit(out)
	v, err := url.ParseQuery(e.Query)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Get("query"); got != `{user(name:"b&o\"b"){id}}` {
		t.Fatalf("document after the splice = %q", got)
	}
}

// Negative controls: values that are not GraphQL documents yield no GraphQL points, and a string
// outside any argument list (an alias-less selection never has one, but JSON does) is not a point.
func TestGraphQLPointsNeedAGraphQLDocument(t *testing.T) {
	for _, body := range []string{
		`{"query":"hello (world) \"x\""}`,                  // prose, not an operation
		`{"query":"{\"a\":\"b\"}"}`,                        // JSON in a string: nested JSON's job, not ours
		`{"query":"query{book(title:\"unterminated){a}}"}`, // unbalanced: not a document
		`{"note":"{x}","q":"query { a }"}`,
		`{"expr":"concat(\"a\", \"b\")"}`, // a call expression is not an operation                 // documents with no string argument
	} {
		if ps := graphQLPoints(t, jsonPost(body)); len(ps) != 0 {
			t.Errorf("%s: got GraphQL points %+v, want none", body, ps)
		}
	}
	// A comment or a block string holding quote characters does not create a point.
	doc := "# \"not\" an arg\nquery { a(x: \"\"\"block \"q\" \"\"\", y: \"real\") }"
	body, _ := json.Marshal(map[string]string{"query": doc})
	ps := graphQLPoints(t, jsonPost(string(body)))
	if len(ps) != 1 || ps[0].Name != "query[graphql:y]" {
		t.Fatalf("points = %+v, want only y", ps)
	}
}

// With nested points switched off the GraphQL points are withheld and counted, like every other
// nested kind.
func TestGraphQLPointsObeyNoNested(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"query": `{book(title:"Dune"){a}}`})
	ps, declined := EnumerateWith([]byte(jsonPost(string(body))), []string{"any"}, EnumerateOptions{NoNested: true})
	for _, p := range ps {
		if p.coding == codingNested {
			t.Fatalf("nested point %q enumerated with NoNested", p.Name)
		}
	}
	found := false
	for _, d := range declined {
		found = found || d.What == DeclinedNestedDisabledWhat
	}
	if !found {
		t.Fatalf("the withheld GraphQL point was not declined: %+v", declined)
	}
}
