package apidoc

import (
	"strings"
	"testing"
)

const collection = `{
  "info": {"_postman_id": "x", "name": "Shop API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
  "variable": [{"key": "base", "value": "https://api.shop.test"}],
  "item": [
    {"name": "Users", "item": [
      {"name": "Get user", "request": {"method": "GET",
        "url": {"raw": "{{base}}/users/:id?expand=orders", "host": ["{{base}}"], "path": ["users", ":id"],
                "variable": [{"key": "id", "value": "42"}]},
        "header": [{"key": "X-Trace", "value": "abc"}, {"key": "X-Off", "value": "1", "disabled": true}]}},
      {"name": "Create user", "request": {"method": "POST", "url": "{{base}}/users",
        "body": {"mode": "raw", "raw": "{\"name\":\"{{name}}\"}", "options": {"raw": {"language": "json"}}}}}
    ]},
    {"name": "Login", "request": {"method": "POST", "url": "https://auth.shop.test/login", "auth": {"type": "noauth"},
      "body": {"mode": "urlencoded", "urlencoded": [{"key": "user", "value": "a b"}, {"key": "x", "value": "1", "disabled": true}]}}},
    {"name": "Query", "request": {"method": "POST", "url": "{{gql}}/graphql",
      "body": {"mode": "graphql", "graphql": {"query": "{ me { id } }", "variables": "{\"a\":1}"}}}}
  ]
}`

func TestAPostmanCollectionBecomesOperations(t *testing.T) {
	doc, err := Parse([]byte(collection))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != FormatPostman || doc.Title != "Shop API" || doc.SpecVersion != "2.1" {
		t.Errorf("doc = %+v", doc)
	}
	if len(doc.Operations) != 4 {
		t.Fatalf("want 4 operations (folders walked), got %d", len(doc.Operations))
	}
	get, create, login, gql := doc.Operations[0], doc.Operations[1], doc.Operations[2], doc.Operations[3]
	if get.Method != "GET" || get.Path != "/users/42?expand=orders" {
		t.Errorf("get = %s %s", get.Method, get.Path)
	}
	headers := map[string]string{}
	for _, h := range get.Header {
		headers[h.Name] = h.Value
	}
	if headers["X-Trace"] != "abc" || headers["X-Off"] != "" || headers["Authorization"] != "Bearer token" {
		t.Errorf("headers = %v (disabled dropped; collection bearer inherited, undefined {{token}} as its name)", headers)
	}
	if create.ContentType != "application/json" || string(create.Body) != `{"name":"name"}` {
		t.Errorf("create body = %q %q", create.ContentType, create.Body)
	}
	if login.ContentType != "application/x-www-form-urlencoded" || string(login.Body) != "user=a+b" {
		t.Errorf("login body = %q %q", login.ContentType, login.Body)
	}
	for _, h := range login.Header {
		if h.Name == "Authorization" {
			t.Error("noauth on the request must override the collection's bearer")
		}
	}
	if gql.Path != "/graphql" || !strings.Contains(string(gql.Body), `"variables":{"a":1}`) {
		t.Errorf("graphql = %s %q", gql.Path, gql.Body)
	}
	if strings.Join(doc.Servers, ",") != "https://api.shop.test,https://auth.shop.test" {
		t.Errorf("servers = %v", doc.Servers)
	}
	if doc.PlaceholderValues() == 0 {
		t.Error("undefined variables must be counted as placeholders")
	}
}
