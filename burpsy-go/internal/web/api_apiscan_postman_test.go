package web

// An API scan launched from a Postman Collection (burpsy-react-ui-r39r) sends the collection's requests:
// methods, paths with their variables filled, query, headers and bodies.

import (
	"fmt"
	"testing"
)

func TestAnAPIScanSendsAPostmanCollectionsRequests(t *testing.T) {
	target, hits := newAPIScanTarget(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	doc := fmt.Sprintf(`{
	  "info": {"name": "Shop", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	  "variable": [{"key": "base", "value": %q}],
	  "item": [{"name": "f", "item": [
	    {"name": "list", "request": {"method": "GET", "url": "{{base}}/items?page=2", "header": [{"key": "X-Api-Key", "value": "k1"}]}},
	    {"name": "make", "request": {"method": "POST", "url": "{{base}}/items",
	      "body": {"mode": "raw", "raw": "{\"n\":1}", "options": {"raw": {"language": "json"}}}}}
	  ]}]
	}`, target.URL)
	body := apiScan(t, s, map[string]any{"definition": doc, "audit": false})
	definition, _ := body["definition"].(map[string]any)
	if definition == nil || definition["base_url"] != target.URL {
		t.Errorf("definition summary = %v, want the collection's own base", body["definition"])
	}
	waitForTaskKind(t, s, "api-scan")
	seen := map[string]apiScanHit{}
	for _, h := range *hits {
		seen[h.method+" "+h.uri] = h
	}
	if h, ok := seen["GET /items?page=2"]; !ok || h.apiKey != "k1" {
		t.Errorf("GET not sent as the collection wrote it: %+v", *hits)
	}
	if h, ok := seen["POST /items"]; !ok || h.body != `{"n":1}` {
		t.Errorf("POST body not sent: %+v", *hits)
	}
	if len(seen) != 2 {
		t.Errorf("want exactly the 2 collection requests, got %+v", *hits)
	}
}
