package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/dash"
)

// ---- API-only scan (Burp's fourth scan kind) ----------------------------------------------------
//
// These pin the launch surface and not the engine. What the run *sends* is internal/crawler's
// seeds-only behaviour, asserted there; what is new here is the document, and the document is where
// every interesting failure lives — a file that cannot be read, one that names no host, one that names
// a host nobody authorised. A launch surface that got any of those wrong would send traffic the
// operator never described, which is why each of them is its own test rather than one "invalid input"
// case.
//
// The refusals are asserted on their *words*. A 400 that said "invalid definition" would satisfy every
// status-code check while telling an operator nothing about their file, and the messages here name the
// document's actual flavour (AsyncAPI, Postman, Swagger 1.x) precisely because "not OpenAPI" does not.

// apiScanHit is one request the test target received, with the two things a definition supplies beyond
// a path: the method, and the body.
type apiScanHit struct {
	method string
	uri    string
	body   string
	apiKey string
}

// newAPIScanTarget records every request it is given and answers JSON with a link in it, so a scan
// that traversed would visibly ask for the link as well.
func newAPIScanTarget(t *testing.T) (*httptest.Server, *[]apiScanHit) {
	t.Helper()
	hits := &[]apiScanHit{}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		mu.Lock()
		*hits = append(*hits, apiScanHit{
			method: r.Method, uri: r.URL.RequestURI(), body: string(body[:n]), apiKey: r.Header.Get("X-Api-Key"),
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"link":"http://%s/should-not-be-fetched"}`, r.Host)
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

// apiScan launches a definition and returns the decoded 202 body, or fails with the server's own
// refusal text so a test that expected acceptance shows what it got instead.
func apiScan(t *testing.T, s *Server, body map[string]any) map[string]any {
	t.Helper()
	rec := postJSON(t, s, "/api/apiscan", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode reply: %v (%s)", err, rec.Body.String())
	}
	return out
}

// apiScanRefusal posts a launch expected to be refused and returns the status and message.
func apiScanRefusal(t *testing.T, s *Server, body map[string]any) (int, string) {
	t.Helper()
	rec := postJSON(t, s, "/api/apiscan", body)
	if rec.Code == http.StatusAccepted {
		t.Fatalf("the launch was accepted; body: %s", rec.Body.String())
	}
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

// waitForTaskKind waits for a task of the given kind to appear and finish, which is how a launch's
// asynchronous half is observed. A scan is asynchronous by design here — it outlives the request — so
// asserting on the reply alone would only ever test the hand-off.
func waitForTaskKind(t *testing.T, s *Server, kind string) (string, string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, task := range s.tasks.Snapshot() {
			if string(task.Kind) != kind {
				continue
			}
			if task.State != dash.TaskRunning {
				return task.Target, task.Note
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no finished %s task appeared", kind)
	return "", ""
}

// A definition document is a description of requests, and the scan must send *those* requests: the
// methods, the query values the document supplied, the header it declared, and a body built from its
// schema. This is the one test that would fail if the launch reduced a document to a list of paths.
func TestAnAPIScanSendsTheRequestsTheDefinitionDescribes(t *testing.T) {
	target, hits := newAPIScanTarget(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")

	doc := fmt.Sprintf(`{
	  "openapi": "3.0.3",
	  "info": {"title": "Petstore", "version": "1.0.2"},
	  "servers": [{"url": %q}],
	  "paths": {
	    "/pets": {
	      "get": {"parameters": [
	        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 20}}
	      ], "responses": {"200": {"description": "ok"}}},
	      "post": {
	        "parameters": [{"name": "X-Api-Key", "in": "header", "example": "from-the-document"}],
	        "requestBody": {"content": {"application/json": {"schema": {
	          "type": "object", "properties": {"name": {"type": "string", "example": "Rex"}}
	        }}}},
	        "responses": {"201": {"description": "created"}}
	      }
	    },
	    "/pets/{petId}": {
	      "delete": {"parameters": [{"name": "petId", "in": "path", "required": true, "schema": {"type": "integer"}}],
	        "responses": {"204": {"description": "gone"}}}
	    }
	  }
	}`, target.URL+"/api/v1")

	body := apiScan(t, s, map[string]any{"definition": doc, "audit": false})
	if got := body["kind"]; got != "api-scan" {
		t.Errorf("kind = %v, want api-scan; the run and the task row must say which of the four scan kinds ran", got)
	}
	definition, _ := body["definition"].(map[string]any)
	if definition == nil {
		t.Fatal("the reply carries no definition summary; the operator cannot then check what was read")
	}
	if got := definition["base_url"]; got != target.URL+"/api/v1" {
		t.Errorf("base_url = %v, want the document's own server", got)
	}

	waitForTaskKind(t, s, "api-scan")

	byURI := map[string]apiScanHit{}
	for _, h := range *hits {
		byURI[h.method+" "+h.uri] = h
	}
	if len(byURI) != 3 {
		t.Fatalf("expected three endpoints sent, got %d: %+v", len(byURI), *hits)
	}
	// A path parameter the document types as an integer becomes the recognisable placeholder 1 — the
	// same value an operator would type, and visibly not data from the API.
	if _, ok := byURI["DELETE /api/v1/pets/1"]; !ok {
		t.Errorf("the path parameter was not substituted; the target saw %+v", *hits)
	}
	get, ok := byURI["GET /api/v1/pets?limit=20"]
	if !ok {
		t.Errorf("the query parameter's default was not sent; the target saw %+v", *hits)
	}
	if get.body != "" {
		t.Errorf("a GET carried a body: %q", get.body)
	}
	post, ok := byURI["POST /api/v1/pets"]
	if !ok {
		t.Fatalf("the document's POST was not sent; the target saw %+v", *hits)
	}
	if post.apiKey != "from-the-document" {
		t.Errorf("the declared header parameter was not sent: %q", post.apiKey)
	}
	if !strings.Contains(post.body, `"name":"Rex"`) {
		t.Errorf("the body was not built from the schema's example: %q", post.body)
	}
	for _, h := range *hits {
		if strings.Contains(h.uri, "should-not-be-fetched") {
			t.Error("the scan followed a link out of a JSON response body; a definition sweep's surface is the document")
		}
		if h.uri == "/robots.txt" {
			t.Error("the scan probed robots.txt; the probe is a request the definition did not describe")
		}
	}
}

// The dry run is what makes the wizard's API step possible, and its defining property is that it
// starts *nothing*. A check that registered a task would leave a row behind on the dashboard for work
// that was never asked for.
func TestAnAPIScanDryRunReportsWithoutStartingAnything(t *testing.T) {
	target, hits := newAPIScanTarget(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")

	doc := fmt.Sprintf(`{"openapi":"3.0.3","info":{"title":"Petstore","version":"1"},
	  "servers":[{"url":%q}],"paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`, target.URL)

	rec := postJSON(t, s, "/api/apiscan", map[string]any{"definition": doc, "dry_run": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s) — a dry run accepts nothing, because it starts nothing", rec.Code, rec.Body.String())
	}
	var body struct {
		DryRun     bool `json:"dry_run"`
		Definition struct {
			Title        string           `json:"title"`
			BaseURL      string           `json:"base_url"`
			Declared     int              `json:"declared_values"`
			Placeholders int              `json:"placeholder_values"`
			Note         string           `json:"placeholder_note"`
			Operations   []map[string]any `json:"operations"`
		} `json:"definition"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode reply: %v (%s)", err, rec.Body.String())
	}
	if !body.DryRun {
		t.Error("the reply does not say it was a dry run; a caller holding only a summary cannot tell it from an acceptance")
	}
	if body.Definition.Title != "Petstore" || body.Definition.BaseURL != target.URL {
		t.Errorf("the summary does not describe the document it read: %+v", body.Definition)
	}
	if len(body.Definition.Operations) != 1 {
		t.Errorf("operations = %d, want 1", len(body.Definition.Operations))
	}
	// A dry run answers with a summary and nothing a caller could follow: no task id, because there is
	// no task. Decoded generically because the absence of a key is the claim.
	var generic map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &generic); err != nil {
		t.Fatalf("decode reply as a map: %v", err)
	}
	if _, hasTask := generic["task_id"]; hasTask {
		t.Error("a dry run answered with a task id")
	}
	if len(s.tasks.Snapshot()) != 0 {
		t.Errorf("a dry run registered a task: %+v", s.tasks.Snapshot())
	}
	time.Sleep(150 * time.Millisecond)
	if len(*hits) != 0 {
		t.Errorf("a dry run sent traffic: %+v", *hits)
	}
}

// Every document this build cannot read is refused by what it actually is. The failure this prevents is
// a loader that reads an unreadable file as an empty one and reports "0 endpoints" — which reads as an
// empty API rather than as a document nobody could read, and sends the operator to the wrong place.
func TestAnAPIScanRefusesADocumentItCannotRead(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"an AsyncAPI document", `{"asyncapi":"2.0.0","channels":{}}`, "AsyncAPI"},
		{"a Postman collection", `{"info":{"name":"c"},"item":[]}`, "Postman"},
		{"a Swagger 1.x document", `{"swagger":"1.2","apis":[]}`, "Swagger 1.2"},
		{"a future OpenAPI", `{"openapi":"4.0.0","paths":{}}`, "OpenAPI 4.0.0"},
		{"something that is not a definition at all", `{"hello":"world"}`, "not an OpenAPI or Swagger document"},
		{"a document with no paths", `{"openapi":"3.0.3","info":{"title":"X","version":"1"},"servers":[{"url":"http://127.0.0.1:1"}]}`, "no `paths` object"},
		{"a paths object with no operations", `{"openapi":"3.0.3","info":{"title":"X","version":"1"},"servers":[{"url":"http://127.0.0.1:1"}],"paths":{"/a":{}}}`, "no operations"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, message := apiScanRefusal(t, s, map[string]any{"definition": tc.doc})
			if code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", code)
			}
			if !strings.Contains(message, tc.want) {
				t.Errorf("refusal must name what the document is; want %q in: %s", tc.want, message)
			}
			if len(s.tasks.Snapshot()) != 0 {
				t.Errorf("a refused document registered a task: %+v", s.tasks.Snapshot())
			}
		})
	}
}

// A document with no host and no base URL supplied is refused, not scanned against a guess. A guessed
// host is traffic to somebody nobody named, and the scope gate would answer only if the operator were
// lucky enough to have configured one that happens to exclude it.
func TestAnAPIScanRefusesADefinitionThatNamesNoHost(t *testing.T) {
	s := newTestServer()
	doc := `{"openapi":"3.0.3","info":{"title":"X","version":"1"},
	  "paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	code, message := apiScanRefusal(t, s, map[string]any{"definition": doc})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(message, "base URL") {
		t.Errorf("the refusal must ask for the base URL by name; got: %s", message)
	}

	// A relative server URL is the same case: a pasted document has no host to be relative to, and
	// guessing one from the operator's proxy would be a different kind of guess, not a fix.
	relative := `{"openapi":"3.0.3","info":{"title":"X","version":"1"},"servers":[{"url":"/api/v1"}],
	  "paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	if _, message := apiScanRefusal(t, s, map[string]any{"definition": relative}); !strings.Contains(message, "relative") {
		t.Errorf("a relative server URL must be refused with the reason; got: %s", message)
	}
}

// A document pointing at a host no scope rule can reach is refused before the task exists, and the
// refusal quotes the scope's own explanation. The alternative is a twelve-endpoint sweep that is
// twelve refusals, which the operator would have to read a report to discover.
func TestAnAPIScanRefusesAHostNoScopeRuleCanReach(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("allowed.test")
	doc := `{"openapi":"3.0.3","info":{"title":"X","version":"1"},"servers":[{"url":"https://not-allowed.test/v1"}],
	  "paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

	code, message := apiScanRefusal(t, s, map[string]any{"definition": doc})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	for _, want := range []string{"out of scope", "not-allowed.test", "matches no include rule"} {
		if !strings.Contains(message, want) {
			t.Errorf("refusal %q does not mention %q; the operator needs to know which host and which rule", message, want)
		}
	}
	if len(s.tasks.Snapshot()) != 0 {
		t.Error("an out-of-scope document registered a task; it must not appear as work at all")
	}
}

// Two operations declaring one header with different values cannot both be sent on one request, and
// this build will not quietly pick one: the scan exists to answer "does my API behave under its own
// contract", and a contract this build silently rewrote is not that contract.
func TestAnAPIScanRefusesOneHeaderDeclaredTwiceWithTwoValues(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	doc := `{"openapi":"3.0.3","info":{"title":"X","version":"1"},"servers":[{"url":"http://127.0.0.1:1"}],
	  "paths":{"/a":{"get":{"parameters":[
	    {"name":"X-Api-Key","in":"header","example":"one"},
	    {"name":"X-Api-Key","in":"header","example":"two"}
	  ],"responses":{"200":{"description":"ok"}}}}}}`

	code, message := apiScanRefusal(t, s, map[string]any{"definition": doc})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	for _, want := range []string{"X-Api-Key", `"one"`, `"two"`} {
		if !strings.Contains(message, want) {
			t.Errorf("refusal %q does not mention %q; it must name the header and both values", message, want)
		}
	}
}

// The definition travels back out on the retained run, because "which endpoints did this scan send"
// is a question asked after the launch reply is long gone — and because a scan whose record named only
// a count could not be checked against the document at all.
func TestTheRunRecordCarriesTheDefinitionTheScanUsed(t *testing.T) {
	target, _ := newAPIScanTarget(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	doc := fmt.Sprintf(`{"openapi":"3.0.3","info":{"title":"Petstore","version":"1.0.2"},"servers":[{"url":%q}],
	  "paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}},
	           "/b":{"post":{"responses":{"201":{"description":"made"}}}}}}`, target.URL)

	body := apiScan(t, s, map[string]any{"definition": doc, "audit": false})
	task := uint64(body["task_id"].(float64))

	rec := get(t, s, fmt.Sprintf("/api/crawl?task=%d", task))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/crawl?task=%d: status = %d (%s)", task, rec.Code, rec.Body.String())
	}
	var run struct {
		Kind       string   `json:"kind"`
		Seeds      []string `json:"seeds"`
		Definition *struct {
			Title      string           `json:"title"`
			Operations []map[string]any `json:"operations"`
		} `json:"definition"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v (%s)", err, rec.Body.String())
	}
	if run.Kind != "api-scan" {
		t.Errorf("kind = %q, want api-scan; a run read back tomorrow must still say which scan it was", run.Kind)
	}
	if run.Definition == nil {
		t.Fatal("the run record carries no definition")
	}
	if run.Definition.Title != "Petstore" {
		t.Errorf("definition.title = %q, want Petstore", run.Definition.Title)
	}
	if len(run.Definition.Operations) != 2 {
		t.Errorf("operations = %d, want 2", len(run.Definition.Operations))
	}
	// The seeds are the resolved request URLs, so the field that answers "what did this scan point at"
	// answers it for both scan kinds rather than being blank for this one.
	if len(run.Seeds) != 2 {
		t.Errorf("seeds = %v, want the two resolved endpoint URLs", run.Seeds)
	}
}

// A cancelled sweep reports its endpoint count as *not sent* rather than quietly finishing short, and
// the row says how many were left. A definition with more endpoints than the operator's cap is the
// ordinary way this happens, so the cap is the mechanism under test.
func TestAnAPIScanThatIsCappedSaysHowManyEndpointsWereNeverSent(t *testing.T) {
	target, _ := newAPIScanTarget(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	doc := fmt.Sprintf(`{"openapi":"3.0.3","info":{"title":"Petstore","version":"1"},"servers":[{"url":%q}],
	  "paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}},
	           "/b":{"get":{"responses":{"200":{"description":"ok"}}}},
	           "/c":{"get":{"responses":{"200":{"description":"ok"}}}}}}`, target.URL)

	body := apiScan(t, s, map[string]any{"definition": doc, "audit": false, "max_requests": 1})
	task := uint64(body["task_id"].(float64))
	_, note := waitForTaskKind(t, s, "api-scan")

	if !strings.Contains(note, "never sent") {
		t.Errorf("note = %q; a capped sweep must say it did not reach the end of its list, or 1 fetched reads as a "+
			"one-endpoint API", note)
	}

	rec := get(t, s, fmt.Sprintf("/api/crawl?task=%d", task))
	var run struct {
		Report struct {
			Fetched int `json:"fetched"`
			Limits  struct {
				FrontierRemaining int      `json:"frontier_remaining"`
				Reasons           []string `json:"reasons"`
			} `json:"limits"`
		} `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v (%s)", err, rec.Body.String())
	}
	if run.Report.Fetched != 1 {
		t.Errorf("fetched = %d, want 1", run.Report.Fetched)
	}
	if run.Report.Limits.FrontierRemaining != 2 {
		t.Errorf("frontier_remaining = %d, want 2 — the two endpoints the cap excluded are the report's only "+
			"way to distinguish a capped sweep from a short document", run.Report.Limits.FrontierRemaining)
	}
}

// The GET on this path is a 405, which is what the route manifest's verb sweep asserts. Spelled out
// here as well because the temptation is real: every other scan door in this API is a GET/POST pair,
// and this one deliberately is not — the read door is /api/crawl, which serves the run record.
func TestTheAPIScanRouteAnswersOnlyPOST(t *testing.T) {
	s := newTestServer()
	if rec := get(t, s, "/api/apiscan"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/apiscan = %d, want 405; an API scan's record is read through /api/crawl, and a second "+
			"read door is a second answer to disagree with the first", rec.Code)
	}
}
