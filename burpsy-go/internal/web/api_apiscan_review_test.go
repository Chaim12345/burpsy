package web

// The API-details review step (burpsy-react-ui-vuw7): excluded endpoints are not sent, overridden
// values and the auth method reach the wire, the dry run returns each endpoint's parameters, and a
// Fixed parameter is kept out of the audit.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const reviewDoc = `{
  "openapi": "3.0.3", "info": {"title": "Pets", "version": "1"}, "servers": [{"url": %q}],
  "paths": {
    "/pets": {"get": {"parameters": [
      {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 20}},
      {"name": "q", "in": "query", "schema": {"type": "string", "example": "cat"}}
    ], "responses": {"200": {"description": "ok"}}}},
    "/pets/{petId}": {"delete": {"parameters": [{"name": "petId", "in": "path", "required": true, "schema": {"type": "integer"}}],
      "responses": {"204": {"description": "gone"}}}}
  }
}`

type reviewHit struct{ method, uri, auth string }

func reviewTarget(t *testing.T) (*httptest.Server, func() []reviewHit) {
	var mu sync.Mutex
	var hits []reviewHit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, reviewHit{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization")})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []reviewHit {
		mu.Lock()
		defer mu.Unlock()
		return append([]reviewHit(nil), hits...)
	}
}

func TestTheReviewStepShapesWhatAnAPIScanSends(t *testing.T) {
	target, hits := reviewTarget(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	doc := fmt.Sprintf(reviewDoc, target.URL)
	review := map[string]any{
		"definition":        doc,
		"exclude_endpoints": []string{"DELETE /pets/{petId}"},
		"parameters":        []map[string]any{{"in": "query", "name": "limit", "value": "5", "mode": "fixed"}},
		"auth":              map[string]any{"type": "bearer", "token": "t0k"},
	}
	// The dry run: what the review would send, with each endpoint's parameters.
	dry := map[string]any{"dry_run": true}
	for k, v := range review {
		dry[k] = v
	}
	rec := postJSON(t, s, "/api/apiscan", dry)
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("dry run = %d %s", rec.Code, rec.Body.String())
	}
	var preview struct {
		Definition struct {
			Operations []struct {
				Key        string `json:"key"`
				Path       string `json:"path"`
				Parameters []struct {
					Name, Value, Source string
				} `json:"parameters"`
			} `json:"operations"`
		} `json:"definition"`
	}
	json.Unmarshal(rec.Body.Bytes(), &preview)
	ops := preview.Definition.Operations
	if len(ops) != 1 || ops[0].Key != "GET /pets" || !strings.Contains(ops[0].Path, "limit=5") {
		t.Fatalf("preview = %+v", ops)
	}
	if strings.Contains(rec.Body.String(), `"parameters":null`) {
		t.Error("parameters went out as null")
	}

	apiScan(t, s, map[string]any{"definition": doc, "audit": false, "exclude_endpoints": review["exclude_endpoints"], "parameters": review["parameters"], "auth": review["auth"]})
	waitForTaskKind(t, s, "api-scan")
	got := hits()
	if len(got) != 1 || got[0].method != "GET" || !strings.Contains(got[0].uri, "limit=5") || got[0].auth != "Bearer t0k" {
		t.Errorf("the target saw %+v; want one GET with limit=5 and the bearer token, and no DELETE", got)
	}
	// Unknown review rows are refused by name.
	if rec := postJSON(t, s, "/api/apiscan", map[string]any{"definition": doc, "dry_run": true, "exclude_endpoints": []string{"PUT /nope"}}); rec.Code < 400 {
		t.Errorf("an unknown endpoint key was accepted: %d", rec.Code)
	}
}

func TestAFixedParameterIsNotAttackedByTheAudit(t *testing.T) {
	target, hits := reviewTarget(t)
	s := newTestServer()
	s.scope.AddInclude("127.0.0.1")
	doc := fmt.Sprintf(reviewDoc, target.URL)
	apiScan(t, s, map[string]any{
		"definition":        doc,
		"exclude_endpoints": []string{"DELETE /pets/{petId}"},
		"parameters":        []map[string]any{{"in": "query", "name": "limit", "value": "5", "mode": "fixed"}},
	})
	waitForTaskKind(t, s, "api-scan")
	waitForTaskKind(t, s, "audit")
	limitAttacked, qAttacked := false, false
	for _, h := range hits() {
		if !strings.Contains(h.uri, "limit=5") {
			limitAttacked = true
		}
		if strings.Contains(h.uri, "q=") && !strings.Contains(h.uri, "q=cat&") && !strings.HasSuffix(h.uri, "q=cat") {
			qAttacked = true
		}
	}
	if limitAttacked {
		t.Error("the audit sent a request with limit changed although the review fixed it")
	}
	if !qAttacked {
		t.Skip("the audit attacked neither parameter, so the fixed-parameter assertion proves nothing here")
	}
}
