package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The published OpenAPI document (burpsy-react-ui-pg5a).
//
// The document is GENERATED from the two declarations that already have to be true — the route
// manifest (route_manifest.go: pattern, verbs, summary, risk) and the route schema table
// (route_schemas.go: the handler's own request type, query parameters, and declared response
// type) — so it cannot drift from the server it describes without one of the tests here failing.
// A hand-written openapi.yaml would be a third declaration nothing checks, exactly the failure
// route_schema.go's header comment argues against.

// openAPIPathItem is one path entry in the parsed document.
type openAPIPathItem map[string]json.RawMessage

func parseOpenAPI(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the served document is not JSON: %v", err)
	}
	return doc
}

func serveOpenAPI(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// GET /api/openapi.json serves an OpenAPI 3.1 document over the real mux.
func TestOpenAPIDocumentIsServed(t *testing.T) {
	s := newTestServer()
	rec := serveOpenAPI(t, s)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/openapi.json answered %d: %.200s", rec.Code, rec.Body.String())
	}
	doc := parseOpenAPI(t, rec.Body.Bytes())
	if doc["openapi"] != "3.1.0" {
		t.Errorf("openapi = %v, want 3.1.0", doc["openapi"])
	}
	info, _ := doc["info"].(map[string]any)
	if info["title"] == "" || info["version"] == "" {
		t.Errorf("info = %v, want a title and version", info)
	}
	paths, _ := doc["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Error("the document publishes no paths")
	}
}

// Every route in the manifest appears in the document with exactly its declared verbs, and every
// path in the document resolves back to a manifest pattern — neither side can drop or invent one.
func TestOpenAPICoversEveryManifestRoute(t *testing.T) {
	doc := openAPIDocument()
	paths, _ := doc["paths"].(map[string]any)

	// patternInDoc collects the document paths a manifest pattern is expected to produce.
	covered := map[string]bool{}
	var failures []string
	for _, pattern := range sortedKeys(manifest) {
		spec := manifest[pattern]
		if pattern == "/" {
			continue // the console's static assets are not an API surface
		}
		var expect []string
		for path := range expectedOpenAPIPaths(pattern, spec) {
			expect = append(expect, path)
		}
		for _, path := range expect {
			rawItem, ok := paths[path]
			if !ok {
				failures = append(failures, pattern+" produced no document path "+path)
				continue
			}
			covered[path] = true
			item, _ := rawItem.(map[string]any)
			for _, method := range expectedOpenAPIMethods(pattern, path, spec) {
				if _, ok := item[strings.ToLower(method)]; !ok {
					failures = append(failures, path+" is missing the manifest's "+method+" operation")
				}
			}
		}
	}
	for _, key := range sortedKeys(routeSchemas) {
		spec := routeSchemas[key]
		if len(spec.variants) == 0 {
			continue
		}
		_, pattern, _ := strings.Cut(key, " ")
		pattern = oracleSubtree(pattern)
		for _, variantKey := range sortedKeys(spec.variants) {
			if strings.HasPrefix(variantKey, "?") {
				continue
			}
			concrete := concretePath(pattern, variantKey)
			segments := strings.Split(concrete, "/")
			for j, segment := range segments {
				if isNumericID(segment) {
					wildcard := "id"
					if i := strings.Index(pattern, "{"); i >= 0 {
						wildcard = pattern[i+1 : strings.Index(pattern, "}")]
					}
					segments[j] = "{" + wildcard + "}"
				}
			}
			covered[strings.Join(segments, "/")] = true
		}
	}
	for path := range paths {
		if !covered[path] {
			failures = append(failures, "document path "+path+" names no manifest route")
		}
	}
	if len(failures) > 0 {
		t.Errorf("%d manifest/document disagreements:\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
}

// A subtree path parameter is declared on every operation the templated path carries.
func TestOpenAPISubtreePathsDeclareTheirIDParameter(t *testing.T) {
	doc := openAPIDocument()
	paths, _ := doc["paths"].(map[string]any)
	for path, rawItem := range paths {
		if !strings.Contains(path, "{id}") {
			continue
		}
		item, _ := rawItem.(map[string]any)
		for method, rawOp := range item {
			op, _ := rawOp.(map[string]any)
			params, _ := op["parameters"].([]any)
			found := false
			for _, rawParam := range params {
				param, _ := rawParam.(map[string]any)
				if param["name"] == "id" && param["in"] == "path" && param["required"] == true {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s: the {id} in the path has no required path parameter", strings.ToUpper(method), path)
			}
		}
	}
}

// The published request body and query parameters for every route-verb are byte-identical to what
// MCPSchemaFor — the agent surface's own view — publishes. One generator, two renderings.
func TestOpenAPIRequestsMatchTheRouteSchemaTable(t *testing.T) {
	doc := openAPIDocument()
	paths, _ := doc["paths"].(map[string]any)
	for _, key := range sortedKeys(routeSchemas) {
		method, pattern, _ := strings.Cut(key, " ")
		want, ok := MCPSchemaFor(method, pattern)
		if !ok {
			continue
		}
		if len(routeSchemas[key].variants) > 0 {
			continue // variant bodies are asserted per action path by the variants test below
		}
		op := openAPIOperationFor(t, paths, method, pattern)
		if op == nil {
			continue // an asset route, covered or exempted elsewhere
		}
		if want.Body != nil {
			body, _ := op["requestBody"].(map[string]any)
			content, _ := body["content"].(map[string]any)
			jsonMedia, _ := content["application/json"].(map[string]any)
			gotSchema, _ := json.Marshal(jsonMedia["schema"])
			wantSchema, _ := json.Marshal(want.Body)
			if !bytes.Equal(gotSchema, wantSchema) {
				t.Errorf("%s: the document's request body schema differs from MCPSchemaFor's", key)
			}
			if required, _ := body["required"].(bool); required != want.BodyRequired {
				t.Errorf("%s: requestBody.required = %v, the table says %v", key, required, want.BodyRequired)
			}
		}
		if want.Query != nil {
			params, _ := op["parameters"].([]any)
			declared := map[string]bool{}
			for _, rawParam := range params {
				param, _ := rawParam.(map[string]any)
				if param["in"] == "query" {
					name, _ := param["name"].(string)
					declared[name] = true
				}
			}
			props, _ := want.Query["properties"].(map[string]any)
			for name := range props {
				if !declared[name] {
					t.Errorf("%s: query parameter %q is in the route table but not the document", key, name)
				}
			}
		}
	}
}

// openAPIOperationFor finds the operation a "VERB /pattern" declaration landed on, following the
// same subtree templating the coverage test asserts.
func openAPIOperationFor(t *testing.T, paths map[string]any, method, pattern string) map[string]any {
	t.Helper()
	var candidates []string
	if spec, ok := manifest[pattern]; ok {
		for path := range expectedOpenAPIPaths(pattern, spec) {
			candidates = append(candidates, path)
		}
	} else {
		candidates = []string{pattern}
	}
	for _, path := range candidates {
		rawItem, ok := paths[path]
		if !ok {
			continue
		}
		item, _ := rawItem.(map[string]any)
		if op, ok := item[strings.ToLower(method)]; ok {
			typed, _ := op.(map[string]any)
			return typed
		}
	}
	return nil
}

// An action-path operation of a subtree with variants publishes its own variant's body — the exact
// branch, not the pattern's anyOf — and an action that takes no body publishes none.
func TestOpenAPIActionVariantsPublishTheirOwnBody(t *testing.T) {
	doc := openAPIDocument()
	paths, _ := doc["paths"].(map[string]any)
	for _, key := range sortedKeys(routeSchemas) {
		spec := routeSchemas[key]
		if len(spec.variants) == 0 {
			continue
		}
		method, pattern, _ := strings.Cut(key, " ")
		pattern = oracleSubtree(pattern)
		for variantKey, variantType := range spec.variants {
			concrete := pattern
			if !strings.HasPrefix(variantKey, "?") {
				concrete = concretePath(pattern, variantKey)
			}
			segments := strings.Split(concrete, "/")
			for j, segment := range segments {
				if isNumericID(segment) {
					wildcard := "id"
					if i := strings.Index(pattern, "{"); i >= 0 {
						wildcard = pattern[i+1 : strings.Index(pattern, "}")]
					}
					segments[j] = "{" + wildcard + "}"
				}
			}
			path := strings.Join(segments, "/")
			item, ok := paths[path]
			if !ok {
				t.Errorf("%s variant %q: no document path %s", key, variantKey, path)
				continue
			}
			typedItem, _ := item.(map[string]any)
			rawOp, ok := typedItem[strings.ToLower(method)]
			if !ok {
				t.Errorf("%s variant %q: no %s operation on %s", key, variantKey, method, path)
				continue
			}
			op, _ := rawOp.(map[string]any)
			body, hasBody := op["requestBody"].(map[string]any)
			if variantType == nil {
				if hasBody {
					t.Errorf("%s variant %q takes no body, but %s publishes one", key, variantKey, path)
				}
				continue
			}
			if !hasBody {
				t.Errorf("%s variant %q declares a body, but %s publishes none", key, variantKey, path)
				continue
			}
			content, _ := body["content"].(map[string]any)
			media, _ := content["application/json"].(map[string]any)
			published, _ := media["schema"].(map[string]any)
			wantSchema, _ := jsonSchemaOf(variantType)
			want, _ := json.Marshal(wantSchema)
			got, _ := json.Marshal(published)
			if bytes.Equal(got, want) {
				continue
			}
			// On a base path with several query- or empty-keyed bodies the published schema is an
			// anyOf; this variant must be one of its branches.
			branches, _ := published["anyOf"].([]any)
			found := false
			for _, branch := range branches {
				// A published branch carries a title the reflected schema does not; compare without it.
				branchMap, _ := branch.(map[string]any)
				delete(branchMap, "title")
				gotBranch, _ := json.Marshal(branchMap)
				if bytes.Equal(gotBranch, want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s variant %q: the published body is neither the declared variant type's schema nor an anyOf containing it", key, variantKey)
			}
		}
	}
}

// Every declared response type reflects to a complete schema — no unresolved members — and the
// document publishes exactly that schema on the route's 200. A declaration that names a type the
// generator cannot describe fails here rather than shipping a guess.
func TestOpenAPIDeclaredResponsesResolveAndPublish(t *testing.T) {
	doc := openAPIDocument()
	paths, _ := doc["paths"].(map[string]any)
	declared := 0
	for _, key := range sortedKeys(routeSchemas) {
		spec := routeSchemas[key]
		if spec.response == nil {
			continue
		}
		declared++
		schema, unresolved := jsonSchemaOf(spec.response)
		if len(unresolved) > 0 {
			t.Errorf("%s: the declared response type does not resolve: %s", key, strings.Join(unresolved, "; "))
			continue
		}
		method, pattern, _ := strings.Cut(key, " ")
		op := openAPIOperationFor(t, paths, method, pattern)
		if op == nil {
			t.Errorf("%s: declares a response but has no operation in the document", key)
			continue
		}
		responses, _ := op["responses"].(map[string]any)
		ok200, _ := responses["200"].(map[string]any)
		content, _ := ok200["content"].(map[string]any)
		media, _ := content["application/json"].(map[string]any)
		got, _ := json.Marshal(media["schema"])
		want, _ := json.Marshal(schema)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the document's 200 schema differs from the declared response type's", key)
		}
	}
	if declared == 0 {
		t.Error("no route declares its response type yet — the typed client this feeds would type every answer as unknown")
	}
}

// The document is a function of two sorted tables, so two builds are byte-identical; the UI's
// --check gate depends on it.
func TestOpenAPIDocumentIsStable(t *testing.T) {
	first, err := OpenAPIJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := OpenAPIJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two builds of the document differ")
	}
	if !json.Valid(first) {
		t.Error("the document is not valid JSON")
	}
}

// The risk class rides each operation, so a generated client — and the human reading the raw
// document — can tell a read from an attack without cross-referencing the manifest.
func TestOpenAPIOperationsCarryTheirRiskClass(t *testing.T) {
	doc := openAPIDocument()
	paths, _ := doc["paths"].(map[string]any)
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for method, rawOp := range item {
			op, _ := rawOp.(map[string]any)
			risk, _ := op["x-burpsy-risk"].(string)
			if risk == "" {
				t.Errorf("%s %s carries no x-burpsy-risk", strings.ToUpper(method), path)
			}
		}
	}
}

// expectedOpenAPIPaths is the test's own derivation of the paths a manifest pattern publishes —
// written against the rule, not against the implementation, so a disagreement in either direction
// fails the coverage test:
//
//   - a plain pattern publishes itself;
//   - a subtree pattern (trailing "/") publishes its example subPath and every action path, each
//     appended, with every all-numeric segment templated to {id};
//   - a wildcard pattern ("/api/message/{id}") publishes itself plus its action paths substituted
//     through the wildcard, numeric segments templated back to the wildcard's own name.
func expectedOpenAPIPaths(pattern string, spec route) map[string]bool {
	out := map[string]bool{}
	// A trailing remainder wildcard publishes as the trailing-slash subtree it replaced.
	if strings.HasSuffix(pattern, "...}") {
		pattern = pattern[:strings.LastIndex(pattern, "/")+1]
	}
	template := func(sub string) string {
		var concrete string
		wildcard := "id"
		if i := strings.Index(pattern, "{"); i >= 0 {
			wildcard = pattern[i+1 : strings.Index(pattern, "}")]
			concrete = pattern[:i] + sub + pattern[strings.Index(pattern, "}")+1:]
		} else {
			concrete = pattern + sub
		}
		if strings.Contains(pattern, "{") && strings.HasSuffix(pattern, "/") {
			concrete = strings.TrimSuffix(concrete, "/")
		}
		segments := strings.Split(concrete, "/")
		for j, segment := range segments {
			if isNumericID(segment) {
				segments[j] = "{" + wildcard + "}"
			}
		}
		return strings.Join(segments, "/")
	}
	switch {
	case strings.HasSuffix(pattern, "/"):
		if spec.subPath != "" {
			out[template(spec.subPath)] = true
		}
		for _, suffix := range sortedKeys(spec.actionPaths) {
			out[template(suffix)] = true
		}
	case strings.Contains(pattern, "{"):
		out[pattern] = true
		for _, suffix := range sortedKeys(spec.actionPaths) {
			out[template(suffix)] = true
		}
	default:
		out[pattern] = true
	}
	return out
}

// expectedOpenAPIMethods is the verb set one published path answers: the pattern's own methods for
// its base path, an action path's own verb set for its path.
func expectedOpenAPIMethods(pattern, path string, spec route) []string {
	for _, suffix := range sortedKeys(spec.actionPaths) {
		concrete := concretePath(pattern, suffix)
		segments := strings.Split(concrete, "/")
		for j, segment := range segments {
			if isNumericID(segment) {
				wildcard := "id"
				if i := strings.Index(pattern, "{"); i >= 0 {
					wildcard = pattern[i+1 : strings.Index(pattern, "}")]
				}
				segments[j] = "{" + wildcard + "}"
			}
		}
		if strings.Join(segments, "/") == path {
			return spec.actionPaths[suffix]
		}
	}
	return spec.methods
}

func isNumericID(segment string) bool {
	if segment == "" {
		return false
	}
	for _, r := range segment {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// The operation ids are unique across the document — a generator keys on them.
func TestOpenAPIOperationIDsAreUnique(t *testing.T) {
	doc := openAPIDocument()
	paths, _ := doc["paths"].(map[string]any)
	seen := map[string]string{}
	var dups []string
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for method, rawOp := range item {
			op, _ := rawOp.(map[string]any)
			id, _ := op["operationId"].(string)
			if id == "" {
				dups = append(dups, path+" "+method+" has no operationId")
				continue
			}
			if prev, ok := seen[id]; ok {
				dups = append(dups, id+" on both "+prev+" and "+method+" "+path)
			}
			seen[id] = method + " " + path
		}
	}
	sort.Strings(dups)
	if len(dups) > 0 {
		t.Errorf("operation ids are not unique:\n  %s", strings.Join(dups, "\n  "))
	}
}

// A declared response type is the handler's own: the declaration names the type writeJSON is handed
// on the success path. The reflect import pins the field's shape for readers of route_schemas.go.
func TestOpenAPIResponseDeclarationsAreTypes(t *testing.T) {
	for _, key := range sortedKeys(routeSchemas) {
		if response := routeSchemas[key].response; response != nil && response.Kind() == reflect.Invalid {
			t.Errorf("%s: response is not a reflectable type", key)
		}
	}
}

// oracleSubtree restates how a trailing remainder wildcard publishes: as the trailing-slash subtree
// it replaced. The document tests keep their own oracle instead of calling the generator's helper.
func oracleSubtree(pattern string) string {
	if strings.HasSuffix(pattern, "...}") {
		return pattern[:strings.LastIndex(pattern, "/")+1]
	}
	return pattern
}
