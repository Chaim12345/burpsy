package web

// The OpenAPI 3.1 document for the console's API (burpsy-react-ui-pg5a).
//
// The document is GENERATED at request time from the two declarations the server already keeps
// honest — the route manifest (route_manifest.go: pattern, verbs, summary, risk class) and the
// route schema table (route_schemas.go: the handler's own request type, the query parameters it
// reads, and its declared response type) — served at GET /api/openapi.json, and dumped by
// cmd/openapi-dump for the UI's typed-client generator. A hand-written openapi.yaml would be a
// third declaration of the same facts, and nothing would check it; the tests in openapi_test.go
// prove document and server agree, which is the same argument route_schema.go makes for requests.
//
// What the document does NOT claim: a response shape for a route whose handler has no declared
// response type. Those operations publish an empty schema marked x-burpsy-declared: false, so a
// generated client types the answer as unknown rather than as a shape nobody verified. Declaring
// one is reading the handler's success write and naming the type it encodes — see the confirmed
// set in route_schemas.go.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"runtime/debug"
	"strings"
)

// openAPIVersion is the only 3.1 version string the document ever carries.
const openAPIVersion = "3.1.0"

// openAPIPath is one document path: the operations on it, keyed by lower-case method.
type openAPIPath struct {
	methods []string // upper-case, manifest order
}

// openAPIDocument builds the document. Exported within the package for the tests; the wire form
// comes from OpenAPIJSON.
func openAPIDocument() map[string]any {
	paths := map[string]any{}
	for _, pattern := range sortedKeys(manifest) {
		spec := manifest[pattern]
		if pattern == "/" {
			continue // the console's static assets are not an API surface
		}
		for path, methods := range openAPIPathsFor(pattern, spec) {
			item := map[string]any{}
			for _, method := range methods {
				item[strings.ToLower(method)] = openAPIOperation(method, pattern, path, spec)
			}
			paths[path] = item
		}
	}
	// Variants name requestable shapes the manifest does not enumerate: a subtree's handler branches
	// on an action segment ("POST /api/intercept/{id}/forward") without the manifest listing it as an
	// action path. The schema table's variant keys ARE the concrete sub-paths, so the document
	// publishes them; a key that starts "?" is a query-distinguished body on the base path and adds
	// no path.
	for _, key := range sortedKeys(routeSchemas) {
		spec := routeSchemas[key]
		if len(spec.variants) == 0 {
			continue
		}
		method, pattern, _ := strings.Cut(key, " ")
		routeSpec, ok := manifest[pattern]
		if !ok {
			continue
		}
		for _, variantKey := range sortedKeys(spec.variants) {
			if strings.HasPrefix(variantKey, "?") {
				continue
			}
			sub := subtreeSpelling(pattern)
			path := templateIDSegments(concretePath(sub, variantKey), sub)
			if _, ok := paths[path]; ok {
				continue // the manifest already publishes it; the variant body merges below
			}
			paths[path] = map[string]any{
				strings.ToLower(method): openAPIOperation(method, pattern, path, routeSpec),
			}
		}
	}
	return map[string]any{
		"openapi": openAPIVersion,
		"info": map[string]any{
			"title":   "burpsy console API",
			"version": openAPIVersionOf(),
			"description": "The console's whole HTTP surface, generated from the server's own route " +
				"manifest and schema table. Operations carry their risk class as x-burpsy-risk; a " +
				"route whose risk is not \"read\" requires a minted confirmation token " +
				"(X-Burpsy-Confirm) before it acts. Responses marked x-burpsy-declared: false have " +
				"no verified shape yet; treat them as unknown JSON.",
		},
		"paths": paths,
	}
}

// openAPIVersionOf names the build the document describes, so a generated client can be tied to a
// server build when a bug report pairs them. A binary built from a module proxy carries its version;
// a local build is "dev", which is honest.
func openAPIVersionOf() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// openAPIPathsFor derives the document paths one manifest pattern publishes, with the methods each
// answers. Subtree and wildcard patterns are not requestable URLs themselves; the manifest's
// subPath example and action paths are the concrete shapes callers send, so those — with their id
// segments templated — are what the document names.
func openAPIPathsFor(pattern string, spec route) map[string][]string {
	out := map[string][]string{}
	// A trailing remainder wildcard ("/api/datasets/{rest...}") is the subtree it replaced
	// ("/api/datasets/"): the document keeps naming the concrete sub-shapes callers send, not the
	// remainder spelling, so rekeying a route does not rewrite its published contract.
	pattern = subtreeSpelling(pattern)
	templated := func(sub string) string {
		path := templateIDSegments(concretePath(pattern, sub), pattern)
		if strings.Contains(pattern, "{") && strings.HasSuffix(pattern, "/") {
			// "/api/x/{id}/{action...}" spelled as the subtree "/api/x/{id}/": the sub-shape
			// already carries the action segment, so the pattern's own trailing slash is not part
			// of the published path.
			path = strings.TrimSuffix(path, "/")
		}
		return path
	}
	switch {
	case strings.HasSuffix(pattern, "/"):
		if spec.subPath != "" {
			out[templated(spec.subPath)] = append([]string(nil), spec.methods...)
		}
		for _, suffix := range sortedKeys(spec.actionPaths) {
			out[templated(suffix)] = append([]string(nil), spec.actionPaths[suffix]...)
		}
	case strings.Contains(pattern, "{"):
		// A wildcard pattern ("GET /api/message/{id}") is already a template; its subPath exists so
		// the sweeps have a concrete URL, and the published path keeps the wildcard.
		out[pattern] = append([]string(nil), spec.methods...)
		for _, suffix := range sortedKeys(spec.actionPaths) {
			out[templated(suffix)] = append([]string(nil), spec.actionPaths[suffix]...)
		}
	default:
		out[pattern] = append([]string(nil), spec.methods...)
	}
	return out
}

// subtreeSpelling maps a trailing remainder wildcard onto the trailing-slash subtree it replaced;
// any other pattern is returned unchanged.
func subtreeSpelling(pattern string) string {
	if strings.HasSuffix(pattern, "...}") {
		if i := strings.LastIndex(pattern, "/"); i >= 0 {
			return pattern[:i+1]
		}
	}
	return pattern
}

// templateIDSegments re-templates the concrete id segments of a path the manifest spelled out as an
// example ("1", "00100200", "1/run") back into path parameters. The parameter keeps the wildcard's
// own name when the pattern named one; under a plain subtree it is {id}.
func templateIDSegments(path, pattern string) string {
	wildcard := "id"
	if i := strings.Index(pattern, "{"); i >= 0 {
		wildcard = pattern[i+1 : strings.Index(pattern, "}")]
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "" {
			continue
		}
		numeric := true
		for _, r := range segment {
			if r < '0' || r > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			segments[i] = "{" + wildcard + "}"
		}
	}
	return strings.Join(segments, "/")
}

// openAPIOperation builds one operation. method and pattern address the route schema table; path is
// the published (templated) path, whose parameters the operation declares.
func openAPIOperation(method, pattern, path string, spec route) map[string]any {
	op := map[string]any{
		"operationId":   openAPIOperationID(method, path),
		"summary":       spec.summary,
		"x-burpsy-risk": string(spec.risk),
	}
	if spec.risk != riskRead && spec.risk != riskAsset {
		op["description"] = fmt.Sprintf("Risk class %s: an unattended caller must mint a confirmation "+
			"for the exact call (POST {pattern}/confirm) and spend it in the X-Burpsy-Confirm header.", spec.risk)
	}

	var params []any
	for _, name := range openAPIPathParams(path) {
		params = append(params, map[string]any{
			"name":     name,
			"in":       "path",
			"required": true,
			"schema":   map[string]any{"type": "string", "description": "the resource's id, as the console's URLs carry it"},
		})
	}
	if schema, ok := routeSchemas[method+" "+pattern]; ok {
		params = append(params, openAPIQueryParams(schema.query)...)
		if body := openAPIRequestBody(method, pattern, path, schema); body != nil {
			op["requestBody"] = body
		}
	}
	if len(params) > 0 {
		op["parameters"] = params
	}

	op["responses"] = openAPIResponses(method, pattern)
	return op
}

// openAPIPathParams lists the templated parameter names in a published path, in order.
func openAPIPathParams(path string) []string {
	var names []string
	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			names = append(names, segment[1:len(segment)-1])
		}
	}
	return names
}

// openAPIQueryParams renders the route table's query declarations as OpenAPI parameters.
func openAPIQueryParams(query []queryParam) []any {
	var params []any
	for _, q := range query {
		schema := map[string]any{"type": "string"}
		desc := q.desc
		switch q.kind {
		case "integer":
			schema["pattern"] = "^-?[0-9]+$"
			desc = strings.TrimSpace(desc + " (an integer)")
		case "boolean":
			schema["enum"] = []string{"true", "false", "1", "0"}
		}
		if len(q.enum) > 0 {
			schema["enum"] = q.enum
		}
		param := map[string]any{"name": q.name, "in": "query", "required": false, "schema": schema}
		if desc != "" {
			param["description"] = desc
		}
		params = append(params, param)
	}
	return params
}

// openAPIRequestBody renders the declared request body for one operation. An action-path operation
// of a subtree with variants publishes its own variant's body, not the pattern's anyOf — the anyOf
// is the MCP surface's answer to "one route-verb, several actions"; OpenAPI has one operation per
// action path, so each gets the exact branch.
func openAPIRequestBody(method, pattern, path string, spec opSchema) map[string]any {
	body := map[string]any{"required": !spec.optional}
	content := map[string]any{}
	media := func(schema map[string]any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": schema}}
	}
	switch {
	case len(spec.variants) > 0:
		variant, ok := openAPIVariantFor(path, pattern, spec)
		if ok {
			if variant == nil {
				return nil // this action takes no body
			}
			schema, _ := jsonSchemaOf(variant)
			content = media(schema)
			break
		}
		// No action sub-path matched. On the base path of a single-path route, the bodies keyed by
		// a query discriminator or the empty key are what a caller can send; several of them publish
		// as anyOf branches titled with their discriminator, the same framing MCPSchemaFor uses.
		if base := openAPIBaseVariants(path, pattern, spec); base != nil {
			content = media(base)
		} else {
			return nil
		}
	case spec.schema != nil:
		content = media(spec.schema())
	case spec.body != nil:
		schema, _ := jsonSchemaOf(spec.body)
		content = media(schema)
	case spec.raw != "":
		content = media(map[string]any{"description": spec.raw})
	default:
		return nil
	}
	body["content"] = content
	return body
}

// openAPIVariantFor matches a published action path back to its declared variant. Variant keys are
// concrete action sub-paths ("1/move"); the published path templated them.
func openAPIVariantFor(path, pattern string, spec opSchema) (reflect.Type, bool) {
	for _, key := range sortedKeys(spec.variants) {
		if key == "" || strings.HasPrefix(key, "?") {
			continue // a base-path discriminator, not an action sub-path; openAPIBaseVariants owns it
		}
		sub := subtreeSpelling(pattern)
		if templateIDSegments(concretePath(sub, key), sub) == path {
			return spec.variants[key], true
		}
	}
	return nil, false
}

// openAPIBaseVariants builds the request body schema for the base path of a single-path route with
// variants: the bodies keyed by the empty key or a query discriminator ("?id=1"), as one schema or
// an anyOf titled per discriminator. Nil when the route is a subtree or wildcard (whose base
// resource takes no action body) or no base-keyed variant exists.
func openAPIBaseVariants(path, pattern string, spec opSchema) map[string]any {
	if path != pattern || strings.HasSuffix(pattern, "/") || strings.Contains(pattern, "{") {
		return nil
	}
	var branches []any
	for _, key := range sortedKeys(spec.variants) {
		if key != "" && !strings.HasPrefix(key, "?") {
			continue
		}
		if spec.variants[key] == nil {
			continue
		}
		schema, _ := jsonSchemaOf(spec.variants[key])
		title := "body for " + methodless(pattern, key)
		schema["title"] = title
		branches = append(branches, schema)
	}
	switch len(branches) {
	case 0:
		return nil
	case 1:
		return branches[0].(map[string]any)
	default:
		return map[string]any{
			"anyOf":       branches,
			"description": "the body depends on the query the caller sends; each branch is titled with the discriminator it belongs to",
		}
	}
}

// methodless joins a pattern and discriminator for a schema title.
func methodless(pattern, key string) string {
	if key == "" {
		return pattern
	}
	return pattern + " " + key
}

// openAPIResponses renders one operation's responses: the declared success shape when the route has
// one, an explicit unknown otherwise, and the error answer every route can give.
func openAPIResponses(method, pattern string) map[string]any {
	success := map[string]any{}
	if spec, ok := routeSchemas[method+" "+pattern]; ok && spec.response != nil {
		schema, _ := jsonSchemaOf(spec.response)
		success["description"] = "the handler's declared response type"
		success["x-burpsy-declared"] = true
		success["content"] = map[string]any{
			"application/json": map[string]any{"schema": schema},
		}
	} else {
		success["description"] = "JSON result; no verified shape is declared for this route yet"
		success["x-burpsy-declared"] = false
		success["content"] = map[string]any{
			"application/json": map[string]any{"schema": map[string]any{}},
		}
	}
	return map[string]any{
		"200": success,
		"default": map[string]any{
			"description": "the refusal: plain text (http.Error) or an {\"error\": \"...\"} object, naming what was rejected",
		},
	}
}

// openAPIOperationID builds a unique, generator-friendly id: "getApiAdvisoriesById".
func openAPIOperationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, segment := range strings.Split(path, "/") {
		if segment == "" {
			continue
		}
		if strings.HasPrefix(segment, "{") {
			segment = "by-" + strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
		}
		for _, word := range strings.FieldsFunc(segment, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		}) {
			if word == "" {
				continue
			}
			b.WriteString(strings.ToUpper(word[:1]))
			b.WriteString(word[1:])
		}
	}
	return b.String()
}

// OpenAPIJSON is the document's wire form: one deterministic marshalling (Go sorts map keys), so
// the UI generator's --check compares bytes, not semantics.
func OpenAPIJSON() ([]byte, error) {
	return json.Marshal(openAPIDocument())
}

// handleOpenAPI serves GET /api/openapi.json.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	raw, err := OpenAPIJSON()
	if err != nil {
		http.Error(w, "the OpenAPI document failed to build: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}
