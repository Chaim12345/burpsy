package mcp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/web"
)

// The burpsy-react-ui-3zw0 acceptance on the MCP side: every grouped tool publishes each operation's
// body as the schema web.MCPSchemaFor reflects from the handler's own type (route_schema_test.go
// proves that schema against the handler), the dangling "/api/apidoc" reference is gone, and an
// agent's unknown field comes back as a 400 naming the field — through the real stdio session.

// bodyBranches returns a tool's body schema per op title.
func bodyBranches(t *testing.T, schema map[string]any) map[string]map[string]any {
	t.Helper()
	props, _ := schema["properties"].(map[string]any)
	body, _ := props["body"].(map[string]any)
	out := map[string]map[string]any{}
	if title, ok := body["title"].(string); ok {
		out[title] = body
	}
	if anyOf, ok := body["anyOf"].([]any); ok {
		for _, b := range anyOf {
			m := b.(map[string]any)
			out[m["title"].(string)] = m
		}
	}
	return out
}

func TestEveryGroupedOperationPublishesItsHandlersBodySchema(t *testing.T) {
	tools, raw := listGrouped(t)
	if strings.Contains(raw, "apidoc") {
		t.Fatal("tools/list still points a model at /api/apidoc, a route that does not exist")
	}
	typed := 0
	for _, tl := range tools {
		if tl.Name == confirmToolName {
			continue
		}
		branches := bodyBranches(t, tl.InputSchema)
		for _, o := range tl.Annotations.Operations {
			verb, pattern, _ := strings.Cut(o, " ")
			spec, declared := web.MCPSchemaFor(verb, pattern)
			if web.MCPMethodMutates(verb) && !declared {
				t.Fatalf("%s (tool %s) mutates and has no declared input", o, tl.Name)
			}
			if !declared || spec.Body == nil {
				if _, has := branches[o]; has {
					t.Fatalf("%s (tool %s) takes no body but publishes one", o, tl.Name)
				}
				continue
			}
			got, ok := branches[o]
			if !ok {
				t.Fatalf("%s (tool %s) has a declared body and the tool does not publish it", o, tl.Name)
			}
			// The published branch is the reflected schema plus a title and description; every other
			// key must be the reflected one, verbatim, after a JSON round trip.
			want, _ := json.Marshal(spec.Body)
			var wantM map[string]any
			_ = json.Unmarshal(want, &wantM)
			for k, v := range wantM {
				if k == "description" || k == "title" {
					continue
				}
				if !reflect.DeepEqual(got[k], v) {
					t.Fatalf("%s: published body key %q differs from the handler's reflected schema", o, k)
				}
			}
			typed++
		}
	}
	if typed < 90 {
		t.Fatalf("only %d operations publish a typed body; the manifest has about a hundred body-taking route-verbs", typed)
	}
}

func TestAGroupedToolsQueryIsTypedFromTheHandler(t *testing.T) {
	tools, _ := listGrouped(t)
	for _, tl := range tools {
		if tl.Name != "history" {
			continue
		}
		props := tl.InputSchema["properties"].(map[string]any)
		q := props["query"].(map[string]any)["properties"].(map[string]any)
		for _, name := range []string{"limit", "q", "search", "search_regex"} {
			if _, ok := q[name]; !ok {
				t.Fatalf("history's query schema lacks %q: %v", name, q)
			}
		}
		return
	}
	t.Fatal("no history tool")
}

// The two halves of "proven against the handler", through the transport: an example built from the
// PUBLISHED schema is accepted by the real handler, and an unknown field is refused with 400 naming it.
func TestAnExampleFromThePublishedSchemaIsAcceptedAndAnUnknownFieldRefused(t *testing.T) {
	tools, _ := listGrouped(t)
	var hash map[string]any
	for _, tl := range tools {
		if tl.Name == "decoder" {
			hash = bodyBranches(t, tl.InputSchema)["POST /api/tools/hash"]
		}
	}
	if hash == nil {
		t.Fatal("decoder publishes no body for POST /api/tools/hash")
	}
	props := hash["properties"].(map[string]any)
	if _, ok := props["algorithm"]; !ok || hash["additionalProperties"] != false {
		t.Fatalf("the hash body schema is not the handler's typed object: %v", hash)
	}

	_, base := newConsole(t)
	ok := callGrouped(t, base, "decoder", map[string]any{"op": "POST /api/tools/hash", "body": map[string]any{"input": "abc", "algorithm": "md5"}})
	if ok.IsError || !strings.Contains(textOf(ok), "900150983cd24fb0d6963f7d28e17f72") {
		t.Fatalf("a body valid against the published schema was not accepted:\n%s", textOf(ok))
	}
	bad := callGrouped(t, base, "decoder", map[string]any{"op": "POST /api/tools/hash", "body": map[string]any{"input": "abc", "algoritm": "md5"}})
	if !bad.IsError || !strings.Contains(textOf(bad), "HTTP 400") || !strings.Contains(textOf(bad), `unknown field "algoritm"`) {
		t.Fatalf("a misspelled field was not refused with 400 naming it:\n%s", textOf(bad))
	}
}
