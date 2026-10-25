package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The burpsy-react-ui-3zw0 sweep: every body-taking route-verb's published schema is the handler's
// own type, proven against the real handler through the real mux.

// routeVerbKeys is every "VERB /pattern" of the manifest.
func routeVerbKeys() map[string]route {
	out := map[string]route{}
	for pattern, r := range manifest {
		for _, m := range r.methods {
			out[m+" "+pattern] = r
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestEveryMutatingRouteVerbDeclaresItsInput(t *testing.T) {
	var missing []string
	for _, key := range sortedKeys(routeVerbKeys()) {
		method, _, _ := strings.Cut(key, " ")
		if !methodMutates(method) {
			continue
		}
		if _, ok := routeSchemas[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d mutating route-verbs declare no input in routeSchemas (body type, noBody, or raw):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	verbs := routeVerbKeys()
	for key := range routeSchemas {
		if _, ok := verbs[key]; !ok {
			t.Errorf("routeSchemas declares %q, which is not a route-verb of the manifest", key)
		}
	}
}

// exampleFrom builds a value that satisfies schema s: every property present, the first enum member
// for an enumerated value, one item in every array. It is generated from the PUBLISHED schema, not
// from the Go type, so it proves the schema a model reads is one the handler accepts.
func exampleFrom(s map[string]any) any {
	if enum, ok := s["enum"].([]string); ok && len(enum) > 0 {
		return enum[0]
	}
	if anyOf, ok := s["anyOf"].([]any); ok && len(anyOf) > 0 {
		return exampleFrom(anyOf[0].(map[string]any))
	}
	switch s["type"] {
	case "object":
		out := map[string]any{}
		if props, ok := s["properties"].(map[string]any); ok {
			for name, p := range props {
				out[name] = exampleFrom(p.(map[string]any))
			}
		}
		return out
	case "array":
		items, _ := s["items"].(map[string]any)
		n := 1
		if min, ok := s["minItems"].(int); ok && min > 0 {
			n = min
		}
		out := make([]any, n)
		for i := range out {
			out[i] = exampleFrom(items)
		}
		return out
	case "string":
		if s["contentEncoding"] == "base64" {
			return ""
		}
		if s["format"] == "date-time" {
			return "2026-01-01T00:00:00Z"
		}
		return ""
	case "integer", "number":
		return 0
	case "boolean":
		return false
	default:
		return nil
	}
}

// probePath is the concrete path the probe requests for a declaration key and optional action.
func probePath(pattern, action string) string {
	// An explicit action wins (schema keys name "1/forward"-style subPaths); otherwise the
	// manifest's example subPath stands in, matching how the console builds these URLs.
	subPath := action
	if subPath == "" {
		if r, ok := manifest[pattern]; ok {
			subPath = r.subPath
		}
	}
	return concretePath(pattern, subPath)
}

func probe(t *testing.T, s *Server, method, path string, body []byte) (*decodeProbe, *httptest.ResponseRecorder) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req, p := withDecodeProbe(req)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return p, rec
}

// TestEveryBodyTakingRouteDecodesItsDeclaredType is the proof that a published schema is the
// handler's own: for each declared body, the real handler (reached through the real mux) decodes
// into exactly the declared type, accepts an example generated from the published schema, and refuses
// an unknown field. The probe stops the handler at its decode, so nothing is launched, sent or saved.
func TestEveryBodyTakingRouteDecodesItsDeclaredType(t *testing.T) {
	s := newTestServer()
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }

	for _, key := range sortedKeys(routeSchemas) {
		spec := routeSchemas[key]
		method, pattern, _ := strings.Cut(key, " ")
		type target struct {
			action string
			typ    reflect.Type
		}
		var targets []target
		switch {
		case len(spec.variants) > 0:
			for _, action := range sortedKeys(spec.variants) {
				targets = append(targets, target{action, spec.variants[action]})
			}
		case spec.body != nil:
			targets = append(targets, target{"", spec.body})
			if spec.schema != nil && spec.keysCheckedBy == "" {
				fail("%s: a hand-built schema must say where unknown keys are refused (keysCheckedBy)", key)
			}
		default:
			continue
		}
		for _, tg := range targets {
			if tg.typ == nil {
				continue // an action of this route that takes no body
			}
			path := probePath(pattern, tg.action)
			schema, unresolved := jsonSchemaOf(tg.typ)
			if spec.schema != nil {
				schema, unresolved = spec.schema(), nil
			}
			for _, u := range unresolved {
				fail("%s %s: %s", method, path, u)
			}
			example, _ := json.Marshal(exampleFrom(schema))

			p, rec := probe(t, s, method, path, example)
			switch {
			case !p.called:
				fail("%s %s: the handler never reached decodeBody (it answered %d: %.120s)", method, path, rec.Code, strings.TrimSpace(rec.Body.String()))
				continue
			case p.typ != reflect.PointerTo(tg.typ):
				fail("%s %s: the handler decodes into %v, but routeSchemas declares %v", method, path, p.typ, tg.typ)
				continue
			case p.err != nil:
				fail("%s %s: an example generated from the published schema was refused: %v\n    example: %s", method, path, p.err, example)
			}

			// A key-table patch decodes into a map, which accepts any key; the handler refuses an
			// unknown one after the decode, where the probe has already stopped it. keysCheckedBy
			// names where, and TestAKeyTablePatchRefusesAnUnknownKey drives that refusal for real.
			if schema["type"] == "object" && spec.schema == nil {
				var withExtra map[string]any
				_ = json.Unmarshal(example, &withExtra)
				withExtra["zz_burpsy_probe"] = true
				extra, _ := json.Marshal(withExtra)
				p, _ = probe(t, s, method, path, extra)
				if p.err == nil || !strings.Contains(p.err.Error(), `unknown field "zz_burpsy_probe"`) {
					fail("%s %s: an unknown field was not refused (err=%v)", method, path, p.err)
				}
			}
		}
	}
	if len(failures) > 0 {
		t.Errorf("%d declaration/handler disagreements:\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
}

// The real refusal an agent sees: through the real mux, no probe, the agent header set, an unknown
// field answers 400 naming the field, before the handler acts.
func TestAnAgentsUnknownFieldIsRefusedWith400(t *testing.T) {
	s := newTestServer()
	var failures []string
	for _, key := range sortedKeys(routeSchemas) {
		spec := routeSchemas[key]
		if spec.body == nil || spec.schema != nil {
			continue
		}
		schema, _ := jsonSchemaOf(spec.body)
		if schema["type"] != "object" {
			continue
		}
		method, pattern, _ := strings.Cut(key, " ")
		req := httptest.NewRequest(method, probePath(pattern, ""), strings.NewReader(`{"zz_burpsy_probe":1}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(AgentHeader, "test")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		// The handler's own message stays (most predate this and say "Invalid request body"); the
		// decoder's error naming the field rides BodyErrorHeader, which the MCP transport prints.
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Header().Get(BodyErrorHeader), `unknown field "zz_burpsy_probe"`) {
			failures = append(failures, fmt.Sprintf("%s: answered %d, %s=%q, body %.120q", key, rec.Code, BodyErrorHeader, rec.Header().Get(BodyErrorHeader), rec.Body.String()))
		}
	}
	if len(failures) > 0 {
		t.Errorf("%d routes did not refuse an agent's unknown field with 400:\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
}

// The console's own UI is not an agent: the same unknown field from it is ignored, as it always was.
// One safe route stands for the rule (a read-class POST that computes and stores nothing).
func TestAnUnknownFieldFromTheConsoleIsStillIgnored(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/tools/hash", strings.NewReader(`{"input":"abc","zz_ui_extra":1}`))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a console request with an extra field answered %d: %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/api/tools/hash", strings.NewReader(`{"input":"abc","zz_ui_extra":1}`))
	req.Header.Set(AgentHeader, "test")
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Header().Get(BodyErrorHeader), "zz_ui_extra") {
		t.Fatalf("the same request from an agent answered %d: %s", rec.Code, rec.Body.String())
	}
}

// Every published schema resolves: no type the reflector could only guess at.
func TestEveryDeclaredTypeHasAnHonestSchema(t *testing.T) {
	for _, key := range sortedKeys(routeSchemas) {
		spec := routeSchemas[key]
		types := []reflect.Type{}
		if spec.body != nil {
			types = append(types, spec.body)
		}
		for _, v := range spec.variants {
			if v != nil {
				types = append(types, v)
			}
		}
		for _, typ := range types {
			if _, unresolved := jsonSchemaOf(typ); len(unresolved) > 0 {
				t.Errorf("%s: %s", key, strings.Join(unresolved, "; "))
			}
		}
		if spec.body != nil && len(spec.variants) > 0 {
			t.Errorf("%s declares both a body and variants", key)
		}
	}
}

// A declared query parameter must at least be spelled somewhere in this package's handlers: a
// cheap guard against a typo publishing a parameter no handler reads. It cannot prove the read; it
// catches the name appearing nowhere, which is the drift a rename produces.
func TestEveryDeclaredQueryParameterIsReadSomewhere(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var corpus strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "route_schemas.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		corpus.Write(b)
	}
	src := corpus.String()
	if !strings.Contains(src, `"limit"`) {
		t.Fatal("positive control: the handlers' source does not contain \"limit\"; the corpus was not read")
	}
	for _, key := range sortedKeys(routeSchemas) {
		for _, q := range routeSchemas[key].query {
			if !strings.Contains(src, `"`+q.name+`"`) {
				t.Errorf("%s declares query parameter %q, which no handler source spells", key, q.name)
			}
		}
	}
}

func TestEveryPayloadSourceTagDecodes(t *testing.T) {
	for _, v := range payloadSourceVariants {
		var src intruder.PayloadSource
		if err := json.Unmarshal([]byte(`{"type":"`+v.tag+`"}`), &src); err != nil || src.Type != v.tag {
			t.Errorf("payload source tag %q does not decode through PayloadSource.UnmarshalJSON: %v", v.tag, err)
		}
	}
	var src intruder.PayloadSource
	if err := json.Unmarshal([]byte(`{"type":"zz_not_a_source"}`), &src); err == nil {
		t.Fatal("positive control: an unknown tag decoded, so this test proves nothing")
	}
}

// TestAKeyTablePatchRefusesAnUnknownKey drives the three key-table patches whose published schema is
// hand-built from the handler's own table: the map decode accepts any key, so the refusal the schema
// promises (additionalProperties false) is the handler's, and it is checked here for real.
func TestAKeyTablePatchRefusesAnUnknownKey(t *testing.T) {
	s := newTestServer().
		WithScanner(scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop())).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithProxyOptions(proxy.NewOptions())
	cases := map[string]string{
		"PUT /api/scanner/config":   `{"zz_burpsy_probe":true}`,
		"PUT /api/proxy/options":    `{"zz_burpsy_probe":true}`,
		"PUT /api/network/settings": `{"zz_burpsy_probe":{}}`,
	}
	for key, body := range cases {
		spec := routeSchemas[key]
		if spec.schema == nil || spec.keysCheckedBy == "" {
			t.Fatalf("%s is no longer a key-table patch; this test's premise moved", key)
		}
		if ap, _ := spec.schema()["additionalProperties"].(bool); ap {
			t.Fatalf("%s publishes additionalProperties true", key)
		}
		method, path, _ := strings.Cut(key, " ")
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set(AgentHeader, "test")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "zz_burpsy_probe") {
			t.Errorf("%s with an unknown key answered %d: %s", key, rec.Code, rec.Body.String())
		}
		// And a key the published schema lists is accepted.
		props, _ := spec.schema()["properties"].(map[string]any)
		if len(props) == 0 {
			t.Fatalf("%s publishes no keys", key)
		}
	}
}
