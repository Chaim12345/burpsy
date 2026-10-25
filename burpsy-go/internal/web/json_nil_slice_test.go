package web

// burpsy-react-ui-j0s2: encoding/json emits null for a nil slice, and the UI types these
// collections as arrays - "tree":null crashed it (2f8c1f7d fixed one route by hand). writeJSON
// now normalises nil slices to empty ones; these tests pin what changes and what does not.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWriteJSONEmitsEmptyArraysForNilSlices(t *testing.T) {
	type dto struct {
		Items  []string `json:"items"`
		Nested struct {
			IDs []int `json:"ids"`
		} `json:"nested"`
		Lists  [][]string       `json:"lists"`
		ByHost map[string][]int `json:"by_host"`
	}
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, dto{Lists: [][]string{nil}, ByHost: map[string][]int{"h": nil}})
	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if items, ok := got["items"].([]interface{}); !ok || len(items) != 0 {
		t.Errorf("items = %#v, want []", got["items"])
	}
	if ids, ok := got["nested"].(map[string]interface{})["ids"].([]interface{}); !ok || len(ids) != 0 {
		t.Errorf("nested.ids = %#v, want []", got["nested"])
	}
	first := got["lists"].([]interface{})[0]
	if inner, ok := first.([]interface{}); !ok || len(inner) != 0 {
		t.Errorf("lists[0] = %#v, want []", first)
	}
	if hv, ok := got["by_host"].(map[string]interface{})["h"].([]interface{}); !ok || len(hv) != 0 {
		t.Errorf("by_host.h = %#v, want []", got["by_host"])
	}
}

func TestWriteJSONLeavesOtherNullsAlone(t *testing.T) {
	type dto struct {
		Note *string        `json:"note"`
		Meta map[string]int `json:"meta"`
		Any  interface{}    `json:"any"`
	}
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, dto{})
	body := rec.Body.String()
	for _, want := range []string{`"note":null`, `"meta":null`, `"any":null`} {
		if !strings.Contains(body, want) {
			t.Errorf("body %s is missing %s - only nil slices become [], other nulls stay", body, want)
		}
	}
}

func TestWriteJSONEmitsAnEmptyArrayForANilSliceBody(t *testing.T) {
	rec := httptest.NewRecorder()
	var body []string
	writeJSON(rec, http.StatusOK, body)
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("nil slice body encoded as %s, want []", got)
	}
}

// The route sweep the bead asks for, with its coverage stated exactly: every manifest GET route
// WITHOUT path variables, against an empty-state server. Routes with path variables have no
// empty-state sample and are counted, not claimed. A response must be valid JSON to be judged;
// non-JSON answers (downloads, upgrades, HTML) and error statuses are named in their own lists
// below, so joining either list is a loud, cited decision. Streaming routes that never return
// (server-sent events) are named too. Within a JSON 2xx body, EVERY null is asserted justified:
// the deliberate nulls are matched per JSON path with their contracts cited - a new null
// anywhere else fails the test.
func Test_no_get_route_serves_a_null_on_empty_state(t *testing.T) {
	s := newTestServer()
	patterns, _ := registeredPatterns(t)

	// Deliberate nulls by JSON path, each with its contract. writeJSON deliberately leaves nil
	// pointers and interfaces alone for exactly these; the normaliser must never erase them.
	deliberateNull := map[string]string{
		"/api/scanner/configs.configs":                "same null-inherits-default override shape, under each named config (api_scanner_configs.go:57 and neighbours)",
		"/api/scanner/configs.default":                "scanner config overrides: null inherits the engine default (api_scanner_configs.go:57 and neighbours)",
		"/api/collaborator/interactions.interactions": "null distinguishes 'no channel configured' from an empty list (api_collaborator.go:941)",
		"/api/collaborator/status.last_read":          "nullable pointer by contract",
		"/api/collaborator/status.gated_checks":       "nullable pointer by contract",
		"/api/collaborator/status.interactions":       "same no-channel distinction as the interactions route",
		"/api/extensions.policy.registry":             "the documented no-registry signal (api_extensions.go:21)",
		"/api/config/export.scope.rules":              "bundle null = absent, do-not-touch on import; [] would mean wipe (api_config.go export/import contract)",
	}
	// GET routes whose answer is not JSON on empty state: two static assets and the routes
	// whose empty-state answer is a plain-text error (a required parameter, a resource that
	// does not exist yet, or a process component the test server does not attach). Each entry
	// names what the route actually serves; a route joining the list is a loud, cited decision.
	nonJSON := map[string]string{
		"/":                                  "the console's HTML shell",
		"/api/engagement/clickbandit.js":     "the Clickbandit JavaScript payload",
		"/api/advisories/":                   "plain-text 400/404: a type index is required",
		"/api/crawl/live":                    "plain-text 400: task id is required",
		"/api/engagement/":                   "plain-text 404: an engagement kind is required",
		"/api/exchange/":                     "plain-text 400: an exchange ID is required",
		"/api/exchanges/":                    "plain-text 400: an exchange ID is required",
		"/api/extensions/console":            "plain-text 400: a plugin name is required",
		"/api/intercept/rules/":              "plain-text 404: a direction is required",
		"/api/project/logging":               "plain-text 503: no file logger attached",
		"/api/proxy/listener":                "plain-text 503: no proxy server attached",
		"/api/proxy/options":                 "plain-text 503: no proxy option set attached",
		"/api/proxy/passthrough":             "plain-text 503: no TLS policy attached",
		"/api/repeater/ws-handshake-preview": "plain-text 400: socket or target is required",
		"/api/report/":                       "plain-text 404: a report kind is required",
		"/api/scanner/checks/source":         "plain-text 503: no scanner attached",
		"/api/scanner/config":                "plain-text 503: no scanner configured",
		"/api/scope/check":                   "plain-text 400: url is required",
		"/api/settings/triage":               "plain-text 503: persistence is not attached",
		"/api/skills/":                       "plain-text 404: a skill name is required",
		"/api/target/analyze":                "plain-text 400: host is required",
		"/ca.crt":                            "plain-text 404: TLS interception is off in the test server",
		"/reissue/":                          "plain-text 410: no live re-issue token",
	}
	var nulls, streamed []string
	var sampled, skipped int
	seen := map[string]bool{}
	for _, pattern := range patterns {
		method, path := splitPattern(pattern)
		if method != "" && method != http.MethodGet {
			continue
		}
		if strings.ContainsAny(path, "{}") || seen[path] {
			skipped++
			continue
		}
		seen[path] = true
		spec, ok := manifest[path]
		if !ok {
			continue
		}
		gets := false
		for _, m := range spec.methods {
			if m == http.MethodGet {
				gets = true
			}
		}
		if !gets {
			skipped++
			continue
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		// A streaming route never returns on empty state; give each route two seconds and name
		// what streams past them.
		done := make(chan struct{})
		go func() {
			s.mux.ServeHTTP(rec, req)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			streamed = append(streamed, path)
			continue
		}
		// Error statuses on empty state are not skipped: their bodies are walked too when they
		// are JSON (an error DTO has no unjustified nulls either), and named when they are not.
		var body interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			if _, ok := nonJSON[path]; !ok {
				t.Errorf("%s answered %d with a non-JSON body and is not on the named non-JSON list: %.80q",
					path, rec.Code, rec.Body.String())
			}
			continue
		}
		sampled++
		walkNulls(body, path, deliberateNull, &nulls)
	}
	if len(nulls) > 0 {
		t.Errorf("%d unjustified null value(s) in GET sample output:\n%s", len(nulls), strings.Join(nulls, "\n"))
	}
	t.Logf("sampled %d GET routes on empty state; %d skipped (path variables or no GET verb); streaming: %v",
		sampled, skipped, streamed)
}

// walkNulls reports every null in the decoded body - the root, map values, and array elements -
// unless the JSON path falls under a cited deliberate null (exact path or anything beneath it).
func nullPathIsDeliberate(path string, deliberate map[string]string) bool {
	for prefix := range deliberate {
		if path == prefix || strings.HasPrefix(path, prefix+".") || strings.HasPrefix(path, prefix+"[") {
			return true
		}
	}
	return false
}

func walkNulls(v interface{}, path string, deliberate map[string]string, nulls *[]string) {
	if v == nil {
		if !nullPathIsDeliberate(path, deliberate) {
			*nulls = append(*nulls, path+" (root)")
		}
		return
	}
	switch node := v.(type) {
	case map[string]interface{}:
		for k, child := range node {
			childPath := path + "." + k
			if child == nil {
				if !nullPathIsDeliberate(childPath, deliberate) {
					*nulls = append(*nulls, childPath)
				}
				continue
			}
			walkNulls(child, childPath, deliberate, nulls)
		}
	case []interface{}:
		for i, child := range node {
			childPath := path + "[" + strconv.Itoa(i) + "]"
			if child == nil {
				if !nullPathIsDeliberate(childPath, deliberate) {
					*nulls = append(*nulls, childPath)
				}
				continue
			}
			walkNulls(child, childPath, deliberate, nulls)
		}
	}
}

// W12 extraction probes: the shapes the normaliser must NOT touch. A top-level untyped nil
// encoded as null before and must not panic now; a nil []byte is a base64 string when present,
// so null stays null; a nil json.RawMessage is null, not an invalid empty document; and a type
// that marshals itself never has its state rewritten under it.
func TestWriteJSONLeavesTheNonSliceShapesAlone(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, nil)
	if got := strings.TrimSpace(rec.Body.String()); got != "null" {
		t.Errorf("top-level nil encoded as %q, want null", got)
	}

	rec = httptest.NewRecorder()
	var blob []byte
	writeJSON(rec, http.StatusOK, blob)
	if got := strings.TrimSpace(rec.Body.String()); got != "null" {
		t.Errorf("nil []byte encoded as %q, want null (an empty one would be a base64 string)", got)
	}

	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]interface{}{"raw": json.RawMessage(nil)})
	if got := strings.TrimSpace(rec.Body.String()); got != `{"raw":null}` {
		t.Errorf("nil json.RawMessage encoded as %q, want null", got)
	}

	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, selfMarshalling{Items: nil})
	if got := strings.TrimSpace(rec.Body.String()); got != `{"items":null}` {
		t.Errorf("self-marshalling type encoded as %q, want its own null", got)
	}
}

type selfMarshalling struct {
	Items []string
}

func (s selfMarshalling) MarshalJSON() ([]byte, error) {
	if s.Items == nil {
		return []byte(`{"items":null}`), nil
	}
	return []byte(`{"items":[]}`), nil
}

// The supported-DTO contract: the input is never mutated, aliases survive as aliases, and a
// cyclic graph terminates (the encoder then reports the cycle, as it would on the original).
func TestNormalisationNeverMutatesItsInput(t *testing.T) {
	shared := []string{"a", "b"}
	type dto struct {
		Items  []string   `json:"items"`
		Shared []string   `json:"shared"`
		Nested [][]string `json:"nested"`
	}
	in := dto{Items: nil, Shared: shared, Nested: [][]string{nil, shared}}
	out := normalizeNilSlices(reflect.ValueOf(in)).Interface().(dto)
	if in.Items != nil || in.Nested[0] != nil {
		t.Error("the normaliser nil-filled a slice on the input value")
	}
	out.Shared[0] = "MUTATED"
	out.Nested[1][1] = "MUTATED"
	if shared[0] != "a" || shared[1] != "b" {
		t.Errorf("a write through the normalised copy reached the shared backing array: %v", shared)
	}
	if out.Items == nil || out.Nested[0] == nil {
		t.Error("the copy kept a nil slice it was built to fill")
	}
}

func TestNormalisationPreservesAliases(t *testing.T) {
	leaf := []string{"x"}
	type dto struct {
		A *[]string
		B *[]string
		C []string
		D []string
	}
	in := dto{A: &leaf, B: &leaf, C: leaf, D: leaf}
	out := normalizeNilSlices(reflect.ValueOf(in)).Interface().(dto)
	if out.A != out.B {
		t.Error("two fields sharing one pointer stopped sharing it")
	}
	// Slice headers alias the same backing array; the normalised copies must too.
	if &out.C[0] != &out.D[0] {
		t.Error("two fields sharing one backing array stopped sharing it")
	}
}

func TestNormalisationTerminatesOnACycle(t *testing.T) {
	type node struct {
		Name string `json:"name"`
		Next *node  `json:"next"`
	}
	a := &node{Name: "a"}
	b := &node{Name: "b"}
	a.Next = b
	b.Next = a
	done := make(chan reflect.Value, 1)
	go func() { done <- normalizeNilSlices(reflect.ValueOf(a)) }()
	var cloned reflect.Value
	select {
	case cloned = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the normaliser recursed forever on a cyclic graph")
	}
	if _, err := json.Marshal(cloned.Interface()); err == nil {
		t.Error("a cyclic graph marshalled cleanly; the encoder should report the cycle as before")
	}
}
