package web

// burpsy-react-ui-j0s2: encoding/json emits null for a nil slice, and the UI types these
// collections as arrays - "tree":null crashed it (2f8c1f7d fixed one route by hand). writeJSON
// now normalises nil slices to empty ones; these tests pin what changes and what does not.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// The route sweep the bead asks for: every GET route the manifest declares, answered by an
// empty-state server, must not carry a null anywhere in its JSON. With writeJSON normalising nil
// slices, a surviving null is either a response that bypasses writeJSON (the bug class this test
// exists to catch) or a deliberate nullable field - and deliberate nullables must be few enough to
// name. Routes with path variables are out of reach of an empty-state sample; they are counted so
// the coverage statement stays honest.
func Test_no_get_route_serves_a_null_on_empty_state(t *testing.T) {
	s := newTestServer()
	patterns, _ := registeredPatterns(t)
	// Deliberate nulls, named with their contracts: null carries meaning at each of these, and
	// writeJSON deliberately leaves nil pointers and interfaces alone for exactly this reason.
	// A route joining this list needs the same kind of cited contract, not a preference.
	deliberate := map[string]string{
		"/api/scanner/configs":           "scanner config overrides: null inherits the engine default (api_scanner_configs.go:57 and neighbours)",
		"/api/collaborator/interactions": "interactions:null distinguishes 'no channel configured' from an empty list (api_collaborator.go:941)",
		"/api/collaborator/status":       "last_read/gated_checks are nullable pointers by contract",
		"/api/extensions":                "registry:null is the documented no-registry signal (api_extensions.go:21)",
		"/api/config/export":             "null section = absent, do-not-touch on import; [] would mean wipe (api_config.go export/import contract)",
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
		// A streaming route (the events feed is server-sent events) never returns on empty
		// state; give each route two seconds and name what streams past them.
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
		var body interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			continue // not JSON - nothing for this test to say about it
		}
		sampled++
		if _, ok := deliberate[path]; ok {
			continue
		}
		walkNulls(body, path, &nulls)
	}
	if len(nulls) > 0 {
		t.Errorf("%d null value(s) in GET sample output:\n%s", len(nulls), strings.Join(nulls, "\n"))
	}
	t.Logf("sampled %d GET routes on empty state, skipped %d with path variables or no GET verb, %d streaming: %v",
		sampled, skipped, len(streamed), streamed)
}

func walkNulls(v interface{}, path string, nulls *[]string) {
	switch node := v.(type) {
	case map[string]interface{}:
		for k, child := range node {
			if child == nil {
				*nulls = append(*nulls, path+" -> ."+k)
				continue
			}
			walkNulls(child, path+"."+k, nulls)
		}
	case []interface{}:
		for i, child := range node {
			walkNulls(child, path+"["+strconv.Itoa(i)+"]", nulls)
		}
	}
}
