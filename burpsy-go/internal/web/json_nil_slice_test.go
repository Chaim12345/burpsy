package web

// burpsy-react-ui-j0s2: encoding/json emits null for a nil slice, and the UI types these
// collections as arrays - "tree":null crashed it (2f8c1f7d fixed one route by hand). writeJSON
// now normalises nil slices to empty ones; these tests pin what changes and what does not.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
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
// non-JSON answers are named in two asserted lists below (assets must answer 200 with their
// documented shape; error-list entries must answer an error status), so joining either list is
// a loud, cited decision. Only the named streaming route may take the per-route timeout - any
// other route hanging fails. Within every JSON body, EVERY null is asserted justified: the
// deliberate nulls are matched per JSON path with their contracts cited - a new null anywhere
// else fails the test. A JSON error body is walked too, but only at the exact status its named
// list entry binds; today that list is empty, so the first JSON error status a route serves
// fails until it is named.
func Test_no_get_route_serves_a_null_on_empty_state(t *testing.T) {
	s := newTestServer()
	patterns, _ := registeredPatterns(t)

	// Deliberate nulls by JSON path, each with its contract. writeJSON deliberately leaves nil
	// pointers and interfaces alone for exactly these; the normaliser must never erase them.
	deliberateNull := map[string]string{
		"/api/scanner/configs.configs[*].resolved":    "Resolved is the auditConfigView override shape: null inherits the engine default (api_scanner_configs.go:426, field contract at :57 and neighbours)",
		"/api/scanner/configs.default":                "scanner config overrides: null inherits the engine default (api_scanner_configs.go:57 and neighbours)",
		"/api/collaborator/interactions.interactions": "null distinguishes 'no channel configured' from an empty list (api_collaborator.go:941)",
		"/api/collaborator/status.last_read":          "nullable pointer by contract",
		"/api/collaborator/status.gated_checks":       "nullable pointer by contract",
		"/api/collaborator/status.interactions":       "same no-channel distinction as the interactions route",
		"/api/extensions.policy.registry":             "the documented no-registry signal (api_extensions.go:21)",
		"/api/config/export.scope.rules":              "bundle null = absent, do-not-touch on import; [] would mean wipe (api_config.go export/import contract)",
	}
	// GET routes whose empty-state answer is not JSON, in two asserted classes; a route joins a
	// list only as a loud, cited decision. Assets must answer 200 with their documented shape -
	// a 200 on an error-listed route, or malformed content on an asset route, fails.
	nonJSONAsset := map[string]string{
		"/":                              "<!doctype html",
		"/api/engagement/clickbandit.js": "text/javascript",
		"/ui2/":                          "<!doctype html",
		"/ui2/history":                   "<!doctype html",
		"/ui2/issues":                    "<!doctype html",
		"/ui2/htmx.min.js":               "text/javascript",
		"/ui2/sse.min.js":                "text/javascript",
		"/ui2/app.js":                    "text/javascript",
		"/ui2/collaborator":              "<!doctype html",
		"/ui2/intruder":                  "<!doctype html",
		"/ui2/sequencer":                 "<!doctype html",
		"/ui2/intruder/{id}/results":     "<!doctype html",
		"/ui2/intruder/{id}/{action}":    "<!doctype html",
		"/ui2/intruder/points":           "<!doctype html",
		"/ui2/intruder/confirm":          "<!doctype html",
		"/ui2/intruder/run":              "<!doctype html",
		"/ui2/sequencer/analyse":         "<!doctype html",
		"/ui2/collaborator/mint":         "<!doctype html",
		"/ui2/advisories":                "<!doctype html",
		"/ui2/comparer":                  "<!doctype html",
		"/ui2/dashboard":                 "<!doctype html",
		"/ui2/decoder":                   "<!doctype html",
		"/ui2/extensions":                "<!doctype html",
		"/ui2/intercept":                 "<!doctype html",
		"/ui2/logger":                    "<!doctype html",
		"/ui2/organizer":                 "<!doctype html",
		"/ui2/proxy":                     "<!doctype html",
		"/ui2/repeater":                  "<!doctype html",
		"/ui2/scanner":                   "<!doctype html",
		"/ui2/scope":                     "<!doctype html",
		"/ui2/session":                   "<!doctype html",
		"/ui2/settings":                  "<!doctype html",
		"/ui2/sitemap":                   "<!doctype html",
		"/ui2/ws":                        "<!doctype html",
		"/ui2/intercept/{action}":        "<!doctype html",
		"/ui2/decoder/run":               "<!doctype html",
		"/ui2/comparer/run":              "<!doctype html",
		"/ui2/repeater/send":             "<!doctype html",
	}
	nonJSONError := map[string]string{
		"/api/advisories/":                   "plain-text 400/404: a type index is required",
		"/api/crawl/live":                    "plain-text 400: task id is required",
		"/api/exchange/":                     "plain-text 400: an exchange ID is required",
		"/api/exchanges/":                    "plain-text 400: an exchange ID is required",
		"/api/extensions/console":            "plain-text 400: a plugin name is required",
		"/api/intercept/rules/{dir...}":      "plain-text 404: a direction is required",
		"/api/project/logging":               "plain-text 503: no file logger attached",
		"/api/proxy/listener":                "plain-text 503: no proxy server attached",
		"/api/proxy/options":                 "plain-text 503: no proxy option set attached",
		"/api/proxy/passthrough":             "plain-text 503: no TLS policy attached",
		"/api/repeater/ws-handshake-preview": "plain-text 400: socket or target is required",
		"/api/issues/":                       "plain-text 400: an issue id is required",
		"/api/report/{rest...}":              "plain-text 404: a report kind is required",
		"/api/scanner/checks/source":         "plain-text 503: no scanner attached",
		"/api/scanner/config":                "plain-text 503: no scanner configured",
		"/api/scope/check":                   "plain-text 400: url is required",
		"/api/target/analyze":                "plain-text 400: host is required",
		"/ca.crt":                            "plain-text 404: TLS interception is off in the test server",
	}
	// Routes that never return on empty state because they stream. Any other route that takes
	// the two-second timeout is a hang, not a stream, and fails.
	streaming := map[string]string{
		"/api/events": "the SSE event feed",
	}
	// GET routes whose empty-state answer is a JSON error body, with the exact status each
	// serves. Their bodies are walked for unjustified nulls like any other JSON - an error DTO
	// has no unjustified nulls either - but the status is bound: a new error status, a changed
	// status, or an unlisted route answering one all fail. The end of the test asserts this
	// list is EMPTY - not just observes it - because the empty-state contract is that no
	// route serves a JSON error at all.
	errorJSONStatus := map[string]int{}
	var nulls, streamed []string
	var sampled, errorSampled, skipped int
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
			if why, ok := streaming[path]; ok {
				streamed = append(streamed, path+" ("+why+")")
			} else {
				t.Errorf("%s did not answer within two seconds and is not a named streaming route", path)
			}
			continue
		}
		var body interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			if marker, ok := nonJSONAsset[path]; ok {
				bodyText := rec.Body.String()
				if rec.Code != http.StatusOK ||
					!strings.Contains(bodyText, marker) && !strings.Contains(rec.Header().Get("Content-Type"), marker) {
					t.Errorf("%s answered %d without its documented shape (%s): %.80q",
						path, rec.Code, marker, bodyText)
				}
			} else if why, ok := nonJSONError[path]; ok {
				if rec.Code < http.StatusBadRequest {
					t.Errorf("%s answered %d, want the error status its list entry cites (%s)", path, rec.Code, why)
				}
			} else {
				t.Errorf("%s answered %d with a non-JSON body and is on neither named non-JSON list: %.80q",
					path, rec.Code, rec.Body.String())
			}
			continue
		}
		if rec.Code >= http.StatusBadRequest {
			want, ok := errorJSONStatus[path]
			if !ok {
				t.Errorf("%s answered a JSON error body with status %d and is not on the named error-status list", path, rec.Code)
			} else if want != rec.Code {
				t.Errorf("%s answered status %d, want the %d its list entry binds", path, rec.Code, want)
			}
			errorSampled++
		} else {
			sampled++
		}
		walkNulls(body, path, deliberateNull, &nulls)
	}
	if len(nulls) > 0 {
		t.Errorf("%d unjustified null value(s) in GET sample output:\n%s", len(nulls), strings.Join(nulls, "\n"))
	}
	// The error-status list must be EMPTY: no route serves a JSON error on empty state, and
	// keeping it that way is a checked claim, not an initial value. Naming a route here is a
	// deliberate, cited decision that starts by retiring this assertion.
	if len(errorJSONStatus) != 0 {
		t.Errorf("error-status list has %d entries; the empty-state contract is that no route serves a JSON error - retire this assertion as part of naming one", len(errorJSONStatus))
	}
	if errorSampled != 0 {
		t.Errorf("%d route(s) served a JSON error status on empty state; each must be named on the error-status list with its exact status", errorSampled)
	}
	t.Logf("sampled %d GET routes on empty state (%d of them named JSON error statuses); %d skipped (path variables or no GET verb); streaming: %v",
		sampled+errorSampled, errorSampled, skipped, streamed)
}

// walkNulls reports every null in the decoded body - the root, map values, and array elements -
// unless the JSON path falls under a cited deliberate null. An exception matches the exact path
// or anything beneath it, and "[*]" in an exception matches any one array index, so an exception
// can name a shape inside every element of an array without naming the whole array.
var arrayIndexPattern = regexp.MustCompile(`\[\d+\]`)

func nullPathIsDeliberate(path string, deliberate map[string]string) bool {
	wild := arrayIndexPattern.ReplaceAllString(path, "[*]")
	for prefix := range deliberate {
		for _, candidate := range []string{path, wild} {
			if candidate == prefix || strings.HasPrefix(candidate, prefix+".") || strings.HasPrefix(candidate, prefix+"[") {
				return true
			}
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
// implementing json.Marshaler or encoding.TextMarshaler never has its state rewritten under it.
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

	rec = httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]textMarshalling{"k": {Items: nil}})
	if got := strings.TrimSpace(rec.Body.String()); got != `{"k":"nil"}` {
		t.Errorf("text-marshalling type encoded as %q, want its own view of the nil slice", got)
	}
}

// textMarshalling reports through MarshalText whether its slice is nil; the normaliser must not
// change what it sees (encoding/json honours encoding.TextMarshaler too).
type textMarshalling struct {
	Items []string
}

func (tm textMarshalling) MarshalText() ([]byte, error) {
	if tm.Items == nil {
		return []byte("nil"), nil
	}
	return []byte("not-nil"), nil
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

	// Maps: two fields holding the same map hold one shared clone afterwards.
	sharedMap := map[string][]string{"k": nil}
	type mapDto struct {
		M1 map[string][]string
		M2 map[string][]string
	}
	mout := normalizeNilSlices(reflect.ValueOf(mapDto{M1: sharedMap, M2: sharedMap})).Interface().(mapDto)
	mout.M1["k2"] = []string{}
	if _, ok := mout.M2["k2"]; !ok {
		t.Error("two fields sharing one map stopped sharing it")
	}
	if sharedMap["k"] != nil {
		t.Error("the input map was mutated")
	}

	// Same start and length, different spare capacity: these DO alias one backing array, but
	// they are different headers, and the clone contract covers identical headers only - each
	// gets its own clone, so the cap difference survives.
	base := make([]string, 1, 4)
	capped := base[:1:1]
	type capDto struct {
		X []string
		Y []string
	}
	cout := normalizeNilSlices(reflect.ValueOf(capDto{X: base[:1], Y: capped})).Interface().(capDto)
	if cap(cout.X) != 4 || cap(cout.Y) != 1 {
		t.Errorf("capacities collapsed: X cap %d, Y cap %d", cap(cout.X), cap(cout.Y))
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
