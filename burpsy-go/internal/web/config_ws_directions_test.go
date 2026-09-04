package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

// ---- one table of direction names, and both ends must use it -------------------------------
//
// The wire names for intercept directions used to be written down twice: once in directionFor,
// which decides what the URL router and the config importer accept, and once as a literal map
// inside handleConfigExport. Nothing tied them together.
//
// That is the same defect shape as the session_rules `omitempty` bug in api_config.go, and it
// became live the moment WebSocket directions were added: the importer accepted
// websocket_to_server, the exporter never wrote it, so a donor's WebSocket interception rules
// would vanish in transit while the round trip still reported success. The operator would carry
// their engagement config to another machine and silently lose the rules that decide which
// frames get held.
//
// interceptDirectionNames is now the single table. These tests exist to keep it single.

// Exhaustiveness. A direction added to the intercept package without a wire name here is
// unreachable from the API and unexportable, and shows up as a failure rather than as a
// silently missing feature.
func TestEveryInterceptDirectionHasAWireName(t *testing.T) {
	if len(interceptDirectionNames) != intercept.DirectionCount {
		t.Fatalf("%d wire names for %d directions; a direction was added without one",
			len(interceptDirectionNames), intercept.DirectionCount)
	}

	seenName := map[string]bool{}
	seenDir := map[intercept.Direction]bool{}
	for _, d := range interceptDirectionNames {
		if seenName[d.Name] {
			t.Errorf("wire name %q appears twice", d.Name)
		}
		if seenDir[d.Dir] {
			t.Errorf("direction %s appears twice", d.Dir)
		}
		seenName[d.Name] = true
		seenDir[d.Dir] = true

		// Round trip through the mapper the router and importer both use.
		if got, ok := directionFor(d.Name); !ok || got != d.Dir {
			t.Errorf("directionFor(%q) = (%s, %v), want (%s, true)", d.Name, got, ok, d.Dir)
		}
	}
	for dir := intercept.Direction(0); int(dir) < intercept.DirectionCount; dir++ {
		if !seenDir[dir] {
			t.Errorf("direction %s has no wire name, so it cannot be reached from the API", dir)
		}
	}
}

// An unknown name must be refused rather than resolving to requests. directionFor returns
// DirectionRequest as its zero value, so a caller that ignores the bool would apply a bundle's
// unknown section to the request rules — writing rules the operator never asked for.
func TestDirectionForRefusesAnUnknownName(t *testing.T) {
	for _, name := range []string{"", "request", "response", "websocket", "WEBSOCKET_TO_SERVER", "../requests"} {
		if _, ok := directionFor(name); ok {
			t.Errorf("directionFor(%q) was accepted", name)
		}
	}
}

// The export must write a key for every direction, including the ones with no rules. An absent
// key means "leave this surface alone" on import, so a donor with no WebSocket rules must still
// say so out loud or importing will not clear the recipient's.
func TestConfigExportWritesEveryInterceptDirection(t *testing.T) {
	ts := newTestServer()

	rec := get(t, ts, "/api/config/export")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/export = %d: %s", rec.Code, rec.Body.String())
	}
	var bundle struct {
		Intercept map[string]json.RawMessage `json:"intercept"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}

	if len(bundle.Intercept) != intercept.DirectionCount {
		t.Errorf("exported %d intercept sections, want %d: %v",
			len(bundle.Intercept), intercept.DirectionCount, keysOf(bundle.Intercept))
	}
	for _, d := range interceptDirectionNames {
		if _, ok := bundle.Intercept[d.Name]; !ok {
			t.Errorf("the bundle has no %q section, so importing it leaves the recipient's %s "+
				"rules running", d.Name, d.Dir)
		}
	}
}

// The whole round trip, which is the property that actually matters: WebSocket rules set on one
// instance must arrive on another. This is the test that would have failed before the export
// loop was tied to the table.
func TestWebSocketInterceptRulesSurviveAnExportImportRoundTrip(t *testing.T) {
	donor := newTestServer()

	// Distinctive rule per WebSocket direction, so a cross-wired or dropped section is
	// identifiable by content rather than only by count.
	for _, dir := range []intercept.Direction{
		intercept.DirectionWebSocketToServer,
		intercept.DirectionWebSocketToClient,
	} {
		if err := donor.intercept.SetRules(dir, true, []intercept.Rule{{
			Field:       intercept.FieldHost,
			Category:    intercept.CategoryLiteral,
			StringMatch: dir.String() + ".example",
			Enabled:     true,
		}}); err != nil {
			t.Fatalf("SetRules(%s): %v", dir, err)
		}
	}

	exported := get(t, donor, "/api/config/export")
	if exported.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", exported.Code, exported.Body.String())
	}

	recipient := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/config/import",
		strings.NewReader(exported.Body.String()))
	rec := httptest.NewRecorder()
	recipient.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}

	// The import result must count all four sections, not just the two it used to know about.
	var result struct {
		InterceptDirs int `json:"intercept_dirs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode import result: %v", err)
	}
	if result.InterceptDirs != intercept.DirectionCount {
		t.Errorf("import reported %d intercept directions, want %d",
			result.InterceptDirs, intercept.DirectionCount)
	}

	for _, dir := range []intercept.Direction{
		intercept.DirectionWebSocketToServer,
		intercept.DirectionWebSocketToClient,
	} {
		list := recipient.intercept.Rules(dir)
		if !list.Active {
			t.Errorf("%s: inactive after import; the donor had it active", dir)
			continue
		}
		if len(list.Rules) != 1 {
			t.Errorf("%s: %d rules after import, want 1", dir, len(list.Rules))
			continue
		}
		if want := dir.String() + ".example"; list.Rules[0].StringMatch != want {
			t.Errorf("%s: rule is %q, want %q — the sections are cross-wired",
				dir, list.Rules[0].StringMatch, want)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
