package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// burpsy-react-ui-saq3.3.1: the per-issue selection, its deny half and the two parameter skip lists
// are edited in the console through the configuration library's settings block. These tests drive
// that write through the real handler and read the result back as the console does — the marshalled
// JSON — and then through an audit run, which is where a saved configuration has to mean something.

const (
	sqliType          uint32 = 0x00100200 // SQL injection: Burp defines nine methods, burpsy runs one
	reflectedXSSType  uint32 = 0x00200300 // Cross-site scripting (reflected)
	notInTheCatalogue uint32 = 0x0badf00d
)

// The catalogue route is the other side of the selection's join: every type by name, Burp's methods
// for it and the subset burpsy runs, each a JSON array even when empty.
func TestTheIssueTypeCatalogueRouteListsEveryTypeWithItsMethods(t *testing.T) {
	s := newTestServer()
	rec := get(t, s, "/api/scanner/issue-types")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scanner/issue-types: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		IssueTypes []map[string]json.RawMessage `json:"issue_types"`
		Count      int                          `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Count != len(scanner.All()) || len(body.IssueTypes) != len(scanner.All()) {
		t.Fatalf("count = %d, rows = %d, want the whole catalogue (%d)", body.Count, len(body.IssueTypes), len(scanner.All()))
	}
	byType := map[string]map[string]json.RawMessage{}
	for _, row := range body.IssueTypes {
		byType[string(row["type_index"])] = row
	}
	sqli := byType[fmt.Sprint(sqliType)]
	if sqli == nil {
		t.Fatalf("SQL injection (%d) is missing; type_index must be the number issue_types uses", sqliType)
	}
	if got := string(sqli["name"]); got != `"SQL injection"` {
		t.Errorf("name = %s, want \"SQL injection\"", got)
	}
	if got := string(sqli["implemented_methods"]); got != `["Error messages"]` {
		t.Errorf("implemented_methods = %s, want only the method burpsy's SQL injection check uses", got)
	}
	if !strings.Contains(string(sqli["detection_methods"]), `"Time delays"`) {
		t.Errorf("detection_methods = %s, want Burp's full set including Time delays", sqli["detection_methods"])
	}
	// A type Burp selects by type alone: both lists are [], never null, so the console cannot read an
	// absent list as an unknown one.
	for _, d := range scanner.All() {
		if len(scanner.BurpDetectionMethods(d.TypeIndex)) > 0 {
			continue
		}
		row := byType[fmt.Sprint(d.TypeIndex)]
		if string(row["detection_methods"]) != "[]" || string(row["implemented_methods"]) != "[]" {
			t.Errorf("%s: detection_methods = %s, implemented_methods = %s, want [] and []",
				d.Name, row["detection_methods"], row["implemented_methods"])
		}
		break
	}
}

// libraryScannerServer is a server with both a database (the library needs one) and a scanner whose
// audit route can be run under a saved name.
func libraryScannerServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, id := configuredScannerServer(t, distinctiveBase())
	store, err := persist.Open(filepath.Join(t.TempDir(), "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	s.persist = store
	s.logger = zap.NewNop()
	return s, fmt.Sprint(id)
}

// savedResolved reads one saved configuration's resolved view off the GET listing, as raw JSON per key.
func savedResolved(t *testing.T, s *Server, name string) map[string]json.RawMessage {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleScannerConfigs(rec, httptest.NewRequest(http.MethodGet, "/api/scanner/configs", nil))
	var out struct {
		Configs []struct {
			Name     string                     `json:"name"`
			Resolved map[string]json.RawMessage `json:"resolved"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	for _, c := range out.Configs {
		if c.Name == name {
			return c.Resolved
		}
	}
	t.Fatalf("%q is not in the listing", name)
	return nil
}

// The whole edit the console makes, through the handler, read back as JSON and then run.
func TestTheSelectionAndSkipListsAreWrittenThroughTheLibraryAndAnAuditRunsUnderThem(t *testing.T) {
	s, exchange := libraryScannerServer(t)
	body := fmt.Sprintf(`{"action":"save","name":"tuned","settings":{
		"issue_types":[%d,%d],
		"disabled_issue_types":[%d],
		"disabled_detection_methods":[{"type_index":%d,"method":"Time delays"}],
		"skip_all_tests_for_parameters":["csrf_token"],
		"skip_server_side_injection_for_parameters":[" sort ","id"],
		"per_host_throttle_random":true}}`, sqliType, reflectedXSSType, reflectedXSSType, sqliType)
	if rec := configWrite(t, s, http.MethodPost, body); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}

	want := map[string]string{
		"issue_types":                               fmt.Sprintf("[%d,%d]", sqliType, reflectedXSSType),
		"disabled_issue_types":                      fmt.Sprintf("[%d]", reflectedXSSType),
		"disabled_detection_methods":                fmt.Sprintf(`[{"type_index":%d,"method":"Time delays"}]`, sqliType),
		"skip_all_tests_for_parameters":             `["csrf_token"]`,
		"skip_server_side_injection_for_parameters": `["sort","id"]`,
		"per_host_throttle_random":                  "true",
		"declined_detection_methods":                "[]",
	}
	got := savedResolved(t, s, "tuned")
	for key, w := range want {
		if string(got[key]) != w {
			t.Errorf("listing resolved.%s = %s, want %s", key, got[key], w)
		}
	}

	// The run: the saved document is decoded back into the AuditConfig the audit uses, and the reply
	// echoes the configuration it actually ran under.
	rec := postJSON(t, s, "/api/audit/"+exchange, map[string]any{"config": "tuned"})
	if rec.Code != http.StatusOK {
		t.Fatalf("audit under the saved name: %d %s", rec.Code, rec.Body.String())
	}
	var reply struct {
		ConfigName string                     `json:"config_name"`
		Config     map[string]json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("decode audit reply: %v", err)
	}
	if reply.ConfigName != "tuned" {
		t.Errorf("config_name = %q, want tuned", reply.ConfigName)
	}
	for key, w := range want {
		if string(reply.Config[key]) != w {
			t.Errorf("audit config.%s = %s, want %s", key, reply.Config[key], w)
		}
	}
}

// A second, partial save edits one field and leaves the rest of the saved configuration alone — the
// jitter switch above all, which a plain bool used to reset to false on any save that omitted it.
func TestAPartialSaveKeepsTheFieldsItDoesNotMention(t *testing.T) {
	s, _ := libraryScannerServer(t)
	first := fmt.Sprintf(`{"action":"save","name":"tuned","settings":{"per_host_throttle_random":true,
		"disabled_issue_types":[%d],"skip_all_tests_for_parameters":["csrf_token"]}}`, reflectedXSSType)
	if rec := configWrite(t, s, http.MethodPost, first); rec.Code != http.StatusOK {
		t.Fatalf("first save: %d %s", rec.Code, rec.Body.String())
	}
	second := fmt.Sprintf(`{"action":"save","name":"tuned","from":"tuned","settings":{"issue_types":[%d]}}`, sqliType)
	if rec := configWrite(t, s, http.MethodPost, second); rec.Code != http.StatusOK {
		t.Fatalf("second save: %d %s", rec.Code, rec.Body.String())
	}
	got := savedResolved(t, s, "tuned")
	for key, w := range map[string]string{
		"per_host_throttle_random":      "true",
		"disabled_issue_types":          fmt.Sprintf("[%d]", reflectedXSSType),
		"skip_all_tests_for_parameters": `["csrf_token"]`,
		"issue_types":                   fmt.Sprintf("[%d]", sqliType),
	} {
		if string(got[key]) != w {
			t.Errorf("after a save that did not mention it, resolved.%s = %s, want %s", key, got[key], w)
		}
	}
	// And [] is an explicit clear, distinct from absent.
	clear := `{"action":"save","name":"tuned","from":"tuned","settings":{"issue_types":[],"disabled_issue_types":[],"per_host_throttle_random":false}}`
	if rec := configWrite(t, s, http.MethodPost, clear); rec.Code != http.StatusOK {
		t.Fatalf("clearing save: %d %s", rec.Code, rec.Body.String())
	}
	got = savedResolved(t, s, "tuned")
	if string(got["issue_types"]) != "null" || string(got["disabled_issue_types"]) != "[]" || string(got["per_host_throttle_random"]) != "false" {
		t.Errorf("after clearing: issue_types = %s, disabled_issue_types = %s, per_host_throttle_random = %s; want null (no restriction), [] and false",
			got["issue_types"], got["disabled_issue_types"], got["per_host_throttle_random"])
	}
}

// Every refusal names what it refused, answers 400, and stores nothing.
func TestASelectionEntryThatNamesNothingIsRefusedByName(t *testing.T) {
	s, _ := libraryScannerServer(t)
	for _, tc := range []struct {
		settings string
		mention  string
	}{
		{fmt.Sprintf(`{"issue_types":[%d]}`, notInTheCatalogue), "0x0badf00d"},
		{fmt.Sprintf(`{"disabled_issue_types":[%d]}`, notInTheCatalogue), "0x0badf00d"},
		{fmt.Sprintf(`{"disabled_detection_methods":[{"type_index":%d,"method":"Time delays"}]}`, notInTheCatalogue), "0x0badf00d"},
		// Burp resolves a method name inside its type: "Time delays" is SQL injection's, not reflected XSS's.
		{fmt.Sprintf(`{"disabled_detection_methods":[{"type_index":%d,"method":"Time delays"}]}`, reflectedXSSType), `"Time delays"`},
		{fmt.Sprintf(`{"disabled_detection_methods":[{"type_index":%d,"method":"time delays"}]}`, sqliType), `"time delays"`},
	} {
		rec := configWrite(t, s, http.MethodPost, `{"action":"save","name":"refused","settings":`+tc.settings+`}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s -> %d, want 400", tc.settings, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.mention) {
			t.Errorf("%s -> %q, which does not name %s", tc.settings, rec.Body.String(), tc.mention)
		}
	}
	if _, saved := configNames(t, s)["refused"]; saved {
		t.Error("a refused save still stored a configuration under the operator's name")
	}
}

// A method switched off for a type Burp selects by type alone has nothing to switch off.
func TestADisabledMethodOnAMethodlessTypeIsRefused(t *testing.T) {
	var methodless scanner.IssueDefinition
	for _, d := range scanner.All() {
		if len(scanner.BurpDetectionMethods(d.TypeIndex)) == 0 {
			methodless = d
			break
		}
	}
	_, err := applyConfigOverlay(t, scanner.AuditConfig{},
		fmt.Sprintf(`{"disabled_detection_methods":[{"type_index":%d,"method":"Passive checks"}]}`, methodless.TypeIndex))
	if err == nil || !strings.Contains(err.Error(), "selected by type alone") {
		t.Errorf("%s: err = %v, want a refusal saying the type has no methods", methodless.Name, err)
	}
}

// Writing the deny list drops exactly the "enabled but not implemented" declines it made untrue, and
// keeps the declines that stay true whatever is disabled.
func TestWritingTheDenyListPrunesOnlyTheDeclinesItContradicts(t *testing.T) {
	base := scanner.AuditConfig{DeclinedDetectionMethods: scanner.MethodDeclines{
		{TypeIndex: sqliType, Issue: "SQL injection", Method: "Time delays", Reason: "not implemented"},
		{TypeIndex: sqliType, Issue: "SQL injection", Method: "Boolean conditions", Reason: "not implemented"},
		{TypeIndex: sqliType, Issue: "SQL injection", Method: "Bogus", Reason: "Burp defines no such method"},
		{TypeIndex: notInTheCatalogue, Reason: "not in the catalogue"},
		{TypeIndex: reflectedXSSType, Method: "Server-side template breakout", Reason: "not implemented"},
	}}
	got, err := applyConfigOverlay(t, base,
		fmt.Sprintf(`{"disabled_detection_methods":[{"type_index":%d,"method":"Time delays"}]}`, sqliType))
	if err != nil {
		t.Fatal(err)
	}
	if methods := declineMethods(got.DeclinedDetectionMethods); methods != "Boolean conditions,Bogus,,Server-side template breakout" {
		t.Errorf("after disabling Time delays, declines = %q; want only the Time delays row gone", methods)
	}
	got, err = applyConfigOverlay(t, got, fmt.Sprintf(`{"disabled_issue_types":[%d,%d]}`, reflectedXSSType, sqliType))
	if err != nil {
		t.Fatal(err)
	}
	if methods := declineMethods(got.DeclinedDetectionMethods); methods != "Bogus," {
		t.Errorf("after disabling both types, declines = %q; want the two that stay true (an undefined name, an unknown type)", methods)
	}
	// A write that touches neither deny list leaves the declines alone.
	kept, _ := applyConfigOverlay(t, base, `{"skip_all_tests_for_parameters":["a"]}`)
	if len(kept.DeclinedDetectionMethods) != len(base.DeclinedDetectionMethods) {
		t.Errorf("a write that did not touch the deny list changed the declines: %v", kept.DeclinedDetectionMethods)
	}
}

func declineMethods(d scanner.MethodDeclines) string {
	names := make([]string, 0, len(d))
	for _, r := range d {
		names = append(names, r.Method)
	}
	return strings.Join(names, ",")
}

// A saved row's keys are [], never null. The console's library table reads keys.length, and a null
// there blanked the whole Settings page the moment one configuration was saved — the saq3.3.1 live
// drive found it, since nothing had ever rendered the library with a saved row in it.
func TestASavedConfigurationListsItsKeysAsAnEmptyArray(t *testing.T) {
	s, _ := libraryScannerServer(t)
	if rec := configWrite(t, s, http.MethodPost, `{"action":"save","name":"mine"}`); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := s.persist.SaveScanConfigLibrary("broken", "{not json"); err != nil {
		t.Fatalf("seed a damaged row: %v", err)
	}
	rec := httptest.NewRecorder()
	s.handleScannerConfigs(rec, httptest.NewRequest(http.MethodGet, "/api/scanner/configs", nil))
	var out struct {
		Configs []map[string]json.RawMessage `json:"configs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	seen := 0
	for _, c := range out.Configs {
		var name string
		_ = json.Unmarshal(c["name"], &name)
		if name != "mine" && name != "broken" {
			continue
		}
		seen++
		if string(c["keys"]) != "[]" {
			t.Errorf("%s: keys = %s, want []", name, c["keys"])
		}
	}
	if seen != 2 {
		t.Fatalf("saw %d of the two saved rows", seen)
	}
}
