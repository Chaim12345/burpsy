package web

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"

	_ "modernc.org/sqlite"
)

// ---- Scope libraries (burpsy-react-ui-e365) ------------------------------------------------------
//
// Burp's "Save to library" names a rule set so it can be brought back; burpsy had only the live list,
// so the only way back to yesterday's scope was to retype it. The claims that carry weight here are
// not "a save round-trips" but the two refusals: a load REPLACES the rule list (so it can narrow a
// scope, not only widen one), and a library that cannot be read is refused by name rather than
// installed as nothing — because a core.Scope with no rules is default-allow, and "restore my scope"
// silently becoming "authorise everything" is the worst thing this endpoint could do.
//
// # Why these drive POST /api/scope rather than a route of their own
//
// A library is a saved copy of the scope resource's own state, so it rides that resource: three more
// actions on the switch POST /api/scope already multiplexes, and the listing on the GET that already
// reports the rules. Two URLs that can disagree about what the scope is would be a worse shape than
// a long switch.

// scopeLibraryServer builds a server whose scope is live and whose persistence is a real database,
// because a library that is never written to disk proves nothing about the feature's whole point.
func scopeLibraryServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "project.db")
	store, err := persist.Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s := newTestServer()
	s.persist = store
	s.logger = zap.NewNop()
	return s, path
}

// seedScopeLibraryRow writes a library document the store's own API would never produce — a damaged
// one. It goes in through a second connection to the same file rather than through an exported
// test-only method on Store, because a way to write arbitrary rows into the scope tables is not
// something production code should carry just so a test can describe corruption.
func seedScopeLibraryRow(t *testing.T, dbPath, name, document string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s to seed a damaged library: %v", dbPath, err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO scope_libraries (name, rules_json, saved_at) VALUES (?, ?, ?)`, name, document, 1); err != nil {
		t.Fatalf("seed the %s library: %v", name, err)
	}
}

// postScopeLibrary posts one library action to the scope resource, through the mux the console
// reaches: these actions are part of /api/scope, not a route of their own.
func postScopeLibrary(t *testing.T, s *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return postJSON(t, s, "/api/scope", body)
}

// scopeLibraryListing reads the saved-library list off GET /api/scope, where it rides beside the
// rules.
func scopeLibraryListing(t *testing.T, s *Server) (*httptest.ResponseRecorder, []persist.ScopeLibrary) {
	t.Helper()
	rec := get(t, s, "/api/scope")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scope: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Libraries []persist.ScopeLibrary `json:"libraries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode scope response %q: %v", rec.Body.String(), err)
	}
	return rec, body.Libraries
}

// scopePatterns reads the live rule list as kind|pattern strings, the shape a claim about "which
// rules are in force" is easiest to state in.
func scopePatterns(s *Server) []string {
	out := []string{}
	for _, r := range s.scope.Rules() {
		kind := "include"
		if r.Kind == core.ScopeExclude {
			kind = "exclude"
		}
		out = append(out, kind+"|"+r.Pattern)
	}
	return out
}

func TestScopeLibrary_a_named_rule_set_is_saved_and_loads_back_with_its_arms_intact(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "app.test", "path": "/api", "port": 8443, "protocol": "https"}); rec.Code != http.StatusOK {
		t.Fatalf("seed rule: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "exclude", "pattern": `regex:admin[0-9]\.test`}); rec.Code != http.StatusOK {
		t.Fatalf("seed exclude: status = %d (%s)", rec.Code, rec.Body.String())
	}

	rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": "engagement"})
	if rec.Code != http.StatusOK {
		t.Fatalf("save: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var saved struct {
		Saved    bool `json:"saved"`
		Replaced bool `json:"replaced"`
		Rules    int  `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode save response %q: %v", rec.Body.String(), err)
	}
	if !saved.Saved || saved.Rules != 2 {
		t.Errorf("save reported %+v, want saved with 2 rules; a count that does not match what the page shows means the operator cannot tell what was stored", saved)
	}
	if saved.Replaced {
		t.Error("a first save reported replaced=true; the operator would believe they had just destroyed a rule set that never existed")
	}

	// Clear the live scope the way the operator would, then bring the library back.
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "clear"}); rec.Code != http.StatusOK {
		t.Fatalf("clear: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postScopeLibrary(t, s, map[string]any{"action": "library_load", "name": "engagement"}); rec.Code != http.StatusOK {
		t.Fatalf("load: status = %d (%s)", rec.Code, rec.Body.String())
	}

	rules := s.scope.Rules()
	if len(rules) != 2 {
		t.Fatalf("after the load the scope holds %d rules, want 2; a library that restores a different number of rules than it saved is not a restore", len(rules))
	}
	first := rules[0]
	if first.Port == nil || *first.Port != 8443 || first.PathPrefix == nil || *first.PathPrefix != "/api" || first.Protocol == nil || *first.Protocol != "https" {
		t.Errorf("the restored rule is %+v; a rule that comes back without its port, path or protocol arm authorises more than the operator saved", first)
	}
	// The arms have to be compiled, not just stored: a `regex:` exclude that is present but never
	// compiled is a restriction the table shows and the proxy ignores.
	if s.scope.Contains("admin2.test", 443, "/", true) {
		t.Error("a host the restored regex exclude names is still in scope; the arm survived the round trip as text but was never compiled, so the exclusion the operator restored does nothing")
	}
	if !s.scope.Contains("app.test", 8443, "/api/users", true) {
		t.Error("the restored include does not match the traffic it authorised before the save; the library restored a scope narrower than the one it was taken from")
	}
}

func TestScopeLibrary_loading_replaces_the_live_rule_list_rather_than_merging_into_it(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "saved.test"}); rec.Code != http.StatusOK {
		t.Fatalf("seed: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": "narrow"}); rec.Code != http.StatusOK {
		t.Fatalf("save: status = %d (%s)", rec.Code, rec.Body.String())
	}
	// A rule the library does not carry. Replace semantics mean it must be gone afterwards — that is
	// the whole reason a library can NARROW a scope, and a merge would make it impossible to.
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "added-later.test"}); rec.Code != http.StatusOK {
		t.Fatalf("second rule: status = %d (%s)", rec.Code, rec.Body.String())
	}

	rec := postScopeLibrary(t, s, map[string]any{"action": "library_load", "name": "narrow"})
	if rec.Code != http.StatusOK {
		t.Fatalf("load: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var loaded struct {
		Loaded bool `json:"loaded"`
		Rules  int  `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loaded); err != nil {
		t.Fatalf("decode load response %q: %v", rec.Body.String(), err)
	}
	if !loaded.Loaded || loaded.Rules != 1 {
		t.Errorf("load reported %+v, want 1 rule installed; the number the page shows the operator has to be the number that is now in force", loaded)
	}
	got := scopePatterns(s)
	if len(got) != 1 || got[0] != "include|saved.test" {
		t.Errorf("after the load the scope is %v, want only include|saved.test; a load that merges leaves hosts authorised that the library was supposed to take out of scope, and the page told the operator it would replace them", got)
	}
	if s.scope.Contains("added-later.test", 443, "/", true) {
		t.Error("a host added after the save is still in scope after loading a library that never carried it; the operator believes the library's boundary is in force and it is not")
	}
}

func TestScopeLibrary_a_library_that_cannot_be_read_is_refused_by_name_and_leaves_the_scope_alone(t *testing.T) {
	s, dbPath := scopeLibraryServer(t)
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "live.test"}); rec.Code != http.StatusOK {
		t.Fatalf("seed: status = %d (%s)", rec.Code, rec.Body.String())
	}
	// Two ways a stored library can refuse to become rules: a document that is not JSON, and a
	// document that parses into a rule whose arm does not compile. Both must refuse, and neither may
	// leave the live scope empty — an empty core.Scope is default-allow.
	seedScopeLibraryRow(t, dbPath, "truncated", `[{"kind":"include",`)
	seedScopeLibraryRow(t, dbPath, "uncompilable", `[{"kind":"include","pattern":"regex:[unclosed","enabled":true}]`)
	// A third way, and the one that would widen the scope most quietly: a kind this build does not
	// know. Falling back to "include" would turn a stored exclusion into an authorisation.
	seedScopeLibraryRow(t, dbPath, "strange-kind", `[{"kind":"excluded","pattern":"admin.test","enabled":true}]`)

	for _, name := range []string{"truncated", "uncompilable", "strange-kind"} {
		rec := postScopeLibrary(t, s, map[string]any{"action": "library_load", "name": name})
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("loading the %s library returned %d (%s), want 500; a library that cannot be read must be refused, not installed as an empty rule list or as rules that mean something other than what was stored — an empty scope authorises every host, and an exclusion read as an inclusion authorises the one host it was written to keep out", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), name) {
			t.Errorf("the refusal for %s reads %q and does not name the library; an operator with several saved rule sets cannot tell which one is damaged", name, rec.Body.String())
		}
		if got := scopePatterns(s); len(got) != 1 || got[0] != "include|live.test" {
			t.Fatalf("after the refused load the scope is %v, want the rule that was there before; a failed load that clears the scope first turns a restore into default-allow, which is the exact widening this endpoint exists to avoid", got)
		}
	}
}

func TestScopeLibrary_a_name_with_no_library_is_refused_and_the_refusal_names_what_exists(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "app.test"}); rec.Code != http.StatusOK {
		t.Fatalf("seed: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": "friday"}); rec.Code != http.StatusOK {
		t.Fatalf("save: status = %d (%s)", rec.Code, rec.Body.String())
	}

	for _, action := range []string{"library_load", "library_delete"} {
		rec := postScopeLibrary(t, s, map[string]any{"action": action, "name": "thursday"})
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s of an absent library returned %d (%s), want 404; a delete reported as a success leaves the operator believing a rule set is gone when it is still on disk, and a silent load leaves them believing a scope was restored when it was not", action, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "friday") {
			t.Errorf("the refusal for %s reads %q and does not say which libraries exist; an operator who mistyped a name has to go and look it up instead of reading it off the refusal", action, rec.Body.String())
		}
	}
}

func TestScopeLibrary_a_library_with_no_usable_name_is_refused_before_anything_is_stored(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	for _, name := range []string{"", "   ", "\t\n"} {
		rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": name})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("saving under %q returned %d (%s), want 400; a library with a blank name cannot be picked out of the list again, and the next blank save replaces it with nothing to tell the two apart", name, rec.Code, rec.Body.String())
		}
	}
	_, listed := scopeLibraryListing(t, s)
	if len(listed) != 0 {
		t.Errorf("the refused saves still left %d libraries behind (%+v); the refusal was reported to the operator and written anyway", len(listed), listed)
	}
}

func TestScopeLibrary_saving_over_an_existing_name_says_that_it_replaced_one(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "first.test"}); rec.Code != http.StatusOK {
		t.Fatalf("seed: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": "engagement"}); rec.Code != http.StatusOK {
		t.Fatalf("first save: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "second.test"}); rec.Code != http.StatusOK {
		t.Fatalf("second rule: status = %d (%s)", rec.Code, rec.Body.String())
	}

	rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": " engagement "})
	if rec.Code != http.StatusOK {
		t.Fatalf("second save: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var saved struct {
		Replaced bool `json:"replaced"`
		Rules    int  `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode save response %q: %v", rec.Body.String(), err)
	}
	if !saved.Replaced {
		t.Error("saving over a library reported replaced=false; the toast then says 'saved' for something that destroyed an earlier rule set, which the operator only discovers when they try to load it")
	}
	if saved.Rules != 2 {
		t.Errorf("the overwrite stored %d rules, want 2; the library no longer holds the scope the page was showing when the operator saved it", saved.Rules)
	}
	// The surrounding whitespace must not have created a second library: the picker shows the
	// trimmed name, and a name the picker cannot express is a rule set the operator cannot reach.
	_, listed := scopeLibraryListing(t, s)
	if len(listed) != 1 || listed[0].Name != "engagement" || listed[0].Rules != 2 {
		t.Errorf("the listing is %+v, want one entry named engagement with 2 rules; a padded name that stores a second library leaves two rule sets the picker draws identically", listed)
	}
}

func TestScopeLibrary_the_listing_reports_every_saved_name_with_its_rule_count(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "include", "pattern": "one.test"}); rec.Code != http.StatusOK {
		t.Fatalf("seed: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": "one-rule"}); rec.Code != http.StatusOK {
		t.Fatalf("save one-rule: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, s, "/api/scope", map[string]any{"action": "exclude", "pattern": "two.test"}); rec.Code != http.StatusOK {
		t.Fatalf("second rule: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": "two-rules"}); rec.Code != http.StatusOK {
		t.Fatalf("save two-rules: status = %d (%s)", rec.Code, rec.Body.String())
	}

	rec, listed := scopeLibraryListing(t, s)
	// Asserted against the marshalled JSON rather than the Go value: the page reads .length on this
	// array, and a Go nil slice reaches the browser as null, which takes the whole page down.
	if !strings.Contains(rec.Body.String(), `"libraries":[`) {
		t.Errorf("the scope response is %s; libraries must marshal as an array — a null there is read as .length by the page and takes the scope view down with it", rec.Body.String())
	}
	counts := map[string]int{}
	for _, lib := range listed {
		counts[lib.Name] = lib.Rules
		if lib.SavedAt <= 0 {
			t.Errorf("library %q lists saved_at %d; the picker cannot tell the operator which of two rule sets is the recent one", lib.Name, lib.SavedAt)
		}
	}
	if counts["one-rule"] != 1 || counts["two-rules"] != 2 {
		t.Errorf("the listing reports %v, want one-rule=1 two-rules=2; a count that does not match what a load would install misleads the operator about the scope they are about to replace", counts)
	}
}

func TestScopeLibrary_an_empty_listing_is_served_as_an_empty_array(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	rec, listed := scopeLibraryListing(t, s)
	if len(listed) != 0 {
		t.Errorf("a database with nothing saved lists %+v; the picker would offer libraries that do not exist", listed)
	}
	// The marshalled shape, not the decoded one: a nil slice decodes to an empty slice just fine and
	// reaches the browser as null, where the picker reads .length on it and takes the page down.
	if !strings.Contains(rec.Body.String(), `"libraries":[]`) {
		t.Errorf("an empty listing serves %s; libraries must be [] and never null", rec.Body.String())
	}
}

func TestScopeLibrary_a_console_with_no_project_database_still_serves_the_scope_with_an_empty_listing(t *testing.T) {
	// Running without a project file is a supported configuration, not a fault: the scope page has
	// to draw, with a picker that says nothing is saved rather than an error where the rules go.
	s := newTestServer()
	rec, listed := scopeLibraryListing(t, s)
	if len(listed) != 0 {
		t.Errorf("a console with no database lists %+v libraries; there is nowhere for one to have been stored", listed)
	}
	if strings.Contains(rec.Body.String(), "libraries_error") {
		t.Errorf("the scope response reports a library error (%s); having no project database is a configuration, not a failure, and an error here would make the page look broken", rec.Body.String())
	}
}

func TestScopeLibrary_without_a_project_database_the_endpoint_says_so_rather_than_failing(t *testing.T) {
	s := newTestServer() // no persist: the console can run without a project file
	rec := postScopeLibrary(t, s, map[string]any{"action": "library_save", "name": "engagement"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("save without a database returned %d (%s), want 503; the request is well formed and this configuration cannot store anything, which the operator has to be told rather than left to read a 500 as a bug", rec.Code, rec.Body.String())
	}
}

func TestScopeLibrary_an_unknown_action_is_refused_rather_than_treated_as_one_of_the_three(t *testing.T) {
	s, _ := scopeLibraryServer(t)
	rec := postScopeLibrary(t, s, map[string]any{"action": "library_overwrite_everything", "name": "engagement"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown action returned %d (%s), want 400; an action this endpoint does not know must not fall through to one that changes the engagement's scope", rec.Code, rec.Body.String())
	}
}
