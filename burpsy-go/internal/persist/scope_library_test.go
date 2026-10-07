package persist

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// ---- Scope libraries (burpsy-react-ui-e365) ------------------------------------------------------
//
// A named rule set that can be loaded back is only worth having if what comes back is what went in,
// arm for arm, and if a document that cannot be read is refused rather than returned as nothing. The
// second claim is the one that carries weight: core.Scope with no rules is default-allow, so a
// corrupt library that loaded as an empty rule set would widen an engagement's authorisation to
// everything at the moment the operator believed they were restoring a restriction.

func openStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return store
}

func port(v uint16) *uint16 { return &v }
func text(v string) *string { return &v }

func Test_a_saved_scope_library_comes_back_with_every_arm_it_was_saved_with(t *testing.T) {
	store := openStore(t)
	saved := []*core.ScopeRule{
		core.NewScopeRule(core.ScopeInclude, "app.test"),
		{Kind: core.ScopeInclude, Pattern: "api.test", Port: port(8443), PathPrefix: text("/v1"), Protocol: text("https"), Enabled: true},
		{Kind: core.ScopeExclude, Pattern: `regex:admin[0-9]\.test`, Enabled: false},
	}
	if replaced, err := store.SaveScopeLibrary("engagement", saved); err != nil || replaced {
		t.Fatalf("SaveScopeLibrary = (%v, %v), want (false, nil); a first save must not report a replacement", replaced, err)
	}

	rules, found, err := store.LoadScopeLibrary("engagement")
	if err != nil || !found {
		t.Fatalf("LoadScopeLibrary = (found %v, err %v); a library saved in this test is not readable back, so nothing stored survives a restart", found, err)
	}
	if len(rules) != 3 {
		t.Fatalf("LoadScopeLibrary returned %d rules, want 3; a rule that vanished between save and load is an authorisation boundary the operator believes is in force and is not", len(rules))
	}
	if rules[1].Port == nil || *rules[1].Port != 8443 || rules[1].PathPrefix == nil || *rules[1].PathPrefix != "/v1" ||
		rules[1].Protocol == nil || *rules[1].Protocol != "https" {
		t.Errorf("the port/path/protocol arms came back as %+v; a rule restored without its arms covers more than the operator authorised", rules[1])
	}
	if rules[2].Kind != "exclude" || rules[2].Enabled {
		t.Errorf("the disabled exclude came back as %+v; a rule that changes kind or wakes up enabled means the library does not describe the scope it was taken from", rules[2])
	}
	if rules[0].Enabled != true {
		t.Errorf("the plain include came back disabled (%+v); a restored scope with silently inactive rules excludes traffic the operator allowed", rules[0])
	}
}

func Test_saving_over_a_scope_library_reports_that_it_replaced_one(t *testing.T) {
	store := openStore(t)
	if _, err := store.SaveScopeLibrary("engagement", []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "first.test")}); err != nil {
		t.Fatalf("first SaveScopeLibrary: %v", err)
	}
	replaced, err := store.SaveScopeLibrary("engagement", []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "second.test")})
	if err != nil {
		t.Fatalf("second SaveScopeLibrary: %v", err)
	}
	if !replaced {
		t.Error("saving over an existing library reported replaced=false; the operator is never told they overwrote a rule set, which is how a saved scope is lost silently")
	}
	rules, _, err := store.LoadScopeLibrary("engagement")
	if err != nil {
		t.Fatalf("LoadScopeLibrary: %v", err)
	}
	if len(rules) != 1 || rules[0].Pattern != "second.test" {
		t.Errorf("after the overwrite the library holds %+v; an overwrite that keeps the old rules means the library no longer matches what the operator saved", rules)
	}
}

func Test_a_scope_library_whose_document_cannot_be_parsed_is_refused_by_name(t *testing.T) {
	store := openStore(t)
	if _, err := store.db.Exec(
		`INSERT INTO scope_libraries (name, rules_json, saved_at) VALUES (?, ?, ?)`,
		"corrupt", `[{"kind":"include",`, 1700000000000); err != nil {
		t.Fatalf("seed a corrupt library row: %v", err)
	}

	rules, found, err := store.LoadScopeLibrary("corrupt")
	if err == nil {
		t.Fatal("a library holding unparseable JSON loaded without an error; it would reach the live scope as an empty rule list, and an empty scope is default-allow — the engagement would silently authorise everything")
	}
	if !found {
		t.Error("the corrupt library reported found=false; that reads as a typo in the name rather than as data the operator has lost, and they would stop looking for it")
	}
	if len(rules) != 0 {
		t.Errorf("the refusal still returned %d rules; a half-read authorisation document must not reach the scope at all", len(rules))
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("the refusal reads %q and does not name the library; an operator with several libraries cannot tell which one to re-create", err)
	}
}

func Test_listing_scope_libraries_reports_counts_without_the_rule_bodies(t *testing.T) {
	store := openStore(t)
	if _, err := store.SaveScopeLibrary("one", []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "a.test")}); err != nil {
		t.Fatalf("SaveScopeLibrary one: %v", err)
	}
	if _, err := store.SaveScopeLibrary("two", []*core.ScopeRule{
		core.NewScopeRule(core.ScopeInclude, "b.test"),
		core.NewScopeRule(core.ScopeExclude, "c.test"),
	}); err != nil {
		t.Fatalf("SaveScopeLibrary two: %v", err)
	}
	if _, err := store.db.Exec(
		`INSERT INTO scope_libraries (name, rules_json, saved_at) VALUES (?, ?, ?)`,
		"corrupt", `not json at all`, 1); err != nil {
		t.Fatalf("seed a corrupt library row: %v", err)
	}

	list, err := store.LoadScopeLibraries()
	if err != nil {
		t.Fatalf("LoadScopeLibraries: %v", err)
	}
	counts := map[string]int{}
	for _, lib := range list {
		counts[lib.Name] = lib.Rules
		if lib.SavedAt == 0 {
			t.Errorf("library %q lists saved_at 0; the picker cannot tell the operator which of two similarly named rule sets is the recent one", lib.Name)
		}
	}
	if counts["one"] != 1 || counts["two"] != 2 {
		t.Errorf("the listing reports counts %v, want one=1 two=2; a count that does not match the stored rules misleads the operator about what a load would install", counts)
	}
	if _, listed := counts["corrupt"]; !listed {
		t.Error("the unreadable library is missing from the listing; a name that exists and is not shown is a name the operator will save over by accident")
	}
	if counts["corrupt"] != -1 {
		t.Errorf("the unreadable library lists %d rules, want -1; reporting 0 is indistinguishable from an empty rule set, which is the one number that must never be guessed about a scope", counts["corrupt"])
	}
}

func Test_deleting_a_scope_library_that_is_not_there_reports_that_nothing_was_deleted(t *testing.T) {
	store := openStore(t)
	if _, err := store.SaveScopeLibrary("keep", []*core.ScopeRule{core.NewScopeRule(core.ScopeInclude, "keep.test")}); err != nil {
		t.Fatalf("SaveScopeLibrary: %v", err)
	}

	if deleted, err := store.DeleteScopeLibrary("never-saved"); err != nil || deleted {
		t.Errorf("DeleteScopeLibrary(absent) = (%v, %v), want (false, nil); reporting a delete that did not happen tells the operator a rule set is gone when it is still on disk", deleted, err)
	}
	if deleted, err := store.DeleteScopeLibrary("keep"); err != nil || !deleted {
		t.Errorf("DeleteScopeLibrary(present) = (%v, %v), want (true, nil); a delete that reports nothing happened leaves the operator retrying a delete that already worked", deleted, err)
	}
	if _, found, err := store.LoadScopeLibrary("keep"); err != nil || found {
		t.Errorf("the deleted library is still readable (found %v, err %v); a delete that leaves the document behind means a name the operator expects to be free is not", found, err)
	}
}

func Test_a_scope_library_survives_reopening_the_database(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "project.db")
	store, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := store.SaveScopeLibrary("restart", []*core.ScopeRule{
		{Kind: core.ScopeInclude, Pattern: "app.test", PathPrefix: text("/api"), Enabled: true},
	}); err != nil {
		t.Fatalf("SaveScopeLibrary: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	rules, found, err := reopened.LoadScopeLibrary("restart")
	if err != nil || !found {
		t.Fatalf("after reopening: LoadScopeLibrary = (found %v, err %v); the library did not outlive the process, which is the whole reason it is stored rather than held in memory", found, err)
	}
	if len(rules) != 1 || rules[0].PathPrefix == nil || *rules[0].PathPrefix != "/api" {
		t.Errorf("after reopening the library holds %+v; a restored rule missing its path arm covers the whole host the operator limited", rules)
	}
}
