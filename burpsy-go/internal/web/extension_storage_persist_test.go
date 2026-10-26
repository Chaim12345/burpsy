package web

// 97dk: plugin storage is per project (the file is <project>.db.extensions.json). What is pinned
// here is that it really is: the file is read before the first write, the path is the project open
// NOW (not the one at the moment services were built), project A's rows never reach project B and
// come back on A, and a file that cannot be parsed is refused rather than overwritten.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/extension"
	"github.com/burpsy-go/burpsy/internal/persist"
)

func openProject(t *testing.T, dir, name string) *persist.Store {
	t.Helper()
	p, err := persist.Open(filepath.Join(dir, name), zap.NewNop())
	if err != nil {
		t.Fatalf("persist.Open %s: %v", name, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func readStorageFile(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s is not JSON: %v", path, err)
	}
	return m
}

func mustGet(t *testing.T, st extension.Storage, key string) (string, bool) {
	t.Helper()
	v, found, err := st.Get("plug", extension.ScopeProject, key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	return string(v), found
}

func Test_storage_reads_the_existing_file_before_the_first_write(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.db") + ".extensions.json"
	seed, _ := json.Marshal(map[string]json.RawMessage{
		extensionStorageKey("plug", extension.ScopeProject, "old"): json.RawMessage(`"kept"`),
	})
	if err := os.WriteFile(file, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer()
	s.WithPersist(openProject(t, dir, "a.db"))
	st := s.ExtensionServices().Storage

	if v, found := mustGet(t, st, "old"); !found || v != `"kept"` {
		t.Fatalf("a row from the file did not read back: %q found=%v", v, found)
	}
	if err := st.Set("plug", extension.ScopeProject, "new", json.RawMessage(`1`)); err != nil {
		t.Fatalf("set: %v", err)
	}
	onDisk := readStorageFile(t, file)
	if len(onDisk) != 2 {
		t.Fatalf("first write replaced the file: %d rows on disk, want 2 (old + new): %v", len(onDisk), onDisk)
	}
}

func Test_storage_services_built_before_the_project_is_attached_still_persist(t *testing.T) {
	// main.go builds the services before WithPersist; the path must be resolved when used.
	dir := t.TempDir()
	s := newTestServer()
	st := s.ExtensionServices().Storage // persist is still nil here
	s.WithPersist(openProject(t, dir, "a.db"))

	if err := st.Set("plug", extension.ScopeProject, "k", json.RawMessage(`"v"`)); err != nil {
		t.Fatalf("set: %v", err)
	}
	file := filepath.Join(dir, "a.db") + ".extensions.json"
	if got := readStorageFile(t, file); len(got) != 1 {
		t.Fatalf("storage did not land beside the project: %v", got)
	}
}

func Test_storage_follows_the_project_A_to_B_to_A_without_leaking(t *testing.T) {
	dir := t.TempDir()
	s := newTestServer()
	st := s.ExtensionServices().Storage
	s.WithPersist(openProject(t, dir, "a.db"))
	if err := st.Set("plug", extension.ScopeProject, "k", json.RawMessage(`"A"`)); err != nil {
		t.Fatal(err)
	}

	s.WithPersist(openProject(t, dir, "b.db"))
	if v, found := mustGet(t, st, "k"); found {
		t.Fatalf("project A's row is visible in project B: %q", v)
	}
	if err := st.Set("plug", extension.ScopeProject, "k", json.RawMessage(`"B"`)); err != nil {
		t.Fatal(err)
	}

	s.WithPersist(openProject(t, dir, "a.db"))
	if v, found := mustGet(t, st, "k"); !found || v != `"A"` {
		t.Fatalf("project A's row did not come back: %q found=%v", v, found)
	}
	// Delete is write-through to the current project only.
	if err := st.Delete("plug", extension.ScopeProject, "k"); err != nil {
		t.Fatal(err)
	}
	if got := readStorageFile(t, filepath.Join(dir, "a.db")+".extensions.json"); len(got) != 0 {
		t.Fatalf("delete did not reach A's file: %v", got)
	}
	if got := readStorageFile(t, filepath.Join(dir, "b.db")+".extensions.json"); len(got) != 1 {
		t.Fatalf("deleting in A changed B's file: %v", got)
	}
}

func Test_storage_with_no_project_is_memory_only_and_missing_file_is_empty(t *testing.T) {
	s := newTestServer()
	st := s.ExtensionServices().Storage
	if err := st.Set("plug", extension.ScopeProject, "k", json.RawMessage(`1`)); err != nil {
		t.Fatal(err)
	}
	if v, found := mustGet(t, st, "k"); !found || v != `1` {
		t.Fatalf("memory round trip: %q %v", v, found)
	}
	dir := t.TempDir()
	s2 := newTestServer()
	s2.WithPersist(openProject(t, dir, "fresh.db"))
	if _, found := mustGet(t, s2.ExtensionServices().Storage, "nothing"); found {
		t.Fatal("a missing file read as non-empty")
	}
}

func Test_storage_refuses_to_overwrite_a_file_it_cannot_parse(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.db") + ".extensions.json"
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer()
	s.WithPersist(openProject(t, dir, "a.db"))
	st := s.ExtensionServices().Storage
	if err := st.Set("plug", extension.ScopeProject, "k", json.RawMessage(`1`)); err == nil {
		t.Fatal("set succeeded over an unparseable file")
	}
	if raw, _ := os.ReadFile(file); string(raw) != "{not json" {
		t.Fatalf("the unparseable file was rewritten: %q", raw)
	}
}
