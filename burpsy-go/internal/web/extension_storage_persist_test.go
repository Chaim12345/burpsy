package web

// 97dk: plugin storage is per project (the file is <project>.db.extensions.json). What is pinned
// here is that it really is: the file is read before the first write, the path is the project open
// NOW (not the one at the moment services were built), project A's rows never reach project B and
// come back on A, and a file that cannot be parsed is refused rather than overwritten.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// An existing file that is empty (or any bytes that are not a JSON object) is a parse failure and
// is refused like any other corrupt file. It is NOT the same as a missing file, which is an empty
// store. Our own writes go temp file then rename, so a zero-byte document is not something this
// code produces; refusing is the conservative reading.
func Test_storage_treats_an_empty_existing_file_as_unparseable_not_as_missing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.db") + ".extensions.json"
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer()
	s.WithPersist(openProject(t, dir, "a.db"))
	st := s.ExtensionServices().Storage
	if _, _, err := st.Get("plug", extension.ScopeProject, "k"); err == nil {
		t.Fatal("an empty existing file read as an empty store")
	}
	if err := st.Set("plug", extension.ScopeProject, "k", json.RawMessage(`1`)); err == nil {
		t.Fatal("set succeeded over an empty existing file")
	}
	if fi, _ := os.Stat(file); fi == nil || fi.Size() != 0 {
		t.Fatal("the empty file was rewritten")
	}
}

// Both scopes share the project's document and stay distinct inside it. "preferences" is per
// project here (as before this fix), not user-level.
func Test_storage_keeps_both_scopes_in_the_project_document_and_distinct(t *testing.T) {
	dir := t.TempDir()
	s := newTestServer()
	s.WithPersist(openProject(t, dir, "a.db"))
	st := s.ExtensionServices().Storage
	if err := st.Set("plug", extension.ScopeProject, "k", json.RawMessage(`"proj"`)); err != nil {
		t.Fatal(err)
	}
	if err := st.Set("plug", extension.ScopePreferences, "k", json.RawMessage(`"pref"`)); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := st.Get("plug", extension.ScopeProject, "k"); string(v) != `"proj"` {
		t.Errorf("project scope read %q", v)
	}
	if v, _, _ := st.Get("plug", extension.ScopePreferences, "k"); string(v) != `"pref"` {
		t.Errorf("preferences scope read %q", v)
	}
	if got := readStorageFile(t, filepath.Join(dir, "a.db")+".extensions.json"); len(got) != 2 {
		t.Fatalf("document holds %d rows, want 2 (one per scope): %v", len(got), got)
	}
	s.WithPersist(openProject(t, dir, "b.db"))
	if _, found, _ := st.Get("plug", extension.ScopePreferences, "k"); found {
		t.Fatal("preferences followed the operator into another project (they are per project)")
	}
}

// The race the integrator asked for, through the real handler: POST /api/project/open takes the
// project-switch WRITE lock, storage takes the READ side. Writers hammer Get/Set while the
// console switches A->B->A repeatedly. Run under -race. It fails by deadlock (the test timeout),
// by the race detector, by a torn read (the per-project marker must read as exactly that
// project's value), or by a document that stops being valid JSON.
func Test_storage_operations_race_a_real_project_switch_without_tearing_or_deadlock(t *testing.T) {
	dir := t.TempDir()
	aPath, bPath := filepath.Join(dir, "a.db"), filepath.Join(dir, "b.db")
	a, b := openProject(t, dir, "a.db"), openProject(t, dir, "b.db")
	s := newTestServer()
	st := s.ExtensionServices().Storage
	s.WithPersist(a)
	if err := st.Set("plug", extension.ScopeProject, "marker", json.RawMessage(`"A"`)); err != nil {
		t.Fatal(err)
	}
	s.WithPersist(b)
	if err := st.Set("plug", extension.ScopeProject, "marker", json.RawMessage(`"B"`)); err != nil {
		t.Fatal(err)
	}
	s.WithPersist(a)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bad atomic.Int32
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				v, found, err := st.Get("plug", extension.ScopeProject, "marker")
				if err != nil || !found || (string(v) != `"A"` && string(v) != `"B"`) {
					bad.Add(1)
				}
				if err := st.Set("plug", extension.ScopeProject, "w"+string(rune('0'+w)), json.RawMessage(`1`)); err != nil {
					bad.Add(1)
				}
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 6; i++ {
			next := bPath
			if i%2 == 1 {
				next = aPath
			}
			if rec := openProjectSwitch(t, s, next); rec.Code != http.StatusOK {
				t.Errorf("switch %d = %d: %s", i, rec.Code, rec.Body.String())
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("deadlock: switches did not finish while storage operations were running")
	}
	close(stop)
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d storage operations errored or read a torn marker during switches", n)
	}
	for name, want := range map[string]string{aPath: `"A"`, bPath: `"B"`} {
		rows := readStorageFile(t, name+".extensions.json")
		if got := string(rows[extensionStorageKey("plug", extension.ScopeProject, "marker")]); got != want {
			t.Errorf("%s marker = %q, want %q", filepath.Base(name), got, want)
		}
	}
}
