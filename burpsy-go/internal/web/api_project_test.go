package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// ---- the Project surface (burpsy-react-ui-je3y) -------------------------------------------------
//
// burpsy's project IS the -db file, so these tests pin the three facts the Project menu states
// about it: which name the operator gave it (and that the name survives a reopen, because a name
// that died with the process was never a project name), which file it lives in, and — when there
// is no -db — that every Project-menu item which needs durability says so rather than failing.

// newProjectServer is a server with a real persist store behind it, which is the state a running
// burpsy has whenever it was started with -db. The store is closed by the test because the
// project routes read through it; a leaked handle would hold the temp file open on Windows.
func newProjectServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	p, err := persist.Open(filepath.Join(dir, "project.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return NewServer(core.NewTrafficStore(), core.NewScope()).WithPersist(p)
}

// An unnamed project reads as the "Unnamed" placeholder and says so with unnamed: true, because
// "the operator named it Unnamed" and "it was never named" are different facts and a stored
// placeholder would make them indistinguishable forever after.
func TestAnUnsetProjectNameReadsAsUnnamedAndSaysSo(t *testing.T) {
	s := newProjectServer(t)

	rec := get(t, s, "/api/project/name")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/project/name = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var view projectView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Name != "Unnamed" || !view.Unnamed {
		t.Fatalf("an unset name read as %q unnamed=%v, want \"Unnamed\" true — the placeholder must "+
			"be distinguishable from a name the operator actually typed", view.Name, view.Unnamed)
	}
}

// The readout names the file the project lives in, and — with no persistence — it must not
// render the missing file as an empty path, because "no file" and "no durability" are different
// states and the menu's other items hang off which one is true.
func TestTheProjectReadoutNamesTheFileOrSaysNothingIsPersisted(t *testing.T) {
	s := newProjectServer(t)
	rec := get(t, s, "/api/project")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/project = %d", rec.Code)
	}
	var view projectView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !view.Persisted || !view.Backupable {
		t.Fatalf("a server with a persist store read persisted=%v backupable=%v, want both true",
			view.Persisted, view.Backupable)
	}
	if !strings.HasSuffix(view.Database, "project.db") {
		t.Fatalf("the readout names %q, want the -db path — an operator who cannot see which file "+
			"the project lives in cannot tell two engagements apart", view.Database)
	}
	if view.Unnamed != true || view.Name != "Unnamed" {
		t.Fatalf("fresh project read as %q, want Unnamed", view.Name)
	}

	// The same readout on a server built without persistence (direct construction, the state of
	// every existing test server and of a burpsy started with no -db).
	bare := newTestServer()
	rec = get(t, bare, "/api/project")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/project on a bare server = %d", rec.Code)
	}
	var bareView projectView
	if err := json.Unmarshal(rec.Body.Bytes(), &bareView); err != nil {
		t.Fatalf("decode bare view: %v", err)
	}
	if bareView.Persisted || bareView.Backupable || bareView.Database != "" {
		t.Fatalf("a bare server read persisted=%v backupable=%v database=%q; nothing is durable and "+
			"an empty path would read as \"a project that has no file yet\"", bareView.Persisted,
			bareView.Backupable, bareView.Database)
	}
	if bareView.DatabaseNote == "" {
		t.Fatalf("the bare readout carried no note; the menu needs the reason to label its items, " +
			"and a disabled item without a reason is the dead end this build refuses to ship")
	}
}

// A rename goes through PUT and survives a reopen of the same database — the property that makes
// it a project name rather than a process label. The persist package has the reopen half of that
// assertion; this test holds the wire half: what the API answered is what the file kept.
func TestRenamingAProjectStoresTheNameWithTheDatabase(t *testing.T) {
	dir := t.TempDir()
	p, err := persist.Open(filepath.Join(dir, "engagement.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithPersist(p)

	rec := putJSON(t, s, "/api/project/name", map[string]string{"name": "Springfield bank, phase 2"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/project/name = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var view projectView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode rename answer: %v", err)
	}
	if view.Name != "Springfield bank, phase 2" || view.Unnamed {
		t.Fatalf("rename answered %q unnamed=%v, want the stored name and named", view.Name, view.Unnamed)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened, err := persist.Open(filepath.Join(dir, "engagement.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	s2 := NewServer(core.NewTrafficStore(), core.NewScope()).WithPersist(reopened)
	rec = get(t, s2, "/api/project/name")
	var reread projectView
	if err := json.Unmarshal(rec.Body.Bytes(), &reread); err != nil {
		t.Fatalf("decode reread: %v", err)
	}
	if reread.Name != "Springfield bank, phase 2" {
		t.Fatalf("after a reopen the project reads as %q — the name did not travel with the "+
			"database, so it was never attached to the project at all", reread.Name)
	}
}

// A blank name is refused, never stored: the readout renders the absent name as "Unnamed", and a
// stored blank (or a stored "Unnamed") would be indistinguishable from the placeholder it renders.
func TestABlankProjectNameIsRefusedNotStored(t *testing.T) {
	s := newProjectServer(t)
	for _, name := range []string{"", "   "} {
		rec := putJSON(t, s, "/api/project/name", map[string]string{"name": name})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("PUT with name %q = %d, want 400 — a blank stored as a name would become "+
				"indistinguishable from the Unnamed placeholder", name, rec.Code)
		}
	}
	rec := get(t, s, "/api/project/name")
	var view projectView
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.Name != "Unnamed" || !view.Unnamed {
		t.Fatalf("after refused renames the project reads %q unnamed=%v; the refusals must not have "+
			"written anything", view.Name, view.Unnamed)
	}
}

// A bare server refuses the PUT with 503 rather than a 200 that stored nothing, because a rename
// that answers ok on a process with no database is a rename that cannot survive the process.
func TestRenamingWithoutPersistenceIsRefusedWithTheReason(t *testing.T) {
	bare := newTestServer()
	rec := putJSON(t, bare, "/api/project/name", map[string]string{"name": "nowhere"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT on a bare server = %d, want 503 — the name lives in the database, and there "+
			"is none", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "persistence") {
		t.Fatalf("the refusal does not say why: %s", rec.Body.String())
	}

	// GET still works and still answers "Unnamed" — reading the state is not the act that needs
	// the database, and a menu that could not even display the name would be hiding the reason.
	rec = get(t, bare, "/api/project/name")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET on a bare server = %d, want 200: the readout must still say what the state is", rec.Code)
	}
}

// The manifest's verb contract is enforced by the 405 sweep; this test pins the shape the menu
// actually consumes: the readout and the name are two routes, not one, so that the name's PUT
// can be riskLocal while the readout stays riskRead — the gate treats them differently and so
// must the manifest.
func TestTheProjectRoutesDeclareTheirVerbs(t *testing.T) {
	if m := manifest["/api/project"]; len(m.methods) != 1 || m.methods[0] != "GET" {
		t.Fatalf("/api/project declares methods %v, want [GET]", m.methods)
	}
	if m := manifest["/api/project/name"]; len(m.methods) != 2 || m.methods[0] != "GET" || m.methods[1] != "PUT" {
		t.Fatalf("/api/project/name declares methods %v, want [GET PUT]", m.methods)
	}
	if manifest["/api/project"].risk != riskRead {
		t.Fatalf("the readout must be riskRead: it sends nothing and writes nothing")
	}
	if manifest["/api/project/name"].risk != riskLocal {
		t.Fatalf("the name's write is burpsy's own state, which is the definition of riskLocal")
	}
}

var _ = httptest.NewRequest // keep the import honest if assertions above change shape
