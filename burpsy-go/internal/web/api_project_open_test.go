package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// ---- in-console project switch (burpsy-react-ui-dlw2) --------------------------------------------
//
// The acceptance claim is that switching engagements stops needing a relaunch, and the failure
// this file exists to prevent is the one a pointer swap would produce: the console keeps serving
// project A's traffic while appending to project B's file. So the tests are about WHAT THE
// CONSOLE SERVES AFTER A SWITCH, not about whether the route exists or returns 200.

// guardedSwitch drives one request through s.guarded — the same chain the gate's own tests use,
// and the reason the mint is reachable at all: confirmations are served from a SEPARATE mux
// (confirmMux) that the gate consults before the route mux, because a mint is itself a mutating
// POST on a gated pattern and gating it would make the gate unsatisfiable. Driving s.mux
// directly would skip the gate entirely, and a test that did that would be testing a route no
// client can reach — the switch would answer 200 to anyone who skipped the mint.
func guardedSwitch(t *testing.T, srv *Server, method, path, body string, confirm string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// The loopback Host and matching Origin, because the cross-site gate is OUTER and s.guarded
	// serves it too: a mutating request whose Host is not this console is refused 403 before the
	// confirmation gate is ever consulted. httptest's default Host is example.com, so a request
	// that does not set these is not one the console would have answered — the console's own
	// fetch() carries exactly these two.
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	if confirm != "" {
		req.Header.Set(ConfirmHeader, confirm)
	}
	rec := httptest.NewRecorder()
	srv.guarded.ServeHTTP(rec, req)
	return rec
}

// mintSwitchConfirmation asks the gate for a confirmation against the switch route, exactly as
// the console's useOpenProject does.
func mintSwitchConfirmation(t *testing.T, srv *Server, body string) string {
	t.Helper()
	desc, err := json.Marshal(map[string]string{"method": http.MethodPost, "url": "/api/project/open", "body": body})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := guardedSwitch(t, srv, http.MethodPost, "/api/project/open/confirm", string(desc), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("minting the switch confirmation = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var minted struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode mint: %v", err)
	}
	if minted.Token == "" {
		t.Fatalf("the mint returned no token: %s", rec.Body.String())
	}
	return minted.Token
}

// openProjectSwitch drives POST /api/project/open the way the console does — mint the
// confirmation first, then spend it — because a bare POST is refused 428 and a test that skipped
// the mint would be testing a route no client can reach.
func openProjectSwitch(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"path": path})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return guardedSwitch(t, srv, http.MethodPost, "/api/project/open", string(raw), mintSwitchConfirmation(t, srv, string(raw)))
}

// seedCapture puts one exchange into the store the console serves, so a test can tell which
// project's history it is looking at afterwards. Through the store's own public appends rather
// than by poking its fields, because the store is the thing under test.
func seedCapture(t *testing.T, srv *Server, host string) {
	t.Helper()
	if _, err := srv.store.Put([]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest); err != nil {
		t.Fatalf("put the request: %v", err)
	}
	srv.store.AddExchange(&core.Exchange{Host: host, Port: 80, Method: "GET", Path: "/"})
}

// The switch's whole point: after it, the console serves the INCOMING project's captured traffic.
// A switch that re-pointed the mirror without re-running the restore would pass every "did the
// path change" check and fail this one — it would serve the outgoing project's history from the
// incoming project's file, which is the bug the bead exists to prevent.
func TestSwitchingProjectsServesTheIncomingProjectsTrafficNotTheOutgoingOnes(t *testing.T) {
	dir := t.TempDir()
	first, err := persist.Open(filepath.Join(dir, "first.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open first: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	srv := newTestServer().WithPersist(first)
	// Seed the outgoing project and let it reach its file, the way a real session would.
	seedCapture(t, srv, "outgoing.test")
	// No hand-written row: the sink WithPersist installed already mirrored the capture above, which
	// is both how a real session writes one and the only version whose id the store agrees with
	// (AddExchange assigns the id by position, so a hand-written ID 0 would be rewritten).

	// The incoming project: a file with one exchange of its own, on a different host.
	second, err := persist.Open(filepath.Join(dir, "second.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	second.SaveExchange(&core.Exchange{Host: "incoming.test", Port: 80, Method: "GET", Path: "/"})
	_ = second.Close()

	rec := openProjectSwitch(t, srv, filepath.Join(dir, "second.db"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the switch = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	// The path moved.
	var view projectView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode the switch answer: %v", err)
	}
	if !strings.HasSuffix(view.Database, "second.db") {
		t.Fatalf("after the switch the console reports %q, want the second project file", view.Database)
	}

	// And the SERVED HISTORY is the incoming project's, which is the claim.
	var rows []struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(get(t, srv, "/api/history?limit=10").Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	for _, row := range rows {
		if row.Host == "outgoing.test" {
			t.Fatalf("history still serves the outgoing project's exchange after the switch: %+v\n"+
				"A switch that re-points the mirror without re-running the restore serves project A's "+
				"traffic out of project B's file — the exact failure this bead is about.", rows)
		}
	}
}

// The write-through sinks are the failure that is invisible: the console looks right and the data
// is in a file nobody is reading. After a switch, a NEW capture must reach the NEW file.
func TestACaptureAfterASwitchIsWrittenToTheIncomingProjectFile(t *testing.T) {
	dir := t.TempDir()
	first, err := persist.Open(filepath.Join(dir, "first.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open first: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	srv := newTestServer().WithPersist(first)

	secondPath := filepath.Join(dir, "second.db")
	if rec := openProjectSwitch(t, srv, secondPath); rec.Code != http.StatusOK {
		t.Fatalf("the switch = %d; body %s", rec.Code, rec.Body.String())
	}

	// A capture, after the switch, through the store the console holds — an exchange, which is
	// the row Restore reads back and the one a session actually produces.
	srv.store.AddExchange(&core.Exchange{Host: "after-switch.test", Port: 80, Method: "GET", Path: "/fresh"})

	// Read the incoming file directly and ask whether it holds the capture.
	read, err := persist.Open(secondPath, zap.NewNop())
	if err != nil {
		t.Fatalf("reopen the incoming project: %v", err)
	}
	t.Cleanup(func() { _ = read.Close() })
	// Read the file back through the only API that shows what it holds: the one-time restore.
	readBack := core.NewTrafficStore()
	if err := read.Restore(readBack, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("restore the incoming project's file: %v", err)
	}
	found := false
	for _, ex := range readBack.Exchanges() {
		if ex != nil && ex.Host == "after-switch.test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the capture made after the switch is not in the incoming project's file.\n" +
			"The sinks point at the store this process closed, so every capture after a switch is " +
			"being written to a file nobody is reading — invisible in the console, lost on exit.")
	}
}

// Switching to the file already open must be a no-op that says so, not an error and not a
// re-restore: the operator asked for the project they are already in.
func TestSwitchingToTheAlreadyOpenProjectAnswersWithItAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	p, err := persist.Open(filepath.Join(dir, "current.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv := newTestServer().WithPersist(p)
	seedCapture(t, srv, "current.test")
	before, _ := srv.store.Count()

	// The same file by a different spelling — the check has to survive that, because closing the
	// store this process is switching TO is not a recoverable mistake.
	rec := openProjectSwitch(t, srv, filepath.Join(dir, ".", "current.db"))
	if rec.Code != http.StatusOK {
		t.Fatalf("switching to the open project = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got, _ := srv.store.Count(); got != before {
		t.Fatalf("switching to the already-open project changed the store: %d messages, had %d", got, before)
	}
	if srv.persist == nil || !sameFile(srv.persist.Path(), filepath.Join(dir, "current.db")) {
		t.Fatalf("the switch moved the process off the project it was already on")
	}
}

// A path that cannot be opened must leave the operator where they were. This is the ordering
// claim: open the incoming file BEFORE closing the outgoing one, because a switch that destroys
// the open project and then fails is the worst outcome available.
func TestARefusedSwitchLeavesTheOpenProjectIntact(t *testing.T) {
	dir := t.TempDir()
	p, err := persist.Open(filepath.Join(dir, "current.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv := newTestServer().WithPersist(p)
	seedCapture(t, srv, "current.test")

	notADatabase := filepath.Join(dir, "not-a-database.db")
	if err := os.WriteFile(notADatabase, []byte("this is a text file, not a database\n"), 0o600); err != nil {
		t.Fatalf("write the bad file: %v", err)
	}
	rec := openProjectSwitch(t, srv, notADatabase)
	if rec.Code == http.StatusOK {
		t.Fatalf("switching to a text file answered 200:\n%s", rec.Body.String())
	}
	// The refusal names what is wrong, and says the current project is unchanged.
	if !strings.Contains(rec.Body.String(), "current project is unchanged") {
		t.Fatalf("the refusal does not say the operator's project is untouched:\n%s", rec.Body.String())
	}
	if srv.persist == nil || !sameFile(srv.persist.Path(), filepath.Join(dir, "current.db")) {
		t.Fatalf("a refused switch moved the process off its project — the refusal closed the open store")
	}
	if count, _ := srv.store.Count(); count == 0 {
		t.Fatalf("a refused switch emptied the store")
	}
}

// A directory is not a project file, and a path with no extension is a typo rather than an
// intent — both refused with the reason, because "open whatever was clicked" is how an operator
// loses their engagement database.
func TestAPathThatIsNotAProjectFileIsRefusedWithTheReason(t *testing.T) {
	dir := t.TempDir()
	p, err := persist.Open(filepath.Join(dir, "current.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv := newTestServer().WithPersist(p)
	if err := os.Mkdir(filepath.Join(dir, "subdir.db"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rec := openProjectSwitch(t, srv, filepath.Join(dir, "subdir.db"))
	if rec.Code == http.StatusOK {
		t.Fatalf("switching to a directory answered 200:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "directory") {
		t.Fatalf("the refusal does not say what is wrong:\n%s", rec.Body.String())
	}
}

// GET /api/projects lists what the operator can open, marks the active one, and says where it
// looked — so an empty list is "there is nothing here", not "we did not search".
func TestTheProjectListNamesWhatItListedAndMarksTheActiveOne(t *testing.T) {
	dir := t.TempDir()
	active, err := persist.Open(filepath.Join(dir, "alpha.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open active: %v", err)
	}
	t.Cleanup(func() { _ = active.Close() })
	if err := active.SetProjectName("Alpha engagement"); err != nil {
		t.Fatalf("name: %v", err)
	}
	other, err := persist.Open(filepath.Join(dir, "beta.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open other: %v", err)
	}
	if err := other.SetProjectName("Beta engagement"); err != nil {
		t.Fatalf("name other: %v", err)
	}
	_ = other.Close()
	// A file with no stored name: the list falls back to the file name and says which it used.
	unnamed, err := persist.Open(filepath.Join(dir, "gamma.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open unnamed: %v", err)
	}
	_ = unnamed.Close()
	// Not a project file at all, and must not appear.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("write notes: %v", err)
	}

	srv := newTestServer().WithPersist(active)
	rec := get(t, srv, "/api/projects")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/projects = %d, want 200", rec.Code)
	}
	var list projectListResp
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Projects) != 3 {
		t.Fatalf("the list has %d projects, want the 3 .db files (and not notes.txt): %+v", len(list.Projects), list.Projects)
	}
	if list.ProjectDir != dir {
		t.Fatalf("project_dir = %q, want %q — the console must show which directory it listed rather "+
			"than implying a search happened", list.ProjectDir, dir)
	}
	byPath := map[string]projectListEntry{}
	for _, e := range list.Projects {
		byPath[filepath.Base(e.Path)] = e
	}
	if e := byPath["alpha.db"]; !e.Active || e.Name != "Alpha engagement" || !e.Named {
		t.Fatalf("the active project reads %+v, want active with its stored name", e)
	}
	if e := byPath["beta.db"]; e.Active || e.Name != "Beta engagement" {
		t.Fatalf("the other named project reads %+v", e)
	}
	if e := byPath["gamma.db"]; e.Name != "gamma" || e.Named {
		t.Fatalf("the unnamed project reads %+v, want the file's base name with named=false so the "+
			"console can mark that the name is a guess", e)
	}
}

// A process with no -db has no project directory to list, and must say so rather than answering
// an empty list — "nothing here" and "no project" are different claims.
func TestTheProjectListOnAProcessWithoutADatabaseSaysWhyItIsEmpty(t *testing.T) {
	srv := newTestServer()
	rec := get(t, srv, "/api/projects")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/projects = %d", rec.Code)
	}
	var list projectListResp
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if list.Note == "" {
		t.Fatalf("a process with no -db answered an empty list with no reason: %+v", list)
	}
	if len(list.Projects) != 0 {
		t.Fatalf("a process with no -db listed projects: %+v", list.Projects)
	}
}

// The switch is riskDestructive and must stay so: a class change is a decision about what an
// unattended caller may do without asking, and the manifest test pins the set.
func TestTheSwitchIsDeclaredDestructiveAndTheListIsARead(t *testing.T) {
	if r, ok := manifest["/api/project/open"]; !ok {
		t.Fatal("/api/project/open is not in the manifest")
	} else {
		if r.risk != riskDestructive {
			t.Fatalf("/api/project/open is %s, want riskDestructive — it replaces every store's "+
				"contents, which is discarding what the operator was looking at", r.risk)
		}
		if len(r.methods) != 1 || r.methods[0] != "POST" {
			t.Fatalf("/api/project/open declares %v, want [POST]", r.methods)
		}
	}
	if r, ok := manifest["/api/projects"]; !ok {
		t.Fatal("/api/projects is not in the manifest")
	} else if r.risk != riskRead {
		t.Fatalf("/api/projects is %s, want riskRead: it reads a directory and sends nothing", r.risk)
	}
}

// burpsy-react-ui-nagj, the live repro: capture in project A, switch to a NEW (empty) project B,
// capture again — and the new capture's bytes must be readable through /api/message/{id}. Before the
// fix the message-id counter kept A's length, so B's first capture got id N while sitting in slot 0
// and /api/message/N answered 404: every capture after a switch was stored without readable bytes.
func TestACaptureAfterSwitchingToAnEmptyProjectKeepsItsBytes(t *testing.T) {
	dir := t.TempDir()
	first, err := persist.Open(filepath.Join(dir, "a.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	srv := newTestServer().WithPersist(first)
	seedCapture(t, srv, "a.test")
	seedCapture(t, srv, "a.test")

	if rec := openProjectSwitch(t, srv, filepath.Join(dir, "b.db")); rec.Code != http.StatusOK {
		t.Fatalf("switch = %d: %s", rec.Code, rec.Body.String())
	}

	id, err := srv.store.Put([]byte("GET /in-b HTTP/1.1\r\nHost: b.test\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put after switch: %v", err)
	}
	rec := get(t, srv, "/api/message/"+strconv.FormatUint(uint64(id), 10))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/message/%d after the switch = %d — the capture was stored without readable bytes", id, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "/in-b") {
		t.Errorf("message %d resolves to the wrong bytes: %s", id, rec.Body.String())
	}
}
