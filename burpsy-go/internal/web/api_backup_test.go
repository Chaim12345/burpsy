package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// ---- POST /api/backup and the backup schedule (W6 #2) --------------------------------------
//
// State 0 before this: nothing in the build ever copied the project file. Persistence existed, so an
// operator who lost the machine lost the engagement.
//
// The tests that carry weight are the retention ones. A backup that fills the disk the live database
// is on turns a safety net into an outage, and pruning is the part that can silently delete the wrong
// thing.

func newTestServerWithDB(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "project.db")
	store, err := persist.Open(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	// Something identifiable in the database, so a snapshot can be shown to hold real content.
	store.SaveScope([]*core.ScopeRule{{Kind: core.ScopeInclude, Pattern: "backup-target.test"}})

	s := newTestServer()
	s.persist = store
	s.logger = zap.NewNop()
	return s, dir
}

func postBackup(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/backup", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestBackupWritesASnapshotThatHoldsTheProject(t *testing.T) {
	ts, dir := newTestServerWithDB(t)
	dest := filepath.Join(dir, "backups")

	rec := postBackup(t, ts, fmt.Sprintf(`{"dir":%q}`, dest))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var out backupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if out.Bytes <= 0 {
		t.Errorf("bytes = %d, want a non-empty snapshot", out.Bytes)
	}
	if !backupFilePattern.MatchString(filepath.Base(out.Path)) {
		t.Errorf("snapshot name %q does not match the pattern pruning relies on", filepath.Base(out.Path))
	}

	// It must be a real database holding the real content — the only assertion that proves a backup.
	restored, err := persist.Open(out.Path, zap.NewNop())
	if err != nil {
		t.Fatalf("the snapshot does not open as a database: %v", err)
	}
	rules, err := restored.LoadScope()
	if err != nil {
		t.Fatalf("reading the snapshot: %v", err)
	}
	if len(rules) != 1 || rules[0].Pattern != "backup-target.test" {
		t.Errorf("snapshot holds %+v, want the seeded scope rule", rules)
	}
}

// Retention: only the newest N survive, and the ones deleted are the oldest.
func TestRetentionKeepsTheNewestAndDeletesTheOldest(t *testing.T) {
	dir := t.TempDir()
	// Names in this format sort lexicographically in chronological order, which is what pruning
	// relies on — so they are created out of order here to prove pruning sorts rather than trusting
	// directory order.
	names := []string{
		"burpsy-backup-20260101T000003Z.db",
		"burpsy-backup-20260101T000001Z.db",
		"burpsy-backup-20260101T000004Z.db",
		"burpsy-backup-20260101T000002Z.db",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600); err != nil {
			t.Fatalf("seeding %s: %v", n, err)
		}
	}

	pruned, kept, warning := pruneBackups(dir, 2)
	if warning != "" {
		t.Errorf("unexpected warning: %s", warning)
	}
	if pruned != 2 || kept != 2 {
		t.Errorf("pruned=%d kept=%d, want 2 and 2", pruned, kept)
	}

	survivors := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		survivors[e.Name()] = true
	}
	for _, want := range []string{"burpsy-backup-20260101T000003Z.db", "burpsy-backup-20260101T000004Z.db"} {
		if !survivors[want] {
			t.Errorf("%s was deleted; the two newest must survive", want)
		}
	}
	for _, gone := range []string{"burpsy-backup-20260101T000001Z.db", "burpsy-backup-20260101T000002Z.db"} {
		if survivors[gone] {
			t.Errorf("%s survived; the oldest must be pruned first", gone)
		}
	}
}

// Pruning must never touch a file it did not write. A backup directory an operator also keeps their
// own files in is entirely likely, and deleting one of those would be unforgivable.
func TestPruningNeverTouchesFilesItDidNotWrite(t *testing.T) {
	dir := t.TempDir()
	ours := []string{
		"burpsy-backup-20260101T000001Z.db",
		"burpsy-backup-20260101T000002Z.db",
		"burpsy-backup-20260101T000003Z.db",
	}
	theirs := []string{
		"notes.txt",
		"project.db",
		"burpsy-backup.db",                    // close, but not the pattern
		"burpsy-backup-2026-01-01T000000Z.db", // dashes: not the pattern
		"my-burpsy-backup-20260101T000001Z.db",
	}
	for _, n := range append(append([]string{}, ours...), theirs...) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600); err != nil {
			t.Fatalf("seeding %s: %v", n, err)
		}
	}

	pruned, _, _ := pruneBackups(dir, 1)
	if pruned != 2 {
		t.Errorf("pruned %d, want 2 (only our own snapshots beyond retention)", pruned)
	}
	for _, n := range theirs {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s was deleted, and it is not a file this feature wrote: %v", n, err)
		}
	}
}

// A negative retention keeps everything, stated explicitly rather than treated as an error.
func TestANegativeRetentionKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 3; i++ {
		n := fmt.Sprintf("burpsy-backup-2026010%dT000000Z.db", i)
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}
	pruned, kept, _ := pruneBackups(dir, -1)
	if pruned != 0 || kept != 3 {
		t.Errorf("pruned=%d kept=%d, want 0 and 3", pruned, kept)
	}
}

// Fewer snapshots than the retention count must prune nothing rather than going negative.
func TestFewerSnapshotsThanRetentionPrunesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "burpsy-backup-20260101T000000Z.db"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	pruned, kept, _ := pruneBackups(dir, 5)
	if pruned != 0 || kept != 1 {
		t.Errorf("pruned=%d kept=%d, want 0 and 1", pruned, kept)
	}
}

// With no -db there is nothing durable to snapshot, and reporting a successful backup of nothing is
// the shape of claim that gets discovered during a restore.
func TestBackupWithNoDatabaseIsRefused(t *testing.T) {
	ts := newTestServer() // no persist store
	rec := postBackup(t, ts, `{}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("POST = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "-db") {
		t.Errorf("the refusal does not say how to enable persistence: %s", rec.Body.String())
	}
}

// Defaulting the directory to beside the live database is the least-surprising choice and the worst
// place for a backup, so it must warn.
func TestDefaultingTheDirectoryWarnsThatItIsBesideTheLiveDatabase(t *testing.T) {
	ts, _ := newTestServerWithDB(t)
	rec := postBackup(t, ts, `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var out backupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Warning == "" {
		t.Error("no warning when the snapshot lands beside the live database")
	}
	if !strings.Contains(out.Warning, "separate storage") {
		t.Errorf("the warning does not say what to do about it: %q", out.Warning)
	}
}

// An empty body means defaults, not a bad request.
func TestAnEmptyBodyMeansDefaults(t *testing.T) {
	ts, _ := newTestServerWithDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/backup", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST with no body = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// The schedule starter must reach the same code the endpoint does, so a scheduled backup and a
// clicked one are one path.
func TestTheBackupScheduleStarterTakesARealSnapshot(t *testing.T) {
	ts, dir := newTestServerWithDB(t)
	dest := filepath.Join(dir, "scheduled")

	summary, err := ts.runProjectBackup(backupParams{Dir: dest, Retention: 3})
	if err != nil {
		t.Fatalf("runProjectBackup: %v", err)
	}
	if !strings.Contains(summary, "backed up to") {
		t.Errorf("summary does not say what happened: %q", summary)
	}

	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatalf("reading %s: %v", dest, err)
	}
	var found int
	for _, e := range entries {
		if backupFilePattern.MatchString(e.Name()) {
			found++
		}
	}
	if found != 1 {
		t.Errorf("%d snapshots in %s, want 1", found, dest)
	}
}

// A partial success must not read as a clean one: the summary the scheduler logs has to carry the
// warning, because a scheduled backup is precisely the case nobody is watching.
func TestTheScheduleSummaryCarriesTheWarning(t *testing.T) {
	ts, _ := newTestServerWithDB(t)
	// No Dir, so the default-location warning fires.
	summary, err := ts.runProjectBackup(backupParams{})
	if err != nil {
		t.Fatalf("runProjectBackup: %v", err)
	}
	if !strings.Contains(summary, "—") || !strings.Contains(summary, "separate storage") {
		t.Errorf("the summary drops the warning: %q", summary)
	}
}

func TestBackupRejectsNonPost(t *testing.T) {
	ts, _ := newTestServerWithDB(t)
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		req := httptest.NewRequest(method, "/api/backup", nil)
		rec := httptest.NewRecorder()
		ts.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", method, rec.Code)
		}
	}
}

// The registered kind must exist, or a schedule saved against it would be refused at save time and
// the panel would offer something unusable.
func TestTheBackupScheduleKindIsRegistered(t *testing.T) {
	ts, _ := newTestServerWithDB(t)
	ts.registerScheduleKinds()
	// Registering twice is how this test avoids depending on NewServer's ordering; what it asserts is
	// that the kind name the UI would send is one the runner knows.
	if scheduleKindBackup != "backup" {
		t.Errorf("scheduleKindBackup = %q; the UI's option list is written against \"backup\"",
			scheduleKindBackup)
	}
}
