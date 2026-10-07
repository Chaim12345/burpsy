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
)

// ---- the automatic-backup setting (burpsy-react-ui-jkvb) -----------------------------------------
//
// The interval is a real schedule under the covers — the one a clicked backup and a scheduled backup
// already share — so the test that carries weight is that setting the interval reconciles that one
// managed schedule, and clearing it removes it. The delete-on-clean-shutdown switch deletes files, so
// it is tested on both sides: it removes the snapshots this feature wrote, and only those.

func putBackupConfig(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/backup/config", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestBackupConfigRefusesANegativeInterval(t *testing.T) {
	ts, _ := newTestServerWithDB(t)
	rec := putBackupConfig(t, ts, `{"interval_minutes":-5}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT negative interval = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// Refused, not clamped: nothing was persisted.
	if _, ok := ts.persist.LoadBackupConfig(); ok {
		t.Fatalf("a refused interval must not be persisted")
	}
}

func TestBackupConfigIntervalReconcilesTheManagedSchedule(t *testing.T) {
	ts, _ := newTestServerWithDB(t)

	// Setting an interval creates the one managed schedule, firing on that period.
	rec := putBackupConfig(t, ts, `{"interval_minutes":15,"retention":7}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	sc, err := ts.schedules.Get(autoBackupScheduleName)
	if err != nil {
		t.Fatalf("the managed backup schedule was not created: %v", err)
	}
	if sc.Kind != scheduleKindBackup {
		t.Fatalf("managed schedule kind = %q, want %q", sc.Kind, scheduleKindBackup)
	}
	if sc.IntervalSecs != 15*60 {
		t.Fatalf("managed schedule interval = %ds, want %ds", sc.IntervalSecs, 15*60)
	}

	// Raising the interval updates the same schedule rather than creating a second one.
	if rec := putBackupConfig(t, ts, `{"interval_minutes":30}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT update = %d: %s", rec.Code, rec.Body.String())
	}
	if n := countManagedBackupSchedules(ts); n != 1 {
		t.Fatalf("after an interval change there are %d managed schedules, want 1", n)
	}

	// Zero turns it off: the managed schedule is removed.
	if rec := putBackupConfig(t, ts, `{"interval_minutes":0}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT off = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := ts.schedules.Get(autoBackupScheduleName); err == nil {
		t.Fatalf("interval 0 must remove the managed schedule")
	}
}

func countManagedBackupSchedules(s *Server) int {
	n := 0
	for _, sc := range s.schedules.List() {
		if sc.Name == autoBackupScheduleName {
			n++
		}
	}
	return n
}

func TestBackupConfigRoundTrips(t *testing.T) {
	ts, _ := newTestServerWithDB(t)
	putBackupConfig(t, ts, `{"interval_minutes":10,"dir":"/tmp/x","retention":3,"delete_on_shutdown":true}`)

	req := httptest.NewRequest(http.MethodGet, "/api/backup/config", nil)
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	var out backupConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.IntervalMinutes != 10 || out.Dir != "/tmp/x" || out.Retention != 3 || !out.DeleteOnShutdown {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestBackupConfigWithoutDatabaseRefuses(t *testing.T) {
	ts := newTestServer() // no persist
	rec := putBackupConfig(t, ts, `{"interval_minutes":10}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT without -db = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteBackupsOnShutdownRemovesOnlyOwnSnapshots(t *testing.T) {
	ts, dir := newTestServerWithDB(t)
	backupDir := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// One snapshot this feature wrote, and one file the operator keeps in the same directory.
	ours := filepath.Join(backupDir, "burpsy-backup-20260101T000000Z.db")
	theirs := filepath.Join(backupDir, "notes.txt")
	for _, p := range []string{ours, theirs} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Off: nothing is deleted.
	putBackupConfig(t, ts, fmt.Sprintf(`{"interval_minutes":0,"dir":%q,"delete_on_shutdown":false}`, backupDir))
	ts.deleteBackupsOnShutdown()
	if _, err := os.Stat(ours); err != nil {
		t.Fatalf("delete_on_shutdown off must not delete the snapshot: %v", err)
	}

	// On: the snapshot goes, the operator's own file stays.
	putBackupConfig(t, ts, fmt.Sprintf(`{"interval_minutes":0,"dir":%q,"delete_on_shutdown":true}`, backupDir))
	ts.deleteBackupsOnShutdown()
	if _, err := os.Stat(ours); !os.IsNotExist(err) {
		t.Fatalf("the snapshot should have been deleted on shutdown")
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Fatalf("a file this feature did not write must never be touched: %v", err)
	}
}
