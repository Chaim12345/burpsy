package web

// The project backup — Burp's `configPanelAutomaticProjectBackup` (W6 #2).
//
// State 0 before this: `grep -rEil 'project.?backup|autosave|auto.?save' internal/ cmd/` returned
// nothing. Persistence existed — `-db` and `internal/persist` — and nothing ever copied it, so an
// operator who lost the machine lost the engagement: every captured exchange, every finding, every
// scope decision.
//
// # Snapshotting, not copying
//
// `Store.Backup` runs `VACUUM INTO`. The reasoning is in that method's comment and it is the whole
// correctness argument: this store runs in WAL mode, so the main database file on its own is not a
// database anyone can open, and a `cp`-style backup yields a file of plausible size that opens to a
// corrupt schema. VACUUM INTO writes a complete single-file snapshot, consistent by construction.
//
// # Retention, and why pruning is the operator's number
//
// A backup taken hourly and never pruned fills the disk the proxy is recording to, which turns a
// safety net into an outage. So a retention count is part of the request, and the default is small.
// Pruning deletes the oldest snapshots *this feature made* — matched by the filename pattern it
// writes — never anything else in the directory, because a backup directory an operator also keeps
// their own files in is entirely likely.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// defaultBackupRetention is how many snapshots are kept when the operator names no number. Small on
// purpose: a snapshot is a whole copy of the project database, and the failure this feature must not
// cause is filling the disk that the live database is on.
const defaultBackupRetention = 7

// backupFilePattern matches the names runProjectBackup writes, and only those. Pruning is scoped to
// it so a directory holding an operator's own files is never touched.
//
// The timestamp is second-resolution UTC, which makes the names sort lexicographically in
// chronological order — that is what lets pruning sort by name rather than by mtime, and mtime is
// the wrong key here because copying or restoring a file rewrites it.
var backupFilePattern = regexp.MustCompile(`^burpsy-backup-\d{8}T\d{6}Z\.db$`)

// backupParams is a backup schedule's own configuration, and the body of POST /api/backup.
type backupParams struct {
	// Dir is where snapshots are written. Empty means beside the live database, which is the
	// least-surprising default and the only one that cannot fail for a missing path — though it is
	// also the worst place for a backup if the disk is what fails, and the response says so.
	Dir string `json:"dir"`
	// Retention is how many snapshots to keep. 0 means the default; negative means keep everything,
	// stated explicitly rather than treated as an error, because "never prune" is a legitimate
	// choice when the directory is on separate storage.
	Retention int `json:"retention"`
}

// backupResult is what a backup reports. Written to be readable in a task log line as well as JSON.
type backupResult struct {
	Path    string `json:"path"`
	Bytes   int64  `json:"bytes"`
	Pruned  int    `json:"pruned"`
	Kept    int    `json:"kept"`
	Warning string `json:"warning,omitempty"`
}

// runProjectBackup takes one snapshot and prunes older ones. Returns the one-line summary the
// scheduler records against the task.
func (s *Server) runProjectBackup(params backupParams) (string, error) {
	result, err := s.projectBackup(params)
	if err != nil {
		return "", err
	}
	summary := fmt.Sprintf("backed up to %s (%d bytes); kept %d, pruned %d",
		result.Path, result.Bytes, result.Kept, result.Pruned)
	if result.Warning != "" {
		// Appended rather than dropped: a scheduled backup nobody is watching is exactly the case
		// where a partial success must not read as a clean one.
		summary += " — " + result.Warning
	}
	return summary, nil
}

func (s *Server) projectBackup(params backupParams) (backupResult, error) {
	if s.persist == nil {
		// No -db means there is nothing durable to snapshot. Refused rather than reporting a
		// successful backup of nothing, which is the shape of claim that gets discovered during a
		// restore.
		return backupResult{}, fmt.Errorf("this instance has no project database, so there is " +
			"nothing to back up; start burpsy with -db to persist the project")
	}
	live := s.persist.Path()
	if live == "" {
		return backupResult{}, fmt.Errorf("the project database has no path on disk")
	}

	dir := params.Dir
	warning := ""
	if dir == "" {
		dir = filepath.Dir(live)
		warning = "written beside the live database, so a disk failure loses both; set a directory " +
			"on separate storage"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return backupResult{}, fmt.Errorf("could not create %s: %w", dir, err)
	}

	// Second-resolution UTC, so names sort chronologically. Two backups inside the same second
	// would collide, and Store.Backup refuses an existing destination rather than overwriting — so
	// the collision surfaces as an error instead of silently replacing the earlier snapshot.
	name := fmt.Sprintf("burpsy-backup-%s.db", time.Now().UTC().Format("20060102T150405Z"))
	dest := filepath.Join(dir, name)

	if err := s.persist.Backup(dest); err != nil {
		return backupResult{}, err
	}

	info, err := os.Stat(dest)
	if err != nil {
		// The backup was written; only its size is unknown. Reported as a warning rather than
		// failing, because failing here would tell the operator the backup did not happen.
		warning = strings.TrimSpace(warning + " could not stat the snapshot: " + err.Error())
	}
	var size int64
	if info != nil {
		size = info.Size()
	}

	retention := params.Retention
	if retention == 0 {
		retention = defaultBackupRetention
	}
	pruned, kept, pruneWarning := pruneBackups(dir, retention)
	if pruneWarning != "" {
		warning = strings.TrimSpace(warning + " " + pruneWarning)
	}

	s.logger.Info("project backup written",
		zap.String("path", dest), zap.Int64("bytes", size),
		zap.Int("kept", kept), zap.Int("pruned", pruned))

	return backupResult{Path: dest, Bytes: size, Pruned: pruned, Kept: kept, Warning: warning}, nil
}

// pruneBackups deletes the oldest snapshots beyond retention, and returns how many it removed, how
// many remain, and any partial-failure note.
//
// A negative retention keeps everything. A delete that fails is reported rather than retried: the
// snapshot that mattered is already written, and the honest outcome is "backed up, could not prune".
func pruneBackups(dir string, retention int) (pruned, kept int, warning string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, "could not list " + dir + " to prune: " + err.Error()
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !backupFilePattern.MatchString(e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	// Lexicographic is chronological for this name format — see backupFilePattern.
	sort.Strings(names)

	if retention < 0 || len(names) <= retention {
		return 0, len(names), ""
	}
	var failures []string
	for _, name := range names[:len(names)-retention] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			failures = append(failures, name)
			continue
		}
		pruned++
	}
	kept = len(names) - pruned
	if len(failures) > 0 {
		warning = fmt.Sprintf("could not delete %d old snapshot(s): %s",
			len(failures), strings.Join(failures, ", "))
	}
	return pruned, kept, warning
}

// handleBackup serves POST /api/backup: take a snapshot now.
//
// POST and not GET even though it reads the database: it writes a file and may delete others, which
// is not something a GET may do.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	// Verb-checked by the mux: registered as "POST /api/backup" (burpsy-react-ui-vnlh).
	var params backupParams
	if r.Body != nil {
		// An empty body is a valid request meaning "defaults", so a decode failure is only an error
		// when there was something to decode.
		if err := requestJSON(w, r, nil).Decode(&params); err != nil && err.Error() != "EOF" {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	}
	result, err := s.projectBackup(params)
	if err != nil {
		// 503 rather than 500 for the no-database case: the request was well formed and the server
		// simply cannot do it in this configuration.
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "no project database") {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
