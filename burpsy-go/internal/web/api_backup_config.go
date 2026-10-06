package web

// Automatic-backup configuration — the interval schedule and the delete-on-clean-shutdown lifecycle
// of Burp's configPanelAutomaticProjectBackup (burpsy-react-ui-jkvb).
//
// The recurring backup was already reachable as a generic scheduled task of kind "backup". What this
// adds is the two things Burp carries as first-class backup settings and burpsy did not: an interval
// the operator states as a backup *setting* ("every 15 minutes, keep 7") rather than as a hand-built
// schedule, and a "delete the backup on a clean shutdown" switch for a throwaway snapshot.
//
// The interval is still a real schedule under the covers — the one a clicked backup and a scheduled
// backup already share — so there is no second firing path to drift. This file owns one managed
// schedule (autoBackupScheduleName) and keeps it in step with the setting: set an interval and the
// schedule appears, set it to zero and the schedule is removed. The delete-on-shutdown flag and the
// directory it applies to are the part that cannot live in a schedule, so they are persisted here.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/burpsy-go/burpsy/internal/schedule"
	"go.uber.org/zap"
)

// autoBackupScheduleName is the reserved name of the one schedule this setting manages. A name rather
// than an id because the schedule runner keys on names, and a human-readable one shows up legibly in
// the Scheduled-tasks list as what it is.
const autoBackupScheduleName = "Automatic backup"

// maxBackupIntervalMinutes is the schedule runner's year ceiling expressed in minutes, so the setting
// refuses a nonsensical interval at save time with a backup-shaped message rather than a schedule one.
const maxBackupIntervalMinutes = schedule.MaxIntervalSecs / 60

// backupConfig is the persisted automatic-backup setting and the body of PUT /api/backup/config.
type backupConfig struct {
	// IntervalMinutes is how often the automatic backup runs. 0 means off — the managed schedule is
	// removed — which is the default a project that never configured one reads as. Validated and
	// refused rather than clamped, so "every 0.5 minutes" is an error the operator sees, not a silent
	// bump to a minute they did not ask for.
	IntervalMinutes int `json:"interval_minutes"`
	// Dir and Retention are the same two knobs a manual backup takes; carried here so the managed
	// schedule is built from the setting and the shutdown-delete knows which directory to sweep.
	Dir       string `json:"dir"`
	Retention int    `json:"retention"`
	// DeleteOnShutdown removes the snapshots this feature wrote from Dir on a clean shutdown — Burp's
	// "Delete backup file on clean shutdown of Burp". Off by default; a backup is a safety net, and
	// deleting it is the opt-in exception for a throwaway one.
	DeleteOnShutdown bool `json:"delete_on_shutdown"`
}

// loadBackupConfig reads the persisted automatic-backup setting, or the zero config (off) when none
// was written or there is no project database to read it from.
func (s *Server) loadBackupConfig() backupConfig {
	var cfg backupConfig
	if s.persist == nil {
		return cfg
	}
	raw, ok := s.persist.LoadBackupConfig()
	if !ok {
		return cfg
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		// A corrupted blob reads as "off" rather than taking the Settings page down — the same choice
		// the browser-side appearance prefs make for a corrupted value.
		s.logger.Warn("stored backup config did not parse; treating as off", zap.Error(err))
		return backupConfig{}
	}
	return cfg
}

// validateBackupConfig reports the first thing wrong with a proposed setting. The interval is the one
// genuinely new constraint; the directory and retention are validated by the backup itself at run
// time, where the filesystem is the authority.
func validateBackupConfig(cfg backupConfig) error {
	if cfg.IntervalMinutes < 0 {
		return fmt.Errorf("the backup interval is %d minutes: it cannot be negative (0 turns automatic backup off)", cfg.IntervalMinutes)
	}
	if cfg.IntervalMinutes > maxBackupIntervalMinutes {
		return fmt.Errorf("the backup interval is %d minutes, longer than the %d-minute (one year) maximum", cfg.IntervalMinutes, maxBackupIntervalMinutes)
	}
	return nil
}

// handleBackupConfig serves GET/PUT /api/backup/config.
//
// PUT persists the setting and reconciles the one managed schedule in the same request, so the
// Scheduled-tasks list and the backup setting can never disagree about whether an automatic backup
// is running.
func (s *Server) handleBackupConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.loadBackupConfig())

	case http.MethodPut:
		if s.persist == nil {
			http.Error(w, "this instance has no project database, so backup settings cannot be saved; start burpsy with -db to persist the project", http.StatusServiceUnavailable)
			return
		}
		var cfg backupConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Body must be a JSON backup config: interval_minutes, dir, retention, delete_on_shutdown", http.StatusBadRequest)
			return
		}
		if err := validateBackupConfig(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.reconcileAutoBackupSchedule(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		blob, err := json.Marshal(cfg)
		if err != nil {
			http.Error(w, "could not encode the backup config", http.StatusInternalServerError)
			return
		}
		s.persist.SaveBackupConfig(string(blob))
		writeJSON(w, http.StatusOK, cfg)

	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// reconcileAutoBackupSchedule makes the managed schedule match the setting: removed when the interval
// is 0, otherwise created or updated to fire every IntervalMinutes with the setting's dir/retention.
// The first occurrence is one interval out, not now, so saving the setting does not itself kick off a
// whole-database snapshot.
func (s *Server) reconcileAutoBackupSchedule(cfg backupConfig) error {
	// Get returns a nil error when the schedule exists; a non-nil error (ErrNoSuchSchedule) means it
	// is absent. That distinction is what decides create-vs-update and remove-vs-noop below.
	_, getErr := s.schedules.Get(autoBackupScheduleName)
	exists := getErr == nil

	if cfg.IntervalMinutes == 0 {
		// Off: drop the managed schedule if it was there, and report success either way — "there is no
		// automatic backup" is the state the operator asked for whether or not one existed.
		if exists {
			s.schedules.Remove(autoBackupScheduleName)
		}
		return nil
	}

	params, err := json.Marshal(backupParams{Dir: cfg.Dir, Retention: cfg.Retention})
	if err != nil {
		return fmt.Errorf("could not encode the backup schedule params: %w", err)
	}
	intervalSecs := cfg.IntervalMinutes * 60
	sc := schedule.Schedule{
		Name:         autoBackupScheduleName,
		Kind:         scheduleKindBackup,
		Enabled:      true,
		FirstMs:      time.Now().Add(time.Duration(intervalSecs) * time.Second).UnixMilli(),
		IntervalSecs: intervalSecs,
		Params:       params,
	}
	if exists {
		// Update preserves the run counters an operator watches; a fresh interval should not read as
		// "never run" when the schedule has been firing for a week.
		return s.schedules.Update(autoBackupScheduleName, sc)
	}
	return s.schedules.Add(sc)
}

// deleteBackupsOnShutdown removes the snapshots this feature wrote from the configured directory, when
// the operator asked for it — Burp's "delete backup file on clean shutdown". Called from CloseProject,
// which runs only on a clean shutdown; a crash leaves the backup in place, which is the safe default.
//
// Scoped to backupFilePattern exactly as pruning is, so a directory the operator also keeps their own
// files in is never touched. A delete that fails is logged, not fatal: the process is already going
// down, and a leftover snapshot is a smaller problem than a shutdown that hangs.
func (s *Server) deleteBackupsOnShutdown() {
	if s.persist == nil {
		return
	}
	cfg := s.loadBackupConfig()
	if !cfg.DeleteOnShutdown {
		return
	}
	dir := cfg.Dir
	if dir == "" {
		live := s.persist.Path()
		if live == "" {
			return
		}
		dir = filepath.Dir(live)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.logger.Warn("could not list backup directory to delete on shutdown", zap.String("dir", dir), zap.Error(err))
		return
	}
	deleted := 0
	for _, e := range entries {
		if e.IsDir() || !backupFilePattern.MatchString(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			s.logger.Warn("could not delete backup on shutdown", zap.String("name", e.Name()), zap.Error(err))
			continue
		}
		deleted++
	}
	if deleted > 0 {
		s.logger.Info("deleted automatic backups on clean shutdown", zap.Int("count", deleted), zap.String("dir", dir))
	}
}
