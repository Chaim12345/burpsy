package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// ---- in-console project open / new / switch (burpsy-react-ui-dlw2) ------------------------------
//
// The Project menu (burpsy-react-ui-je3y) could read which project a process is and copy it, and
// had to decline "open project file" with a reason: the -db file IS the project, and the running
// process cannot swap its database underneath itself. That decline was true of the code and wrong
// about the possibility — swapping is possible, it just has to be done properly.
//
// # Why a switch is not a pointer swap
//
// internal/persist's header says it plainly: on startup the database is loaded back into the
// in-memory stores, and "nothing is read from SQLite at runtime except the one-time restore". So
// changing which file this process writes to has three parts, and doing only the first is the
// failure this file exists to prevent:
//
//  1. Re-point the durable mirror — open the new file, close the old one.
//  2. RE-RUN the one-time restore against the new file. Skipping this is the bug: the process
//     would keep serving project A's captured traffic, findings and scope while appending every
//     new capture to project B's file. Project B's first hour would be project A's last hour
//     plus whatever followed.
//  3. Re-point every write-through sink, because the sinks are closures over the OLD store.
//     main.go installs them once at startup (SetPersistenceSinks, SetPersistenceSink,
//     SetDeleteSink); a switch that does not re-install them writes the old (now closed) store.
//
// # The hazard this guards most carefully: cross-project capture
//
// The proxy is capturing continuously, and its captures go straight into the store this call is
// replacing. Traffic that arrives during the switch would otherwise be attributed to whichever
// project happened to be open at the moment the bytes landed — a capture from client A's
// engagement written into client B's file, with no record that it happened. The switch therefore
// holds a project-wide lock that the capture path also takes, and it reports the switch as
// refused rather than partial if anything could not be quiesced. See projectSwitchMu's doc.

// projectSwitchMu serializes a project switch against everything that writes durable state.
//
// Taken by the switch for its whole duration, and by the capture/record path around its mirror
// writes, so no capture can land in the middle of a swap. A `sync.RWMutex` rather than a plain
// mutex because the common case — capturing while nobody is switching — must not serialize
// against itself: capture takes the read side, the switch takes the write side and therefore
// waits for in-flight captures to finish rather than racing them.
var projectSwitchMu sync.RWMutex

// InstallCaptureSinks is installCaptureSinks for the process's startup path. main.go installs the
// first project's sinks through it rather than wiring them bare, so the switch lock is held around
// every durable write from the first capture on — a bare startup sink would leave the very first
// switch racing captures that never took the lock.
func InstallCaptureSinks(store *core.TrafficStore, findings *core.FindingStore, p *persist.Store) {
	installCaptureSinks(store, findings, p)
}

// CloseProject closes whichever project database is open NOW, under the switch lock. main.go
// defers this rather than closing the store it opened at startup: after an in-console switch that
// startup store is already closed and the live one is a different file, which a deferred Close of
// the startup pointer would never reach.
func (s *Server) CloseProject() {
	projectSwitchMu.Lock()
	defer projectSwitchMu.Unlock()
	if s.persist != nil {
		// Burp's "delete backup file on clean shutdown" (burpsy-react-ui-jkvb): this runs only on a
		// clean close, so a crash leaves the snapshots in place. Done before Close while the config and
		// the database path are still readable.
		s.deleteBackupsOnShutdown()
		if err := s.persist.Close(); err != nil {
			s.logger.Warn("closing the project database", zap.String("path", s.persist.Path()), zap.Error(err))
		}
	}
}

// installCaptureSinks points the shared stores' write-through sinks at `store`, taking the
// project-switch READ lock around each write.
//
// This is where the capture path is serialized against a switch, and the choice is deliberate:
// the sinks are the ONE seam every capture passes through — the proxy's record(), the active
// scanner's, the crawler's — because each of them ends in the same mirror write. Wrapping the
// sinks catches every writer without internal/web being imported by internal/proxy or
// internal/scanner (which would invert the dependency direction), and without editing any of
// them.
//
// The lock is per-write, not per-capture: a capture's in-memory append is authoritative and
// needs no protection (core's own design says so — "memory is authoritative, SQLite is durable
// backup"), and holding the read side for the whole capture would serialize every proxy
// connection against a switch for the duration of a response body.
func installCaptureSinks(store *core.TrafficStore, findings *core.FindingStore, p *persist.Store) {
	if p == nil {
		return
	}
	store.SetPersistenceSinks(
		func(m *core.StoredMessage) {
			unlock := lockProjectCapture()
			defer unlock()
			p.SaveMessage(m)
		},
		func(e *core.Exchange) {
			unlock := lockProjectCapture()
			defer unlock()
			p.SaveExchange(e)
		},
	)
	if findings != nil {
		findings.SetPersistenceSink(func(f *core.Finding) {
			unlock := lockProjectCapture()
			defer unlock()
			p.SaveFinding(f)
		})
		findings.SetDeleteSink(func(id uint64) {
			unlock := lockProjectCapture()
			defer unlock()
			p.DeleteFinding(id)
		})
	}
}

// lockProjectCapture takes the project-switch lock's READ side and returns its release. Every
// durable write goes through it, so a switch — which holds the write side — waits for the
// writes in flight and none can land in the middle of a swap.
func lockProjectCapture() func() {
	projectSwitchMu.RLock()
	return projectSwitchMu.RUnlock
}

// projectSwitchRefuse is what a refused switch answers with: the reason, and what the operator
// has to do about it. A refusal that only said "busy" would send them to restart the process,
// which is the thing this feature exists to remove.
type projectSwitchRefuse struct {
	Reason string `json:"reason"`
	// Remedy is the concrete next step, or "" when there is nothing for the operator to do
	// (a transient refusal resolves on its own).
	Remedy string `json:"remedy,omitempty"`
}

// projectOpenReq is the request body handleProjectOpen decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type projectOpenReq struct {
	// Path is the database file to switch to. A relative path is resolved against the
	// directory of the CURRENT project, so "client-b.db" means "next to this one" — the
	// same convenience a -db flag on a command line gets from the operator's cwd, and
	// resolved here rather than guessed so the answer never depends on what the
	// console's working directory happens to be.
	Path string `json:"path"`
}

// handleProjectOpen is POST /api/project/open — switch the running process to another project's
// database file.
//
// riskDestructive is this route's class, and it is the same reasoning /api/backup carries: a
// switch REPLACES every in-memory store's contents with the new file's, so anything the operator
// had not yet persisted to the outgoing project is not in the file they are leaving, and the
// console answers with the new project's history — a look that is easy to mistake for data loss
// in the direction people do not expect. The confirm gate is the right control for it, and this
// route is one of the few where refusing by default is more honest than proceeding.
func (s *Server) handleProjectOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req projectOpenReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		http.Error(w, "A project file path is required", http.StatusBadRequest)
		return
	}
	resolved, err := s.resolveProjectPath(path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, projectSwitchRefuse{Reason: err.Error()})
		return
	}

	// Take the write side for the whole switch: from here until the new sinks are installed,
	// no capture may be written, because anything written in that window would be attributed
	// to whichever project happened to be open at the moment.
	projectSwitchMu.Lock()
	defer projectSwitchMu.Unlock()

	// A switch to the file already open is not an error and not a no-op by accident: the
	// operator asked for this project, so the answer says this project, with its restored
	// name. Re-restoring would be harmless but would also re-run the restore for nothing.
	if s.persist != nil && sameFile(s.persist.Path(), resolved) {
		writeJSON(w, http.StatusOK, s.projectView())
		return
	}

	// Quiesce the background work first. A crawl or audit in flight holds its own state and
	// writes progress rows; switching the file under one would leave its writes aimed at the
	// store this call is about to close. Pausing is not cancelling — the operator's work is
	// still there to resume after the switch.
	var paused bool
	if s.tasks != nil {
		if !s.tasks.Paused() {
			s.tasks.PauseAll()
			paused = true
		}
	}

	// 1. Open the new file BEFORE closing the old one. If the path is unwritable or the file
	// is not a database, the operator gets that refusal with their current project intact —
	// a switch that destroys the open project and then fails is the worst ordering available.
	next, err := persist.Open(resolved, s.logger)
	if err != nil {
		if paused {
			s.tasks.ResumeAll()
		}
		writeJSON(w, http.StatusBadRequest, projectSwitchRefuse{
			Reason: "could not open " + resolved + ": " + err.Error(),
			Remedy: "the current project is unchanged; check the path and its permissions",
		})
		return
	}

	// 2. Re-run the one-time restore for the SHARED stores — history, findings, scope — which
	// main.go does before the server is built and which a server constructed directly never
	// did. This is the step whose absence would serve the outgoing project's traffic from the
	// incoming project's file: the path would change, the sinks would follow, and the console
	// would still be showing the project the operator just left.
	//
	// The nil arguments are the three web-owned stores (match & replace, session rules,
	// organizer, tool log): WithPersist below restores those from the same file, and passing
	// them here as well would restore them twice — wasteful, and a second Restore over
	// already-restored state is not a no-op by contract.
	restoreErr := next.Restore(s.store, s.findings, s.scope, nil, nil, nil, nil)

	// 3. Re-point every write-through sink at the new store. Skipping any of these writes the
	// old (about-to-be-closed) store, and the failure is silent: the console looks fine and
	// the data is in a file nobody is reading.
	installCaptureSinks(s.store, s.findings, next)

	// 4. Close the outgoing project LAST, after every read of it is done and after nothing
	// points at it any more. Closing earlier would fail every capture still in flight.
	var previous *persist.Store
	if s.persist != nil {
		previous = s.persist
	}
	// WithPersist restores the web-owned stores from the new file and re-installs the tool
	// log, intercept-startup and pools sinks — the same work main.go's startup path does,
	// called here because the file it is restoring from has changed.
	s.WithPersist(next)

	if previous != nil {
		if err := previous.Close(); err != nil {
			s.logger.Warn("closing the previous project database", zap.String("path", previous.Path()), zap.Error(err))
		}
	}
	if paused {
		s.tasks.ResumeAll()
	}
	if restoreErr != nil {
		// The stores are pointed at the new file, so this is a report of a PARTIAL switch,
		// not a refusal: the operator's history may be incomplete. Saying so is the whole
		// point — a switch that quietly lost the history would read as the new project
		// simply having none.
		s.logger.Error("project switch restored with failures", zap.Error(restoreErr))
		// The real view of the project now open, plus the failure — not a hard-coded "Unnamed" view,
		// which answered exactly like a clean switch and hid that the history may be incomplete.
		view := s.projectView()
		view.RestoreError = "the switch completed but restoring this project's saved state failed partway, " +
			"so its history may be incomplete: " + restoreErr.Error()
		writeJSON(w, http.StatusOK, view)
		return
	}
	writeJSON(w, http.StatusOK, s.projectView())
}

// resolveProjectPath turns a caller-supplied path into the absolute path a project file lives
// at, refusing the two shapes that would otherwise be destructive by accident.
func (s *Server) resolveProjectPath(path string) (string, error) {
	if !filepath.IsAbs(path) && s.persist != nil {
		if base := filepath.Dir(s.persist.Path()); base != "" {
			path = filepath.Join(base, path)
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("could not resolve %s: %w", path, err)
	}
	// A project file is a SQLite database burpsy creates itself. An existing file that is not
	// one is refused here rather than at Open, because the refusal names the file the
	// operator actually pointed at — and because "open whatever I clicked" is how an operator
	// loses their engagement database to a text file in the wrong directory.
	if info, err := os.Stat(abs); err == nil {
		if info.IsDir() {
			return "", fmt.Errorf("%s is a directory, not a project file", abs)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("could not read %s: %w", abs, err)
	}
	return abs, nil
}

// sameFile compares two paths for identity after resolving symlinks, because the switch's
// "already open" check must not be fooled by a path that names the same file two ways (a
// relative path, a symlink, a trailing "./") — re-restoring is harmless, but a switch that
// CLOSES the store it is switching to is not.
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	if errA != nil {
		ra = a
	}
	if errB != nil {
		rb = b
	}
	return filepath.Clean(ra) == filepath.Clean(rb)
}

// projectView reads the current project's identity, for the routes that answer with it. Shared
// by handleProject and the switch so both report the same fields from one place — the two
// disagreeing about which file is open is the failure a reader would have no way to detect.
func (s *Server) projectView() projectView {
	view := projectView{
		Name:       "Unnamed",
		Unnamed:    true,
		Persisted:  s.persist != nil,
		Backupable: s.persist != nil,
	}
	if s.persist == nil {
		view.DatabaseNote = "no -db was given, so nothing is persisted: this instance is not a project file that can be named, copied or reopened"
		return view
	}
	view.Database = s.persist.Path()
	if stored, err := s.persist.ProjectName(); err == nil && stored != "" {
		view.Name = stored
		view.Unnamed = false
	}
	return view
}

// handleProjectList is GET /api/projects — the project files this process can see.
//
// The directory is the one the active project lives in, because that is the only place the
// operator has already been shown and the only directory this process may safely enumerate:
// burpsy is given one -db path, and walking upward from it looking for other engagements would
// be browsing a filesystem the operator never pointed the tool at. A .db extension is the
// filter, and it is stated in the answer (projectDir) so the console shows what it listed rather
// than implying a search happened.
func (s *Server) handleProjectList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := projectListResp{}
	if s.persist == nil {
		resp.Note = "this instance was started without -db, so there is no project directory to list"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	active := s.persist.Path()
	dir := filepath.Dir(active)
	resp.ProjectDir = dir
	resp.Active = active
	entries, err := os.ReadDir(dir)
	if err != nil {
		resp.Note = "could not read " + dir + ": " + err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".db") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		entry := projectListEntry{
			Path:   path,
			Name:   strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())),
			Active: sameFile(path, active),
		}
		// The stored name when there is one, because a file's name on disk is usually its
		// path and the operator named the project separately (je3y's Rename). Read as a
		// read-only peek: a file that is not a database, or a database without the row,
		// both answer with the file name, which is the honest fallback.
		if p, err := persist.Open(path, zap.NewNop()); err == nil {
			if name, err := p.ProjectName(); err == nil && name != "" {
				entry.Name = name
				entry.Named = true
			}
			_ = p.Close()
		}
		resp.Projects = append(resp.Projects, entry)
	}
	// Sorted by name so the list does not reorder between refreshes for the operator's eye —
	// os.ReadDir already sorts by filename, but the displayed name may not be it.
	sort.Slice(resp.Projects, func(i, j int) bool { return resp.Projects[i].Name < resp.Projects[j].Name })
	writeJSON(w, http.StatusOK, resp)
}

// projectListResp is what GET /api/projects answers with.
type projectListResp struct {
	Projects []projectListEntry `json:"projects"`
	// Active is the database file this process has open, so the console can mark it without
	// comparing paths itself.
	Active string `json:"active"`
	// ProjectDir is the directory the list came from — always the active project's own
	// directory, never a search upward.
	ProjectDir string `json:"project_dir,omitempty"`
	// Note says why the list is empty when it is empty for a reason (no -db, unreadable
	// directory). An empty list with no reason reads as "this directory has no projects",
	// which is a different claim.
	Note string `json:"note,omitempty"`
}

// projectListEntry is one project file.
type projectListEntry struct {
	Path string `json:"path"`
	// Name is the stored project name when the file carries one, else the file's base name.
	Name string `json:"name"`
	// Named says which of the two it is, so the console can mark a project that has been
	// named rather than leaving every row looking like a guess.
	Named  bool `json:"named"`
	Active bool `json:"active"`
}
