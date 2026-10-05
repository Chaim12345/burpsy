package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ---- the Project surface (burpsy-react-ui-je3y) -------------------------------------------------
//
// Burp's Project menu is four items, every one an operation on a project *file*. burpsy has no
// separate project container — the -db file IS the project — so the items this build can honour
// are fewer and simpler: name the project, read which file it lives in, and save a copy of it.
// The two Burp items that are Pro-gated (Open project file, Import project file) are named as
// declined in the menu rather than omitted, the same way the settings page names its absent
// sections: a menu that silently omits them reads as "this build never had them" rather than
// "this build chose not to ship them", and those are different facts.

// handleProjectName serves GET and PUT /api/project/name.
//
// GET answers the persisted project name, "Unnamed" when never set — the same blank-is-"Unnamed"
// rule the UI applies, so the two surfaces cannot disagree about what this project is called.
// PUT validates the name is non-blank and persists it.
func (s *Server) handleProjectName(w http.ResponseWriter, r *http.Request) {
	// The verb guard answers before the persist check: an unimplemented verb is 405 no
	// matter the wiring, and the manifest's verb test probes exactly that contract.
	switch r.Method {
	case http.MethodGet:
		name := "Unnamed"
		if s.persist != nil {
			stored, err := s.persist.ProjectName()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if stored != "" {
				name = stored
			}
		}
		writeJSON(w, http.StatusOK, projectView{Name: name, Unnamed: name == "Unnamed"})
	case http.MethodPut:
		if s.persist == nil {
			http.Error(w, "persistence is not attached to this process: the project name cannot be stored", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			http.Error(w, "Project name must not be blank", http.StatusBadRequest)
			return
		}
		if err := s.persist.SetProjectName(req.Name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, projectView{Name: req.Name})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProject serves GET /api/project — the "Project file" readout the Project menu shows.
//
// This is the one place an operator can see which project a running instance actually is: the
// name they gave it, the file it lives in, and — when there is no -db — the fact that nothing is
// durable, which is the precondition for every other Project-menu item saying "unavailable"
// honestly rather than disabled-with-no-reason.
func (s *Server) handleProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	view := projectView{
		Name:       "Unnamed",
		Unnamed:    true,
		Persisted:  s.persist != nil,
		Backupable: s.persist != nil,
	}
	if s.persist == nil {
		// No -db: every word of this is the truth a menu item has to be able to say. An empty
		// database field would read as "the project has no file yet", which is not the state —
		// the state is that nothing this process does is being written anywhere.
		view.DatabaseNote = "no -db was given, so nothing is persisted: this instance is not a project file that can be named, copied or reopened"
		writeJSON(w, http.StatusOK, view)
		return
	}
	view.Database = s.persist.Path()
	stored, err := s.persist.ProjectName()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if stored != "" {
		view.Name = stored
		view.Unnamed = false
	}
	writeJSON(w, http.StatusOK, view)
}

// projectView is the wire shape of both project routes.
type projectView struct {
	// Name is the project name as an operator reads it: the stored name, or "Unnamed".
	Name string `json:"name"`
	// Unnamed distinguishes "the operator called it Unnamed" from "it was never named", which
	// the PUT refuses: a stored literal "Unnamed" would make the two states indistinguishable
	// forever after.
	Unnamed bool `json:"unnamed"`
	// Database is the -db path this project lives in, empty when there is none.
	Database string `json:"database,omitempty"`
	// DatabaseNote is set only in the no-persistence case, because that case is not "empty
	// path" and must not render as one.
	DatabaseNote string `json:"database_note,omitempty"`
	// Persisted reports whether this process writes durable state at all.
	Persisted bool `json:"persisted"`
	// Backupable reports whether "Save copy" can work: it is the same condition the backup
	// route checks, surfaced here so the menu can label the item before the operator clicks it.
	Backupable bool `json:"backupable"`
	// RestoreError is set only on the answer to an in-console switch whose one-time restore failed
	// partway (burpsy-react-ui-nagj): the stores now point at the new file, but its history may be
	// incomplete. Without it a partial switch answered exactly like a clean one.
	RestoreError string `json:"restore_error,omitempty"`
}
