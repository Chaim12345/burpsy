package web

// The skills library over HTTP (burpsy-react-ui-ulsy).
//
//	GET /api/skills            the library: every skill, whether it is available and disabled, and
//	                           every manifest that was refused, with why
//	GET /api/skills/{name}     one skill with its prompt rendered from ?argument=value
//	PUT /api/skills/disabled   {"disabled":[names]} — which skills this PROJECT turns off
//
// The directory is named by the operator at start (-skills DIR); no route takes a path. The disabled
// list is a project setting (persisted with -db), so one engagement can switch a technique off without
// touching the library on disk. The MCP transport publishes the available, enabled skills as MCP
// prompts.

import (
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/skills"
)

// WithSkills attaches the operator's skill library.
func (s *Server) WithSkills(lib *skills.Library) *Server {
	s.skills = lib
	return s
}

// skillsState holds the disabled set when no project database is attached.
type skillsState struct {
	mu       sync.Mutex
	disabled []string
}

// disabledSkills reads the project's disabled list: the database when one is attached, otherwise
// this process's memory. The bool says whether the list is persisted.
func (s *Server) disabledSkills() ([]string, bool, error) {
	if s.persist != nil {
		names, err := s.persist.LoadDisabledSkills()
		return names, true, err
	}
	s.skillsMem.mu.Lock()
	defer s.skillsMem.mu.Unlock()
	return append([]string{}, s.skillsMem.disabled...), false, nil
}

type skillView struct {
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Tools             []string          `json:"tools"`
	Arguments         []skills.Argument `json:"arguments"`
	File              string            `json:"file"`
	Available         bool              `json:"available"`
	UnavailableReason string            `json:"unavailable_reason,omitempty"`
	Disabled          bool              `json:"disabled"`
}

type skillsView struct {
	Configured bool               `json:"configured"`
	Dir        string             `json:"dir,omitempty"`
	Hint       string             `json:"hint,omitempty"`
	Skills     []skillView        `json:"skills"`
	Refused    []skills.LoadError `json:"refused"`
	Disabled   []string           `json:"disabled"`
	Persisted  bool               `json:"persisted"`
	// DisabledError reports an unreadable stored list, which is then treated as empty — said, not hidden.
	DisabledError string `json:"disabled_error,omitempty"`
}

func viewOf(sk skills.Skill, disabled map[string]bool) skillView {
	ok, why := sk.Available()
	return skillView{Name: sk.Name, Description: sk.Description, Tools: sk.Tools, Arguments: sk.Arguments,
		File: sk.File, Available: ok, UnavailableReason: why, Disabled: disabled[sk.Name]}
}

func (s *Server) handleSkills(w http.ResponseWriter, r *http.Request) {
	names, persisted, derr := s.disabledSkills()
	view := skillsView{Skills: []skillView{}, Refused: []skills.LoadError{}, Disabled: names, Persisted: persisted}
	if derr != nil {
		view.DisabledError = derr.Error()
	}
	if s.skills == nil {
		view.Hint = "no skills library is loaded; start burpsy with -skills DIR, a directory of <name>.json skill manifests"
		writeJSON(w, http.StatusOK, view)
		return
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	view.Configured, view.Dir = true, s.skills.Dir
	for _, sk := range s.skills.Skills {
		view.Skills = append(view.Skills, viewOf(sk, set))
	}
	view.Refused = append(view.Refused, s.skills.Errors...)
	writeJSON(w, http.StatusOK, view)
}

// skillPromptView is GET /api/skills/{name}.
type skillPromptView struct {
	skillView
	Prompt string `json:"prompt"`
}

func (s *Server) handleSkill(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/skills/"), "/")
	sk, ok := s.skills.Get(name)
	if !ok {
		http.Error(w, "No skill named "+name+" is loaded", http.StatusNotFound)
		return
	}
	names, _, _ := s.disabledSkills()
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	view := viewOf(sk, set)
	if view.Disabled {
		http.Error(w, "Skill "+name+" is disabled for this project", http.StatusConflict)
		return
	}
	if !view.Available {
		http.Error(w, "Skill "+name+" is unavailable: "+view.UnavailableReason, http.StatusConflict)
		return
	}
	args := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			args[k] = v[0]
		}
	}
	prompt, err := sk.Render(args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, skillPromptView{skillView: view, Prompt: prompt})
}

// skillsDisabledReq is PUT /api/skills/disabled's body.
type skillsDisabledReq struct {
	Disabled []string `json:"disabled" required:"true" desc:"the skills this project turns off; the whole list, replacing the previous one"`
}

func (s *Server) handleSkillsDisabled(w http.ResponseWriter, r *http.Request) {
	var req skillsDisabledReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "body must be JSON {\"disabled\": [names]}", http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	names := []string{}
	for _, n := range req.Disabled {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		// A name the library does not hold is refused: a typo would otherwise be stored as a switch
		// that turns nothing off while the operator believes it did.
		if _, ok := s.skills.Get(n); !ok {
			http.Error(w, "No skill named "+n+" is loaded", http.StatusBadRequest)
			return
		}
		seen[n] = true
		names = append(names, n)
	}
	sort.Strings(names)
	if s.persist != nil {
		if err := s.persist.SaveDisabledSkills(names); err != nil {
			http.Error(w, "saving the disabled list failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		s.skillsMem.mu.Lock()
		s.skillsMem.disabled = names
		s.skillsMem.mu.Unlock()
	}
	s.handleSkillsAfterPut(w, r)
}

// handleSkillsAfterPut answers a PUT with the library view, as a GET would.
func (s *Server) handleSkillsAfterPut(w http.ResponseWriter, r *http.Request) {
	get := r.Clone(r.Context())
	get.Method = http.MethodGet
	s.handleSkills(w, get)
}
