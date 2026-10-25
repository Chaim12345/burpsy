package web

// The LLM post-scan triage surface (burpsy-react-ui-ei0v): Burp AI's "second look" shape —
// an operator-configured OpenAI-compatible endpoint investigates gated findings and writes
// advice. What this file owns:
//
//   - GET/PUT /api/settings/triage: the endpoint configuration (base URL, model, key,
//     enabled). The key is WRITE-ONLY on the wire: GET answers configured/not-configured
//     and the shape it stores, never the key itself — a settings surface that echoed the
//     key would put it in every browser tab that renders the page.
//   - POST /api/issues/triage: run the pass over the gated findings (Burp's Standard
//     profile — High any-confidence, Medium tentative-or-better; Collaborator excluded).
//     The response counts investigated / skipped-outside-gate / errored, and each
//     investigated finding's note is named — the count is the honest metric the bead
//     demands, not a "done" flag.
//   - POST /api/issues/{id}/triage: run it on ONE finding (an operator can second-look
//     anything they choose; the gate bounds the sweep, not the operator's hand).
//
// The pass is OFF until configured AND enabled — two gates, because a
// configured-but-unwanted endpoint is a surprise bill and an on-but-unconfigured switch is
// a silent no-op.
import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// triageSettingsView is the wire shape. APIKey is write-only: present on PUT, absent on GET
// (Configured answers whether one is stored).
type triageSettingsView struct {
	Enabled    bool   `json:"enabled"`
	BaseURL    string `json:"base_url"`
	Model      string `json:"model"`
	APIKey     string `json:"api_key,omitempty"` // echoed only when the operator just sent it; GET omits
	Configured bool   `json:"configured"`        // GET only: a key is stored
}

// handleTriageSettings serves GET/PUT /api/settings/triage.
func (s *Server) handleTriageSettings(w http.ResponseWriter, r *http.Request) {
	// The verb guard answers before the persist check: an unimplemented verb is 405 no
	// matter the wiring, and the manifest's verb test probes exactly that contract.
	switch r.Method {
	case http.MethodGet:
		if s.persist == nil {
			http.Error(w, "persistence is not attached to this process: the triage endpoint cannot be stored", http.StatusServiceUnavailable)
			return
		}
		cfg, err := s.persist.LoadTriageSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, triageSettingsView{
			Enabled:    cfg.Enabled,
			BaseURL:    cfg.BaseURL,
			Model:      cfg.Model,
			Configured: cfg.APIKey != "",
		})
	case http.MethodPut:
		var v triageSettingsView
		if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<16)).Decode(&v); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.persist == nil {
			http.Error(w, "persistence is not attached to this process: the triage endpoint cannot be stored", http.StatusServiceUnavailable)
			return
		}
		// A PUT without a key keeps the stored one: the UI sends the shape it read from GET
		// (which omits the key), and "re-save the settings" must not clear the credential.
		existing, err := s.persist.LoadTriageSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		key := v.APIKey
		if key == "" {
			key = existing.APIKey
		}
		if (v.Enabled || existing.Enabled) && strings.TrimSpace(v.BaseURL) == "" && strings.TrimSpace(existing.BaseURL) == "" {
			http.Error(w, "triage needs a base URL before it can be enabled — an unconfigured endpoint is a silent no-op, which is the failure the two-gate rule exists to prevent", http.StatusBadRequest)
			return
		}
		cfg := persistTriageSettingsFromView(v, key)
		if err := s.persist.SaveTriageSettings(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, triageSettingsView{
			Enabled:    cfg.Enabled,
			BaseURL:    cfg.BaseURL,
			Model:      cfg.Model,
			Configured: cfg.APIKey != "",
		})
	default:
		http.Error(w, "Method not allowed: GET/PUT /api/settings/triage", http.StatusMethodNotAllowed)
	}
}

func persistTriageSettingsFromView(v triageSettingsView, key string) persist.TriageSettings {
	return persist.TriageSettings{
		Enabled: v.Enabled,
		BaseURL: strings.TrimSpace(v.BaseURL),
		Model:   strings.TrimSpace(v.Model),
		APIKey:  key,
	}
}

// triageRunResponse is the honest count the bead demands.
type triageRunResponse struct {
	// Investigated names every finding the model looked at.
	Investigated []triageRunRow `json:"investigated"`
	// InvestigatedCount is len(Investigated), carried so a caller can say the number without
	// re-counting.
	InvestigatedCount int `json:"investigated_count"`
	// OutsideGate counts findings the Standard profile skips.
	OutsideGate int `json:"outside_gate"`
	// Errors names the findings whose investigation errored, with the reason — an error is
	// not a verdict and must not be counted as one.
	Errors []triageRunError `json:"errors"`
}

type triageRunRow struct {
	FindingID uint64 `json:"finding_id"`
	Name      string `json:"name"`
	Verdict   string `json:"verdict"`
	Model     string `json:"model"`
}

type triageRunError struct {
	FindingID uint64 `json:"finding_id"`
	Name      string `json:"name"`
	Error     string `json:"error"`
}

// triageCfg resolves the run's endpoint config; the bool answers whether the pass may run.
func (s *Server) triageCfg() (scanner.TriageEndpointConfig, bool, error) {
	if s.persist == nil {
		return scanner.TriageEndpointConfig{}, false, nil
	}
	stored, err := s.persist.LoadTriageSettings()
	if err != nil {
		return scanner.TriageEndpointConfig{}, false, err
	}
	if !stored.Enabled || stored.BaseURL == "" {
		return scanner.TriageEndpointConfig{}, false, nil
	}
	return scanner.TriageEndpointConfig{
		BaseURL: stored.BaseURL,
		Model:   stored.Model,
		APIKey:  stored.APIKey,
	}, true, nil
}

// handleIssueTriageRun serves POST /api/issues/triage: the pass over every gated finding.
func (s *Server) handleIssueTriageRun(w http.ResponseWriter, r *http.Request) {
	cfg, on, err := s.triageCfg()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !on {
		http.Error(w, "LLM triage is not configured: set an endpoint in Settings first — the pass is off until an endpoint is configured AND enabled", http.StatusServiceUnavailable)
		return
	}
	out := triageRunResponse{}
	for _, f := range s.findings.All() {
		if !scanner.TriageEligible(&scanner.Finding{
			Name: f.Name, Severity: f.EffectiveSeverity().String(), Confidence: f.EffectiveConfidence().String(),
		}) {
			out.OutsideGate++
			continue
		}
		note, err := scanner.TriageFinding(r.Context(), &scanner.Finding{
			Name: f.Name, Severity: f.EffectiveSeverity().String(), Confidence: f.EffectiveConfidence().String(),
			URL: f.Target.Path, Evidence: f.Description, Solution: f.Remediation,
		}, cfg)
		if err != nil {
			out.Errors = append(out.Errors, triageRunError{FindingID: f.ID, Name: f.Name, Error: err.Error()})
			continue
		}
		// Attach to the STORED finding so the note outlives the pass and rides the view.
		s.findings.SetTriage(f.ID, &core.TriageNote{
			Verdict: note.Verdict, Reasoning: note.Reasoning, Model: note.Model, InvestigatedAt: note.InvestigatedAt,
		})
		out.Investigated = append(out.Investigated, triageRunRow{FindingID: f.ID, Name: f.Name, Verdict: note.Verdict, Model: note.Model})
	}
	out.InvestigatedCount = len(out.Investigated)
	writeJSON(w, http.StatusOK, out)
}

// handleIssueTriageOne serves POST /api/issues/{id}/triage: the operator's hand on one
// finding, outside the gate — the gate bounds the sweep, not the operator.
func (s *Server) handleIssueTriageOne(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, on, err := s.triageCfg()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !on {
		http.Error(w, "LLM triage is not configured: set an endpoint in Settings first", http.StatusServiceUnavailable)
		return
	}
	var id uint64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		http.Error(w, "Invalid issue ID", http.StatusBadRequest)
		return
	}
	f, err := s.findings.Get(id)
	if err != nil {
		http.Error(w, "Issue not found", http.StatusNotFound)
		return
	}
	note, err := scanner.TriageFinding(r.Context(), &scanner.Finding{
		Name: f.Name, Severity: f.EffectiveSeverity().String(), Confidence: f.EffectiveConfidence().String(),
		URL: f.Target.Path, Evidence: f.Description, Solution: f.Remediation,
	}, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.findings.SetTriage(f.ID, &core.TriageNote{
		Verdict: note.Verdict, Reasoning: note.Reasoning, Model: note.Model, InvestigatedAt: note.InvestigatedAt,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"finding_id": f.ID,
		"triage":     note,
	})
}
