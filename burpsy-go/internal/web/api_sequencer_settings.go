package web

import (
	"io"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/sequencer"
	"go.uber.org/zap"
)

// ---- Sequencer analysis settings (burpsy-react-ui-nm81, -3iao) ----------------------------------
//
// Burp's Sequencer "Analysis Settings": which statistical tests run, and whether tokens are
// base64-decoded first — the ten sequencer.* keys, read and written here under Burp's own names. They
// govern every analysis that does not name its own tests, which is what makes them settings rather
// than a stored preference nothing reads: POST /api/tools/sequencer without disabled_tests runs the
// tests these leave on, and the report marks each switched-off test as not run, by name.

// sequencerSettingsView is the wire shape: the settings, plus the accepted keys so a client can render
// one control per key without hard-coding the list.
type sequencerSettingsView struct {
	sequencer.Settings
	Keys []string `json:"keys"`
}

// sequencerTestIDs lists the switchable test ids, for a refusal that names the accepted set.
func sequencerTestIDs() []string {
	out := make([]string, 0, len(sequencer.AnalysisTests))
	for _, t := range sequencer.AnalysisTests {
		out = append(out, t.ID)
	}
	return out
}

// sequencerSettings returns the live settings, defaulted when nothing has been set.
func (s *Server) sequencerSettings() sequencer.Settings {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	if s.seqSettings.TokenAnalysis == nil {
		return sequencer.DefaultSettings()
	}
	return s.seqSettings.Normalise()
}

// restoreSequencerSettings loads the project's saved settings, or resets to Burp's defaults when the
// project has none — the reset matters on a project switch, where keeping the outgoing project's
// switches would apply one engagement's analysis choices to another's tokens.
func (s *Server) restoreSequencerSettings(p *persist.Store) {
	saved, err := p.LoadSequencerSettings()
	if err != nil {
		s.logger.Warn("failed to restore sequencer settings; using Burp's defaults", zap.Error(err))
	}
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	if saved != nil {
		s.seqSettings = *saved
		return
	}
	s.seqSettings = sequencer.DefaultSettings()
}

// handleSequencerSettings serves GET/PUT /api/sequencer/settings. riskLocal: it changes which tests
// burpsy's own analysis runs and sends nothing anywhere.
func (s *Server) handleSequencerSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, sequencerSettingsView{Settings: s.sequencerSettings(), Keys: sequencer.SettingsKeys()})
	case http.MethodPut:
		var edit sequencer.SettingsEdit
		if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<16)).Decode(&edit); err != nil {
			http.Error(w, `the body must be a JSON object like {"token_analysis":{"fips_poker":false}}`, http.StatusBadRequest)
			return
		}
		next, err := s.sequencerSettings().Apply(edit)
		if err != nil {
			// Refused whole: nothing changed, so the operator can correct the body and retry.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.seqMu.Lock()
		s.seqSettings = next
		s.seqMu.Unlock()
		if s.persist != nil {
			if err := s.persist.SaveSequencerSettings(next); err != nil {
				// The live settings already changed, so this answers 200 and says durability is in
				// doubt in the log — the same contract the network settings follow.
				s.logger.Warn("sequencer settings persist failed", zap.Error(err))
			}
		}
		writeJSON(w, http.StatusOK, sequencerSettingsView{Settings: next, Keys: sequencer.SettingsKeys()})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
