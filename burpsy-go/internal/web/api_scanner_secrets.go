package web

import (
	"io"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Secret detection (burpsy-react-ui-8j0d) ------------------------------------------------------
//
// The switch for the gitleaks-backed secret scan of every captured response — proxy, crawl,
// Repeater and API scan alike, since each records through the one passive scanner. Off until the
// operator turns it on: a scan that always ran would be a surface reporting findings nobody enabled.

type secretDetectionView struct {
	Enabled bool `json:"enabled"`
	// Corpus names the embedded rule set and Rules counts what runs from it, so the console can say
	// what "on" means rather than show a bare switch.
	Corpus string `json:"corpus"`
	Rules  int    `json:"rules"`
	// Excluded names corpus rules this module never reports, each with its reason.
	Excluded map[string]string `json:"excluded"`
	// Extra names the provider rules burpsy carries beside the corpus, which has no equivalent.
	Extra []string `json:"extra"`
}

func (s *Server) viewSecretDetection() secretDetectionView {
	on := s.passiveScanner != nil && s.passiveScanner.SecretDetection()
	return secretDetectionView{
		Enabled: on,
		Corpus:  scanner.GitleaksVersion,
		Rules:   scanner.GitleaksRuleCount(),
		Excluded: map[string]string{
			"jwt": "a token in a response is how a login works, not a leak; the JWT checks read tokens for real weaknesses",
		},
		Extra: []string{"AWS secret access key (labelled)", "Azure Storage connection string", "GCP service-account JSON"},
	}
}

// restoreSecretDetection loads the project's switch from WithPersist, so it follows a project switch.
func (s *Server) restoreSecretDetection(p *persist.Store) {
	if s.passiveScanner == nil {
		return
	}
	on, err := p.LoadSecretDetection()
	if err != nil {
		s.logger.Warn("failed to restore the secret-detection switch", zap.Error(err))
	}
	s.passiveScanner.SetSecretDetection(on)
}

// scannerSecretsReq is the request body handleScannerSecrets decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type scannerSecretsReq struct {
	Enabled *bool `json:"enabled"`
}

// handleScannerSecrets serves GET/PUT /api/scanner/secrets. riskLocal: the scan reads responses
// burpsy already holds and sends nothing; the switch changes which findings future captures file.
func (s *Server) handleScannerSecrets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.viewSecretDetection())
	case http.MethodPut:
		var body scannerSecretsReq
		if err := requestJSON(w, r, io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil || body.Enabled == nil {
			http.Error(w, `the body must be {"enabled":true|false}`, http.StatusBadRequest)
			return
		}
		if s.passiveScanner == nil {
			http.Error(w, "No passive scanner is attached to this server, so there is nothing to switch", http.StatusServiceUnavailable)
			return
		}
		s.passiveScanner.SetSecretDetection(*body.Enabled)
		if s.persist != nil {
			if err := s.persist.SaveSecretDetection(*body.Enabled); err != nil {
				s.logger.Warn("secret-detection switch persist failed", zap.Error(err))
			}
		}
		writeJSON(w, http.StatusOK, s.viewSecretDetection())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
