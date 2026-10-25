package web

// The project-level token rules' CRUD (burpsy-react-ui-xe82): the surface the capture-and-inject
// set is managed over. Every write persists through persistTokenRules - and a write the store
// refuses FAILS THE REQUEST and rolls the in-memory change back: these rules carry credentials,
// so a set the project never saved is not allowed to keep injecting (the session rules' handlers
// persist silently, a shape this surface deliberately does not copy).

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/session"
)

// tokenRulesResp is the list answer: the rules in their capture order and the tool names a scope
// can name, mirroring the session rules' list shape.
type tokenRulesResp struct {
	Wired bool                 `json:"wired"`
	Rules []*session.TokenRule `json:"rules"`
	Tools []string             `json:"tools"`
}

func (s *Server) handleSessionTokenRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenRulesResp{
			Wired: true,
			Rules: s.sessionCoordinator.TokenRules(),
			Tools: toolNames(),
		})
	case http.MethodPost:
		var rule session.TokenRule
		if err := requestJSON(w, r, nil).Decode(&rule); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		prev := s.sessionCoordinator.TokenRules()
		id, err := s.sessionCoordinator.AddTokenRule(&rule)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.persistTokenRules(); err != nil {
			_ = s.sessionCoordinator.ReplaceTokenRules(prev)
			http.Error(w, "The rule was not saved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rule": s.sessionCoordinator.TokenRule(id)})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSessionTokenRuleDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/session/token-rules/"), "/")
	if id == "" {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var rule session.TokenRule
		if err := requestJSON(w, r, nil).Decode(&rule); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		// "The rule is gone" and "the edit is not a valid rule" are different answers, so they
		// get different codes rather than one generic failure.
		prev := s.sessionCoordinator.TokenRules()
		if err := s.sessionCoordinator.UpdateTokenRule(id, &rule); err != nil {
			if errors.Is(err, session.ErrNoSuchTokenRule) {
				http.Error(w, "Rule not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.persistTokenRules(); err != nil {
			_ = s.sessionCoordinator.ReplaceTokenRules(prev)
			http.Error(w, "The edit was not saved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"rule": s.sessionCoordinator.TokenRule(id)})
	case http.MethodDelete:
		prev := s.sessionCoordinator.TokenRules()
		if !s.sessionCoordinator.RemoveTokenRule(id) {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}
		if err := s.persistTokenRules(); err != nil {
			_ = s.sessionCoordinator.ReplaceTokenRules(prev)
			http.Error(w, "The removal was not saved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": id})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
