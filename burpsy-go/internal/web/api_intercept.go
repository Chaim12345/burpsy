package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

// ---- Intercept ----------------------------------------------------------------------------------

// The Go proxy holds matching requests and responses in the intercept engine
// (internal/intercept) until the operator forwards or drops them. These handlers
// are the other half of the wire: they edit the rule lists, read the queue, and
// resolve held messages.

// interceptRuleSpec mirrors intercept.ts's RuleSpec.
type interceptRuleSpec struct {
	Field    string `json:"field"`
	Category string `json:"category"`
	Match    string `json:"string_match"`
	Enabled  bool   `json:"enabled"`
	Comment  string `json:"comment"`
}

// interceptListState mirrors intercept.ts's ListState (the PUT body and the GET rules body).
type interceptListState struct {
	Wired         bool                `json:"wired"`
	Active        bool                `json:"active"`
	Unconditional bool                `json:"unconditional"`
	Count         int                 `json:"count"`
	Rules         []interceptRuleSpec `json:"rules"`
}

// heldView mirrors intercept.ts's HeldView.
type heldView struct {
	ID        uint64 `json:"id"`
	Direction string `json:"direction"`
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	TLS       bool   `json:"tls"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    *int   `json:"status"`
	HeldMs    int64  `json:"held_ms"`
	Len       int    `json:"len"`
	Raw       string `json:"raw"`
	// Opcode is the WebSocket frame type ("text", "binary", …) and is absent for
	// HTTP. Sent because a held frame's payload alone does not say how to read it:
	// an operator shown binary bytes with no marking will edit them as text.
	Opcode string `json:"opcode,omitempty"`
}

type interceptStatusResp struct {
	Enabled            bool       `json:"enabled"`
	Wired              bool       `json:"wired"`
	Hint               string     `json:"hint,omitempty"`
	Pending            int        `json:"pending"`
	Held               []heldView `json:"held"`
	HoldsEveryRequest  *bool      `json:"holds_every_request,omitempty"`
	HoldsEveryResponse *bool      `json:"holds_every_response,omitempty"`
}

func (s *Server) handleIntercept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	enabled := s.intercept.Enabled()
	reqRules := s.intercept.Rules(intercept.DirectionRequest)
	respRules := s.intercept.Rules(intercept.DirectionResponse)
	held := s.intercept.Held()

	now := time.Now()
	views := make([]heldView, 0, len(held))
	for _, h := range held {
		status := (*int)(nil)
		if h.Status != nil {
			sc := *h.Status
			status = &sc
		}
		views = append(views, heldView{
			ID:        h.ID,
			Direction: h.Direction.String(),
			Host:      h.Host,
			Port:      h.Port,
			TLS:       h.TLS,
			Method:    h.Method,
			Path:      h.Path,
			Status:    status,
			HeldMs:    now.Sub(h.HeldAt).Milliseconds(),
			Len:       len(h.Raw),
			Raw:       string(h.Raw),
			Opcode:    h.Opcode,
		})
	}

	holdsEveryReq, holdsEveryResp := reqRules.Unconditional(), respRules.Unconditional()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interceptStatusResp{
		Enabled:            enabled,
		Wired:              true,
		Pending:            len(views),
		Held:               views,
		HoldsEveryRequest:  &holdsEveryReq,
		HoldsEveryResponse: &holdsEveryResp,
	})
}

func (s *Server) handleInterceptEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	s.intercept.SetEnabled(req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled})
}

// handleInterceptDropAll serves POST /api/intercept/drop-all and resolves every
// held message as dropped in one round trip — the queue toolbar's "Drop all".
// The count in the answer is what the engine actually dropped on this call: a
// message resolved elsewhere between the page's last poll and this request is
// not double-counted, so the toast the UI shows cannot overstate.
func (s *Server) handleInterceptDropAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" {
		req.Reason = "dropped by operator"
	}
	dropped := s.intercept.DropAll(req.Reason)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"dropped": dropped})
}

// interceptDirectionNames is the wire name for every intercept direction, and it
// is the only place these strings are written down.
//
// It exists as one table because the names had been spelled out twice — here for
// the URL suffix and again inside handleConfigExport's loop — and the two lists
// were allowed to disagree. That is not hypothetical: the export loop covered
// requests and responses only, so the moment a third direction became routable
// an exported bundle would have carried none of its rules while the importer
// happily accepted them. A donor's WebSocket rules would vanish in transit and
// the round trip would still report success, which is the same defect shape as
// the session_rules omitempty bug in api_config.go.
//
// Ordered rather than a map so export writes its keys deterministically; a
// config file whose key order changes between two identical exports is
// needlessly hard to diff.
var interceptDirectionNames = []struct {
	Name string
	Dir  intercept.Direction
}{
	{"requests", intercept.DirectionRequest},
	{"responses", intercept.DirectionResponse},
	{"websocket_to_server", intercept.DirectionWebSocketToServer},
	{"websocket_to_client", intercept.DirectionWebSocketToClient},
}

// directionFor maps a wire name to a Direction.
func directionFor(s string) (intercept.Direction, bool) {
	for _, d := range interceptDirectionNames {
		if d.Name == s {
			return d.Dir, true
		}
	}
	return intercept.DirectionRequest, false
}

func specToRules(specs []interceptRuleSpec) ([]intercept.Rule, error) {
	rules := make([]intercept.Rule, 0, len(specs))
	for _, sp := range specs {
		field, err := intercept.ParseField(sp.Field)
		if err != nil {
			return nil, err
		}
		cat := intercept.CategoryRegex
		if sp.Category == "literal" {
			cat = intercept.CategoryLiteral
		}
		rules = append(rules, intercept.Rule{
			Field:       field,
			Category:    cat,
			StringMatch: sp.Match,
			Enabled:     sp.Enabled,
			Comment:     sp.Comment,
		})
	}
	return rules, nil
}

func rulesToSpecs(rules []*intercept.Rule) []interceptRuleSpec {
	specs := make([]interceptRuleSpec, 0, len(rules))
	for _, r := range rules {
		cat := "regex"
		if r.Category == intercept.CategoryLiteral {
			cat = "literal"
		}
		specs = append(specs, interceptRuleSpec{
			Field:    r.Field.String(),
			Category: cat,
			Match:    r.StringMatch,
			Enabled:  r.Enabled,
			Comment:  r.Comment,
		})
	}
	return specs
}

// handleInterceptRules serves GET/PUT /api/intercept/rules/{requests|responses}.
func (s *Server) handleInterceptRules(w http.ResponseWriter, r *http.Request) {
	dir, ok := directionFor(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/intercept/rules/"), "/"))
	if !ok {
		http.Error(w, "Unknown direction", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(listView(dir, s.intercept.Rules(dir), s.intercept.Enabled()))
	case http.MethodPut:
		var state interceptListState
		if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		rules, err := specToRules(state.Rules)
		if err != nil {
			http.Error(w, "Invalid rule: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.intercept.SetRules(dir, state.Active, rules); err != nil {
			http.Error(w, "Invalid rule: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(listView(dir, s.intercept.Rules(dir), s.intercept.Enabled()))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func listView(dir intercept.Direction, l intercept.List, enabled bool) interceptListState {
	return interceptListState{
		Wired:         true,
		Active:        l.Active,
		Unconditional: l.Unconditional(),
		Count:         len(l.Rules),
		Rules:         rulesToSpecs(l.Rules),
	}
}

// handleInterceptHeld serves POST /api/intercept/{id}/forward and /api/intercept/{id}/drop.
func (s *Server) handleInterceptHeld(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/intercept/"), "/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "Usage: /api/intercept/{id}/forward|drop", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "Invalid held message id", http.StatusBadRequest)
		return
	}

	switch parts[1] {
	case "forward":
		var req struct {
			// A pointer so an explicitly empty string clears the payload while an absent key
			// forwards what was held. On a WebSocket frame an empty payload is ordinary, and the
			// old plain string treated "" as "unchanged" — so an operator who deleted the payload
			// got the original forwarded, answered 200, with no sign the edit was discarded.
			Raw              *string `json:"raw"`
			FixContentLength bool    `json:"fix_content_length"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.intercept.Forward(id, req.Raw, req.FixContentLength); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"forwarded": true})
	case "drop":
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := s.intercept.Drop(id, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"dropped": true})
	default:
		http.Error(w, "Unknown action", http.StatusNotFound)
	}
}
