package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	// Member is the header or cookie NAME a header/cookie rule matches against (ajpn):
	// "Cookie: session" on the request-cookie rule names the Cookie member and matches its
	// value against Match. Empty for every other field, and refused non-empty for them —
	// a member on a host rule is a rule that cannot mean anything.
	Member  string `json:"member,omitempty"`
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment"`
	// Action is "hold" (Do intercept) or "pass" (Don't intercept), Burp's per-rule
	// action. Absent means hold, so every list written before actions existed reads back
	// unchanged.
	Action string `json:"action,omitempty"`
	// Op is "and" or "none needed" — how THIS rule combines with the rules above it. Absent or
	// unrecognised means OR, so a list written before the boolean column existed reads back and
	// re-evaluates identically (burpsy-react-ui-80tg).
	Op string `json:"op,omitempty"`
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
	// RawBodyBase64 is the held message's body octets when `raw` cannot carry them (not UTF-8) and they
	// are the plain wire body (burpsy-react-ui-3pco) — so the Protobuf tab can read and edit a held gRPC
	// body, and the forward can send the edit back byte-exact as raw_base64.
	RawBodyBase64 string `json:"raw_body_base64,omitempty"`
	// Opcode is the WebSocket frame type ("text", "binary", …) and is absent for
	// HTTP. Sent because a held frame's payload alone does not say how to read it:
	// an operator shown binary bytes with no marking will edit them as text.
	Opcode string `json:"opcode,omitempty"`
	// The operator's annotation on this hold (burpsy-react-ui-5q8u). Report on every
	// row — a switch has to read the state it toggles.
	Comment   string `json:"comment"`
	Highlight string `json:"highlight"`
}

type interceptStatusResp struct {
	Enabled            bool       `json:"enabled"`
	Wired              bool       `json:"wired"`
	Hint               string     `json:"hint,omitempty"`
	Pending            int        `json:"pending"`
	Held               []heldView `json:"held"`
	HoldsEveryRequest  *bool      `json:"holds_every_request,omitempty"`
	HoldsEveryResponse *bool      `json:"holds_every_response,omitempty"`
	// InScopeOnly is Burp's "Only intercept in-scope messages" (burpsy-react-ui-cz1).
	InScopeOnly bool `json:"in_scope_only"`
	// ScopeAttached reports whether the engine has a scope to consult. False makes InScopeOnly inert,
	// and the console says so rather than offering a toggle that silently changes nothing — the same
	// reason `wired` exists beside `enabled`.
	ScopeAttached bool `json:"scope_attached"`
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
			ID:            h.ID,
			Direction:     h.Direction.String(),
			Host:          h.Host,
			Port:          h.Port,
			TLS:           h.TLS,
			Method:        h.Method,
			Path:          h.Path,
			Status:        status,
			HeldMs:        now.Sub(h.HeldAt).Milliseconds(),
			Len:           len(h.Raw),
			Raw:           string(h.Raw),
			RawBodyBase64: editableBodyBase64(h.Raw),
			Opcode:        h.Opcode,
			Comment:       h.Comment,
			Highlight:     h.Highlight,
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
		InScopeOnly:        s.intercept.InScopeOnly(),
		ScopeAttached:      s.intercept.ScopeAttached(),
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
	// Recorded for the "restore" startup mode (burpsy-react-ui-7vy): what the switch read when
	// the session ended is what restore brings back. Best-effort — an unavailable mirror costs
	// restart fidelity, not this toggle.
	if s.persist != nil {
		s.persist.SaveInterceptLive(req.Enabled)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled})
}

// handleInterceptStartup serves GET/POST /api/intercept/startup — Burp's "Default Proxy
// interception state" (configPanelProxyInterception): whether interception is on, off, or
// restored-from-last-session when a server starts. GET answers the current mode; POST writes
// it and echoes the whole state, the convention the passthrough and proxy-options endpoints
// share, so a client never renders a state it has not seen confirmed.
//
// The choice is a preference about the NEXT start, not a live toggle — /api/intercept/enable
// remains the switch — and it is persisted immediately: a mode that needed a separate save
// step would silently apply only when the operator remembered it.
func (s *Server) handleInterceptStartup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.persist == nil {
			// "off" is not a guess: without a persistence store burpsy starts every run with
			// interception off, so off IS the current startup mode. Answering it keeps the read
			// truthful. The 503 that stood here instead made the Settings panel log a failed
			// request on every visit to a default (no -db) server (burpsy-react-ui-92o5) and
			// misdescribe the state as if the server had confirmed it — a refusal is the right
			// answer to a WRITE, which the POST branch below keeps, not to a read.
			writeJSON(w, http.StatusOK, map[string]string{"mode": "off"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mode": s.persist.LoadInterceptStartup()})
	case http.MethodPost:
		if s.persist == nil {
			http.Error(w, "No persistence is attached to this server, so a startup preference would not survive a restart", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		switch req.Mode {
		case "on", "off", "restore":
		default:
			http.Error(w, fmt.Sprintf("Unknown mode %q; the valid modes are on, off and restore", req.Mode), http.StatusBadRequest)
			return
		}
		s.persist.SaveInterceptStartup(req.Mode)
		writeJSON(w, http.StatusOK, map[string]string{"mode": req.Mode})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProxyHistoryLogging serves GET/POST /api/proxy/history-logging — Burp's "Proxy history
// logging" (settings/tools/proxy.html, burpsy-react-ui-z80e): when hosts are added to the target scope,
// whether the proxy stops sending out-of-scope items to history ("stop"), asks each time ("ask"), or
// leaves logging alone ("nothing"). The console's Add to scope reads it; the switch it acts on is the
// proxy option dont_log_out_of_scope. Same shape as /api/intercept/startup: GET answers, POST writes
// and echoes, and without persistence a read answers the default while a write is refused.
func (s *Server) handleProxyHistoryLogging(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mode := "ask"
		if s.persist != nil {
			mode = s.persist.LoadProxyHistoryLogging()
		}
		writeJSON(w, http.StatusOK, map[string]string{"mode": mode})
	case http.MethodPost:
		if s.persist == nil {
			http.Error(w, "No persistence is attached to this server, so the choice would not survive a restart", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		switch req.Mode {
		case "stop", "ask", "nothing":
		default:
			http.Error(w, fmt.Sprintf("Unknown mode %q; the valid modes are stop (Stop logging out-of-scope items), "+
				"ask (Ask me what to do each time) and nothing (Do nothing)", req.Mode), http.StatusBadRequest)
			return
		}
		s.persist.SaveProxyHistoryLogging(req.Mode)
		writeJSON(w, http.StatusOK, map[string]string{"mode": req.Mode})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInterceptInScopeOnly serves POST /api/intercept/in-scope-only — Burp's "Only intercept
// in-scope messages".
//
// Its own route rather than a second field on /api/intercept/enable: they are two independent
// switches, and an endpoint named "enable" that also carried a filter would make a caller setting one
// have to restate the other, which is how a UI ends up turning interception off by accident.
//
// The answer echoes both the new value and whether a scope is attached, so a caller cannot conclude
// the filter is in force when there is nothing for it to filter against.
func (s *Server) handleInterceptInScopeOnly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		InScopeOnly bool `json:"in_scope_only"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	s.intercept.SetInScopeOnly(req.InScopeOnly)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"in_scope_only":  req.InScopeOnly,
		"scope_attached": s.intercept.ScopeAttached(),
	})
}

// handleInterceptNewlineCorrection serves GET and PUT /api/intercept/newline-correction — Burp's
// two newline fixes for an EDITED interception (settings/tools/proxy.html:273-292,
// burpsy-react-ui-80tg).
//
// Its own endpoint rather than two fields on the forward body because they are not properties of a
// forward: they are how the interception tool behaves, an operator sets them once, and putting them
// on every forward would make a caller that forgot them silently rewrite nothing.
//
// GET reports what is in force rather than assuming the defaults, so a surface cannot show a
// control as off when a plugin or a previous session turned it on.
func (s *Server) handleInterceptNewlineCorrection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPut:
		var req struct {
			AddMissingBlankLine                bool `json:"add_missing_blank_line"`
			TrimTrailingNewlinesURLEncodedBody bool `json:"trim_trailing_newlines_urlencoded_body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		s.intercept.SetNewlineCorrection(intercept.NewlineCorrection{
			AddMissingBlankLine:                  req.AddMissingBlankLine,
			TrimTrailingNewlinesInURLEncodedBody: req.TrimTrailingNewlinesURLEncodedBody,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current := s.intercept.NewlineCorrections()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"add_missing_blank_line":                 current.AddMissingBlankLine,
		"trim_trailing_newlines_urlencoded_body": current.TrimTrailingNewlinesInURLEncodedBody,
	})
}

// handleInterceptForwardAll serves POST /api/intercept/forward-all and resolves every
// held message as forwarded, unmodified, in one round trip — the queue toolbar's
// "Forward all", the safe half of the pair whose destructive half is above. The
// count in the answer is what the engine actually forwarded on this call: a
// message resolved elsewhere between the page's last poll and this request is
// not double-counted, so the toast the UI shows cannot overstate. There is no
// body to read on purpose: the engine applies no edits and no content-length
// rewrite, because nobody has looked at what a bulk forward sends.
func (s *Server) handleInterceptForwardAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	forwarded := s.intercept.ForwardAll()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"forwarded": forwarded})
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
		if sp.Member != "" && !field.IsMember() {
			// A member name on a field that is not a list (host, path, body, …) is a rule
			// that cannot mean anything: the engine would silently ignore the member and
			// match the field's whole value, which is a match the operator never asked
			// for. Refused here, at the wire, so the console's rule editor can say why —
			// and the refusal names the MEMBER that caused it (burpsy-react-ui-lhrr), not
			// only the field: "which of my rules' members is the problem" is the answer
			// an operator needs, and a field-only message sends them looking at every
			// rule they wrote.
			return nil, fmt.Errorf("rule member %q on field %q does not name a list, so it cannot carry a member name (use the member only on request/response header or cookie rules)", sp.Member, sp.Field)
		}
		if sp.Member == "" && field.IsMember() {
			return nil, fmt.Errorf("rule field %q names a list and needs a member: the header or cookie name to match against", sp.Field)
		}
		cat := intercept.CategoryRegex
		if sp.Category == "literal" {
			cat = intercept.CategoryLiteral
		}
		action, err := intercept.ParseRuleAction(sp.Action)
		if err != nil {
			return nil, err
		}
		rules = append(rules, intercept.Rule{
			Op:          intercept.ParseRuleOp(sp.Op),
			Field:       field,
			Category:    cat,
			StringMatch: sp.Match,
			Member:      sp.Member,
			Enabled:     sp.Enabled,
			Comment:     sp.Comment,
			Action:      action,
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
			Member:   r.Member,
			Enabled:  r.Enabled,
			Comment:  r.Comment,
			Action:   r.Action.String(),
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

// handleInterceptAnnotate serves POST /api/intercept/{id}/annotate — the operator's
// comment and highlight on a held message (burpsy-react-ui-5q8u). Empty highlight clears,
// matching the shared annotation vocabulary; unknown ids 404 because a stale queue render
// must be told the message resolved, not told "done".
func (s *Server) handleInterceptAnnotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The route is /api/intercept/annotate/{id}; the held queue's own sub-paths
	// (/api/intercept/{id}/forward|drop) keep their shape, and "annotate" as the first
	// segment cannot be an id, so the two surfaces cannot collide.
	idStr := strings.TrimPrefix(r.URL.Path, "/api/intercept/annotate/")
	idStr = strings.Trim(idStr, "/")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid held message id", http.StatusBadRequest)
		return
	}
	var req struct {
		Comment   string `json:"comment"`
		Highlight string `json:"highlight"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if err := s.intercept.SetAnnotation(id, req.Comment, req.Highlight); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
			Raw *string `json:"raw"`
			// RawBase64 is the edited message's exact bytes, base64, and wins over Raw when set
			// (burpsy-react-ui-3pco): a JSON string cannot carry a binary body, so a protobuf field edited
			// in a held request would otherwise forward as U+FFFD-mangled bytes.
			RawBase64        *string `json:"raw_base64"`
			FixContentLength bool    `json:"fix_content_length"`
			// HoldResponse arms a one-shot hold for this request's response (burpsy-react-ui-v6jw):
			// Burp's "Do intercept > Response to this request". Refused for anything but a held
			// request, by the engine.
			HoldResponse bool `json:"hold_response"`
			// Target is the operator's edited destination — Burp's "Edit target" pencil
			// (burpsy-react-ui-akv). Absent means "send it where the client asked", which is what
			// every caller that has no opinion sends. The three fields are separate rather than a
			// nested object so a caller that changes only the port does not have to restate the host.
			Host *string `json:"host"`
			Port *uint16 `json:"port"`
			TLS  *bool   `json:"tls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if req.RawBase64 != nil {
			decoded, derr := base64.StdEncoding.DecodeString(*req.RawBase64)
			if derr != nil {
				http.Error(w, "raw_base64 is not valid base64", http.StatusBadRequest)
				return
			}
			exact := string(decoded) // string([]byte) is byte-exact; Forward reads it back with []byte()
			req.Raw = &exact
		}
		if req.HoldResponse {
			if err := s.intercept.ArmResponseHold(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		}
		// A destination is only built when the caller said something about one. An outright empty
		// host is not treated as "no target": it is a caller that named a destination it cannot
		// have, and the engine refuses it below by name rather than silently sending the request to
		// the original host — which would look like a successful forward to the wrong place.
		var target *intercept.Target
		set := 0
		for _, present := range []bool{req.Host != nil, req.Port != nil, req.TLS != nil} {
			if present {
				set++
			}
		}
		switch {
		case set == 0:
			// No opinion: send it where the client asked. This is the ordinary forward.
		case set < 3:
			// Partial, and refused rather than completed from the hold. Filling the gaps from the current
			// authority would look helpful and be a trap: a caller that sent host alone would silently
			// inherit the old port, and a caller that sent port alone would silently inherit the old host
			// — both of which produce a destination the operator never typed. The console sends all three
			// because it is showing all three.
			http.Error(w, "A retarget needs host, port and tls together; a partial one would inherit the fields it left out", http.StatusBadRequest)
			return
		default:
			target = &intercept.Target{Host: strings.TrimSpace(*req.Host), Port: *req.Port, TLS: *req.TLS}
		}
		if err := s.intercept.Forward(id, req.Raw, req.FixContentLength, target); err != nil {
			// A refused destination is the caller's mistake about the request, not a missing hold —
			// 400 rather than 404, so the console shows the reason instead of "no such item".
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "no held message") || strings.Contains(err.Error(), "already resolved") {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
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
