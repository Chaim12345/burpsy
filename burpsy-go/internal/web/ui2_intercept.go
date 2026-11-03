package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---- Intercept -------------------------------------------------------------------------------

// handleUI2Intercept serves GET /ui2/intercept: the interception state and the held queue.
func (s *Server) handleUI2Intercept(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy /ui2/ — Intercept", "intercept", ui2Exec("intercept.html", s.ui2InterceptView()))
}

// ui2InterceptView builds the intercept page's view model: the held queue plus both rule
// lists, so the page renders the rule toggles next to the queue. The rule lists come through
// the API like everything else on the page; a list that fails to decode is simply left out of
// the view rather than failing the whole page.
func (s *Server) ui2InterceptView() map[string]any {
	rec := newRecorder()
	s.handleIntercept(rec, newReq(http.MethodGet, "/api/intercept"))
	var view map[string]any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	s.ui2MarkHeldEditable(view)
	for _, dir := range []string{"requests", "responses", "websocket_to_server", "websocket_to_client"} {
		recRules := newRecorder()
		s.mux.ServeHTTP(recRules, newReq(http.MethodGet, "/api/intercept/rules/"+dir))
		var state interceptListState
		if err := ui2DecodeJSON(recRules.Body.Bytes(), &state); err != nil {
			continue
		}
		view["rules_"+dir] = map[string]any{
			"active":        state.Active,
			"unconditional": state.Unconditional,
			"count":         state.Count,
		}
	}
	s.ui2InterceptViewExtras(view)
	return view
}

// handleUI2InterceptAction serves POST /ui2/intercept/{action}: enable/disable, forward-all,
// drop-all, and the per-item forward-<id>/drop-<id> — local state changes that then refresh the
// queue fragment. A forward-<id> whose form carries the editor's raw field forwards the held
// message with the operator's edits; without the field the message goes out untouched.
func (s *Server) handleUI2InterceptAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if strings.HasPrefix(action, "rules-") {
		s.handleUI2InterceptRulesToggle(w, action)
		return
	}
	if s.ui2InterceptOptionAction(w, r, action) {
		return
	}
	var target string
	body := `{"enabled":true}`
	switch action {
	case "enable":
		target = "/api/intercept/enable"
	case "disable":
		target = "/api/intercept/enable"
		body = `{"enabled":false}`
	case "forward-all":
		target = "/api/intercept/forward-all"
	case "drop-all":
		target = "/api/intercept/drop-all"
	default:
		// The per-item actions ride the same {action} route: forward-<id> resolves the held
		// message through the API's plain-raw path (the same edit the console sends), drop-<id>
		// drops it. The id belongs to the held queue, not to any URL of burpsy's own, so a
		// malformed one is the same kind of caller error as an unknown action name.
		if idText, ok := strings.CutPrefix(action, "forward-"); ok {
			id, err := strconv.ParseUint(idText, 10, 64)
			if err != nil {
				http.Error(w, "unknown intercept action", http.StatusBadRequest)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form body", http.StatusBadRequest)
				return
			}
			fwd := map[string]any{"fix_content_length": r.PostForm.Get("fix_content_length") == "on"}
			// The editor's textarea always submits a raw field; its presence, not its content,
			// marks the message as edited and hands the API the operator's bytes instead of the
			// original. An emptied textarea is a real edit to an empty message, not a missing
			// field. What the field cannot carry faithfully is line endings — an HTML textarea
			// normalizes every break in its value to a lone LF — so the submission goes through
			// ui2EditedRaw before it is treated as bytes for the wire.
			if rawValues, present := r.PostForm["raw"]; present {
				submitted := rawValues[len(rawValues)-1]
				orig, ws, found := s.ui2HeldInfo(id)
				if found && !ui2TextareaSafe([]byte(orig)) {
					// The editor is withheld for holds it cannot carry; a raw field arriving
					// anyway crossed a textarea and came back with replacement characters
					// where the bytes were (invalid UTF-8 or NUL both get U+FFFD). Refuse by
					// name rather than ship the corruption — the untouched Forward button
					// and the console's base64 editor both remain.
					http.Error(w, "held message is not safe for the page editor (non-UTF-8 or NUL bytes): forward it untouched, or edit the exact bytes in the console's base64 editor", http.StatusBadRequest)
					return
				}
				if found && ui2NormalizeNewlines(orig) == submitted {
					// An editor round-trip the operator did not change: ship the original
					// bytes, unmarked — no raw override.
				} else if ws {
					// A WebSocket message has no headers: the operator saw and edited the
					// whole payload, so their bytes ship exactly as submitted. Restoring
					// header newlines would inject CR bytes they never typed — into the
					// middle of application data, since a payload holding a blank line
					// would be misread as head+body. The textarea shows line breaks as LF
					// and they go out as LF; exact CR bytes belong to the console's
					// base64 editor.
					fwd["raw"] = submitted
				} else {
					fwd["raw"] = ui2RestoreHeaderNewlines(submitted)
				}
			}
			if msg := s.ui2ForwardTargetFields(id, r, fwd); msg != "" {
				s.ui2InterceptRender(w, "Not forwarded: "+msg)
				return
			}
			encoded, err := json.Marshal(fwd)
			if err != nil {
				http.Error(w, "could not encode forward request", http.StatusInternalServerError)
				return
			}
			target = "/api/intercept/" + strconv.FormatUint(id, 10) + "/forward"
			body = string(encoded)
		} else if idText, ok := strings.CutPrefix(action, "drop-"); ok {
			id, err := strconv.ParseUint(idText, 10, 64)
			if err != nil {
				http.Error(w, "unknown intercept action", http.StatusBadRequest)
				return
			}
			target = "/api/intercept/" + strconv.FormatUint(id, 10) + "/drop"
			body = `{}`
		} else {
			http.Error(w, "unknown intercept action", http.StatusBadRequest)
			return
		}
	}
	req := newReq(http.MethodPost, target)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(body))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code >= 400 {
		http.Error(w, rec.Body.String(), rec.Code)
		return
	}
	// Refresh the queue fragment.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intercept.html", s.ui2InterceptView())))
}

// handleUI2InterceptRulesToggle serves POST /ui2/intercept/rules-{direction}-{on|off}, where
// direction is one of requests, responses, websocket_to_server, websocket_to_client:
// it flips one rule list's active flag through the API, carrying the stored rules across
// unchanged so a toggle never rewrites the operator's list. Rule editing itself stays in the
// console; the page only exposes the switch.
func (s *Server) handleUI2InterceptRulesToggle(w http.ResponseWriter, action string) {
	parts := strings.Split(action, "-")
	if len(parts) != 3 || (parts[2] != "on" && parts[2] != "off") {
		http.Error(w, "unknown intercept action", http.StatusBadRequest)
		return
	}
	switch parts[1] {
	case "requests", "responses", "websocket_to_server", "websocket_to_client":
	default:
		http.Error(w, "unknown intercept action", http.StatusBadRequest)
		return
	}
	path := "/api/intercept/rules/" + parts[1]
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
	if rec.Code != http.StatusOK {
		http.Error(w, "could not read the rule list", http.StatusBadGateway)
		return
	}
	var state interceptListState
	if err := ui2DecodeJSON(rec.Body.Bytes(), &state); err != nil {
		http.Error(w, "could not decode the rule list", http.StatusBadGateway)
		return
	}
	state.Active = parts[2] == "on"
	body, err := json.Marshal(state)
	if err != nil {
		http.Error(w, "could not encode the rule list", http.StatusInternalServerError)
		return
	}
	req := newReq(http.MethodPut, path)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(body)))
	recPut := newRecorder()
	s.mux.ServeHTTP(recPut, req)
	if recPut.Code >= 400 {
		http.Error(w, recPut.Body.String(), recPut.Code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intercept.html", s.ui2InterceptView())))
}

// ui2NormalizeNewlines applies the same normalization an HTML textarea applies to its value:
// CRLF and lone CR both become LF.
func ui2NormalizeNewlines(s string) string {
	return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s)
}

// ui2RestoreHeaderNewlines undoes the textarea's normalization where the wire needs it undone.
// The head of an HTTP message — request or status line and headers, up to the first blank line
// — must be CRLF or many servers never answer, so a head that arrived pure-LF gets its endings
// restored. The body keeps the bytes the operator saw: textarea content round-trips LF-only
// content unchanged, and a submission that still has any CR came from a client that can carry
// them (a native form post, the console, a test) and is already byte-exact. Byte-exact editing
// of bodies with significant CRs stays with the console's base64 path.
func ui2RestoreHeaderNewlines(raw string) string {
	if strings.ContainsRune(raw, '\r') {
		return raw
	}
	head, body, found := strings.Cut(raw, "\n\n")
	if !found {
		// No blank line: a header-only fragment, so all of it is the head.
		return strings.ReplaceAll(raw, "\n", "\r\n")
	}
	return strings.ReplaceAll(head, "\n", "\r\n") + "\r\n\r\n" + body
}

// ui2HeldInfo returns the current bytes of a held message and whether it is a WebSocket
// message, so the per-item forward can tell an untouched round-trip from a real edit, can
// refuse a textarea edit of bytes the editor cannot carry, and can keep header-shaped
// newline restoration off payloads that have no headers. A missing hold is left for the API forward to name, which reports it as the
// 404 it is.
func (s *Server) ui2HeldInfo(id uint64) (string, bool, bool) {
	for _, h := range s.intercept.Held() {
		if h.ID == id {
			return string(h.Raw), h.Direction.IsWebSocket(), true
		}
	}
	return "", false, false
}

// ui2TextareaSafe reports whether a held message's bytes can cross the page's raw-message
// editor without corruption. Two kinds cannot: bytes that are not valid UTF-8, and NULs — the
// HTML parser replaces a NUL in a textarea with U+FFFD exactly as it does invalid bytes, so a
// message that is valid UTF-8 but carries a NUL would come back from an "unchanged" round-trip
// with its bytes rewritten. Both kinds keep an untouched Forward and a pointer to the console's
// base64 editor instead of an editing surface.
func ui2TextareaSafe(raw []byte) bool {
	return utf8.Valid(raw) && !bytes.Contains(raw, []byte{0})
}

// ui2MarkHeldEditable flags each held view with whether the page's editor can carry it (see
// ui2TextareaSafe). The check reads the engine's bytes rather than the decoded view because the
// JSON encoding has already replaced invalid bytes with U+FFFD — itself valid UTF-8 — so the
// view cannot see the corruption it would pass along.
func (s *Server) ui2MarkHeldEditable(view map[string]any) {
	held, ok := view["held"].([]any)
	if !ok {
		return
	}
	unsafe := map[uint64]bool{}
	for _, h := range s.intercept.Held() {
		unsafe[h.ID] = !ui2TextareaSafe(h.Raw)
	}
	for _, item := range held {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if idf, ok := m["id"].(float64); ok {
			m["raw_editable"] = !unsafe[uint64(idf)]
		}
	}
}
