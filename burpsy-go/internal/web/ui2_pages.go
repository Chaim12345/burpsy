package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- shared ui2 page rendering helpers -------------------------------------------------------

// ui2RenderPage renders the shell with the given view and fragment body.
func ui2RenderPage(w http.ResponseWriter, title, view string, body templateHTML) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "layout.html", ui2Page{Title: title, View: view, Body: body}); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ui2Fragment answers an htmx request with just the fragment, or renders the full shell.
func ui2Fragment(w http.ResponseWriter, r *http.Request, title, view string, body templateHTML) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
		return
	}
	ui2RenderPage(w, title, view, body)
}

// ui2Exec renders one named template into a string.
func ui2Exec(name string, model any) templateHTML {
	var sb strings.Builder
	_ = ui2Templates.ExecuteTemplate(&sb, name, model)
	return templateHTML(sb.String())
}

// ---- Dashboard -------------------------------------------------------------------------------

// handleUI2Dashboard serves GET /ui2/dashboard: summaries, running tasks, recent activity
// and events, and the suite-wide pause state — one page, no client computation.
func (s *Server) handleUI2Dashboard(w http.ResponseWriter, r *http.Request) {
	body := s.renderUI2Dashboard()
	ui2Fragment(w, r, "burpsy /ui2/ — Dashboard", "dashboard", body)
}

func (s *Server) renderUI2Dashboard() templateHTML {
	messages, exchanges := s.store.Count()
	resp := dashboardResp{
		Summaries:       s.dashboardSummaries(),
		Tasks:           s.tasks.Snapshot(),
		TasksRunning:    s.tasks.Running(),
		TasksDropped:    s.tasks.Dropped(),
		Activity:        nil,
		ActivityShown:   0,
		ActivityTotal:   0,
		ActivityDropped: s.toolLog.Dropped(),
		Events:          s.events.Recent(dashboardActivityLimit),
		EventsShown:     0,
		EventsTotal:     s.events.Count(),
		EventsDropped:   s.events.Dropped(),
		Exchanges:       exchanges,
		Messages:        messages,
		StoredBytes:     s.store.Bytes(),
		Sources:         s.sourceCounts(),
		Paused:          s.tasks.Paused(),
	}
	entries := s.toolLog.All()
	for i := len(entries) - 1; i >= 0 && len(resp.Activity) < dashboardActivityLimit; i-- {
		resp.Activity = append(resp.Activity, toolLogEntryView(entries[i]))
	}
	resp.ActivityShown = len(resp.Activity)
	resp.ActivityTotal = len(entries)
	resp.EventsShown = len(resp.Events)
	return ui2Exec("dashboard.html", resp)
}

// ---- Site map --------------------------------------------------------------------------------

// handleUI2Sitemap serves GET /ui2/sitemap: the host → path tree with per-node counts,
// in-scope dimming and issue markers, rendered flat (depth 2) with links into history.
func (s *Server) handleUI2Sitemap(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		_, _ = w.Write([]byte(s.renderUI2Sitemap(q.Get("host"), q.Get("path"))))
		return
	}
	ui2RenderPage(w, "burpsy /ui2/ — Site map", "sitemap", s.renderUI2Sitemap(q.Get("host"), q.Get("path")))
}

func (s *Server) renderUI2Sitemap(hostFilter, pathFilter string) templateHTML {
	// Reuse the JSON handler's own view builder so the two surfaces cannot drift.
	rec := newRecorder()
	req := newReq(http.MethodGet, "/api/sitemap?host="+hostFilter+"&path="+pathFilter)
	s.sitemapGet(rec, req)
	var tree sitemapTreeResp
	if err := ui2DecodeJSON(rec.Body.Bytes(), &tree); err != nil {
		return ui2Exec("error.html", ui2Error{Message: "site map unavailable: " + err.Error()})
	}
	flat := flattenSitemap(tree.Tree, 0, nil)
	return ui2Exec("sitemap.html", ui2SitemapModel{Tree: tree, Flat: flat})
}

type ui2SitemapNode struct {
	Depth         int
	Segment       string
	Path          string
	Key           string
	Host          string
	Exchanges     int
	Subtree       int
	Methods       string
	Statuses      string
	Mimes         string
	Params        string
	Issues        int
	SubtreeIssues int
	Worst         string
	InScope       bool
	Requested     bool
	Children      int
	Recent        []uint64
}

type ui2SitemapModel struct {
	Tree sitemapTreeResp
	Flat []ui2SitemapNode
}

func flattenSitemap(nodes []sitemapNodeView, depth int, out *[]ui2SitemapNode) []ui2SitemapNode {
	if out == nil {
		out = &[]ui2SitemapNode{}
	}
	for _, n := range nodes {
		*out = append(*out, ui2SitemapNode{
			Depth: depth, Segment: n.Segment, Path: n.Path, Key: n.Key, Host: n.HostName,
			Exchanges: n.Exchanges, Subtree: n.SubtreeCount, Methods: strings.Join(n.Methods, ","),
			Statuses: intSliceString(n.Statuses), Mimes: strings.Join(n.Mimes, ","), Params: strings.Join(n.Params, ","),
			Issues: n.Issues, SubtreeIssues: n.SubtreeIssues, Worst: n.WorstSeverity,
			InScope: n.InScope, Requested: n.Requested, Children: n.ChildCount,
		})
		for i := range n.Children {
			flattenSitemap([]sitemapNodeView{n.Children[i]}, depth+1, out)
		}
	}
	return *out
}

func intSliceString(vs []int) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

// ---- Scope -----------------------------------------------------------------------------------

// handleUI2Scope serves GET /ui2/scope: the include/exclude rules, drop switches and libraries.
func (s *Server) handleUI2Scope(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy /ui2/ — Scope", "scope", ui2Exec("scope.html", s.ui2ScopeView("")))
}

// ui2ScopeView builds the Scope page model through the API: the rules, switches and libraries,
// plus a note slot so a refused action explains itself on the page it was sent from.
func (s *Server) ui2ScopeView(note string) map[string]any {
	return s.ui2ScopeViewDone(note, "")
}

// ui2ScopeViewDone is ui2ScopeView with a success line as well as a refusal one. The
// database-availability flag is server-side knowledge the GET body cannot carry: an empty
// library list cannot say whether nothing is saved or no database is open, and the page
// must not offer save/load forms for a console that has nowhere durable to put them.
func (s *Server) ui2ScopeViewDone(note, done string) map[string]any {
	rec := newRecorder()
	s.getScope(rec, newReq(http.MethodGet, "/api/scope"))
	var view map[string]any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	if view == nil {
		view = map[string]any{}
	}
	view["note"] = note
	view["done"] = done
	view["libraries_db"] = s.persist != nil
	return view
}

// ui2ScopeAPIPayload builds the exact /api/scope call body from the scope form fields. Both the
// confirm step (which mints a token bound to this body) and the run step (which spends it) build
// the body with this one function, so the call the operator reviews is the call that runs; a
// field changed between the two steps no longer matches the minted call and the gate refuses it.
func ui2ScopeAPIPayload(r *http.Request) (map[string]any, string) {
	action := r.PostFormValue("scope_action")
	body := map[string]any{}
	switch action {
	case "rule-add":
		kind := r.PostFormValue("kind")
		if kind != "include" && kind != "exclude" {
			return nil, "kind must be include or exclude"
		}
		body["action"] = kind
		body["pattern"] = strings.TrimSpace(r.PostFormValue("pattern"))
		if p := strings.TrimSpace(r.PostFormValue("path")); p != "" {
			body["path"] = p
		}
		if p := strings.TrimSpace(r.PostFormValue("port")); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return nil, "port must be 1-65535"
			}
			body["port"] = n
		}
		if p := strings.TrimSpace(r.PostFormValue("protocol")); p != "" {
			body["protocol"] = p
		}
	case "rule-toggle", "rule-remove":
		if action == "rule-toggle" {
			body["action"] = "toggle"
			body["enabled"] = r.PostFormValue("enabled") == "true"
		} else {
			body["action"] = "remove"
		}
		body["kind"] = r.PostFormValue("kind")
		body["pattern"] = r.PostFormValue("pattern")
		if p := r.PostFormValue("path"); p != "" {
			body["path"] = p
		}
		if p := r.PostFormValue("port"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, "port must be a number"
			}
			body["port"] = n
		}
		// The row's protocol is part of the rule's identity: carrying it through keeps a click
		// aimed at the https row from hitting its http sibling (the API refuses an unnamed
		// protocol over protocol-differentiated siblings rather than guessing).
		if p := r.PostFormValue("protocol"); p != "" {
			body["protocol"] = p
		}
	case "rule-edit":
		// Edit-in-place: old_* names the rule being replaced by its full identity (kind,
		// pattern, and the path/port/protocol arms when the row carries them), and the new
		// values validate exactly like an add. The API refuses a tuple that no longer matches
		// a rule with 404 rather than editing whichever rule now sits there.
		oldKind := r.PostFormValue("old_kind")
		if oldKind != "include" && oldKind != "exclude" {
			return nil, "old_kind must be include or exclude"
		}
		kind := r.PostFormValue("kind")
		if kind != "include" && kind != "exclude" {
			return nil, "kind must be include or exclude"
		}
		body["action"] = "edit"
		body["old_kind"] = oldKind
		oldPattern := strings.TrimSpace(r.PostFormValue("old_pattern"))
		if oldPattern == "" {
			return nil, "old_pattern is required: it names the rule being replaced"
		}
		body["old_pattern"] = oldPattern
		if p := r.PostFormValue("old_path"); p != "" {
			body["old_path"] = p
		}
		if p := r.PostFormValue("old_port"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, "old_port must be a number"
			}
			body["old_port"] = n
		}
		if p := r.PostFormValue("old_protocol"); p != "" {
			body["old_protocol"] = p
		}
		body["kind"] = kind
		pattern := strings.TrimSpace(r.PostFormValue("pattern"))
		if pattern == "" {
			return nil, "pattern is required: it is the replacement rule's host"
		}
		body["pattern"] = pattern
		if p := strings.TrimSpace(r.PostFormValue("path")); p != "" {
			body["path"] = p
		}
		if p := strings.TrimSpace(r.PostFormValue("port")); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return nil, "port must be 1-65535"
			}
			body["port"] = n
		}
		if p := strings.TrimSpace(r.PostFormValue("protocol")); p != "" {
			body["protocol"] = p
		}
	case "drop-switch":
		body["action"] = "drop_out_of_scope"
		body["enabled"] = r.PostFormValue("enabled") == "true"
	case "library-save", "library-load", "library-delete":
		// The three library actions ride the same gate as rule edits: the body built here is
		// minted at the confirm step and rebuilt from the confirm page's hidden fields at the
		// run step, so the reviewed call is the call that runs. The expected_* digests are
		// computed from server state at mint (handleUI2ScopeConfirm overwrites whatever the
		// form carried) and carried back as hidden fields; a form that invents or edits them
		// no longer matches the minted body and the gate refuses it.
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			return nil, "a scope library needs a name"
		}
		body["action"] = strings.Replace(action, "-", "_", 1)
		body["name"] = name
		if v := strings.TrimSpace(r.PostFormValue("expected_library")); v != "" {
			body["expected_library"] = v
		}
		if v := strings.TrimSpace(r.PostFormValue("expected_rules")); v != "" {
			body["expected_rules"] = v
		}
	default:
		return nil, "unknown scope action"
	}
	return body, ""
}

// handleUI2ScopeConfirm serves POST /ui2/scope/confirm: builds the /api/scope call from the
// form, mints a one-time confirmation for that exact call and renders the review step. Scope
// decides where the proxy and every tool may send traffic and the change persists, so the first
// click never applies.
func (s *Server) handleUI2ScopeConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := map[string]any{
		"scope_action": r.PostFormValue("scope_action"),
		"kind":         r.PostFormValue("kind"),
		"pattern":      r.PostFormValue("pattern"),
		"path":         r.PostFormValue("path"),
		"port":         r.PostFormValue("port"),
		"protocol":     r.PostFormValue("protocol"),
		"enabled":      r.PostFormValue("enabled"),
		"old_kind":     r.PostFormValue("old_kind"),
		"old_pattern":  r.PostFormValue("old_pattern"),
		"old_path":     r.PostFormValue("old_path"),
		"old_port":     r.PostFormValue("old_port"),
		"old_protocol": r.PostFormValue("old_protocol"),
		"name":         r.PostFormValue("name"),
	}
	payload, errText := ui2ScopeAPIPayload(r)
	if errText == "" && strings.HasPrefix(r.PostFormValue("scope_action"), "library-") {
		// The review binds content, not a name: digests of the stored document and the live
		// list are computed from server state NOW and overwrite whatever the form carried,
		// and the sheet renders the exact lists those digests name.
		errText = s.ui2ScopeLibraryReview(r.PostFormValue("scope_action"), payload, model)
	}
	if errText != "" {
		model["error"] = errText
	} else {
		body, _ := ui2Marshal(payload)
		token, _, errText := s.ui2MintConfirm("/api/scope", http.MethodPost, "/api/scope", body)
		// The review copy says the confirmation covers "exactly the call above", so the
		// preview projects the FULL body, not ui2MintConfirm's 200-character abbreviation:
		// a library call carries two content digests that push it past that cut, and a
		// truncated body under an "exactly this call" claim is a label the bytes do not
		// keep (the session-rule review's full-projection rule applies here too).
		model["preview"] = fmt.Sprintf("%s %s — body %s", http.MethodPost, "/api/scope", string(body))
		model["token"] = token
		model["error"] = errText
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("scope_confirm.html", model)))
}

// handleUI2ScopeRun serves POST /ui2/scope/run: spends the confirmation token on the exact
// /api/scope call the operator reviewed and re-renders the rules. A refusal (a missing or spent
// token, a body the token was not minted for, or the API's own reason such as a tuple that no
// longer matches a rule) renders as the note; the rules shown are the ones still in force.
func (s *Server) handleUI2ScopeRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	note := ""
	done := ""
	payload, errText := ui2ScopeAPIPayload(r)
	if errText != "" {
		note = errText
	} else {
		result, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/scope", payload, r.PostFormValue("token"))
		note = errText
		if errText == "" {
			done = ui2ScopeLibraryDoneNote(payload, result)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("scope.html", s.ui2ScopeViewDone(note, done))))
}

// ui2ScopeLibraryDoneNote turns a successful library call's response into the page's
// confirmation line: the counts a bare "ok" cannot carry (why updateScopeLibrary answers
// for itself). Non-library actions and unreadable responses get no line rather than a
// guessed one.
func ui2ScopeLibraryDoneNote(payload map[string]any, result any) string {
	m, ok := result.(map[string]any)
	if !ok {
		return ""
	}
	name, _ := m["name"].(string)
	switch payload["action"] {
	case "library_load":
		if m["loaded"] == true {
			return fmt.Sprintf("Loaded library %q: %v rules now in force.", name, m["rules"])
		}
	case "library_save":
		if m["saved"] == true {
			if m["replaced"] == true {
				return fmt.Sprintf("Saved library %q (%v rules), replacing the previous save.", name, m["rules"])
			}
			return fmt.Sprintf("Saved new library %q (%v rules).", name, m["rules"])
		}
	case "library_delete":
		if m["deleted"] == true {
			return fmt.Sprintf("Deleted library %q; the live scope was not changed.", name)
		}
	}
	return ""
}

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

// ---- Logger ----------------------------------------------------------------------------------

// handleUI2Logger serves GET /ui2/logger: requests burpsy itself sent (the tool log),
// server-paged like history.
func (s *Server) handleUI2Logger(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	offset := 0
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		offset = n
	}
	search := strings.TrimSpace(q.Get("search"))
	if offset > 0 {
		// Infinite-scroll append: only the <tr> rows plus the next sentinel, so the beforeend
		// swap grows the tbody without re-appending the capture panel, filter and table head.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("logger_rows_append.html", s.ui2LoggerView(search, limit, offset, ""))))
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Logger", "logger", ui2Exec("logger.html", s.ui2LoggerView(search, limit, offset, "")))
}

// ui2LoggerView builds the Logger page model through the API: the entry page plus the capture
// axis (per-tool recording state and not-captured counters).
func (s *Server) ui2LoggerView(search string, limit, offset int, filterNote string) ui2LoggerModel {
	rec := newRecorder()
	req := newReq(http.MethodGet, fmt.Sprintf("/api/tools/log?limit=%d", 100000))
	s.toolLogGet(rec, req)
	var resp toolLogResp
	_ = ui2DecodeJSON(rec.Body.Bytes(), &resp)
	// Newest first already; apply search + page server-side.
	entries := resp.Entries
	if search != "" {
		needle := strings.ToLower(search)
		filtered := entries[:0]
		for _, e := range entries {
			hay := strings.ToLower(e.Tool + " " + e.Method + " " + e.Host + e.Path + " " + ui2StatusString2(e.Status))
			if strings.Contains(hay, needle) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}
	total := len(entries)
	end := offset + limit
	if end > total {
		end = total
	}
	var page []toolLogEntry
	if offset < total {
		page = entries[offset:end]
	}
	next := -1
	if end < total {
		next = end
	}
	fv := ui2LoggerFilterView{
		Term: resp.Filter.Term, Regex: resp.Filter.Regex, Case: resp.Filter.Case,
		Negate: resp.Filter.Negate, ScopeOnly: resp.Filter.ScopeOnly,
		MimeJoined: strings.Join(resp.Filter.MIME, ", "), FilteredTotal: resp.FilteredTotal,
	}
	var parts []string
	for _, class := range resp.Filter.Status {
		switch class {
		case 2:
			fv.S2 = true
			parts = append(parts, "2xx")
		case 3:
			fv.S3 = true
			parts = append(parts, "3xx")
		case 4:
			fv.S4 = true
			parts = append(parts, "4xx")
		case 5:
			fv.S5 = true
			parts = append(parts, "5xx")
		}
	}
	if len(parts) > 0 {
		fv.Active = true
	}
	if fv.Term != "" {
		fv.Active = true
		t := strconv.Quote(fv.Term)
		var mods []string
		if fv.Regex {
			mods = append(mods, "regex")
		}
		if fv.Case {
			mods = append(mods, "case-sensitive")
		}
		if fv.Negate {
			mods = append(mods, "negated")
		}
		if len(mods) > 0 {
			t += " (" + strings.Join(mods, ", ") + ")"
		}
		parts = append(parts, "term "+t)
	}
	if fv.ScopeOnly {
		fv.Active = true
		parts = append(parts, "in scope only")
	}
	if len(resp.Filter.MIME) > 0 {
		fv.Active = true
		parts = append(parts, "excluding MIME "+fv.MimeJoined)
	}
	fv.Summary = strings.Join(parts, " · ")

	captureRows := make([]ui2LoggerCaptureRow, 0, len(toollog.ToolAll))
	for _, t := range toollog.ToolAll {
		name := t.String()
		captureRows = append(captureRows, ui2LoggerCaptureRow{
			Tool: name, On: resp.Capturing[name], Uncaptured: resp.Uncaptured[name],
		})
	}
	return ui2LoggerModel{
		Entries: page, Total: resp.Total, Matched: total, Offset: offset, Limit: limit,
		NextOffset: next, Search: search, HasMore: next >= 0, Counts: resp.Counts, Capturing: resp.Capturing,
		CaptureRows: captureRows, Filter: fv, FilterNote: filterNote,
	}
}

// handleUI2LoggerAction serves POST /ui2/logger/{action}: capture-<tool>-on/off flips one
// tool's recording through the API and re-renders the fragment. Turning capture off means the
// tool's next requests are sent and deliberately not recorded, so the page says so next to the
// button and the not-captured counters keep the count honest.
func (s *Server) handleUI2LoggerAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action == "filter-set" || action == "filter-clear" {
		s.ui2LoggerFilterSet(w, r, action == "filter-clear")
		return
	}
	tool, state, ok := strings.Cut(strings.TrimPrefix(action, "capture-"), "-")
	if !strings.HasPrefix(action, "capture-") || !ok || (state != "on" && state != "off") {
		http.Error(w, "unknown logger action", http.StatusBadRequest)
		return
	}
	if _, ok := toollog.ToolFromName(tool); !ok {
		http.Error(w, "unknown logger action", http.StatusBadRequest)
		return
	}
	body, _ := ui2Marshal(map[string]any{"tool": tool, "on": state == "on"})
	req := newReq(http.MethodPost, "/api/tools/log")
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytes.NewReader(body))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code >= 400 {
		http.Error(w, rec.Body.String(), rec.Code)
		return
	}
	_ = r.ParseForm()
	search := strings.TrimSpace(r.PostFormValue("search"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("logger.html", s.ui2LoggerView(search, 100, 0, ""))))
}

// ui2LoggerFilterSet applies or clears the capture filter through the API and re-renders the
// fragment. The filter decides what gets RECORDED: a row it refuses is not kept and the filtered
// counter advances, so the page says that next to the form rather than presenting it as a view
// filter. An invalid filter (a bad regex, a bad MIME pattern) is refused by the API with its
// reason, and the page carries that reason unchanged with the filter left as it was.
func (s *Server) ui2LoggerFilterSet(w http.ResponseWriter, r *http.Request, clear bool) {
	_ = r.ParseForm()
	search := strings.TrimSpace(r.PostFormValue("search"))
	fv := map[string]any{}
	if !clear {
		var status []int
		for _, v := range r.PostForm["status"] {
			n, err := strconv.Atoi(v)
			if err != nil || n < 2 || n > 5 {
				http.Error(w, "status classes are 2, 3, 4 and 5", http.StatusBadRequest)
				return
			}
			status = append(status, n)
		}
		if status == nil {
			status = []int{}
		}
		var mime []string
		for _, piece := range strings.Split(r.PostFormValue("mime"), ",") {
			if p := strings.TrimSpace(piece); p != "" {
				mime = append(mime, p)
			}
		}
		fv = map[string]any{
			"status":         status,
			"term":           strings.TrimSpace(r.PostFormValue("term")),
			"regex":          r.PostFormValue("regex") != "",
			"case_sensitive": r.PostFormValue("case") != "",
			"negate":         r.PostFormValue("negate") != "",
			"scope_only":     r.PostFormValue("scope_only") != "",
			"mime":           mime,
		}
	}
	body, _ := ui2Marshal(map[string]any{"filter": fv})
	req := newReq(http.MethodPost, "/api/tools/log")
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytes.NewReader(body))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	note := ""
	if rec.Code >= 400 {
		// The API refused the filter; it stays as it was, and the page says why.
		note = strings.TrimSpace(rec.Body.String())
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("logger.html", s.ui2LoggerView(search, 100, 0, note))))
}

type ui2LoggerCaptureRow struct {
	Tool       string
	On         bool
	Uncaptured uint64
}

type ui2LoggerModel struct {
	Entries     []toolLogEntry
	Total       int
	Matched     int
	Offset      int
	Limit       int
	NextOffset  int
	Search      string
	HasMore     bool
	Counts      map[string]int
	Capturing   map[string]bool
	CaptureRows []ui2LoggerCaptureRow
	Filter      ui2LoggerFilterView
	FilterNote  string
}

// ui2LoggerFilterView is the capture filter prepared for the template: the echo of what the
// server enforces plus per-class booleans the checkbox markup needs.
type ui2LoggerFilterView struct {
	Active         bool
	Summary        string
	S2, S3, S4, S5 bool
	Term           string
	Regex          bool
	Case           bool
	Negate         bool
	ScopeOnly      bool
	MimeJoined     string
	FilteredTotal  uint64
}

// ---- WS history ------------------------------------------------------------------------------

// handleUI2WS serves GET /ui2/ws: connections and frames.
func (s *Server) handleUI2WS(w http.ResponseWriter, r *http.Request) {
	connsRec := newRecorder()
	s.handleWSConnections(connsRec, newReq(http.MethodGet, "/api/ws/connections"))
	var conns []any
	_ = ui2DecodeJSON(connsRec.Body.Bytes(), &conns)
	histRec := newRecorder()
	s.handleWSHistory(histRec, newReq(http.MethodGet, "/api/ws/history?limit=200"))
	var hist map[string]any
	_ = ui2DecodeJSON(histRec.Body.Bytes(), &hist)
	ui2Fragment(w, r, "burpsy /ui2/ — WebSockets", "ws", ui2Exec("ws.html", map[string]any{"connections": conns, "history": hist}))
}

// ---- Proxy settings: listeners + options -----------------------------------------------------

// handleUI2Proxy serves GET /ui2/proxy: listeners, response-modification options with counters,
// and match & replace rules.
func (s *Server) handleUI2Proxy(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	// A section whose API errors (no proxy attached answers 503, not an object) must fall back
	// to the template's empty state, not nil: a nil section aborts the whole template at the
	// first key lookup and the rest of the page never renders.
	get := func(path string) map[string]any {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		var m map[string]any
		if err := ui2DecodeJSON(rec.Body.Bytes(), &m); err != nil {
			return map[string]any{}
		}
		return m
	}
	model["listeners"] = get("/api/proxy/listener")
	model["options"] = get("/api/proxy/options")
	model["rules"] = get("/api/tools/rules")
	model["passthrough"] = get("/api/proxy/passthrough")
	ui2Fragment(w, r, "burpsy /ui2/ — Proxy settings", "proxy", ui2Exec("proxy.html", model))
}

// ---- Extensions ------------------------------------------------------------------------------

// handleUI2Extensions serves GET /ui2/extensions: the plugin list, state breakdown and allowlist.
func (s *Server) handleUI2Extensions(w http.ResponseWriter, r *http.Request) {
	rec := newRecorder()
	s.handleExtensions(rec, newReq(http.MethodGet, "/api/extensions"))
	var view any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	apisRec := newRecorder()
	s.handleExtensionAPIs(apisRec, newReq(http.MethodGet, "/api/extensions/apis"))
	var apis any
	_ = ui2DecodeJSON(apisRec.Body.Bytes(), &apis)
	ui2Fragment(w, r, "burpsy /ui2/ — Extensions", "extensions", ui2Exec("extensions.html", map[string]any{"extensions": view, "apis": apis}))
}

// ---- Scanner: launch configs, checks, coverage, live ----------------------------------------

// handleUI2Scanner serves GET /ui2/scanner: saved configurations, the corpus inventory and
// the live-audit state — the read side of the Scanner tool.
func (s *Server) handleUI2Scanner(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy /ui2/ — Scanner", "scanner", ui2Exec("scanner.html", s.ui2ScannerModel()))
}

// ui2ScannerModel gathers the scanner page's read model through the API, the same shape the
// console reads.
func (s *Server) ui2ScannerModel() map[string]any {
	model := map[string]any{}
	get := func(path string, target any) {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		_ = ui2DecodeJSON(rec.Body.Bytes(), target)
	}
	var configs, issueTypes, checks, coverage, live, auditItems, config any
	get("/api/scanner/configs", &configs)
	get("/api/scanner/issue-types", &issueTypes)
	get("/api/scanner/checks", &checks)
	get("/api/scanner/coverage", &coverage)
	get("/api/scanner/live", &live)
	get("/api/scanner/audit-items", &auditItems)
	get("/api/scanner/config", &config)
	model["configs"] = configs
	model["issue_types"] = issueTypes
	model["checks"] = checks
	model["coverage"] = coverage
	model["live"] = live
	model["audit_items"] = auditItems
	model["config"] = config
	if view, ok := config.(map[string]any); ok {
		model["scan_config_rows"] = ui2ScanConfigRows(view)
	}
	return model
}

// ui2ScannerAuditPayload reads the launch form's exchange id and configuration name into the
// exact /api/scanner/audit body. The error text is for the page; the API does the real
// validation on dispatch.
func ui2ScannerAuditPayload(r *http.Request) (map[string]any, string) {
	exchangeID := r.PostFormValue("exchange_id")
	id, err := strconv.ParseUint(exchangeID, 10, 64)
	if err != nil {
		return nil, "an exchange id is required - pick one from the History page"
	}
	payload := map[string]any{"exchange_id": id}
	if name := r.PostFormValue("config"); name != "" {
		payload["config"] = name
	}
	return payload, ""
}

// handleUI2ScannerLaunch serves POST /ui2/scanner/launch: builds the /api/scanner/audit call
// from the form, mints a one-time confirmation for that exact call, and renders the review
// step. An audit sends active probes at the target, so the first click never launches.
func (s *Server) handleUI2ScannerLaunch(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := map[string]any{
		"exchange_id": r.PostFormValue("exchange_id"),
		"config":      r.PostFormValue("config"),
	}
	payload, errText := ui2ScannerAuditPayload(r)
	if errText != "" {
		model["error"] = errText
	} else {
		body, _ := ui2Marshal(payload)
		token, preview, errText := s.ui2MintConfirm("/api/scanner/audit", http.MethodPost, "/api/scanner/audit", body)
		model["token"] = token
		model["preview"] = preview
		model["error"] = errText
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("scanner_launch.html", model)))
}

// handleUI2ScannerRun serves POST /ui2/scanner/run: spends the confirmation token on the real
// /api/scanner/audit call and re-renders the page with the audit's outcome. The audit answers
// synchronously, so the outcome the operator reviewed is the outcome on the page.
func (s *Server) handleUI2ScannerRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := s.ui2ScannerModel()
	payload, errText := ui2ScannerAuditPayload(r)
	if errText != "" {
		model["audit_error"] = errText
	} else {
		result, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/scanner/audit", payload, r.PostFormValue("token"))
		model["audit_result"] = result
		model["audit_error"] = errText
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Scanner", "scanner", ui2Exec("scanner.html", model))
}

// ---- Scanner: engine and check-family configuration ------------------------------------------

// ui2ScanConfigBoolKeys is the ordered list of the check-family switches PUT /api/scanner/config
// accepts, mirrored from scannerConfigBoolKeys so the page offers exactly the wire's keys - the
// endpoint refuses anything else, and a page that invented a key would teach the operator a
// control that does not exist.
var ui2ScanConfigBoolKeys = []string{
	"check_sqli", "check_xss", "check_path_traversal", "check_ssrf", "check_xxe",
	"check_jwt_weak", "check_js_vulns", "check_headers", "check_cache_poisoning", "check_corpus",
	"check_dom", "check_xss_browser_confirm", "check_ssrf_in_band", "check_extended_coverage",
	"check_reflection_probes", "check_host_discovery", "check_response_dependence",
	"check_passive_posture", "check_passive_analysis", "check_active_injection",
	"check_extended_active", "check_out_of_band", "check_stored", "check_file_upload",
	"check_jwt_forgery", "check_jwt_exposure", "check_idor", "check_login_rate_limit",
	"check_username_enumeration", "check_graphql_hardening", "check_sqli_heavy_query",
	"check_sqli_or_boolean", "check_sqli_stacked", "check_password_reset", "check_session_management",
	"check_request_smuggling", "check_host_header", "check_insecure_deserialization",
	"check_nosql_injection", "check_websocket_hijacking", "check_client_ip_spoofing",
	"check_server_side_parameter_pollution", "check_llm_prompt_injection", "check_weak_crypto",
	"check_cookie_attributes", "check_subdomain_takeover",
}

// ui2ScanConfigView reads the live engine configuration the way the page does.
func (s *Server) ui2ScanConfigView() map[string]any {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/scanner/config"))
	var view map[string]any
	if err := ui2DecodeJSON(rec.Body.Bytes(), &view); err != nil {
		return map[string]any{}
	}
	return view
}

// ui2ScanConfigRows pairs each switch's key with its current state for the template.
func ui2ScanConfigRows(view map[string]any) []map[string]any {
	rows := []map[string]any{}
	for _, key := range ui2ScanConfigBoolKeys {
		on, _ := view[key].(bool)
		rows = append(rows, map[string]any{"key": key, "label": strings.TrimPrefix(key, "check_"), "on": on})
	}
	return rows
}

// ui2ScanConfigPatch diffs the submitted form against the live view into the exact PUT body:
// only keys whose value changed, so the review step and the confirmation cover precisely what
// moves. Numbers come back as float64 from the JSON decode; a negative or unparseable value is
// an error before any token exists.
func ui2ScanConfigPatch(r *http.Request, view map[string]any) (map[string]any, []string, string) {
	patch := map[string]any{}
	changes := []string{}
	for _, key := range ui2ScanConfigBoolKeys {
		cur, _ := view[key].(bool)
		want := r.PostFormValue(key) == "on"
		if want != cur {
			patch[key] = want
			onOff := func(b bool) string {
				if b {
					return "on"
				}
				return "off"
			}
			changes = append(changes, strings.TrimPrefix(key, "check_")+": "+onOff(cur)+" -> "+onOff(want))
		}
	}
	for _, key := range []string{"timeout_ms", "probe_timeout_ms"} {
		raw := strings.TrimSpace(r.PostFormValue(key))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return nil, nil, key + " wants a non-negative number of milliseconds"
		}
		if cur, _ := view[key].(float64); int(cur) != n {
			patch[key] = n
			changes = append(changes, fmt.Sprintf("%s: %d -> %d", key, int(cur), n))
		}
	}
	if len(patch) == 0 {
		return nil, nil, "nothing changed - the submitted configuration matches the running one"
	}
	return patch, changes, ""
}

// handleUI2ScannerConfigConfirm serves POST /ui2/scanner/config-confirm: diffs the form against
// the live configuration, mints a one-time confirmation for the exact PUT, and renders the
// review step naming every change.
func (s *Server) handleUI2ScannerConfigConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := map[string]any{}
	patch, changes, errText := ui2ScanConfigPatch(r, s.ui2ScanConfigView())
	if errText != "" {
		model["error"] = errText
	} else {
		body, _ := ui2Marshal(patch)
		token, preview, errText := s.ui2MintConfirm("/api/scanner/config", http.MethodPut, "/api/scanner/config", body)
		model["token"] = token
		model["preview"] = preview
		model["error"] = errText
		model["changes"] = changes
		model["patch"] = string(body)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("scanner_config_confirm.html", model)))
}

// handleUI2ScannerConfigRun serves POST /ui2/scanner/config-run: spends the confirmation token
// on the exact patch the operator reviewed and re-renders the page with the outcome.
func (s *Server) handleUI2ScannerConfigRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// Dispatch first: the re-rendered page must show the state AFTER the change, so the model is
	// built once the PUT has landed - a model fetched first would show the operator the
	// configuration they just replaced, next to a banner saying it was applied.
	var patch map[string]any
	var outcomeErr string
	applied := false
	if err := ui2DecodeJSON([]byte(r.PostFormValue("patch")), &patch); err != nil || len(patch) == 0 {
		outcomeErr = "the reviewed change set was lost - submit the form again"
	} else {
		_, outcomeErr = s.ui2DispatchConfirmed(http.MethodPut, "/api/scanner/config", patch, r.PostFormValue("token"))
		applied = outcomeErr == ""
	}
	model := s.ui2ScannerModel()
	model["config_error"] = outcomeErr
	model["config_applied"] = applied
	ui2Fragment(w, r, "burpsy /ui2/ — Scanner", "scanner", ui2Exec("scanner.html", model))
}

// ---- Scanner: crawl launch -----------------------------------------------------------------

// ui2CrawlPayload reads the crawl form's seed list and configuration name into the exact
// /api/crawl body. Seeds are whitespace-separated; the API does the real scope and URL
// validation on dispatch.
func ui2CrawlPayload(r *http.Request) (map[string]any, string) {
	seeds := []string{}
	for _, f := range strings.Fields(r.PostFormValue("seeds")) {
		seeds = append(seeds, f)
	}
	if len(seeds) == 0 {
		return nil, "at least one seed URL is required"
	}
	payload := map[string]any{"seeds": seeds}
	if name := r.PostFormValue("config"); name != "" {
		payload["config"] = name
	}
	return payload, ""
}

// handleUI2ScannerCrawlLaunch serves POST /ui2/scanner/crawl-launch: builds the /api/crawl
// call from the form, mints a one-time confirmation for that exact call, and renders the
// review step. A crawl sends its own requests at the target, so the first click never launches.
func (s *Server) handleUI2ScannerCrawlLaunch(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := map[string]any{
		"seeds":  r.PostFormValue("seeds"),
		"config": r.PostFormValue("config"),
	}
	payload, errText := ui2CrawlPayload(r)
	if errText != "" {
		model["error"] = errText
	} else {
		body, _ := ui2Marshal(payload)
		token, preview, errText := s.ui2MintConfirm("/api/crawl", http.MethodPost, "/api/crawl", body)
		model["token"] = token
		model["preview"] = preview
		model["error"] = errText
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("crawl_launch.html", model)))
}

// handleUI2ScannerCrawlRun serves POST /ui2/scanner/crawl-run: spends the confirmation token on
// the real /api/crawl call and re-renders the page with the accepted task or the refusal. A
// crawl is asynchronous, so the page names the task and says it does not watch it run.
func (s *Server) handleUI2ScannerCrawlRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := s.ui2ScannerModel()
	payload, errText := ui2CrawlPayload(r)
	if errText != "" {
		model["crawl_error"] = errText
	} else {
		result, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/crawl", payload, r.PostFormValue("token"))
		model["crawl_result"] = result
		model["crawl_error"] = errText
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Scanner", "scanner", ui2Exec("scanner.html", model))
}

// handleUI2ScannerCrawlWatch serves GET /ui2/scanner/crawl-watch?task=N: the page's
// refresh-on-demand view of one retained crawl - the /api/crawl/live read rendered as state,
// phase, fetch count and recent fetches. It answers only when asked: nothing on the page polls.
func (s *Server) handleUI2ScannerCrawlWatch(w http.ResponseWriter, r *http.Request) {
	task := r.URL.Query().Get("task")
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/crawl/live?task="+url.QueryEscape(task)))
	var view map[string]any
	if rec.Code != http.StatusOK {
		view = map[string]any{"task_id": task, "error": strings.TrimSpace(rec.Body.String())}
	} else {
		_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	}
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("crawl_watch.html", view)))
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Scanner", "scanner", ui2Exec("crawl_watch.html", view))
}

// ---- Advisories (issue definitions) ----------------------------------------------------------

// handleUI2Advisories serves GET /ui2/advisories: the issue-definition catalogue.
func (s *Server) handleUI2Advisories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/advisories?q="+q.Get("q")+"&severity="+q.Get("severity")))
	var view any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &view)
	ui2Fragment(w, r, "burpsy /ui2/ — Issue definitions", "advisories", ui2Exec("advisories.html", view))
}

// ---- Organizer -------------------------------------------------------------------------------

// handleUI2Organizer serves GET /ui2/organizer: saved items and collections.
func (s *Server) handleUI2Organizer(w http.ResponseWriter, r *http.Request) {
	s.ui2OrganizerRender(w, r, "")
}

// ---- Session ---------------------------------------------------------------------------------

// handleUI2Session serves GET /ui2/session: rules, cookie jar, trace, prompts.
func (s *Server) handleUI2Session(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session.html", s.ui2SessionView("")))
}

// ui2SessionView builds the Session page model: rules, cookie jar, trace and prompts through the
// API, plus a note slot so a refused or applied rule change explains itself on the page it was
// sent from. Each rule row is enriched with its tools axis rendered as checkbox state against the
// served palette, so the edit form prefills what the rule actually restricts (absent scope_tools
// = every tool) instead of guessing.
func (s *Server) ui2SessionView(note string) map[string]any {
	model := map[string]any{}
	get := func(path string, target any) {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		_ = ui2DecodeJSON(rec.Body.Bytes(), target)
	}
	var rules, cookies, trace, prompts any
	get("/api/session/rules", &rules)
	get("/api/session/cookies", &cookies)
	get("/api/session/trace", &trace)
	get("/api/session/prompts", &prompts)
	// The API's expires is a bare time.Time, so a session cookie's zero value crosses the wire
	// as "0001-01-01T00:00:00Z" (omitempty cannot drop a struct). The page says "session" for it
	// instead — the jar's own word for a cookie with no expiry.
	if jar, ok := cookies.(map[string]any); ok {
		if auths, ok := jar["cookies"].([]any); ok {
			for _, a := range auths {
				if auth, ok := a.(map[string]any); ok {
					if pairs, ok := auth["cookies"].([]any); ok {
						for _, pr := range pairs {
							if pair, ok := pr.(map[string]any); ok {
								if exp, _ := pair["expires"].(string); strings.HasPrefix(exp, "0001-01-01") {
									delete(pair, "expires")
								}
							}
						}
					}
				}
			}
		}
	}
	model["rules"], model["cookies"], model["trace"], model["prompts"] = rules, cookies, trace, prompts
	model["note"] = note
	// Row enrichment: tools_mode ("all" when scope_tools is absent - Burp's unrestricted reading)
	// and tools_checks (the palette with this rule's picks ticked) drive the edit form's radios
	// and checkboxes.
	if rv, ok := rules.(map[string]any); ok {
		palette, _ := rv["tools"].([]any)
		if rows, ok := rv["rules"].([]any); ok {
			for _, row := range rows {
				rule, ok := row.(map[string]any)
				if !ok {
					continue
				}
				picked := map[string]bool{}
				list, has := rule["scope_tools"].([]any)
				if has {
					for _, t := range list {
						if name, ok := t.(string); ok {
							picked[name] = true
						}
					}
				}
				if has {
					rule["tools_mode"] = "selected"
				} else {
					rule["tools_mode"] = "all"
				}
				checks := make([]map[string]any, 0, len(palette))
				for _, t := range palette {
					if name, ok := t.(string); ok {
						checks = append(checks, map[string]any{"name": name, "checked": picked[name]})
					}
				}
				rule["tools_checks"] = checks
				if s.sessionCoordinator != nil {
					if id, err := strconv.ParseInt(fmt.Sprint(rule["id"]), 10, 64); err == nil {
						if snapshot, digest, found := s.sessionCoordinator.RuleSnapshot(session.RuleID(id)); found {
							rule["action_base"] = digest
							rule["action_rows"] = ui2SessionActionRows(snapshot)
						}
					}
				}
			}
		}
	}
	return model
}

// ---- Tools: decoder / comparer ---------------------------------------------------------------

// handleUI2Decoder serves GET /ui2/decoder (form) and POST /ui2/decoder/run (the transform),
// posting to /api/tools/decode|encode|hash server-side and rendering the result.
func (s *Server) handleUI2Decoder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2DecoderRun(w, r)
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Decoder", "decoder", ui2Exec("decoder.html", map[string]any{"result": nil}))
}

func (s *Server) handleUI2DecoderRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	op := r.PostFormValue("op")
	input := r.PostFormValue("input")
	arg := r.PostFormValue("arg")
	var path string
	body := map[string]string{"input": input}
	switch op {
	case "decode":
		path = "/api/tools/decode"
		body["encoding"] = arg // toolsDecodeReq reads "encoding"; "op" would fall into the guesser
	case "encode":
		path = "/api/tools/encode"
		body["encoding"] = arg // toolsEncodeReq reads "encoding"
	case "hash":
		path = "/api/tools/hash"
		body["algorithm"] = arg
	default:
		http.Error(w, "unknown decoder op", http.StatusBadRequest)
		return
	}
	result, errText := s.ui2APIResult(http.MethodPost, path, body)
	display, meta := ui2ToolOutputText(result)
	ui2Fragment(w, r, "burpsy /ui2/ — Decoder", "decoder", ui2Exec("decoder.html", map[string]any{"result": display, "meta": meta, "error": errText, "op": op, "arg": arg, "input": input}))
}

// handleUI2Comparer serves GET /ui2/comparer (form) and POST /ui2/comparer/run.
func (s *Server) handleUI2Comparer(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2ComparerRun(w, r)
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Comparer", "comparer", ui2Exec("comparer.html", map[string]any{"result": nil}))
}

func (s *Server) handleUI2ComparerRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	a := r.PostFormValue("a")
	b := r.PostFormValue("b")
	// JSON encoding silently repairs invalid UTF-8 to U+FFFD, which would put the
	// API's diff offsets in a different byte space than the strings rendered here.
	// Repair explicitly so both sides see the same bytes, and disclose it.
	ra, rb := strings.ToValidUTF8(a, "\uFFFD"), strings.ToValidUTF8(b, "\uFFFD")
	repaired := ra != a || rb != b
	result, errText := s.ui2APIResult(http.MethodPost, "/api/tools/compare", map[string]string{"a": ra, "b": rb})
	ui2Fragment(w, r, "burpsy /ui2/ — Comparer", "comparer", ui2Exec("comparer.html", map[string]any{"result": ui2RenderCompare(ra, rb, result, repaired), "error": errText, "a": a, "b": b}))
}

// ---- Repeater --------------------------------------------------------------------------------

// handleUI2Repeater serves GET /ui2/repeater: the editor with the last captured request as
// the draft, and POST /ui2/repeater/send forwards through /api/repeater/send.
func (s *Server) handleUI2Repeater(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2RepeaterSend(w, r)
		return
	}
	draft := ""
	if exs := s.store.Exchanges(); len(exs) > 0 {
		ex := exs[len(exs)-1]
		if ex.Request != nil {
			if msg, err := s.store.Get(*ex.Request); err == nil {
				draft = string(msg.Raw())
			}
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", ui2Exec("repeater.html", map[string]any{"draft": draft, "result": nil}))
}

func (s *Server) handleUI2RepeaterSend(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	raw := r.PostFormValue("raw")
	target := r.PostFormValue("target")
	if target == "" {
		// /api/repeater/send requires a target; the ui2 form's field is optional, so derive it
		// from the request's own Host header (absolute-form request lines also work).
		target = ui2HostFromRequest(raw)
	}
	if target == "" {
		ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", ui2Exec("repeater.html", map[string]any{
			"draft": raw, "result": nil,
			"error": "no target: the request carries no Host header and no target was given",
		}))
		return
	}
	result, errText := s.ui2APIResult(http.MethodPost, "/api/repeater/send", map[string]string{"target": target, "request": raw})
	ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", ui2Exec("repeater.html", map[string]any{
		"draft": raw, "result": result, "error": errText, "target": target,
	}))
}

// ui2HostFromRequest extracts the target authority from a raw request: an absolute-form
// request line wins, else the Host header. Line endings are normalised first: an htmx form
// post delivers the textarea's value with LF newlines, not the CRLF a raw request file has.
func ui2HostFromRequest(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) >= 2 && strings.Contains(fields[1], "://") {
		rest := fields[1][strings.Index(fields[1], "://")+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	for _, line := range strings.Split(norm, "\n") {
		if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

// ui2APIResult calls one internal JSON API through the mux and returns either the decoded
// body or a plain-text error string. Returning a string (not map[string]any{"error":…}) is
// what keeps templates from printing Go map syntax like "map[error:empty target]".
func (s *Server) ui2APIResult(method, path string, payload any) (any, string) {
	var body ioReadCloser
	if payload != nil {
		b, _ := ui2Marshal(payload)
		body = ioNopCloser(strings.NewReader(string(b)))
	}
	req := newReq(method, path)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = body
	}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return nil, strings.TrimSpace(rec.Body.String())
	}
	var result any
	if err := ui2DecodeJSON(rec.Body.Bytes(), &result); err != nil {
		return nil, "unreadable response: " + err.Error()
	}
	return result, ""
}

// ui2APIErrorText renders an API error body for display: the error sentence plus the hint
// when one came back, never the raw JSON blob — the blob's escaped angle brackets and nested
// status dump bury the actual refusal (browser UAT caught the collaborator mint refusal
// rendering as one unreadable JSON line). A body that is not the API's error shape falls
// back to the raw text unchanged: an ugly refusal the operator can read beats a hidden one.
func ui2APIErrorText(errText string) string {
	var m map[string]any
	if err := ui2DecodeJSON([]byte(errText), &m); err != nil {
		return errText
	}
	msg, _ := m["error"].(string)
	if msg == "" {
		return errText
	}
	if hint, _ := m["hint"].(string); hint != "" {
		return msg + " " + hint
	}
	return msg
}

// ui2ToolOutputText renders a tools API result (decode/encode/hash) as display text:
// the output text plus honest flags — never a Go map dump of the JSON.
func ui2ToolOutputText(result any) (display, meta string) {
	m, ok := result.(map[string]any)
	if !ok {
		return "", ""
	}
	out, _ := m["output"].(map[string]any)
	text, _ := out["text"].(string)
	flags := []string{}
	if t, _ := out["truncated"].(bool); t {
		flags = append(flags, "output truncated")
	}
	if p, _ := m["partial"].(bool); p {
		flags = append(flags, "partial decode: a compressed stream stopped early")
	}
	if u, ok := out["utf8"].(bool); ok && !u {
		flags = append(flags, "not valid UTF-8: replacement characters shown")
	}
	return text, strings.Join(flags, " · ")
}

// ui2DiffSeg is one rendered diff piece: prefix is "  " (context), "- " (removed
// from a) or "+ " (added in b); text may contain newlines.
type ui2DiffSeg struct {
	prefix string
	text   string
}

// ui2CompareSegs turns byte-granular compare ops into display segments without
// ever splitting or duplicating a multibyte character. Ops are consumed in
// order; consecutive ops whose shared boundary falls inside a UTF-8 rune (on
// either side) are grouped, so every group's a-range and b-range is a whole
// number of runes and groups partition both buffers exactly. A group that is
// all-equal renders as context; any other group renders as common leading
// runes (context), the differing a-middle ("- "), the differing b-middle
// ("+ "), then common trailing runes (context). Concatenating the "  "/"- "
// segments therefore reconstructs a byte-for-byte, and "  "/"+ " reconstructs
// b — no widening past op boundaries, no dropped partial bytes.
func ui2CompareSegs(a, b string, ops []any) (segs []ui2DiffSeg, corruptRepaired bool) {
	num := func(v any) int {
		f, _ := v.(float64)
		return int(f)
	}
	type rawOp struct {
		kind                   string
		aOff, aLen, bOff, bLen int
	}
	runeAligned := func(s string, p int) bool {
		return p <= 0 || p >= len(s) || utf8.RuneStart(s[p])
	}
	// repair keeps corrupt op offsets from ever emitting invalid UTF-8: any
	// sliced segment that splits a rune is repaired for display and disclosed.
	repair := func(s string) string {
		if utf8.ValidString(s) {
			return s
		}
		corruptRepaired = true
		return strings.ToValidUTF8(s, "�")
	}
	// group accumulates ops sharing rune-split boundaries.
	var gOps []rawOp
	gAStart, gAEnd, gBStart, gBEnd := 0, 0, 0, 0
	flush := func() {
		if len(gOps) == 0 {
			return
		}
		aText, bText := "", ""
		if 0 <= gAStart && gAStart <= gAEnd && gAEnd <= len(a) {
			aText = repair(a[gAStart:gAEnd])
		}
		if 0 <= gBStart && gBStart <= gBEnd && gBEnd <= len(b) {
			bText = repair(b[gBStart:gBEnd])
		}
		allEqual := true
		for _, o := range gOps {
			if o.kind != "equal" {
				allEqual = false
				break
			}
		}
		switch {
		case aText == "" && bText == "":
			// nothing to show
		case allEqual && aText == bText:
			segs = append(segs, ui2DiffSeg{"  ", aText})
		default:
			ar, br := []rune(aText), []rune(bText)
			p := 0
			for p < len(ar) && p < len(br) && ar[p] == br[p] {
				p++
			}
			sfx := 0
			for sfx < len(ar)-p && sfx < len(br)-p && ar[len(ar)-1-sfx] == br[len(br)-1-sfx] {
				sfx++
			}
			if p > 0 {
				segs = append(segs, ui2DiffSeg{"  ", string(ar[:p])})
			}
			if mid := ar[p : len(ar)-sfx]; len(mid) > 0 {
				segs = append(segs, ui2DiffSeg{"- ", string(mid)})
			}
			if mid := br[p : len(br)-sfx]; len(mid) > 0 {
				segs = append(segs, ui2DiffSeg{"+ ", string(mid)})
			}
			if sfx > 0 {
				segs = append(segs, ui2DiffSeg{"  ", string(ar[len(ar)-sfx:])})
			}
		}
		gOps = nil
	}
	prevAEnd, prevBEnd := 0, 0
	for i, o := range ops {
		om, _ := o.(map[string]any)
		op := rawOp{
			kind: strOf(om["kind"]),
			aOff: num(om["a_offset"]), aLen: num(om["a_len"]),
			bOff: num(om["b_offset"]), bLen: num(om["b_len"]),
		}
		if len(gOps) == 0 {
			// Defensive: a gap between the previous group and this op is
			// uncovered bytes; emit it so reconstruction still holds.
			if op.aOff > prevAEnd && op.aOff <= len(a) {
				gap := repair(a[prevAEnd:op.aOff])
				bGap := ""
				if prevBEnd <= op.bOff && op.bOff <= len(b) {
					bGap = repair(b[prevBEnd:op.bOff])
				}
				if gap != "" && gap == bGap {
					segs = append(segs, ui2DiffSeg{"  ", gap})
				} else {
					if gap != "" {
						segs = append(segs, ui2DiffSeg{"- ", gap})
					}
					if bGap != "" {
						segs = append(segs, ui2DiffSeg{"+ ", bGap})
					}
				}
			}
			gAStart, gBStart = op.aOff, op.bOff
		}
		gOps = append(gOps, op)
		gAEnd, gBEnd = op.aOff+op.aLen, op.bOff+op.bLen
		// Close the group when the boundary to the next op is rune-aligned on
		// both sides (or the stream ends or jumps discontiguously).
		last := i == len(ops)-1
		if last || ((runeAligned(a, gAEnd) && runeAligned(b, gBEnd)) || boundaryJumps(ops, i, gAEnd, gBEnd, num)) {
			prevAEnd, prevBEnd = gAEnd, gBEnd
			flush()
		}
	}
	flush()
	// Defensive: bytes past the last op are uncovered; emit rather than drop.
	if prevAEnd < len(a) || prevBEnd < len(b) {
		aTail, bTail := "", ""
		if prevAEnd <= len(a) {
			aTail = repair(a[prevAEnd:])
		}
		if prevBEnd <= len(b) {
			bTail = repair(b[prevBEnd:])
		}
		if aTail != "" && aTail == bTail {
			segs = append(segs, ui2DiffSeg{"  ", aTail})
		} else {
			if aTail != "" {
				segs = append(segs, ui2DiffSeg{"- ", aTail})
			}
			if bTail != "" {
				segs = append(segs, ui2DiffSeg{"+ ", bTail})
			}
		}
	}
	return segs, corruptRepaired
}

func boundaryJumps(ops []any, i, aEnd, bEnd int, num func(any) int) bool {
	om, _ := ops[i+1].(map[string]any)
	return num(om["a_offset"]) != aEnd || num(om["b_offset"]) != bEnd
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// ui2RenderCompare renders the compare ops against the two buffers as a readable
// line diff ("  " equal, "- " removed, "+ " added) — never a Go map dump.
// repaired reports that the handler already replaced invalid UTF-8 in the
// inputs; the disclosure is rendered, never silent.
func ui2RenderCompare(a, b string, result any, repaired bool) string {
	m, ok := result.(map[string]any)
	if !ok {
		return ""
	}
	var sb strings.Builder
	if id, _ := m["identical"].(bool); id {
		// identical after repair is not the same statement as identical: disclose.
		sb.WriteString("buffers are identical\n")
		if repaired {
			sb.WriteString("\u2026 identical only after invalid UTF-8 bytes in the input were replaced with \uFFFD\n")
		}
		return sb.String()
	}
	ops, _ := m["ops"].([]any)
	num := func(v any) int {
		f, _ := v.(float64)
		return int(f)
	}
	segs, corruptRepaired := ui2CompareSegs(a, b, ops)
	for _, seg := range segs {
		for i, line := range strings.Split(seg.text, "\n") {
			if i > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(seg.prefix + line)
		}
		sb.WriteByte('\n')
	}
	if n := num(m["ops_omitted"]); n > 0 {
		fmt.Fprintf(&sb, "\u2026 %d further ops omitted by the API\n", n)
	}
	if t, _ := m["truncated"].(bool); t {
		sb.WriteString("\u2026 alignment truncated by the diff engine limit - coarse replace shown, not a full alignment\n")
	}
	if corruptRepaired {
		sb.WriteString("\u2026 corrupt diff ops produced segments splitting a UTF-8 sequence - repaired with \uFFFD for display\n")
	}
	if repaired {
		sb.WriteString("\u2026 invalid UTF-8 bytes in the input were replaced with \uFFFD before comparing\n")
	}
	return sb.String()
}

// ---- Settings overview -----------------------------------------------------------------------

// handleUI2Settings serves GET /ui2/settings: project, stats, CA, protocols, pools,
// schedules, skills, wordlists — the read-only diagnostics surface.
func (s *Server) handleUI2Settings(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	get := func(path string, key string) {
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
		var v any
		_ = ui2DecodeJSON(rec.Body.Bytes(), &v)
		model[key] = v
	}
	get("/api/project", "project")
	get("/api/stats", "stats")
	get("/api/proxy/ca", "ca")
	get("/api/protocols", "protocols")
	get("/api/pools", "pools")
	get("/api/schedules", "schedules")
	get("/api/skills", "skills")
	get("/api/wordlists", "wordlists")
	get("/api/settings/triage", "triage")
	get("/api/network/auth", "netauth")
	get("/api/network/server-certificates", "certs")
	get("/api/browser/settings", "browser")
	get("/api/events/stats", "events")
	ui2Fragment(w, r, "burpsy /ui2/ — Settings", "settings", ui2Exec("settings.html", model))
}

// ---- small io/json helpers (kept here so the ui2 file set stays self-contained) ---------------

type templateHTML = templateHTMLAlias

// newReq builds an internal request for a fixed console path. Every call site passes a
// literal /api/... or /ui2/... path — never caller input — so no SSRF surface exists here.
func newReq(method, path string) *http.Request {
	// #nosec G704 -- path is a literal console path at every call site, never caller input.
	req, err := http.NewRequest(method, "http://console.invalid"+path, nil)
	if err != nil {
		// path is always a literal starting with '/', so this cannot fail; a non-nil request
		// keeps the caller simple.
		return &http.Request{Method: method, URL: &url.URL{Path: path}, Header: http.Header{}}
	}
	return req
}
func ui2DecodeJSON(b []byte, v any) error        { return ui2JSONUnmarshal(b, v) }
func ui2Marshal(v any) ([]byte, error)           { return ui2JSONMarshal(v) }
func ioNopCloser(r *strings.Reader) ioReadCloser { return ioReadCloser{r} }

var _ = core.ExchangeID(0)
