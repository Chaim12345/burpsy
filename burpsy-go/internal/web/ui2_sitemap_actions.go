package web

// ui2 site-map row actions (burpsy /ui2/ lane D1).
//
// The site map was the last read-only target view: the React tree's right-click menu can add a
// row to the target scope and seed Repeater from a row, while the /ui2/ table rendered the same
// rows with no way to act on them. This file closes exactly those two actions, no more:
//
//   - Add to scope: POST /ui2/sitemap/scope/confirm resolves the row's node from a FRESH
//     server-side tree (the form carries only the node's key, never host/port/path fields a
//     client could edit), mints a one-time confirmation for the exact /api/scope include call
//     and renders the review sheet; POST /ui2/sitemap/scope/run spends the token on the
//     reviewed call. The minted body is rebuilt from the sheet's hidden fields at run time, so
//     a tampered field fails the token digest and burns it - and a site map that drifts after
//     the review changes nothing: the rule the operator read is the rule that runs, which the
//     sheet says out loud. No traffic is sent by either step; the rule persists.
//   - Send to Repeater: GET /ui2/sitemap/repeater?key= loads the newest stored request under
//     the row into the Repeater editor as an editable draft. This sends nothing - the operator
//     still presses Send on the Repeater page, and the draft is the stored bytes as editable
//     text, never a byte-exact replay claim. Rows with no captured exchange, a request-less
//     tunnel, or bytes a textarea cannot carry unchanged get a named refusal instead of a
//     silently empty or corrupted editor.
//
// Both steps reuse the proven ui2 confirm gate (ui2MintConfirm / ui2DispatchConfirmed, the
// scope page's own flow) rather than inventing a second review mechanism.

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- shared resolution helpers ---------------------------------------------------------------

// ui2SitemapSnapshot reads the live site map through the JSON handler's own view builder, the
// same way renderUI2Sitemap does, so a row action and the page it came from can never disagree
// about what the map holds.
func (s *Server) ui2SitemapSnapshot() (*sitemapTreeResp, string) {
	rec := newRecorder()
	s.sitemapGet(rec, newReq(http.MethodGet, "/api/sitemap"))
	var tree sitemapTreeResp
	if err := ui2DecodeJSON(rec.Body.Bytes(), &tree); err != nil {
		return nil, "site map unavailable: " + err.Error()
	}
	return &tree, ""
}

// ui2SitemapFindNode returns the tree node with exactly this key and the host it sits under.
// The key is the node's stated identity (nodeKey: scheme://host:port, plus NUL + path for a
// path node), so a lookup never re-parses it into a second host/path grammar that could drift
// from the first. The host is read off the tree instead: every top-level row is a host row
// whose Path IS the host (observed, inserted and unrequested builders all set it), so the host
// of any node is its top-level ancestor's Path - server state, not client-supplied fields, and
// not the node's HostName field, which is json:"-" and empty for observed rows.
func ui2SitemapFindNode(nodes []sitemapNodeView, key string) (*sitemapNodeView, string) {
	var found *sitemapNodeView
	host := ""
	var walk func(ns []sitemapNodeView, top string) bool
	walk = func(ns []sitemapNodeView, top string) bool {
		for i := range ns {
			t := top
			if t == "" {
				t = ns[i].Path
			}
			if ns[i].Key == key {
				found = &ns[i]
				host = t
				return true
			}
			if walk(ns[i].Children, t) {
				return true
			}
		}
		return false
	}
	walk(nodes, "")
	return found, host
}

// ui2SitemapNewestExchange names the newest captured exchange under a node: a path node's
// Recent holds its own latest exchanges, and a folder or host row's newest is the newest of
// anything beneath it. Each node's Recent keeps that path's last 20 exchanges, and a path's
// newest exchange is always inside its own last 20, so the subtree maximum is exact.
func ui2SitemapNewestExchange(n *sitemapNodeView) (core.ExchangeID, bool) {
	var best core.ExchangeID
	found := false
	var walk func(v *sitemapNodeView)
	walk = func(v *sitemapNodeView) {
		for _, id := range v.Recent {
			if !found || id > best {
				best = id
				found = true
			}
		}
		for i := range v.Children {
			walk(&v.Children[i])
		}
	}
	walk(n)
	return best, found
}

// ui2SitemapNodeLabel is how the review sheets and refusals name a row: the host for a host
// row, host + path for a path row.
func ui2SitemapNodeLabel(n *sitemapNodeView, host string) string {
	if strings.Contains(n.Key, "\x00") {
		return host + n.Path
	}
	return host
}

// ui2SitemapFields is the run step's form contract, mirroring the organizer's
// ui2WorkflowFields: every permitted field exactly once, nothing else, and no query fields -
// a run that answers to smuggled fields is how a reviewed call becomes a different call.
func ui2SitemapFields(r *http.Request, keys ...string) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("invalid form")
	}
	if len(r.URL.Query()) != 0 {
		return fmt.Errorf("query fields are not permitted here")
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
		if len(r.PostForm[k]) != 1 {
			return fmt.Errorf("%s must be a single permitted field", k)
		}
	}
	for k, v := range r.PostForm {
		if !allowed[k] || len(v) != 1 {
			return fmt.Errorf("%s is not a single permitted field", k)
		}
	}
	return nil
}

// ---- Add to scope ----------------------------------------------------------------------------

// handleUI2SitemapScope routes POST /ui2/sitemap/scope/{action}: confirm renders the review
// step, run spends the reviewed call. The first click never changes the scope.
func (s *Server) handleUI2SitemapScope(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.PathValue("action") {
	case "run":
		s.ui2SitemapScopeRun(w, r)
	case "confirm":
		s.ui2SitemapScopeConfirm(w, r)
	default:
		s.ui2SitemapScopeSheet(w, map[string]any{"error": "unknown site-map scope action"})
	}
}

// ui2SitemapScopeSheet renders the review fragment (which is also how a refusal is shown).
func (s *Server) ui2SitemapScopeSheet(w http.ResponseWriter, model map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("sitemap_action_confirm.html", model)))
}

// ui2SitemapScopeConfirm resolves the row's node from server state and mints the confirmation
// for the exact include call. The form carries the row key in the post URL's query (a NUL-
// carrying key cannot cross a form field unchanged, and only the key crosses at all): every
// identity fact in the minted call - host, port, scheme, path prefix - is read off the node
// the key names NOW, never off client-supplied fields. A row that vanished since the page
// loaded is a named refusal, not a rule aimed at a re-parsed guess.
func (s *Server) ui2SitemapScopeConfirm(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) { s.ui2SitemapScopeSheet(w, map[string]any{"error": msg}) }
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 0 {
		fail("a site-map row action carries no form fields - use the row's own button")
		return
	}
	q := r.URL.Query()
	if len(q) != 1 || len(q["key"]) != 1 {
		fail("exactly one site-map row key is required")
		return
	}
	tree, errText := s.ui2SitemapSnapshot()
	if errText != "" {
		fail(errText)
		return
	}
	node, host := ui2SitemapFindNode(tree.Tree, q.Get("key"))
	if node == nil {
		fail("that site-map row is gone - the map changed since the page loaded; reload the site map and choose again")
		return
	}
	if host == "" || node.Port == 0 {
		fail("the row's host and port could not be resolved from the live map - reload the site map and choose again")
		return
	}
	protocol := "http"
	if node.TLS {
		protocol = "https"
	}
	payload := map[string]any{
		"action":   "include",
		"pattern":  host,
		"port":     node.Port,
		"protocol": protocol,
	}
	pathPrefix := ""
	if strings.Contains(node.Key, "\x00") {
		// A path row scopes its subtree: the rule's path arm is a literal prefix
		// (core.ScopeRule.PathPrefix), which is what "this branch of the map" means.
		payload["path"] = node.Path
		pathPrefix = node.Path
	}
	body, _ := ui2Marshal(payload)
	token, preview, mintErr := s.ui2MintConfirm("/api/scope", http.MethodPost, "/api/scope", body)
	s.ui2SitemapScopeSheet(w, map[string]any{
		"node":     ui2SitemapNodeLabel(node, host),
		"pattern":  host,
		"port":     strconv.Itoa(int(node.Port)),
		"protocol": protocol,
		"path":     pathPrefix,
		"inscope":  node.InScope,
		"preview":  preview,
		"token":    token,
		"error":    mintErr,
	})
}

// ui2SitemapScopeRun spends the confirmation on the exact reviewed call and re-renders the
// rows with the outcome. The body is rebuilt from the sheet's hidden fields and validated
// field by field; the token digest refuses anything that no longer matches what was minted,
// and the API's own refusals (a duplicate tuple, an unreadable arm) render as the note.
func (s *Server) ui2SitemapScopeRun(w http.ResponseWriter, r *http.Request) {
	note := ""
	done := ""
	payload, errText := ui2SitemapScopePayload(r)
	if errText != "" {
		note = errText
	} else {
		_, dispatchErr := s.ui2DispatchConfirmed(http.MethodPost, "/api/scope", payload, r.PostFormValue("token"))
		if dispatchErr != "" {
			note = dispatchErr
		} else {
			done = ui2SitemapScopeDoneNote(payload)
		}
	}
	s.ui2SitemapRows(w, note, done)
}

// ui2SitemapScopePayload rebuilds the reviewed include call from the sheet's hidden fields.
func ui2SitemapScopePayload(r *http.Request) (map[string]any, string) {
	if err := ui2SitemapFields(r, "token", "pattern", "port", "protocol", "path"); err != nil {
		return nil, err.Error()
	}
	pattern := strings.TrimSpace(r.PostFormValue("pattern"))
	if pattern == "" {
		return nil, "the reviewed rule has no host pattern - review again"
	}
	payload := map[string]any{"action": "include", "pattern": pattern}
	if p := strings.TrimSpace(r.PostFormValue("port")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, "port must be 1-65535"
		}
		payload["port"] = n
	}
	if p := strings.TrimSpace(r.PostFormValue("protocol")); p != "" {
		if p != "http" && p != "https" {
			return nil, "protocol must be http or https"
		}
		payload["protocol"] = p
	}
	if p := r.PostFormValue("path"); p != "" {
		payload["path"] = p
	}
	return payload, ""
}

// ui2SitemapScopeDoneNote states the landed rule in the run's own words, because the API's
// success view is the whole scope, not the one rule this review was about.
func ui2SitemapScopeDoneNote(payload map[string]any) string {
	rule := fmt.Sprintf("host %s, port %v, %s only", payload["pattern"], payload["port"], payload["protocol"])
	if p, ok := payload["path"].(string); ok && p != "" {
		rule += ", path prefix " + p
	}
	return "Scope rule added: " + rule + ". No traffic was sent; the proxy and tools may now reach it."
}

// ui2SitemapRows re-renders the table fragment with the outcome line. The note is a refusal
// the operator must read; the done line is the landed fact.
func (s *Server) ui2SitemapRows(w http.ResponseWriter, note, done string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tree, errText := s.ui2SitemapSnapshot()
	if errText != "" {
		_, _ = w.Write([]byte(ui2Exec("error.html", ui2Error{Message: errText})))
		return
	}
	model := s.ui2SitemapTreeModel(tree, ui2SitemapFilter{}, "")
	model.Note, model.Done = note, done
	_, _ = w.Write([]byte(ui2Exec("sitemap.html", model)))
}

// ---- Send to Repeater ------------------------------------------------------------------------

// handleUI2SitemapRepeater serves GET /ui2/sitemap/repeater?key=: the Repeater editor with the
// newest stored request under the row loaded as the draft. Loading a draft sends nothing; the
// send stays on the Repeater page's own reviewed path (/ui2/repeater/send), which is unchanged.
// Every failure is named - a gone row, an empty branch, a request-less tunnel, or bytes a text
// editor cannot carry unchanged - because an editor that opens empty or corrupted reads as
// "nothing was captured", the lie this surface exists to avoid.
func (s *Server) handleUI2SitemapRepeater(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fail := func(msg string) {
		ui2RenderPage(w, "burpsy /ui2/ — Site map", "sitemap", ui2Exec("error.html", ui2Error{Message: msg}))
	}
	q := r.URL.Query()
	if len(q) != 1 || len(q["key"]) != 1 {
		fail("exactly one site-map row key is required")
		return
	}
	tree, errText := s.ui2SitemapSnapshot()
	if errText != "" {
		fail(errText)
		return
	}
	node, host := ui2SitemapFindNode(tree.Tree, q.Get("key"))
	if node == nil {
		fail("that site-map row is gone - reload the site map and choose again")
		return
	}
	id, ok := ui2SitemapNewestExchange(node)
	if !ok {
		fail("nothing has been captured under " + ui2SitemapNodeLabel(node, host) + " yet - there is no stored request to load into Repeater")
		return
	}
	var ex *core.Exchange
	for _, e := range s.store.Exchanges() {
		if e.ID == id {
			ex = e
			break
		}
	}
	if ex == nil {
		fail(fmt.Sprintf("exchange #%d is no longer in the store - reload the site map", uint64(id)))
		return
	}
	if ex.Request == nil {
		fail(fmt.Sprintf("exchange #%d has no stored request - a blind tunnel cannot seed Repeater", uint64(id)))
		return
	}
	msg, err := s.store.Get(*ex.Request)
	if err != nil {
		fail(fmt.Sprintf("the stored request for exchange #%d is unavailable: %v", uint64(id), err))
		return
	}
	raw := msg.Raw()
	if !ui2TextareaSafe(raw) {
		fail(fmt.Sprintf("the stored request for exchange #%d carries bytes a text editor cannot keep unchanged (invalid UTF-8 or NUL) - use the console's binary-safe view instead; nothing was loaded", uint64(id)))
		return
	}
	// The notice is composition, not a template change: the Repeater fragment stays byte-
	// identical and the page states what loading a stored draft means where the operator reads it.
	notice := fmt.Sprintf("Draft loaded from stored exchange #%d under %s. This is an editable text copy of the stored request - sending happens from the editor and is not a byte-exact replay of the capture.",
		uint64(id), ui2SitemapNodeLabel(node, host))
	body := templateHTML(`<p class="meta">`+template.HTMLEscapeString(notice)+`</p>`) +
		ui2Exec("repeater.html", map[string]any{"draft": string(raw), "result": nil})
	ui2RenderPage(w, "burpsy /ui2/ — Repeater", "repeater", body)
}
