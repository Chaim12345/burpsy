package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- shared ui2 page rendering helpers -------------------------------------------------------

// ui2RenderPage renders the shell with the given view and fragment body.
func ui2RenderPage(w http.ResponseWriter, title, view string, body templateHTML) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var sb strings.Builder
	if err := ui2Templates.ExecuteTemplate(&sb, "layout.html", ui2Page{Title: title, View: view, Body: body}); err != nil {
		slog.Error("ui2 layout failed", "view", view, "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(sb.String()))
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

// ui2Exec renders one named template into a string. A template error is logged and the
// fragment becomes error.html: a half-rendered fragment would read as a page with data missing.
func ui2Exec(name string, model any) templateHTML {
	var sb strings.Builder
	if err := ui2Templates.ExecuteTemplate(&sb, name, model); err != nil {
		slog.Error("ui2 template failed", "template", name, "error", err)
		sb.Reset()
		if err := ui2Templates.ExecuteTemplate(&sb, "error.html", ui2Error{Message: "the " + name + " view could not be rendered; the server log has the cause"}); err != nil {
			return templateHTML("")
		}
	}
	return templateHTML(sb.String())
}

// ---- Dashboard: see ui2_dashboard.go ---------------------------------------------------------

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

// ---- Logger ----------------------------------------------------------------------------------

// ---- WS history ------------------------------------------------------------------------------

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
	s.ui2ProxyOverviewExtras(model)
	ui2Fragment(w, r, "burpsy /ui2/ — Proxy settings", "proxy", ui2Exec("proxy.html", model))
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
	if _, ok := config.(map[string]any); !ok {
		// An unreadable config (no scanner wired) must not abort the page mid-template:
		// field access on a nil interface is a template error, which ui2Exec now reports.
		config = map[string]any{}
	}
	model["config"] = config
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
		token, _, errText := s.ui2MintConfirm("/api/scanner/audit", http.MethodPost, "/api/scanner/audit", body)
		model["token"] = token
		// The FULL bound body, not ui2MintConfirm's 200-character abbreviation: the sheet says the
		// confirmation covers exactly this call (the scope and sequencer reviews' rule).
		model["preview"] = http.MethodPost + " /api/scanner/audit"
		model["full_body"] = string(body)
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
		model["audit_view"] = ui2AuditResultView(result)
		model["audit_error"] = errText
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Scanner", "scanner", ui2Exec("scanner.html", model))
}

// The engine and check-family configuration (config-confirm/config-run) lives in
// ui2_scanner_config.go with the rest of the scanner configuration surface.

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
		token, _, errText := s.ui2MintConfirm("/api/crawl", http.MethodPost, "/api/crawl", body)
		model["token"] = token
		// The FULL bound body: a long seed list ran past the 200-character preview cut.
		model["preview"] = http.MethodPost + " /api/crawl"
		model["full_body"] = string(body)
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
	ui2SessionViewRedact(model)
	return model
}

// ---- Tools: decoder / comparer ---------------------------------------------------------------

// ---- Repeater --------------------------------------------------------------------------------

// ui2HostFromRequest extracts the target authority from a raw request: an absolute-form
// request line wins, else the Host header. The scheme is kept on an absolute-form answer:
// targetParts reads it for TLS and the default port, and dropping it sent https request
// lines as plain http to port 80. Line endings are normalised first: an htmx form post
// delivers the textarea's value with LF newlines, not the CRLF a raw request file has.
func ui2HostFromRequest(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) >= 2 && strings.Contains(fields[1], "://") {
		scheme := fields[1][:strings.Index(fields[1], "://")+3]
		rest := fields[1][len(scheme):]
		// http is the default the parsers assume anyway, so only https is carried through;
		// anything else stays stripped and gets refused downstream as before.
		if !strings.EqualFold(scheme, "https://") {
			scheme = ""
		}
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return scheme + rest[:j]
		}
		return scheme + rest
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

func strOf(v any) string {
	s, _ := v.(string)
	return s
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
