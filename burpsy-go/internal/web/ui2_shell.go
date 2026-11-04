package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ---- ui2 shell: status bar, File menu (exports, config import), Project menu ------------------
//
// The menus themselves are static <details> dropdowns in nav.html; the routes here are the
// sheets they open. Every write follows the ui2 review discipline: rename is riskLocal and
// one-click, while config import (riskScope), save copy and project open (riskDestructive) mint
// a gate confirmation for the exact call, show the full bound body, and the run step rebuilds
// that body from the same function so an edited hidden field is refused by the gate.

// ui2CSP is the policy for every server-rendered console page. Scripts come only from this
// origin (htmx.min.js, app.js: no inline script, no eval - htmx-config turns allowEval off).
// style-src keeps 'unsafe-inline' because the layout carries its stylesheet inline and
// templates use style attributes; no script capability rides on that.
const ui2CSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; " +
	"frame-ancestors 'none'; object-src 'none'"

// ui2SecurityHeaders sets the console's page headers. Called for every /ui2/ route and the
// "/" console root.
func ui2SecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", ui2CSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// ---- status bar -------------------------------------------------------------------------------

// handleUI2ShellStatus serves GET /ui2/shell/status: the status bar's data segment. app.js
// fetches it on load, on change frames and on a slow timer; the stream state and last-event
// time are client-side facts and live beside it in the layout.
func (s *Server) handleUI2ShellStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("shell_status.html", s.ui2ShellStatusModel())))
}

func (s *Server) ui2ShellStatusModel() map[string]any {
	m := map[string]any{}
	if res, errText := s.ui2APIResult(http.MethodGet, "/api/stats", nil); errText == "" {
		if st, ok := res.(map[string]any); ok {
			m["exchanges"] = st["exchanges"]
			m["messages"] = st["messages"]
			m["proxy_bind"] = st["proxy_bind"]
			if b, ok := st["stored_bytes"].(float64); ok {
				m["stored"] = ui2HumanBytes(int64(b))
			}
		}
	} else {
		m["stats_error"] = ui2APIErrorText(errText)
	}
	m["scope"] = s.ui2ScopeSummary()
	ca := s.caStatus()
	m["ca_configured"] = ca.Configured
	m["ca_subject"] = ca.Subject
	m["ca_not_after"] = ca.NotAfter
	return m
}

// ui2ScopeSummary renders the scope as one status-bar phrase from GET /api/scope.
func (s *Server) ui2ScopeSummary() string {
	res, errText := s.ui2APIResult(http.MethodGet, "/api/scope", nil)
	if errText != "" {
		return "unreadable"
	}
	m, _ := res.(map[string]any)
	rules, _ := m["rules"].([]any)
	inc, exc, off := 0, 0, 0
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		if on, _ := rule["enabled"].(bool); !on {
			off++
			continue
		}
		if rule["kind"] == "Exclude" {
			exc++
		} else {
			inc++
		}
	}
	var out string
	if inc == 0 {
		out = "no include rules (everything in scope)"
	} else {
		out = fmt.Sprintf("%d include", inc)
	}
	if exc > 0 {
		out += fmt.Sprintf(", %d exclude", exc)
	}
	if off > 0 {
		out += fmt.Sprintf(", %d disabled", off)
	}
	if drop, _ := m["drop_out_of_scope"].(bool); drop {
		out += " · dropping out-of-scope"
	}
	return out
}

func ui2HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---- Project menu ------------------------------------------------------------------------------

// handleUI2ShellProject serves GET /ui2/shell/project: the project file, rename, save copy and
// the open/create/switch list.
func (s *Server) handleUI2ShellProject(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy — Project", "project", ui2Exec("shell_project.html", s.ui2ProjectModel()))
}

func (s *Server) ui2ProjectModel() map[string]any {
	m := map[string]any{"project": s.projectView()}
	if res, errText := s.ui2APIResult(http.MethodGet, "/api/projects", nil); errText == "" {
		m["projects"] = res
	} else {
		m["projects_error"] = ui2APIErrorText(errText)
	}
	return m
}

// handleUI2ShellProjectAction serves POST /ui2/shell/project/{action}.
func (s *Server) handleUI2ShellProjectAction(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch r.PathValue("action") {
	case "rename":
		m := s.ui2ProjectModel()
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			m["error"] = "a project name cannot be blank"
		} else if _, errText := s.ui2APIResult(http.MethodPut, "/api/project/name", map[string]any{"name": name}); errText != "" {
			m["error"] = ui2APIErrorText(errText)
		} else {
			m = s.ui2ProjectModel()
			m["done"] = "Project renamed to " + name + "."
		}
		_, _ = w.Write([]byte(ui2Exec("shell_project.html", m)))
	case "backup-confirm":
		m := map[string]any{"op": "backup", "project": s.projectView()}
		if s.persist == nil || s.persist.Path() == "" {
			m["error"] = "this instance has no project database, so there is nothing to copy; start burpsy with -db"
		} else {
			dir := filepath.Dir(s.persist.Path())
			existing := ui2CountBackups(dir)
			m["dir"] = dir
			m["retention"] = defaultBackupRetention
			m["existing"] = existing
			m["prunes"] = max(existing+1-defaultBackupRetention, 0)
			token, _, errText := s.ui2MintConfirm("/api/backup", http.MethodPost, "/api/backup", nil)
			m["token"], m["error"] = token, errText
			m["preview"] = "POST /api/backup — no body (defaults: beside the live database, default retention)"
		}
		_, _ = w.Write([]byte(ui2Exec("shell_project_confirm.html", m)))
	case "backup-run":
		m := s.ui2ProjectModel()
		res, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/backup", nil, r.PostFormValue("token"))
		if errText != "" {
			m["error"] = "Save copy refused: " + ui2APIErrorText(errText)
		} else {
			m["backup"] = res
		}
		_, _ = w.Write([]byte(ui2Exec("shell_project.html", m)))
	case "open-confirm":
		m := map[string]any{"op": "open", "project": s.projectView()}
		payload, errText := ui2ProjectOpenPayload(r)
		if errText == "" {
			target := payload["path"].(string)
			resolved, err := s.resolveProjectPath(target)
			if err != nil {
				errText = err.Error()
			} else {
				m["path"] = target
				m["resolved"] = resolved
				m["already_open"] = s.persist != nil && sameFile(s.persist.Path(), resolved)
				_, statErr := os.Stat(resolved)
				m["creates"] = os.IsNotExist(statErr)
				body, _ := ui2Marshal(payload)
				token, _, mintErr := s.ui2MintConfirm("/api/project/open", http.MethodPost, "/api/project/open", body)
				m["token"], errText = token, mintErr
				m["preview"] = "POST /api/project/open — body " + string(body)
			}
		}
		m["error"] = errText
		_, _ = w.Write([]byte(ui2Exec("shell_project_confirm.html", m)))
	case "open-run":
		payload, errText := ui2ProjectOpenPayload(r)
		var res any
		if errText == "" {
			res, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/project/open", payload, r.PostFormValue("token"))
		}
		m := s.ui2ProjectModel()
		if errText != "" {
			m["error"] = "Project switch refused: " + ui2ProjectRefusalText(errText)
		} else {
			m["switched"] = res
		}
		_, _ = w.Write([]byte(ui2Exec("shell_project.html", m)))
	default:
		http.Error(w, "unknown project action", http.StatusNotFound)
	}
}

// ui2ProjectOpenPayload is the one builder of the /api/project/open body, shared by the review
// and run steps so the run cannot dispatch a body other than the one reviewed.
func ui2ProjectOpenPayload(r *http.Request) (map[string]any, string) {
	p := strings.TrimSpace(r.PostFormValue("path"))
	if p == "" {
		return nil, "a project file path is required"
	}
	return map[string]any{"path": p}, ""
}

// ui2ProjectRefusalText reads the switch route's {reason, remedy} refusal shape as well as the
// generic API error shape.
func ui2ProjectRefusalText(errText string) string {
	var ref projectSwitchRefuse
	if err := json.Unmarshal([]byte(errText), &ref); err == nil && ref.Reason != "" {
		if ref.Remedy != "" {
			return ref.Reason + " — " + ref.Remedy
		}
		return ref.Reason
	}
	return ui2APIErrorText(errText)
}

func ui2CountBackups(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && backupFilePattern.MatchString(e.Name()) {
			n++
		}
	}
	return n
}

// ---- File menu: exports and configuration import ------------------------------------------------

// handleUI2ShellConfig serves GET /ui2/shell/config: report and configuration exports, the CA
// download, and the configuration import form.
func (s *Server) handleUI2ShellConfig(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy — Import / export", "config", ui2Exec("shell_config.html", s.ui2ConfigModel()))
}

func (s *Server) ui2ConfigModel() map[string]any {
	return map[string]any{
		"coverage":      exportCoverage(),
		"ca_configured": s.caStatus().Configured,
	}
}

// ui2ConfigSection is one row of the import review and result sheets.
type ui2ConfigSection struct {
	Name   string
	Detail string
}

// ui2ConfigImportPayload parses the pasted bundle into the canonical payload both steps send,
// and describes which sections it replaces and which it leaves untouched.
func ui2ConfigImportPayload(r *http.Request) (payload map[string]any, applied, untouched []ui2ConfigSection, errText string) {
	raw := strings.TrimSpace(r.PostFormValue("bundle"))
	if raw == "" {
		return nil, nil, nil, "paste or choose a configuration bundle (the JSON File > Export configuration downloads)"
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload == nil {
		return nil, nil, nil, "the bundle is not a JSON object"
	}
	var b configBundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, nil, nil, "the bundle does not have the configuration bundle shape: " + err.Error()
	}
	add := func(present bool, name, detail string) {
		if present {
			applied = append(applied, ui2ConfigSection{name, detail})
		} else {
			untouched = append(untouched, ui2ConfigSection{name, "absent from the bundle — left as it is"})
		}
	}
	scopeN := 0
	if b.Scope != nil {
		scopeN = len(b.Scope.Rules)
	}
	add(b.Scope != nil, "scope", fmt.Sprintf("replaced by %d rule(s)", scopeN))
	dirs := make([]string, 0, len(b.Intercept))
	for name, st := range b.Intercept {
		dirs = append(dirs, fmt.Sprintf("%s: %d rule(s), active=%t", name, len(st.Rules), st.Active))
	}
	sort.Strings(dirs)
	add(len(b.Intercept) > 0, "intercept", "replaced for "+strings.Join(dirs, "; "))
	add(b.SessionRules != nil, "session_rules", fmt.Sprintf("replaced by %d rule(s)", len(b.SessionRules)))
	uh := ""
	if b.UninterestingHeaders != nil {
		uh = fmt.Sprintf("replaced: %d request, %d response header name(s)",
			len(b.UninterestingHeaders.Request), len(b.UninterestingHeaders.Response))
	}
	add(b.UninterestingHeaders != nil, "uninteresting_headers", uh)
	if len(applied) == 0 {
		return nil, nil, nil, "the bundle carries none of the importable sections (scope, intercept, session_rules, uninteresting_headers)"
	}
	return payload, applied, untouched, ""
}

// handleUI2ShellConfigAction serves POST /ui2/shell/config/{action}: import-confirm renders the
// review (the sections replaced, those left untouched, and the full bound body); import-run
// spends the token and renders the result sheet.
func (s *Server) handleUI2ShellConfigAction(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	m := s.ui2ConfigModel()
	payload, applied, untouched, errText := ui2ConfigImportPayload(r)
	m["applied"], m["untouched"] = applied, untouched
	switch r.PathValue("action") {
	case "import-confirm":
		if errText == "" {
			body, _ := ui2Marshal(payload)
			token, _, mintErr := s.ui2MintConfirm("/api/config/import", http.MethodPost, "/api/config/import", body)
			m["token"], errText = token, mintErr
			m["bundle"] = string(body)
			m["preview"] = "POST /api/config/import — body " + string(body)
		}
		m["error"] = errText
		_, _ = w.Write([]byte(ui2Exec("shell_config_confirm.html", m)))
	case "import-run":
		var res any
		if errText == "" {
			res, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/config/import", payload, r.PostFormValue("token"))
		}
		if errText != "" {
			m["error"] = "Import refused, nothing was applied: " + ui2APIErrorText(errText)
			m["applied"], m["untouched"] = nil, nil
		} else {
			m["result"] = res
		}
		_, _ = w.Write([]byte(ui2Exec("shell_config.html", m)))
	default:
		http.Error(w, "unknown configuration action", http.StatusNotFound)
	}
}
