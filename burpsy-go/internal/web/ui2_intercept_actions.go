package web

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Intercept: options, annotation, bulk resolution, retarget, row actions ------------------

// ui2InterceptViewExtras adds what the full page shows beyond the queue: the newline
// corrections and the startup default (both read from their API rather than assumed), and per
// held message its URL plus, for a request, its curl command and
// quick-rule inputs.
func (s *Server) ui2InterceptViewExtras(view map[string]any) {
	if nl, errText := s.ui2APIResult(http.MethodGet, "/api/intercept/newline-correction", nil); errText == "" {
		view["newline"] = nl
	}
	if st, errText := s.ui2APIResult(http.MethodGet, "/api/intercept/startup", nil); errText == "" {
		if m, ok := st.(map[string]any); ok {
			view["startup_mode"] = m["mode"]
		}
	}
	view["startup_persisted"] = s.persist != nil
	held, _ := view["held"].([]any)
	for _, item := range held {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		dir, _ := m["direction"].(string)
		host, _ := m["host"].(string)
		path, _ := m["path"].(string)
		raw, _ := m["raw"].(string)
		tls, _ := m["tls"].(bool)
		port := 0
		if p, ok := m["port"].(float64); ok {
			port = int(p)
		}
		scheme := "http"
		if tls {
			scheme = "https"
		}
		m["scheme"] = scheme
		m["is_request"] = dir == "request"
		m["is_response"] = dir == "response"
		u := ui2HeldURL(scheme, host, port, path)
		m["url"] = u
		if dir == "request" {
			m["curl"] = ui2RawToCurl(raw, u)
			m["ext"] = ui2PathExtension(path)
		}
	}
}

// ui2HeldURL spells a held message's URL, omitting the scheme's default port.
func ui2HeldURL(scheme, host string, port int, path string) string {
	authority := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		authority = "[" + host + "]"
	}
	if port > 0 && !(scheme == "https" && port == 443) && !(scheme == "http" && port == 80) {
		authority += ":" + strconv.Itoa(port)
	}
	return scheme + "://" + authority + path
}

// ui2PathExtension is the final path segment's extension without the dot, query excluded:
// the value an "extension" rule is matched against.
func ui2PathExtension(path string) string {
	path, _, _ = strings.Cut(path, "?")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return ""
}

// ui2ShellQuote single-quotes one argument for a POSIX shell.
func ui2ShellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// ui2RawToCurl renders a raw request as a curl command line: method, URL, every header except
// Content-Length (curl computes it), and the body when there is one.
func ui2RawToCurl(raw, u string) string {
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, _ := strings.Cut(norm, "\n\n")
	lines := strings.Split(head, "\n")
	method := "GET"
	if f := strings.Fields(lines[0]); len(f) > 0 {
		method = f[0]
	}
	parts := []string{"curl -i -X " + ui2ShellQuote(method) + " " + ui2ShellQuote(u)}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.EqualFold(name, "content-length") {
			continue
		}
		parts = append(parts, "  -H "+ui2ShellQuote(name+": "+strings.TrimSpace(value)))
	}
	if strings.TrimSpace(body) != "" {
		parts = append(parts, "  --data-raw "+ui2ShellQuote(body))
	}
	return strings.Join(parts, " \\\n")
}

// ui2InterceptRender re-renders the queue fragment with an outcome note.
func (s *Server) ui2InterceptRender(w http.ResponseWriter, note string) {
	view := s.ui2InterceptView()
	view["note"] = note
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intercept.html", view)))
}

// ui2InterceptOptionAction handles the {action} values beyond resolve/enable: the in-scope
// filter, newline corrections, startup default, annotation and bulk forward/drop. All are
// riskLocal one-click writes; each answers the re-rendered queue with a note naming the outcome
// or the API's refusal. It reports false for an action it does not own.
func (s *Server) ui2InterceptOptionAction(w http.ResponseWriter, r *http.Request, action string) bool {
	switch {
	case action == "in-scope-on" || action == "in-scope-off":
		on := action == "in-scope-on"
		if _, errText := s.ui2APIResult(http.MethodPost, "/api/intercept/in-scope-only", map[string]bool{"in_scope_only": on}); errText != "" {
			s.ui2InterceptRender(w, "Not changed: "+errText)
			return true
		}
		note := "Only in-scope messages are held now."
		if !on {
			note = "Messages are held whether or not they are in scope."
		}
		if on && !s.intercept.ScopeAttached() {
			note += " No scope is attached, so the filter has nothing to compare against."
		}
		s.ui2InterceptRender(w, note)
	case action == "newline":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return true
		}
		body := map[string]bool{
			"add_missing_blank_line":                 r.PostForm.Get("add_missing_blank_line") == "on",
			"trim_trailing_newlines_urlencoded_body": r.PostForm.Get("trim_trailing_newlines_urlencoded_body") == "on",
		}
		if _, errText := s.ui2APIResult(http.MethodPut, "/api/intercept/newline-correction", body); errText != "" {
			s.ui2InterceptRender(w, "Not saved: "+errText)
			return true
		}
		s.ui2InterceptRender(w, "Newline corrections saved; they apply to edited forwards only.")
	case action == "startup":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return true
		}
		mode := r.PostForm.Get("mode")
		if _, errText := s.ui2APIResult(http.MethodPost, "/api/intercept/startup", map[string]string{"mode": mode}); errText != "" {
			s.ui2InterceptRender(w, "Not saved: "+errText)
			return true
		}
		s.ui2InterceptRender(w, "Startup interception set to "+mode+"; it applies at the next server start. The live switch is unchanged.")
	case strings.HasPrefix(action, "annotate-"):
		id, err := strconv.ParseUint(strings.TrimPrefix(action, "annotate-"), 10, 64)
		if err != nil {
			http.Error(w, "unknown intercept action", http.StatusBadRequest)
			return true
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return true
		}
		highlight := r.PostForm.Get("highlight")
		if highlight != "" && !core.ValidHighlights[highlight] {
			s.ui2InterceptRender(w, "Not annotated: unknown highlight "+strconv.Quote(highlight))
			return true
		}
		body := map[string]string{"comment": r.PostForm.Get("comment"), "highlight": highlight}
		if _, errText := s.ui2APIResult(http.MethodPost, "/api/intercept/annotate/"+strconv.FormatUint(id, 10), body); errText != "" {
			s.ui2InterceptRender(w, "Not annotated: "+errText)
			return true
		}
		s.ui2InterceptRender(w, "Annotation saved on held #"+strconv.FormatUint(id, 10)+"; it rides into HTTP history when the message is forwarded.")
	case action == "forward-checked" || action == "drop-checked":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return true
		}
		s.ui2InterceptRender(w, s.ui2InterceptBulk(r.PostForm["ids"], action == "forward-checked"))
	default:
		return false
	}
	return true
}

// ui2InterceptBulk forwards or drops the checked held messages one at a time and says what
// happened to each. A bulk forward sends the held bytes unedited, like Forward all: one
// item's edit buffer never rides under another id.
func (s *Server) ui2InterceptBulk(ids []string, forward bool) string {
	var ok, failed []string
	for _, idText := range ids {
		id, err := strconv.ParseUint(idText, 10, 64)
		if err != nil {
			failed = append(failed, strconv.Quote(idText))
			continue
		}
		label := "#" + strconv.FormatUint(id, 10)
		path, payload := "/api/intercept/"+strconv.FormatUint(id, 10)+"/drop", any(map[string]string{})
		if forward {
			path, payload = "/api/intercept/"+strconv.FormatUint(id, 10)+"/forward", map[string]bool{"fix_content_length": false}
		}
		if _, errText := s.ui2APIResult(http.MethodPost, path, payload); errText != "" {
			failed = append(failed, label)
			continue
		}
		ok = append(ok, label)
	}
	if len(ok)+len(failed) == 0 {
		return "No held message was checked."
	}
	verb := "Dropped"
	if forward {
		verb = "Forwarded"
	}
	note := verb + " " + strconv.Itoa(len(ok)) + " checked message(s)"
	if len(ok) > 0 {
		note += " (" + strings.Join(ok, ", ") + ")"
	}
	if len(failed) > 0 {
		note += "; not resolved (no longer held or refused): " + strings.Join(failed, ", ")
	}
	return note + "."
}

// ui2ForwardTargetFields adds the editor's destination and hold-response choices to a forward
// body. The destination is sent only when it differs from where the client asked, and then as
// all three of host, port and tls, the API's retarget contract. Returns a refusal message for a
// destination that cannot be sent.
func (s *Server) ui2ForwardTargetFields(id uint64, r *http.Request, fwd map[string]any) string {
	if r.PostForm.Get("hold_response") == "on" {
		fwd["hold_response"] = true
	}
	_, hasHost := r.PostForm["host"]
	_, hasPort := r.PostForm["port"]
	_, hasScheme := r.PostForm["scheme"]
	if !hasHost && !hasPort && !hasScheme {
		return ""
	}
	if !hasHost || !hasPort || !hasScheme {
		return "a destination needs host, port and scheme together"
	}
	host := strings.TrimSpace(r.PostForm.Get("host"))
	if host == "" {
		return "the destination host is empty"
	}
	port, err := strconv.ParseUint(strings.TrimSpace(r.PostForm.Get("port")), 10, 16)
	if err != nil || port == 0 {
		return "the destination port must be 1 to 65535"
	}
	scheme := r.PostForm.Get("scheme")
	if scheme != "http" && scheme != "https" {
		return "the destination scheme must be http or https"
	}
	for _, h := range s.intercept.Held() {
		if h.ID == id && h.Host == host && h.Port == uint16(port) && h.TLS == (scheme == "https") {
			return "" // unchanged: send it where the client asked
		}
	}
	fwd["host"] = host
	fwd["port"] = port
	fwd["tls"] = scheme == "https"
	return ""
}

// handleUI2InterceptSend serves GET /ui2/intercept/send?id=&to=repeater|comparer|decoder: the
// target tool's page seeded with one held message's bytes. It reads the hold and sends
// nothing; the message stays held.
func (s *Server) handleUI2InterceptSend(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fail := func(msg string) {
		ui2RenderPage(w, "burpsy /ui2/ — Intercept", "intercept", ui2Exec("error.html", ui2Error{Message: msg}))
	}
	id, err := strconv.ParseUint(q.Get("id"), 10, 64)
	if err != nil {
		fail("a held message id is required")
		return
	}
	var raw, target string
	found := false
	for _, h := range s.intercept.Held() {
		if h.ID != id {
			continue
		}
		raw, found = string(h.Raw), true
		scheme := "http"
		if h.TLS {
			scheme = "https"
		}
		host := h.Host
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		target = scheme + "://" + host + ":" + strconv.Itoa(int(h.Port))
	}
	idText := strconv.FormatUint(id, 10)
	if !found {
		fail("held message #" + idText + " is no longer held - it was forwarded or dropped")
		return
	}
	if !ui2TextareaSafe([]byte(raw)) {
		fail("held message #" + idText + " carries bytes a text editor cannot keep unchanged (invalid UTF-8 or NUL); nothing was loaded")
		return
	}
	notice := templateHTML(`<p class="meta">` + template.HTMLEscapeString("Loaded from held message #"+idText+" as an editable text copy. The message is still held on the Intercept page.") + `</p>`)
	switch q.Get("to") {
	case "repeater":
		ui2RenderPage(w, "burpsy /ui2/ — Repeater", "repeater", notice+ui2Exec("repeater.html", map[string]any{"draft": raw, "target": target, "result": nil}))
	case "comparer":
		ui2RenderPage(w, "burpsy /ui2/ — Comparer", "comparer", notice+ui2Exec("comparer.html", map[string]any{"a": raw, "result": nil}))
	case "decoder":
		ui2RenderPage(w, "burpsy /ui2/ — Decoder", "decoder", notice+ui2Exec("decoder.html", map[string]any{"input": raw, "op": "decode", "arg": "", "result": nil}))
	default:
		fail("unknown tool: choose repeater, comparer or decoder")
	}
}
