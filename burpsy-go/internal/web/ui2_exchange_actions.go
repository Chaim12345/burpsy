package web

// ui2 single-exchange actions and the detached exchange page (burpsy /ui2/ unit 3).
//
// The SPA's shared exchange context menu (ui/src/lib/actions.ts) is one menu offered by History,
// Logger and the site map. Here it is one server-rendered fragment, GET /ui2/exchange/{id}/menu,
// loaded lazily by those surfaces and embedded in the detached page GET /ui2/exchange/{id}.
//
// Writes, by the risk class of the API route each one reaches:
//   - riskLocal (annotate, add to Organizer, record an issue) and riskEgress (open the URL in the
//     burpsy browser): one deliberate POST from the menu, dispatched on the internal mux.
//   - riskScope / riskAttack (add host to scope, audit, crawl branch/host): the confirm step builds
//     the exact call from the stored exchange, mints a one-time gate token and shows the FULL bound
//     body; the run step rebuilds the body with the same function and spends the token through the
//     guarded chain. The run form carries the token alone, so nothing typed after the review can
//     change the call - a changed body fails the token's digest.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ui2HighlightOrder is the menu's colour order, the SPA's HIGHLIGHTS minus its "none" sentinel.
var ui2HighlightOrder = []string{"red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"}

// ---- URL and command generation (ported from lib/actions.ts) -------------------------------

// ui2ExchangeScheme reads the scheme from the TLS flag; the wire's protocol is the HTTP version.
func ui2ExchangeScheme(tls bool) string {
	if tls {
		return "https"
	}
	return "http"
}

// ui2HostPort joins host and port, bracketing an IPv6 literal.
func ui2HostPort(host string, port uint16) string {
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(int(port)))
}

// ui2ExchangeURL is exchangeUrl: the default port is omitted from the authority.
func ui2ExchangeURL(ex *core.Exchange) string {
	scheme := ui2ExchangeScheme(ex.TLS)
	authority := ui2HostPort(ex.Host, ex.Port)
	if (scheme == "https" && ex.Port == 443) || (scheme == "http" && ex.Port == 80) {
		authority = strings.Trim(ex.Host, "[]")
		if strings.Contains(authority, ":") {
			authority = "[" + authority + "]"
		}
	}
	return scheme + "://" + authority + ex.Path
}

// ui2ExchangeTarget is the scheme://host:port target the Repeater/Sequencer APIs take.
func ui2ExchangeTarget(ex *core.Exchange) string {
	return ui2ExchangeScheme(ex.TLS) + "://" + ui2HostPort(ex.Host, ex.Port)
}

// ui2ShellQuote single-quotes s for a POSIX shell; an embedded ' closes, escapes and reopens.
// Single quotes, not the SPA's JSON.stringify double quotes: inside double quotes a shell still
// expands $(...) and backticks, so a captured header could run a command on paste.
func ui2ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ui2ShellWord leaves a plain token bare and quotes anything else.
func ui2ShellWord(s string) string {
	if s == "" {
		return ui2ShellQuote(s)
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return ui2ShellQuote(s)
		}
	}
	return s
}

// ui2SplitRequest splits a raw request into its method, header lines and body.
func ui2SplitRequest(raw string) (method string, headers []string, body string) {
	head := raw
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head, body = raw[:i], raw[i+4:]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, body = raw[:i], raw[i+2:]
	}
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	method = "GET"
	if f := strings.Fields(lines[0]); len(f) > 0 {
		method = f[0]
	}
	return method, lines[1:], body
}

// ui2HeaderLine splits "Name: value" into its trimmed parts; ok is false for a line with no name.
func ui2HeaderLine(line string) (name, value string, ok bool) {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:colon]), strings.TrimSpace(line[colon+1:]), true
}

// ui2RawToCurl is rawToCurl with POSIX quoting: every captured value is single-quoted.
func ui2RawToCurl(raw, u string) string {
	method, headers, body := ui2SplitRequest(raw)
	parts := []string{"curl -i -X " + ui2ShellWord(method) + " " + ui2ShellQuote(u)}
	for _, line := range headers {
		name, value, ok := ui2HeaderLine(line)
		if !ok || strings.EqualFold(name, "content-length") {
			continue
		}
		parts = append(parts, "  -H "+ui2ShellQuote(name+": "+value))
	}
	if strings.TrimSpace(body) != "" {
		parts = append(parts, "  --data-raw "+ui2ShellQuote(body))
	}
	return strings.Join(parts, " \\\n")
}

// ui2RawToSqlmap is rawToSqlmap: Host and Content-Length are left to sqlmap, and --method is
// only spelled out when sqlmap would not infer it (GET, or POST with a body).
func ui2RawToSqlmap(raw, u string) string {
	method, headers, body := ui2SplitRequest(raw)
	parts := []string{"sqlmap -u " + ui2ShellQuote(u)}
	if method != "GET" && (method != "POST" || body == "") {
		parts = append(parts, "  --method="+ui2ShellWord(method))
	}
	for _, line := range headers {
		name, value, ok := ui2HeaderLine(line)
		if !ok || strings.EqualFold(name, "host") || strings.EqualFold(name, "content-length") {
			continue
		}
		parts = append(parts, "  -H "+ui2ShellQuote(name+": "+value))
	}
	if strings.TrimSpace(body) != "" {
		parts = append(parts, "  --data="+ui2ShellQuote(body))
	}
	parts = append(parts, "  --batch")
	return strings.Join(parts, " \\\n")
}

// ui2QueryString quotes s as a burpsy query DSL string literal.
func ui2QueryString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`, "\r", `\r`)
	return `"` + r.Replace(s) + `"`
}

// ui2CrawlRetention is crawlFrom's retention query: the host, or the branch's directory with its
// trailing slash (a bare "/v2" prefix would also keep "/v22").
func ui2CrawlRetention(ex *core.Exchange, branch bool) string {
	if !branch {
		return "host = " + ui2QueryString(ex.Host)
	}
	p := ex.Path
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return "path ~ " + ui2QueryString(p+"/")
}

// ---- models ------------------------------------------------------------------------------------

// ui2ExchangeMenu is the actions menu for one exchange.
type ui2ExchangeMenu struct {
	ID          uint64
	Method      string
	Host        string
	Port        uint16
	Path        string
	URL         string
	HasRequest  bool
	MsgID       uint64
	HasResponse bool
	Curl        string
	Sqlmap      string
	CopyNote    string // why curl/sqlmap are not offered, "" when they are
	Highlight   string
	Notes       string
	Colours     []string
}

// ui2ExchangeView is the detached exchange page.
type ui2ExchangeView struct {
	Menu        ui2ExchangeMenu
	Status      string
	Mime        string
	ResponseLen int
	DurationMs  uint64
	Request     string
	Response    string
	ReqPane     ui2PaneView
	RespPane    ui2PaneView
	ReqPretty   bool
	RespPretty  bool
	ReqHeaders  []ui2KV
	RespHeaders []ui2KV
	Query       []ui2KV
	BodyParams  []ui2KV
	BodyNote    string
	Cookies     []ui2KV
	SetCookies  []ui2KV
	// Outcome is an action's result when the page answers a non-htmx form post.
	Outcome map[string]any
}

// ui2ExchangeLoad parses the path id and reads the exchange and its request bytes.
func (s *Server) ui2ExchangeLoad(r *http.Request) (*core.Exchange, []byte, string) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, nil, "exchange id must be a whole number"
	}
	ex, err := s.store.GetExchange(core.ExchangeID(id))
	if err != nil || ex == nil {
		return nil, nil, fmt.Sprintf("no exchange #%d has been captured", id)
	}
	return ex, requestMessageForExchange(s.store, ex), ""
}

func (s *Server) ui2ExchangeMenuModel(ex *core.Exchange, raw []byte) ui2ExchangeMenu {
	m := ui2ExchangeMenu{
		ID: uint64(ex.ID), Method: ex.Method, Host: ex.Host, Port: ex.Port, Path: ex.Path,
		URL: ui2ExchangeURL(ex), HasResponse: ex.Response != nil, Highlight: ex.Highlight,
		Colours: ui2HighlightOrder,
	}
	if ex.Notes != nil {
		m.Notes = *ex.Notes
	}
	switch {
	case ex.Request == nil || raw == nil:
		m.CopyNote = "This exchange has no request bytes - it is a blind tunnel - so there is no request to send to a tool or to turn into a command."
	case !ui2TextareaSafe(raw):
		m.HasRequest, m.MsgID = true, uint64(*ex.Request)
		m.CopyNote = "The request carries bytes a shell command cannot hold unchanged (invalid UTF-8 or NUL), so no curl or sqlmap command is offered."
	default:
		m.HasRequest, m.MsgID = true, uint64(*ex.Request)
		m.Curl = ui2RawToCurl(string(raw), m.URL)
		m.Sqlmap = ui2RawToSqlmap(string(raw), m.URL)
	}
	return m
}

// ---- GET routes ----------------------------------------------------------------------------------

// handleUI2ExchangeMenu serves GET /ui2/exchange/{id}/menu: the actions menu fragment.
func (s *Server) handleUI2ExchangeMenu(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ex, raw, errText := s.ui2ExchangeLoad(r)
	if errText != "" {
		ui2Fragment(w, r, "burpsy /ui2/ — Exchange", "exchange", ui2Exec("error.html", ui2Error{Message: errText}))
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Exchange actions", "exchange", ui2Exec("exchange_actions.html", s.ui2ExchangeMenuModel(ex, raw)))
}

// handleUI2ExchangePage serves GET /ui2/exchange/{id}: the detached exchange window.
func (s *Server) handleUI2ExchangePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ex, raw, errText := s.ui2ExchangeLoad(r)
	if errText != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		ui2Fragment(w, r, "burpsy /ui2/ — Exchange", "exchange", ui2Exec("error.html", ui2Error{Message: errText}))
		return
	}
	view := s.ui2ExchangePageModel(ex, raw, r.URL.Query().Get("view_req") != "raw", r.URL.Query().Get("view_resp") != "raw")
	ui2Fragment(w, r, fmt.Sprintf("burpsy /ui2/ — Exchange #%d", uint64(ex.ID)), "exchange", ui2Exec("exchange_page.html", view))
}

func (s *Server) ui2ExchangePageModel(ex *core.Exchange, raw []byte, reqPretty, respPretty bool) ui2ExchangeView {
	v := ui2ExchangeView{
		Menu: s.ui2ExchangeMenuModel(ex, raw), Status: ui2StatusString(ex.Status), Mime: ex.Mime,
		ReqPretty: reqPretty, RespPretty: respPretty,
	}
	ev := exchangeView(ex)
	v.ResponseLen, v.DurationMs = ev.ResponseLen, ev.DurationMs
	if raw != nil {
		v.Request = string(raw)
		var body []byte
		var ctype string
		v.ReqHeaders, body = ui2MessageHeaders(raw, core.DirectionRequest)
		for _, h := range v.ReqHeaders {
			switch strings.ToLower(h.Name) {
			case "cookie":
				v.Cookies = append(v.Cookies, ui2CookiePairs(h.Value)...)
			case "content-type":
				ctype = h.Value
			}
		}
		if shape, err := core.Parse(raw, core.DirectionRequest); err == nil {
			target := string(raw[shape.SecondToken.Offset : shape.SecondToken.Offset+shape.SecondToken.Len])
			if i := strings.IndexByte(target, '?'); i >= 0 {
				v.Query = ui2FormPairs(target[i+1:])
			}
		}
		v.BodyParams, v.BodyNote = ui2BodyParams(ctype, body)
	}
	if ex.Response != nil {
		if msg, err := s.store.Get(*ex.Response); err == nil {
			resp := msg.Raw()
			v.Response = string(resp)
			v.RespHeaders, _ = ui2MessageHeaders(resp, core.DirectionResponse)
			for _, h := range v.RespHeaders {
				if strings.EqualFold(h.Name, "set-cookie") {
					name, value, _ := strings.Cut(h.Value, "=")
					v.SetCookies = append(v.SetCookies, ui2KV{Name: strings.TrimSpace(name), Value: value})
				}
			}
		}
	}
	v.ReqPane = renderMessagePane(v.Request, true, reqPretty)
	v.RespPane = renderMessagePane(v.Response, false, respPretty)
	return v
}

// ui2MessageHeaders lists a message's headers in order and returns its body bytes.
func ui2MessageHeaders(raw []byte, dir core.Direction) ([]ui2KV, []byte) {
	shape, err := core.Parse(raw, dir)
	if err != nil {
		return nil, nil
	}
	out := make([]ui2KV, 0, len(shape.Headers))
	for _, h := range shape.Headers {
		out = append(out, ui2KV{
			Name:  string(raw[h.Name.Offset : h.Name.Offset+h.Name.Len]),
			Value: string(raw[h.Value.Offset : h.Value.Offset+h.Value.Len]),
		})
	}
	end := shape.Body.Offset + shape.Body.Len
	if shape.Body.Offset < 0 || end > len(raw) || shape.Body.Offset > end {
		return out, nil
	}
	return out, raw[shape.Body.Offset:end]
}

// ui2FormPairs splits a urlencoded string into decoded pairs; a value that does not decode is
// shown as recorded rather than dropped.
func ui2FormPairs(s string) []ui2KV {
	var out []ui2KV
	for _, part := range strings.Split(s, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		out = append(out, ui2KV{Name: name, Value: value})
	}
	return out
}

// ui2CookiePairs splits a Cookie header into its name=value pairs.
func ui2CookiePairs(header string) []ui2KV {
	var out []ui2KV
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		out = append(out, ui2KV{Name: name, Value: value})
	}
	return out
}

// ui2BodyParams reads a request body's parameters for the formats that have names: form
// urlencoding, multipart and a JSON object's top-level members. Anything else is named as
// unexamined rather than reported as parameterless.
func ui2BodyParams(ctype string, body []byte) ([]ui2KV, string) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, ""
	}
	mt, params, _ := mime.ParseMediaType(ctype)
	switch {
	case mt == "application/x-www-form-urlencoded":
		return ui2FormPairs(string(body)), ""
	case mt == "multipart/form-data" && params["boundary"] != "":
		var out []ui2KV
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			if fn := p.FileName(); fn != "" {
				out = append(out, ui2KV{Name: p.FormName(), Value: "(file " + fn + ")"})
			} else {
				b, _ := io.ReadAll(io.LimitReader(p, 4096))
				out = append(out, ui2KV{Name: p.FormName(), Value: string(b)})
			}
		}
		return out, ""
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(body, &obj); err != nil {
			return nil, "The JSON body is not an object, so it has no named top-level parameters."
		}
		out := make([]ui2KV, 0, len(obj))
		for k, v := range obj {
			out = append(out, ui2KV{Name: k, Value: string(v)})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, ""
	}
	return nil, "The body (" + ctype + ") is not in a name/value format this page reads; see the request pane."
}

// ---- POST /ui2/exchange/{id}/{action} -------------------------------------------------------------

// ui2ExchangeCall dispatches one riskLocal/riskEgress API call on the internal mux and accepts
// any 2xx (POST /api/issues/record answers 201). The error is the API's own refusal text.
func (s *Server) ui2ExchangeCall(method, path string, payload any) (any, string) {
	b, _ := ui2Marshal(payload)
	req := newReq(method, path)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(b)))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code < 200 || rec.Code > 299 {
		return nil, ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
	}
	var result any
	_ = ui2DecodeJSON(rec.Body.Bytes(), &result)
	return result, ""
}

// handleUI2ExchangeAction routes the menu's writes.
func (s *Server) handleUI2ExchangeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ex, _, errText := s.ui2ExchangeLoad(r)
	if errText != "" {
		ui2Fragment(w, r, "burpsy /ui2/ — Exchange", "exchange", ui2Exec("error.html", ui2Error{Message: errText}))
		return
	}
	action := r.PathValue("action")
	out := map[string]any{"id": uint64(ex.ID)}
	switch action {
	case "annotate":
		out["note"], out["done"] = s.ui2ExchangeAnnotate(r, ex)
	case "organizer":
		if err := ui2SitemapFields(r); err != nil {
			out["note"] = err.Error()
		} else if _, e := s.ui2ExchangeCall(http.MethodPost, "/api/tools/organizer", map[string]any{"exchange": uint64(ex.ID)}); e != "" {
			out["note"] = e
		} else {
			out["done"] = fmt.Sprintf("Exchange #%d added to Organizer.", uint64(ex.ID))
		}
	case "issue":
		out["note"], out["done"] = s.ui2ExchangeRecordIssue(r, ex)
	case "browser":
		if err := ui2SitemapFields(r); err != nil {
			out["note"] = err.Error()
		} else if _, e := s.ui2ExchangeCall(http.MethodPost, "/api/browser/launch", map[string]any{"url": ui2ExchangeURL(ex)}); e != "" {
			out["note"] = "The burpsy browser did not open: " + e
		} else {
			out["done"] = "Opened " + ui2ExchangeURL(ex) + " in the burpsy browser (proxied, so what you do there is captured)."
		}
	default:
		kind, step, ok := strings.Cut(action, ".")
		call, known := ui2ExchangeGatedCall(ex, kind)
		if !ok || !known || (step != "confirm" && step != "run") {
			out["note"] = "unknown exchange action"
			break
		}
		if step == "confirm" {
			s.ui2ExchangeReview(w, r, ex, kind, call)
			return
		}
		out["note"], out["done"] = s.ui2ExchangeGatedRun(r, call)
	}
	s.ui2ExchangeOutcome(w, r, ex, out)
}

// ui2ExchangeOutcome answers an action: the outcome fragment for htmx, or the whole detached page
// with the outcome on top for a plain form post.
func (s *Server) ui2ExchangeOutcome(w http.ResponseWriter, r *http.Request, ex *core.Exchange, out map[string]any) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("exchange_outcome.html", out)))
		return
	}
	// Re-read: the action may have changed the exchange's annotation.
	if fresh, err := s.store.GetExchange(ex.ID); err == nil && fresh != nil {
		ex = fresh
	}
	view := s.ui2ExchangePageModel(ex, requestMessageForExchange(s.store, ex), true, true)
	view.Outcome = out
	ui2RenderPage(w, fmt.Sprintf("burpsy /ui2/ — Exchange #%d", uint64(ex.ID)), "exchange", ui2Exec("exchange_page.html", view))
}

// ui2ExchangeAnnotate sets the highlight (one colour, or "none") or the comment (empty clears it):
// exactly one field per post, so a colour click can never also rewrite the comment.
func (s *Server) ui2ExchangeAnnotate(r *http.Request, ex *core.Exchange) (note, done string) {
	_ = r.ParseForm()
	_, hasHL := r.PostForm["highlight"]
	_, hasNotes := r.PostForm["notes"]
	var payload map[string]any
	switch {
	case hasHL && !hasNotes:
		if err := ui2SitemapFields(r, "highlight"); err != nil {
			return err.Error(), ""
		}
		colour := r.PostFormValue("highlight")
		if colour == "none" {
			colour = ""
		}
		if colour != "" && !core.ValidHighlights[colour] {
			return fmt.Sprintf("%q is not a highlight colour", colour), ""
		}
		payload = map[string]any{"highlight": colour}
		done = "Highlight cleared."
		if colour != "" {
			done = "Highlighted " + colour + "."
		}
	case hasNotes && !hasHL:
		if err := ui2SitemapFields(r, "notes"); err != nil {
			return err.Error(), ""
		}
		text := strings.TrimSpace(ui2NormalizeNewlines(r.PostFormValue("notes")))
		if text == "" {
			payload = map[string]any{"notes": nil}
			done = "Comment removed."
		} else {
			payload = map[string]any{"notes": text}
			done = "Comment saved."
		}
	default:
		return "send either a highlight or a comment", ""
	}
	if _, e := s.ui2ExchangeCall(http.MethodPatch, "/api/exchange/"+strconv.FormatUint(uint64(ex.ID), 10), payload); e != "" {
		return e, ""
	}
	return "", fmt.Sprintf("Exchange #%d: %s", uint64(ex.ID), done)
}

// ui2ExchangeRecordIssue posts Burp's "Record an issue" against this exchange.
func (s *Server) ui2ExchangeRecordIssue(r *http.Request, ex *core.Exchange) (note, done string) {
	if err := ui2SitemapFields(r, "name", "severity", "description"); err != nil {
		return err.Error(), ""
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		return "name the issue the way it should read in the report", ""
	}
	sev := r.PostFormValue("severity")
	switch sev {
	case "high", "medium", "low", "info":
	default:
		return "severity must be high, medium, low or info", ""
	}
	id := uint64(ex.ID)
	result, e := s.ui2ExchangeCall(http.MethodPost, "/api/issues/record", map[string]any{
		"name": name, "severity": sev, "exchange_id": id,
		"description": strings.TrimSpace(ui2NormalizeNewlines(r.PostFormValue("description"))),
	})
	if e != "" {
		return e, ""
	}
	if m, ok := result.(map[string]any); ok {
		if fid, ok := m["id"].(float64); ok {
			return "", fmt.Sprintf("Issue #%d recorded against exchange #%d.", uint64(fid), id)
		}
	}
	return "", fmt.Sprintf("Issue recorded against exchange #%d.", id)
}

// ui2GatedCall is one gated API call built from the stored exchange.
type ui2GatedCall struct {
	Title   string // what the review sheet calls the action
	Path    string // the exact API path
	Pattern string // the manifest pattern the gate mints for
	Payload map[string]any
	Effect  string // what running it does, stated on the sheet
}

// ui2ExchangeGatedCall builds the gated call for one kind. Confirm and run both call this, so the
// run's body is rebuilt from server state, never from the form.
func ui2ExchangeGatedCall(ex *core.Exchange, kind string) (ui2GatedCall, bool) {
	id := strconv.FormatUint(uint64(ex.ID), 10)
	switch kind {
	case "scope":
		// Port and protocol are bound, as the site map's add-to-scope does: the exchange names one
		// service, and a host-only rule would also admit every other port on that host.
		scheme := ui2ExchangeScheme(ex.TLS)
		return ui2GatedCall{
			Title: fmt.Sprintf("Add host %s (%s, port %d) to scope", ex.Host, scheme, ex.Port), Path: "/api/scope", Pattern: "/api/scope",
			Payload: map[string]any{"action": "include", "pattern": ex.Host, "port": ex.Port, "protocol": scheme},
			Effect:  "Adds an include rule for this host, port and protocol. Scope decides where the proxy and every tool may send traffic, and the change persists. No traffic is sent by adding it.",
		}, true
	case "audit":
		return ui2GatedCall{
			Title: "Actively audit exchange #" + id, Path: "/api/audit/" + id, Pattern: "/api/audit/",
			Payload: map[string]any{"async": true},
			Effect:  "Starts an active audit with the default configuration: the scanner sends attack probes to " + ex.Host + ". It runs as a task; follow it on the Dashboard.",
		}, true
	case "crawl-branch", "crawl-host":
		branch := kind == "crawl-branch"
		title := "Crawl this host"
		if branch {
			title = "Crawl this branch"
		}
		return ui2GatedCall{
			Title: title, Path: "/api/crawl", Pattern: "/api/crawl",
			Payload: map[string]any{"seeds": []string{ui2ExchangeURL(ex)}, "retention_query": ui2CrawlRetention(ex, branch)},
			Effect:  "Starts a crawl from this URL: the crawler sends its own requests to the target within the engagement scope, keeping what matches the retention query. It runs as a task.",
		}, true
	}
	return ui2GatedCall{}, false
}

// ui2ExchangeReview mints the gate token for the exact call and renders the review sheet with
// the full body the token is bound to.
func (s *Server) ui2ExchangeReview(w http.ResponseWriter, r *http.Request, ex *core.Exchange, kind string, call ui2GatedCall) {
	model := map[string]any{"id": uint64(ex.ID), "kind": kind, "title": call.Title, "effect": call.Effect,
		"method": http.MethodPost, "path": call.Path}
	if err := ui2SitemapFields(r); err != nil {
		model["error"] = err.Error()
	} else {
		body, _ := ui2Marshal(call.Payload)
		token, _, mintErr := s.ui2MintConfirm(call.Pattern, http.MethodPost, call.Path, body)
		if mintErr == "" && token == "" {
			mintErr = "the confirmation could not be minted"
		}
		model["body"], model["token"], model["error"] = string(body), token, mintErr
	}
	ui2Fragment(w, r, fmt.Sprintf("burpsy /ui2/ — Exchange #%d", uint64(ex.ID)), "exchange", ui2Exec("exchange_review.html", model))
}

// ui2ExchangeGatedRun spends the token on the rebuilt call.
func (s *Server) ui2ExchangeGatedRun(r *http.Request, call ui2GatedCall) (note, done string) {
	if err := ui2SitemapFields(r, "token"); err != nil {
		return err.Error(), ""
	}
	result, e := s.ui2DispatchConfirmed(http.MethodPost, call.Path, call.Payload, r.PostFormValue("token"))
	if e != "" {
		return ui2APIErrorText(e), ""
	}
	done = call.Title + ": done."
	if m, ok := result.(map[string]any); ok {
		if tid, ok := m["task_id"].(float64); ok {
			done = fmt.Sprintf("%s: started as task %d - follow it on the Dashboard.", call.Title, uint64(tid))
		}
	}
	return "", done
}

// ---- send-to seeds -----------------------------------------------------------------------------

// ui2MsgSeed is a stored request a tool page was asked to load (?msg_id=N).
type ui2MsgSeed struct {
	MsgID       uint64
	Raw         string
	Target      string // scheme://host:port of the exchange that owns the message, "" if none does
	ExchangeID  uint64
	HasExchange bool
	HostPort    string // host:port of the owning exchange, for forms that take the scheme separately
	TLS         bool
}

// ui2SeedFor reads an optional ?msg_id=N seed for a tool page. It returns the notice to show above
// the tool (empty when the query names no seed) and whether the seed is usable. needsText refuses
// bytes a textarea cannot carry unchanged, for tools that resend the edited text.
func (s *Server) ui2SeedFor(r *http.Request, tool string, needsText bool) (templateHTML, ui2MsgSeed, bool) {
	q := r.URL.Query()
	if !q.Has("msg_id") {
		return "", ui2MsgSeed{}, false
	}
	fail := func(msg string) (templateHTML, ui2MsgSeed, bool) {
		return ui2Exec("exchange_seed.html", map[string]any{"error": msg}), ui2MsgSeed{}, false
	}
	n, err := strconv.ParseUint(q.Get("msg_id"), 10, 64)
	if err != nil {
		return fail("msg_id must be a whole number; nothing was loaded")
	}
	msg, err := s.store.Get(core.MsgId(n))
	if err != nil || msg.Shape.Direction != core.DirectionRequest {
		return fail(fmt.Sprintf("message %d is not a stored request; nothing was loaded", n))
	}
	seed := ui2MsgSeed{MsgID: n, Raw: string(msg.Raw())}
	if needsText && !ui2TextareaSafe(msg.Raw()) {
		return fail(fmt.Sprintf("request message %d carries bytes a text editor cannot keep unchanged (invalid UTF-8 or NUL); nothing was loaded", n))
	}
	if ex, err := s.store.ExchangeByRequest(core.MsgId(n)); err == nil && ex != nil {
		seed.ExchangeID, seed.HasExchange, seed.Target = uint64(ex.ID), true, ui2ExchangeTarget(ex)
		seed.HostPort, seed.TLS = ui2HostPort(ex.Host, ex.Port), ex.TLS
	}
	return ui2Exec("exchange_seed.html", map[string]any{"tool": tool, "seed": seed}), seed, true
}

// ---- row entry points ----------------------------------------------------------------------------

// ActionsID is the newest exchange recorded at this site-map row itself, for its Actions link;
// ok is false for a row with none of its own (exchange 0 is a real id, hence the flag).
func (n ui2SitemapRow) ActionsID() (uint64, bool) {
	if len(n.Recent) == 0 {
		return 0, false
	}
	best := n.Recent[0]
	for _, id := range n.Recent {
		if id > best {
			best = id
		}
	}
	return best, true
}

// HasActions reports whether the row has an exchange of its own to act on.
func (n ui2SitemapRow) HasActions() bool { _, ok := n.ActionsID(); return ok }

// ActionsExchange is ActionsID's id alone, for the template.
func (n ui2SitemapRow) ActionsExchange() uint64 { id, _ := n.ActionsID(); return id }

// ui2ExchangeIDs converts a node's recent exchange ids for the flattened site-map row.
func ui2ExchangeIDs(ids []core.ExchangeID) []uint64 {
	out := make([]uint64, len(ids))
	for i, id := range ids {
		out[i] = uint64(id)
	}
	return out
}
