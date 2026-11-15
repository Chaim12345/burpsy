package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/proxy"
)

// ---- Proxy settings editors: listeners, options, history logging, match & replace ------------
//
// Every write is a two-step reviewed call, the settings-write shape (ui2_settings_write.go): the
// confirm step builds the EXACT API call from the form, holds it server-side, and renders a
// review whose projection is the held bytes; the run step spends the entry (LoadAndDelete),
// compares the token in constant time, re-reads the state the call overwrites and refuses on
// drift, then dispatches the held call verbatim. Whether the call needs the confirmation gate is
// derived from the API route's risk class: a gated route gets a gate-minted token and runs
// through the guarded chain; an ungated (riskLocal) route gets a ui2-local one-use handle and
// runs through the internal mux. Today every route here is riskLocal.

const ui2ProxyReviewCap = 8

type ui2ProxyReview struct {
	area     string
	token    string
	gated    bool
	method   string
	callURL  string
	body     []byte
	snap     func(*Server) (string, error)
	snapshot string
	driftMsg string
	expires  time.Time
}

// ui2ProxyCall is what a per-area parser produces: the exact call plus its review copy.
type ui2ProxyCall struct {
	area         string
	method       string
	callURL      string
	body         []byte
	title        string
	consequences []string
	snap         func(*Server) (string, error) // state the call overwrites; nil when absolute
	snapshot     string                        // that state as the parser read and checked it
	driftMsg     string
	wrap         bool // the review is the whole #rows page, not the review slot's content
}

// ui2ProxyNeedsGate derives the gate requirement from the API route's manifest risk class. An
// unknown route fails closed (gated): its mint then fails and the review is refused.
func ui2ProxyNeedsGate(callURL string) bool {
	path := callURL
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	_, risk, ok := routeRiskFor(path)
	return !ok || needsConfirmation(risk)
}

// ui2ProxyCanonicalField reads one console GET and returns the canonical JSON of one top-level
// field: counters and traffic-driven figures sit beside the state and must not read as drift.
func (s *Server) ui2ProxyCanonicalField(path, field string) (string, error) {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, path))
	if rec.Code != http.StatusOK {
		return "", fmt.Errorf("reading %s answered %d", path, rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		return "", fmt.Errorf("reading %s: %v", path, err)
	}
	b, err := json.Marshal(m[field])
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ui2ProxySnap(path, field string) func(*Server) (string, error) {
	return func(s *Server) (string, error) { return s.ui2ProxyCanonicalField(path, field) }
}

// ui2ProxyRenderers re-render an area's page after a run (or a refusal), with a note.
var ui2ProxyRenderers = map[string]func(*Server, http.ResponseWriter, *http.Request, ui2ProxyNote){
	"listeners":     (*Server).renderUI2ProxyListeners,
	"options":       (*Server).renderUI2ProxyOptions,
	"match-replace": (*Server).renderUI2MatchReplaceSaved,
}

type ui2ProxyNote struct {
	OK    string
	Error string
}

// ui2ProxyReviewFail renders a refusal into the review slot.
func ui2ProxyReviewFail(w http.ResponseWriter, r *http.Request, view, msg string) {
	ui2Fragment(w, r, "burpsy /ui2/ — Proxy", view, ui2Exec("proxy_review.html", map[string]any{"error": msg}))
}

// ui2ProxyReviewMu makes sweep, cap check, same-area replacement and store one step, so two
// concurrent confirms cannot both pass the cap.
var ui2ProxyReviewMu sync.Mutex

// ui2ProxyHold sweeps expired entries, drops this area's earlier unspent review (the page shows
// one review slot, so a re-review replaces it), and reserves the new one unless the map is full.
func (s *Server) ui2ProxyHold(id string, e ui2ProxyReview) bool {
	ui2ProxyReviewMu.Lock()
	defer ui2ProxyReviewMu.Unlock()
	now := time.Now()
	count := 0
	s.ui2ProxyReviews.Range(func(k, v any) bool {
		if old, ok := v.(ui2ProxyReview); ok && (now.After(old.expires) || old.area == e.area) {
			s.ui2ProxyReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2ProxyReviewCap {
		return false
	}
	s.ui2ProxyReviews.Store(id, e)
	return true
}

// ui2ProxyArm sets the token on a reserved entry, unless a newer review replaced it meanwhile.
func (s *Server) ui2ProxyArm(id string, e ui2ProxyReview) bool {
	ui2ProxyReviewMu.Lock()
	defer ui2ProxyReviewMu.Unlock()
	if _, ok := s.ui2ProxyReviews.Load(id); !ok {
		return false
	}
	s.ui2ProxyReviews.Store(id, e)
	return true
}

// ui2ProxyConfirm holds one call for review and renders the review sheet.
func (s *Server) ui2ProxyConfirm(w http.ResponseWriter, r *http.Request, view string, call ui2ProxyCall) {
	fail := func(msg string) { ui2ProxyReviewFail(w, r, view, msg) }
	snapshot := call.snapshot
	if call.snap != nil && snapshot == "" {
		snap, err := call.snap(s)
		if err != nil {
			fail("could not read the current state to review against: " + err.Error())
			return
		}
		snapshot = snap
	}
	id, err := randomHex(16)
	if err != nil {
		fail("review id: " + err.Error())
		return
	}
	entry := ui2ProxyReview{
		area: call.area, method: call.method, callURL: call.callURL,
		body: call.body, snap: call.snap, snapshot: snapshot, driftMsg: call.driftMsg,
		expires: time.Now().Add(ConfirmTTL),
	}
	// Reserve the slot before any gate token exists, so a full map never strands a minted token.
	// The reserved entry has no token, so it cannot be spent until it is armed below.
	if !s.ui2ProxyHold(id, entry) {
		fail("too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	gated := ui2ProxyNeedsGate(call.callURL)
	token := ""
	if gated {
		path := call.callURL
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		tok, _, errText := s.ui2MintConfirm(path, call.method, call.callURL, call.body)
		if errText != "" || tok == "" {
			s.ui2ProxyReviews.Delete(id)
			fail("the confirmation gate refused to mint a review - try again")
			return
		}
		token = tok
	} else {
		local, err := randomHex(16)
		if err != nil {
			s.ui2ProxyReviews.Delete(id)
			fail("review token: " + err.Error())
			return
		}
		token = local
	}
	entry.token, entry.gated = token, gated
	if !s.ui2ProxyArm(id, entry) {
		fail("this review was replaced by a newer one on the same page - review again")
		return
	}
	// The projection is the held bytes, pretty-printed: what the run dispatches, in full.
	projection := call.method + " " + call.callURL
	if call.body != nil {
		var v any
		if json.Unmarshal(call.body, &v) == nil {
			if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
				projection += "\n" + string(pretty)
			} else {
				projection += "\n" + string(call.body)
			}
		} else {
			projection += "\n" + string(call.body)
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Proxy", view, ui2Exec("proxy_review.html", map[string]any{
		"area":         call.area,
		"title":        call.title,
		"review_id":    id,
		"token":        token,
		"gated":        gated,
		"projection":   projection,
		"consequences": call.consequences,
		"snapshotted":  call.snap != nil,
		"wrap":         call.wrap,
	}))
}

// ui2ProxyRun spends a held review and dispatches it, then re-renders the area's page.
func (s *Server) ui2ProxyRun(w http.ResponseWriter, r *http.Request, area string) {
	render := ui2ProxyRenderers[area]
	_ = r.ParseForm()
	v, ok := s.ui2ProxyReviews.LoadAndDelete(r.PostFormValue("review_id"))
	entry, isReview := v.(ui2ProxyReview)
	fail := func(msg string) {
		// A failed Match & Replace save keeps the held draft on screen: the body is the whole set
		// the operator built, and reloading the saved set would throw that work away.
		var set matchReplaceSetSpec
		if area == "match-replace" && isReview && entry.area == area && json.Unmarshal(entry.body, &set) == nil {
			s.renderUI2MatchReplace(w, r, ui2MRDraft{Set: set, Baseline: entry.snapshot, Dir: "request"},
				ui2ProxyNote{Error: msg + " Your draft is shown below, unsaved."}, nil)
			return
		}
		render(s, w, r, ui2ProxyNote{Error: msg})
	}
	if !ok || !isReview || entry.area != area || entry.token == "" {
		fail("that review is unknown or was already used - review the change again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired with the confirmation window - review the change again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostFormValue("token"))) != 1 {
		fail("that review does not match this confirmation - review the change again")
		return
	}
	if entry.snap != nil {
		now, err := entry.snap(s)
		if err != nil {
			fail("could not re-read the current state to confirm against: " + err.Error())
			return
		}
		if now != entry.snapshot {
			fail(entry.driftMsg)
			return
		}
	}
	req := newReq(entry.method, entry.callURL)
	if entry.body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	}
	rec := newRecorder()
	if entry.gated {
		req.Header.Set(ConfirmHeader, entry.token)
		req.Host = "127.0.0.1"
		req.Header.Set("Origin", "http://127.0.0.1")
		s.guarded.ServeHTTP(rec, req)
	} else {
		s.mux.ServeHTTP(rec, req)
	}
	if rec.Code/100 != 2 {
		fail("the API refused the change: " + truncateForDisplay(strings.TrimSpace(rec.Body.String()), 300))
		return
	}
	render(s, w, r, ui2ProxyNote{OK: "Saved: " + entry.method + " " + entry.callURL + " answered " + strconv.Itoa(rec.Code) + "."})
}

// ---- overview extras (/ui2/proxy) ------------------------------------------------------------

// ui2ProxyOverviewExtras adds the counters table and the history-logging mode to the overview.
func (s *Server) ui2ProxyOverviewExtras(model map[string]any) {
	opts, _ := model["options"].(map[string]any)
	model["counter_rows"] = ui2ProxyCounterRows(opts)
	if res, errText := s.ui2APIResult(http.MethodGet, "/api/proxy/history-logging", nil); errText == "" {
		if m, ok := res.(map[string]any); ok {
			model["history_logging"] = m["mode"]
		}
	}
}

type ui2ProxyCounterRow struct {
	Key, Label, Detail, Value string
}

var ui2ProxyCounterLabels = []struct{ key, label, detail string }{
	{"responses_considered", "Considered", "responses an enabled response rule looked at"},
	{"responses_modified", "Modified", "responses a rule rewrote"},
	{"responses_modified_unrecorded", "Modified, not recorded", "rewritten, but scope kept them out of history"},
	{"responses_unchanged", "Unchanged", "rules looked and found nothing to rewrite"},
	{"skipped_compressed", "Skipped: compressed", "turn on Unpack compressed responses to reach gzip, deflate, br and zstd"},
	{"skipped_unsupported_encoding", "Skipped: unsupported encoding", "unpacking on, but a chain or a corrupt body"},
	{"skipped_not_html", "Skipped: not HTML", ""},
	{"skipped_unframed", "Skipped: unframed", "no header/body separator or unparseable chunking"},
	{"unpacked_responses", "Unpacked: responses", "actually decompressed"},
	{"unpacked_requests", "Unpacked: requests", "actually decompressed"},
	{"accept_encoding_stripped", "Accept-Encoding stripped from requests", ""},
	{"dechunked", "Responses dechunked before rule matching", ""},
	{"relayed_http2", "HTTP/2 responses relayed without rewriting", ""},
	{"exchanges_dropped_out_of_scope", "Out-of-scope exchanges not logged", ""},
}

// ui2ProxyCounterRows renders every outcome counter; a counter this table does not name is
// still listed by its wire key, so nothing the engine counts is hidden.
func ui2ProxyCounterRows(opts map[string]any) []ui2ProxyCounterRow {
	counters, _ := opts["counters"].(map[string]any)
	if counters == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []ui2ProxyCounterRow
	for _, c := range ui2ProxyCounterLabels {
		seen[c.key] = true
		if v, ok := counters[c.key]; ok {
			out = append(out, ui2ProxyCounterRow{Key: c.key, Label: c.label, Detail: c.detail, Value: ui2ProxyNum(v)})
		}
	}
	var extra []string
	for k := range counters {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, ui2ProxyCounterRow{Key: k, Label: k, Value: ui2ProxyNum(counters[k])})
	}
	return out
}

func ui2ProxyNum(v any) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// ---- listeners -------------------------------------------------------------------------------

func (s *Server) handleUI2ProxyListeners(w http.ResponseWriter, r *http.Request) {
	s.renderUI2ProxyListeners(w, r, ui2ProxyNote{})
}

func (s *Server) renderUI2ProxyListeners(w http.ResponseWriter, r *http.Request, note ui2ProxyNote) {
	model := map[string]any{"note": note}
	globalInvisible := false
	if _, flags, ok := s.ui2ProxyLiveOptions(); ok {
		globalInvisible = flags["invisible_proxy"]
	}
	model["global_invisible"] = globalInvisible
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/proxy/listener"))
	var view proxyListenerView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil {
		msg := ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
		if msg == "" {
			msg = "the listener list could not be read"
		}
		model["unwired"] = msg
	} else {
		rows := make([]ui2ListenerView, 0, len(view.Listeners))
		for _, l := range view.Listeners {
			v := ui2ListenerView{Row: l, Invisible: "inherit", HTTP2: l.SupportHTTP2 == nil || *l.SupportHTTP2}
			if l.Invisible != nil {
				v.Invisible = map[bool]string{true: "on", false: "off"}[*l.Invisible]
			}
			v.Effective = globalInvisible
			if l.Invisible != nil {
				v.Effective = *l.Invisible
			}
			if l.RedirectHost != "" || l.RedirectPort != 0 {
				host, port := l.RedirectHost, "(client's port)"
				if host == "" {
					host = "(client's host)"
				}
				if l.RedirectPort != 0 {
					port = strconv.Itoa(int(l.RedirectPort))
				}
				v.Redirect = host + ":" + port
			}
			v.Form = ui2ListenerForm{Bind: l.Bind, RedirectHost: l.RedirectHost, Invisible: v.Invisible, ForceTLS: l.ForceTLS, HTTP2: v.HTTP2}
			if l.RedirectPort != 0 {
				v.Form.RedirectPort = strconv.Itoa(int(l.RedirectPort))
			}
			rows = append(rows, v)
		}
		model["rows"] = rows
		model["add_form"] = ui2ListenerForm{Invisible: "inherit", HTTP2: true}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Proxy listeners", "proxy-listeners", ui2Exec("proxy_listeners.html", model))
}

// ui2ListenerView is one listener row as the editor renders it.
type ui2ListenerView struct {
	Row       proxyListenerRow
	Invisible string // inherit | on | off
	Effective bool   // invisible proxying in force, inheritance resolved
	HTTP2     bool
	Redirect  string
	Form      ui2ListenerForm
}

// ui2ListenerForm prefills the add/edit fields.
type ui2ListenerForm struct {
	Bind, RedirectHost, RedirectPort, Invisible string
	ForceTLS, HTTP2                             bool
}

func (s *Server) handleUI2ProxyListenersAction(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		_ = r.ParseForm()
		call, msg := s.ui2ParseListenerCall(r)
		if msg != "" {
			ui2ProxyReviewFail(w, r, "proxy-listeners", msg)
			return
		}
		s.ui2ProxyConfirm(w, r, "proxy-listeners", call)
	case "run":
		s.ui2ProxyRun(w, r, "listeners")
	default:
		http.Error(w, "unknown listener action", http.StatusNotFound)
	}
}

var ui2ListenerIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ui2ProxyListenerWire is the exact POST / PUT ?id= body, in the field order the API documents.
type ui2ProxyListenerWire struct {
	Bind         string `json:"bind"`
	RedirectHost string `json:"redirect_host"`
	RedirectPort int    `json:"redirect_port"`
	ForceTLS     bool   `json:"force_tls"`
	Invisible    *bool  `json:"invisible"`
	SupportHTTP2 *bool  `json:"support_http2,omitempty"`
}

// ui2ListenerRows reads the live listener list (id -> row) and, from the same read, the
// canonical drift snapshot the review holds (the generic "listeners" field ui2ProxySnap reads).
func (s *Server) ui2ListenerRows() (map[string]proxyListenerRow, string, bool) {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/proxy/listener"))
	var view proxyListenerView
	var generic map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil ||
		json.Unmarshal(rec.Body.Bytes(), &generic) != nil {
		return nil, "", false
	}
	snap, err := json.Marshal(generic["listeners"])
	if err != nil {
		return nil, "", false
	}
	out := make(map[string]proxyListenerRow, len(view.Listeners))
	for _, l := range view.Listeners {
		out[l.ID] = l
	}
	return out, string(snap), true
}

func (s *Server) ui2ParseListenerCall(r *http.Request) (ui2ProxyCall, string) {
	c := ui2ProxyCall{
		area:     "listeners",
		title:    "Proxy listener",
		snap:     ui2ProxySnap("/api/proxy/listener", "listeners"),
		driftMsg: "the listeners changed between your review and this confirmation - review the current listeners and save again",
	}
	rows, snap, ok := s.ui2ListenerRows()
	if !ok {
		return c, "no proxy server is attached, so there are no listeners to change"
	}
	c.snapshot = snap
	op := r.PostFormValue("op")
	id := strings.TrimSpace(r.PostFormValue("id"))
	if op == "edit" || op == "remove" {
		if !ui2ListenerIDPattern.MatchString(id) {
			return c, "that is not a listener id"
		}
		row, found := rows[id]
		if !found {
			return c, "no listener " + id + " is serving - the page may be stale; reload it"
		}
		if op == "remove" {
			if !row.Removable {
				return c, "listener " + id + " is the one -proxy-bind opened: it can be re-bound but not removed"
			}
			c.method = http.MethodDelete
			c.callURL = "/api/proxy/listener?id=" + url.QueryEscape(id)
			c.consequences = []string{
				"Listener " + id + " (" + row.BoundAddr + ") stops accepting connections immediately; exchanges it is already relaying run to completion.",
			}
			return c, ""
		}
	}
	if op != "add" && op != "edit" {
		return c, "unknown listener operation"
	}
	body := ui2ProxyListenerWire{
		Bind:         strings.TrimSpace(r.PostFormValue("bind")),
		RedirectHost: strings.TrimSpace(r.PostFormValue("redirect_host")),
		ForceTLS:     r.PostFormValue("force_tls") != "",
	}
	if p := strings.TrimSpace(r.PostFormValue("redirect_port")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return c, "the redirect port must be a number between 0 and 65535; leave it blank to keep the client's port"
		}
		body.RedirectPort = n
	}
	switch r.PostFormValue("invisible") {
	case "", "inherit":
	case "on":
		t := true
		body.Invisible = &t
	case "off":
		f := false
		body.Invisible = &f
	default:
		return c, "invisible proxying must be inherit, on or off"
	}
	if r.PostFormValue("support_http2") == "" {
		f := false
		body.SupportHTTP2 = &f
	}
	// Validate with the API's own spec check so a bad value is refused at review, not at run.
	port := body.RedirectPort
	if _, err := specFromBody(proxyListenerBody{
		Bind: body.Bind, RedirectHost: body.RedirectHost, RedirectPort: &port,
		ForceTLS: &body.ForceTLS, Invisible: body.Invisible, SupportHTTP2: body.SupportHTTP2,
	}); err != nil {
		return c, err.Error()
	}
	c.body, _ = json.Marshal(body)
	if op == "add" {
		c.method = http.MethodPost
		c.callURL = "/api/proxy/listener"
		c.consequences = append(c.consequences, "A new listener opens on "+body.Bind+" as soon as you confirm. A bind that fails adds nothing and you will see the reason.")
	} else {
		c.method = http.MethodPut
		c.callURL = "/api/proxy/listener?id=" + url.QueryEscape(id)
		c.consequences = append(c.consequences, "Listener "+id+" is replaced with these settings. A changed bind opens the new socket before closing the old one, so a failed move leaves it serving where it was.")
	}
	if body.RedirectHost != "" || body.RedirectPort != 0 {
		c.consequences = append(c.consequences, "Every request this listener accepts is sent to the redirect target instead of the host/port the client named; the Host header is not rewritten.")
	}
	if body.ForceTLS {
		c.consequences = append(c.consequences, "The leg to the destination uses TLS whatever the client used.")
	}
	c.consequences = append(c.consequences, "Not persisted: a restart reverts to the single listener -proxy-bind names.")
	return c, ""
}

// ---- options + history logging ---------------------------------------------------------------

type ui2ProxyOptionDef struct{ key, label, detail string }

var ui2ProxyOptionGroups = []struct {
	title string
	opts  []ui2ProxyOptionDef
}{
	{"Response modification", []ui2ProxyOptionDef{
		{"unhide_hidden_form_fields", "Unhide hidden form fields", `Rewrite type="hidden" inputs to type="text".`},
		{"enable_disabled_form_fields", "Enable disabled form fields", "Remove the disabled attribute from form controls."},
		{"remove_input_field_length_limits", "Remove input field length limits", "Remove maxlength from inputs and textareas."},
		{"remove_object_tags", "Remove object tags", "Strip <object> elements and everything inside them."},
		{"remove_javascript_form_validation", "Remove JavaScript form validation", "Remove onsubmit/onreset handlers."},
		{"remove_all_javascript", "Remove all JavaScript", "Remove <script> elements, inline on* handlers and javascript: hrefs."},
		{"convert_https_links_to_http", "Convert HTTPS links to HTTP", "Rewrite https:// to http:// in href, src and action values."},
		{"remove_secure_flag_from_cookies", "Remove secure flag from cookies", "Remove Secure from Set-Cookie headers (every response, any body)."},
		{"strip_accept_encoding", "Strip Accept-Encoding from requests", "Ask the origin for an uncompressed response."},
		{"unpack_compressed_requests", "Unpack compressed requests", "Decompress gzip/deflate/br/zstd request bodies before forwarding."},
		{"unpack_compressed_responses", "Unpack compressed responses", "Decompress gzip/deflate/br/zstd response bodies so rules can rewrite them."},
	}},
	{"Transport", []ui2ProxyOptionDef{
		{"strip_sec_websocket_extensions", "Strip Sec-WebSocket-Extensions from handshakes", "Frames are captured uncompressed; applies from the next handshake."},
		{"dont_log_out_of_scope", "Don't log out-of-scope traffic", "Forwarded as usual, only the history record is dropped (counted)."},
		{"invisible_proxy", "Support invisible proxying", "Accept origin-form requests addressed only by Host; the default for listeners set to inherit."},
		{"strip_proxy_headers", "Strip Proxy-* headers from requests", "Proxy-Connection, Proxy-Authorization, … never reach the origin."},
		{"set_connection_close", "Set Connection: close on requests and responses", "Both directions end after one exchange."},
		{"use_http10_to_server", "Use HTTP/1.0 in requests to server", "Only the version token changes."},
		{"use_http10_to_client", "Use HTTP/1.0 in responses to client", "History records what the browser received."},
	}},
	{"Console", []ui2ProxyOptionDef{
		{"suppress_error_messages", "Suppress burpsy error messages in browser", "Close the connection instead of sending burpsy's error page."},
		{"disable_web_interface", "Disable web interface at http://burpsy", "Stop answering http://burpsy with the welcome page and CA certificate."},
	}},
}

type ui2ProxyOptionRow struct {
	Key, Label, Detail string
	On                 bool
}

type ui2ProxyOptionGroup struct {
	Title string
	Rows  []ui2ProxyOptionRow
}

func ui2ProxyOptionLabel(key string) string {
	for _, g := range ui2ProxyOptionGroups {
		for _, o := range g.opts {
			if o.key == key {
				return o.label
			}
		}
	}
	return key
}

// ui2ProxyLiveOptions reads the live flag set; ok is false when no option set is attached.
func (s *Server) ui2ProxyLiveOptions() (map[string]any, map[string]bool, bool) {
	res, errText := s.ui2APIResult(http.MethodGet, "/api/proxy/options", nil)
	if errText != "" {
		return nil, nil, false
	}
	m, _ := res.(map[string]any)
	raw, _ := m["options"].(map[string]any)
	flags := make(map[string]bool, len(raw))
	for k, v := range raw {
		flags[k] = v == true
	}
	return m, flags, true
}

func (s *Server) handleUI2ProxyOptions(w http.ResponseWriter, r *http.Request) {
	s.renderUI2ProxyOptions(w, r, ui2ProxyNote{})
}

func (s *Server) renderUI2ProxyOptions(w http.ResponseWriter, r *http.Request, note ui2ProxyNote) {
	model := map[string]any{"note": note}
	view, flags, ok := s.ui2ProxyLiveOptions()
	if !ok {
		model["unwired"] = true
	} else {
		seen := map[string]bool{}
		var groups []ui2ProxyOptionGroup
		for _, g := range ui2ProxyOptionGroups {
			grp := ui2ProxyOptionGroup{Title: g.title}
			for _, o := range g.opts {
				seen[o.key] = true
				if _, live := flags[o.key]; live {
					grp.Rows = append(grp.Rows, ui2ProxyOptionRow{Key: o.key, Label: o.label, Detail: o.detail, On: flags[o.key]})
				}
			}
			groups = append(groups, grp)
		}
		// A key the engine has and this table does not name is still editable, by its wire key.
		other := ui2ProxyOptionGroup{Title: "Other"}
		for _, k := range proxy.OptionKeys {
			if _, live := flags[string(k)]; live && !seen[string(k)] {
				other.Rows = append(other.Rows, ui2ProxyOptionRow{Key: string(k), Label: string(k), On: flags[string(k)]})
			}
		}
		if len(other.Rows) > 0 {
			groups = append(groups, other)
		}
		model["groups"] = groups
		model["counter_rows"] = ui2ProxyCounterRows(view)
	}
	if res, errText := s.ui2APIResult(http.MethodGet, "/api/proxy/history-logging", nil); errText == "" {
		if m, ok := res.(map[string]any); ok {
			model["history_logging"] = m["mode"]
		}
	}
	model["persist"] = s.persist != nil
	ui2Fragment(w, r, "burpsy /ui2/ — Proxy options", "proxy-options", ui2Exec("proxy_options.html", model))
}

func (s *Server) handleUI2ProxyOptionsAction(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		_ = r.ParseForm()
		call, msg := s.ui2ParseOptionsCall(r)
		if msg != "" {
			ui2ProxyReviewFail(w, r, "proxy-options", msg)
			return
		}
		s.ui2ProxyConfirm(w, r, "proxy-options", call)
	case "run":
		s.ui2ProxyRun(w, r, "options")
	default:
		http.Error(w, "unknown options action", http.StatusNotFound)
	}
}

// ui2ParseOptionsCall builds a diff-only PUT: only the switches the operator changed relative to
// the state the form was drawn from (was_<key>), so a stale page never writes back other keys.
func (s *Server) ui2ParseOptionsCall(r *http.Request) (ui2ProxyCall, string) {
	c := ui2ProxyCall{
		area:     "options",
		title:    "Proxy options",
		method:   http.MethodPut,
		callURL:  "/api/proxy/options",
		snap:     ui2ProxySnap("/api/proxy/options", "options"),
		driftMsg: "the proxy options changed between your review and this confirmation - review the current options and save again",
	}
	view, live, ok := s.ui2ProxyLiveOptions()
	if !ok {
		return c, "no proxy option set is attached to this server"
	}
	// The drift snapshot comes from the same read the stale-page check uses.
	if b, err := json.Marshal(view["options"]); err == nil {
		c.snapshot = string(b)
	}
	diff := map[string]bool{}
	var keys []string
	for _, k := range proxy.OptionKeys {
		key := string(k)
		was := r.PostFormValue("was_" + key)
		if was == "" {
			continue // not on the submitted form
		}
		wasOn := was == "true"
		on := r.PostFormValue("opt_"+key) != ""
		if on == wasOn {
			continue
		}
		if live[key] != wasOn {
			return c, ui2ProxyOptionLabel(key) + " changed since this page was loaded - reload it and edit again"
		}
		diff[key] = on
		keys = append(keys, key)
	}
	if len(diff) == 0 {
		return c, "nothing changed - tick or untick a switch first"
	}
	c.body, _ = json.Marshal(diff)
	for _, k := range keys {
		state := "OFF"
		if diff[k] {
			state = "ON"
		}
		c.consequences = append(c.consequences, ui2ProxyOptionLabel(k)+" turns "+state+" - live, from the next matching message.")
	}
	c.consequences = append(c.consequences, "Only these keys are sent; every other switch is left as it is.")
	return c, ""
}

// handleUI2ProxyHistoryLogging serves POST /ui2/proxy/history-logging: a riskLocal preference,
// so one click writes it; were the route ever gated, the same form gets a review instead.
func (s *Server) handleUI2ProxyHistoryLogging(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	mode := r.PostFormValue("mode")
	switch mode {
	case "stop", "ask", "nothing":
	default:
		s.renderUI2ProxyOptions(w, r, ui2ProxyNote{Error: "proxy history logging must be stop, ask or nothing"})
		return
	}
	body, _ := json.Marshal(map[string]string{"mode": mode})
	call := ui2ProxyCall{
		area: "options", title: "Proxy history logging", method: http.MethodPost,
		callURL: "/api/proxy/history-logging", body: body, wrap: true,
		consequences: []string{"Adding hosts to scope will " + ui2HistoryLoggingCopy(mode) + "."},
	}
	if ui2ProxyNeedsGate(call.callURL) {
		s.ui2ProxyConfirm(w, r, "proxy-options", call)
		return
	}
	req := newReq(call.method, call.callURL)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(body)))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		s.renderUI2ProxyOptions(w, r, ui2ProxyNote{Error: "not saved: " + truncateForDisplay(strings.TrimSpace(rec.Body.String()), 300)})
		return
	}
	s.renderUI2ProxyOptions(w, r, ui2ProxyNote{OK: "Proxy history logging saved: " + mode + "."})
}

func ui2HistoryLoggingCopy(mode string) string {
	switch mode {
	case "stop":
		return "stop logging out-of-scope items to history"
	case "nothing":
		return "leave proxy logging alone"
	default:
		return "ask what to do each time"
	}
}

// ---- match & replace -------------------------------------------------------------------------

// ui2MRTarget is one rule target the API compiles, and the rule set it belongs to.
type ui2MRTarget struct{ Value, Label, Set string }

var ui2MRTargets = []ui2MRTarget{
	{"request_first_line", "Request line", "request"},
	{"request_header", "Request header", "request"},
	{"request_body", "Request body", "request"},
	{"request_param_name", "Request param name", "request"},
	{"request_param_value", "Request param value", "request"},
	{"websocket_to_server", "WebSocket → server", "request"},
	{"response_header", "Response header", "response"},
	{"response_body", "Response body", "response"},
	{"websocket_to_client", "WebSocket → client", "response"},
}

// ui2MRSet names which rule set a target belongs to: client-to-server or server-to-client.
func ui2MRSet(ruleType string) string {
	for _, t := range ui2MRTargets {
		if t.Value == ruleType {
			return t.Set
		}
	}
	return "request" // an unknown target is shown (and refused by the API on save), never dropped
}

const ui2MRMaxRules = 500

type ui2MRDraft struct {
	Set      matchReplaceSetSpec
	Baseline string // hash of the saved config the draft was adopted from
	Sample   string
	Dir      string
}

func ui2MRHash(spec matchReplaceSetSpec) string {
	if spec.Rules == nil {
		spec.Rules = []matchReplaceRuleSpec{}
	}
	b, _ := json.Marshal(spec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ui2MRSaved reads the saved rule set's config.
func (s *Server) ui2MRSaved() (matchReplaceGetResp, error) {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/tools/rules"))
	var resp matchReplaceGetResp
	if rec.Code != http.StatusOK {
		return resp, fmt.Errorf("reading the rules answered %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// ui2MRSnap is the drift read for a save: the saved config's hash.
func ui2MRSnap(s *Server) (string, error) {
	resp, err := s.ui2MRSaved()
	if err != nil {
		return "", err
	}
	return ui2MRHash(resp.Config), nil
}

// ui2ParseMRDraft reads the editor form: n rows of indexed fields plus the set-wide switches.
func ui2ParseMRDraft(r *http.Request) (ui2MRDraft, string) {
	d := ui2MRDraft{
		Baseline: r.PostFormValue("baseline"),
		Sample:   r.PostFormValue("sample"),
		Dir:      r.PostFormValue("direction"),
	}
	if d.Dir != "response" {
		d.Dir = "request"
	}
	n, err := strconv.Atoi(r.PostFormValue("n"))
	if err != nil || n < 0 || n > ui2MRMaxRules {
		return d, "the rule list on this form is unreadable - reload the editor"
	}
	d.Set.Rules = make([]matchReplaceRuleSpec, 0, n)
	for i := 0; i < n; i++ {
		p := "r" + strconv.Itoa(i) + "_"
		cat := "literal"
		if r.PostFormValue(p+"cat") == "regex" {
			cat = "regex"
		}
		var fields [3]string
		for j, f := range []string{"match", "replace", "comment"} {
			v, ok := ui2MRField(r, p+f)
			if !ok {
				return d, "rule " + strconv.Itoa(i) + " carries an unreadable " + f + " - reload the editor"
			}
			fields[j] = v
		}
		d.Set.Rules = append(d.Set.Rules, matchReplaceRuleSpec{
			RuleType:      r.PostFormValue(p + "type"),
			Enabled:       r.PostFormValue(p+"enabled") != "",
			StringMatch:   fields[0],
			StringReplace: fields[1],
			Category:      cat,
			Comment:       fields[2],
		})
	}
	d.Set.UpdateContentLength = r.PostFormValue("ucl") != ""
	d.Set.InScopeOnly = r.PostFormValue("in_scope") != ""
	return d, ""
}

// ui2MRField reads one rule text field. A value with a line break cannot ride a single-line
// input (the browser strips CR/LF), so it travels as <name>_b64 in a hidden input and is shown
// read-only; the exact bytes therefore round-trip through every draft operation and save.
func ui2MRField(r *http.Request, name string) (string, bool) {
	if enc := r.PostFormValue(name + "_b64"); enc != "" {
		b, err := base64.StdEncoding.DecodeString(enc)
		return string(b), err == nil
	}
	return r.PostFormValue(name), true
}

// ui2MRMultiline is the base64 carrier for a value an <input> cannot hold, "" otherwise.
func ui2MRMultiline(v string) string {
	if strings.ContainsAny(v, "\r\n") {
		return base64.StdEncoding.EncodeToString([]byte(v))
	}
	return ""
}

type ui2MRRow struct {
	MatchB64, ReplaceB64, CommentB64        string
	I                                       int
	Type, Cat, Match, Replace, Comment, Set string
	Enabled, First, Last, Known             bool
	Targets                                 []ui2MRTarget
}

func (s *Server) handleUI2MatchReplace(w http.ResponseWriter, r *http.Request) {
	s.renderUI2MatchReplaceSaved(w, r, ui2ProxyNote{})
}

// renderUI2MatchReplaceSaved renders the editor from the saved set (page load, revert, after a run).
func (s *Server) renderUI2MatchReplaceSaved(w http.ResponseWriter, r *http.Request, note ui2ProxyNote) {
	resp, err := s.ui2MRSaved()
	if err != nil {
		note.Error = strings.TrimSpace(note.Error + " " + err.Error())
	}
	cfg := resp.Config
	if cfg.Rules == nil {
		cfg.Rules = []matchReplaceRuleSpec{}
	}
	s.renderUI2MatchReplace(w, r, ui2MRDraft{Set: cfg, Baseline: ui2MRHash(cfg), Dir: "request"}, note, &resp)
}

func (s *Server) renderUI2MatchReplace(w http.ResponseWriter, r *http.Request, d ui2MRDraft, note ui2ProxyNote, saved *matchReplaceGetResp) {
	if saved == nil {
		if resp, err := s.ui2MRSaved(); err == nil {
			saved = &resp
		}
	}
	rows := map[string][]ui2MRRow{"request": nil, "response": nil}
	enabled := 0
	for i, rule := range d.Set.Rules {
		set := ui2MRSet(rule.RuleType)
		known := false
		for _, t := range ui2MRTargets {
			if t.Value == rule.RuleType {
				known = true
			}
		}
		if rule.Enabled {
			enabled++
		}
		rows[set] = append(rows[set], ui2MRRow{
			I: i, Type: rule.RuleType, Cat: rule.Category, Match: rule.StringMatch,
			Replace: rule.StringReplace, Comment: rule.Comment, Set: set, Enabled: rule.Enabled, Known: known,
			Targets:  ui2MRTargets,
			MatchB64: ui2MRMultiline(rule.StringMatch), ReplaceB64: ui2MRMultiline(rule.StringReplace),
			CommentB64: ui2MRMultiline(rule.Comment),
		})
	}
	for _, set := range []string{"request", "response"} {
		if n := len(rows[set]); n > 0 {
			rows[set][0].First = true
			rows[set][n-1].Last = true
		}
	}
	model := map[string]any{
		"note":      note,
		"req_rows":  rows["request"],
		"resp_rows": rows["response"],
		"n":         len(d.Set.Rules),
		"enabled":   enabled,
		"ucl":       d.Set.UpdateContentLength,
		"in_scope":  d.Set.InScopeOnly,
		"baseline":  d.Baseline,
		"dirty":     ui2MRHash(d.Set) != d.Baseline,
		"sample":    d.Sample,
		"direction": d.Dir,
	}
	if saved != nil {
		model["saved"] = saved
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Match & Replace", "match-replace", ui2Exec("proxy_match_replace.html", model))
}

func (s *Server) handleUI2MatchReplaceAction(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.PathValue("action")
	if action == "run" {
		s.ui2ProxyRun(w, r, "match-replace")
		return
	}
	d, msg := ui2ParseMRDraft(r)
	switch action {
	case "edit":
		if msg != "" {
			s.renderUI2MatchReplaceSaved(w, r, ui2ProxyNote{Error: msg})
			return
		}
		if msg := ui2MREdit(&d, r.URL.Query()); msg != "" {
			s.renderUI2MatchReplace(w, r, d, ui2ProxyNote{Error: msg}, nil)
			return
		}
		s.renderUI2MatchReplace(w, r, d, ui2ProxyNote{}, nil)
	case "test":
		model := map[string]any{}
		if msg != "" {
			model["error"] = msg
		} else {
			res, errText := s.ui2APIResult(http.MethodPost, "/api/tools/rules/test", matchReplaceTestReq{
				Input: d.Sample, Direction: d.Dir, DraftRules: d.Set.Rules,
			})
			if errText != "" {
				model["error"] = ui2APIErrorText(errText)
			} else if m, ok := res.(map[string]any); ok {
				model["changed"] = m["changed"] == true
				if out, ok := m["output"].(map[string]any); ok {
					model["output"] = out["text"]
				}
				model["ran"] = true
			}
		}
		model["direction"] = d.Dir
		ui2Fragment(w, r, "burpsy /ui2/ — Match & Replace", "match-replace", ui2Exec("proxy_mr_test.html", model))
	case "confirm":
		if msg != "" {
			ui2ProxyReviewFail(w, r, "match-replace", msg)
			return
		}
		call, msg := s.ui2ParseMRCall(d)
		if msg != "" {
			ui2ProxyReviewFail(w, r, "match-replace", msg)
			return
		}
		s.ui2ProxyConfirm(w, r, "match-replace", call)
	default:
		http.Error(w, "unknown match & replace action", http.StatusNotFound)
	}
}

// ui2MREdit applies one draft operation (?op=add|del|dup|up|down&i=<index>&set=request|response).
// Nothing is saved: the draft round-trips through the form until the reviewed save.
func ui2MREdit(d *ui2MRDraft, q url.Values) string {
	rules := d.Set.Rules
	op := q.Get("op")
	if op == "add" {
		if len(rules) >= ui2MRMaxRules {
			return "a rule set holds at most " + strconv.Itoa(ui2MRMaxRules) + " rules on this page"
		}
		t := "request_header"
		if q.Get("set") == "response" {
			t = "response_header"
		}
		d.Set.Rules = append(rules, matchReplaceRuleSpec{RuleType: t, Enabled: true, Category: "literal"})
		return ""
	}
	i, err := strconv.Atoi(q.Get("i"))
	if err != nil || i < 0 || i >= len(rules) {
		return "that rule is not on this draft - reload the editor"
	}
	set := ui2MRSet(rules[i].RuleType)
	switch op {
	case "del":
		d.Set.Rules = append(rules[:i:i], rules[i+1:]...)
	case "dup":
		if len(rules) >= ui2MRMaxRules {
			return "a rule set holds at most " + strconv.Itoa(ui2MRMaxRules) + " rules on this page"
		}
		out := append([]matchReplaceRuleSpec{}, rules[:i+1]...)
		out = append(out, rules[i])
		d.Set.Rules = append(out, rules[i+1:]...)
	case "up", "down":
		// Order is per set: swap with the nearest rule of the same set, so the other set's
		// relative order (the only order that affects it) never changes.
		step := -1
		if op == "down" {
			step = 1
		}
		for j := i + step; j >= 0 && j < len(rules); j += step {
			if ui2MRSet(rules[j].RuleType) == set {
				rules[i], rules[j] = rules[j], rules[i]
				return ""
			}
		}
	default:
		return "unknown draft operation"
	}
	return ""
}

func (s *Server) ui2ParseMRCall(d ui2MRDraft) (ui2ProxyCall, string) {
	c := ui2ProxyCall{
		area:     "match-replace",
		title:    "Match & Replace rules",
		method:   http.MethodPut,
		callURL:  "/api/tools/rules",
		snap:     ui2MRSnap,
		driftMsg: "the saved rules changed between your review and this confirmation - revert to load the current set and edit again",
	}
	saved, err := s.ui2MRSaved()
	if err != nil {
		return c, err.Error()
	}
	if ui2MRHash(saved.Config) != d.Baseline {
		return c, "the saved rules changed since this editor was loaded - revert to load the current set (your draft is not saved)"
	}
	if ui2MRHash(d.Set) == d.Baseline {
		return c, "nothing changed - the draft equals the saved rule set"
	}
	// The drift snapshot is the baseline just verified, never a second read: a change landing
	// after that check would otherwise become the snapshot and be overwritten silently.
	c.snapshot = d.Baseline
	// Dry-run the draft through the test route: it compiles every rule exactly as the PUT does,
	// so an invalid rule is refused here with its index instead of at run.
	if _, errText := s.ui2APIResult(http.MethodPost, "/api/tools/rules/test", matchReplaceTestReq{DraftRules: d.Set.Rules}); errText != "" {
		return c, ui2APIErrorText(errText)
	}
	c.body, _ = json.Marshal(d.Set)
	reqN, respN, on := 0, 0, 0
	for _, rule := range d.Set.Rules {
		if rule.Enabled {
			on++
		}
		if ui2MRSet(rule.RuleType) == "response" {
			respN++
		} else {
			reqN++
		}
	}
	c.consequences = []string{
		fmt.Sprintf("The whole saved set (%d rules) is replaced by these %d rules: %d request-side, %d response-side, %d enabled. Live traffic is rewritten by them from the moment you confirm.",
			len(saved.Config.Rules), len(d.Set.Rules), reqN, respN, on),
		fmt.Sprintf("Fix Content-Length: %t. Only apply to in-scope items: %t.", d.Set.UpdateContentLength, d.Set.InScopeOnly),
	}
	return c, ""
}
