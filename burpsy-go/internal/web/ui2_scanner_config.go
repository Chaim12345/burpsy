package web

// The ui2 scanner configuration surface: every audit-check switch and knob, the issue-row
// restriction, the XSS browser routes, secret detection, the live active audit, passive coverage,
// and the named scan-configuration library.
//
// Two review mechanics, one per kind of write:
//   - PUT /api/scanner/config (riskScope, gated) keeps the existing config-confirm/config-run
//     flow: the form is diffed into the exact patch, the gate mints a token bound to those bytes,
//     the review sheet shows the FULL body, and the run re-sends the reviewed patch with the token.
//   - The live audit, secret detection and library writes go through one server-held review
//     (/ui2/scanner/review -> /ui2/scanner/review-run): the call's exact bytes are held here,
//     the run form carries only the review id and token, and the entry is spent atomically.
//     Whether the token comes from the gate or is a local review handle is derived from the
//     route's risk class (needsConfirmation), never assumed per op.

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

const (
	ui2ScanConfigTitle  = "burpsy /ui2/ — Scanner configuration"
	ui2ScanLibraryTitle = "burpsy /ui2/ — Scan configuration library"
	ui2ScanReviewCap    = 8
)

// ---- Audit-check families --------------------------------------------------------------------

type ui2ScanCheckRow struct {
	Key, Label, Hint string
	DefaultOn        bool
}

type ui2ScanCheckGroup struct {
	Title, Detail string
	Rows          []ui2ScanCheckRow
}

// ui2ScanCheckGroups groups every check-family switch by what it does to the target (the SPA's
// grouping). DefaultOn mirrors the scanner's own defaults; it is a label, never a value sent.
var ui2ScanCheckGroups = []ui2ScanCheckGroup{
	{"Passive", "Response inspection that sends no request of its own.", []ui2ScanCheckRow{
		{"check_headers", "Security headers & cookies", "", true},
		{"check_passive_posture", "Security posture", "", true},
		{"check_passive_analysis", "Advanced passive analysis", "", true},
		{"check_host_discovery", "Host discovery notes", "", true},
		{"check_cookie_attributes", "Cookie prefix & SameSite", "Read from captured Set-Cookie headers", false},
		{"check_subdomain_takeover", "Subdomain takeover", "Sends nothing to the target, but resolves DNS for every audited hostname", false},
	}},
	{"Active injection", "Inert probes, each proven by evidence a reflection cannot fake.", []ui2ScanCheckRow{
		{"check_sqli", "SQL injection", "", true},
		{"check_xss", "Cross-site scripting", "", true},
		{"check_path_traversal", "File path traversal", "", true},
		{"check_ssrf", "Server-side request forgery", "Its out-of-band row also needs Extended active checks and a collaborator", true},
		{"check_xxe", "XML external entity", "File read through an external entity; needs the target to accept XML", true},
		{"check_active_injection", "OS command, LDAP, XPath, template & code injection", "Twelve checks, each proven by a computed value, an error signature, a control differential or file content", true},
		{"check_reflection_probes", "Reflection probing", "Input reflection, open redirect, link manipulation, header injection, SSI", true},
		{"check_jwt_weak", "Weak JWT secrets", "", false},
		{"check_js_vulns", "JavaScript vulnerabilities", "", false},
		{"check_cache_poisoning", "Web cache poisoning", "", false},
		{"check_response_dependence", "Response-dependence analysis", "", false},
	}},
	{"Opt-in active probes", "Off until switched on. They send request shapes a monitoring system may flag, or replay captured requests in altered form.", []ui2ScanCheckRow{
		{"check_sqli_heavy_query", "SQL injection: heavy-query delays", "Time delays that cost the database CPU", false},
		{"check_sqli_or_boolean", "SQL injection: widening OR shapes", "An always-true OR can widen an UPDATE or DELETE to every row", false},
		{"check_sqli_stacked", "SQL injection: stacked queries", "Several multi-second sleeps per confirmation", false},
		{"check_nosql_injection", "NoSQL injection", "Reads only (GET, or a POST naming a read or a login)", false},
		{"check_server_side_parameter_pollution", "Server-side parameter pollution", "", false},
		{"check_llm_prompt_injection", "LLM prompt injection", "Appends a benign instruction to text values a model may answer", false},
		{"check_weak_crypto", "Weak cryptography", "Submits random markers; on a login form they are failed logins", false},
		{"check_idor", "Insecure direct object references", "Read-only probes, confirmed against two controls", false},
		{"check_graphql_hardening", "GraphQL hardening", "Query batching, depth and debug errors", false},
		{"check_host_header", "Host header injection", "Sends requests naming hosts the target does not serve", false},
		{"check_client_ip_spoofing", "Spoofable client-IP headers", "Claims loopback to refused pages", false},
		{"check_jwt_forgery", "JWT forgery", "Replays the request with only the token changed", false},
		{"check_jwt_exposure", "JWT credential exposure", "Replays with the signature altered and with the token removed", false},
		{"check_insecure_deserialization", "Insecure deserialization", "Benign accepted/rejected value pairs; no gadget is sent", false},
		{"check_websocket_hijacking", "Cross-site WebSocket hijacking", "Opens authenticated sockets as the captured session", false},
		{"check_request_smuggling", "HTTP request smuggling", "Timing only; holds a back-end connection open per confirmed attack", false},
		{"check_extended_active", "Extended active checks", "GraphQL, CORS, entity expansion, smuggling, file-upload and OpenAPI discovery and more. Slower, noisier", false},
	}},
	{"Intrusive", "Leaves state on the target or acts on an account. Use a test account or a disposable environment.", []ui2ScanCheckRow{
		{"check_file_upload", "File upload", "Leaves files on the target", false},
		{"check_login_rate_limit", "Login rate limiting", "A burst of failed logins under an invented identity", false},
		{"check_username_enumeration", "Username enumeration", "Failed logins for the captured, real username", false},
		{"check_password_reset", "Password reset tokens", "Changes the test identity's password; does nothing without listed test identities", false},
		{"check_session_management", "Session management", "Replays the captured login, with its credentials", false},
	}},
	{"Engines & coverage", "Cross-cutting engines and where the scanner is allowed to spend effort.", []ui2ScanCheckRow{
		{"check_corpus", "BCheck corpus actives", "The bundled corpus, or one loaded via --bchecks", false},
		{"check_dom", "DOM-based checks", "Needs -dom chrome (or ws://) at startup", false},
		{"check_xss_browser_confirm", "Browser confirmation of reflected XSS", "Needs -dom; a point on a route not listed below is declined, not reported clean", false},
		{"check_out_of_band", "Out-of-band callbacks", "interactsh confirmation for blind findings", false},
		{"check_ssrf_in_band", "In-band SSRF canary", "Plants a URL this scanner serves and sees whether the application fetches it", false},
		{"check_stored", "Stored-input rendering", "", false},
		{"check_extended_coverage", "Extended crawl coverage", "", false},
	}},
}

// ui2ScanConfigBoolKeys is every switch the page offers, in group order. It must equal the set
// PUT /api/scanner/config accepts (TestUI2ScanConfigKeysMatchTheEndpoint).
var ui2ScanConfigBoolKeys = func() []string {
	var out []string
	for _, g := range ui2ScanCheckGroups {
		for _, r := range g.Rows {
			out = append(out, r.Key)
		}
	}
	return out
}()

// ui2ScanConfigView reads the live engine configuration the way the page does; {} when no
// scanner is wired.
func (s *Server) ui2ScanConfigView() map[string]any {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/scanner/config"))
	var view map[string]any
	if rec.Code != http.StatusOK || ui2DecodeJSON(rec.Body.Bytes(), &view) != nil {
		return map[string]any{}
	}
	return view
}

// ui2StringList reads a JSON list of strings decoded as []any.
func ui2StringList(v any) []string {
	out := []string{}
	list, _ := v.([]any)
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ui2TrimmedLines splits a textarea into trimmed, non-blank lines.
func ui2TrimmedLines(raw string) []string {
	out := []string{}
	for _, l := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func ui2SameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ui2Present(r *http.Request, key string) bool {
	_, ok := r.PostForm[key]
	return ok
}

// ui2XSSSinkNames is every sink a route may name, from the instrumented set itself (SinkEval is
// value 0 and means "the default innerHTML family", so it is not offered by name).
func ui2XSSSinkNames() []string {
	out := []string{}
	for k := domexec.SinkKind(1); k <= domexec.SinkAjaxHeader; k++ {
		out = append(out, k.String())
	}
	return out
}

// ui2XSSRouteTextFields are the route's string fields in form order; sink is a select.
var ui2XSSRouteTextFields = []struct{ Key, Label string }{
	{"match", "match (URL substring, blank = any)"},
	{"root_url", "root URL *"},
	{"master_selector", "master selector *"},
	{"master_text", "master text *"},
	{"level_selector", "level selector"},
	{"level_text", "level text"},
	{"input_selector", "input selector *"},
	{"submit_selector", "submit selector"},
}

// ui2OnlyRowNames is the catalogue's row names, unique and sorted, for the restriction picker.
func (s *Server) ui2OnlyRowNames() []string {
	res, _ := s.ui2APIResult(http.MethodGet, "/api/scanner/issue-types", nil)
	m, _ := res.(map[string]any)
	seen := map[string]bool{}
	out := []string{}
	for _, e := range ui2AnyMaps(m["issue_types"]) {
		if n, _ := e["name"].(string); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func ui2AnyMaps(v any) []map[string]any {
	out := []map[string]any{}
	list, _ := v.([]any)
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ---- The configuration page --------------------------------------------------------------------

// handleUI2ScannerConfig serves GET /ui2/scanner/config.
func (s *Server) handleUI2ScannerConfig(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, ui2ScanConfigTitle, "scanconfig", ui2Exec("scanner_config.html", s.ui2ScanConfigPageModel()))
}

func (s *Server) ui2ScanConfigPageModel() map[string]any {
	view := s.ui2ScanConfigView()
	m := map[string]any{"wired": len(view) > 0, "config": view}
	groups := []map[string]any{}
	for _, g := range ui2ScanCheckGroups {
		rows := []map[string]any{}
		for _, row := range g.Rows {
			on, _ := view[row.Key].(bool)
			rows = append(rows, map[string]any{"key": row.Key, "label": row.Label, "hint": row.Hint, "default_on": row.DefaultOn, "on": on})
		}
		groups = append(groups, map[string]any{"title": g.Title, "detail": g.Detail, "rows": rows})
	}
	m["groups"] = groups
	num := func(k string) string {
		f, _ := view[k].(float64)
		return strconv.FormatInt(int64(f), 10)
	}
	m["max_concurrency"] = num("max_concurrency")
	m["timeout_ms"] = num("timeout_ms")
	m["probe_timeout_ms"] = num("probe_timeout_ms")
	m["login_attempts"] = num("login_rate_limit_attempts")
	m["login_hint"] = fmt.Sprintf("0 = scanner default (%d), otherwise %d to %d", scanner.DefaultLoginRateLimitAttempts,
		scanner.MinLoginRateLimitAttempts, scanner.MaxLoginRateLimitAttempts)
	m["identities_text"] = strings.Join(ui2StringList(view["reset_test_identities"]), "\n")
	m["mailbox_url"], _ = view["reset_mailbox_url"].(string)
	m["only_rows_text"] = strings.Join(ui2StringList(view["only_rows"]), "\n")
	m["row_names"] = s.ui2OnlyRowNames()
	routes := []map[string]any{}
	for i, rt := range ui2AnyMaps(view["xss_browser_targets"]) {
		routes = append(routes, ui2XSSRouteModel(i, rt))
	}
	m["xss_routes"] = routes
	m["xss_new"] = ui2XSSRouteModel(len(routes), map[string]any{})
	m["xss_count"] = len(routes) + 1
	m["xss_can_add"] = len(routes) < MaxXSSBrowserTargets
	m["xss_max"] = MaxXSSBrowserTargets
	m["secrets"] = s.ui2SecretsModel()
	m["live"] = s.ui2LiveModel()
	m["coverage"] = s.ui2CoverageModel()
	return m
}

// ui2XSSRouteModel projects one route into its form block: field names carry the route's index.
func ui2XSSRouteModel(i int, rt map[string]any) map[string]any {
	fields := []map[string]any{}
	for _, f := range ui2XSSRouteTextFields {
		v, _ := rt[f.Key].(string)
		fields = append(fields, map[string]any{"name": fmt.Sprintf("xr%d_%s", i, f.Key), "label": f.Label, "value": v})
	}
	sinks := []map[string]any{}
	cur, _ := rt["sink"].(string)
	for _, name := range ui2XSSSinkNames() {
		sinks = append(sinks, map[string]any{"name": name, "selected": name == cur})
	}
	lfp, _ := rt["level_from_path"].(bool)
	ct, _ := rt["click_trigger"].(bool)
	return map[string]any{"index": i, "number": i + 1, "fields": fields, "sinks": sinks,
		"prefix": fmt.Sprintf("xr%d_", i), "level_from_path": lfp, "click_trigger": ct}
}

// ui2XSSRoutesFromForm reads the route blocks back. A block marked for removal is dropped, and a
// block with every field blank is the unused "new route" block, not a route.
func ui2XSSRoutesFromForm(r *http.Request) []any {
	count, _ := strconv.Atoi(r.PostFormValue("xr_count"))
	if count > MaxXSSBrowserTargets+1 {
		count = MaxXSSBrowserTargets + 1
	}
	out := []any{}
	for i := 0; i < count; i++ {
		p := fmt.Sprintf("xr%d_", i)
		if r.PostFormValue(p+"remove") == "on" {
			continue
		}
		rt := map[string]any{}
		blank := true
		for _, f := range ui2XSSRouteTextFields {
			v := strings.TrimSpace(r.PostFormValue(p + f.Key))
			rt[f.Key] = v
			if v != "" {
				blank = false
			}
		}
		rt["sink"] = strings.TrimSpace(r.PostFormValue(p + "sink"))
		rt["level_from_path"] = r.PostFormValue(p+"level_from_path") == "on"
		rt["click_trigger"] = r.PostFormValue(p+"click_trigger") == "on"
		if blank && rt["sink"] == "" && rt["level_from_path"] == false && rt["click_trigger"] == false {
			continue
		}
		out = append(out, rt)
	}
	return out
}

// ui2ScanConfigPatch diffs the submitted form against the live view into the exact PUT body:
// only keys whose value changed, so the review and the confirmation cover precisely what moves.
// The switches are always on the form (an absent checkbox is off); every other field is diffed
// only when the form carries it, and a blank number means "leave as is". Values the endpoint
// would refuse are refused here, before any token exists.
func ui2ScanConfigPatch(r *http.Request, view map[string]any) (map[string]any, []string, string) {
	patch := map[string]any{}
	changes := []string{}
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	for _, key := range ui2ScanConfigBoolKeys {
		cur, _ := view[key].(bool)
		want := r.PostFormValue(key) == "on"
		if want != cur {
			patch[key] = want
			changes = append(changes, strings.TrimPrefix(key, "check_")+": "+onOff(cur)+" -> "+onOff(want))
		}
	}
	for _, k := range []struct {
		key  string
		ok   func(int) bool
		want string
	}{
		{"max_concurrency", func(n int) bool { return n >= 1 }, "an integer of at least 1"},
		{"timeout_ms", func(n int) bool { return n >= 0 }, "a non-negative number of milliseconds"},
		{"probe_timeout_ms", func(n int) bool { return n >= 0 }, "a non-negative number of milliseconds"},
		{"login_rate_limit_attempts", func(n int) bool {
			return n == 0 || (n >= scanner.MinLoginRateLimitAttempts && n <= scanner.MaxLoginRateLimitAttempts)
		}, fmt.Sprintf("0 (the default, %d) or an integer from %d to %d", scanner.DefaultLoginRateLimitAttempts,
			scanner.MinLoginRateLimitAttempts, scanner.MaxLoginRateLimitAttempts)},
	} {
		raw := strings.TrimSpace(r.PostFormValue(k.key))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || !k.ok(n) {
			return nil, nil, k.key + " wants " + k.want
		}
		if cur, _ := view[k.key].(float64); int(cur) != n {
			patch[k.key] = n
			changes = append(changes, fmt.Sprintf("%s: %d -> %d", k.key, int(cur), n))
		}
	}
	if ui2Present(r, "reset_test_identities") {
		cur, want := ui2StringList(view["reset_test_identities"]), ui2TrimmedLines(r.PostFormValue("reset_test_identities"))
		if !ui2SameStrings(cur, want) {
			patch["reset_test_identities"] = want
			changes = append(changes, fmt.Sprintf("reset_test_identities: %d -> %d identities", len(cur), len(want)))
		}
	}
	if ui2Present(r, "reset_mailbox_url") {
		cur, _ := view["reset_mailbox_url"].(string)
		want := strings.TrimSpace(r.PostFormValue("reset_mailbox_url"))
		if want != "" {
			pu, err := url.Parse(strings.ReplaceAll(want, "{identity}", "x"))
			if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
				return nil, nil, "reset_mailbox_url wants an absolute http(s) URL"
			}
		}
		if want != cur {
			patch["reset_mailbox_url"] = want
			changes = append(changes, fmt.Sprintf("reset_mailbox_url: %q -> %q", cur, want))
		}
	}
	if ui2Present(r, "only_rows") {
		cur := ui2StringList(view["only_rows"])
		want := []string{}
		seen := map[string]bool{}
		for _, n := range append(ui2TrimmedLines(r.PostFormValue("only_rows")), strings.TrimSpace(r.PostFormValue("only_rows_add"))) {
			if n != "" && !seen[n] {
				seen[n] = true
				want = append(want, n)
			}
		}
		if len(want) > MaxOnlyRows {
			return nil, nil, fmt.Sprintf("only_rows holds %d names; at most %d", len(want), MaxOnlyRows)
		}
		if unknown := scanner.UnknownRows(want); len(unknown) > 0 {
			return nil, nil, "only_rows names unknown issue row(s): " + strings.Join(quoteAll(unknown), ", ")
		}
		if !ui2SameStrings(cur, want) {
			patch["only_rows"] = want
			changes = append(changes, fmt.Sprintf("only_rows: %d -> %d rows (empty runs every enabled check)", len(cur), len(want)))
		}
	}
	if ui2Present(r, "xr_count") {
		want := ui2XSSRoutesFromForm(r)
		raw, _ := json.Marshal(want)
		if _, err := parseXSSBrowserTargets(raw); err != nil {
			return nil, nil, "xss_browser_targets: " + err.Error()
		}
		curList, _ := view["xss_browser_targets"].([]any)
		if curList == nil {
			curList = []any{}
		}
		curRaw, _ := json.Marshal(curList)
		if string(curRaw) != string(raw) {
			patch["xss_browser_targets"] = want
			changes = append(changes, fmt.Sprintf("xss_browser_targets: %d -> %d routes", len(curList), len(want)))
		}
	}
	if len(patch) == 0 {
		return nil, nil, "nothing changed - the submitted configuration matches the running one"
	}
	return patch, changes, ""
}

// ui2ReviewProjection is the review sheet's view of one call: method, path and the body exactly
// as minted, indented for reading. Indenting re-spaces the bytes and changes nothing else.
func ui2ReviewProjection(method, path string, body []byte) string {
	out := method + " " + path
	if len(body) > 0 {
		var buf bytes.Buffer
		if json.Indent(&buf, body, "", "  ") != nil {
			buf.Reset()
			buf.Write(body)
		}
		out += "\n" + buf.String()
	}
	return out
}

// handleUI2ScannerConfigConfirm serves POST /ui2/scanner/config-confirm: diffs the form against
// the live configuration, mints a one-time confirmation for the exact PUT, and renders the
// review sheet with the full bound body and every change named.
func (s *Server) handleUI2ScannerConfigConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := map[string]any{}
	view := s.ui2ScanConfigView()
	if len(view) == 0 {
		model["error"] = "No scanner is configured in this process"
	} else if patch, changes, errText := ui2ScanConfigPatch(r, view); errText != "" {
		model["error"] = errText
	} else {
		body, _ := ui2Marshal(patch)
		token, _, mintErr := s.ui2MintConfirm("/api/scanner/config", http.MethodPut, "/api/scanner/config", body)
		if mintErr == "" && token == "" {
			mintErr = "the confirmation gate refused to mint a review - try again"
		}
		model["token"] = token
		model["error"] = mintErr
		model["changes"] = changes
		model["patch"] = string(body)
		model["projection"] = ui2ReviewProjection(http.MethodPut, "/api/scanner/config", body)
	}
	ui2Fragment(w, r, ui2ScanConfigTitle, "scanconfig", ui2Exec("scanner_config_confirm.html", model))
}

// handleUI2ScannerConfigRun serves POST /ui2/scanner/config-run: spends the confirmation token on
// the exact patch the operator reviewed and re-renders the page with the outcome. The gate binds
// the body, so a patch altered after the review is refused and burns the token.
func (s *Server) handleUI2ScannerConfigRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// Dispatch first: the re-rendered page must show the state AFTER the change.
	var patch map[string]any
	var outcomeErr string
	applied := false
	if err := ui2DecodeJSON([]byte(r.PostFormValue("patch")), &patch); err != nil || len(patch) == 0 {
		outcomeErr = "the reviewed change set was lost - submit the form again"
	} else {
		_, outcomeErr = s.ui2DispatchConfirmed(http.MethodPut, "/api/scanner/config", patch, r.PostFormValue("token"))
		applied = outcomeErr == ""
	}
	model := s.ui2ScanConfigPageModel()
	model["config_error"] = ui2APIErrorText(outcomeErr)
	model["config_applied"] = applied
	ui2Fragment(w, r, ui2ScanConfigTitle, "scanconfig", ui2Exec("scanner_config.html", model))
}

// ---- Secret detection, live audit, coverage (read side) ----------------------------------------

func (s *Server) ui2SecretsModel() map[string]any {
	v := s.viewSecretDetection()
	excluded := []string{}
	for rule, why := range v.Excluded {
		excluded = append(excluded, rule+" ("+why+")")
	}
	sort.Strings(excluded)
	return map[string]any{"wired": s.passiveScanner != nil, "enabled": v.Enabled, "corpus": v.Corpus,
		"rules": v.Rules, "extra": strings.Join(v.Extra, ", "), "excluded": excluded}
}

func ui2Millis(ms int64) string {
	return (time.Duration(ms) * time.Millisecond).Round(time.Second).String()
}

func (s *Server) ui2LiveModel() map[string]any {
	v := s.liveAuditStatus()
	gaps := []string{}
	if v.Behind > 0 {
		gaps = append(gaps, fmt.Sprintf("%d not reached yet (behind for %s)", v.Behind, ui2Millis(v.BehindForMs)))
	}
	if v.Skipped > 0 {
		gaps = append(gaps, fmt.Sprintf("%d given up on", v.Skipped))
	}
	stalled := ""
	if v.StalledAt != nil {
		stalled = strconv.FormatUint(*v.StalledAt, 10)
		gaps = append(gaps, "waiting on #"+stalled)
	}
	source := v.TrafficSource
	if source == "" {
		source = string(LiveAuditSourceProxy)
	}
	return map[string]any{"v": v, "stalled": stalled, "gaps": strings.Join(gaps, "; "),
		"behind_for": ui2Millis(v.BehindForMs), "source": source}
}

// handleUI2ScannerLive serves GET /ui2/scanner/live: the live-audit metrics block alone, which the
// page's live refresh swaps on capture and finding events. It carries no form field, so a swap can
// never take an unsaved edit away.
func (s *Server) handleUI2ScannerLive(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, ui2ScanConfigTitle, "scanconfig", ui2Exec("scanner_live_metrics.html", s.ui2LiveModel()))
}

type ui2CoverageView struct {
	Enabled   bool   `json:"enabled"`
	Hint      string `json:"hint"`
	Loaded    int    `json:"loaded"`
	Summary   string `json:"summary"`
	Undecoded uint64 `json:"undecoded_bodies"`
	Partition []struct {
		State string `json:"state"`
		Count int    `json:"count"`
	} `json:"partition"`
	Checks []coverageCheckView `json:"checks"`
}

func (s *Server) ui2CoverageModel() ui2CoverageView {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/scanner/coverage"))
	var v ui2CoverageView
	_ = ui2DecodeJSON(rec.Body.Bytes(), &v)
	return v
}

// ---- Targeted audit result -------------------------------------------------------------------

// ui2AuditResult is the audit reply as the result panel reads it, typed so counts render as
// integers rather than float64's exponent form.
type ui2AuditResult struct {
	ExchangeID        uint64 `json:"exchange_id"`
	ActiveChecks      int    `json:"active_checks"`
	Unimplemented     int    `json:"unimplemented"`
	ConfigName        string `json:"config_name"`
	Summary           string `json:"summary"`
	CapabilityMissing int    `json:"capability_missing"`
	Config            struct {
		TimeBudgetMs int64   `json:"time_budget_ms"`
		MaxRequests  *uint32 `json:"max_requests"`
	} `json:"config"`
	Outcome struct {
		State           string `json:"state"`
		Ran             int    `json:"ran"`
		Findings        int    `json:"findings"`
		Skipped         int    `json:"skipped"`
		SendFailures    int    `json:"send_failures"`
		RequestsSent    uint32 `json:"requests_sent"`
		RequestsRefused uint32 `json:"requests_refused"`
		TimedOut        bool   `json:"timed_out"`
		Cancelled       bool   `json:"cancelled"`
		Error           string `json:"error"`
	} `json:"outcome"`
	Dispositions []struct {
		Disposition    string `json:"disposition"`
		Reason         string `json:"reason"`
		Count          int    `json:"count"`
		StoppedLooking bool   `json:"stopped_looking"`
	} `json:"dispositions"`
	Breakdown struct {
		Unit      string `json:"unit"`
		WorkUnit  string `json:"work_unit"`
		Breakdown struct {
			Found, Skipped, Errored, Gated uint64
		} `json:"breakdown"`
		Reasons []struct {
			Bucket string `json:"bucket"`
			Detail string `json:"detail"`
			Count  uint64 `json:"count"`
		} `json:"reasons"`
	} `json:"breakdown"`
	TimeBudget string `json:"-"`
}

// ui2AuditResultView types the /api/scanner/audit reply for scanner_audit_result.html; nil when
// there is no reply to show.
func ui2AuditResultView(result any) *ui2AuditResult {
	if result == nil {
		return nil
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil
	}
	var v ui2AuditResult
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	v.TimeBudget = ui2Millis(v.Config.TimeBudgetMs)
	return &v
}

// ---- Server-held reviews (live audit, secrets, library) ----------------------------------------

type ui2ScanHeld struct {
	token    string
	gated    bool
	method   string
	path     string
	body     []byte
	page     string // "config" or "library": what the run re-renders
	open     string // the library detail to reopen after the run
	done     string
	snapshot string // live-audit switch state at review; "" when not checked
	expires  time.Time
}

// ui2ScanCall is what one op builds: the exact call plus the review copy.
type ui2ScanCall struct {
	method, path string
	body         map[string]any
	title        string
	consequences []string
	page, open   string
	done         string
	snapshot     bool
}

// ui2ScanGated says whether a route sits behind the confirmation gate, from its risk class. An
// unknown route fails closed (gated).
func ui2ScanGated(path string) bool {
	_, risk, ok := routeRiskFor(path)
	return !ok || needsConfirmation(risk)
}

func (s *Server) ui2LiveSnapshot() string {
	v := s.liveAuditStatus()
	return fmt.Sprintf("enabled=%v source=%s", v.Enabled, v.TrafficSource)
}

func ui2ScanOpPage(op string) string {
	if strings.HasPrefix(op, "lib-") {
		return "library"
	}
	return "config"
}

// ui2ScanBuildCall turns one op's form into the exact API call. Every refusal the API would give
// for state this page can see is given here, before a token exists.
func (s *Server) ui2ScanBuildCall(op string, r *http.Request) (ui2ScanCall, string) {
	c := ui2ScanCall{page: ui2ScanOpPage(op)}
	switch op {
	case "live-enable", "live-disable", "live-source", "live-retry":
		if s.liveAudit == nil {
			return c, "Live active audit is not wired up on this server"
		}
		v := s.liveAuditStatus()
		c.method, c.path, c.snapshot = http.MethodPost, "/api/scanner/live", true
		switch op {
		case "live-enable", "live-disable":
			on := op == "live-enable"
			if on == v.Enabled {
				return c, "nothing changed - the live audit is already " + map[bool]string{true: "on", false: "off"}[on]
			}
			c.body = map[string]any{"enabled": on}
			if on {
				c.title = "Switch the live active audit ON"
				c.consequences = []string{"Active attack probes will be sent automatically at newly captured in-scope traffic (source: " +
					v.TrafficSource + ") until it is switched off. Out-of-scope traffic is never audited."}
				c.done = "Live active audit is on."
			} else {
				c.title = "Switch the live active audit OFF"
				c.consequences = []string{"No further active checks are sent automatically; work already dispatched finishes."}
				c.done = "Live active audit is off."
			}
		case "live-source":
			src := r.PostFormValue("traffic_source")
			if src != string(LiveAuditSourceProxy) && src != string(LiveAuditSourceEverything) {
				return c, fmt.Sprintf("traffic source %q is not one of proxy or everything", src)
			}
			if src == v.TrafficSource {
				return c, "nothing changed - the live audit already admits " + src + " traffic"
			}
			c.body = map[string]any{"enabled": v.Enabled, "traffic_source": src}
			c.title = "Change the live audit's traffic source"
			c.consequences = []string{"proxy admits only your own proxied captures; everything admits any tool's in-scope captures (a crawl's discoveries are then audited as they land).",
				"The on/off switch is restated as it is now (" + strconv.FormatBool(v.Enabled) + "); if it changes before you confirm, the call is refused."}
			c.done = "Live audit traffic source set to " + src + "."
		case "live-retry":
			if v.StalledAt == nil {
				return c, "not stalled: the sweep is not waiting on any exchange right now"
			}
			c.body = map[string]any{"enabled": v.Enabled, "retry_stalled": true}
			c.title = fmt.Sprintf("Retry the stalled exchange #%d", *v.StalledAt)
			c.consequences = []string{"The sweep waits on the stalled exchange again with its stall budget carried, not restarted."}
			c.done = "Re-queued the stalled exchange."
		}
	case "secrets-on", "secrets-off":
		if s.passiveScanner == nil {
			return c, "No passive scanner is attached to this server, so there is nothing to switch"
		}
		on := op == "secrets-on"
		if on == s.passiveScanner.SecretDetection() {
			return c, "nothing changed - secret detection is already " + map[bool]string{true: "on", false: "off"}[on]
		}
		c.method, c.path, c.body = http.MethodPut, "/api/scanner/secrets", map[string]any{"enabled": on}
		c.title = "Switch secret detection " + map[bool]string{true: "ON", false: "OFF"}[on]
		c.consequences = []string{"Passive: it reads responses already captured and sends nothing. It applies to responses captured from now on and is saved with the project."}
		c.done = "Secret detection is " + map[bool]string{true: "on", false: "off"}[on] + "."
	case "lib-new", "lib-rename", "lib-delete", "lib-edit":
		if s.persist == nil {
			return c, "no database is attached, so a saved scan configuration would not survive this process; start burpsy with -db to use the configuration library"
		}
		c.method, c.path = http.MethodPost, "/api/scanner/configs"
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			return c, "a configuration must be named"
		}
		if _, shipped := scanner.BuiltInConfigByName(name); shipped && op != "lib-edit" {
			return c, strconv.Quote(name) + " is a configuration burpsy ships, which is read-only: pick another name"
		}
		_, exists := s.savedScanConfig(name)
		switch op {
		case "lib-new":
			from := strings.TrimSpace(r.PostFormValue("from"))
			c.body = map[string]any{"action": "clone", "name": name}
			src := "the settings this server audits under"
			if from != "" {
				if _, _, _, err := s.resolveAuditConfig(from); err != nil {
					return c, err.Error()
				}
				c.body["from"] = from
				src = strconv.Quote(from)
			}
			c.title = "Save " + strconv.Quote(name) + " as a copy of " + src
			if exists {
				c.consequences = append(c.consequences, "This REPLACES the saved configuration already named "+strconv.Quote(name)+".")
			}
			c.consequences = append(c.consequences, "Nothing runs; a later audit can be launched under this name.")
			c.done = "Saved " + name + "."
		case "lib-rename":
			from := strings.TrimSpace(r.PostFormValue("from"))
			if from == name {
				return c, "nothing changed - the new name is the current name"
			}
			if _, found := s.savedScanConfig(from); !found {
				return c, "no saved configuration is named " + strconv.Quote(from)
			}
			c.body = map[string]any{"action": "rename", "name": name, "from": from}
			c.title = "Rename " + strconv.Quote(from) + " to " + strconv.Quote(name)
			if exists {
				c.consequences = append(c.consequences, "This REPLACES the saved configuration already named "+strconv.Quote(name)+".")
			}
			c.done = "Renamed " + from + " to " + name + "."
		case "lib-delete":
			if !exists {
				return c, "no saved configuration is named " + strconv.Quote(name)
			}
			c.body = map[string]any{"action": "delete", "name": name}
			c.title = "Delete the saved configuration " + strconv.Quote(name)
			c.consequences = []string{"The configuration is removed from the library; findings and the audit history are not touched."}
			c.done = "Deleted " + name + "."
		case "lib-edit":
			if _, shipped := scanner.BuiltInConfigByName(name); shipped {
				return c, strconv.Quote(name) + " is a configuration burpsy ships, which is read-only: save a copy and edit that"
			}
			cfg, found := s.savedScanConfig(name)
			if !found {
				return c, "no saved configuration is named " + strconv.Quote(name)
			}
			rows := s.ui2IssueCatalogue()
			patch, changes, errText := ui2SelectionPatch(r, ui2DraftFrom(newAuditConfigView(cfg)), rows)
			if errText != "" {
				return c, errText
			}
			c.body = map[string]any{"action": "save", "name": name, "from": name, "settings": patch}
			c.title = "Save changes to " + strconv.Quote(name)
			keys := make([]string, 0, len(patch))
			for k := range patch {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			c.consequences = append(changes, "Writes "+strings.Join(keys, ", ")+"; every other setting of "+name+" stays as saved.")
			c.open = name
			c.done = "Saved " + name + "."
		}
	default:
		return c, fmt.Sprintf("unknown action %q", op)
	}
	return c, ""
}

// handleUI2ScannerReview serves POST /ui2/scanner/review: builds the op's exact call, holds it,
// and renders the review sheet whose projection is the held bytes.
func (s *Server) handleUI2ScannerReview(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	op := r.PostFormValue("op")
	model := map[string]any{"page": ui2ScanOpPage(op)}
	render := func() {
		title, view := ui2ScanConfigTitle, "scanconfig"
		if model["page"] == "library" {
			title, view = ui2ScanLibraryTitle, "scanlibrary"
		}
		ui2Fragment(w, r, title, view, ui2Exec("scanner_review.html", model))
	}
	call, errText := s.ui2ScanBuildCall(op, r)
	if errText != "" {
		model["error"] = ui2APIErrorText(errText)
		render()
		return
	}
	body, err := json.Marshal(call.body)
	if err != nil {
		model["error"] = "the call could not be encoded: " + err.Error()
		render()
		return
	}
	held := ui2ScanHeld{method: call.method, path: call.path, body: body, page: call.page, open: call.open,
		done: call.done, gated: ui2ScanGated(call.path)}
	if call.snapshot {
		held.snapshot = s.ui2LiveSnapshot()
	}
	if held.gated {
		token, _, mintErr := s.ui2MintConfirm(call.path, call.method, call.path, body)
		if mintErr == "" && token == "" {
			mintErr = "the confirmation gate refused to mint a review - try again"
		}
		if mintErr != "" {
			model["error"] = mintErr
			render()
			return
		}
		held.token = token
	} else {
		token, err := randomHex(16)
		if err != nil {
			model["error"] = "review token: " + err.Error()
			render()
			return
		}
		held.token = token
	}
	id, err := randomHex(16)
	if err != nil {
		model["error"] = "review id: " + err.Error()
		render()
		return
	}
	now := time.Now()
	count := 0
	s.ui2ScannerReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2ScanHeld); ok && now.After(e.expires) {
			s.ui2ScannerReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2ScanReviewCap {
		model["error"] = "too many reviews are open at once - confirm or let some expire, then try again"
		render()
		return
	}
	held.expires = now.Add(ConfirmTTL)
	s.ui2ScannerReviews.Store(id, held)
	model["title"] = call.title
	model["consequences"] = call.consequences
	model["projection"] = ui2ReviewProjection(call.method, call.path, body)
	model["gated"] = held.gated
	model["review_id"] = id
	model["token"] = held.token
	render()
}

// handleUI2ScannerReviewRun serves POST /ui2/scanner/review-run: spends the held review (any
// attempt deletes it), checks the token in constant time and the live switch for drift, and
// dispatches the held bytes verbatim.
func (s *Server) handleUI2ScannerReviewRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	page := r.PostFormValue("page")
	open := ""
	result := func(note, errText string) {
		s.ui2RenderScanPage(w, r, page, open, note, ui2APIErrorText(errText))
	}
	v, ok := s.ui2ScannerReviews.LoadAndDelete(r.PostFormValue("review_id"))
	held, isHeld := v.(ui2ScanHeld)
	if !ok || !isHeld {
		result("", "that review is unknown or was already used - review the change again")
		return
	}
	page, open = held.page, held.open
	if time.Now().After(held.expires) {
		result("", "that review expired with the confirmation window - review the change again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(held.token), []byte(r.PostFormValue("token"))) != 1 {
		result("", "that review does not match this confirmation - review the change again")
		return
	}
	if held.snapshot != "" && held.snapshot != s.ui2LiveSnapshot() {
		result("", "the live audit changed since this review (switched or re-sourced elsewhere) - review the change again")
		return
	}
	req := newReq(held.method, held.path)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(held.body)))
	rec := newRecorder()
	if held.gated {
		req.Header.Set(ConfirmHeader, held.token)
		req.Host = "127.0.0.1"
		req.Header.Set("Origin", "http://127.0.0.1")
		s.guarded.ServeHTTP(rec, req)
	} else {
		s.mux.ServeHTTP(rec, req)
	}
	if rec.Code == http.StatusPreconditionRequired {
		result("", "confirmation required (428) - the review and the dispatch disagree; review again")
		return
	}
	if rec.Code != http.StatusOK {
		result("", strings.TrimSpace(rec.Body.String()))
		return
	}
	result(held.done, "")
}

func (s *Server) ui2RenderScanPage(w http.ResponseWriter, r *http.Request, page, open, note, errText string) {
	if page == "library" {
		m := s.ui2ScanLibraryModel(open, "", "")
		m["note"], m["note_error"] = note, errText
		ui2Fragment(w, r, ui2ScanLibraryTitle, "scanlibrary", ui2Exec("scanner_library.html", m))
		return
	}
	m := s.ui2ScanConfigPageModel()
	m["note"], m["note_error"] = note, errText
	ui2Fragment(w, r, ui2ScanConfigTitle, "scanconfig", ui2Exec("scanner_config.html", m))
}

// ---- Configuration library -------------------------------------------------------------------

// handleUI2ScannerLibrary serves GET /ui2/scanner/library: the shipped and saved configurations,
// and with ?open=NAME the detail editor (q and filter narrow its issue-type list).
func (s *Server) handleUI2ScannerLibrary(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	m := s.ui2ScanLibraryModel(q.Get("open"), q.Get("q"), q.Get("filter"))
	ui2Fragment(w, r, ui2ScanLibraryTitle, "scanlibrary", ui2Exec("scanner_library.html", m))
}

func (s *Server) ui2ScanLibraryModel(open, q, filter string) map[string]any {
	m := map[string]any{"persisted": s.persist != nil, "open": open}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/scanner/configs"))
	var listing struct {
		Configs []struct {
			Name     string           `json:"name"`
			Shipped  bool             `json:"shipped"`
			Damaged  bool             `json:"damaged"`
			Keys     []map[string]any `json:"keys"`
			Resolved auditConfigView  `json:"resolved"`
		} `json:"configs"`
		Default         auditConfigView `json:"default"`
		ShippedByBurp   int             `json:"shipped_by_burp"`
		ImplementedHere int             `json:"implemented_here"`
		OmittedReason   string          `json:"omitted_reason"`
		AppliesTo       string          `json:"applies_to_server"`
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), &listing); err != nil {
		m["load_error"] = "the configuration listing could not be read: " + err.Error()
		return m
	}
	rows := []map[string]any{}
	names := []string{}
	for _, c := range listing.Configs {
		keys := []string{}
		for _, k := range c.Keys {
			if n, _ := k["name"].(string); n != "" {
				keys = append(keys, n)
			}
		}
		rows = append(rows, map[string]any{"name": c.Name, "shipped": c.Shipped, "damaged": c.Damaged,
			"key_count": len(keys), "keys": strings.Join(keys, ", "), "opened": c.Name == open})
		if !c.Damaged {
			names = append(names, c.Name)
		}
		if c.Name == open && !c.Damaged {
			m["detail"] = s.ui2ScanDetailModel(c.Name, c.Shipped, c.Resolved, q, filter)
		}
	}
	m["configs"] = rows
	m["names"] = names
	m["shipped_by_burp"] = listing.ShippedByBurp
	m["implemented_here"] = listing.ImplementedHere
	m["omitted_reason"] = listing.OmittedReason
	m["applies_to"] = listing.AppliesTo
	m["default"] = ui2ConfigSummary(listing.Default)
	if open != "" && m["detail"] == nil {
		m["open_error"] = "no readable configuration is named " + strconv.Quote(open)
	}
	return m
}

// ui2ConfigSummary is the read-only rows a configuration shows beside its editor.
func ui2ConfigSummary(v auditConfigView) []map[string]string {
	onOff := func(p *bool, unset string) string {
		if p == nil {
			return unset
		}
		if *p {
			return "on"
		}
		return "off"
	}
	secs := func(p *uint32, unset string) string {
		if p == nil {
			return unset
		}
		if *p == 0 {
			return "no limit"
		}
		return fmt.Sprintf("%d s", *p)
	}
	maxReq := "uncapped"
	if v.MaxRequests != nil {
		maxReq = strconv.FormatUint(uint64(*v.MaxRequests), 10)
	}
	sel := "every issue type"
	if len(v.IssueTypes) > 0 {
		sel = fmt.Sprintf("only %d selected issue types", len(v.IssueTypes))
	}
	return []map[string]string{
		{"label": "Time budget", "value": ui2Millis(v.TimeBudgetMs)},
		{"label": "Max requests", "value": maxReq},
		{"label": "Issue selection", "value": sel},
		{"label": "Issue types disabled", "value": strconv.Itoa(len(v.DisabledIssueTypes))},
		{"label": "Detection methods disabled", "value": strconv.Itoa(len(v.DisabledDetectionMethods))},
		{"label": "Follow redirections", "value": onOff(v.FollowRedirections, "not overridden")},
		{"label": "Connect timeout", "value": secs(v.ConnectTimeoutS, "not overridden")},
		{"label": "Normal timeout", "value": secs(v.NormalTimeoutS, "not overridden")},
		{"label": "JavaScript analysis", "value": onOff(v.JavaScriptAnalysis, "inherited")},
		{"label": "Static analysis", "value": onOff(v.JavaScriptStaticAnalysis, "on (unset)")},
		{"label": "Dynamic analysis", "value": onOff(v.JavaScriptDynamicAnalysis, "on (unset)")},
		{"label": "Max static time per item", "value": secs(v.MaxStaticTimePerItemS, "no limit (unset)")},
		{"label": "Max dynamic time per item", "value": secs(v.MaxDynamicTimePerItemS, "no limit (unset)")},
	}
}

// ui2IssueRow is one catalogue row (GET /api/scanner/issue-types).
type ui2IssueRow struct {
	TypeIndex          uint32   `json:"type_index"`
	Name               string   `json:"name"`
	DetectionMethods   []string `json:"detection_methods"`
	ImplementedMethods []string `json:"implemented_methods"`
}

func (s *Server) ui2IssueCatalogue() []ui2IssueRow {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/scanner/issue-types"))
	var out struct {
		IssueTypes []ui2IssueRow `json:"issue_types"`
	}
	_ = ui2DecodeJSON(rec.Body.Bytes(), &out)
	return out.IssueTypes
}

// ui2SelDraft is one configuration's per-issue selection and skip lists as an editable draft;
// the rules mirror the console's scan-selection draft (allow list, deny list, method deny list).
type ui2SelDraft struct {
	onlySelected    bool
	issueTypes      []uint32
	disabledTypes   []uint32
	disabledMethods []scanner.IssueDetectionMethod
	skipAll         []string
	skipServerSide  []string
}

func ui2DraftFrom(v auditConfigView) ui2SelDraft {
	return ui2SelDraft{
		onlySelected:    len(v.IssueTypes) > 0,
		issueTypes:      append([]uint32{}, v.IssueTypes...),
		disabledTypes:   append([]uint32{}, v.DisabledIssueTypes...),
		disabledMethods: append([]scanner.IssueDetectionMethod{}, v.DisabledDetectionMethods...),
		skipAll:         append([]string{}, v.SkipAllTestsForParameters...),
		skipServerSide:  append([]string{}, v.SkipServerSideInjectionForParameters...),
	}
}

func ui2HasU32(list []uint32, v uint32) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func ui2WithoutU32(list []uint32, v uint32) []uint32 {
	out := []uint32{}
	for _, e := range list {
		if e != v {
			out = append(out, e)
		}
	}
	return out
}

func (d ui2SelDraft) typeRuns(t uint32) bool {
	if ui2HasU32(d.disabledTypes, t) {
		return false
	}
	return !d.onlySelected || ui2HasU32(d.issueTypes, t)
}

func (d ui2SelDraft) setTypeRuns(t uint32, runs bool) ui2SelDraft {
	d.disabledTypes = ui2WithoutU32(d.disabledTypes, t)
	if runs {
		if d.onlySelected && !ui2HasU32(d.issueTypes, t) {
			d.issueTypes = append(append([]uint32{}, d.issueTypes...), t)
		}
		return d
	}
	if d.onlySelected {
		// Leaving the allow list is how a type stops running in this mode; it is not ALSO denied.
		d.issueTypes = ui2WithoutU32(d.issueTypes, t)
		return d
	}
	d.disabledTypes = append(d.disabledTypes, t)
	return d
}

func (d ui2SelDraft) methodEnabled(t uint32, m string) bool {
	for _, e := range d.disabledMethods {
		if e.TypeIndex == t && e.Method == m {
			return false
		}
	}
	return true
}

func (d ui2SelDraft) setMethodEnabled(t uint32, m string, on bool) ui2SelDraft {
	rest := []scanner.IssueDetectionMethod{}
	for _, e := range d.disabledMethods {
		if e.TypeIndex != t || e.Method != m {
			rest = append(rest, e)
		}
	}
	if !on {
		rest = append(rest, scanner.IssueDetectionMethod{TypeIndex: t, Method: m})
	}
	d.disabledMethods = rest
	return d
}

func (d ui2SelDraft) changed(row ui2IssueRow) bool {
	if !d.typeRuns(row.TypeIndex) {
		return true
	}
	for _, m := range row.DetectionMethods {
		if !d.methodEnabled(row.TypeIndex, m) {
			return true
		}
	}
	return false
}

func ui2SameU32Set(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]uint32{}, a...), append([]uint32{}, b...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	sort.Slice(y, func(i, j int) bool { return y[i] < y[j] })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func ui2SameMethods(a, b []scanner.IssueDetectionMethod) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[scanner.IssueDetectionMethod]bool{}
	for _, m := range a {
		set[m] = true
	}
	for _, m := range b {
		if !set[m] {
			return false
		}
	}
	return true
}

// ui2SkipList parses a parameter list: one name per line, duplicates matched case-insensitively.
func ui2SkipList(raw string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, n := range ui2TrimmedLines(raw) {
		if k := strings.ToLower(n); !seen[k] {
			seen[k] = true
			out = append(out, n)
		}
	}
	return out
}

// ui2SelectionPatch applies the detail form to the draft and returns the settings block holding
// only the keys that changed. Only rows the form rendered ("shown") are read, so a filtered view
// leaves every other row as saved.
func ui2SelectionPatch(r *http.Request, base ui2SelDraft, rows []ui2IssueRow) (map[string]any, []string, string) {
	d := base
	if want := r.PostFormValue("only_selected") == "on"; want != d.onlySelected {
		d.onlySelected, d.issueTypes = want, []uint32{}
	}
	byIdx := map[uint32]ui2IssueRow{}
	for _, row := range rows {
		byIdx[row.TypeIndex] = row
	}
	for _, raw := range r.PostForm["shown"] {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			continue
		}
		t := uint32(n)
		row, ok := byIdx[t]
		if !ok {
			continue
		}
		key := strconv.FormatUint(n, 10)
		if runs := r.PostFormValue("run_"+key) == "on"; runs != d.typeRuns(t) {
			d = d.setTypeRuns(t, runs)
		}
		on := map[string]bool{}
		for _, m := range r.PostForm["m_"+key] {
			on[m] = true
		}
		for _, m := range row.DetectionMethods {
			if on[m] != d.methodEnabled(t, m) {
				d = d.setMethodEnabled(t, m, on[m])
			}
		}
	}
	if ui2Present(r, "skip_all") {
		d.skipAll = ui2SkipList(r.PostFormValue("skip_all"))
	}
	if ui2Present(r, "skip_server_side") {
		d.skipServerSide = ui2SkipList(r.PostFormValue("skip_server_side"))
	}
	if d.onlySelected && len(d.issueTypes) == 0 {
		return nil, nil, "\"Run only the selected issue types\" is on and none is ticked. An empty selection means no restriction, so saving it would run every issue type - tick at least one, or switch it off."
	}
	allow := func(x ui2SelDraft) []uint32 {
		if x.onlySelected {
			return x.issueTypes
		}
		return []uint32{}
	}
	patch := map[string]any{}
	changes := []string{}
	if !ui2SameU32Set(allow(base), allow(d)) {
		patch["issue_types"] = allow(d)
		changes = append(changes, fmt.Sprintf("issue selection: %d -> %d selected types (0 = every type)", len(allow(base)), len(allow(d))))
	}
	if !ui2SameU32Set(base.disabledTypes, d.disabledTypes) {
		patch["disabled_issue_types"] = d.disabledTypes
		changes = append(changes, fmt.Sprintf("issue types disabled: %d -> %d", len(base.disabledTypes), len(d.disabledTypes)))
	}
	if !ui2SameMethods(base.disabledMethods, d.disabledMethods) {
		patch["disabled_detection_methods"] = d.disabledMethods
		changes = append(changes, fmt.Sprintf("detection methods switched off: %d -> %d", len(base.disabledMethods), len(d.disabledMethods)))
	}
	if !ui2SameStrings(base.skipAll, d.skipAll) {
		patch["skip_all_tests_for_parameters"] = d.skipAll
		changes = append(changes, "skip all tests for: ["+strings.Join(base.skipAll, ", ")+"] -> ["+strings.Join(d.skipAll, ", ")+"]")
	}
	if !ui2SameStrings(base.skipServerSide, d.skipServerSide) {
		patch["skip_server_side_injection_for_parameters"] = d.skipServerSide
		changes = append(changes, "skip server-side injection for: ["+strings.Join(base.skipServerSide, ", ")+"] -> ["+strings.Join(d.skipServerSide, ", ")+"]")
	}
	if len(patch) == 0 {
		return nil, nil, "nothing changed - the submitted selection matches the saved one"
	}
	return patch, changes, ""
}

// ui2ScanDetailModel is one configuration's detail editor: the issue catalogue narrowed by q and
// filter, each row's run state and methods, declines, skip lists and the read-only overrides.
func (s *Server) ui2ScanDetailModel(name string, shipped bool, v auditConfigView, q, filter string) map[string]any {
	d := ui2DraftFrom(v)
	catalogue := s.ui2IssueCatalogue()
	words := strings.Fields(strings.ToLower(q))
	shown := []map[string]any{}
	running := 0
	for _, row := range catalogue {
		runs := d.typeRuns(row.TypeIndex)
		if runs {
			running++
		}
		switch filter {
		case "running":
			if !runs {
				continue
			}
		case "not-running":
			if runs {
				continue
			}
		case "changed":
			if !d.changed(row) {
				continue
			}
		}
		hex := fmt.Sprintf("0x%08x", row.TypeIndex)
		if len(words) > 0 {
			name := strings.ToLower(row.Name)
			match := true
			for _, w := range words {
				if !strings.Contains(name, w) {
					match = false
					break
				}
			}
			dec := strconv.FormatUint(uint64(row.TypeIndex), 10)
			if !match && (len(words) != 1 || (words[0] != hex && words[0] != hex[2:] && words[0] != dec)) {
				continue
			}
		}
		methods := []map[string]any{}
		for _, m := range row.DetectionMethods {
			impl := false
			for _, im := range row.ImplementedMethods {
				if im == m {
					impl = true
				}
			}
			methods = append(methods, map[string]any{"name": m, "on": d.methodEnabled(row.TypeIndex, m), "implemented": impl})
		}
		shown = append(shown, map[string]any{"index": strconv.FormatUint(uint64(row.TypeIndex), 10), "hex": hex,
			"name": row.Name, "runs": runs, "methods": methods})
	}
	declines := []map[string]any{}
	for _, dc := range v.DeclinedDetectionMethods {
		issue := dc.Issue
		if issue == "" {
			issue = fmt.Sprintf("0x%08x", dc.TypeIndex)
		}
		declines = append(declines, map[string]any{"issue": issue, "method": dc.Method, "reason": dc.Reason})
	}
	return map[string]any{
		"name": name, "read_only": shipped, "only_selected": d.onlySelected,
		"rows": shown, "running": running, "total": len(catalogue), "shown": len(shown),
		"methods_off": len(d.disabledMethods), "q": q, "filter": filter,
		"filters": []map[string]any{
			{"value": "", "label": "All issue types", "selected": filter == ""},
			{"value": "running", "label": "Runs", "selected": filter == "running"},
			{"value": "not-running", "label": "Does not run", "selected": filter == "not-running"},
			{"value": "changed", "label": "Changed from the default", "selected": filter == "changed"},
		},
		"declines":         declines,
		"skip_all":         strings.Join(d.skipAll, "\n"),
		"skip_server_side": strings.Join(d.skipServerSide, "\n"),
		"summary":          ui2ConfigSummary(v),
	}
}
