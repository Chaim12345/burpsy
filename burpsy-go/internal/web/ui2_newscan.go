package web

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/apidoc"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- New scan: crawl launcher, audit selected, API-only scan, recorded logins ----------------
//
// GET /ui2/newscan renders one of four scan kinds; every write is POST /ui2/newscan/{kind}/{action}.
// Two review mechanisms, by what the body carries:
//   - crawl and audit-selected bodies carry no secret, so they use the gate review (flow A): the
//     sheet shows the FULL bound body and the run step rebuilds it from the carried form fields
//     with the same builder, so an edited field no longer matches the minted call.
//   - API-scan and recorded-login bodies can carry credentials (an auth method, a recorder script
//     with typed passwords), so they are held server-side (flow B): the sheet shows a redacted
//     projection of the held bytes and the run step dispatches those bytes verbatim, single-use.
//
// Gating is derived from the API route's own risk class, never assumed.

// ui2NewScanReviewCap bounds the held reviews (flow B), like the other ui2 review stores.
const ui2NewScanReviewCap = 8

// ui2NewScanReview is one held call: the exact method, path (with query) and bytes the run step
// dispatches, the gate token minted for them, and which area may spend it.
type ui2NewScanReview struct {
	area    string // "api" | "logins"
	method  string
	path    string
	body    []byte
	token   string
	gated   bool // the token is a gate token sent with the dispatch, not only a review secret
	expires time.Time
}

type ui2NewScanKind struct {
	ID, Title, Detail string
	Active            bool
}

var ui2NewScanKindList = []ui2NewScanKind{
	{ID: "crawl-audit", Title: "Crawl and audit", Detail: "Maps the attack surface, then audits what the crawl fetched"},
	{ID: "crawl", Title: "Crawl", Detail: "Maps the attack surface without auditing it"},
	{ID: "audit", Title: "Audit selected items", Detail: "Audits chosen captured exchanges as one task"},
	{ID: "api", Title: "API-only scan", Detail: "Sends the endpoints an API definition describes"},
}

// ui2Field is one carried form field (flow A): rendered as a hidden input on the review sheet.
type ui2Field struct{ Name, Value string }

// ui2NewScanCrawlFields is every crawl form field, in the order the builder reads them.
var ui2NewScanCrawlFields = []string{
	"kind", "seeds", "protocols", "scope_mode", "scope_include", "scope_exclude", "isolated",
	"config", "pool", "requests_per_second", "recorded_login", "login_page_pattern",
	"max_requests", "max_depth", "max_duration_secs",
	"max_locations", "max_frontier", "max_links_per_page", "max_parse_bytes", "max_template_visits",
	"max_capture_bytes", "max_fingerprints", "max_relogins",
	"pause_task_requests_timed_out_count", "pause_task_requests_timed_out_percentage",
	"consecutive_authentication_failures_before_pausing_task", "number_of_follow_up_passes",
	"seed_from_site_map", "request_well_known", "submit_forms", "interact", "fill_interaction_forms",
}

// ui2NewScanCrawlOptionalInts are the bounds sent only when filled; 0 is a real value for each.
var ui2NewScanCrawlOptionalInts = []string{
	"max_locations", "max_frontier", "max_links_per_page", "max_parse_bytes", "max_template_visits",
	"max_capture_bytes", "max_fingerprints", "max_relogins",
	"pause_task_requests_timed_out_count", "pause_task_requests_timed_out_percentage",
	"consecutive_authentication_failures_before_pausing_task", "number_of_follow_up_passes",
}

var ui2NewScanAuditFields = []string{"exchange_id", "exchange_ids", "config", "pool"}

// ui2SplitList splits a textarea of URLs or ids on whitespace and commas.
func ui2SplitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

func ui2CarryFields(r *http.Request, keys []string) []ui2Field {
	out := []ui2Field{}
	for _, k := range keys {
		for _, v := range r.PostForm[k] {
			out = append(out, ui2Field{Name: k, Value: v})
		}
	}
	return out
}

// ui2NewScanGated reports whether an internal API call needs a confirmation token, from the
// route's own risk class.
func ui2NewScanGated(apiPath string) bool {
	_, risk, ok := routeRiskFor(apiPath)
	return !ok || needsConfirmation(risk)
}

// ---- GET /ui2/newscan ---------------------------------------------------------------------------

func (s *Server) handleUI2NewScan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ui2Fragment(w, r, "burpsy /ui2/ — New scan", "newscan", ui2Exec("newscan.html", s.ui2NewScanModel(q.Get("kind"), q.Get("ids"))))
}

func (s *Server) ui2NewScanModel(kind, ids string) map[string]any {
	valid := false
	for _, k := range ui2NewScanKindList {
		valid = valid || k.ID == kind
	}
	if !valid {
		kind = "crawl-audit"
	}
	kinds := make([]ui2NewScanKind, 0, len(ui2NewScanKindList))
	for _, k := range ui2NewScanKindList {
		k.Active = k.ID == kind
		kinds = append(kinds, k)
	}
	model := map[string]any{"kind": kind, "kinds": kinds, "crawling": kind == "crawl" || kind == "crawl-audit"}
	configs, _ := s.ui2APIResult(http.MethodGet, "/api/scanner/configs", nil)
	pools, _ := s.ui2APIResult(http.MethodGet, "/api/pools", nil)
	crawls, _ := s.ui2APIResult(http.MethodGet, "/api/crawl", nil)
	model["configs"], model["pools"], model["crawls"] = configs, pools, crawls
	// The engine's own defaults, as placeholder text: every key present, so the template never
	// reads a missing one.
	defaults := map[string]string{}
	for _, k := range append([]string{"max_requests", "max_depth", "max_duration_secs"}, ui2NewScanCrawlOptionalInts...) {
		defaults[k] = "engine default"
	}
	if c, ok := crawls.(map[string]any); ok {
		if dl, ok := c["default_limits"].(map[string]any); ok {
			for k, v := range dl {
				if n, ok := v.(float64); ok {
					defaults[k] = "default (" + strconv.FormatFloat(n, 'f', -1, 64) + ")"
				}
			}
		}
	}
	model["defaults"] = defaults
	switch kind {
	case "audit":
		preset := map[uint64]bool{}
		for _, f := range ui2SplitList(ids) {
			if n, err := strconv.ParseUint(f, 10, 64); err == nil {
				preset[n] = true
			}
		}
		page := s.ui2HistoryPage(newReq(http.MethodGet, "/ui2/history"), ui2HistoryParams{Limit: 50})
		rows := make([]map[string]any, 0, len(page.Rows))
		for _, row := range page.Rows {
			rows = append(rows, map[string]any{"row": row, "checked": preset[row.ID]})
		}
		model["history"] = rows
		shown := map[uint64]bool{}
		for _, row := range page.Rows {
			shown[row.ID] = true
		}
		extra := []string{}
		for n := range preset {
			if !shown[n] {
				extra = append(extra, strconv.FormatUint(n, 10))
			}
		}
		sort.Strings(extra)
		model["preset_extra"] = strings.Join(extra, ", ")
		model["history_total"] = page.Matched
	case "api":
		model["api_check"] = ui2APICheckModel{Empty: true}
	default:
		model["logins"] = s.ui2NewScanLoginsModel("", "", nil)
	}
	return model
}

// ---- POST /ui2/newscan/{kind}/{action} ----------------------------------------------------------

func (s *Server) handleUI2NewScanAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var perr error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		perr = r.ParseMultipartForm(8 << 20)
	} else {
		perr = r.ParseForm()
	}
	if perr != nil {
		ui2NewScanWrite(w, "newscan_review.html", map[string]any{"error": "the form could not be read: " + perr.Error()})
		return
	}
	switch r.PathValue("kind") + "/" + r.PathValue("action") {
	case "crawl/confirm":
		payload, errText := ui2NewScanCrawlPayload(r)
		s.ui2NewScanGateReview(w, r, "crawl", "/api/crawl", payload, errText, ui2NewScanCrawlFields)
	case "crawl/run":
		payload, errText := ui2NewScanCrawlPayload(r)
		s.ui2NewScanGateRun(w, r, "crawl", "/api/crawl", payload, errText)
	case "audit/confirm":
		payload, errText := ui2NewScanAuditPayload(r)
		s.ui2NewScanGateReview(w, r, "audit", "/api/audit/selected", payload, errText, ui2NewScanAuditFields)
	case "audit/run":
		payload, errText := ui2NewScanAuditPayload(r)
		s.ui2NewScanGateRun(w, r, "audit", "/api/audit/selected", payload, errText)
	case "api/check":
		s.ui2NewScanAPICheck(w, r)
	case "api/fetch":
		s.ui2NewScanAPIFetch(w, r)
	case "api/confirm":
		s.ui2NewScanAPIConfirm(w, r)
	case "api/run":
		s.ui2NewScanHeldRun(w, r, "api")
	case "logins/confirm":
		s.ui2NewScanLoginConfirm(w, r)
	case "logins/run":
		s.ui2NewScanHeldRun(w, r, "logins")
	default:
		http.Error(w, "unknown new-scan action", http.StatusNotFound)
	}
}

func ui2NewScanWrite(w http.ResponseWriter, name string, model any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec(name, model)))
}

// ---- crawl ------------------------------------------------------------------------------------------

// ui2NewScanCrawlPayload builds the exact POST /api/crawl body from the crawl form. The confirm and
// run steps both call it, so the reviewed body is the dispatched body.
func ui2NewScanCrawlPayload(r *http.Request) (map[string]any, string) {
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	on := func(k string) bool { return r.PostFormValue(k) != "" }
	kind := f("kind")
	if kind != "crawl" && kind != "crawl-audit" {
		return nil, "the scan kind must be crawl or crawl-audit"
	}
	seeds := ui2SplitList(f("seeds"))
	if len(seeds) == 0 {
		return nil, "at least one URL to scan is required"
	}
	p := map[string]any{"kind": kind, "seeds": seeds}
	switch proto := f("protocols"); proto {
	case "both", "specified":
		p["protocols"] = proto
	case "":
	default:
		return nil, "protocol settings must be both or specified"
	}
	include, exclude := ui2SplitList(f("scope_include")), ui2SplitList(f("scope_exclude"))
	switch mode := f("scope_mode"); mode {
	case "", "engagement":
		if len(include) > 0 || len(exclude) > 0 {
			return nil, "include and exclude prefixes need the detailed scope (or seed directories, for excludes)"
		}
		p["scope"] = map[string]any{"mode": "engagement"}
	case "seed_directories":
		if len(include) > 0 {
			return nil, "include prefixes need the detailed scope configuration"
		}
		sc := map[string]any{"mode": mode}
		if len(exclude) > 0 {
			sc["exclude"] = exclude
		}
		p["scope"] = sc
	case "prefixes":
		if len(include) == 0 {
			return nil, "the detailed scope configuration needs at least one include prefix"
		}
		sc := map[string]any{"mode": mode, "include": include}
		if len(exclude) > 0 {
			sc["exclude"] = exclude
		}
		p["scope"] = sc
	default:
		return nil, "unknown crawl scope mode"
	}
	for _, k := range []string{"config", "pool", "recorded_login", "login_page_pattern"} {
		if v := f(k); v != "" {
			p[k] = v
		}
	}
	if v := f("requests_per_second"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n <= 0 {
			return nil, "requests per second must be a positive number"
		}
		p["requests_per_second"] = n
	}
	ints := append([]string{"max_requests", "max_depth", "max_duration_secs"}, ui2NewScanCrawlOptionalInts...)
	for _, k := range ints {
		v := f(k)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, k + " must be a whole number of 0 or more"
		}
		p[k] = n
	}
	for _, k := range []string{"isolated", "seed_from_site_map", "request_well_known"} {
		if on(k) {
			p[k] = true
		}
	}
	p["submit_forms"] = on("submit_forms")
	p["interact"] = on("interact")
	p["fill_interaction_forms"] = on("interact") && on("fill_interaction_forms")
	return p, ""
}

// ---- audit selected ------------------------------------------------------------------------------

func ui2NewScanAuditPayload(r *http.Request) (map[string]any, string) {
	ids := []uint64{}
	raw := append([]string{}, r.PostForm["exchange_id"]...)
	raw = append(raw, ui2SplitList(r.PostFormValue("exchange_ids"))...)
	for _, v := range raw {
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return nil, fmt.Sprintf("%q is not an exchange id", v)
		}
		ids = append(ids, n)
	}
	if len(ids) == 0 {
		return nil, "select at least one exchange: an audit of nothing is not a scan"
	}
	p := map[string]any{"exchange_ids": ids}
	for _, k := range []string{"config", "pool"} {
		if v := strings.TrimSpace(r.PostFormValue(k)); v != "" {
			p[k] = v
		}
	}
	return p, ""
}

// ---- flow A: gate review with the full body ------------------------------------------------------

func (s *Server) ui2NewScanGateReview(w http.ResponseWriter, r *http.Request, what, apiPath string, payload map[string]any, errText string, keys []string) {
	model := map[string]any{"what": what, "run": "/ui2/newscan/" + what + "/run"}
	if errText != "" {
		model["error"] = errText
		ui2NewScanWrite(w, "newscan_review.html", model)
		return
	}
	body, _ := ui2Marshal(payload)
	model["preview"] = http.MethodPost + " " + apiPath
	// The FULL bound body, not ui2MintConfirm's abbreviated preview: the sheet says it covers
	// exactly this call, so it shows every byte the token binds.
	model["full_body"] = string(body)
	model["fields"] = ui2CarryFields(r, keys)
	if ui2NewScanGated(apiPath) {
		token, _, mintErr := s.ui2MintConfirm(apiPath, http.MethodPost, apiPath, body)
		if mintErr != "" || token == "" {
			model["error"] = "the confirmation gate refused to mint a review: " + mintErr
			ui2NewScanWrite(w, "newscan_review.html", model)
			return
		}
		model["token"] = token
	}
	ui2NewScanWrite(w, "newscan_review.html", model)
}

func (s *Server) ui2NewScanGateRun(w http.ResponseWriter, r *http.Request, what, apiPath string, payload map[string]any, errText string) {
	model := map[string]any{"what": what}
	if errText != "" {
		model["error"] = errText
	} else {
		result, derr := s.ui2DispatchConfirmed(http.MethodPost, apiPath, payload, r.PostFormValue("token"))
		model["result"], model["error"] = result, ui2APIErrorText(derr)
	}
	ui2NewScanWrite(w, "newscan_result.html", model)
}

// ---- flow B: server-held reviews -----------------------------------------------------------------

// ui2NewScanHold mints a gate token for the exact call (when its route is gated) and holds the
// call for one spend. It returns the review id and token, or a refusal.
func (s *Server) ui2NewScanHold(area, apiPattern, method, path string, body []byte) (string, string, string) {
	now := time.Now()
	count := 0
	s.ui2NewScanReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2NewScanReview); ok && now.After(e.expires) {
			s.ui2NewScanReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2NewScanReviewCap {
		return "", "", "too many reviews are open at once - confirm or let some expire, then try again"
	}
	token, gated := "", ui2NewScanGated(apiPattern)
	if gated {
		// Only the token is kept: the mint's echoed preview can carry a credential.
		t, _, errText := s.ui2MintConfirm(apiPattern, method, path, body)
		if errText != "" || t == "" {
			return "", "", "the confirmation gate refused to mint a review - try again"
		}
		token = t
	} else {
		t, err := randomHex(16)
		if err != nil {
			return "", "", "review token: " + err.Error()
		}
		token = t
	}
	id, err := randomHex(16)
	if err != nil {
		return "", "", "review id: " + err.Error()
	}
	s.ui2NewScanReviews.Store(id, ui2NewScanReview{area: area, method: method, path: path, body: body, token: token, gated: gated, expires: now.Add(ConfirmTTL)})
	return id, token, ""
}

// ui2NewScanHeldRun spends one held review: deleted on any attempt, refused when stale, from the
// wrong area, or when the token does not match; otherwise the held bytes are dispatched verbatim.
func (s *Server) ui2NewScanHeldRun(w http.ResponseWriter, r *http.Request, area string) {
	fail := func(msg string) {
		if area == "logins" {
			ui2NewScanWrite(w, "newscan_logins.html", s.ui2NewScanLoginsModel(msg, "", nil))
			return
		}
		ui2NewScanWrite(w, "newscan_result.html", map[string]any{"what": area, "error": msg})
	}
	v, ok := s.ui2NewScanReviews.LoadAndDelete(r.PostFormValue("review_id"))
	entry, isReview := v.(ui2NewScanReview)
	if !ok || !isReview || entry.area != area {
		fail("that review is unknown or was already used - review again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired with the confirmation window - review again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostFormValue("token"))) != 1 {
		fail("that review does not match this confirmation - review again")
		return
	}
	token := ""
	if entry.gated {
		token = entry.token
	}
	result, errText := s.ui2NewScanDispatchRaw(entry.method, entry.path, entry.body, token)
	if area == "logins" {
		done := ""
		var replay any
		if errText == "" {
			switch {
			case entry.method == http.MethodDelete:
				done = "Recorded login removed."
			case strings.HasPrefix(entry.path, "/api/crawl/logins/replay"):
				done, replay = "Replay finished.", ui2NewScanReplayView(result)
			default:
				done = "Recorded login saved."
			}
		}
		ui2NewScanWrite(w, "newscan_logins.html", s.ui2NewScanLoginsModel(ui2APIErrorText(errText), done, replay))
		return
	}
	ui2NewScanWrite(w, "newscan_result.html", map[string]any{"what": area, "result": result, "error": ui2APIErrorText(errText)})
}

// ui2NewScanDispatchRaw sends held bytes through both gates unchanged (a re-marshal could produce
// bytes the token was not minted for).
func (s *Server) ui2NewScanDispatchRaw(method, path string, body []byte, token string) (any, string) {
	req := newReq(method, path)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(body)))
	}
	if token != "" {
		req.Header.Set(ConfirmHeader, token)
	}
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code == http.StatusPreconditionRequired {
		return nil, "confirmation required (428) - the review and the dispatch disagree; review again"
	}
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		return nil, truncateForDisplay(strings.TrimSpace(rec.Body.String()), 600)
	}
	var result any
	if err := ui2DecodeJSON(rec.Body.Bytes(), &result); err != nil {
		return nil, "unreadable response: " + err.Error()
	}
	return result, ""
}

// ---- API-only scan --------------------------------------------------------------------------------

// ui2APICheckModel is the API definition's live validation: the unreviewed parse, the review tables
// (state carried in form fields) and the server's verdict on the review.
type ui2APICheckModel struct {
	Empty     bool
	Error     string
	Summary   *apiScanSummary
	Endpoints []ui2APIEndpointRow
	Rows      []ui2APIParamRow
	Shared    []string // JSON of the shared (all-endpoints) overrides, carried as hidden fields
	Excluded  []string
	Kept      int
	Stale     []string
	Missing   string
	ReviewErr string
	Filtered  int
	// Definition is set when the definition came from an upload, so the textarea is refreshed.
	Definition    string
	DefinitionSet bool
	FileName      string
}

type ui2APIEndpointRow struct {
	Key, Method, Template, Request string
	Params                         int
	Removed                        bool
}

type ui2APIParamRow struct {
	Index                                       int
	Key, Endpoint, In, Name, DocValue, Source   string
	Type, Value, Mode, Scope, Locked, PrevValue string
	Required, Hidden                            bool
}

type ui2APIPosted struct {
	endpoint, in, name             string
	value, mode, scope             string
	prevValue, prevMode, prevScope string
	locked                         bool
}

func ui2APIOverrideID(endpoint, in, name string) string {
	b, _ := json.Marshal([]string{endpoint, in, name})
	return string(b)
}

// ui2NewScanAPIBuild reads the API form into the exact POST /api/apiscan body and the check model.
// The body is nil when something is missing or refused; the model says why.
func (s *Server) ui2NewScanAPIBuild(r *http.Request) ([]byte, ui2APICheckModel) {
	m := ui2APICheckModel{}
	definition := r.PostFormValue("definition")
	if r.MultipartForm != nil {
		if fhs := r.MultipartForm.File["definition_file"]; len(fhs) > 0 && fhs[0].Size > 0 {
			fh := fhs[0]
			file, err := fh.Open()
			if err == nil {
				raw, rerr := io.ReadAll(io.LimitReader(file, maxRequestBodyBytes))
				_ = file.Close()
				if rerr == nil {
					definition = string(raw)
					m.Definition, m.DefinitionSet, m.FileName = definition, true, fh.Filename
				}
			}
		}
	}
	if strings.TrimSpace(definition) == "" {
		m.Empty = true
		m.Missing = "Paste or load an API definition first."
		return nil, m
	}
	base := strings.TrimSpace(r.PostFormValue("base_url"))
	sum, err := s.checkAPIScan(apiScanReq{Definition: definition, BaseURL: base})
	if err != nil {
		m.Error = err.Error()
		m.Missing = "The definition was refused; see the message above."
		return nil, m
	}
	m.Summary = sum
	known := map[string]bool{}
	carries := map[[2]string]bool{}
	type pkey = [3]string
	docParam := map[pkey]apidoc.Parameter{}
	for _, op := range sum.Operations {
		known[op.Key] = true
		for _, p := range op.Parameters {
			carries[[2]string{p.In, p.Name}] = true
			docParam[pkey{op.Key, p.In, p.Name}] = p
		}
	}

	// Endpoints: posted exclusions, then this request's toggle or restore-all.
	excluded := map[string]bool{}
	for _, k := range r.PostForm["exclude"] {
		if known[k] {
			excluded[k] = true
		} else {
			m.Stale = append(m.Stale, "excluded endpoint "+k)
		}
	}
	if t := r.PostFormValue("toggle"); known[t] {
		excluded[t] = !excluded[t]
	}
	if r.PostFormValue("restore_all") != "" {
		excluded = map[string]bool{}
	}

	// Parameters: the previous shared overrides, then each posted row's edit.
	shared := map[[2]string]apiScanParamOverride{}
	for _, raw := range r.PostForm["shared"] {
		var o apiScanParamOverride
		if json.Unmarshal([]byte(raw), &o) == nil && o.Endpoint == "" && o.Name != "" {
			shared[[2]string{o.In, o.Name}] = o
		}
	}
	var posted []ui2APIPosted
	for i := 0; ; i++ {
		idx := strconv.Itoa(i)
		key := r.PostFormValue("pk_" + idx)
		if key == "" {
			break
		}
		var id []string
		if json.Unmarshal([]byte(key), &id) != nil || len(id) != 3 {
			continue
		}
		p := ui2APIPosted{endpoint: id[0], in: id[1], name: id[2],
			value: r.PostFormValue("pv_" + idx), mode: r.PostFormValue("pm_" + idx), scope: r.PostFormValue("ps_" + idx),
			prevValue: r.PostFormValue("ppv_" + idx), prevMode: r.PostFormValue("ppm_" + idx), prevScope: r.PostFormValue("pps_" + idx)}
		p.locked = p.scope == ""
		if p.mode != "fixed" {
			p.mode = "dynamic"
		}
		posted = append(posted, p)
	}
	if ri, err := strconv.Atoi(r.PostFormValue("reset")); err == nil && ri >= 0 && ri < len(posted) {
		p := &posted[ri]
		if p.prevScope == "all" {
			delete(shared, [2]string{p.in, p.name})
			for j := range posted {
				if posted[j].in == p.in && posted[j].name == p.name && posted[j].prevScope == "all" {
					posted[j].locked = true // drop with the shared value
				}
			}
		}
		p.locked = true // its own override is dropped by not re-adding it
	}
	specific := map[pkey]apiScanParamOverride{}
	touched := map[[2]string]bool{}
	for _, p := range posted {
		if p.locked {
			continue
		}
		k := pkey{p.endpoint, p.in, p.name}
		doc, ok := docParam[k]
		if !ok {
			m.Stale = append(m.Stale, fmt.Sprintf("%s parameter %q on %s", p.in, p.name, p.endpoint))
			continue
		}
		pair := [2]string{p.in, p.name}
		if p.scope == "all" {
			changed := p.prevScope != "all" || p.value != p.prevValue || p.mode != p.prevMode
			if changed && !touched[pair] {
				shared[pair] = apiScanParamOverride{In: p.in, Name: p.name, Value: p.value, Mode: p.mode}
				touched[pair] = true
			}
			continue
		}
		if p.prevScope == "all" || p.value != doc.Value || p.mode == "fixed" {
			specific[k] = apiScanParamOverride{Endpoint: p.endpoint, In: p.in, Name: p.name, Value: p.value, Mode: p.mode}
		}
	}
	for pair := range shared {
		if !carries[pair] {
			m.Stale = append(m.Stale, fmt.Sprintf("%s parameter %q (all endpoints)", pair[0], pair[1]))
			delete(shared, pair)
		}
	}

	// The tables, with the governing override folded into each row.
	needle := strings.ToLower(strings.TrimSpace(r.PostFormValue("param_filter")))
	for _, op := range sum.Operations {
		removed := excluded[op.Key]
		m.Endpoints = append(m.Endpoints, ui2APIEndpointRow{Key: op.Key, Method: op.Method, Template: op.Template,
			Request: op.Path, Params: len(op.Parameters), Removed: removed})
		if !removed {
			m.Kept++
		}
		for _, p := range op.Parameters {
			row := ui2APIParamRow{Index: len(m.Rows), Key: ui2APIOverrideID(op.Key, p.In, p.Name), Endpoint: op.Key,
				In: p.In, Name: p.Name, DocValue: p.Value, Source: string(p.Source), Type: p.Type, Required: p.Required,
				Value: p.Value, Mode: "dynamic", Scope: "document"}
			if o, ok := specific[pkey{op.Key, p.In, p.Name}]; ok {
				row.Value, row.Mode, row.Scope = o.Value, o.Mode, "endpoint"
			} else if o, ok := shared[[2]string{p.In, p.Name}]; ok {
				row.Value, row.Mode, row.Scope = o.Value, o.Mode, "all"
			}
			row.PrevValue = row.Value
			row.Locked = ui2APILockReason(sum.Format, p.In)
			if row.Locked != "" {
				row.Value, row.Mode, row.Scope = p.Value, "dynamic", "document"
			}
			hay := strings.ToLower(op.Key + " " + p.In + " " + p.Name + " " + row.Value)
			row.Hidden = removed || (needle != "" && !strings.Contains(hay, needle))
			if needle != "" && !removed && row.Hidden {
				m.Filtered++
			}
			m.Rows = append(m.Rows, row)
		}
	}
	for _, o := range shared {
		b, _ := json.Marshal(o)
		m.Shared = append(m.Shared, string(b))
	}
	sort.Strings(m.Shared)
	for k := range excluded {
		if excluded[k] {
			m.Excluded = append(m.Excluded, k)
		}
	}
	sort.Strings(m.Excluded)

	// The body: exclusions, shared overrides first then endpoint ones (the server applies them in
	// order), the auth method, the cap and the audit switch. Overrides only excluded endpoints
	// carry are held in the form but not sent.
	body := map[string]any{"definition": definition}
	if base != "" {
		body["base_url"] = base
	}
	if len(m.Excluded) > 0 {
		body["exclude_endpoints"] = m.Excluded
	}
	keptCarries := func(o apiScanParamOverride) bool {
		for _, op := range sum.Operations {
			if excluded[op.Key] || (o.Endpoint != "" && op.Key != o.Endpoint) {
				continue
			}
			for _, p := range op.Parameters {
				if p.In == o.In && p.Name == o.Name {
					return true
				}
			}
		}
		return false
	}
	var params []apiScanParamOverride
	var sharedList, specificList []apiScanParamOverride
	for _, o := range shared {
		if keptCarries(o) {
			sharedList = append(sharedList, o)
		}
	}
	for _, o := range specific {
		if keptCarries(o) {
			specificList = append(specificList, o)
		}
	}
	byName := func(l []apiScanParamOverride) {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Endpoint != l[j].Endpoint {
				return l[i].Endpoint < l[j].Endpoint
			}
			if l[i].In != l[j].In {
				return l[i].In < l[j].In
			}
			return l[i].Name < l[j].Name
		})
	}
	byName(sharedList)
	byName(specificList)
	params = append(append(params, sharedList...), specificList...)
	if len(params) > 0 {
		body["parameters"] = params
	}
	f := func(k string) string { return r.PostFormValue(k) }
	switch at := f("auth_type"); at {
	case "", "none":
	case "basic":
		if strings.TrimSpace(f("auth_username")) == "" {
			m.Missing = "Basic authentication needs a username."
		}
		body["auth"] = map[string]any{"type": at, "username": f("auth_username"), "password": f("auth_password")}
	case "bearer":
		if f("auth_token") == "" {
			m.Missing = "Bearer authentication needs a token."
		}
		body["auth"] = map[string]any{"type": at, "token": f("auth_token")}
	case "header":
		if strings.TrimSpace(f("auth_name")) == "" {
			m.Missing = "Header authentication needs a header name."
		}
		body["auth"] = map[string]any{"type": at, "name": strings.TrimSpace(f("auth_name")), "value": f("auth_value")}
	default:
		m.Missing = "Unknown authentication method."
	}
	if v := strings.TrimSpace(f("max_requests")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			m.Missing = "Max requests must be a whole number of 1 or more, or empty for one per endpoint."
		} else {
			body["max_requests"] = n
		}
	}
	body["audit"] = f("audit") != ""
	if m.Kept == 0 {
		m.Missing = "Every endpoint is removed. Restore at least one to scan."
	}
	if m.Missing != "" {
		return nil, m
	}
	raw, _ := json.Marshal(body)
	// The server's verdict on the review, from the same prepareAPIScan the launch runs. A dry run
	// sends nothing, so it is read in-process rather than through the gated route.
	var reviewed apiScanReq
	if err := json.Unmarshal(raw, &reviewed); err == nil {
		if rsum, err := s.checkAPIScan(reviewed); err != nil {
			m.ReviewErr = err.Error()
			m.Missing = "The review was refused; see the message above."
			return nil, m
		} else {
			paths := map[string]string{}
			for _, op := range rsum.Operations {
				paths[op.Key] = op.Path
			}
			for i := range m.Endpoints {
				if p, ok := paths[m.Endpoints[i].Key]; ok {
					m.Endpoints[i].Request = p
				}
			}
		}
	}
	return raw, m
}

// ui2APILockReason mirrors the server's refusals: only path/query/header/formData values are
// re-rendered, and a Postman path variable is set in the collection.
func ui2APILockReason(format, in string) string {
	switch in {
	case "path", "query", "header", "formData":
	default:
		return "A " + in + " parameter cannot be overridden."
	}
	if in == "path" && format == string(apidoc.FormatPostman) {
		return "A Postman path variable is set in the collection, not here."
	}
	return ""
}

// ui2NewScanAPICheck is the live validation: the review tables re-render into #apicheck; a newly
// uploaded definition also refreshes the definition box (out of band). Nothing is sent.
func (s *Server) ui2NewScanAPICheck(w http.ResponseWriter, r *http.Request) {
	_, m := s.ui2NewScanAPIBuild(r)
	ui2NewScanWrite(w, "newscan_api_check.html", m)
}

// ui2NewScanAPIFetch is Upload from URL: POST /api/apiscan/fetch (riskEgress: ungated, one bounded
// fetch, scope-checked by the API). The fetched document fills the definition box out of band.
func (s *Server) ui2NewScanAPIFetch(w http.ResponseWriter, r *http.Request) {
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	req := map[string]any{"url": f("fetch_url")}
	switch at := f("fetch_auth_type"); at {
	case "", "none":
	case "basic":
		req["auth"] = map[string]any{"type": at, "username": f("fetch_username"), "password": r.PostFormValue("fetch_password")}
	case "bearer":
		req["auth"] = map[string]any{"type": at, "token": r.PostFormValue("fetch_token")}
	case "oauth2_client_credentials":
		req["auth"] = map[string]any{"type": at, "token_url": f("fetch_token_url"), "client_id": f("fetch_client_id"),
			"client_secret": r.PostFormValue("fetch_client_secret"), "scope": f("fetch_scope")}
	default:
		ui2NewScanWrite(w, "newscan_api_fetch.html", map[string]any{"error": "unknown fetch authentication"})
		return
	}
	model := map[string]any{}
	if f("fetch_url") == "" {
		model["error"] = "enter the definition's URL"
		ui2NewScanWrite(w, "newscan_api_fetch.html", model)
		return
	}
	if ui2NewScanGated("/api/apiscan/fetch") {
		// Not expected (riskEgress); if the class ever changes the page refuses rather than mints.
		model["error"] = "fetching a definition now needs a confirmation this page does not offer"
		ui2NewScanWrite(w, "newscan_api_fetch.html", model)
		return
	}
	result, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/apiscan/fetch", req, "")
	if errText != "" {
		model["error"] = ui2APIErrorText(errText)
	} else {
		model["result"] = result
		if m, ok := result.(map[string]any); ok {
			if def, _ := m["definition"].(string); def != "" {
				model["definition"] = def
			}
		}
	}
	ui2NewScanWrite(w, "newscan_api_fetch.html", model)
}

// ui2NewScanAPIConfirm holds the exact POST /api/apiscan body (flow B) and renders its projection
// with the authentication secret redacted.
func (s *Server) ui2NewScanAPIConfirm(w http.ResponseWriter, r *http.Request) {
	body, m := s.ui2NewScanAPIBuild(r)
	model := map[string]any{"what": "api"}
	if body == nil {
		msg := m.Missing
		if m.Error != "" {
			msg = m.Error
		} else if m.ReviewErr != "" {
			msg = m.ReviewErr
		}
		model["error"] = msg
		ui2NewScanWrite(w, "newscan_api_review.html", model)
		return
	}
	id, token, errText := s.ui2NewScanHold("api", "/api/apiscan", http.MethodPost, "/api/apiscan", body)
	if errText != "" {
		model["error"] = errText
		ui2NewScanWrite(w, "newscan_api_review.html", model)
		return
	}
	model["review_id"], model["token"] = id, token
	model["projection"] = ui2NewScanAPIProjection(body)
	model["kept"], model["total"] = m.Kept, len(m.Endpoints)
	var req apiScanReq
	_ = json.Unmarshal(body, &req)
	model["audit"] = req.Audit != nil && *req.Audit
	model["auth"] = req.Auth != nil
	model["base_url"] = m.Summary.BaseURL
	ui2NewScanWrite(w, "newscan_api_review.html", model)
}

// ui2NewScanAPIProjection renders the held bytes with the auth method's secret values blanked: the
// projection is derived from what the token binds, not from a second read of the form.
func ui2NewScanAPIProjection(body []byte) string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return "POST /api/apiscan (body unreadable for display)"
	}
	if auth, ok := m["auth"].(map[string]any); ok {
		for _, k := range []string{"password", "token", "value"} {
			if v, _ := auth[k].(string); v != "" {
				auth[k] = "«redacted: bound in the token, not shown»"
			}
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(m)
	return "POST /api/apiscan\n" + buf.String()
}

// ---- recorded logins ------------------------------------------------------------------------------

func (s *Server) ui2NewScanLoginsModel(note, done string, replay any) map[string]any {
	logins, errText := s.ui2APIResult(http.MethodGet, "/api/crawl/logins", nil)
	return map[string]any{"logins": logins, "load_error": errText, "note": note, "done": done, "replay": replay}
}

// ui2NewScanLoginConfirm holds one recorded-login call (save, delete or replay). A save's script
// carries typed passwords, so its projection replaces the script with the secret-free steps it
// imports to.
func (s *Server) ui2NewScanLoginConfirm(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	fail := func(msg string) {
		model["error"] = msg
		ui2NewScanWrite(w, "newscan_login_review.html", model)
	}
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	var method, path, pattern string
	var body []byte
	switch op := f("op"); op {
	case "save":
		script := r.PostFormValue("script")
		imp, err := session.ImportScript([]byte(script))
		if err != nil {
			fail("the script cannot be imported: " + err.Error())
			return
		}
		payload := map[string]any{"label": f("label"), "script": script}
		if u, t := f("check_url"), f("check_text"); u != "" || t != "" {
			payload["status_check"] = map[string]any{"url": u, "text": t}
		}
		body, _ = json.Marshal(payload)
		method, path, pattern = http.MethodPost, "/api/crawl/logins", "/api/crawl/logins"
		preview := (&session.RecordedLogin{Steps: imp.Steps}).View()
		steps := make([]string, 0, len(preview.Steps))
		for _, st := range preview.Steps {
			steps = append(steps, st.Description)
		}
		label := f("label")
		if label == "" {
			label = imp.Name
		}
		redacted := map[string]any{"label": f("label"), "script": fmt.Sprintf("«%d-byte %s script, redacted: typed values are bound in the token, not shown»", len(script), imp.Format)}
		if sc, ok := payload["status_check"]; ok {
			redacted["status_check"] = sc
		}
		proj, _ := json.MarshalIndent(redacted, "", "  ")
		model["op"], model["label"], model["steps"], model["notes"], model["format"] = op, label, steps, imp.Notes, imp.Format
		model["projection"] = "POST /api/crawl/logins\n" + string(proj)
	case "delete", "replay":
		id := f("id")
		if id == "" {
			fail("choose a recorded login")
			return
		}
		label, found := s.ui2NewScanLoginLabel(id)
		if !found {
			fail("no recorded login with that id - it may have been removed")
			return
		}
		model["op"], model["label"] = op, label
		if op == "delete" {
			method, pattern = http.MethodDelete, "/api/crawl/logins"
			path = "/api/crawl/logins?id=" + url.QueryEscape(id)
			model["projection"] = method + " " + path + " (no body)"
		} else {
			method, path, pattern = http.MethodPost, "/api/crawl/logins/replay", "/api/crawl/logins/replay"
			body, _ = json.Marshal(map[string]any{"id": id})
			model["projection"] = method + " " + path + "\n" + string(body)
		}
	default:
		fail("unknown recorded-login action")
		return
	}
	id, token, errText := s.ui2NewScanHold("logins", pattern, method, path, body)
	if errText != "" {
		fail(errText)
		return
	}
	model["review_id"], model["token"] = id, token
	ui2NewScanWrite(w, "newscan_login_review.html", model)
}

func (s *Server) ui2NewScanLoginLabel(id string) (string, bool) {
	res, _ := s.ui2APIResult(http.MethodGet, "/api/crawl/logins", nil)
	m, _ := res.(map[string]any)
	list, _ := m["logins"].([]any)
	for _, it := range list {
		if l, ok := it.(map[string]any); ok && l["id"] == id {
			label, _ := l["label"].(string)
			return label, true
		}
	}
	return "", false
}

// ui2NewScanReplayView keeps the replay result and turns its screenshot into an image URL only
// when it is exactly a base64 JPEG data URL the server produced.
func ui2NewScanReplayView(result any) any {
	m, ok := result.(map[string]any)
	if !ok {
		return result
	}
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	delete(out, "screenshot")
	const prefix = "data:image/jpeg;base64,"
	if shot, _ := m["screenshot"].(string); strings.HasPrefix(shot, prefix) {
		if _, err := base64.StdEncoding.DecodeString(shot[len(prefix):]); err == nil {
			out["screenshot_url"] = template.URL(shot) //nolint:gosec // validated base64 JPEG data URL
		}
	}
	return out
}
