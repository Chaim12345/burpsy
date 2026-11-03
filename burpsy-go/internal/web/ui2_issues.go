package web

// ui2 Issues triage (unit 11): the issue detail's triage actions, the list filter, the
// consolidation policy page and the report-settings page.
//
// Every write is a two-step reviewed call, and the mechanism follows the API route's own risk
// class (needsConfirmation(routeRiskFor(path))), never a choice made here:
//   - gated calls (PUT/DELETE /api/issues/{id}, POST /api/issues/{id}/triage - the subtree is
//     riskDestructive): the confirm step mints a gate token for the exact call and renders the
//     full bound body; the run step rebuilds the call from the sheet's hidden fields with the SAME
//     builder (ui2IssueActionCall) and dispatches through the guarded chain, so a tampered field
//     fails the token digest.
//   - ungated calls (POST /api/issues/triage, PUT /api/issues/consolidation - riskLocal): the
//     confirm step holds the exact bytes server-side (capped, single-use, ConfirmTTL) and the run
//     dispatches them verbatim; the run form carries only the review id and token.

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- shared review engine (issues, consolidation, audit queue) --------------------------------

// ui2Call is one exact internal API call a page wants to make. Payload nil means no body; the
// body bytes are json.Marshal(Payload), which is deterministic (sorted keys), so the confirm and
// run steps of a gated call produce identical bytes from the same builder.
type ui2Call struct {
	Method       string
	Path         string
	Payload      map[string]any
	Title        string
	Consequences []string
	// Snapshot and Reread make a whole-document write refuse on drift: the run re-reads the
	// state and refuses when it no longer matches what the review was drawn against.
	Snapshot string
	Reread   func() string
}

func (c ui2Call) body() []byte {
	if c.Payload == nil {
		return nil
	}
	b, _ := json.Marshal(c.Payload)
	return b
}

// dispatchPayload returns an untyped nil for a bodyless call: a typed nil map in an interface
// would marshal to "null" and change the bound body.
func (c ui2Call) dispatchPayload() any {
	if c.Payload == nil {
		return nil
	}
	return c.Payload
}

// ui2CallGate resolves the call's route pattern and whether the confirmation gate covers it.
func ui2CallGate(path string) (string, bool) {
	pattern, risk, ok := routeRiskFor(path)
	return pattern, ok && needsConfirmation(risk)
}

// ui2Field is one hidden field a gated review carries so the run can rebuild the call.
type ui2Field struct{ Name, Value string }

// ui2ReviewModel is the model for issues_review.html, shared by every page in this unit.
type ui2ReviewModel struct {
	Error        string
	Done         string
	Title        string
	Consequences []string
	Method       string
	Path         string
	Body         string // the full bound body, pretty-printed; "" for a bodyless call
	Gated        bool
	Token        string
	ReviewID     string     // held (ungated) reviews only
	Fields       []ui2Field // gated reviews only
	RunURL       string
	Target       string
	Swap         string
	CancelURL    string
	CancelTarget string
}

// ui2HeldReview is one ungated call held server-side between review and run.
type ui2HeldReview struct {
	scope   string
	token   string
	gated   bool // a held call on a gated route carries a gate token and dispatches guarded
	call    ui2Call
	body    []byte
	expires time.Time
}

// ui2IssueReviewCap bounds the held-review map the same way the settings pages do.
const ui2IssueReviewCap = 8

func ui2PrettyBody(body []byte) string {
	if body == nil {
		return ""
	}
	var v any
	if err := json.Unmarshal(body, &v); err == nil {
		if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
			return string(pretty)
		}
	}
	return string(body)
}

// ui2PrepareReview mints or holds the call and returns the review sheet model. fields non-nil on
// a gated call selects the rebuild-from-fields flow; nil holds the bytes (with a gate token when
// the route is gated) and the run dispatches them verbatim.
func (s *Server) ui2PrepareReview(scope string, call ui2Call, fields []ui2Field) ui2ReviewModel {
	m := ui2ReviewModel{Title: call.Title, Consequences: call.Consequences, Method: call.Method, Path: call.Path}
	body := call.body()
	m.Body = ui2PrettyBody(body)
	pattern, gated := ui2CallGate(call.Path)
	m.Gated = gated
	gateToken := ""
	if gated {
		token, _, errText := s.ui2MintConfirm(pattern, call.Method, call.Path, body)
		if errText != "" || token == "" {
			m.Error = "the confirmation gate refused to mint a review - try again"
			return m
		}
		gateToken = token
		if fields != nil {
			m.Token = token
			m.Fields = fields
			return m
		}
	}
	id, err := randomHex(16)
	if err != nil {
		m.Error = "review id: " + err.Error()
		return m
	}
	token := gateToken
	if token == "" {
		if token, err = randomHex(16); err != nil {
			m.Error = "review token: " + err.Error()
			return m
		}
	}
	now := time.Now()
	s.ui2IssueReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2HeldReview); ok && now.After(e.expires) {
			s.ui2IssueReviews.Delete(k)
		}
		return true
	})
	count := 0
	s.ui2IssueReviews.Range(func(_, _ any) bool { count++; return true })
	if count >= ui2IssueReviewCap {
		m.Error = "too many reviews are open at once - confirm or let some expire, then try again"
		return m
	}
	s.ui2IssueReviews.Store(id, ui2HeldReview{scope: scope, token: token, gated: gated, call: call, body: body, expires: now.Add(ConfirmTTL)})
	m.ReviewID = id
	m.Token = token
	return m
}

// ui2SpendHeld spends one held review atomically. The entry is deleted on ANY attempt.
func (s *Server) ui2SpendHeld(scope, id, token string) (ui2HeldReview, string) {
	v, ok := s.ui2IssueReviews.LoadAndDelete(id)
	entry, isReview := v.(ui2HeldReview)
	if !ok || !isReview || entry.scope != scope {
		return ui2HeldReview{}, "that review is unknown or was already used - review the change again"
	}
	if time.Now().After(entry.expires) {
		return ui2HeldReview{}, "that review expired with the confirmation window - review the change again"
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(token)) != 1 {
		return ui2HeldReview{}, "that review does not match this confirmation - review the change again"
	}
	return entry, ""
}

// ui2DispatchHeld sends a held call's exact bytes: through the guarded chain with its gate token
// when the route is gated, through the internal mux otherwise.
func (s *Server) ui2DispatchHeld(e ui2HeldReview) (any, string) {
	req := newReq(e.call.Method, e.call.Path)
	if e.body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(e.body)))
	}
	rec := newRecorder()
	if e.gated {
		req.Header.Set(ConfirmHeader, e.token)
		req.Host = "127.0.0.1"
		req.Header.Set("Origin", "http://127.0.0.1")
		s.guarded.ServeHTTP(rec, req)
	} else {
		s.mux.ServeHTTP(rec, req)
	}
	if rec.Code == http.StatusPreconditionRequired {
		return nil, "confirmation required (428) - the review and the dispatch disagree; review again"
	}
	if rec.Code/100 != 2 {
		return nil, ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
	}
	var result any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &result)
	}
	return result, ""
}

// ui2RunReviewed spends the run form: a held review (review_id + token) or a gated rebuild (the
// fields + token, rebuilt by rebuild). The form must carry exactly the permitted fields.
func (s *Server) ui2RunReviewed(r *http.Request, scope string, fieldNames []string, rebuild func(*http.Request) (ui2Call, string)) (ui2Call, any, string) {
	_ = r.ParseForm()
	if _, held := r.PostForm["review_id"]; held {
		if err := ui2SitemapFields(r, "review_id", "token"); err != nil {
			return ui2Call{}, nil, err.Error()
		}
		entry, errText := s.ui2SpendHeld(scope, r.PostFormValue("review_id"), r.PostFormValue("token"))
		if errText != "" {
			return ui2Call{}, nil, errText
		}
		if entry.call.Reread != nil && entry.call.Reread() != entry.call.Snapshot {
			return entry.call, nil, "the state changed since this review - review the change again"
		}
		result, errText := s.ui2DispatchHeld(entry)
		return entry.call, result, errText
	}
	if err := ui2SitemapFields(r, append([]string{"token"}, fieldNames...)...); err != nil {
		return ui2Call{}, nil, err.Error()
	}
	call, errText := rebuild(r)
	if errText != "" {
		return call, nil, errText
	}
	// A rebuild is only trustworthy behind the gate: an ungated route would ignore the token
	// and run whatever the fields now say.
	if _, gated := ui2CallGate(call.Path); !gated {
		return call, nil, "this call is not gated, so it can only run from a held review - review it again"
	}
	result, errText := s.ui2DispatchConfirmed(call.Method, call.Path, call.dispatchPayload(), r.PostFormValue("token"))
	if errText != "" {
		errText = ui2APIErrorText(errText)
	}
	return call, result, errText
}

// ---- issues list filter ----------------------------------------------------------------------

var (
	ui2SeverityOptions   = []string{"Critical", "High", "Medium", "Low", "Informational"}
	ui2ConfidenceOptions = []string{"Certain", "Firm", "Tentative"}
)

// ui2IssueFilter is the issues list's view filter, round-tripped through the URL.
type ui2IssueFilter struct {
	Source     string // "", "scan", "manual"
	Text       string
	Severity   string
	Confidence string
}

func ui2OneOf(v string, opts []string) string {
	for _, o := range opts {
		if v == o {
			return v
		}
	}
	return ""
}

func parseUI2IssueFilter(r *http.Request) ui2IssueFilter {
	q := r.URL.Query()
	return ui2IssueFilter{
		Source:     ui2OneOf(q.Get("source"), []string{"scan", "manual"}),
		Text:       strings.TrimSpace(q.Get("q")),
		Severity:   ui2OneOf(q.Get("severity"), ui2SeverityOptions),
		Confidence: ui2OneOf(q.Get("confidence"), ui2ConfidenceOptions),
	}
}

// admits reports whether one list row passes the filter. A row with no source counts as manual,
// the SPA's rule (lib/issue-source-filter.ts).
func (f ui2IssueFilter) admits(v issueFindingView, name string) bool {
	if f.Source != "" {
		src := "manual"
		if v.Source == "scan" {
			src = "scan"
		}
		if src != f.Source {
			return false
		}
	}
	if f.Severity != "" && v.Severity != f.Severity {
		return false
	}
	if f.Confidence != "" && v.Confidence != f.Confidence {
		return false
	}
	if f.Text != "" {
		hay := strings.ToLower(name + " " + v.CheckName + " " + v.Host + " " + v.Param + " " + v.Comment)
		if !strings.Contains(hay, strings.ToLower(f.Text)) {
			return false
		}
	}
	return true
}

// Active reports whether any filter axis is set.
func (f ui2IssueFilter) Active() bool {
	return f.Source != "" || f.Text != "" || f.Severity != "" || f.Confidence != ""
}

// ---- issue detail model ----------------------------------------------------------------------

// ui2IssueDetailModel builds the detail pane's model, including the triage state the action
// forms need. ok is false when the finding does not exist.
func (s *Server) ui2IssueDetailModel(id uint64) (ui2IssueDetail, bool) {
	f, err := s.findings.Get(id)
	if err != nil {
		return ui2IssueDetail{}, false
	}
	v := s.findingToIssueView(f)
	model := ui2IssueDetail{
		ID: v.ID, CheckName: v.CheckName, Severity: v.Severity, Confidence: v.Confidence,
		Host: v.Host, Param: v.Param, Evidence: v.Evidence, TimesSeen: v.TimesSeen,
		FalsePositive: v.FalsePositive, Comment: v.Comment, Source: v.Source,
		Detail: ptrString(v.Detail), Remediation: ptrString(v.Remediation),
		Name:               v.CheckName,
		SeverityOverride:   ptrString(v.SeverityOverride),
		OriginalSeverity:   v.OriginalSeverity,
		ConfidenceOverride: ptrString(v.ConfidenceOverride),
		OriginalConfidence: v.OriginalConfidence,
		Triage:             v.Triage,
		SeverityOptions:    ui2SeverityOptions,
		ConfidenceOptions:  ui2ConfidenceOptions,
	}
	if v.IssueName != nil && *v.IssueName != "" {
		model.Name = *v.IssueName
	}
	model.Location = v.Host
	for _, occ := range v.Occurrences {
		model.Occurrences = append(model.Occurrences, ui2Occurrence{ExchangeID: uint64(occ.ExchangeID), Path: occ.Path})
		if model.Location == v.Host && occ.Path != "" {
			model.Location = v.Host + occ.Path
		}
	}
	return model, true
}

// ---- issue triage actions --------------------------------------------------------------------

// ui2IssueActionFields is the gated run form's contract (besides the token).
var ui2IssueActionFields = []string{"op", "id", "value"}

// ui2IssueActionCall builds the exact API call for one triage action. It is the single builder
// both review steps use, so the bound body and the dispatched body cannot drift.
func ui2IssueActionCall(op, idStr, value string) (ui2Call, string) {
	if op == "llm_all" {
		if idStr != "" || value != "" {
			return ui2Call{}, "triage-all takes no issue id or value"
		}
		return ui2Call{
			Method: http.MethodPost, Path: "/api/issues/triage", Payload: map[string]any{},
			Title: "LLM triage of every gated finding",
			Consequences: []string{
				"Each finding inside the Standard gate (High any confidence, Medium tentative or better) is sent to the configured LLM endpoint for a second look - the finding's name, URL, detail and remediation leave this machine.",
				"The note is advice beside the finding; severity and confidence never move.",
			},
		}, ""
	}
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return ui2Call{}, "an issue id is required"
	}
	path := "/api/issues/" + strconv.FormatUint(id, 10)
	label := "issue #" + strconv.FormatUint(id, 10)
	put := func(key string, v any, title, consequence string) (ui2Call, string) {
		return ui2Call{Method: http.MethodPut, Path: path, Payload: map[string]any{key: v}, Title: title, Consequences: []string{consequence}}, ""
	}
	switch op {
	case "severity":
		if value != "" && ui2OneOf(value, ui2SeverityOptions) == "" {
			return ui2Call{}, "unknown severity"
		}
		if value == "" {
			return put("severity", "", "Restore the engine severity of "+label, "The operator override is cleared; the severity the engine reported stands again.")
		}
		return put("severity", value, "Set the severity of "+label+" to "+value, "The finding reads as "+value+" everywhere (lists, dashboard counts, reports) until the override is cleared.")
	case "confidence":
		if value != "" && ui2OneOf(value, ui2ConfidenceOptions) == "" {
			return ui2Call{}, "unknown confidence"
		}
		if value == "" {
			return put("confidence", "", "Restore the engine confidence of "+label, "The operator override is cleared; the confidence the engine reported stands again.")
		}
		return put("confidence", value, "Set the confidence of "+label+" to "+value, "The finding reads as "+value+" confidence until the override is cleared.")
	case "false_positive":
		fp, err := strconv.ParseBool(value)
		if err != nil {
			return ui2Call{}, "the false-positive value must be true or false"
		}
		if fp {
			return put("false_positive", true, "Mark "+label+" as a false positive", "The finding is struck through in the list, left out of severity counts, and dropped from reports that hide false positives.")
		}
		return put("false_positive", false, "Unmark "+label+" as a false positive", "The finding counts again in lists, dashboards and reports.")
	case "comment":
		value = ui2NormalizeNewlines(value)
		if len(value) > 8192 {
			return ui2Call{}, "the comment is longer than 8192 bytes"
		}
		if value == "" {
			return put("comment", "", "Clear the comment on "+label, "The operator comment is removed.")
		}
		return put("comment", value, "Set the comment on "+label, "The comment replaces any existing one and is stored with the finding.")
	case "delete":
		if value != "" {
			return ui2Call{}, "delete takes no value"
		}
		return ui2Call{
			Method: http.MethodDelete, Path: path, Title: "Delete " + label,
			Consequences: []string{"The finding and its triage state are removed from the project. This cannot be undone; a later scan may report it again."},
		}, ""
	case "llm":
		if value != "" {
			return ui2Call{}, "the LLM second look takes no value"
		}
		return ui2Call{
			Method: http.MethodPost, Path: path + "/triage", Payload: map[string]any{}, Title: "LLM second look at " + label,
			Consequences: []string{
				"The finding's name, URL, detail and remediation are sent to the configured LLM endpoint.",
				"The verdict is stored as a note beside the finding; severity and confidence never move.",
			},
		}, ""
	}
	return ui2Call{}, "unknown issue action"
}

// handleUI2IssueAction serves POST /ui2/issues/action/{step}: confirm renders the review sheet,
// run spends it. The first click never writes.
func (s *Server) handleUI2IssueAction(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("step") {
	case "confirm":
		s.ui2IssueActionConfirm(w, r)
	case "run":
		s.ui2IssueActionRun(w, r)
	default:
		http.Error(w, "unknown issue action step", http.StatusNotFound)
	}
}

func (s *Server) ui2IssueReviewFragment(w http.ResponseWriter, r *http.Request, m ui2ReviewModel) {
	ui2Fragment(w, r, "burpsy /ui2/ — Issues", "issues", ui2Exec("issues_review.html", m))
}

func (s *Server) ui2IssueActionConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	op, idStr, value := r.PostFormValue("op"), r.PostFormValue("id"), r.PostFormValue("value")
	cancel := "/ui2/issues"
	if idStr != "" {
		cancel = "/ui2/issues/" + url.PathEscape(idStr)
	}
	fail := func(msg string) {
		s.ui2IssueReviewFragment(w, r, ui2ReviewModel{Error: msg, CancelURL: cancel, CancelTarget: "#detail"})
	}
	call, errText := ui2IssueActionCall(op, idStr, value)
	if errText != "" {
		fail(errText)
		return
	}
	if op != "llm_all" {
		id, _ := strconv.ParseUint(idStr, 10, 64)
		if _, err := s.findings.Get(id); err != nil {
			fail("that issue no longer exists - reload the list")
			return
		}
	}
	if op == "llm" || op == "llm_all" {
		if _, on, err := s.triageCfg(); err != nil || !on {
			fail("LLM triage is not configured: set and enable an endpoint under Settings first")
			return
		}
	}
	_, gated := ui2CallGate(call.Path)
	var fields []ui2Field
	if gated {
		fields = []ui2Field{{"op", op}, {"id", idStr}, {"value", ui2NormalizeNewlines(value)}}
	}
	m := s.ui2PrepareReview("issues", call, fields)
	m.RunURL, m.Target, m.Swap = "/ui2/issues/action/run", "#detail", "innerHTML"
	m.CancelURL, m.CancelTarget = cancel, "#detail"
	s.ui2IssueReviewFragment(w, r, m)
}

func (s *Server) ui2IssueActionRun(w http.ResponseWriter, r *http.Request) {
	call, result, errText := s.ui2RunReviewed(r, "issues", ui2IssueActionFields, func(r *http.Request) (ui2Call, string) {
		return ui2IssueActionCall(r.PostFormValue("op"), r.PostFormValue("id"), r.PostFormValue("value"))
	})
	if errText == "" {
		// The list is not notified by triage writes; app.js refreshes it on this event.
		w.Header().Set("HX-Trigger", "ui2-issues-changed")
	}
	if call.Path == "" {
		s.ui2IssueReviewFragment(w, r, ui2ReviewModel{Error: errText, CancelURL: "/ui2/issues", CancelTarget: "#detail"})
		return
	}
	// The issue the call was about, when it was about one.
	var id uint64
	if rest, ok := strings.CutPrefix(call.Path, "/api/issues/"); ok {
		id, _ = strconv.ParseUint(strings.TrimSuffix(rest, "/triage"), 10, 64)
	}
	if call.Path == "/api/issues/triage" {
		s.ui2IssueReviewFragment(w, r, ui2ReviewModel{Error: errText, Done: ui2TriageAllSummary(result), CancelURL: "/ui2/issues", CancelTarget: "#detail"})
		return
	}
	model, ok := s.ui2IssueDetailModel(id)
	if !ok {
		done := ""
		if errText == "" && call.Method == http.MethodDelete {
			done = "Issue #" + strconv.FormatUint(id, 10) + " deleted."
		}
		s.ui2IssueReviewFragment(w, r, ui2ReviewModel{Error: errText, Done: done, CancelURL: "/ui2/issues", CancelTarget: "#detail"})
		return
	}
	if errText != "" {
		model.Note = "Not applied: " + errText
	} else {
		model.Done = "Applied: " + call.Title + "."
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Issues", "issues", ui2Exec("issue_detail.html", model))
}

// ui2TriageAllSummary states the sweep's honest counts.
func ui2TriageAllSummary(result any) string {
	m, ok := result.(map[string]any)
	if !ok {
		return ""
	}
	n := func(k string) int {
		f, _ := m[k].(float64)
		return int(f)
	}
	errs, _ := m["errors"].([]any)
	return "LLM triage finished: " + strconv.Itoa(n("investigated_count")) + " investigated, " +
		strconv.Itoa(n("outside_gate")) + " outside the gate, " + strconv.Itoa(len(errs)) + " errored."
}

// ---- consolidation policy page ---------------------------------------------------------------

var ui2ConsolidationActions = []struct{ Value, Label, Hint string }{
	{"keep_existing", "Keep existing (merge)", "fold the duplicate into the issue already reported - occurrences added, severity raised"},
	{"keep_both", "Keep both", "report the duplicate as its own issue"},
	{"keep_new", "Keep new", "replace the reported issue's detail with the newer observation, severity included"},
}

type ui2ConsolidationTally struct {
	TaskID     uint64 `json:"task_id"`
	Collisions int    `json:"collisions"`
	Merged     int    `json:"merged"`
	Replaced   int    `json:"replaced"`
	KeptBoth   int    `json:"kept_both"`
}

type ui2ConsolidationView struct {
	Default    string                  `json:"default"`
	PerRow     map[string]string       `json:"per_row"`
	Tally      ui2ConsolidationTally   `json:"tally"`
	ByTask     []ui2ConsolidationTally `json:"by_task"`
	NeverMerge []string                `json:"never_merge"`
}

type ui2ConsolidationRow struct {
	Name, Action string
	NeverMerge   bool // the store never merges this row, so the exception is inert
}

type ui2ConsolidationModel struct {
	View       ui2ConsolidationView
	Rows       []ui2ConsolidationRow
	Actions    []struct{ Value, Label, Hint string }
	IssueNames []string
	Error      string
	Done       string
}

func (s *Server) ui2ConsolidationRead() (ui2ConsolidationView, string) {
	var v ui2ConsolidationView
	result, errText := s.ui2APIResult(http.MethodGet, "/api/issues/consolidation", nil)
	if errText != "" {
		return v, errText
	}
	b, _ := json.Marshal(result)
	if err := json.Unmarshal(b, &v); err != nil {
		return v, "unreadable consolidation view: " + err.Error()
	}
	return v, ""
}

// ui2ConsolidationPolicyJSON is the canonical {default, per_row} the drift check compares.
func ui2ConsolidationPolicyJSON(v ui2ConsolidationView) string {
	per := v.PerRow
	if per == nil {
		per = map[string]string{}
	}
	b, _ := json.Marshal(map[string]any{"default": v.Default, "per_row": per})
	return string(b)
}

func (s *Server) ui2ConsolidationModel(errText, done string) ui2ConsolidationModel {
	v, readErr := s.ui2ConsolidationRead()
	if errText == "" {
		errText = readErr
	}
	m := ui2ConsolidationModel{View: v, Actions: ui2ConsolidationActions, Error: errText, Done: done}
	never := map[string]bool{}
	for _, n := range v.NeverMerge {
		never[n] = true
	}
	for name, action := range v.PerRow {
		m.Rows = append(m.Rows, ui2ConsolidationRow{Name: name, Action: action, NeverMerge: never[name]})
	}
	sort.Slice(m.Rows, func(i, j int) bool { return m.Rows[i].Name < m.Rows[j].Name })
	seen := map[string]bool{}
	for _, f := range s.findings.All() {
		if f.Name != "" && !seen[f.Name] && !never[f.Name] {
			seen[f.Name] = true
			m.IssueNames = append(m.IssueNames, f.Name)
		}
	}
	sort.Strings(m.IssueNames)
	return m
}

// handleUI2IssueConsolidation serves GET /ui2/issues/consolidation: the policy form, the
// exceptions and what consolidation has done so far.
func (s *Server) handleUI2IssueConsolidation(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy /ui2/ — Issue consolidation", "issueconsolidation", ui2Exec("issues_consolidation.html", s.ui2ConsolidationModel("", "")))
}

// ui2ConsolidationCall builds the whole-document PUT from the form. Exceptions arrive as
// parallel row_name/row_action lists (an action of "remove" drops the row) plus one optional
// new_name/new_action pair.
func ui2ConsolidationCall(r *http.Request) (ui2Call, string) {
	valid := map[string]bool{"keep_existing": true, "keep_both": true, "keep_new": true}
	def := r.PostFormValue("default")
	if !valid[def] {
		return ui2Call{}, "choose an action for every issue type"
	}
	names, actions := r.PostForm["row_name"], r.PostForm["row_action"]
	if len(names) != len(actions) {
		return ui2Call{}, "the exception rows are incomplete - reload the page"
	}
	per := map[string]any{}
	for i, name := range names {
		if actions[i] == "remove" {
			continue
		}
		if name == "" || !valid[actions[i]] {
			return ui2Call{}, "every exception needs an issue type and an action"
		}
		per[name] = actions[i]
	}
	if n := strings.TrimSpace(r.PostFormValue("new_name")); n != "" {
		a := r.PostFormValue("new_action")
		if !valid[a] {
			return ui2Call{}, "choose an action for the new exception"
		}
		per[n] = a
	}
	cons := []string{"For every issue type: " + def + "."}
	keys := make([]string, 0, len(per))
	for k := range per {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cons = append(cons, "Exception: "+k+" - "+per[k].(string)+".")
	}
	cons = append(cons, "The policy applies to issues reported after it; a merge already made is not undone.")
	return ui2Call{
		Method: http.MethodPut, Path: "/api/issues/consolidation",
		Payload: map[string]any{"default": def, "per_row": per},
		Title:   "Save the issue consolidation policy", Consequences: cons,
	}, ""
}

// handleUI2IssueConsolidationAction serves POST /ui2/issues/consolidation/{step}.
func (s *Server) handleUI2IssueConsolidationAction(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	render := func(body templateHTML) {
		ui2Fragment(w, r, "burpsy /ui2/ — Issue consolidation", "issueconsolidation", body)
	}
	switch r.PathValue("step") {
	case "confirm":
		call, errText := ui2ConsolidationCall(r)
		if errText != "" {
			render(ui2Exec("issues_consolidation.html", s.ui2ConsolidationModel(errText, "")))
			return
		}
		before, readErr := s.ui2ConsolidationRead()
		if readErr != "" {
			render(ui2Exec("issues_consolidation.html", s.ui2ConsolidationModel(readErr, "")))
			return
		}
		// The PUT is whole-document: a policy that moves between review and run is refused.
		call.Snapshot = ui2ConsolidationPolicyJSON(before)
		call.Reread = func() string {
			now, err := s.ui2ConsolidationRead()
			if err != "" {
				return "unreadable: " + err
			}
			return ui2ConsolidationPolicyJSON(now)
		}
		m := s.ui2PrepareReview("consolidation", call, nil)
		m.RunURL, m.Target, m.Swap = "/ui2/issues/consolidation/run", "#rows", "outerHTML"
		m.CancelURL, m.CancelTarget = "/ui2/issues/consolidation", "#rows"
		render(ui2Exec("issues_consolidation_review.html", m))
	case "run":
		_, _, errText := s.ui2RunReviewed(r, "consolidation", nil, func(*http.Request) (ui2Call, string) {
			return ui2Call{}, "the consolidation policy is saved only from a held review"
		})
		done := ""
		if errText == "" {
			done = "Consolidation policy saved - it applies to issues reported from now on."
		}
		render(ui2Exec("issues_consolidation.html", s.ui2ConsolidationModel(errText, done)))
	default:
		http.Error(w, "unknown consolidation step", http.StatusNotFound)
	}
}

// ---- report settings page --------------------------------------------------------------------

var ui2ReportSections = []struct{ Value, Label string }{
	{"background", "Issue background"},
	{"detail", "Issue detail"},
	{"remediation", "Remediation detail"},
	{"classifications", "Vulnerability classifications"},
}

type ui2ReportLink struct{ Format, Label, Href string }

type ui2ReportModel struct {
	Title          string
	OrganiseBy     string
	TOCDepth       string
	Sections       map[string]bool
	MessageMode    string
	MaxMessageLen  string
	Host           string
	Severities     map[string]bool
	HideFP         bool
	SectionOptions []struct{ Value, Label string }
	SeverityLevels []string
	Links          []ui2ReportLink
	Error          string
}

// handleUI2IssueReport serves GET /ui2/issues/report: the report settings form and the export
// links those settings produce. Nothing is written; the links carry the settings as the query
// GET /api/report/{format} reads, so the downloaded file is the file the form describes.
func (s *Server) handleUI2IssueReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	m := ui2ReportModel{
		Title:          strings.TrimSpace(q.Get("title")),
		OrganiseBy:     ui2OneOf(q.Get("organise_by"), []string{"severity", "type", "url"}),
		TOCDepth:       ui2OneOf(q.Get("toc_depth"), []string{"0", "1", "2"}),
		MessageMode:    ui2OneOf(q.Get("message_mode"), []string{"none", "relevant", "full"}),
		MaxMessageLen:  strings.TrimSpace(q.Get("max_message_len")),
		Host:           strings.TrimSpace(q.Get("host")),
		HideFP:         q.Get("hide_fp") != "",
		Sections:       map[string]bool{},
		Severities:     map[string]bool{},
		SectionOptions: ui2ReportSections,
		SeverityLevels: []string{"critical", "high", "medium", "low", "informational"},
	}
	if m.OrganiseBy == "" {
		m.OrganiseBy = "severity"
	}
	if m.TOCDepth == "" {
		m.TOCDepth = "0"
	}
	if m.MessageMode == "" {
		m.MessageMode = "none"
	}
	// sections_set distinguishes "the form was submitted with these ticked" (possibly none) from
	// a first load, where every section is on.
	if q.Has("sections_set") {
		for _, v := range q["sections"] {
			m.Sections[v] = true
		}
	} else {
		for _, o := range ui2ReportSections {
			m.Sections[o.Value] = true
		}
	}
	var sevs []string
	for _, lvl := range m.SeverityLevels {
		for _, v := range q["severity"] {
			if v == lvl {
				m.Severities[lvl] = true
				sevs = append(sevs, lvl)
			}
		}
	}
	if m.MaxMessageLen != "" {
		if n, err := strconv.Atoi(m.MaxMessageLen); err != nil || n < 0 {
			m.Error = "the maximum message length must be a non-negative number of bytes"
		}
	}
	if len(m.Title) > 200 {
		m.Error = "the report title is capped at 200 characters"
	}
	if m.Error == "" {
		var sections []string
		for _, o := range ui2ReportSections {
			if m.Sections[o.Value] {
				sections = append(sections, o.Value)
			}
		}
		for _, f := range []struct{ format, label string }{
			{"html", "HTML report"}, {"xml", "Burp XML"}, {"json", "JSON"}, {"sarif", "SARIF"},
		} {
			p := url.Values{}
			if len(sevs) > 0 {
				p.Set("severity", strings.Join(sevs, ","))
			}
			if m.Host != "" {
				p.Set("host", m.Host)
			}
			if m.HideFP {
				p.Set("exclude_false_positives", "true")
			}
			if f.format == "html" {
				if m.Title != "" {
					p.Set("title", m.Title)
				}
				if m.OrganiseBy != "severity" {
					p.Set("organise_by", m.OrganiseBy)
				}
				if m.TOCDepth != "0" {
					p.Set("toc_depth", m.TOCDepth)
				}
			}
			if f.format == "html" || f.format == "xml" {
				if len(sections) != len(ui2ReportSections) {
					p.Set("sections", strings.Join(sections, ","))
				}
				if m.MessageMode != "none" || f.format == "xml" {
					p.Set("message_mode", m.MessageMode)
				}
				if m.MaxMessageLen != "" {
					p.Set("max_message_len", m.MaxMessageLen)
				}
			}
			href := "/api/report/" + f.format
			if enc := p.Encode(); enc != "" {
				href += "?" + enc
			}
			m.Links = append(m.Links, ui2ReportLink{Format: f.format, Label: f.label, Href: href})
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Report settings", "issuereport", ui2Exec("issues_report.html", m))
}
