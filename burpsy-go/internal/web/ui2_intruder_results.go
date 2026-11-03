package web

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
)

// ui2 Intruder: attack settings, results analysis, export and attack config files (unit 19).
//
// /api/intruder/run answers with the whole RunView when the attack ends and keeps nothing: the
// attack's registry entry is gone by then. The ui2 run step is the caller that receives that view,
// so it keeps the last few here, keyed by task id, and the results page renders from them. Attacks
// launched elsewhere (the SPA, an agent) fall back to the stored requests the datasets API holds.

// ---- attack settings (the launch form's Settings section) --------------------------------------

// ui2IntruderSettingsMarker is posted by the settings section. Without it no setting is added to
// the run body: an unticked checkbox and a form that never carried the section look the same.
const ui2IntruderSettingsMarker = "settings_present"

// ui2IntruderSettingsFields are the settings section's form fields, in body-building order. The
// confirm step re-posts exactly these, so the run step rebuilds the body the token was minted for.
var ui2IntruderSettingsFields = []string{
	ui2IntruderSettingsMarker,
	"retries", "retry_delay_ms",
	"store_requests", "store_responses", "baseline", "set_connection_close", "store_full_payloads",
	"grep_match_list", "grep_match_mode", "grep_match_case", "grep_match_exclude_headers",
	"grep_extract",
	"grep_payloads_enabled", "grep_payloads_case", "grep_payloads_exclude_headers", "grep_payloads_pre_encoded",
	"capture_enabled", "capture_discard_no_response", "capture_term", "capture_regex", "capture_case",
	"capture_negate", "capture_status",
	"auto_pause_enabled", "auto_pause_mode", "auto_pause_expressions", "auto_pause_simple", "auto_pause_case",
	"follow_redirects", "response_timeout_ms", "http_version", "http1_connection_reuse",
}

var ui2IntruderStatusClasses = []string{"2xx", "3xx", "4xx", "5xx"}

// ui2IntruderSettings is the settings section's view model.
type ui2IntruderSettings struct {
	Retries, RetryDelayMS                                                      string
	StoreRequests, StoreResponses, Baseline, SetConnectionClose, StorePayloads bool
	GrepMatchList                                                              string
	GrepMatchRegex, GrepMatchCase, GrepMatchExcludeHeaders                     bool
	GrepExtract                                                                string
	GrepPayloadsEnabled, GrepPayloadsCase, GrepPayloadsExcludeHeaders          bool
	GrepPayloadsPreEncoded                                                     bool
	CaptureEnabled, CaptureNoResponse                                          bool
	CaptureTerm                                                                string
	CaptureRegex, CaptureCase, CaptureNegate                                   bool
	CaptureStatuses                                                            map[string]bool
	AutoPauseEnabled                                                           bool
	AutoPauseMissing                                                           bool
	AutoPauseExpressions                                                       string
	AutoPauseSimple, AutoPauseCase                                             bool
	FollowRedirects, ResponseTimeoutMS, HTTPVersion                            string
	HTTP1Reuse                                                                 bool
	// RestoredPoints are the explicit insertion-point indexes a loaded config selected.
	RestoredPoints []string
	// ExtractResponseID is the stored response the define-extract helper reads by default.
	ExtractResponseID uint64
	// Loaded says the section was just restored from a saved attack configuration.
	Loaded bool
}

// ui2IntruderDefaultSettings is Burp's default attack configuration, the SPA's
// emptyIntruderConfig: store requests and responses, Grep - Payloads on and matched pre-encoding,
// every status class captured, HTTP/1 connection reuse on.
func ui2IntruderDefaultSettings() ui2IntruderSettings {
	return ui2IntruderSettings{
		StoreRequests: true, StoreResponses: true,
		GrepPayloadsEnabled: true, GrepPayloadsPreEncoded: true,
		CaptureStatuses: map[string]bool{"2xx": true, "3xx": true, "4xx": true, "5xx": true},
		AutoPauseSimple: true, HTTP1Reuse: true,
	}
}

// ui2IntruderSettingsFromForm reads the section back from a posted form; a form without the
// marker yields the defaults.
func ui2IntruderSettingsFromForm(f url.Values) ui2IntruderSettings {
	if f.Get(ui2IntruderSettingsMarker) == "" {
		return ui2IntruderDefaultSettings()
	}
	on := func(k string) bool { return f.Get(k) == "on" }
	st := map[string]bool{}
	for _, c := range f["capture_status"] {
		st[c] = true
	}
	return ui2IntruderSettings{
		Retries: f.Get("retries"), RetryDelayMS: f.Get("retry_delay_ms"),
		StoreRequests: on("store_requests"), StoreResponses: on("store_responses"), Baseline: on("baseline"),
		SetConnectionClose: on("set_connection_close"), StorePayloads: on("store_full_payloads"),
		GrepMatchList: f.Get("grep_match_list"), GrepMatchRegex: f.Get("grep_match_mode") == "regex",
		GrepMatchCase: on("grep_match_case"), GrepMatchExcludeHeaders: on("grep_match_exclude_headers"),
		GrepExtract:         f.Get("grep_extract"),
		GrepPayloadsEnabled: on("grep_payloads_enabled"), GrepPayloadsCase: on("grep_payloads_case"),
		GrepPayloadsExcludeHeaders: on("grep_payloads_exclude_headers"), GrepPayloadsPreEncoded: on("grep_payloads_pre_encoded"),
		CaptureEnabled: on("capture_enabled"), CaptureNoResponse: on("capture_discard_no_response"),
		CaptureTerm: f.Get("capture_term"), CaptureRegex: on("capture_regex"), CaptureCase: on("capture_case"),
		CaptureNegate: on("capture_negate"), CaptureStatuses: st,
		AutoPauseEnabled: on("auto_pause_enabled"), AutoPauseMissing: f.Get("auto_pause_mode") == "missing",
		AutoPauseExpressions: f.Get("auto_pause_expressions"), AutoPauseSimple: on("auto_pause_simple"),
		AutoPauseCase:   on("auto_pause_case"),
		FollowRedirects: f.Get("follow_redirects"), ResponseTimeoutMS: f.Get("response_timeout_ms"),
		HTTPVersion: f.Get("http_version"), HTTP1Reuse: on("http1_connection_reuse"),
	}
}

// ui2IntruderSettingsForPage is the settings model a re-rendered launch form shows: the posted
// section when there was one, the defaults otherwise, with the define-extract helper pointed at
// the base exchange's response.
func (s *Server) ui2IntruderSettingsForPage(f url.Values) ui2IntruderSettings {
	st := ui2IntruderSettingsFromForm(f)
	exID, _, _ := ui2LatestExchange(s)
	if ex, err := s.store.GetExchange(core.ExchangeID(exID)); err == nil && ex.Response != nil {
		st.ExtractResponseID = uint64(*ex.Response)
	}
	return st
}

// ui2HiddenField is one name/value pair a review step re-posts.
type ui2HiddenField struct{ Name, Value string }

// ui2IntruderSettingsHidden returns the posted settings fields verbatim, in a stable order.
func ui2IntruderSettingsHidden(f url.Values) []ui2HiddenField {
	var out []ui2HiddenField
	for _, k := range ui2IntruderSettingsFields {
		for _, v := range f[k] {
			out = append(out, ui2HiddenField{k, v})
		}
	}
	return out
}

func ui2Lines(s string) []string {
	out := []string{}
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// ui2IntruderApplySettings adds the settings section to the /api/intruder/run body. Values are
// passed through for the API to validate (it names the field it refuses); only whole numbers are
// parsed here, because a typed "3x" must not become an absent field.
func ui2IntruderApplySettings(run map[string]any, f url.Values) string {
	if f.Get(ui2IntruderSettingsMarker) == "" {
		return ""
	}
	on := func(k string) bool { return f.Get(k) == "on" }
	for _, n := range []struct{ field, key string }{
		{"retries", "retries"}, {"retry_delay_ms", "retry_delay_ms"}, {"response_timeout_ms", "response_timeout_ms"},
	} {
		if v := strings.TrimSpace(f.Get(n.field)); v != "" {
			x, errText := ui2ParseCount(n.field, v)
			if errText != "" {
				return errText
			}
			run[n.key] = x
		}
	}
	run["store_requests"] = on("store_requests")
	run["store_responses"] = on("store_responses")
	run["baseline"] = on("baseline")
	run["set_connection_close"] = on("set_connection_close")
	run["store_full_payloads"] = on("store_full_payloads")
	run["http1_connection_reuse"] = on("http1_connection_reuse")
	if list := ui2Lines(f.Get("grep_match_list")); len(list) > 0 {
		run["grep_match_list"] = list
		run["grep_match_simple"] = f.Get("grep_match_mode") != "regex"
		run["grep_match_case_sensitive"] = on("grep_match_case")
		run["grep_match_exclude_headers"] = on("grep_match_exclude_headers")
	}
	if v := f.Get("grep_extract"); v != "" {
		run["grep_extract"] = v
	}
	run["grep_payloads"] = map[string]any{
		"enabled": on("grep_payloads_enabled"), "case_sensitive": on("grep_payloads_case"),
		"exclude_headers": on("grep_payloads_exclude_headers"), "match_pre_url_encoded": on("grep_payloads_pre_encoded"),
	}
	if on("capture_enabled") {
		statuses := []string{} // never nil: null captures every class, [] captures none
		for _, c := range ui2IntruderStatusClasses {
			for _, v := range f["capture_status"] {
				if v == c {
					statuses = append(statuses, c)
					break
				}
			}
		}
		run["capture_filter"] = map[string]any{
			"discard_no_response": on("capture_discard_no_response"), "term": f.Get("capture_term"),
			"regex": on("capture_regex"), "case_sensitive": on("capture_case"), "negate": on("capture_negate"),
			"statuses": statuses,
		}
	}
	if on("auto_pause_enabled") {
		run["auto_pause"] = map[string]any{
			"expressions": ui2Lines(f.Get("auto_pause_expressions")), "missing": f.Get("auto_pause_mode") == "missing",
			"simple": on("auto_pause_simple"), "case_sensitive": on("auto_pause_case"),
		}
	}
	if v := f.Get("follow_redirects"); v != "" {
		run["follow_redirects"] = v
	}
	if v := f.Get("http_version"); v != "" {
		run["http_version"] = v
	}
	return ""
}

// handleUI2IntruderDefaultSettings serves GET /ui2/intruder/config/default: the settings section
// at Burp's defaults ("Use default configuration"). Nothing is stored; the form is the state.
func (s *Server) handleUI2IntruderDefaultSettings(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder",
		ui2Exec("intruder_settings_form.html", s.ui2IntruderSettingsForPage(nil)))
}

// ---- kept reports -----------------------------------------------------------------------------

const ui2IntruderKeptCap = 16

// ui2IntruderKept is one finished attack's report as /api/intruder/run answered it, plus the
// operator's comments (Burp's Comment column) — annotations of this console, not attack state.
type ui2IntruderKept struct {
	view   RunView
	target string
	at     time.Time
	mu     sync.Mutex
	notes  map[int]string
}

func (k *ui2IntruderKept) comment(ord int) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.notes[ord]
}

// ui2IntruderKeepReport records a finished attack's RunView for its results page.
func (s *Server) ui2IntruderKeepReport(run map[string]any, result any) {
	// AttackKind marshals as its wire string and has no decoder; put the number back first.
	if m, ok := result.(map[string]any); ok {
		if rep, ok := m["report"].(map[string]any); ok {
			if k, ok := rep["kind"].(string); ok {
				kind, _ := intruder.ParseAttackKind(k)
				rep["kind"] = int(kind)
			}
		}
	}
	b, err := json.Marshal(result)
	if err != nil {
		return
	}
	var view RunView
	if json.Unmarshal(b, &view) != nil || view.TaskID == 0 {
		return
	}
	target, _ := run["target"].(string)
	s.ui2IntruderReports.Store(view.TaskID, &ui2IntruderKept{view: view, target: target, at: time.Now(), notes: map[int]string{}})
	// Bounded: drop the oldest beyond the cap.
	type aged struct {
		id uint64
		at time.Time
	}
	var all []aged
	s.ui2IntruderReports.Range(func(k, v any) bool {
		all = append(all, aged{k.(uint64), v.(*ui2IntruderKept).at})
		return true
	})
	if len(all) > ui2IntruderKeptCap {
		sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
		for _, a := range all[:len(all)-ui2IntruderKeptCap] {
			s.ui2IntruderReports.Delete(a.id)
		}
	}
}

func (s *Server) ui2IntruderReport(id uint64) *ui2IntruderKept {
	v, ok := s.ui2IntruderReports.Load(id)
	if !ok {
		return nil
	}
	return v.(*ui2IntruderKept)
}

// ui2IntruderID parses the {id} path value as a task id.
func ui2IntruderID(r *http.Request) (uint64, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func ui2IntruderFail(w http.ResponseWriter, r *http.Request, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("error.html", ui2Error{Message: msg}))
}

// ---- results rows -----------------------------------------------------------------------------

// ui2IntruderRow is one attempt as the results table shows it.
type ui2IntruderRow struct {
	Ordinal                       int
	Payload                       string
	Status                        string
	statusN                       int
	Length                        int
	Reflected                     bool
	Counts                        []int
	GrepMatched                   string
	GrepCounts                    []int
	Extract                       string
	Anomaly                       int
	TimeOfDay                     string
	at                            time.Time
	Duration                      int64
	Interactions                  int
	Timeout                       bool
	Cookies, Comment, Error       string
	RequestID, ResponseID         uint64
	HasRequest, HasResponse, Base bool
}

// ui2IntruderPayloadText names the payloads behind an ordinal: the stored full payloads, else the
// server's resolved example for that ordinal.
func ui2IntruderPayloadText(view *RunView, a *intruder.Attempt, examples map[int][]string) (string, bool) {
	if view.Report.Baseline && a.Ordinal == 0 {
		return "(baseline request, no payloads)", true
	}
	parts := a.Payloads
	if parts == nil {
		parts = examples[a.Ordinal]
	}
	if len(parts) == 0 {
		return "", false
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		if p == "" {
			p = "(empty)"
		}
		out[i] = p
	}
	return strings.Join(out, " | "), false
}

// ui2IntruderInteractions maps each attempt's Collaborator addresses to the interactions the log
// attributes to them (Burp's Interactions column), de-duplicated per event.
func (s *Server) ui2IntruderInteractions(view *RunView) (map[int][]map[string]any, string) {
	hasCollab := false
	for _, a := range view.Report.Attempts {
		if len(a.CollaboratorPayloads) > 0 {
			hasCollab = true
			break
		}
	}
	if !hasCollab {
		return nil, ""
	}
	res, errText := s.ui2APIResult(http.MethodGet, "/api/collaborator/interactions", nil)
	if errText != "" {
		return nil, ui2APIErrorText(errText)
	}
	m, _ := res.(map[string]any)
	rows, _ := m["rows"].([]any)
	byAddr := map[string][]map[string]any{}
	for _, r := range rows {
		row, _ := r.(map[string]any)
		if p, _ := row["payload"].(string); p != "" {
			byAddr[strings.ToLower(p)] = append(byAddr[strings.ToLower(p)], row)
		}
	}
	out := map[int][]map[string]any{}
	for _, a := range view.Report.Attempts {
		seen := map[string]bool{}
		for _, addr := range a.CollaboratorPayloads {
			for _, row := range byAddr[strings.ToLower(addr)] {
				key := fmt.Sprintf("%s|%v|%v|%v", strings.ToLower(addr), row["type"], row["q_type"], row["client_ip"])
				if !seen[key] {
					seen[key] = true
					out[a.Ordinal] = append(out[a.Ordinal], row)
				}
			}
		}
	}
	return out, ""
}

func ui2IntruderRows(view *RunView, kept *ui2IntruderKept, inter map[int][]map[string]any) []ui2IntruderRow {
	examples := map[int][]string{}
	for _, e := range view.Examples {
		examples[e.FirstOrdinal] = e.Payloads
	}
	rows := make([]ui2IntruderRow, 0, len(view.Report.Attempts))
	for i := range view.Report.Attempts {
		a := &view.Report.Attempts[i]
		row := ui2IntruderRow{
			Ordinal: a.Ordinal, Status: "—", statusN: -1, Length: a.ResponseLen, Reflected: a.Reflected,
			Counts: a.ReflectedCounts, GrepCounts: a.GrepMatchCounts, Anomaly: a.AnomalyRank,
			at: a.TimeOfDay, TimeOfDay: a.TimeOfDay.Local().Format("15:04:05.000"), Duration: a.DurationMS,
			Interactions: len(inter[a.Ordinal]), Timeout: a.Timeout, Cookies: strings.Join(a.Cookies, "; "),
		}
		row.Payload, row.Base = ui2IntruderPayloadText(view, a, examples)
		if a.Status != nil {
			row.statusN, row.Status = *a.Status, strconv.Itoa(*a.Status)
		}
		if a.GrepMatched != nil {
			row.GrepMatched = map[bool]string{true: "yes", false: "no"}[*a.GrepMatched]
		}
		if a.GrepExtract != nil {
			row.Extract = *a.GrepExtract
		}
		if a.Error != nil {
			row.Error = *a.Error
		}
		if a.RequestID != nil {
			row.HasRequest, row.RequestID = true, *a.RequestID
		}
		if a.ResponseID != nil {
			row.HasResponse, row.ResponseID = true, *a.ResponseID
		}
		if kept != nil {
			row.Comment = kept.comment(a.Ordinal)
		}
		rows = append(rows, row)
	}
	return rows
}

// ---- results view state (sort, filter, page, comparer slots) ----------------------------------

const ui2IntruderResultsPage = 200

// ui2IntruderQuery is the results view's URL state; every link carries it so a sort, filter or
// Comparer pick survives the next click.
type ui2IntruderQuery struct {
	Sort, Order, Q, Status, CmpA, CmpB  string
	OnlyGrep, OnlyReflected, HideErrors bool
	Offset                              int
}

func ui2IntruderParseQuery(q url.Values) ui2IntruderQuery {
	st := ui2IntruderQuery{
		Sort: q.Get("sort"), Order: q.Get("order"), Q: q.Get("q"), Status: q.Get("status"),
		CmpA: q.Get("cmp_a"), CmpB: q.Get("cmp_b"),
		OnlyGrep: q.Get("grep") == "1", OnlyReflected: q.Get("reflected") == "1", HideErrors: q.Get("hide_errors") == "1",
	}
	if st.Order != "desc" {
		st.Order = "asc"
	}
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		st.Offset = n
	}
	return st
}

func (st ui2IntruderQuery) values() url.Values {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("sort", st.Sort)
	if st.Sort != "" {
		set("order", st.Order)
	}
	set("q", st.Q)
	set("status", st.Status)
	set("cmp_a", st.CmpA)
	set("cmp_b", st.CmpB)
	if st.OnlyGrep {
		v.Set("grep", "1")
	}
	if st.OnlyReflected {
		v.Set("reflected", "1")
	}
	if st.HideErrors {
		v.Set("hide_errors", "1")
	}
	if st.Offset > 0 {
		v.Set("offset", strconv.Itoa(st.Offset))
	}
	return v
}

func (st ui2IntruderQuery) url(base string) string {
	if e := st.values().Encode(); e != "" {
		return base + "?" + e
	}
	return base
}

func ui2IntruderStatusClass(n int) string {
	if n < 0 {
		return "none"
	}
	return fmt.Sprintf("%dxx", n/100)
}

func ui2IntruderFilter(rows []ui2IntruderRow, st ui2IntruderQuery) []ui2IntruderRow {
	needle := strings.ToLower(st.Q)
	out := rows[:0:0]
	for _, r := range rows {
		if st.Status != "" && ui2IntruderStatusClass(r.statusN) != st.Status {
			continue
		}
		if st.OnlyReflected && !r.Reflected {
			continue
		}
		if st.HideErrors && r.Error != "" {
			continue
		}
		if st.OnlyGrep {
			hit := r.GrepMatched == "yes" || r.Extract != ""
			for _, c := range r.GrepCounts {
				hit = hit || c > 0
			}
			if !hit {
				continue
			}
		}
		if needle != "" && !strings.Contains(strings.ToLower(r.Payload+"\x00"+r.Error+"\x00"+r.Extract+"\x00"+r.Comment+"\x00"+r.Cookies), needle) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ui2IntruderSortKeys are the sortable columns. grepN sorts by the Nth Grep - Match count.
func ui2IntruderLess(key string) func(a, b ui2IntruderRow) int {
	cmpInt := func(x, y int64) int {
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	}
	b2i := func(b bool) int64 {
		if b {
			return 1
		}
		return 0
	}
	switch key {
	case "payload":
		return func(a, b ui2IntruderRow) int { return strings.Compare(a.Payload, b.Payload) }
	case "status":
		return func(a, b ui2IntruderRow) int { return cmpInt(int64(a.statusN), int64(b.statusN)) }
	case "length":
		return func(a, b ui2IntruderRow) int { return cmpInt(int64(a.Length), int64(b.Length)) }
	case "reflected":
		return func(a, b ui2IntruderRow) int { return cmpInt(b2i(a.Reflected), b2i(b.Reflected)) }
	case "anomaly":
		// Rank 0 is "not ranked"; it sorts after every ranked row either way round.
		return func(a, b ui2IntruderRow) int {
			ra, rb := int64(a.Anomaly), int64(b.Anomaly)
			if ra == 0 {
				ra = 1 << 40
			}
			if rb == 0 {
				rb = 1 << 40
			}
			return cmpInt(ra, rb)
		}
	case "time":
		return func(a, b ui2IntruderRow) int { return a.at.Compare(b.at) }
	case "duration":
		return func(a, b ui2IntruderRow) int { return cmpInt(a.Duration, b.Duration) }
	case "interactions":
		return func(a, b ui2IntruderRow) int { return cmpInt(int64(a.Interactions), int64(b.Interactions)) }
	case "timeout":
		return func(a, b ui2IntruderRow) int { return cmpInt(b2i(a.Timeout), b2i(b.Timeout)) }
	case "error":
		return func(a, b ui2IntruderRow) int { return strings.Compare(a.Error, b.Error) }
	case "extract":
		return func(a, b ui2IntruderRow) int { return strings.Compare(a.Extract, b.Extract) }
	case "comment":
		return func(a, b ui2IntruderRow) int { return strings.Compare(a.Comment, b.Comment) }
	case "cookies":
		return func(a, b ui2IntruderRow) int { return strings.Compare(a.Cookies, b.Cookies) }
	case "grep":
		return func(a, b ui2IntruderRow) int { return strings.Compare(a.GrepMatched, b.GrepMatched) }
	}
	if strings.HasPrefix(key, "grep") {
		if n, err := strconv.Atoi(key[4:]); err == nil && n >= 0 {
			at := func(r ui2IntruderRow) int64 {
				if n < len(r.GrepCounts) {
					return int64(r.GrepCounts[n])
				}
				return -1
			}
			return func(a, b ui2IntruderRow) int { return cmpInt(at(a), at(b)) }
		}
	}
	if strings.HasPrefix(key, "count") {
		if n, err := strconv.Atoi(key[5:]); err == nil && n >= 0 {
			at := func(r ui2IntruderRow) int64 {
				if n < len(r.Counts) {
					return int64(r.Counts[n])
				}
				return -1
			}
			return func(a, b ui2IntruderRow) int { return cmpInt(at(a), at(b)) }
		}
	}
	return func(a, b ui2IntruderRow) int { return cmpInt(int64(a.Ordinal), int64(b.Ordinal)) }
}

// ui2IntruderColumn is one sortable header.
type ui2IntruderColumn struct {
	Label, Key, Href, Arrow string
}

func ui2IntruderColumns(id uint64, st ui2IntruderQuery, view *RunView) []ui2IntruderColumn {
	base := fmt.Sprintf("/ui2/intruder/%d/results", id)
	col := func(label, key string) ui2IntruderColumn {
		next := st
		next.Offset = 0
		next.Sort, next.Order = key, "asc"
		arrow := ""
		if st.Sort == key || (st.Sort == "" && key == "ordinal") {
			if st.Order == "asc" {
				next.Order, arrow = "desc", "▲"
			} else {
				arrow = "▼"
			}
		}
		return ui2IntruderColumn{Label: label, Key: key, Href: next.url(base), Arrow: arrow}
	}
	cols := []ui2IntruderColumn{col("#", "ordinal"), col("Payload", "payload"), col("Status", "status"),
		col("Length", "length"), col("Reflected", "reflected")}
	if view.Report.GrepPayloads.Enabled {
		for i := range view.PayloadSets {
			cols = append(cols, col(fmt.Sprintf("Count %d", i+1), fmt.Sprintf("count%d", i)))
		}
	}
	if len(view.Report.GrepMatchLabels) == 0 {
		cols = append(cols, col("Grep", "grep"))
	}
	for i, l := range view.Report.GrepMatchLabels {
		cols = append(cols, col(l, fmt.Sprintf("grep%d", i)))
	}
	return append(cols, col("Extract", "extract"), col("Anomaly", "anomaly"), col("Time of day", "time"),
		col("Time (ms)", "duration"), col("Interactions", "interactions"), col("Timeout", "timeout"),
		col("Cookies", "cookies"), col("Comment", "comment"), col("Error", "error"))
}

// ---- results page -----------------------------------------------------------------------------

// ui2IntruderLive returns the running attack's controller view, or nil once it has ended.
func (s *Server) ui2IntruderLive(id uint64) map[string]any {
	res, _ := s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	m, _ := res.(map[string]any)
	list, _ := m["attacks"].([]any)
	for _, a := range list {
		am, _ := a.(map[string]any)
		if f, _ := am["task_id"].(float64); uint64(f) == id {
			return am
		}
	}
	return nil
}

func (s *Server) ui2IntruderResultsModel(id uint64, st ui2IntruderQuery) map[string]any {
	idStr := url.PathEscape(strconv.FormatUint(id, 10))
	model := map[string]any{"task": id, "live": s.ui2IntruderLive(id), "state": st.values().Encode()}
	kept := s.ui2IntruderReport(id)
	if kept == nil {
		// Not launched from this console, or still running: the stored requests are what exists.
		q := "limit=200&sort_by=id&sort_order=desc"
		if st.Offset > 0 {
			q += "&offset=" + strconv.Itoa(st.Offset)
		}
		res, errText := s.ui2APIResult(http.MethodGet, "/api/datasets/intruder/"+idStr+"?"+q, nil)
		model["results"], model["error"] = res, errText
		return model
	}
	view := &kept.view
	inter, interErr := s.ui2IntruderInteractions(view)
	all := ui2IntruderRows(view, kept, inter)
	rows := ui2IntruderFilter(all, st)
	less := ui2IntruderLess(st.Sort)
	sort.SliceStable(rows, func(i, j int) bool {
		c := less(rows[i], rows[j])
		if st.Order == "desc" {
			return c > 0
		}
		return c < 0
	})
	matched := len(rows)
	if st.Offset > len(rows) {
		st.Offset = 0
	}
	end := min(st.Offset+ui2IntruderResultsPage, len(rows))
	page := rows[st.Offset:end]
	base := fmt.Sprintf("/ui2/intruder/%d/results", id)
	if end < matched {
		next := st
		next.Offset = end
		model["next_href"] = next.url(base)
	}
	if st.Offset > 0 {
		prev := st
		prev.Offset = max(0, st.Offset-ui2IntruderResultsPage)
		model["prev_href"] = prev.url(base)
	}
	// Comparer slots: "req:N" / "resp:N", picked from the row view.
	if st.CmpA != "" && st.CmpB != "" {
		model["compare_href"] = fmt.Sprintf("/ui2/intruder/%d/compare?%s", id,
			url.Values{"a": {st.CmpA}, "b": {st.CmpB}}.Encode())
	}
	clear := st
	clear.CmpA, clear.CmpB = "", ""
	model["compare_clear"] = clear.url(base)
	itemQ := st
	itemQ.Offset = 0
	model["item_query"] = itemQ.values().Encode()
	model["kept"] = true
	model["view"] = view
	model["target"] = kept.target
	model["rows"] = page
	model["shown"] = len(page)
	model["matched"] = matched
	model["total"] = len(all)
	model["columns"] = ui2IntruderColumns(id, st, view)
	model["has_counts"] = view.Report.GrepPayloads.Enabled
	model["has_grep_list"] = len(view.Report.GrepMatchLabels) > 0
	model["interactions_error"] = interErr
	model["filter"] = st
	model["capped"] = len(view.Report.Attempts) >= view.Report.DetailLimit && view.Report.DetailLimit > 0
	model["finished"] = kept.at.Local().Format("2006-01-02 15:04:05")
	return model
}

// handleUI2IntruderResults serves GET /ui2/intruder/{id}/results: the attack's full results table
// when this console launched it (report, buckets, errors, payload-set accounting), the stored
// requests otherwise, polling while the attack still runs.
func (s *Server) handleUI2IntruderResults(w http.ResponseWriter, r *http.Request) {
	id, ok := ui2IntruderID(r)
	if !ok {
		ui2IntruderFail(w, r, http.StatusNotFound, "attack ids are whole numbers: "+r.PathValue("id")+" is not one")
		return
	}
	model := s.ui2IntruderResultsModel(id, ui2IntruderParseQuery(r.URL.Query()))
	ui2Fragment(w, r, fmt.Sprintf("burpsy /ui2/ — Attack %d", id), "intruder", ui2Exec("intruder_results.html", model))
}

// ---- one row: response view and row actions ---------------------------------------------------

func (s *Server) ui2IntruderAttempt(w http.ResponseWriter, r *http.Request) (uint64, *ui2IntruderKept, *intruder.Attempt, bool) {
	id, ok := ui2IntruderID(r)
	if !ok {
		ui2IntruderFail(w, r, http.StatusNotFound, "attack ids are whole numbers: "+r.PathValue("id")+" is not one")
		return 0, nil, nil, false
	}
	kept := s.ui2IntruderReport(id)
	if kept == nil {
		ui2IntruderFail(w, r, http.StatusNotFound, fmt.Sprintf("no report is held for attack %d: only attacks launched from this console page keep their per-attempt rows", id))
		return 0, nil, nil, false
	}
	ordStr := r.PathValue("ordinal")
	if ordStr == "" {
		ordStr = r.FormValue("ordinal")
	}
	ord, err := strconv.Atoi(ordStr)
	if err != nil || ord < 0 {
		ui2IntruderFail(w, r, http.StatusNotFound, "attempt ordinals are whole numbers: "+ordStr+" is not one")
		return 0, nil, nil, false
	}
	for i := range kept.view.Report.Attempts {
		if kept.view.Report.Attempts[i].Ordinal == ord {
			return id, kept, &kept.view.Report.Attempts[i], true
		}
	}
	ui2IntruderFail(w, r, http.StatusNotFound, fmt.Sprintf("attack %d kept no row for attempt %d", id, ord))
	return 0, nil, nil, false
}

func (s *Server) ui2StoredText(id *uint64) (string, bool) {
	if id == nil {
		return "", false
	}
	msg, err := s.store.Get(core.MsgId(*id))
	if err != nil {
		return "", false
	}
	return string(msg.Raw()), true
}

// ui2IntruderExemplar finds the bucket whose stored exemplar stands for this attempt's shape.
func ui2IntruderExemplar(view *RunView, a *intruder.Attempt) *intruder.ResultBucket {
	for i := range view.Report.Buckets {
		b := &view.Report.Buckets[i]
		same := (b.Status == nil) == (a.Status == nil) && (b.Status == nil || *b.Status == *a.Status)
		if same && b.ResponseLen == a.ResponseLen && b.Reflected == a.Reflected && b.ExampleResponseID != nil {
			return b
		}
	}
	return nil
}

// handleUI2IntruderItem serves GET /ui2/intruder/{id}/item/{ordinal}: the attempt's request and
// response, its Collaborator interactions, and the row actions.
func (s *Server) handleUI2IntruderItem(w http.ResponseWriter, r *http.Request) {
	id, kept, a, ok := s.ui2IntruderAttempt(w, r)
	if !ok {
		return
	}
	model := s.ui2IntruderItemModel(id, kept, a, ui2IntruderParseQuery(r.URL.Query()))
	ui2Fragment(w, r, fmt.Sprintf("burpsy /ui2/ — Attack %d item %d", id, a.Ordinal), "intruder", ui2Exec("intruder_results_item.html", model))
}

func (s *Server) ui2IntruderItemModel(id uint64, kept *ui2IntruderKept, a *intruder.Attempt, st ui2IntruderQuery) map[string]any {
	view := &kept.view
	inter, interErr := s.ui2IntruderInteractions(view)
	row := ui2IntruderRows(&RunView{Report: intruder.AttackReport{Attempts: []intruder.Attempt{*a}, Baseline: view.Report.Baseline},
		Examples: view.Examples}, kept, inter)[0]
	model := map[string]any{"task": id, "row": row, "interactions": inter[a.Ordinal], "interactions_error": interErr,
		"collab": a.CollaboratorPayloads, "comment": row.Comment, "item_query": st.values().Encode()}
	if req, ok := s.ui2StoredText(a.RequestID); ok {
		model["request"] = req
		model["req_pane"] = renderMessagePane(req, true, false)
	}
	if resp, ok := s.ui2StoredText(a.ResponseID); ok {
		model["response"] = resp
		model["resp_pane"] = renderMessagePane(resp, false, false)
	} else if b := ui2IntruderExemplar(view, a); b != nil && b.ExampleOrdinal != nil && *b.ExampleOrdinal != a.Ordinal {
		model["exemplar"] = *b.ExampleOrdinal
	}
	base := fmt.Sprintf("/ui2/intruder/%d/results", id)
	slot := func(which, part string) string {
		next := st
		v := fmt.Sprintf("%s:%d", part, a.Ordinal)
		if which == "a" {
			next.CmpA = v
		} else {
			next.CmpB = v
		}
		return next.url(base)
	}
	model["req_a"], model["req_b"] = slot("a", "req"), slot("b", "req")
	model["resp_a"], model["resp_b"] = slot("a", "resp"), slot("b", "resp")
	return model
}

// handleUI2IntruderItemRepeater serves GET /ui2/intruder/{id}/item/{ordinal}/repeater: the Repeater
// editor with this attempt's stored request as the draft. Loading a draft sends nothing.
func (s *Server) handleUI2IntruderItemRepeater(w http.ResponseWriter, r *http.Request) {
	_, kept, a, ok := s.ui2IntruderAttempt(w, r)
	if !ok {
		return
	}
	raw, ok := s.ui2StoredText(a.RequestID)
	if !ok {
		ui2IntruderFail(w, r, http.StatusNotFound, fmt.Sprintf("attempt %d has no stored request (the attack did not store it, or it was never sent)", a.Ordinal))
		return
	}
	if !ui2TextareaSafe([]byte(raw)) {
		ui2IntruderFail(w, r, http.StatusUnprocessableEntity, "this request carries bytes a text editor cannot keep unchanged (invalid UTF-8 or NUL); nothing was loaded")
		return
	}
	notice := fmt.Sprintf("Draft loaded from attempt %d's stored request. Sending happens from the editor.", a.Ordinal)
	body := templateHTML(`<p class="meta">`+template.HTMLEscapeString(notice)+`</p>`) +
		ui2Exec("repeater.html", map[string]any{"draft": raw, "result": nil, "target": kept.target})
	ui2RenderPage(w, "burpsy /ui2/ — Repeater", "repeater", body)
}

// handleUI2IntruderComment serves POST /ui2/intruder/{id}/comment: Burp's Comment column. The
// comment is this console's annotation of the kept report; it reaches no API and no target.
func (s *Server) handleUI2IntruderComment(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, kept, a, ok := s.ui2IntruderAttempt(w, r)
	if !ok {
		return
	}
	c := strings.TrimSpace(r.PostFormValue("comment"))
	if len(c) > 1000 {
		ui2IntruderFail(w, r, http.StatusBadRequest, "a comment is at most 1000 characters")
		return
	}
	kept.mu.Lock()
	if c == "" {
		delete(kept.notes, a.Ordinal)
	} else {
		kept.notes[a.Ordinal] = c
	}
	kept.mu.Unlock()
	model := s.ui2IntruderItemModel(id, kept, a, ui2IntruderParseQuery(r.URL.Query()))
	model["note"] = "comment saved"
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder_results_item.html", model))
}

// ui2IntruderCompareSide resolves a Comparer slot ("req:N" / "resp:N") to its stored text.
func (s *Server) ui2IntruderCompareSide(kept *ui2IntruderKept, slot string) (string, string) {
	part, ordStr, _ := strings.Cut(slot, ":")
	ord, err := strconv.Atoi(ordStr)
	if err != nil || (part != "req" && part != "resp") {
		return "", fmt.Sprintf("%q is not a Comparer slot (req:N or resp:N)", slot)
	}
	for i := range kept.view.Report.Attempts {
		a := &kept.view.Report.Attempts[i]
		if a.Ordinal != ord {
			continue
		}
		id := a.RequestID
		if part == "resp" {
			id = a.ResponseID
		}
		if text, ok := s.ui2StoredText(id); ok {
			return text, ""
		}
		return "", fmt.Sprintf("attempt %d has no stored %s", ord, map[string]string{"req": "request", "resp": "response"}[part])
	}
	return "", fmt.Sprintf("the attack kept no row for attempt %d", ord)
}

// handleUI2IntruderCompare serves GET /ui2/intruder/{id}/compare?a=&b=: the two picked messages in
// the Comparer, diffed through /api/tools/compare (a read).
func (s *Server) handleUI2IntruderCompare(w http.ResponseWriter, r *http.Request) {
	id, ok := ui2IntruderID(r)
	if !ok {
		ui2IntruderFail(w, r, http.StatusNotFound, "attack ids are whole numbers: "+r.PathValue("id")+" is not one")
		return
	}
	kept := s.ui2IntruderReport(id)
	if kept == nil {
		ui2IntruderFail(w, r, http.StatusNotFound, fmt.Sprintf("no report is held for attack %d", id))
		return
	}
	a, errA := s.ui2IntruderCompareSide(kept, r.URL.Query().Get("a"))
	b, errB := s.ui2IntruderCompareSide(kept, r.URL.Query().Get("b"))
	if errA != "" || errB != "" {
		ui2IntruderFail(w, r, http.StatusBadRequest, strings.TrimSpace("A: "+errA+" B: "+errB))
		return
	}
	ra, rb := strings.ToValidUTF8(a, "�"), strings.ToValidUTF8(b, "�")
	result, errText := s.ui2APIResult(http.MethodPost, "/api/tools/compare", map[string]string{"a": ra, "b": rb})
	ui2Fragment(w, r, "burpsy /ui2/ — Comparer", "comparer", ui2Exec("comparer.html", map[string]any{
		"result": ui2RenderCompare(ra, rb, result, ra != a || rb != b), "error": errText, "a": a, "b": b}))
}

// ---- request item again (attack class: review A with the full bound body) ---------------------

func (s *Server) ui2IntruderAgainBody(kept *ui2IntruderKept, a *intruder.Attempt) (map[string]any, string) {
	if a.RequestID == nil {
		return nil, fmt.Sprintf("attempt %d has no stored request to send again", a.Ordinal)
	}
	target := kept.target
	if target == "" {
		if raw, ok := s.ui2StoredText(a.RequestID); ok {
			target = ui2HostFromRequest(raw)
		}
	}
	if target == "" {
		return nil, "the attack's target is unknown"
	}
	return map[string]any{"target": target, "request_ids": []uint64{*a.RequestID}}, ""
}

// handleUI2IntruderAgain serves POST /ui2/intruder/{id}/again/{step}. "confirm" renders the review
// of the exact /api/intruder/again body (minted when the route is gated); "run" rebuilds the same
// body from the held report — nothing the form carries but the ordinal and token — and spends it.
func (s *Server) handleUI2IntruderAgain(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, kept, a, ok := s.ui2IntruderAttempt(w, r)
	if !ok {
		return
	}
	const api = "/api/intruder/again"
	body, errText := s.ui2IntruderAgainBody(kept, a)
	model := map[string]any{"task": id, "ordinal": a.Ordinal, "error": errText}
	switch r.PathValue("step") {
	case "confirm":
		if errText == "" {
			payload, _ := ui2Marshal(body)
			model["full_body"] = string(payload)
			_, risk, _ := routeRiskFor(api)
			if needsConfirmation(risk) {
				token, preview, mintErr := s.ui2MintConfirm(api, http.MethodPost, api, payload)
				model["token"], model["preview"], model["error"] = token, preview, mintErr
			} else {
				model["ready"] = true
			}
		}
	case "run":
		_, risk, _ := routeRiskFor(api)
		switch {
		case errText != "":
		case needsConfirmation(risk) && r.PostFormValue("token") == "":
			model["error"] = "no confirmation token: review the request first"
		default:
			res, dispErr := s.ui2DispatchConfirmed(http.MethodPost, api, body, r.PostFormValue("token"))
			model["error"] = ui2APIErrorText(dispErr)
			m, _ := res.(map[string]any)
			rows, _ := m["rows"].([]any)
			if len(rows) > 0 {
				row, _ := rows[0].(map[string]any)
				model["again"] = row
				if f, ok := row["response_id"].(float64); ok {
					rid := uint64(f)
					if text, ok := s.ui2StoredText(&rid); ok {
						model["again_pane"] = renderMessagePane(text, false, false)
					}
				}
			}
		}
	default:
		http.Error(w, "unknown step: want confirm or run", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intruder_results_again.html", model)))
}

// ---- export ----------------------------------------------------------------------------------

// ui2CSVCell guards a cell against spreadsheet formula injection: a leading =, +, -, @, tab or CR
// is neutralised with a quote, the way the SPA's csvCell does.
func ui2CSVCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// handleUI2IntruderExport serves GET /ui2/intruder/{id}/export?format=csv|json: the per-attempt
// sheet (with the attack's bounds as # caveat lines) or the RunView /run answered.
func (s *Server) handleUI2IntruderExport(w http.ResponseWriter, r *http.Request) {
	id, ok := ui2IntruderID(r)
	if !ok {
		ui2IntruderFail(w, r, http.StatusNotFound, "attack ids are whole numbers: "+r.PathValue("id")+" is not one")
		return
	}
	kept := s.ui2IntruderReport(id)
	if kept == nil {
		ui2IntruderFail(w, r, http.StatusNotFound, fmt.Sprintf("no report is held for attack %d: only attacks launched from this console page can be exported here", id))
		return
	}
	view := &kept.view
	stem := fmt.Sprintf("intruder-%d-%s-%d", id, view.Report.Kind, view.Report.Planned)
	switch r.URL.Query().Get("format") {
	case "json":
		b, err := json.MarshalIndent(view, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+stem+`.json"`)
		_, _ = w.Write(b)
	case "csv", "":
		var buf bytes.Buffer
		rep := &view.Report
		stopped := ""
		if rep.StopReason != "" {
			stopped = " — " + rep.StopReason
		}
		caveats := []string{
			"# burpsy intruder attack — " + rep.Kind.String(),
			"# exported: " + time.Now().UTC().Format(time.RFC3339),
			fmt.Sprintf("# status: %s%s", rep.Status, stopped),
			fmt.Sprintf("# planned: %d of %d combinations (exact: %v); enumerated: %d; sent: %d; failed: %d", rep.Planned, rep.Combinations, rep.CombinationsExact, rep.Enumerated, rep.Sent, rep.Failed),
			fmt.Sprintf("# truncated: %v (max_requests: %d)", rep.Truncated, rep.MaxRequests),
			fmt.Sprintf("# buckets_truncated: %v; unbucketed: %d", rep.BucketsTruncated, rep.Unbucketed),
			fmt.Sprintf("# detail_limit: %d", rep.DetailLimit),
			fmt.Sprintf("# stored: requests %v, responses %v", rep.RequestsStored, rep.ResponsesStored),
		}
		if rep.CaptureFilter != nil {
			caveats = append(caveats, fmt.Sprintf("# capture filter on; discarded: %d — counted in sent/failed, not written below", rep.Discarded))
		}
		for _, c := range caveats {
			buf.WriteString(strings.ReplaceAll(c, "\n", " ") + "\n")
		}
		cw := csv.NewWriter(&buf)
		head := []string{"Ordinal", "Payload", "Status", "Time of day", "Length", "Duration (ms)", "Reflected", "Grep matched"}
		head = append(head, rep.GrepMatchLabels...)
		head = append(head, "Grep extract", "Anomaly rank", "Error", "Timeout", "Cookies", "Interactions", "Request ID", "Response ID", "Comment")
		for i := range head {
			head[i] = ui2CSVCell(head[i])
		}
		_ = cw.Write(head)
		inter, _ := s.ui2IntruderInteractions(view)
		for _, row := range ui2IntruderRows(view, kept, inter) {
			rec := []string{strconv.Itoa(row.Ordinal), row.Payload, ui2CSVStatus(row), row.at.UTC().Format(time.RFC3339Nano),
				strconv.Itoa(row.Length), strconv.FormatInt(row.Duration, 10), strconv.FormatBool(row.Reflected), row.GrepMatched}
			for i := range rep.GrepMatchLabels {
				if i < len(row.GrepCounts) {
					rec = append(rec, strconv.Itoa(row.GrepCounts[i]))
				} else {
					rec = append(rec, "")
				}
			}
			rec = append(rec, row.Extract, strconv.Itoa(row.Anomaly), row.Error, strconv.FormatBool(row.Timeout), row.Cookies,
				strconv.Itoa(row.Interactions), ui2CSVID(row.HasRequest, row.RequestID), ui2CSVID(row.HasResponse, row.ResponseID), row.Comment)
			for i := range rec {
				rec[i] = ui2CSVCell(rec[i])
			}
			_ = cw.Write(rec)
		}
		cw.Flush()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+stem+`.csv"`)
		_, _ = w.Write(buf.Bytes())
	default:
		ui2IntruderFail(w, r, http.StatusBadRequest, "format must be csv or json")
	}
}

func ui2CSVStatus(r ui2IntruderRow) string {
	if r.statusN < 0 {
		return ""
	}
	return r.Status
}

func ui2CSVID(ok bool, id uint64) string {
	if !ok {
		return ""
	}
	return strconv.FormatUint(id, 10)
}

// ---- attack config files ---------------------------------------------------------------------

const (
	ui2IntruderConfigFormat  = "burpsy-ui2-intruder-attack"
	ui2IntruderConfigVersion = 1
)

// ui2IntruderPositionFields are the fields "copy without positions" leaves out.
var ui2IntruderPositionFields = map[string]bool{"point": true, "all_points": true}

// ui2IntruderConfigFields are the launch-form fields a loaded config can be restored into, each
// with its value check. A field the page cannot restore is refused by name on load, never dropped.
var ui2IntruderConfigFields = func() map[string]func(string) string {
	anyText := func(string) string { return "" }
	checkbox := func(v string) string {
		if v != "on" {
			return fmt.Sprintf("is %q; a ticked box is \"on\"", v)
		}
		return ""
	}
	whole := func(v string) string {
		if v == "" {
			return ""
		}
		if _, err := strconv.ParseUint(v, 10, 32); err != nil {
			return fmt.Sprintf("is %q, not a whole number", v)
		}
		return ""
	}
	oneOf := func(vals ...string) func(string) string {
		return func(v string) string {
			for _, x := range vals {
				if v == x {
					return ""
				}
			}
			return fmt.Sprintf("is %q, not one of %s", v, strings.Join(vals, ", "))
		}
	}
	m := map[string]func(string) string{
		"msg_id": whole, "target": anyText, "payloads": anyText, "all_points": checkbox, "point": whole,
		"payload_placement": oneOf("", "replace", "append"),
		"retries":           whole, "retry_delay_ms": whole, "response_timeout_ms": whole,
		"grep_match_list": anyText, "grep_match_mode": oneOf("simple", "regex"), "grep_extract": anyText,
		"capture_term": anyText, "capture_status": oneOf(ui2IntruderStatusClasses...),
		"auto_pause_mode": oneOf("appears", "missing"), "auto_pause_expressions": anyText,
		"follow_redirects":        oneOf("", "never", "on_site", "in_scope", "always"),
		"http_version":            oneOf("", "http1", "http2"),
		ui2IntruderSettingsMarker: oneOf("1"),
	}
	for _, k := range ui2IntruderSettingsFields {
		if _, ok := m[k]; !ok {
			m[k] = checkbox
		}
	}
	return m
}()

// ui2IntruderMultiFields may carry more than one value.
var ui2IntruderMultiFields = map[string]bool{"point": true, "capture_status": true}

type ui2IntruderConfigDoc struct {
	Format    string              `json:"format"`
	Version   int                 `json:"version"`
	Positions bool                `json:"positions"`
	Form      map[string][]string `json:"form"`
}

// ui2IntruderConfigFromForm is the posted launch form as a config document.
func ui2IntruderConfigFromForm(f url.Values, positions bool) ui2IntruderConfigDoc {
	doc := ui2IntruderConfigDoc{Format: ui2IntruderConfigFormat, Version: ui2IntruderConfigVersion, Positions: positions, Form: map[string][]string{}}
	for k, vs := range f {
		// extract_* belong to the define-extract helper, not to the attack.
		if k == "token" || k == "positions" || k == "config" || strings.HasPrefix(k, "extract_") ||
			(!positions && ui2IntruderPositionFields[k]) {
			continue
		}
		doc.Form[k] = append([]string(nil), vs...)
	}
	return doc
}

// ui2IntruderParseConfig reads a saved config, refusing anything that cannot be restored in full.
func (s *Server) ui2IntruderParseConfig(text []byte) (ui2IntruderConfigDoc, string) {
	var doc ui2IntruderConfigDoc
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, "this is not a ui2 Intruder attack configuration: " + err.Error()
	}
	if doc.Format != ui2IntruderConfigFormat {
		return doc, fmt.Sprintf("\"format\" is %q, not %q", doc.Format, ui2IntruderConfigFormat)
	}
	if doc.Version != ui2IntruderConfigVersion {
		return doc, fmt.Sprintf("\"version\" is %d; this console reads version %d only", doc.Version, ui2IntruderConfigVersion)
	}
	if doc.Form == nil {
		return doc, "the configuration carries no \"form\""
	}
	keys := make([]string, 0, len(doc.Form))
	for k := range doc.Form {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		check, known := ui2IntruderConfigFields[k]
		if !known {
			return doc, fmt.Sprintf("field %q cannot be restored by this console's Intruder form; refusing rather than dropping it", k)
		}
		if len(doc.Form[k]) > 1 && !ui2IntruderMultiFields[k] {
			return doc, fmt.Sprintf("field %q carries %d values; the form holds one", k, len(doc.Form[k]))
		}
		for _, v := range doc.Form[k] {
			if why := check(v); why != "" {
				return doc, fmt.Sprintf("field %q %s", k, why)
			}
		}
	}
	if ids := doc.Form["msg_id"]; len(ids) == 1 && ids[0] != "" {
		n, _ := strconv.ParseUint(ids[0], 10, 64)
		if msg, err := s.store.Get(core.MsgId(n)); err != nil || bytes.HasPrefix(msg.Raw(), []byte("HTTP/")) {
			return doc, fmt.Sprintf("the base request (message %s) is no longer stored, so the attack's positions cannot be restored", ids[0])
		}
	}
	return doc, ""
}

// handleUI2IntruderConfigSave serves POST /ui2/intruder/config/save. From the launch form it renders
// the config document for copying, with a download button ("positions=without" leaves the insertion
// points out). With a "config" field it validates that document and answers it as a download.
func (s *Server) handleUI2IntruderConfigSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if text := r.PostFormValue("config"); text != "" {
		if _, why := s.ui2IntruderParseConfig([]byte(text)); why != "" {
			ui2IntruderFail(w, r, http.StatusBadRequest, why)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="burpsy-attack-`+time.Now().UTC().Format("2006-01-02T15-04-05")+`.json"`)
		_, _ = io.WriteString(w, text)
		return
	}
	positions := r.PostFormValue("positions") != "without"
	doc := ui2IntruderConfigFromForm(r.PostForm, positions)
	b, _ := json.MarshalIndent(doc, "", "  ")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intruder_settings_config.html", map[string]any{"config": string(b) + "\n", "positions": positions})))
}

// handleUI2IntruderConfigLoad serves POST /ui2/intruder/config/load: restore a saved config (an
// uploaded file or pasted text) into the launch form, or refuse it with the reason.
func (s *Server) handleUI2IntruderConfigLoad(w http.ResponseWriter, r *http.Request) {
	var text []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(1 << 20); err == nil {
			if f, _, err := r.FormFile("config_file"); err == nil {
				text, _ = io.ReadAll(io.LimitReader(f, 1<<20))
				_ = f.Close()
			}
		}
	}
	if len(text) == 0 {
		text = []byte(r.FormValue("config"))
	}
	doc, why := s.ui2IntruderParseConfig(text)
	if len(bytes.TrimSpace(text)) == 0 {
		why = "choose a saved attack configuration file, or paste one"
	}
	if why != "" {
		// The refusal belongs next to the load button, not over the whole page.
		w.Header().Set("HX-Retarget", "#intruder-config-out")
		w.Header().Set("HX-Reswap", "innerHTML")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("intruder_settings_config.html", map[string]any{"load_error": why})))
		return
	}
	f := url.Values(doc.Form)
	model := map[string]any{}
	model["attacks"], _ = s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	model["wordlists"], _ = s.ui2APIResult(http.MethodGet, "/api/wordlists", nil)
	model["base_exchange"], model["base_msgid"], model["base_request"] = ui2LatestExchange(s)
	if id := f.Get("msg_id"); id != "" {
		model["base_msgid"] = ui2Atoi(id)
		for _, ex := range s.store.Exchanges() {
			if ex.Request != nil && uint64(*ex.Request) == ui2Atoi(id) {
				model["base_exchange"] = uint64(ex.ID)
			}
		}
	}
	st := s.ui2IntruderSettingsForPage(f)
	st.RestoredPoints = f["point"]
	st.Loaded = true
	model["settings"] = st
	model["loaded_target"] = f.Get("target")
	model["loaded_payloads"] = f.Get("payloads")
	model["loaded_placement"] = f.Get("payload_placement")
	model["loaded_no_all_points"] = f.Get("all_points") == ""
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// ---- define extract grep from a response -------------------------------------------------------

const (
	ui2ExtractMinAnchor = 6
	ui2ExtractMaxAnchor = 200
)

func ui2ExtractClass(r rune) int {
	switch {
	case unicode.IsSpace(r):
		return 0
	case unicode.IsLetter(r) || unicode.IsNumber(r):
		return 1
	}
	return 2
}

// ui2ExtractRule is the SPA's buildExtractRule (lib/intruder-extract.ts) over runes: a "start
// after" anchor grown backwards and an "end at" delimiter grown forwards on token boundaries, each
// until its first occurrence sits against the selection, as one regex with a lazy group.
func ui2ExtractRule(text []rune, start, end int) string {
	idx := func(sub []rune, from int) int {
		i := strings.Index(string(text[from:]), string(sub))
		if i < 0 {
			return -1
		}
		return from + len([]rune(string(text[from:])[:i]))
	}
	back := func(length int) int {
		limit := min(start, ui2ExtractMaxAnchor)
		next := max(length+1, min(ui2ExtractMinAnchor, limit))
		for next < limit && ui2ExtractClass(text[start-next-1]) == ui2ExtractClass(text[start-next]) {
			next++
		}
		return min(next, start)
	}
	fwd := func(length int) int {
		room := len(text) - end
		limit := min(room, ui2ExtractMaxAnchor)
		next := max(length+1, min(ui2ExtractMinAnchor, limit))
		for next < limit && ui2ExtractClass(text[end+next]) == ui2ExtractClass(text[end+next-1]) {
			next++
		}
		return min(next, room)
	}
	prefixLen := 0
	if start > 0 {
		l := back(0)
		found := idx(text[start-l:start], 0) == start-l
		for !found && l < start && l < ui2ExtractMaxAnchor {
			l = back(l)
			found = idx(text[start-l:start], 0) == start-l
		}
		if found {
			prefixLen = l
		}
	}
	suffix := ""
	if end < len(text) {
		l := fwd(0)
		for {
			cand := text[end : end+l]
			if idx(cand, start) == end {
				suffix = string(cand)
				break
			}
			if l >= ui2ExtractMaxAnchor || end+l >= len(text) {
				break
			}
			l = fwd(l)
		}
	}
	tail := "$"
	if suffix != "" {
		tail = ui2RegexLiteral(suffix)
	}
	return ui2RegexLiteral(string(text[start-prefixLen:start])) + `([\s\S]*?)` + tail
}

func ui2RegexLiteral(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case strings.ContainsRune(`\.+*?()|[]{}^$`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// handleUI2IntruderExtract serves POST /ui2/intruder/settings/extract: build a Grep - Extract rule
// from text the operator copied out of a stored response, and preview what it extracts there.
func (s *Server) handleUI2IntruderExtract(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := map[string]any{}
	defer func() {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("intruder_settings_extract.html", model)))
	}()
	sel := r.PostFormValue("extract_text")
	rid, err := strconv.ParseUint(r.PostFormValue("extract_response_id"), 10, 64)
	if err != nil {
		model["error"] = "name the stored response (a message id) to build the rule from"
		return
	}
	raw, ok := s.ui2StoredText(&rid)
	if !ok || !strings.HasPrefix(raw, "HTTP/") {
		model["error"] = fmt.Sprintf("message %d is not a stored response", rid)
		return
	}
	if sel == "" {
		model["error"] = "paste the part of the response to extract"
		return
	}
	// The browser posts textarea text with LF line endings; a response has CRLF heads.
	text := []rune(raw)
	at := strings.Index(raw, sel)
	if at < 0 {
		sel = strings.ReplaceAll(sel, "\n", "\r\n")
		at = strings.Index(raw, sel)
	}
	if at < 0 {
		model["error"] = "that text does not occur in the response"
		return
	}
	start := len([]rune(raw[:at]))
	end := start + len([]rune(sel))
	rule := ui2ExtractRule(text, start, end)
	model["rule"] = rule
	re, err := regexp.Compile(rule)
	if err != nil {
		model["error"] = "the built rule does not compile: " + err.Error()
		return
	}
	m := re.FindStringSubmatchIndex(raw)
	switch {
	case m == nil || len(m) < 4 || m[2] < 0:
		model["warning"] = "the rule matches nothing in this response"
	case m[2] != at || raw[m[2]:m[3]] != sel:
		model["warning"] = "the rule extracts something else from this response: " + truncateForDisplay(raw[m[2]:m[3]], 200)
	default:
		model["preview"] = truncateForDisplay(sel, 256)
		if len(sel) > 256 {
			model["warning"] = "the engine keeps at most 256 bytes of an extracted value"
		}
	}
}
