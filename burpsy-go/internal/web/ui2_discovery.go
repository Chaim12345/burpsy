package web

// ui2 Content discovery (Burp's "Discover content", delegated to ffuf) and the held-call review
// both this page and the DOM auditor (ui2_dominvader.go) use for their writes.
//
// Every write is two steps. The review step builds the exact API call, holds its bytes
// server-side (single-use, capped, expiring with ConfirmTTL) and renders them in full; the run
// step spends the held entry and dispatches those bytes verbatim through the guarded chain. A
// route the gate classifies as needing confirmation (needsConfirmation(routeRiskFor(path)), e.g.
// /api/discovery's riskAttack) is also minted at the gate, and the held token IS that one-time
// confirmation; any other route gets a random review token of its own.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/extscan"
)

// ui2HeldCallCap bounds the open reviews; a full map is refused and said, never silently dropped.
const ui2HeldCallCap = 8

// ui2HeldCall is one reviewed-but-unconfirmed API call.
type ui2HeldCall struct {
	domain  string // the page that minted it; only that page's run step may spend it
	op      string
	method  string
	path    string
	body    []byte // nil for a body-less call
	gated   bool   // token is a gate confirmation, sent as X-Burpsy-Confirm
	token   string
	expires time.Time
}

// ui2HoldCall mints (when the route is gated) and holds one call, returning its review id.
func (s *Server) ui2HoldCall(domain, op, method, path string, body []byte) (ui2HeldCall, string, string) {
	_, risk, ok := routeRiskFor(path)
	if !ok {
		return ui2HeldCall{}, "", path + " is not a known route"
	}
	call := ui2HeldCall{domain: domain, op: op, method: method, path: path, body: body,
		gated: needsConfirmation(risk), expires: time.Now().Add(ConfirmTTL)}
	if call.gated {
		req := map[string]any{"method": method, "url": path}
		if body != nil {
			req["body"] = string(body)
		}
		payload, _ := json.Marshal(req)
		mint := newReq(http.MethodPost, strings.TrimRight(path, "/")+"/confirm")
		mint.Header.Set("Content-Type", "application/json")
		mint.Body = ioNopCloser(strings.NewReader(string(payload)))
		rec := newRecorder()
		s.confirmMux.ServeHTTP(rec, mint)
		var minted struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil || minted.Token == "" {
			return ui2HeldCall{}, "", "the confirmation gate refused to mint a review - try again"
		}
		call.token = minted.Token
	} else {
		tok, err := randomHex(16)
		if err != nil {
			return ui2HeldCall{}, "", "review token: " + err.Error()
		}
		call.token = tok
	}
	id, err := randomHex(16)
	if err != nil {
		return ui2HeldCall{}, "", "review id: " + err.Error()
	}
	now := time.Now()
	count := 0
	s.ui2HeldCalls.Range(func(k, v any) bool {
		if e, ok := v.(ui2HeldCall); ok && now.After(e.expires) {
			s.ui2HeldCalls.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2HeldCallCap {
		return ui2HeldCall{}, "", "too many reviews are open at once - confirm or let some expire, then try again"
	}
	s.ui2HeldCalls.Store(id, call)
	return call, id, ""
}

// ui2SpendCall takes the held entry named by the form (any attempt deletes it) and checks it.
func (s *Server) ui2SpendCall(domain string, r *http.Request) (ui2HeldCall, string) {
	id := r.PostFormValue("review_id")
	v, ok := s.ui2HeldCalls.LoadAndDelete(id)
	call, isCall := v.(ui2HeldCall)
	if !ok || !isCall || call.domain != domain {
		return ui2HeldCall{}, "that review is unknown or was already used - review the change again"
	}
	if time.Now().After(call.expires) {
		return ui2HeldCall{}, "that review expired with the confirmation window - review the change again"
	}
	if subtle.ConstantTimeCompare([]byte(call.token), []byte(r.PostFormValue("token"))) != 1 {
		return ui2HeldCall{}, "that review does not match this confirmation - review the change again"
	}
	return call, ""
}

// ui2DispatchHeldCall sends the held bytes verbatim through the guarded chain, as the operator's
// browser would, and returns the 2xx body or the API's own refusal text.
func (s *Server) ui2DispatchHeldCall(call ui2HeldCall) ([]byte, string) {
	req := newReq(call.method, call.path)
	if call.body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(call.body)))
	}
	if call.gated {
		req.Header.Set(ConfirmHeader, call.token)
	}
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code == http.StatusPreconditionRequired {
		return nil, "confirmation required (428) - the review and the dispatch disagree; review again"
	}
	if rec.Code < 200 || rec.Code > 299 {
		return nil, ui2APIErrorText(truncateForDisplay(strings.TrimSpace(rec.Body.String()), 600))
	}
	return rec.Body.Bytes(), ""
}

// ui2ReviewSheet is the model for discovery_review.html (shared with the DOM auditor).
type ui2ReviewSheet struct {
	Error    string
	What     string // one sentence naming the action
	Effect   string // what running it does
	Method   string
	Path     string
	Body     string // the exact held bytes
	Gated    bool
	ReviewID string
	Token    string
	RunURL   string
	Target   string // hx-target for the run step
	Back     string
}

func ui2RenderReview(w http.ResponseWriter, r *http.Request, title, view string, m ui2ReviewSheet) {
	ui2Fragment(w, r, title, view, ui2Exec("discovery_review.html", m))
}

func ui2FormOnly(r *http.Request) string {
	if r.Method != http.MethodPost {
		return "method not allowed"
	}
	if err := r.ParseForm(); err != nil {
		return "invalid form"
	}
	if len(r.URL.Query()) != 0 {
		return "query fields are not permitted here"
	}
	return ""
}

// ---- page model -----------------------------------------------------------------------------

// ui2DiscoveryState is GET /api/discovery's answer, decoded into the handler's own types.
type ui2DiscoveryState struct {
	Tool     discoveryToolState   `json:"tool"`
	Runs     []discoveryRun       `json:"runs"`
	Lists    []discoveryListEntry `json:"lists"`
	Retained int                  `json:"retained"`
}

type ui2DiscoveryRow struct {
	extscan.Discovery
	Idx         int
	ShownPath   string
	StatusClass string
	HistoryHref string
}

type ui2DiscoveryRunView struct {
	discoveryRun
	StartedAt  string
	StateClass string
	Rows       []ui2DiscoveryRow
	Chips      []ui2DiscoveryChip
}

type ui2DiscoveryChip struct {
	Status, Count int
	Class         string
}

type ui2DiscoveryModel struct {
	Tool      discoveryToolState
	Lists     []discoveryListEntry
	Uploads   []wordlistEntry
	Retained  int
	Runs      []ui2DiscoveryRunView
	Running   bool
	Depths    []int
	Error     string
	Note      string
	Done      string
	LaunchURL string
}

func (s *Server) ui2DiscoveryState() (ui2DiscoveryState, string) {
	var st ui2DiscoveryState
	req := newReq(http.MethodGet, "/api/discovery")
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return st, strings.TrimSpace(rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		return st, "unreadable discovery state: " + err.Error()
	}
	return st, ""
}

func (s *Server) ui2DiscoveryUploads() []wordlistEntry {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/wordlists"))
	var out struct {
		Wordlists []wordlistEntry `json:"wordlists"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	ups := make([]wordlistEntry, 0, len(out.Wordlists))
	for _, w := range out.Wordlists {
		if w.Kind == "upload" {
			ups = append(ups, w)
		}
	}
	return ups
}

func ui2DiscoveryStatusClass(code int) string {
	switch {
	case code >= 500:
		return "st-bad"
	case code == 401 || code == 403:
		return "st-warn"
	case code >= 400:
		return "st-neutral"
	case code >= 300:
		return "st-info"
	default:
		return "st-good"
	}
}

// ui2DiscoveryHistoryHref is the History view filtered to a discovered path, in the query DSL.
func ui2DiscoveryHistoryHref(d extscan.Discovery) string {
	p := d.Path
	if p == "" {
		p = "/"
	}
	esc := strings.ReplaceAll(strings.ReplaceAll(p, `\`, `\\`), `"`, `\"`)
	q := fmt.Sprintf(`host = %s AND path ~ "%s"`, d.Host, esc)
	return "/ui2/history?" + url.Values{"q": {q}}.Encode()
}

func (s *Server) ui2DiscoveryModel() ui2DiscoveryModel {
	st, errText := s.ui2DiscoveryState()
	m := ui2DiscoveryModel{Tool: st.Tool, Lists: st.Lists, Retained: st.Retained, Error: errText}
	for i := 0; i <= MaxDiscoveryRecurseDepth; i++ {
		m.Depths = append(m.Depths, i)
	}
	if st.Tool.Available {
		m.Uploads = s.ui2DiscoveryUploads()
	}
	for _, run := range st.Runs {
		v := ui2DiscoveryRunView{discoveryRun: run, StateClass: "state-" + run.State,
			StartedAt: run.Started.Local().Format("2006-01-02 15:04:05")}
		if run.State == "running" {
			m.Running = true
		}
		for _, c := range run.Counts.ByStatus {
			v.Chips = append(v.Chips, ui2DiscoveryChip{Status: c.Status, Count: c.Count, Class: ui2DiscoveryStatusClass(c.Status)})
		}
		for i, d := range run.Discoveries {
			shown := d.Path
			if shown == "" {
				shown = "/"
			}
			v.Rows = append(v.Rows, ui2DiscoveryRow{Discovery: d, Idx: i, ShownPath: shown,
				StatusClass: ui2DiscoveryStatusClass(d.Status), HistoryHref: ui2DiscoveryHistoryHref(d)})
		}
		m.Runs = append(m.Runs, v)
	}
	return m
}

const ui2DiscoveryTitle = "burpsy /ui2/ — Content discovery"

// handleUI2Discovery serves GET /ui2/discovery: the sweep form and the retained runs.
func (s *Server) handleUI2Discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ui2Fragment(w, r, ui2DiscoveryTitle, "discovery", ui2Exec("discovery.html", s.ui2DiscoveryModel()))
}

// handleUI2DiscoveryRuns serves GET /ui2/discovery/runs: the runs section alone, which polls
// itself every 2s while a run is still going.
func (s *Server) handleUI2DiscoveryRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ui2Fragment(w, r, ui2DiscoveryTitle, "discovery", ui2Exec("discovery_runs.html", s.ui2DiscoveryModel()))
}

// ui2DiscoveryFindRow resolves (task, idx) to a discovered row from server state.
func (s *Server) ui2DiscoveryFindRow(task, idx string) (extscan.Discovery, string) {
	id, err := strconv.ParseUint(task, 10, 64)
	if err != nil {
		return extscan.Discovery{}, "task must be a whole number"
	}
	i, err := strconv.Atoi(idx)
	if err != nil || i < 0 {
		return extscan.Discovery{}, "row index must be a whole number"
	}
	run, ok := s.discoveries.get(id)
	if !ok {
		return extscan.Discovery{}, fmt.Sprintf("no content-discovery run %d is retained", id)
	}
	if i >= len(run.Discoveries) {
		return extscan.Discovery{}, fmt.Sprintf("run %d has no row %d", id, i)
	}
	return run.Discoveries[i], ""
}

// handleUI2DiscoveryRepeater serves GET /ui2/discovery/repeater?task=&idx=: a GET for the
// discovered path, built from its URL, loaded into the Repeater editor. Nothing is sent - the
// sweep captured no request bytes, so the draft is synthesised and the page says so.
func (s *Server) handleUI2DiscoveryRepeater(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	d, errText := s.ui2DiscoveryFindRow(q.Get("task"), q.Get("idx"))
	if errText != "" {
		ui2RenderPage(w, ui2DiscoveryTitle, "discovery", ui2Exec("error.html", ui2Error{Message: errText}))
		return
	}
	u, err := url.Parse(d.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		ui2RenderPage(w, ui2DiscoveryTitle, "discovery", ui2Exec("error.html", ui2Error{Message: "the discovered URL is not an http(s) URL"}))
		return
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	draft := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nAccept: */*\r\n\r\n"
	notice := "A GET for " + d.URL + " was built from the discovered URL - the sweep captured no request bytes. Nothing has been sent."
	body := templateHTML(`<p class="meta">`+template.HTMLEscapeString(notice)+`</p>`) +
		ui2Exec("repeater.html", map[string]any{"draft": draft, "target": u.Scheme + "://" + u.Host, "result": nil})
	ui2RenderPage(w, "burpsy /ui2/ — Repeater", "repeater", body)
}

// ui2DiscoveryStartBody builds the exact POST /api/discovery body from the sweep form. Empty
// optional fields are omitted so ffuf's own defaults apply; a number that does not parse is
// refused with the field named rather than silently meaning "uncapped".
func ui2DiscoveryStartBody(f url.Values, lists []discoveryListEntry, uploads []wordlistEntry) ([]byte, string) {
	body := map[string]any{}
	target := strings.TrimSpace(f.Get("target"))
	if target == "" {
		return nil, "a target URL is required, e.g. https://target.test/app/"
	}
	body["target"] = target
	wl := strings.TrimSpace(f.Get("wordlist"))
	if up := f.Get("wordlist_upload"); up != "" {
		if wl != "" {
			return nil, "give either a wordlist path or an uploaded list, not both"
		}
		known := false
		for _, u := range uploads {
			known = known || u.Ref == up
		}
		if !known {
			return nil, "that uploaded list is no longer in the inventory - reload the page"
		}
		wl = up
	}
	if wl != "" {
		body["wordlist"] = wl
	}
	var picked []string
	for _, name := range f["lists"] {
		known := false
		for _, l := range lists {
			known = known || l.Name == name
		}
		if !known {
			return nil, fmt.Sprintf("unknown built-in list %q", name)
		}
		picked = append(picked, name)
	}
	if len(picked) > 0 {
		body["lists"] = picked
	}
	if wl == "" && len(picked) == 0 {
		return nil, "a wordlist path, an uploaded list or at least one built-in list is required"
	}
	for _, k := range []string{"extensions", "match_codes", "variant_extensions"} {
		if v := strings.TrimSpace(f.Get(k)); v != "" {
			body[k] = v
		}
	}
	rate, errText := ui2ParseCount("rate", strings.TrimSpace(f.Get("rate")))
	if errText != "" {
		return nil, errText
	}
	if rate > 0 {
		body["rate"] = rate
	}
	depth, errText := ui2ParseCount("recurse_depth", strings.TrimSpace(f.Get("recurse_depth")))
	if errText != "" {
		return nil, errText
	}
	if depth > MaxDiscoveryRecurseDepth {
		return nil, fmt.Sprintf("recurse_depth must be 0 to %d", MaxDiscoveryRecurseDepth)
	}
	if depth > 0 {
		body["recurse_depth"] = depth
	}
	if f.Get("observed_names") != "" {
		body["observed_names"] = true
	}
	if f.Get("derivations") != "" {
		body["derivations"] = true
	}
	b, _ := json.Marshal(body)
	return b, ""
}

// handleUI2DiscoveryReview serves POST /ui2/discovery/review: op=start (the sweep form) or
// op=browser (task, idx). It holds the exact call and renders it; nothing is sent.
func (s *Server) handleUI2DiscoveryReview(w http.ResponseWriter, r *http.Request) {
	sheet := ui2ReviewSheet{RunURL: "/ui2/discovery/run", Target: "#discovery", Back: "/ui2/discovery"}
	if msg := ui2FormOnly(r); msg != "" {
		if msg == "method not allowed" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sheet.Error = msg
		ui2RenderReview(w, r, ui2DiscoveryTitle, "discovery", sheet)
		return
	}
	var body []byte
	path := "/api/discovery"
	switch op := r.PostFormValue("op"); op {
	case "start":
		st, errText := s.ui2DiscoveryState()
		if errText == "" && !st.Tool.Available {
			errText = "content discovery is not available on this server: " + st.Tool.Reason
		}
		if errText == "" {
			body, errText = ui2DiscoveryStartBody(r.PostForm, st.Lists, s.ui2DiscoveryUploads())
		}
		if errText != "" {
			sheet.Error = errText
			ui2RenderReview(w, r, ui2DiscoveryTitle, "discovery", sheet)
			return
		}
		sheet.What = "Start a content-discovery sweep."
		sheet.Effect = "ffuf sends one request per word (times each extension) to the target, outside burpsy's proxy: these requests appear in no history row. Scope is checked before the run and on every result."
	case "browser":
		d, errText := s.ui2DiscoveryFindRow(r.PostFormValue("task"), r.PostFormValue("idx"))
		if errText != "" {
			sheet.Error = errText
			ui2RenderReview(w, r, ui2DiscoveryTitle, "discovery", sheet)
			return
		}
		path = "/api/browser/launch"
		body, _ = json.Marshal(map[string]string{"url": d.URL})
		sheet.What = "Open " + d.URL + " in burpsy's browser."
		sheet.Effect = "The browser loads the URL through the proxy - one request to the target, recorded in history."
	default:
		sheet.Error = "unknown review action"
		ui2RenderReview(w, r, ui2DiscoveryTitle, "discovery", sheet)
		return
	}
	call, id, errText := s.ui2HoldCall("discovery", r.PostFormValue("op"), http.MethodPost, path, body)
	if errText != "" {
		sheet.Error = errText
		ui2RenderReview(w, r, ui2DiscoveryTitle, "discovery", sheet)
		return
	}
	sheet.Method, sheet.Path, sheet.Body, sheet.Gated = call.method, call.path, string(call.body), call.gated
	sheet.ReviewID, sheet.Token = id, call.token
	ui2RenderReview(w, r, ui2DiscoveryTitle, "discovery", sheet)
}

// handleUI2DiscoveryRun serves POST /ui2/discovery/run: spends the held call and re-renders the
// page with the outcome.
func (s *Server) handleUI2DiscoveryRun(w http.ResponseWriter, r *http.Request) {
	if msg := ui2FormOnly(r); msg == "method not allowed" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	note, done := "", ""
	call, errText := s.ui2SpendCall("discovery", r)
	if errText == "" {
		var out []byte
		out, errText = s.ui2DispatchHeldCall(call)
		if errText == "" {
			switch call.op {
			case "start":
				var acc struct {
					TaskID uint64 `json:"task_id"`
					Target string `json:"target"`
				}
				_ = json.Unmarshal(out, &acc)
				done = fmt.Sprintf("Sweep #%d started against %s.", acc.TaskID, acc.Target)
			case "browser":
				done = "The browser was asked to open the URL."
			}
		}
	}
	if errText != "" {
		note = "Not run: " + errText
	}
	m := s.ui2DiscoveryModel()
	m.Note, m.Done = note, done
	ui2Fragment(w, r, ui2DiscoveryTitle, "discovery", ui2Exec("discovery.html", m))
}
