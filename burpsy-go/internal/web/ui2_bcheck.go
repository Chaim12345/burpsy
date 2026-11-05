package web

// ui2 Custom scan checks (BCheck) editor: the /ui2/ counterpart of the SPA's
// pages/scannerchecks.tsx and ui/custom-check-editor.tsx.
//
// Every model comes from the JSON API through the in-process mux; nothing here re-implements the
// corpus, the parser or the trial runner. Reads (list, source, validate) are direct calls. Writes:
//   - enable/disable and reload (riskLocal, the SPA fires them on one click) are direct POSTs;
//   - import (Save) and delete hold the exact call server-side for a review sheet, and test
//     (riskAttack: an active draft sends probes) does the same with a gate token minted for the
//     exact body. Which path a call takes is derived from needsConfirmation(routeRiskFor(path)),
//     never hard-coded, so a reclassified route changes this page with it.
//
// The run step spends the held entry atomically (LoadAndDelete), compares the token in constant
// time and dispatches the held bytes verbatim: the run form carries only the review id and token.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ui2BCheckReviewCap bounds the held reviews, as the other ui2 review maps do.
const ui2BCheckReviewCap = 8

// ui2BCheckMaxSource caps an uploaded or posted draft at the API's own body limit.
const ui2BCheckMaxSource = 1 << 20

type ui2BCheckReview struct {
	op      string // save | delete | test
	name    string // the check the call names, for the outcome line
	token   string
	gated   bool
	method  string
	callURL string
	body    []byte
	expires time.Time
}

// ui2BCheckTemplate is one starting draft for New, mirrored from the SPA's CHECK_TEMPLATES.
type ui2BCheckTemplate struct {
	ID     string
	Label  string
	Source string
}

var ui2BCheckTemplates = []ui2BCheckTemplate{
	{ID: "passive", Label: "Passive: match a response", Source: `metadata:
    language: v2-beta
    name: "New passive check"
    description: "Reports responses that contain a marker"
    author: ""

given response then
    if {latest.response.body} matches "(?i)stack trace" then
        report issue:
            severity: low
            confidence: firm
            detail: ` + "`The response contains a stack trace.`" + `
    end if
`},
	{ID: "host", Label: "Active: request a path once per host", Source: `metadata:
    language: v2-beta
    name: "New host check"
    description: "Requests a path on each host and reports a 200"
    author: ""

given host then
    send request called probe:
        method: "GET"
        path: "/.git/HEAD"

    if {probe.response.status_code} is "200" and {probe.response.body} matches "^ref:" then
        report issue:
            severity: medium
            confidence: firm
            detail: ` + "`{probe.request.url} exposes a Git repository.`" + `
    end if
`},
	{ID: "insertion", Label: "Active: payload at each insertion point", Source: `metadata:
    language: v2-beta
    name: "New insertion point check"
    description: "Sends a payload at each insertion point and looks for its reflection"
    author: ""

given insertion point then
    send payload called probe:
        appending: "'\"><bsy{random_str(6)}>"

    if {probe.response.body} matches "<bsy[a-z0-9]{6}>" then
        report issue:
            severity: medium
            confidence: tentative
            detail: ` + "`The payload was reflected unencoded.`" + `
    end if
`},
}

// ---- models ----------------------------------------------------------------------------------

type ui2BCheckCorpus struct {
	Enabled      bool              `json:"enabled"`
	PassiveCount int               `json:"passive_count"`
	ActiveCount  int               `json:"active_count"`
	Checks       []corpusCheckView `json:"checks"`
}

type ui2BCheckListModel struct {
	Corpus    ui2BCheckCorpus
	LoadError string
	Templates []ui2BCheckTemplate
	Note      string // a refusal the operator must read
	Done      string // the landed fact
	Review    templateHTML
}

type ui2BCheckValidation struct {
	Valid          bool             `json:"valid"`
	Name           string           `json:"name"`
	Kind           string           `json:"kind"`
	ExistingOrigin string           `json:"existing_origin"`
	Error          *checkParseError `json:"error"`
}

type ui2BCheckEditorModel struct {
	Heading    string
	Source     string
	Editing    string // a console check being edited; "" for a new draft
	ReadOnly   bool
	From       string // where a read-only check is loaded from
	IDs        string
	Error      string
	Validation *ui2BCheckValidation
	// ValidationError is a refused Validate call (not an invalid draft, which is Validation).
	ValidationError string
	Templates       []ui2BCheckTemplate
}

type ui2BCheckReviewModel struct {
	Error    string
	Op       string
	Name     string
	ReviewID string
	Token    string
	Gated    bool
	Risk     string
	Call     string
	Body     string // the exact held bytes
	Source   string // the draft carried by the body, for reading
	IDs      []uint64
	Replace  bool
	Renamed  string // the console check the editor opened, when the draft now names another
	Kind     string
	Target   string // hx-target for the run form
	Swap     string
}

type ui2BCheckTestModel struct {
	Error   string
	Name    string
	Kind    string
	Results []checkTestResult
}

// ---- page and fragments ----------------------------------------------------------------------

const ui2BCheckTitle = "burpsy /ui2/ — Custom scan checks"

// handleUI2BChecks serves GET /ui2/bchecks: the corpus table with its toolbar.
func (s *Server) handleUI2BChecks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ui2Fragment(w, r, ui2BCheckTitle, "bchecks", s.ui2BCheckList("", "", ""))
}

func (s *Server) ui2BCheckList(note, done string, review templateHTML) templateHTML {
	m := ui2BCheckListModel{Templates: ui2BCheckTemplates, Note: note, Done: done, Review: review}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/scanner/checks"))
	if rec.Code != http.StatusOK {
		m.LoadError = ui2APIErrorText(strings.TrimSpace(rec.Body.String()))
	} else if err := ui2DecodeJSON(rec.Body.Bytes(), &m.Corpus); err != nil {
		m.LoadError = "unreadable corpus: " + err.Error()
	}
	return ui2Exec("bcheck_list.html", m)
}

// ui2BCheckSource reads one loaded check's source through the API (?name= escaped).
func (s *Server) ui2BCheckSource(name string) (map[string]any, string) {
	res, errText := s.ui2APIResult(http.MethodGet, "/api/scanner/checks/source?name="+url.QueryEscape(name), nil)
	if errText != "" {
		return nil, ui2APIErrorText(errText)
	}
	m, _ := res.(map[string]any)
	if m == nil {
		return nil, "unreadable check source"
	}
	return m, ""
}

// handleUI2BCheckEditor serves GET /ui2/bchecks/editor: ?name= opens a loaded check (a console
// check is editable, a file or bundled one read-only), ?template= starts a new draft.
func (s *Server) handleUI2BCheckEditor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := ui2BCheckEditorModel{Templates: ui2BCheckTemplates}
	if name := r.URL.Query().Get("name"); name != "" {
		src, errText := s.ui2BCheckSource(name)
		if errText != "" {
			m.Heading = "Custom scan check"
			m.Error = errText
		} else {
			m.Source, _ = src["source"].(string)
			origin, _ := src["origin"].(string)
			if origin == "console" {
				m.Editing = name
				m.Heading = "Edit custom scan check — " + name
			} else {
				m.ReadOnly = true
				m.From, _ = src["file"].(string)
				if m.From == "" {
					m.From = origin
				}
				m.Heading = "View custom scan check — " + m.From
			}
		}
	} else {
		tpl := ui2BCheckTemplates[0]
		for _, t := range ui2BCheckTemplates {
			if t.ID == r.URL.Query().Get("template") {
				tpl = t
			}
		}
		m.Source = tpl.Source
		m.Heading = "New custom scan check — " + tpl.Label
	}
	ui2Fragment(w, r, ui2BCheckTitle, "bchecks", ui2Exec("bcheck_editor.html", m))
}

// handleUI2BCheckExport serves GET /ui2/bchecks/export?name=: the check's source as a download.
func (s *Server) handleUI2BCheckExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if strings.TrimSpace(name) == "" {
		http.Error(w, "name a check: ?name=", http.StatusBadRequest)
		return
	}
	src, errText := s.ui2BCheckSource(name)
	if errText != "" {
		http.Error(w, errText, http.StatusNotFound)
		return
	}
	body, _ := src["source"].(string)
	file, _ := src["file"].(string)
	if file == "" {
		file = name
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+ui2BCheckFileName(file)+`"`)
	_, _ = io.WriteString(w, body) //nolint:gosec // G705: text/plain, nosniff, attachment — the operator's own check source, never rendered
}

var ui2BCheckUnsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// ui2BCheckFileName is the SPA's export name: unsafe runs become "_" and the name ends .bcheck.
func ui2BCheckFileName(name string) string {
	base := strings.TrimSuffix(ui2BCheckUnsafeName.ReplaceAllString(name, "_"), ".bcheck")
	base = strings.TrimSuffix(base, ".BCHECK")
	if base == "" {
		base = "check"
	}
	return base + ".bcheck"
}

// ---- direct actions (riskLocal, one click in the SPA) -----------------------------------------

// handleUI2BCheckEnable serves POST /ui2/bchecks/enable {name, enabled}: the per-row switch.
func (s *Server) handleUI2BCheckEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	name := r.PostFormValue("name")
	enabled := r.PostFormValue("enabled") == "true"
	res, errText := s.ui2APIResult(http.MethodPut, "/api/scanner/checks/enable", corpusCheckEnableReq{Name: name, Enabled: enabled})
	note, done := "", ""
	if errText != "" {
		note = "Not changed: " + ui2APIErrorText(errText)
	} else {
		// The outcome is the state the API read back, not the click.
		m, _ := res.(map[string]any)
		state := "enabled"
		if d, _ := m["disabled"].(bool); d {
			state = "disabled"
		}
		done = fmt.Sprintf("%q is now %s for the next audit.", name, state)
	}
	ui2Fragment(w, r, ui2BCheckTitle, "bchecks", s.ui2BCheckList(note, done, ""))
}

// handleUI2BCheckReload serves POST /ui2/bchecks/reload: re-read the --bchecks directory.
func (s *Server) handleUI2BCheckReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	res, errText := s.ui2APIResult(http.MethodPost, "/api/scanner/checks/reload", nil)
	note, done := "", ""
	if errText != "" {
		note = "Reload refused: " + ui2APIErrorText(errText)
	} else {
		var out struct {
			Summary  string              `json:"summary"`
			Errors   []map[string]string `json:"errors"`
			Shadowed []string            `json:"shadowed"`
		}
		b, _ := json.Marshal(res)
		_ = json.Unmarshal(b, &out)
		done = "Reloaded: " + out.Summary
		if len(out.Shadowed) > 0 {
			done += ". A file now provides " + strings.Join(out.Shadowed, ", ") + "; the console version was dropped"
		}
		if len(out.Errors) > 0 {
			files := make([]string, 0, len(out.Errors))
			for _, e := range out.Errors {
				files = append(files, e["file"]+": "+e["error"])
			}
			note = fmt.Sprintf("%d file(s) did not parse: %s", len(out.Errors), strings.Join(files, "; "))
		}
	}
	ui2Fragment(w, r, ui2BCheckTitle, "bchecks", s.ui2BCheckList(note, done, ""))
}

// ---- editor reads -----------------------------------------------------------------------------

// ui2BCheckEditorForm reads the editor's fields (source, editing, ids, readonly).
func ui2BCheckEditorForm(w http.ResponseWriter, r *http.Request) (ui2BCheckEditorModel, string) {
	r.Body = http.MaxBytesReader(w, r.Body, 2*ui2BCheckMaxSource)
	if err := r.ParseForm(); err != nil {
		return ui2BCheckEditorModel{}, "the form could not be read (a draft is limited to 1 MiB)"
	}
	m := ui2BCheckEditorModel{
		Source:    ui2NormalizeNewlines(r.PostFormValue("source")),
		Editing:   r.PostFormValue("editing"),
		IDs:       r.PostFormValue("exchange_ids"),
		ReadOnly:  r.PostFormValue("readonly") != "",
		From:      r.PostFormValue("from"),
		Heading:   r.PostFormValue("heading"),
		Templates: ui2BCheckTemplates,
	}
	if m.Heading == "" {
		m.Heading = "Custom scan check"
	}
	return m, ""
}

func (s *Server) ui2BCheckValidate(source string) (*ui2BCheckValidation, string) {
	res, errText := s.ui2APIResult(http.MethodPost, "/api/scanner/checks/validate", checkValidateReq{Source: source})
	if errText != "" {
		return nil, ui2APIErrorText(errText)
	}
	var v ui2BCheckValidation
	b, _ := json.Marshal(res)
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, "unreadable validation: " + err.Error()
	}
	return &v, ""
}

// handleUI2BCheckValidate serves POST /ui2/bchecks/validate: Burp's Validate - a read.
func (s *Server) handleUI2BCheckValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m, errText := ui2BCheckEditorForm(w, r)
	if errText == "" {
		m.Validation, errText = s.ui2BCheckValidate(m.Source)
	}
	m.ValidationError = errText
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("bcheck_validation.html", m)))
		return
	}
	ui2RenderPage(w, ui2BCheckTitle, "bchecks", ui2Exec("bcheck_editor.html", m))
}

// handleUI2BCheckUpload serves POST /ui2/bchecks/upload: Import a .bcheck file into the editor.
// Nothing is loaded - the file opens as a draft that Save reviews like any other.
func (s *Server) handleUI2BCheckUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fail := func(msg string) {
		ui2Fragment(w, r, ui2BCheckTitle, "bchecks", s.ui2BCheckList("Not imported: "+msg, "", ""))
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2*ui2BCheckMaxSource)
	if err := r.ParseMultipartForm(2 * ui2BCheckMaxSource); err != nil {
		fail("choose a .bcheck file (up to 1 MiB)")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail("choose a .bcheck file")
		return
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, ui2BCheckMaxSource+1))
	if err != nil || len(raw) > ui2BCheckMaxSource {
		fail("the file is unreadable or larger than 1 MiB")
		return
	}
	if !utf8.Valid(raw) || strings.ContainsRune(string(raw), 0) {
		fail("the file is not UTF-8 text - a BCheck is plain text")
		return
	}
	m := ui2BCheckEditorModel{
		Source:    ui2NormalizeNewlines(string(raw)),
		Heading:   "Import custom scan check — " + hdr.Filename,
		Templates: ui2BCheckTemplates,
	}
	ui2Fragment(w, r, ui2BCheckTitle, "bchecks", ui2Exec("bcheck_editor.html", m))
}

// ---- reviewed writes --------------------------------------------------------------------------

// ui2BCheckParseIDs reads "3, 7 12" into unique ids, in order.
func ui2BCheckParseIDs(text string) ([]uint64, string) {
	seen := map[uint64]bool{}
	var ids []uint64
	for _, f := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return nil, fmt.Sprintf("%q is not an exchange id", f)
		}
		if !seen[n] {
			seen[n] = true
			ids = append(ids, n)
		}
	}
	if len(ids) == 0 {
		return nil, "add at least one exchange id to test against (see the History page)"
	}
	if len(ids) > maxCheckTestExchanges {
		return nil, fmt.Sprintf("name at most %d exchanges per test", maxCheckTestExchanges)
	}
	return ids, ""
}

// handleUI2BCheckReview serves POST /ui2/bchecks/review/{op}: builds the exact API call for
// save, delete or test, holds it, and renders the review sheet. Nothing is written here.
func (s *Server) handleUI2BCheckReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	op := r.PathValue("op")
	sheet := func(m ui2BCheckReviewModel) {
		m.Op = op
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body := ui2Exec("bcheck_review.html", m)
		if r.Header.Get("HX-Request") == "true" {
			_, _ = w.Write([]byte(body))
			return
		}
		ui2RenderPage(w, ui2BCheckTitle, "bchecks", body)
	}
	fail := func(msg string) { sheet(ui2BCheckReviewModel{Error: msg}) }

	var (
		apiPath, method, callURL, name string
		payload                        any
		model                          ui2BCheckReviewModel
	)
	switch op {
	case "save", "test":
		ed, errText := ui2BCheckEditorForm(w, r)
		if errText != "" {
			fail(errText)
			return
		}
		v, errText := s.ui2BCheckValidate(ed.Source)
		if errText != "" {
			fail(errText)
			return
		}
		if !v.Valid {
			msg := "the draft does not parse"
			if v.Error != nil {
				msg += ": " + ui2BCheckErrorText(v.Error)
			}
			fail(msg + " - Validate shows where")
			return
		}
		name, model.Kind = v.Name, v.Kind
		method = http.MethodPost
		if op == "save" {
			if ed.ReadOnly {
				fail("this check is loaded from " + ed.From + " and is read-only here: edit the file and Reload")
				return
			}
			if v.ExistingOrigin == "file" {
				fail(fmt.Sprintf("a check loaded from a --bchecks file is already named %q; Save would be refused - rename the draft", name))
				return
			}
			replace := v.ExistingOrigin == "console"
			apiPath, callURL = "/api/scanner/checks/import", "/api/scanner/checks/import"
			payload = checkImportReq{Source: ed.Source, Replace: replace}
			model.Replace = replace
			if ed.Editing != "" && ed.Editing != name {
				model.Renamed = ed.Editing
			}
			model.Target, model.Swap = "#bchecks", "outerHTML"
		} else {
			ids, errText := ui2BCheckParseIDs(ed.IDs)
			if errText != "" {
				fail(errText)
				return
			}
			apiPath, callURL = "/api/scanner/checks/test", "/api/scanner/checks/test"
			payload = checkTestReq{Source: ed.Source, ExchangeIDs: ids}
			model.Target, model.Swap = "#bcheck-review", "innerHTML"
		}
	case "delete":
		_ = r.ParseForm()
		name = r.PostFormValue("name")
		if strings.TrimSpace(name) == "" {
			fail("name a check to delete")
			return
		}
		method = http.MethodDelete
		apiPath, callURL = "/api/scanner/checks/source", "/api/scanner/checks/source?name="+url.QueryEscape(name)
		model.Target, model.Swap = "#bchecks", "outerHTML"
	default:
		fail("unknown review step")
		return
	}

	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	_, risk, _ := routeRiskFor(apiPath)
	gated := needsConfirmation(risk)
	token := ""
	if gated {
		mintCall := map[string]any{"method": method, "url": callURL}
		if body != nil {
			mintCall["body"] = string(body)
		}
		raw, _ := json.Marshal(mintCall)
		req := newReq(http.MethodPost, apiPath+"/confirm")
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(raw)))
		rec := newRecorder()
		s.confirmMux.ServeHTTP(rec, req)
		var minted struct {
			Token string `json:"token"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &minted) != nil || minted.Token == "" {
			fail("the confirmation gate refused to mint a review - try again")
			return
		}
		token = minted.Token
	} else {
		local, err := randomHex(16)
		if err != nil {
			fail("review token: " + err.Error())
			return
		}
		token = local
	}
	id, err := randomHex(16)
	if err != nil {
		fail("review id: " + err.Error())
		return
	}
	now := time.Now()
	s.ui2BCheckReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2BCheckReview); ok && now.After(e.expires) {
			s.ui2BCheckReviews.Delete(k)
		}
		return true
	})
	count := 0
	s.ui2BCheckReviews.Range(func(_, _ any) bool { count++; return true })
	if count >= ui2BCheckReviewCap {
		fail("too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	s.ui2BCheckReviews.Store(id, ui2BCheckReview{
		op: op, name: name, token: token, gated: gated, method: method, callURL: callURL, body: body,
		expires: now.Add(ConfirmTTL),
	})

	// The sheet reads the held bytes back, so what it shows is what the token binds.
	model.Name, model.ReviewID, model.Token, model.Gated, model.Risk = name, id, token, gated, string(risk)
	model.Call = method + " " + callURL
	model.Body = string(body)
	var held struct {
		Source      string   `json:"source"`
		ExchangeIDs []uint64 `json:"exchange_ids"`
	}
	if body != nil {
		_ = json.Unmarshal(body, &held)
	}
	model.Source, model.IDs = held.Source, held.ExchangeIDs
	sheet(model)
}

// handleUI2BCheckRun serves POST /ui2/bchecks/run {review_id, token}: spends the held call.
func (s *Server) handleUI2BCheckRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	refuse := func(msg string) {
		ui2Fragment(w, r, ui2BCheckTitle, "bchecks", ui2Exec("bcheck_review.html", ui2BCheckReviewModel{Error: msg}))
	}
	// Deleted on ANY spend attempt, so nothing is replayable.
	v, ok := s.ui2BCheckReviews.LoadAndDelete(r.PostFormValue("review_id"))
	entry, isReview := v.(ui2BCheckReview)
	if !ok || !isReview {
		refuse("that review is unknown or was already used - review again")
		return
	}
	if time.Now().After(entry.expires) {
		refuse("that review expired with the confirmation window - review again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostFormValue("token"))) != 1 {
		refuse("that review does not match this confirmation - review again")
		return
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
	refusal := ""
	switch {
	case rec.Code == http.StatusPreconditionRequired:
		refusal = "confirmation required (428) - the review and the dispatch disagree; review again"
	case rec.Code >= http.StatusBadRequest:
		refusal = ui2BCheckAPIRefusal(rec.Body.Bytes())
	}

	if entry.op == "test" {
		m := ui2BCheckTestModel{Error: refusal}
		if refusal == "" {
			var out struct {
				Name    string            `json:"name"`
				Kind    string            `json:"kind"`
				Results []checkTestResult `json:"results"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				m.Error = "unreadable test result: " + err.Error()
			}
			m.Name, m.Kind, m.Results = out.Name, out.Kind, out.Results
		}
		ui2Fragment(w, r, ui2BCheckTitle, "bchecks", ui2Exec("bcheck_test_results.html", m))
		return
	}
	note, done := "", ""
	if refusal != "" {
		note = "Not applied: " + refusal
	} else if entry.op == "delete" {
		done = fmt.Sprintf("Deleted %q from the corpus and the project.", entry.name)
	} else {
		var out struct {
			Name         string `json:"name"`
			Kind         string `json:"kind"`
			Persisted    bool   `json:"persisted"`
			PersistError string `json:"persist_error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Persisted {
			done = fmt.Sprintf("Saved %q (%s) into the corpus and the project.", out.Name, out.Kind)
		} else {
			done = fmt.Sprintf("Loaded %q (%s); no project database, so it lasts until restart.", out.Name, out.Kind)
			if out.PersistError != "" {
				note = "The project could not be saved: " + out.PersistError
			}
		}
		w.Header().Set("HX-Push-Url", "/ui2/bchecks")
	}
	ui2Fragment(w, r, ui2BCheckTitle, "bchecks", s.ui2BCheckList(note, done, ""))
}

// ui2BCheckAPIRefusal renders an API refusal: a parse error with its position, the API error
// sentence, or the plain-text body.
func ui2BCheckAPIRefusal(body []byte) string {
	var pe struct {
		Error *checkParseError `json:"error"`
	}
	if json.Unmarshal(body, &pe) == nil && pe.Error != nil && pe.Error.Message != "" {
		return ui2BCheckErrorText(pe.Error)
	}
	return truncateForDisplay(ui2APIErrorText(strings.TrimSpace(string(body))), 300)
}

func ui2BCheckErrorText(e *checkParseError) string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d:%d — %s", e.Line, e.Column, e.Message)
	}
	return e.Message
}
