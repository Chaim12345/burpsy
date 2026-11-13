package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/intercept"
)

// ---- Intercept rules editor -------------------------------------------------------------------
//
// GET /ui2/intercept/rules?dir= renders one direction's rule list as an editable form. The
// editor is stateless: add, remove and reorder post the whole draft to /edit, which answers the
// transformed draft without writing anything. Saving is a server-held review (the PUT is
// riskLocal and whole-list): /confirm builds the exact PUT body from the draft, holds it with a
// snapshot of the list it replaces, and renders a sheet from those bytes; /run spends the entry
// once, re-reads the list and refuses on drift, then dispatches the held body verbatim. /quick
// builds the same review for Burp's "Don't intercept ..." rules from a held message.
//
// The draft carries form_base, the digest of the list the editor was opened on, so a draft made
// against an older list (a quick rule saved from the queue meanwhile) is refused instead of
// silently overwriting the newer list.

const (
	ui2InterceptRuleReviewCap = 8
	ui2InterceptMaxRules      = 200
)

// ui2InterceptRuleReview is one minted rule-list PUT held for review.
type ui2InterceptRuleReview struct {
	token    string
	dir      string
	body     []byte
	snapshot string
	expires  time.Time
}

type ui2IDir struct{ Name, Title, Noun, DefaultField string }

var ui2InterceptDirs = []ui2IDir{
	{"requests", "Request", "request", "host"},
	{"responses", "Response", "response", "status_code"},
	{"websocket_to_server", "WebSocket → server", "client frame", "host"},
	{"websocket_to_client", "WebSocket → client", "server frame", "host"},
}

func ui2InterceptDir(name string) (ui2IDir, bool) {
	for _, d := range ui2InterceptDirs {
		if d.Name == name {
			return d, true
		}
	}
	return ui2IDir{}, false
}

// ui2IRuleField is one match field as the editor offers it; Member names the member input's
// label for header/cookie fields, and Applies is false when the direction never carries it.
type ui2IRuleField struct {
	Value, Label, Member string
	Applies              bool
}

var ui2InterceptRuleFieldTable = []ui2IRuleField{
	{Value: "host", Label: "Host"},
	{Value: "path", Label: "Path"},
	{Value: "extension", Label: "File extension"},
	{Value: "method", Label: "Method"},
	{Value: "url", Label: "URL"},
	{Value: "port", Label: "Port"},
	{Value: "protocol", Label: "Protocol"},
	{Value: "status_code", Label: "Status code"},
	{Value: "content_type", Label: "Content type"},
	{Value: "request_body", Label: "Request body"},
	{Value: "response_body", Label: "Response body"},
	{Value: "request_header", Label: "Request header", Member: "Header name"},
	{Value: "response_header", Label: "Response header", Member: "Header name"},
	{Value: "request_cookie", Label: "Request cookie", Member: "Cookie name"},
	{Value: "response_cookie", Label: "Response cookie", Member: "Cookie name"},
}

func ui2InterceptFieldsFor(dir string) []ui2IRuleField {
	d, _ := directionFor(dir)
	out := make([]ui2IRuleField, len(ui2InterceptRuleFieldTable))
	for i, f := range ui2InterceptRuleFieldTable {
		parsed, err := intercept.ParseField(f.Value)
		f.Applies = err == nil && d.HasField(parsed)
		out[i] = f
	}
	return out
}

func ui2InterceptFieldInfo(value string) (ui2IRuleField, bool) {
	for _, f := range ui2InterceptRuleFieldTable {
		if f.Value == value {
			return f, true
		}
	}
	return ui2IRuleField{}, false
}

// ui2IRuleRow is one rule as the editor and the review sheet render it.
type ui2IRuleRow struct {
	Index, Num                                          int
	Enabled, Last                                       bool
	Op, Action, Field, Member, Match, Category, Comment string
	FieldLabel, MemberLabel                             string
	Applies                                             bool
}

type ui2IRulesModel struct {
	Dir      ui2IDir
	Dirs     []ui2IDir
	Active   bool
	Rules    []ui2IRuleRow
	Fields   []ui2IRuleField
	Base     string
	N        int
	Describe string
	Note     string
	Error    string
	// Review sheet only.
	Review       bool
	Call         string
	Consequences []string
	ReviewID     string
	Token        string
}

func ui2InterceptRows(dir string, specs []interceptRuleSpec) []ui2IRuleRow {
	d, _ := directionFor(dir)
	rows := make([]ui2IRuleRow, len(specs))
	for i, sp := range specs {
		info, _ := ui2InterceptFieldInfo(sp.Field)
		parsed, err := intercept.ParseField(sp.Field)
		op := "or"
		if sp.Op == "and" {
			op = "and"
		}
		action := "hold"
		if sp.Action == "pass" {
			action = "pass"
		}
		rows[i] = ui2IRuleRow{
			Index: i, Num: i + 1, Last: i == len(specs)-1, Enabled: sp.Enabled, Op: op, Action: action, Field: sp.Field, Member: sp.Member,
			Match: sp.Match, Category: sp.Category, Comment: sp.Comment,
			FieldLabel: info.Label, MemberLabel: info.Member, Applies: err == nil && d.HasField(parsed),
		}
	}
	return rows
}

// ui2InterceptDescribe states what a list does, including the two states that look selective
// and are not: an empty active list holds everything, and one with every rule unchecked holds
// nothing.
func ui2InterceptDescribe(d ui2IDir, active bool, specs []interceptRuleSpec) string {
	if !active {
		return "off — no " + d.Noun + " is held"
	}
	if len(specs) == 0 {
		return "on with no conditions — every " + d.Noun + " is held"
	}
	for _, sp := range specs {
		if sp.Enabled {
			return fmt.Sprintf("on with %d condition(s)", len(specs))
		}
	}
	return "on, but every condition is unchecked — no " + d.Noun + " is held"
}

// ui2InterceptListRead reads one list through the API, with its canonical form for drift checks.
func (s *Server) ui2InterceptListRead(dir string) (interceptListState, string, error) {
	canon, err := s.ui2CanonicalGet("/api/intercept/rules/" + dir)
	if err != nil {
		return interceptListState{}, "", err
	}
	var state interceptListState
	if err := json.Unmarshal([]byte(canon), &state); err != nil {
		return interceptListState{}, "", err
	}
	return state, canon, nil
}

func ui2InterceptDigest(canon string) string {
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:])
}

func (s *Server) ui2InterceptRulesModel(d ui2IDir, active bool, specs []interceptRuleSpec, base string) ui2IRulesModel {
	return ui2IRulesModel{
		Dir: d, Dirs: ui2InterceptDirs, Active: active, Rules: ui2InterceptRows(d.Name, specs),
		Fields: ui2InterceptFieldsFor(d.Name), Base: base, N: len(specs),
		Describe: ui2InterceptDescribe(d, active, specs),
	}
}

func ui2InterceptRulesWrite(w http.ResponseWriter, r *http.Request, m ui2IRulesModel) {
	name := "intercept_rules.html"
	if m.Review {
		name = "intercept_rules_confirm.html"
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Intercept rules", "intercept_rules", ui2Exec(name, m))
}

// handleUI2InterceptRules serves GET /ui2/intercept/rules?dir=: one list loaded from the API
// into the editor.
func (s *Server) handleUI2InterceptRules(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("dir")
	if name == "" {
		name = "requests"
	}
	d, ok := ui2InterceptDir(name)
	if !ok {
		d = ui2InterceptDirs[0]
		m := ui2IRulesModel{Dir: d, Dirs: ui2InterceptDirs, Error: "unknown rule list " + strconv.Quote(name)}
		ui2InterceptRulesWrite(w, r, m)
		return
	}
	s.ui2InterceptRulesFresh(w, r, d, "")
}

// ui2InterceptRulesFresh renders the editor on the list as stored, with an optional note.
func (s *Server) ui2InterceptRulesFresh(w http.ResponseWriter, r *http.Request, d ui2IDir, note string) {
	state, canon, err := s.ui2InterceptListRead(d.Name)
	if err != nil {
		ui2InterceptRulesWrite(w, r, ui2IRulesModel{Dir: d, Dirs: ui2InterceptDirs, Error: "could not read the rule list: " + err.Error()})
		return
	}
	m := s.ui2InterceptRulesModel(d, state.Active, state.Rules, ui2InterceptDigest(canon))
	m.Note = note
	ui2InterceptRulesWrite(w, r, m)
}

// ui2InterceptParseDraft reads the editor form: the direction, the list switch, the base
// digest and every indexed rule. Values outside each column's vocabulary are refused by name.
func ui2InterceptParseDraft(r *http.Request) (ui2IDir, bool, []interceptRuleSpec, string, string) {
	d, ok := ui2InterceptDir(r.PostForm.Get("dir"))
	if !ok {
		return ui2InterceptDirs[0], false, nil, "", "unknown rule list"
	}
	n, err := strconv.Atoi(r.PostForm.Get("n"))
	if err != nil || n < 0 || n > ui2InterceptMaxRules {
		return d, false, nil, "", fmt.Sprintf("the rule count must be 0 to %d", ui2InterceptMaxRules)
	}
	specs := make([]interceptRuleSpec, 0, n)
	for i := 0; i < n; i++ {
		get := func(k string) string { return r.PostForm.Get(k + "_" + strconv.Itoa(i)) }
		info, ok := ui2InterceptFieldInfo(get("field"))
		if !ok {
			return d, false, nil, "", fmt.Sprintf("rule %d: unknown match field %q", i+1, get("field"))
		}
		sp := interceptRuleSpec{Field: info.Value, Match: get("match"), Enabled: get("enabled") == "on", Comment: get("comment")}
		switch get("category") {
		case "regex", "literal":
			sp.Category = get("category")
		default:
			return d, false, nil, "", fmt.Sprintf("rule %d: match kind must be regex or literal", i+1)
		}
		switch get("action") {
		case "hold", "pass":
			sp.Action = get("action")
		default:
			return d, false, nil, "", fmt.Sprintf("rule %d: action must be hold or pass", i+1)
		}
		switch get("op") {
		case "or", "":
		case "and":
			sp.Op = "and"
		default:
			return d, false, nil, "", fmt.Sprintf("rule %d: combine must be AND or OR", i+1)
		}
		if info.Member != "" {
			sp.Member = strings.TrimSpace(get("member"))
		}
		specs = append(specs, sp)
	}
	return d, r.PostForm.Get("active") == "on", specs, r.PostForm.Get("form_base"), ""
}

// ui2InterceptValidate refuses what the PUT would refuse, before a review is minted.
func ui2InterceptValidate(specs []interceptRuleSpec) string {
	if _, err := specToRules(specs); err != nil {
		return err.Error()
	}
	for i, sp := range specs {
		if sp.Category == "regex" && sp.Match != "" {
			if _, err := regexp.Compile(sp.Match); err != nil {
				return fmt.Sprintf("rule %d: invalid regex: %v", i+1, err)
			}
		}
	}
	return ""
}

// handleUI2InterceptRulesAction serves POST /ui2/intercept/rules/{action}: edit (draft
// transforms, no write), confirm and quick (mint a review), run (spend it and save).
func (s *Server) handleUI2InterceptRulesAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	switch r.PathValue("action") {
	case "edit", "confirm":
		d, active, specs, base, errText := ui2InterceptParseDraft(r)
		if errText != "" {
			m := s.ui2InterceptRulesModel(d, active, specs, base)
			m.Error = errText
			ui2InterceptRulesWrite(w, r, m)
			return
		}
		if r.PathValue("action") == "confirm" {
			s.ui2InterceptRulesConfirm(w, r, d, active, specs, base)
			return
		}
		specs = ui2InterceptApplyEdit(d, specs, r.PostForm.Get("edit"))
		ui2InterceptRulesWrite(w, r, s.ui2InterceptRulesModel(d, active, specs, base))
	case "quick":
		s.ui2InterceptRulesQuick(w, r)
	case "run":
		s.ui2InterceptRulesRun(w, r)
	default:
		http.Error(w, "unknown intercept rules action", http.StatusBadRequest)
	}
}

// ui2InterceptApplyEdit applies one draft transform: add, up-N, down-N or delete-N. Anything
// else re-renders the draft unchanged.
func ui2InterceptApplyEdit(d ui2IDir, specs []interceptRuleSpec, edit string) []interceptRuleSpec {
	if edit == "add" {
		if len(specs) >= ui2InterceptMaxRules {
			return specs
		}
		return append(specs, interceptRuleSpec{Field: d.DefaultField, Category: "regex", Enabled: true, Action: "hold"})
	}
	verb, idxText, ok := strings.Cut(edit, "-")
	i, err := strconv.Atoi(idxText)
	if !ok || err != nil || i < 0 || i >= len(specs) {
		return specs
	}
	switch verb {
	case "up":
		if i > 0 {
			specs[i-1], specs[i] = specs[i], specs[i-1]
		}
	case "down":
		if i < len(specs)-1 {
			specs[i], specs[i+1] = specs[i+1], specs[i]
		}
	case "delete":
		specs = append(specs[:i], specs[i+1:]...)
	}
	return specs
}

func (s *Server) ui2InterceptRulesConfirm(w http.ResponseWriter, r *http.Request, d ui2IDir, active bool, specs []interceptRuleSpec, base string) {
	refuse := func(msg string) {
		m := s.ui2InterceptRulesModel(d, active, specs, base)
		m.Error = msg
		ui2InterceptRulesWrite(w, r, m)
	}
	before, canon, err := s.ui2InterceptListRead(d.Name)
	if err != nil {
		refuse("could not read the current list: " + err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(base), []byte(ui2InterceptDigest(canon))) != 1 {
		refuse("the " + d.Noun + " list changed since this editor opened - reload it (your draft is still shown here) and redo the edit, so the save cannot overwrite the newer rules")
		return
	}
	s.ui2InterceptRulesMint(w, r, d, before, canon, active, specs, refuse, nil)
}

// ui2InterceptRulesMint validates the new list, holds the exact PUT and renders the sheet.
func (s *Server) ui2InterceptRulesMint(w http.ResponseWriter, r *http.Request, d ui2IDir, before interceptListState, canon string, active bool, specs []interceptRuleSpec, refuse func(string), extra []string) {
	if msg := ui2InterceptValidate(specs); msg != "" {
		refuse("not reviewable: " + msg)
		return
	}
	if specs == nil {
		specs = []interceptRuleSpec{}
	}
	type putBody struct {
		Active bool                `json:"active"`
		Rules  []interceptRuleSpec `json:"rules"`
	}
	body, err := json.Marshal(putBody{Active: active, Rules: specs})
	if err != nil {
		refuse("could not encode the list")
		return
	}
	beforeRules := before.Rules
	if beforeRules == nil {
		beforeRules = []interceptRuleSpec{}
	}
	if cur, _ := json.Marshal(putBody{Active: before.Active, Rules: beforeRules}); string(cur) == string(body) {
		refuse("the draft is the same as the stored list - nothing to save")
		return
	}
	now := time.Now()
	count := 0
	s.ui2InterceptRuleReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2InterceptRuleReview); ok && now.After(e.expires) {
			s.ui2InterceptRuleReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2InterceptRuleReviewCap {
		refuse("too many rule reviews are open at once - confirm or let some expire, then try again")
		return
	}
	token, err1 := randomHex(16)
	id, err2 := randomHex(16)
	if err1 != nil || err2 != nil {
		refuse("could not create a review")
		return
	}
	s.ui2InterceptRuleReviews.Store(id, ui2InterceptRuleReview{token: token, dir: d.Name, body: body, snapshot: canon, expires: now.Add(ConfirmTTL)})

	// The sheet is derived from the held bytes, not from the form.
	var held putBody
	_ = json.Unmarshal(body, &held)
	pretty, _ := json.MarshalIndent(held, "", "  ")
	consequences := append([]string{
		fmt.Sprintf("Replaces the whole %s list: %d rule(s) stored now, %d after this save.", d.Noun, len(before.Rules), len(held.Rules)),
		"After saving, the list is " + ui2InterceptDescribe(d, held.Active, held.Rules) + ".",
	}, extra...)
	if before.Active && len(before.Rules) == 0 && len(held.Rules) > 0 {
		consequences = append(consequences, "The list currently holds every "+d.Noun+"; after this save it holds only what its enabled rules select.")
	}
	for _, row := range ui2InterceptRows(d.Name, held.Rules) {
		if !row.Applies {
			consequences = append(consequences, fmt.Sprintf("Rule %d matches %s, which a %s never carries, so it can never match.", row.Index+1, row.FieldLabel, d.Noun))
		}
	}
	consequences = append(consequences,
		"Nothing is sent and no held message is resolved; the rules decide what is held from now on.",
		"Saving re-reads the list and refuses if it changed since this review. That is a check, not a lock.")
	m := ui2IRulesModel{
		Dir: d, Dirs: ui2InterceptDirs, Active: held.Active, Rules: ui2InterceptRows(d.Name, held.Rules),
		Review: true, Call: "PUT /api/intercept/rules/" + d.Name + "\n" + string(pretty),
		Consequences: consequences, ReviewID: id, Token: token,
	}
	ui2InterceptRulesWrite(w, r, m)
}

// ui2InterceptRulesQuick builds Burp's quick rules from a held message: don't intercept
// requests to this host or for this extension, or responses from this host. The pass rule goes
// at the TOP of the list: below a broader hold rule it would never be reached.
func (s *Server) ui2InterceptRulesQuick(w http.ResponseWriter, r *http.Request) {
	fail := func(d ui2IDir, msg string) {
		ui2InterceptRulesWrite(w, r, ui2IRulesModel{Dir: d, Dirs: ui2InterceptDirs, Error: msg})
	}
	id, err := strconv.ParseUint(r.PostForm.Get("id"), 10, 64)
	if err != nil {
		fail(ui2InterceptDirs[0], "a held message id is required")
		return
	}
	var h *intercept.Held
	for _, x := range s.intercept.Held() {
		if x.ID == id {
			h = x
		}
	}
	if h == nil {
		fail(ui2InterceptDirs[0], fmt.Sprintf("held message #%d is no longer held - it was forwarded or dropped", id))
		return
	}
	var dirName, field, match, what string
	switch kind := r.PostForm.Get("kind"); {
	case kind == "pass-host" && h.Direction == intercept.DirectionRequest:
		dirName, field, match, what = "requests", "host", h.Host, "requests to "+h.Host
	case kind == "pass-ext" && h.Direction == intercept.DirectionRequest && ui2PathExtension(h.Path) != "":
		ext := ui2PathExtension(h.Path)
		dirName, field, match, what = "requests", "extension", ext, "requests for ."+ext+" files"
	case kind == "pass-host" && h.Direction == intercept.DirectionResponse:
		dirName, field, match, what = "responses", "host", h.Host, "responses from "+h.Host
	default:
		fail(ui2InterceptDirs[0], "that quick rule does not apply to this held message")
		return
	}
	d, _ := ui2InterceptDir(dirName)
	before, canon, err := s.ui2InterceptListRead(d.Name)
	if err != nil {
		fail(d, "could not read the current list: "+err.Error())
		return
	}
	rule := interceptRuleSpec{Field: field, Category: "literal", Match: match, Enabled: true, Action: "pass", Comment: fmt.Sprintf("from held #%d", id)}
	specs := append([]interceptRuleSpec{rule}, before.Rules...)
	s.ui2InterceptRulesMint(w, r, d, before, canon, before.Active, specs, func(msg string) { fail(d, msg) },
		[]string{"Adds a Don't intercept rule at the top of the list: " + what + " will no longer be held. Held message #" + strconv.FormatUint(id, 10) + " itself stays held."})
}

func (s *Server) ui2InterceptRulesRun(w http.ResponseWriter, r *http.Request) {
	fail := func(d ui2IDir, msg string) {
		ui2InterceptRulesWrite(w, r, ui2IRulesModel{Dir: d, Dirs: ui2InterceptDirs, Error: msg})
	}
	v, ok := s.ui2InterceptRuleReviews.LoadAndDelete(r.PostForm.Get("review_id"))
	entry, isReview := v.(ui2InterceptRuleReview)
	if !ok || !isReview {
		fail(ui2InterceptDirs[0], "that review is unknown or was already used - review the change again")
		return
	}
	d, _ := ui2InterceptDir(entry.dir)
	if time.Now().After(entry.expires) {
		fail(d, "that review expired with the confirmation window - review the change again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(r.PostForm.Get("token"))) != 1 {
		fail(d, "that review does not match this confirmation - review the change again")
		return
	}
	if _, canon, err := s.ui2InterceptListRead(d.Name); err != nil || canon != entry.snapshot {
		fail(d, "the "+d.Noun+" list changed since this review - nothing was saved; reload and review again")
		return
	}
	req := newReq(http.MethodPut, "/api/intercept/rules/"+d.Name)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		fail(d, "the rules API refused the list: "+truncateForDisplay(strings.TrimSpace(rec.Body.String()), 200))
		return
	}
	s.ui2InterceptRulesFresh(w, r, d, "Saved the "+d.Noun+" list.")
}
