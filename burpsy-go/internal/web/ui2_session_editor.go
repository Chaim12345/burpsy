package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- Session rule editor: a server-held draft ---------------------------------------------------
//
// The full editor (name, scope, validity, macro steps, extractions, every action kind) works on a
// DRAFT the server holds, never on a copy in the form. Opening a rule takes a RuleSnapshot (deep
// copy + digest in one lock hold); every editor step posts only what the operator typed and the
// server mutates the draft. Stored credentials - step bodies, header values, credential URLs,
// action values, scripts - are never rendered into a field: edits choose keep/replace/clear, so
// a secret never round-trips through the browser. Saving mints the same reviewed domain install
// the action editor uses (session_confirm.html, spent by /ui2/session/rules/run): an existing
// rule installs with UpdateRuleIfUnchanged against the digest taken when the editor opened, a
// new rule with AddRule.

const (
	ui2SessionDraftCap = 16
	ui2SessionDraftTTL = 30 * time.Minute
)

type ui2SessionDraft struct {
	mu      sync.Mutex
	ruleID  int64 // 0 for a rule not yet created
	base    string
	rev     int // bumped per applied step; forms carry it so a stale tab cannot act on shifted indexes
	rule    *session.SessionRule
	expires time.Time
}

// ui2SessionCloneRule deep-copies a domain rule the way RuleSnapshot does (domain JSON round trip
// plus extraction recompile), so a refused editor step leaves the draft untouched.
func ui2SessionCloneRule(r *session.SessionRule) (*session.SessionRule, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var out session.SessionRule
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for _, ex := range out.Extractions {
		if ex != nil {
			if err := ex.Recompile(); err != nil {
				return nil, err
			}
		}
	}
	return &out, nil
}

func (s *Server) ui2SessionDraftGet(id string) (*ui2SessionDraft, bool) {
	if id == "" {
		return nil, false
	}
	v, ok := s.ui2SessionDrafts.Load(id)
	d, isDraft := v.(*ui2SessionDraft)
	if !ok || !isDraft {
		return nil, false
	}
	d.mu.Lock()
	expired := time.Now().After(d.expires)
	d.mu.Unlock()
	if expired {
		s.ui2SessionDrafts.Delete(id)
		return nil, false
	}
	return d, true
}

func (s *Server) ui2SessionDraftOpen(r *http.Request) (string, *ui2SessionDraft, error) {
	d := &ui2SessionDraft{expires: time.Now().Add(ui2SessionDraftTTL)}
	if raw := strings.TrimSpace(r.PostFormValue("rule_id")); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			return "", nil, fmt.Errorf("that rule id is not valid")
		}
		rule, digest, ok := s.sessionCoordinator.RuleSnapshot(session.RuleID(id))
		if !ok {
			return "", nil, fmt.Errorf("that rule no longer exists")
		}
		d.ruleID, d.base, d.rule = id, digest, rule
	} else {
		rule := session.NewSessionRule("", nil, nil)
		// The list the engine would materialise anyway, made visible so it can be edited.
		rule.NormaliseActions()
		d.rule = rule
	}
	now := time.Now()
	count := 0
	s.ui2SessionDrafts.Range(func(k, v any) bool {
		if e, ok := v.(*ui2SessionDraft); ok {
			e.mu.Lock()
			expired := now.After(e.expires)
			e.mu.Unlock()
			if expired {
				s.ui2SessionDrafts.Delete(k)
				return true
			}
		}
		count++
		return true
	})
	if count >= ui2SessionDraftCap {
		return "", nil, fmt.Errorf("too many rule editors are open at once - save or let some expire, then try again")
	}
	id, err := randomHex(16)
	if err != nil {
		return "", nil, err
	}
	s.ui2SessionDrafts.Store(id, d)
	return id, d, nil
}

// handleUI2SessionEditorPage serves GET /ui2/session/editor: an open draft (?draft=) or the list
// of rules to open. It never creates or changes anything.
func (s *Server) handleUI2SessionEditorPage(w http.ResponseWriter, r *http.Request) {
	if id := r.URL.Query().Get("draft"); id != "" && s.sessionCoordinator != nil {
		if d, ok := s.ui2SessionDraftGet(id); ok {
			d.mu.Lock()
			model := s.ui2SessionEditorModel(id, d, "", "")
			d.mu.Unlock()
			s.ui2SessionEditorRender(w, r, model)
			return
		}
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorChooser("that editor draft expired or is unknown - open the rule again"))
		return
	}
	s.ui2SessionEditorRender(w, r, s.ui2SessionEditorChooser(""))
}

func (s *Server) ui2SessionEditorRender(w http.ResponseWriter, r *http.Request, model map[string]any) {
	ui2Fragment(w, r, "burpsy /ui2/ — Session rule editor", "session", ui2Exec("session_editor.html", model))
}

func (s *Server) ui2SessionEditorChooser(errText string) map[string]any {
	model := map[string]any{"error": errText, "wired": s.sessionCoordinator != nil}
	if s.sessionCoordinator == nil {
		return model
	}
	rows := []map[string]any{}
	for _, rule := range s.sessionCoordinator.AllRules() {
		rows = append(rows, map[string]any{"id": int64(rule.ID), "name": rule.Name, "enabled": rule.Enabled})
	}
	model["rules"] = rows
	return model
}

// handleUI2SessionEditor serves POST /ui2/session/editor/{action}.
func (s *Server) handleUI2SessionEditor(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if s.sessionCoordinator == nil {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorChooser("no session coordinator is wired on this server"))
		return
	}
	action := r.PathValue("action")
	if action == "open" {
		id, d, err := s.ui2SessionDraftOpen(r)
		if err != nil {
			s.ui2SessionEditorRender(w, r, s.ui2SessionEditorChooser(err.Error()))
			return
		}
		d.mu.Lock()
		model := s.ui2SessionEditorModel(id, d, "", "")
		d.mu.Unlock()
		s.ui2SessionEditorRender(w, r, model)
		return
	}
	draftID := r.PostFormValue("draft_id")
	d, ok := s.ui2SessionDraftGet(draftID)
	if !ok {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorChooser("that editor draft expired or is unknown - open the rule again"))
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expires = time.Now().Add(ui2SessionDraftTTL)
	if r.PostFormValue("rev") != strconv.Itoa(d.rev) {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorModel(draftID, d, "", "this editor changed in another tab or step - the page has been refreshed; repeat the change"))
		return
	}
	if action == "review" {
		s.ui2SessionEditorReview(w, r, draftID, d)
		return
	}
	if action == "discard" {
		s.ui2SessionDrafts.Delete(draftID)
		ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session.html", s.ui2SessionView("editor draft discarded; nothing was saved")))
		return
	}
	work, err := ui2SessionCloneRule(d.rule)
	if err != nil {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorModel(draftID, d, "", "the draft could not be copied: "+err.Error()))
		return
	}
	note, err := s.ui2SessionEditorApply(action, work, r)
	if err != nil {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorModel(draftID, d, "", err.Error()))
		return
	}
	d.rule = work
	d.rev++
	s.ui2SessionEditorRender(w, r, s.ui2SessionEditorModel(draftID, d, note+" (draft only - nothing is saved until you review and confirm)", ""))
}

// ui2SessionEditorValidate runs the wire layer's and the engine's own checks over a draft, so a
// review is only minted for a rule the install would accept.
func ui2SessionEditorValidate(rule *session.SessionRule) error {
	if rule.ScopeTools != nil {
		tools := append([]string(nil), rule.ScopeTools...)
		if _, err := scopeToolNames(&tools); err != nil {
			return err
		}
	}
	if err := session.ValidateActions(rule.Actions); err != nil {
		return err
	}
	if err := session.ValidateRuleStatedScope(rule, rule.ScopeMode == "custom" || len(rule.ScopeHosts) > 0); err != nil {
		return err
	}
	return session.ValidateValidityPatterns(rule.Validity)
}

func (s *Server) ui2SessionEditorReview(w http.ResponseWriter, r *http.Request, draftID string, d *ui2SessionDraft) {
	rule, err := ui2SessionCloneRule(d.rule)
	if err == nil {
		err = ui2SessionEditorValidate(rule)
	}
	if err != nil {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorModel(draftID, d, "", "the session engine refuses this rule: "+err.Error()))
		return
	}
	body, _ := json.Marshal(rule)
	entry := ui2SessionRuleReview{body: body, draftID: draftID}
	var summary, consequence, projection string
	state := "turned off"
	if rule.Enabled {
		state = "turned ON"
	}
	if d.ruleID == 0 {
		entry.method, entry.url, entry.create = http.MethodPost, "/api/session/rules", true
		entry.note = "rule created"
		summary = fmt.Sprintf("Create rule %q, %s, with %d macro step(s), %d extraction(s) and %d action(s).", rule.Name, state, len(rule.Steps), len(rule.Extractions), len(rule.Actions))
		consequence = "The rule is appended to the end of the rule order."
		if rule.Enabled {
			consequence += " It is created ON: matching requests are handled by it immediately, which can replay its macro (its login requests) against the target."
		}
		projection = ui2SessionRuleCreateProjection(body)
	} else {
		entry.method, entry.url = http.MethodPut, "/api/session/rules/"+strconv.FormatInt(d.ruleID, 10)
		entry.domain, entry.ruleID, entry.expectedBase = true, d.ruleID, d.base
		entry.note = "rule saved"
		summary = fmt.Sprintf("Save rule %q (id %d), %s, with %d macro step(s), %d extraction(s) and %d action(s).", rule.Name, d.ruleID, state, len(rule.Steps), len(rule.Extractions), len(rule.Actions))
		consequence = "The whole rule is replaced by the draft. It installs only while the stored rule is still exactly what the editor opened; if anything changed it since, nothing is applied."
		if rule.Enabled {
			consequence += " THIS RULE IS ON: the saved flow handles matching requests immediately."
		}
		projection = ui2SessionRuleDomainProjection(d.ruleID, d.base, body)
	}
	token, _, errText := s.ui2MintConfirm("/api/session/rules", entry.method, entry.url, body)
	if errText != "" {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorModel(draftID, d, "", errText))
		return
	}
	entry.token = token
	id, errText := s.ui2SessionHoldRuleReview(entry)
	if errText != "" {
		s.ui2SessionEditorRender(w, r, s.ui2SessionEditorModel(draftID, d, "", errText))
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session_confirm.html", map[string]any{
		"review_id":     id,
		"token":         token,
		"summary":       summary,
		"consequence":   consequence,
		"preview":       projection,
		"preview_label": "exact rule (the domain marshal the token binds; credential values, macro bodies and extension session state are withheld in this view but bound in the token)",
		"back":          "/ui2/session/editor?draft=" + draftID,
	}))
}

// ui2SessionRuleCreateProjection is the review view of a rule about to be created.
func ui2SessionRuleCreateProjection(body []byte) string {
	out := ui2SessionRuleProjection(http.MethodPost, "/api/session/rules", body)
	return strings.Replace(out, "POST /api/session/rules", "Create a new rule (installed in place; nothing is re-encoded through the session API)", 1)
}

// ---- editor steps ---------------------------------------------------------------------------------

func (s *Server) ui2SessionEditorApply(action string, rule *session.SessionRule, r *http.Request) (string, error) {
	switch action {
	case "fields":
		return ui2SessionEditFields(rule, r)
	case "step_add":
		step := session.MacroStep{
			Method: strings.ToUpper(strings.TrimSpace(r.PostFormValue("method"))),
			URL:    strings.TrimSpace(r.PostFormValue("url")),
			Body:   r.PostFormValue("body"),
		}
		if step.Method == "" {
			step.Method = http.MethodGet
		}
		if step.URL == "" {
			return "", fmt.Errorf("a macro step needs a URL")
		}
		headers, err := ui2SessionHeaderLines(r.PostFormValue("headers"))
		if err != nil {
			return "", err
		}
		step.Headers = headers
		rule.Steps = append(rule.Steps, step)
		return fmt.Sprintf("macro step %d added", len(rule.Steps)), nil
	case "step_edit", "step_remove", "step_up", "step_down":
		i, err := strconv.Atoi(r.PostFormValue("step"))
		if err != nil || i < 0 || i >= len(rule.Steps) {
			return "", fmt.Errorf("that macro step no longer exists")
		}
		return ui2SessionStepOp(rule, action, i, r)
	case "extract_add":
		return ui2SessionExtractAdd(rule, r)
	case "extract_remove":
		i, err := strconv.Atoi(r.PostFormValue("extract"))
		if err != nil || i < 0 || i >= len(rule.Extractions) {
			return "", fmt.Errorf("that extraction no longer exists")
		}
		name := ""
		if rule.Extractions[i] != nil {
			name = rule.Extractions[i].Name
		}
		rule.Extractions = append(rule.Extractions[:i], rule.Extractions[i+1:]...)
		return fmt.Sprintf("extraction %q removed", name), nil
	case "record":
		return s.ui2SessionRecord(rule, r)
	case "action_add":
		list, err := ui2SessionActionList(rule, r.PostFormValue("parent"))
		if err != nil {
			return "", err
		}
		kind, err := session.ParseActionKind(r.PostFormValue("kind"))
		if err != nil {
			return "", fmt.Errorf("choose an action kind")
		}
		a := &session.Action{Kind: kind, Enabled: true}
		if kind == session.ActionRunMacro {
			a.UpdateWithParams = true // as Burp's editor starts a new macro action
		}
		*list = append(*list, a)
		return session.ActionKindLabel(kind) + " added - fill in its fields below", nil
	case "action_edit", "action_remove", "action_up", "action_down":
		list, i, err := ui2SessionActionAt(rule, r.PostFormValue("path"))
		if err != nil {
			return "", err
		}
		a := (*list)[i]
		switch action {
		case "action_remove":
			*list = append((*list)[:i], (*list)[i+1:]...)
			return "action removed, with any conditional branches it held", nil
		case "action_up":
			if i == 0 {
				return "", fmt.Errorf("the first action cannot move up")
			}
			(*list)[i-1], (*list)[i] = (*list)[i], (*list)[i-1]
			return "action moved up", nil
		case "action_down":
			if i+1 >= len(*list) {
				return "", fmt.Errorf("the last action cannot move down")
			}
			(*list)[i+1], (*list)[i] = (*list)[i], (*list)[i+1]
			return "action moved down", nil
		}
		if a == nil {
			return "", fmt.Errorf("that action is missing - remove it instead")
		}
		if err := ui2SessionEditAction(a, r); err != nil {
			return "", err
		}
		return session.ActionKindLabel(a.Kind) + " updated", nil
	}
	return "", fmt.Errorf("unknown editor step")
}

func ui2SessionNameList(text string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ui2SessionHeaderLines reads "Name: value" lines typed for a NEW step.
func ui2SessionHeaderLines(text string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("header line %q is not Name: value", truncateForDisplay(line, 40))
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return out, nil
}

func ui2SessionEditFields(rule *session.SessionRule, r *http.Request) (string, error) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		return "", fmt.Errorf("a rule needs a name")
	}
	rule.Name = name
	rule.Enabled = r.PostFormValue("enabled") == "1"
	if raw := strings.TrimSpace(r.PostFormValue("max_attempts")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return "", fmt.Errorf("max attempts must be a positive whole number")
		}
		rule.MaxAttempts = n
	}
	hosts := ui2SessionNameList(r.PostFormValue("hosts"))
	rule.ScopePathPrefix, rule.ScopePort, rule.ScopeProtocol = "", nil, ""
	switch r.PostFormValue("scope_mode") {
	case "all":
		rule.ScopeMode, rule.ScopeHosts = "", hosts
	case "suite":
		rule.ScopeMode, rule.ScopeHosts = "suite", nil
	case "custom":
		rule.ScopeMode, rule.ScopeHosts = "custom", hosts
		rule.ScopePathPrefix = strings.TrimSpace(r.PostFormValue("scope_path"))
		if raw := strings.TrimSpace(r.PostFormValue("scope_port")); raw != "" {
			p, err := strconv.ParseUint(raw, 10, 16)
			if err != nil || p == 0 {
				return "", fmt.Errorf("the scope port must be 1-65535")
			}
			port := uint16(p)
			rule.ScopePort = &port
		}
		switch proto := r.PostFormValue("scope_protocol"); proto {
		case "", "http", "https":
			rule.ScopeProtocol = proto
		default:
			return "", fmt.Errorf("the scope protocol must be http or https")
		}
	default:
		return "", fmt.Errorf("choose a URL scope: all URLs, the suite scope, or a custom scope")
	}
	rule.ScopeParams = ui2SessionNameList(r.PostFormValue("params"))
	switch r.PostFormValue("tools_mode") {
	case "all":
		rule.ScopeTools = nil
	case "selected":
		tools := r.PostForm["tools"]
		if len(tools) == 0 {
			return "", fmt.Errorf("a rule with no tools selected applies to nothing - pick at least one tool, or choose every tool")
		}
		if _, err := scopeToolNames(&tools); err != nil {
			return "", err
		}
		rule.ScopeTools = append([]string(nil), tools...)
	default:
		return "", fmt.Errorf("tools must be every tool or selected")
	}
	v, err := ui2SessionValidityFrom(r, "v_", rule.Validity)
	if err != nil {
		return "", err
	}
	rule.Validity = v
	return "rule fields updated", nil
}

// ui2SessionValidityFrom reads the top-level validity clauses under prefix; nested all/any/not
// groups the form does not show are kept as stored.
func ui2SessionValidityFrom(r *http.Request, prefix string, old *session.ValidityRule) (*session.ValidityRule, error) {
	v := &session.ValidityRule{}
	if old != nil {
		v.All, v.Any, v.Not = old.All, old.Any, old.Not
	}
	if raw := strings.TrimSpace(r.PostFormValue(prefix + "status")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 100 || n > 599 {
			return nil, fmt.Errorf("the validity status must be an HTTP status code (100-599)")
		}
		v.StatusIs = &n
	}
	v.BodyContains = r.PostFormValue(prefix + "body_contains")
	v.BodyNotContains = r.PostFormValue(prefix + "body_not_contains")
	v.HeaderPresent = strings.TrimSpace(r.PostFormValue(prefix + "header_present"))
	v.HeaderAbsent = strings.TrimSpace(r.PostFormValue(prefix + "header_absent"))
	v.URLContains = r.PostFormValue(prefix + "url_contains")
	v.Regex = r.PostFormValue(prefix+"regex") == "1"
	v.CaseSensitive = r.PostFormValue(prefix+"case_sensitive") == "1"
	if v.StatusIs == nil && v.BodyContains == "" && v.BodyNotContains == "" && v.HeaderPresent == "" &&
		v.HeaderAbsent == "" && v.URLContains == "" && len(v.All) == 0 && len(v.Any) == 0 && v.Not == nil {
		return nil, nil
	}
	if err := session.ValidateValidityPatterns(v); err != nil {
		return nil, err
	}
	return v, nil
}

func ui2SessionStepOp(rule *session.SessionRule, action string, i int, r *http.Request) (string, error) {
	// Extractions name their step by position, so every structural step change carries them along.
	renumber := func(f func(int) int) {
		kept := rule.Extractions[:0]
		for _, ex := range rule.Extractions {
			if ex == nil {
				continue
			}
			if n := f(ex.Step); n >= 0 {
				ex.Step = n
				kept = append(kept, ex)
			}
		}
		rule.Extractions = kept
	}
	switch action {
	case "step_remove":
		dropped := 0
		for _, ex := range rule.Extractions {
			if ex != nil && ex.Step == i {
				dropped++
			}
		}
		rule.Steps = append(rule.Steps[:i], rule.Steps[i+1:]...)
		renumber(func(n int) int {
			switch {
			case n == i:
				return -1
			case n > i:
				return n - 1
			}
			return n
		})
		return fmt.Sprintf("macro step %d removed with its %d extraction(s)", i+1, dropped), nil
	case "step_up", "step_down":
		j := i - 1
		if action == "step_down" {
			j = i + 1
		}
		if j < 0 || j >= len(rule.Steps) {
			return "", fmt.Errorf("that step cannot move further")
		}
		rule.Steps[i], rule.Steps[j] = rule.Steps[j], rule.Steps[i]
		renumber(func(n int) int {
			switch n {
			case i:
				return j
			case j:
				return i
			}
			return n
		})
		return fmt.Sprintf("macro step %d moved to position %d (its extractions moved with it)", i+1, j+1), nil
	}
	step := &rule.Steps[i]
	if m := strings.ToUpper(strings.TrimSpace(r.PostFormValue("method"))); m != "" {
		step.Method = m
	}
	var err error
	if step.URL, err = ui2SessionSecretEdit(r, "url", step.URL, false); err != nil {
		return "", err
	}
	step.URL = strings.TrimSpace(step.URL)
	if step.Body, err = ui2SessionSecretEdit(r, "body", step.Body, true); err != nil {
		return "", err
	}
	names := ui2SessionSortedHeaders(step.Headers)
	headers := map[string]string{}
	for k, name := range names {
		key := "h" + strconv.Itoa(k)
		switch r.PostFormValue(key + "_mode") {
		case "remove":
			if r.PostFormValue(key) != "" {
				return "", fmt.Errorf("header %s: remove must not carry a value", name)
			}
			continue
		default:
			v, err := ui2SessionSecretEdit(r, key, step.Headers[name], true)
			if err != nil {
				return "", fmt.Errorf("header %s: %w", name, err)
			}
			headers[name] = v
		}
	}
	if n := strings.TrimSpace(r.PostFormValue("new_header_name")); n != "" {
		headers[n] = r.PostFormValue("new_header_value")
	} else if r.PostFormValue("new_header_value") != "" {
		return "", fmt.Errorf("a new header needs a name")
	}
	step.Headers = headers
	return fmt.Sprintf("macro step %d updated", i+1), nil
}

func ui2SessionSortedHeaders(h map[string]string) []string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func ui2SessionExtractAdd(rule *session.SessionRule, r *http.Request) (string, error) {
	step, err := strconv.Atoi(r.PostFormValue("step"))
	if err != nil || step < 0 || step >= len(rule.Steps) {
		return "", fmt.Errorf("that macro step no longer exists")
	}
	name := strings.TrimSpace(r.PostFormValue("ex_name"))
	if name == "" {
		return "", fmt.Errorf("an extraction needs a name (it becomes the {{name}} placeholder)")
	}
	from, header := "body", ""
	if r.PostFormValue("ex_from") == "header" {
		from, header = "header", strings.TrimSpace(r.PostFormValue("ex_header"))
		if header == "" {
			return "", fmt.Errorf("extraction %q reads from a header with no name", name)
		}
	}
	var ex *session.Extraction
	switch r.PostFormValue("ex_how") {
	case "regex":
		group := 1
		if raw := strings.TrimSpace(r.PostFormValue("ex_group")); raw != "" {
			if group, err = strconv.Atoi(raw); err != nil || group < 0 {
				return "", fmt.Errorf("the capture group must be a whole number")
			}
		}
		ex, err = session.NewExtraction(name, from, r.PostFormValue("ex_pattern"), group)
	case "json_path":
		path := strings.TrimSpace(r.PostFormValue("ex_json_path"))
		if path == "" {
			return "", fmt.Errorf("extraction %q extracts by an empty json path", name)
		}
		ex, err = session.NewJSONPathExtraction(name, from, path)
	case "whole":
		ex, err = session.NewExtraction(name, from, wholeValuePattern, 0)
	default:
		return "", fmt.Errorf("choose how the extraction reads its value: regex, JSON path or the whole value")
	}
	if err != nil {
		return "", fmt.Errorf("extraction %q: %w", name, err)
	}
	ex.Header, ex.Step = header, step
	ex.Prefix, ex.Suffix = r.PostFormValue("ex_prefix"), r.PostFormValue("ex_suffix")
	switch r.PostFormValue("ex_url_encoded") {
	case "yes":
		t := true
		ex.URLEncoded = &t
	case "no":
		f := false
		ex.URLEncoded = &f
	}
	for _, other := range rule.Extractions {
		if other != nil && other.Name == name {
			return "", fmt.Errorf("an extraction named %q already exists - {{%s}} would be ambiguous", name, name)
		}
	}
	rule.Extractions = append(rule.Extractions, ex)
	return fmt.Sprintf("extraction %q added to step %d", name, step+1), nil
}

// ui2SessionRecord is the Macro Recorder: the chosen history rows become steps through the API's
// own conversion (POST /api/session/macro-steps, riskRead - it sends nothing).
func (s *Server) ui2SessionRecord(rule *session.SessionRule, r *http.Request) (string, error) {
	var ids []uint64
	for _, raw := range append(append([]string{}, r.PostForm["exchange"]...), ui2SessionNameList(r.PostFormValue("exchange_ids"))...) {
		id, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(raw), "#"), 10, 64)
		if err != nil {
			return "", fmt.Errorf("%q is not a history row id", truncateForDisplay(raw, 20))
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("tick at least one history row to record")
	}
	variant := r.PostFormValue("variant")
	if variant == "" {
		variant = "edited"
	}
	result, errText := s.ui2APIResult(http.MethodPost, "/api/session/macro-steps", map[string]any{"exchanges": ids, "variant": variant})
	if errText != "" {
		return "", fmt.Errorf("%s", ui2APIErrorText(errText))
	}
	raw, _ := json.Marshal(result)
	var resp struct {
		Steps   []sessionStepDto `json:"steps"`
		Skipped []struct {
			Exchange uint64 `json:"exchange"`
			Reason   string `json:"reason"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("unreadable recorder answer")
	}
	for _, st := range resp.Steps {
		rule.Steps = append(rule.Steps, stepDtoToMacroStep(st))
	}
	note := fmt.Sprintf("recorded %d step(s) from history", len(resp.Steps))
	for _, sk := range resp.Skipped {
		note += fmt.Sprintf("; skipped #%d: %s", sk.Exchange, sk.Reason)
	}
	return note, nil
}

// ui2SessionActionList resolves "" (the rule's list) or "<i>/then|else[/<j>/then|else...]".
func ui2SessionActionList(rule *session.SessionRule, parent string) (*[]*session.Action, error) {
	list := &rule.Actions
	if parent == "" {
		return list, nil
	}
	parts := strings.Split(parent, "/")
	if len(parts)%2 != 0 {
		return nil, fmt.Errorf("that action branch no longer exists")
	}
	for k := 0; k < len(parts); k += 2 {
		i, err := strconv.Atoi(parts[k])
		if err != nil || i < 0 || i >= len(*list) || (*list)[i] == nil || (*list)[i].Kind != session.ActionCheckValidity {
			return nil, fmt.Errorf("that action branch no longer exists")
		}
		switch parts[k+1] {
		case "then":
			list = &(*list)[i].Then
		case "else":
			list = &(*list)[i].Else
		default:
			return nil, fmt.Errorf("that action branch no longer exists")
		}
	}
	return list, nil
}

func ui2SessionActionAt(rule *session.SessionRule, path string) (*[]*session.Action, int, error) {
	parent, last := "", path
	if k := strings.LastIndex(path, "/"); k >= 0 {
		parent, last = path[:k], path[k+1:]
	}
	list, err := ui2SessionActionList(rule, parent)
	if err != nil {
		return nil, 0, err
	}
	i, err := strconv.Atoi(last)
	if err != nil || i < 0 || i >= len(*list) {
		return nil, 0, fmt.Errorf("that action no longer exists")
	}
	return list, i, nil
}

// ui2SessionEditAction applies one action's edit form. Every kind is editable; secret-bearing
// fields use keep/replace/clear so a stored value is never sent to the page.
func ui2SessionEditAction(a *session.Action, r *http.Request) error {
	a.Enabled = r.PostFormValue("enabled") == "1"
	a.Stop = r.PostFormValue("stop") == "1"
	var err error
	switch a.Kind {
	case session.ActionSetCookie, session.ActionSetHeader, session.ActionSetParam:
		a.Name = strings.TrimSpace(r.PostFormValue("name"))
		if a.Value, err = ui2SessionSecretEdit(r, "value", a.Value, true); err != nil {
			return err
		}
		if a.Kind == session.ActionSetParam {
			a.In = r.PostFormValue("in")
		}
	case session.ActionReplace:
		if a.Match, err = ui2SessionSecretEdit(r, "match", a.Match, false); err != nil {
			return err
		}
		if a.Replacement, err = ui2SessionSecretEdit(r, "replacement", a.Replacement, true); err != nil {
			return err
		}
		a.Regex = r.PostFormValue("regex") == "1"
	case session.ActionRunScript:
		if a.Script, err = ui2SessionSecretEdit(r, "script", a.Script, false); err != nil {
			return err
		}
	case session.ActionInvokeExtension:
		a.Extension = strings.TrimSpace(r.PostFormValue("extension"))
	case session.ActionCheckValidity:
		a.ValidateEvery = 0
		if raw := strings.TrimSpace(r.PostFormValue("validate_every")); raw != "" {
			if a.ValidateEvery, err = strconv.Atoi(raw); err != nil || a.ValidateEvery < 0 {
				return fmt.Errorf("validate every must be 0 (every request) or a positive number of requests")
			}
		}
		switch r.PostFormValue("validity_mode") {
		case "rule":
			a.Validity = nil
		case "own":
			v, err := ui2SessionValidityFrom(r, "av_", a.Validity)
			if err != nil {
				return err
			}
			if v == nil {
				return fmt.Errorf("own validity criteria need at least one condition - or use the rule's")
			}
			a.Validity = v
		default:
			return fmt.Errorf("choose whether the check uses the rule's validity or its own")
		}
	case session.ActionRunMacro:
		a.UpdateWithParams = r.PostFormValue("update_with_params") == "1"
		a.MatchParams, a.Params, a.TolerateURLMismatch = "", nil, false
		if a.UpdateWithParams {
			if r.PostFormValue("match_params") == "specified_params" {
				a.MatchParams = "specified_params"
			}
			a.Params = ui2SessionNameList(r.PostFormValue("params"))
			a.TolerateURLMismatch = r.PostFormValue("tolerate_url_mismatch") == "1"
		}
		a.MatchCookies, a.Cookies = "", nil
		if r.PostFormValue("update_with_cookies") == "1" {
			a.UpdateWithCookies = nil // absent is the whole jar, the stored default
			if r.PostFormValue("match_cookies") == "specified_cookies" {
				a.MatchCookies = "specified_cookies"
			}
			a.Cookies = ui2SessionNameList(r.PostFormValue("cookies"))
			if a.MatchCookies != "" || len(a.Cookies) > 0 {
				t := true
				a.UpdateWithCookies = &t
			}
		} else {
			f := false
			a.UpdateWithCookies = &f
		}
		if r.PostFormValue("macro_source") == "rule" {
			a.Macro = nil
		}
	case session.ActionRunPostRequestMacro:
		if r.PostFormValue("macro_source") == "rule" {
			a.Macro = nil
		}
	}
	return nil
}

// ---- view model -------------------------------------------------------------------------------

func ui2SessionValidityView(v *session.ValidityRule, prefix string) map[string]any {
	// Every key is present so an unset rule renders empty fields, never a placeholder.
	m := map[string]any{"set": v != nil, "prefix": prefix, "status": "", "body_contains": "", "body_not_contains": "",
		"header_present": "", "header_absent": "", "url_contains": "", "regex": false, "case_sensitive": false, "nested": false}
	if v == nil {
		return m
	}
	if v.StatusIs != nil {
		m["status"] = strconv.Itoa(*v.StatusIs)
	}
	m["body_contains"], m["body_not_contains"] = v.BodyContains, v.BodyNotContains
	m["header_present"], m["header_absent"], m["url_contains"] = v.HeaderPresent, v.HeaderAbsent, v.URLContains
	m["regex"], m["case_sensitive"] = v.Regex, v.CaseSensitive
	m["nested"] = len(v.All) > 0 || len(v.Any) > 0 || v.Not != nil
	return m
}

func ui2SessionStepView(steps []session.MacroStep) []map[string]any {
	out := make([]map[string]any, 0, len(steps))
	for i, st := range steps {
		headers := []map[string]any{}
		for k, name := range ui2SessionSortedHeaders(st.Headers) {
			headers = append(headers, map[string]any{"key": "h" + strconv.Itoa(k), "name": name, "len": len(st.Headers[name])})
		}
		out = append(out, map[string]any{
			"index": i, "position": i + 1, "method": st.Method,
			"url": ui2SessionRuleSanitizeURL(st.URL), "url_len": len(st.URL),
			"body_len": len(st.Body), "headers": headers,
			"up": i > 0, "down": i+1 < len(steps),
		})
	}
	return out
}

func ui2SessionActionRowsTree(list []*session.Action, parent string, depth int, out *[]map[string]any) {
	for i, a := range list {
		path := strconv.Itoa(i)
		if parent != "" {
			path = parent + "/" + path
		}
		row := map[string]any{"type": "action", "path": path, "depth": depth, "indent": depth * 24,
			"up": i > 0, "down": i+1 < len(list), "position": i + 1}
		if a == nil {
			row["label"] = "Missing action"
			*out = append(*out, row)
			continue
		}
		row["label"], row["kind"] = session.ActionKindLabel(a.Kind), session.ActionKindName(a.Kind)
		row["enabled"], row["stop"], row["name"], row["in"], row["regex"] = a.Enabled, a.Stop, a.Name, a.In, a.Regex
		row["has_value"], row["has_match"], row["has_replacement"], row["has_script"] = a.Value != "", a.Match != "", a.Replacement != "", a.Script != ""
		row["extension"], row["has_extension_session"] = a.Extension, a.ExtensionSession != ""
		row["validate_every"] = a.ValidateEvery
		row["validity"] = ui2SessionValidityView(a.Validity, "av_")
		row["own_macro"] = len(a.Macro)
		row["update_with_params"], row["match_params"], row["params"] = a.UpdateWithParams, a.MatchParams, strings.Join(a.Params, ", ")
		row["tolerate_url_mismatch"] = a.TolerateURLMismatch
		row["update_with_cookies"] = a.UpdateWithCookies == nil || *a.UpdateWithCookies
		row["match_cookies"], row["cookies"] = a.MatchCookies, strings.Join(a.Cookies, ", ")
		*out = append(*out, row)
		if a.Kind == session.ActionCheckValidity {
			for _, branch := range []string{"then", "else"} {
				label := "If the session is valid"
				children := a.Then
				if branch == "else" {
					label, children = "If it is not valid (or cannot be told)", a.Else
				}
				*out = append(*out, map[string]any{"type": "branch", "label": label, "parent": path + "/" + branch,
					"indent": (depth + 1) * 24, "empty": len(children) == 0})
				ui2SessionActionRowsTree(children, path+"/"+branch, depth+1, out)
			}
		}
	}
}

func (s *Server) ui2SessionEditorModel(draftID string, d *ui2SessionDraft, note, errText string) map[string]any {
	rule := d.rule
	model := map[string]any{
		"wired": true, "draft_id": draftID, "rev": d.rev, "rule_id": d.ruleID, "is_new": d.ruleID == 0,
		"note": note, "error": errText,
		"name": rule.Name, "enabled": rule.Enabled, "max_attempts": rule.MaxAttempts,
		"hosts": strings.Join(rule.ScopeHosts, "\n"), "scope_path": rule.ScopePathPrefix,
		"scope_protocol": rule.ScopeProtocol, "params": strings.Join(rule.ScopeParams, ", "),
		"validity": ui2SessionValidityView(rule.Validity, "v_"), "scope_port": "",
	}
	mode := rule.ScopeMode
	if mode == "" {
		mode = "all"
	}
	model["scope_mode"] = mode
	if rule.ScopePort != nil {
		model["scope_port"] = strconv.Itoa(int(*rule.ScopePort))
	}
	picked := map[string]bool{}
	for _, t := range rule.ScopeTools {
		picked[t] = true
	}
	model["tools_mode"] = "all"
	if rule.ScopeTools != nil {
		model["tools_mode"] = "selected"
	}
	checks := []map[string]any{}
	for _, t := range toolNames() {
		checks = append(checks, map[string]any{"name": t, "checked": picked[t]})
	}
	model["tools_checks"] = checks
	steps := ui2SessionStepView(rule.Steps)
	model["steps"] = steps
	extracts := make([]map[string]any, 0, len(rule.Extractions))
	for i, ex := range rule.Extractions {
		if ex == nil {
			continue
		}
		how := "regex " + ex.Pattern + " group " + strconv.Itoa(ex.Group)
		switch {
		case ex.JSONPath != "":
			how = "JSON path " + ex.JSONPath
		case ex.Pattern == wholeValuePattern && ex.Group == 0:
			how = "whole value"
		}
		from := "body"
		if ex.From == "header" {
			from = "header " + ex.Header
		}
		enc := "default"
		if ex.URLEncoded != nil {
			enc = strconv.FormatBool(*ex.URLEncoded)
		}
		extracts = append(extracts, map[string]any{"index": i, "name": ex.Name, "step": ex.Step + 1, "from": from,
			"how": how, "prefix": ex.Prefix, "suffix": ex.Suffix, "url_encoded": enc})
	}
	model["extractions"] = extracts
	rows := []map[string]any{}
	ui2SessionActionRowsTree(rule.Actions, "", 0, &rows)
	model["actions"] = rows
	model["kinds"] = sessionActionKinds()
	// History rows for the Macro Recorder: the newest proxy rows, as the History page lists them.
	if s.store != nil {
		model["history"] = s.ui2HistoryPage(newReq(http.MethodGet, "/ui2/history"), ui2HistoryParams{Limit: 25}).Rows
	}
	if clone, err := ui2SessionCloneRule(rule); err == nil {
		if err := ui2SessionEditorValidate(clone); err != nil {
			model["problem"] = err.Error()
		}
	}
	return model
}
