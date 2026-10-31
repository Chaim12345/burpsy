package web

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- Session handling rules: page controls via the confirm gate ------------------------------
//
// The console edits session rules through POST/PUT/DELETE /api/session/rules, all riskCredential
// and all behind the one-time confirmation gate. The ui2 page mirrors the Triage pattern rather
// than the Scope one: the confirm step mints the token, holds the exact minted call (method,
// path, bytes) in the bounded review map below, and renders a review sheet from those same
// bytes; the run form carries only the review id and token, and the run step dispatches the held
// call verbatim. Nothing typed after the review can change what is written, and a double-confirm
// cannot dispatch twice (LoadAndDelete).
//
// Add still dispatches through the wire API (POST with a body this page builds whole), and
// remove through DELETE; neither re-reads stored state, so the wire round-trip loses nothing.
//
// Toggle and edit do NOT go through the wire API. The served DTO carries no Action.Validity or
// Action.ExtensionSession (verified against sessionActionDto/actionToDto/actionsToModel), so a
// PUT of the served map silently drops both - the sheet's "everything else is kept unchanged"
// was false for rules carrying them. Those ops now merge at the DOMAIN level: a deep copy of
// the coordinator's stored rule (session.Coordinator.RuleSnapshot, one lock hold with the
// digest, extraction recompile like the persistence loader) has exactly the form-owned fields
// mutated (enabled; name, scope_tools), is validated with the engine's own session.ValidateRule
// at mint, and is installed by session.UpdateRuleIfUnchanged - the same compare-and-update the
// API's PUT uses, in one lock hold - followed by persistSessionRules in the API's ordering.
// The review entry holds the merged rule's domain marshal: those exact bytes are what
// session.RuleDigest binds, what the token covers, and what the sheet shows redacted, so
// what the operator sees is what installs. Per-action validity criteria render as stored
// (the sheet says so); extension_session and the credential carriers are withheld.
//
// expected_base is the session.RuleDigest of the rule at mint time (RuleSnapshot's half of the
// same lock hold); the check-and-swap runs inside one coordinator lock hold - a digest compared
// by the caller before a separate unconditional write would be a window, not a guard.
//
// The review map is bounded by ui2SessionRuleReviewCap with sweep-on-issue, the same shape the
// reviewer approved for Triage: enough for a few open tabs, small enough that a full map is a
// pileup to surface rather than paper over.
const ui2SessionRuleReviewCap = 8

// ui2SessionRuleReview is one minted session-rule change held for review. It dies with ConfirmTTL
// so a stale review refuses alongside its token, and the run step spends it atomically.
type ui2SessionRuleReview struct {
	token   string
	method  string
	url     string
	body    []byte // wire ops: the exact minted call body, dispatched verbatim on run (nil for DELETE); domain ops: the merged rule's domain marshal, installed via compare-and-update
	note    string // the success note the run step renders, written at mint time
	expires time.Time
	// domain marks a coordinator-level install (toggle/edit): the run step decodes body as a
	// session.SessionRule and installs it with UpdateRuleIfUnchanged under expectedBase, rather
	// than dispatching method+url+body through the API - the wire DTO drops Action.Validity and
	// Action.ExtensionSession, so re-encoding would lose them. ruleID names the rule the swap
	// targets; expectedBase is the RuleDigest the swap is preconditioned on.
	domain       bool
	ruleID       int64
	expectedBase string
}

// ui2SessionRulesTools renders the tools axis as the review sheet must say it: an absent or
// empty selection is Burp's "every tool", never an empty restriction (the engine refuses an
// explicitly empty scope_tools list rather than silently widening it).
func ui2SessionRulesToolsNote(tools []string) string {
	if len(tools) == 0 {
		return "every tool"
	}
	return strings.Join(tools, ", ")
}

// ui2SessionRuleDTO fetches one rule's dto map as GET /api/session/rules serves it, decoded with
// UseNumber so a merge re-marshal keeps number literals exact. False when the coordinator is not
// wired or the id is gone.
func (s *Server) ui2SessionRuleDTO(id int64) (map[string]any, bool) {
	if s.sessionCoordinator == nil {
		return nil, false
	}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/session/rules"))
	var resp struct {
		Rules []map[string]any `json:"rules"`
	}
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		return nil, false
	}
	for _, rule := range resp.Rules {
		if n, ok := rule["id"].(json.Number); ok {
			if v, err := n.Int64(); err == nil && v == id {
				return rule, true
			}
		}
	}
	return nil, false
}

// ui2SessionRuleDigest is the compare-and-update precondition for a rule the coordinator holds.
func (s *Server) ui2SessionRuleDigest(id int64) (string, bool) {
	if s.sessionCoordinator == nil {
		return "", false
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		return "", false
	}
	return session.RuleDigest(rule), true
}

// ui2SessionActionLabels reads the operator-facing action labels out of a served rule dto, for
// the toggle-on consequence line: "when on, this rule runs: <labels>". The API serves the labels
// (Burp's own words) so this page never keeps its own copy of the vocabulary.
func ui2SessionActionLabels(rule map[string]any) string {
	actions, ok := rule["actions"].([]any)
	if !ok || len(actions) == 0 {
		return "the engine's default flow (check login validity, then run its macro)"
	}
	labels := make([]string, 0, len(actions))
	for _, a := range actions {
		if m, ok := a.(map[string]any); ok {
			if l, ok := m["label"].(string); ok && l != "" {
				labels = append(labels, l)
				continue
			}
			if k, ok := m["kind"].(string); ok {
				labels = append(labels, k)
			}
		}
	}
	return strings.Join(labels, "; ")
}

// ui2SessionRuleToolsOf reads a served rule dto's tools axis for the review sheet.
func ui2SessionRuleToolsOf(rule map[string]any) string {
	tools, _ := rule["scope_tools"].([]any)
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		if name, ok := t.(string); ok {
			names = append(names, name)
		}
	}
	return ui2SessionRulesToolsNote(names)
}

// ui2SessionActionEffects describes what each served action DOES, for the toggle-on consequence:
// the operator enabling a rule is changing how matching requests get authenticated or rewritten,
// and the sheet must say that in words, not only name the kinds. Phrases come from the served
// kind and name fields; an unknown kind falls back to its served label rather than a guess.
func ui2SessionActionEffects(rule map[string]any) string {
	actions, ok := rule["actions"].([]any)
	if !ok || len(actions) == 0 {
		return "the engine's default flow (check login validity, then replay its macro against the target)"
	}
	effects := make([]string, 0, len(actions))
	for _, a := range actions {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		kindName, _ := m["kind"].(string)
		aname, _ := m["name"].(string)
		label, _ := m["label"].(string)
		kind, err := session.ParseActionKind(kindName)
		if err != nil {
			effects = append(effects, label)
			continue
		}
		switch kind {
		case session.ActionAddCookiesFromJar:
			effects = append(effects, "attach the session cookie jar's cookies for the request's own host - if the jar holds none for that host, nothing is attached")
		case session.ActionRunMacro, session.ActionRunPostRequestMacro:
			effects = append(effects, "replay the rule's recorded macro against the target (its login requests run again)")
		case session.ActionCheckValidity:
			effects = append(effects, "check whether the current session is still valid and run its conditional sub-actions")
		case session.ActionSetCookie:
			effects = append(effects, fmt.Sprintf("set the %q cookie on matching requests", aname))
		case session.ActionSetParam:
			effects = append(effects, fmt.Sprintf("set the %q parameter on matching requests", aname))
		case session.ActionSetHeader:
			effects = append(effects, fmt.Sprintf("set the %q header on matching requests", aname))
		default:
			effects = append(effects, label)
		}
	}
	return strings.Join(effects, "; ")
}

// ui2SessionRuleProjection renders the review sheet's exact call from the FULL held body: the
// gate's own preview truncates (200 chars in the ui2 helper) and a label that says "exact" must
// not hide the expected_base precondition it asks the operator to approve. The rendering is the
// same CONTENT the token binds, re-encoded for display - the binding itself is computed from the
// minted bytes, which the run step dispatches verbatim.
//
// A full body is not a safe body to show: rules coming from the console can CARRY credentials -
// a set-cookie/set-header/set-param action's value, a macro step's login form body, an
// Authorization or Cookie header, an embedded script with a token inside. The projection
// withholds those values in the view (the token still binds them: the held bytes are
// dispatched untouched). Redaction here is domain-aware, not only the gate's key-name pass:
// redactSecrets matches on member names, and a set-cookie action's secret sits in a generic
// "value" member whose sibling "name" is the cookie's name, not a secret-looking key.
func ui2SessionRuleProjection(method, url string, body []byte) string {
	out := method + " " + url
	if len(body) == 0 {
		return out
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return out + "\n(unreadable body - " + strconv.Itoa(len(body)) + " bytes held)"
	}
	ui2SessionRuleRedact(v)
	if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
		return out + "\n" + string(pretty)
	}
	return out + "\n" + string(body)
}

// ui2SessionRuleDomainProjection renders the review sheet's exact-change view for a
// coordinator-level install: the merged rule's domain marshal, redacted by the same walker the
// wire projection uses (its kind arms accept the domain's enum numbers), so what the sheet
// shows is field-for-field what the compare-and-update installs - minus the withheld values,
// which the token still binds. The op line names the operation rather than an HTTP call,
// because no request is dispatched on run.
func ui2SessionRuleDomainProjection(ruleID int64, expectedBase string, body []byte) string {
	out := "Update stored rule " + strconv.FormatInt(ruleID, 10) + " in place (compare-and-update; installs only while the stored rule still digests to " + expectedBase + "; nothing is re-encoded through the session API)"
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return out + "\n(unreadable body - " + strconv.Itoa(len(body)) + " bytes held)"
	}
	ui2SessionRuleRedact(v)
	if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
		return out + "\n" + string(pretty)
	}
	return out + "\n" + string(body)
}

// ui2SessionRuleRedact walks a decoded rule body withholding credential-carrying values in
// place. The generic key-name pass runs first; the domain pass then covers the shapes it
// cannot see: action values keyed by a generic "value", macro step bodies (the login form
// data), header PAIRS (two-element arrays, not the {name,value} maps redactSecrets knows),
// and embedded script source.
func ui2SessionRuleRedact(v any) {
	redactSecrets(v, map[string]bool{})
	ui2SessionRuleRedactDomain(v)
}

func ui2SessionRuleRedactDomain(v any) {
	switch t := v.(type) {
	case map[string]any:
		// kind arrives as the wire name on DTO-shaped bodies and as the enum number on a
		// domain marshal (ActionKind has no custom JSON marshaler - verified by probe); both
		// resolve to the same name before the per-kind arms decide what is withheld, or a
		// domain projection would show a set_cookie's value in the clear.
		kind, _ := t["kind"].(string)
		if kind == "" {
			if kn, ok := t["kind"].(json.Number); ok {
				if ki, err := kn.Int64(); err == nil {
					kind = session.ActionKindName(session.ActionKind(ki))
				}
			}
		}
		// extension_session is a free-form extension state blob (session.Action.ExtensionSession)
		// that only a domain marshal carries - the wire DTO never serves it. secretMember does
		// not match the name, so withhold it explicitly.
		if v, ok := t["extension_session"].(string); ok && v != "" {
			t["extension_session"] = redactedValue
		}
		if kind != "" {
			switch kind {
			case "set_cookie", "set_header", "set_param":
				if val, ok := t["value"].(string); ok && val != "" {
					t["value"] = redactedValue
				}
			case "replace":
				// Replacement resolves macro-extracted placeholders (the engine's own
				// actionPlaceholders classifies it with the set_* values), and a literal
				// Match is very often the old token being rewritten - both are withheld.
				for _, f := range []string{"replacement", "match"} {
					if val, ok := t[f].(string); ok && val != "" {
						t[f] = redactedValue
					}
				}
			case "run_script":
				if val, ok := t["script"].(string); ok && val != "" {
					t["script"] = redactedValue
				}
			}
		}
		// A macro step is the map with method+url: its body is the login form data, its
		// headers are [name, value] pairs, and its URL can itself carry a credential -
		// userinfo (http://user:pass@host) or a token-style query value. The engine's
		// placeholder classification does not decide that; the string does.
		if _, hasMethod := t["method"].(string); hasMethod {
			if stepURL, ok := t["url"].(string); ok {
				if b, ok := t["body"].(string); ok && b != "" {
					t["body"] = redactedValue
				}
				t["url"] = ui2SessionRuleSanitizeURL(stepURL)
			}
		}
		for _, val := range t {
			ui2SessionRuleRedactDomain(val)
		}
	case []any:
		// A header pair: ["Authorization", "Bearer ..."] - withhold the value when the name is
		// a credential carrier. Other pair arrays (none today) have no secret reading.
		if len(t) == 2 {
			if name, ok := t[0].(string); ok && secretMember.MatchString(name) {
				if val, ok := t[1].(string); ok && val != "" {
					t[1] = redactedValue
					return
				}
			}
		}
		for _, item := range t {
			ui2SessionRuleRedactDomain(item)
		}
	}
}

// ui2SessionRuleSanitizeURL rewrites a macro step URL for display only, keeping the host and
// path visible for the operator's review while withholding the credential-carrying parts:
// userinfo (http://user:pass@host) is replaced with the redaction marker, and query values
// whose KEY names a credential (token, key, sig, password, ...) are withheld while innocuous
// parameters stay visible. Both rewrites are string surgery on the wire form, so the marker
// stays readable and no percent-decode shows a credential by accident. A URL that will not
// parse is withheld whole - fail closed, since an unparseable form may be hiding a credential
// in the part that could not be classified. The engine's placeholder classification does not
// decide whether a URL contains a secret; the string does.
func ui2SessionRuleSanitizeURL(raw string) string {
	if _, err := url.Parse(raw); err != nil {
		return redactedValue
	}
	work := raw
	if i := strings.Index(work, "://"); i >= 0 {
		rest := work[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			if end := strings.IndexAny(rest, "/?#"); end < 0 || at < end {
				work = work[:i+3] + redactedValue + rest[at:]
			}
		}
	}
	mask := func(pairs string) string {
		parts := strings.Split(pairs, "&")
		for i, part := range parts {
			eq := strings.IndexByte(part, '=')
			if eq < 0 {
				continue
			}
			if key, err := url.QueryUnescape(part[:eq]); err == nil && secretMember.MatchString(key) {
				parts[i] = part[:eq+1] + redactedValue
			}
		}
		return strings.Join(parts, "&")
	}
	if q := strings.IndexByte(work, '?'); q >= 0 {
		tail := work[q+1:]
		frag := ""
		if h := strings.IndexByte(tail, '#'); h >= 0 {
			frag = tail[h:]
			tail = tail[:h]
		}
		work = work[:q+1] + mask(tail) + frag
	}
	// The fragment carries credentials in OAuth-style flows (#access_token=...): mask
	// secret-named pairs the same way. A fragment with no pairs and no path shape is a bare
	// unclassifiable token - withhold it whole rather than guess.
	if h := strings.IndexByte(work, '#'); h >= 0 {
		frag := work[h+1:]
		if frag != "" {
			switch {
			case strings.Contains(frag, "="):
				work = work[:h+1] + mask(frag)
			case strings.Contains(frag, "/"):
				// a routed anchor (#/dashboard), no carrier shape
			default:
				work = work[:h+1] + redactedValue
			}
		}
	}
	return work
}

// handleUI2SessionRules serves POST /ui2/session/rules/{action}: confirm mints and renders the
// review; run spends the held entry and dispatches the reviewed call.
func (s *Server) handleUI2SessionRules(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "confirm":
		s.ui2SessionRulesConfirm(w, r)
	case "run":
		s.ui2SessionRulesRun(w, r)
	default:
		http.Error(w, "unknown session rules action", http.StatusBadRequest)
	}
}

// ui2SessionRulePageKind reports whether the add form can create this action kind. Macros,
// validity checks and extension actions stay in the console: a fresh page rule has no macro
// steps to run, validity checks nest sub-actions, and an extension action names a registered
// extension, none of which a bounded form edits honestly. Multi-action rules and editing an
// existing rule's advanced fields stay there too.
func ui2SessionRulePageKind(k session.ActionKind) bool {
	switch k {
	case session.ActionAddCookiesFromJar, session.ActionSetCookie, session.ActionSetHeader,
		session.ActionSetParam, session.ActionReplace, session.ActionRunScript,
		session.ActionPromptForBrowserRecovery:
		return true
	}
	return false
}

// ui2SessionRuleActionFields lists every per-kind field the add form carries. The browser
// submits only the chosen kind's fields - the other kinds' controls stay disabled in the
// markup, and a disabled control is never successful - so one of these arriving for a kind
// that does not use it means a crafted or stale post, and the add is refused rather than the
// field ignored: the call the operator reviews must be the call they saw.
var ui2SessionRuleActionFields = []string{
	"action_name", "action_value", "action_in",
	"action_match", "action_replacement", "action_regex", "action_script",
}

// ui2SessionRulePageAction builds the one action a page-created rule carries from exactly the
// fields its kind defines. Field values are taken verbatim - a cookie value's spaces and a
// match's leading whitespace are the operator's content, and the review sheet shows the bytes
// the token binds.
func ui2SessionRulePageAction(kind session.ActionKind, r *http.Request) (map[string]any, error) {
	allowed := map[string]bool{}
	action := map[string]any{"kind": session.ActionKindName(kind), "enabled": true}
	switch kind {
	case session.ActionAddCookiesFromJar, session.ActionPromptForBrowserRecovery:
		// Fieldless kinds: any action_* field is foreign here.
	case session.ActionSetCookie, session.ActionSetHeader:
		allowed["action_name"], allowed["action_value"] = true, true
		action["name"] = strings.TrimSpace(r.PostFormValue("action_name"))
		action["value"] = r.PostFormValue("action_value")
	case session.ActionSetParam:
		allowed["action_name"], allowed["action_value"], allowed["action_in"] = true, true, true
		action["name"] = strings.TrimSpace(r.PostFormValue("action_name"))
		action["value"] = r.PostFormValue("action_value")
		action["in"] = r.PostFormValue("action_in")
	case session.ActionReplace:
		allowed["action_match"], allowed["action_replacement"], allowed["action_regex"] = true, true, true
		action["match"] = r.PostFormValue("action_match")
		action["replacement"] = r.PostFormValue("action_replacement")
		action["regex"] = r.PostFormValue("action_regex") != ""
	case session.ActionRunScript:
		allowed["action_script"] = true
		action["script"] = r.PostFormValue("action_script")
	}
	for _, field := range ui2SessionRuleActionFields {
		if allowed[field] {
			continue
		}
		if _, sent := r.PostForm[field]; sent {
			return nil, fmt.Errorf("the %s field does not belong to the %s action - the page you acted on was out of date", field, session.ActionKindLabel(kind))
		}
	}
	return action, nil
}

// ui2SessionRuleValidateAddBody validates the exact marshaled call the run step would dispatch:
// decoded by the API's own dtoToRule, then refused by the engine's validators - ValidateActions
// names the action's fault, and ValidateRule adds the rule-level placeholder check (a value
// naming a macro-extracted placeholder is refused: a page-created rule has no macro, so nothing
// extracts it). No page-side copy of the engine's checks exists to drift.
func ui2SessionRuleValidateAddBody(body []byte) error {
	var dto sessionRuleDto
	if err := json.Unmarshal(body, &dto); err != nil {
		return err
	}
	rule, err := dtoToRule(dto)
	if err != nil {
		return err
	}
	if err := session.ValidateActions(rule.Actions); err != nil {
		return err
	}
	return session.ValidateRule(rule)
}

// ui2SessionRulePageActionSummary names the chosen action in the review's own words, without
// repeating its values - the sheet's projection is where content shows, withheld where it must be.
func ui2SessionRulePageActionSummary(kind session.ActionKind, action map[string]any) string {
	switch kind {
	case session.ActionAddCookiesFromJar:
		return "add cookies from the session jar"
	case session.ActionSetCookie:
		return fmt.Sprintf("set the %q cookie", action["name"])
	case session.ActionSetHeader:
		return fmt.Sprintf("set the %q header", action["name"])
	case session.ActionSetParam:
		where := map[string]string{"": "wherever it already is", "query": "in the query string", "body": "in the form body"}[action["in"].(string)]
		return fmt.Sprintf("set the %q parameter %s", action["name"], where)
	case session.ActionReplace:
		if action["regex"] == true {
			return "replace what the regular expression matches"
		}
		return "replace the literal match"
	case session.ActionRunScript:
		return "run a pre-request script"
	case session.ActionPromptForBrowserRecovery:
		return "prompt for in-browser session recovery"
	}
	return session.ActionKindLabel(kind)
}

// ui2SessionRulesFail renders the review sheet's error arm; the back link returns to the page.
func (s *Server) ui2SessionRulesFail(w http.ResponseWriter, r *http.Request, msg string) {
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session_confirm.html", map[string]any{"error": msg}))
}

func (s *Server) ui2SessionRulesConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if s.sessionCoordinator == nil {
		s.ui2SessionRulesFail(w, r, "no session coordinator is wired on this server")
		return
	}
	op := r.PostFormValue("rule_op")
	var method, url string
	var body []byte
	var summary, consequence, successNote string
	// domainOp marks a coordinator-level install (toggle/edit): body then holds the merged
	// rule's domain marshal, and the run step installs it via UpdateRuleIfUnchanged under
	// domainBase instead of dispatching method+url+body through the wire API.
	var domainOp bool
	var domainID int64
	var domainBase string
	switch op {
	case "add":
		name := strings.TrimSpace(r.PostFormValue("name"))
		if name == "" {
			s.ui2SessionRulesFail(w, r, "a new rule needs a name")
			return
		}
		// The action is an explicit choice, never a default: adding a rule is substantive intent
		// (once on, it changes how matching requests are authenticated), so the form makes the
		// operator pick one of the kinds this page can create and the handler refuses the add
		// without that pick. The engine refuses a step-less default-macro rule, which is why
		// this page cannot offer a bare name+tools add at all.
		kind, kindErr := session.ParseActionKind(r.PostFormValue("action"))
		if kindErr != nil || !ui2SessionRulePageKind(kind) {
			s.ui2SessionRulesFail(w, r, "choose the rule's action on the form - this page creates the cookie-jar, set-cookie, set-header, set-parameter, replace, pre-request-script and browser-recovery-prompt actions; macros, validity checks and extension actions are written in the console")
			return
		}
		tools := r.PostForm["tools"]
		action, actErr := ui2SessionRulePageAction(kind, r)
		if actErr != nil {
			s.ui2SessionRulesFail(w, r, actErr.Error())
			return
		}
		// One action per page-created rule: a fresh page rule cannot run a macro (the engine
		// refuses a step-less one) and multi-action lists stay in the console. It is created
		// turned off, so adding it changes no traffic until the operator turns it on with its
		// own review.
		m := map[string]any{
			"name":    name,
			"enabled": false,
			"actions": []any{action},
		}
		if len(tools) > 0 {
			m["scope_tools"] = tools
		}
		body, _ = json.Marshal(m)
		// Mint-time validation runs the exact bytes the run step will dispatch through the same
		// conversion the install path uses and then the engine's own validators, so a call that
		// would fail at install never earns a review sheet - and this page's checks cannot drift
		// from the engine's.
		if verr := ui2SessionRuleValidateAddBody(body); verr != nil {
			s.ui2SessionRulesFail(w, r, verr.Error())
			return
		}
		method, url = http.MethodPost, "/api/session/rules"
		summary = fmt.Sprintf("Add rule %q, created turned off, with one action: %s. Tools scope: %s.", name, ui2SessionRulePageActionSummary(kind, action), ui2SessionRulesToolsNote(tools))
		consequence = "The rule is created turned off: it changes no traffic until you turn it on, which is its own reviewed step. Macro, validity and extension fields stay in the console. Existing rules offer ordered action-list controls."
		successNote = "rule added (turned off)"
	case "action_append", "action_edit", "action_up", "action_down", "action_remove", "action_enable", "action_disable", "action_stop_on", "action_stop_off":
		id, err := strconv.ParseInt(r.PostFormValue("rule_id"), 10, 64)
		if err != nil || id <= 0 {
			s.ui2SessionRulesFail(w, r, "that rule id is not valid")
			return
		}
		merged, digest, ok := s.sessionCoordinator.RuleSnapshot(session.RuleID(id))
		if !ok {
			s.ui2SessionRulesFail(w, r, "that rule no longer exists")
			return
		}
		if r.PostFormValue("form_base") != digest {
			s.ui2SessionRulesFail(w, r, "the rule changed since this action form opened - reopen it before reviewing")
			return
		}
		change, err := ui2SessionMutateActions(merged, r)
		if err != nil {
			s.ui2SessionRulesFail(w, r, err.Error())
			return
		}
		if err := session.ValidateActions(merged.Actions); err != nil {
			s.ui2SessionRulesFail(w, r, err.Error())
			return
		}
		if err := session.ValidateRule(merged); err != nil {
			s.ui2SessionRulesFail(w, r, err.Error())
			return
		}
		body, _ = json.Marshal(merged)
		method, url = http.MethodPut, "/api/session/rules/"+strconv.FormatInt(id, 10)
		domainOp, domainID, domainBase = true, id, digest
		summary = fmt.Sprintf("Rule %q (id %d): %s.", merged.Name, id, change)
		if merged.Enabled {
			consequence = "THIS RULE IS ON: applying changes its live action flow for matching requests immediately. Rule enabled state is preserved. Reordering can change authentication and rewriting; a stop action can prevent later actions from running."
		} else {
			consequence = "This rule stays OFF: applying changes its stored action flow, not current traffic. Turning it on remains a separate reviewed step."
		}
		if strings.HasPrefix(op, "action_stop_") || op == "action_enable" || op == "action_disable" {
			if merged.Enabled {
				consequence = "THIS RULE IS ON: the reviewed switch is stored immediately for matching requests. Actual traffic effect follows the action state and execution conditions named above; a disabled action stop change has no effect until enabled. Rule enabled state is preserved."
			} else {
				consequence = "THIS RULE IS OFF: the switch is stored now but changes no traffic until this rule is turned on. Rule enabled state is preserved."
			}
		}
		consequence += " Only the reviewed change is installed; a rule changed after review is refused. Macro, validity, other scope and unedited action fields are preserved."
		successNote = "rule actions updated"
	case "toggle", "edit", "remove":
		id, err := strconv.ParseInt(r.PostFormValue("rule_id"), 10, 64)
		if err != nil || id <= 0 {
			s.ui2SessionRulesFail(w, r, "that rule id is not valid")
			return
		}

		rule, ok := s.ui2SessionRuleDTO(id)
		if !ok {
			s.ui2SessionRulesFail(w, r, "that rule no longer exists - the page you acted on was out of date")
			return
		}
		name, _ := rule["name"].(string)
		enabled, _ := rule["enabled"].(bool)
		switch op {
		case "toggle":
			target := r.PostFormValue("target_enabled") == "true"
			if target == enabled {
				s.ui2SessionRulesFail(w, r, fmt.Sprintf("rule %q is already turned %s - the page you acted on was out of date", name, ui2OnOff(target)))
				return
			}
			// Domain merge, not a wire PUT: the served DTO drops Action.Validity and
			// Action.ExtensionSession, so re-encoding would lose them. The snapshot is a deep
			// copy taken with the digest in one lock hold; only the form-owned field changes.
			merged, digest, ok := s.sessionCoordinator.RuleSnapshot(session.RuleID(id))
			if !ok {
				s.ui2SessionRulesFail(w, r, "that rule no longer exists - the page you acted on was out of date")
				return
			}
			merged.Enabled = target
			if verr := session.ValidateRule(merged); verr != nil {
				s.ui2SessionRulesFail(w, r, "the session engine refuses this change: "+verr.Error())
				return
			}
			body, _ = json.Marshal(merged)
			method, url = http.MethodPut, "/api/session/rules/"+strconv.FormatInt(id, 10)
			domainOp, domainID, domainBase = true, id, digest
			if target {
				summary = fmt.Sprintf("Turn rule %q (id %d) on.", name, id)
				consequence = fmt.Sprintf("When on, this rule runs for every request matching its scope (tools: %s; URL scope as shown in the exact change): %s.", ui2SessionRuleToolsOf(rule), ui2SessionActionEffects(rule))
			} else {
				summary = fmt.Sprintf("Turn rule %q (id %d) off.", name, id)
				consequence = "When off, this rule's actions stop running for new requests; the rule itself is kept."
			}
			successNote = fmt.Sprintf("rule turned %s", ui2OnOff(target))
		case "edit":
			newName := strings.TrimSpace(r.PostFormValue("name"))
			if newName == "" {
				s.ui2SessionRulesFail(w, r, "a rule needs a name")
				return
			}
			merged, digest, ok := s.sessionCoordinator.RuleSnapshot(session.RuleID(id))
			if !ok {
				s.ui2SessionRulesFail(w, r, "that rule no longer exists - the page you acted on was out of date")
				return
			}
			merged.Name = newName
			var tools []string
			switch r.PostFormValue("tools_mode") {
			case "all":
				// Nil = every tool (the nil-vs-[] distinction the engine draws): a stated-empty
				// list applies to nothing, and the form refuses that below rather than letting a
				// restriction the operator did not mean stand.
				merged.ScopeTools = nil
			case "selected":
				tools = r.PostForm["tools"]
				if len(tools) == 0 {
					s.ui2SessionRulesFail(w, r, "a rule with no tools selected applies to nothing - pick at least one tool, or choose every tool")
					return
				}
				merged.ScopeTools = tools
			default:
				s.ui2SessionRulesFail(w, r, "tools_mode must be all or selected")
				return
			}
			if verr := session.ValidateRule(merged); verr != nil {
				s.ui2SessionRulesFail(w, r, "the session engine refuses this change: "+verr.Error())
				return
			}
			body, _ = json.Marshal(merged)
			method, url = http.MethodPut, "/api/session/rules/"+strconv.FormatInt(id, 10)
			domainOp, domainID, domainBase = true, id, digest
			summary = fmt.Sprintf("Edit rule %q (id %d): rename to %q, tools scope: %s. Everything else - macro steps, actions, validity, other scope - is kept unchanged.", name, id, newName, ui2SessionRulesToolsNote(tools))
			consequence = "The change applies only if the rule is still exactly what this review shows; if it changed in the meantime the compare-and-update refuses and nothing is applied."
			successNote = "rule updated"
		case "remove":
			digest, ok := s.ui2SessionRuleDigest(id)
			if !ok {
				s.ui2SessionRulesFail(w, r, "that rule no longer exists - the page you acted on was out of date")
				return
			}
			// The precondition rides the query because a DELETE has no body; the gate token
			// binds the canonical query, so the confirmation covers this exact base.
			method, url = http.MethodDelete, "/api/session/rules/"+strconv.FormatInt(id, 10)+"?expected_base="+digest
			summary = fmt.Sprintf("Remove rule %q (id %d) permanently. Its current actions: %s.", name, id, ui2SessionActionLabels(rule))
			consequence = "Removal is immediate and does not keep a copy; recreating the rule means writing it again. It applies only if the rule is still exactly what this review shows - if it changed in the meantime the API refuses and nothing is removed."
			successNote = "rule removed"
		}
	default:
		s.ui2SessionRulesFail(w, r, "unknown rule operation")
		return
	}
	token, _, errText := s.ui2MintConfirm("/api/session/rules", method, url, body)
	if errText != "" {
		s.ui2SessionRulesFail(w, r, errText)
		return
	}
	previewLabel := "exact call (the full content the token binds; credential values are withheld in this view but bound in the token)"
	projection := ui2SessionRuleProjection(method, url, body)
	if domainOp {
		previewLabel = "exact change (the stored rule after install - the domain marshal the token binds; credential values and extension session state are withheld in this view but bound in the token; per-action validity criteria are shown as stored)"
		projection = ui2SessionRuleDomainProjection(domainID, domainBase, body)
	}
	id, err := randomHex(16)
	if err != nil {
		s.ui2SessionRulesFail(w, r, "review id: "+err.Error())
		return
	}
	now := time.Now()
	s.ui2SessionRuleReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2SessionRuleReview); ok && now.After(e.expires) {
			s.ui2SessionRuleReviews.Delete(k)
		}
		return true
	})
	count := 0
	s.ui2SessionRuleReviews.Range(func(_, _ any) bool { count++; return true })
	if count >= ui2SessionRuleReviewCap {
		s.ui2SessionRulesFail(w, r, "too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	s.ui2SessionRuleReviews.Store(id, ui2SessionRuleReview{
		token: token, method: method, url: url, body: body, note: successNote,
		expires: now.Add(ConfirmTTL), domain: domainOp, ruleID: domainID, expectedBase: domainBase,
	})
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session_confirm.html", map[string]any{
		"review_id":     id,
		"token":         token,
		"summary":       summary,
		"consequence":   consequence,
		"preview":       projection,
		"preview_label": previewLabel,
	}))
}

// ui2SessionRulesRun spends the held review entry and dispatches the exact reviewed call with
// the entry's token. The entry is deleted on ANY spend attempt so nothing here is replayable.
func (s *Server) ui2SessionRulesRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	fail := func(msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("session.html", s.ui2SessionView(msg))))
	}
	id := r.PostFormValue("review_id")
	token := r.PostFormValue("token")
	v, ok := s.ui2SessionRuleReviews.LoadAndDelete(id)
	entry, isReview := v.(ui2SessionRuleReview)
	if !ok || !isReview {
		fail("that review is unknown or was already used - review the change again")
		return
	}
	if time.Now().After(entry.expires) {
		fail("that review expired with the confirmation window - review the change again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.token), []byte(token)) != 1 {
		fail("that review does not match this confirmation - review the change again")
		return
	}
	if entry.domain {
		// Coordinator-level install: decode the held domain marshal into a FRESH rule (the
		// entry's bytes are the reviewed change; nothing is re-read or re-merged at run time),
		// rebuild the extraction matchers the JSON form cannot carry, and install through the
		// same compare-and-update the API's PUT uses - ValidateRule + NormaliseActions run on
		// this private copy, then the digest check and swap happen in one lock hold.
		var merged session.SessionRule
		if err := json.Unmarshal(entry.body, &merged); err != nil {
			fail("the held review does not decode - review the change again")
			return
		}
		for _, ex := range merged.Extractions {
			if ex == nil {
				continue
			}
			if err := ex.Recompile(); err != nil {
				fail("the held review's extractions do not rebuild - review the change again")
				return
			}
		}
		err := s.sessionCoordinator.UpdateRuleIfUnchanged(session.RuleID(entry.ruleID), entry.expectedBase, &merged)
		switch {
		case errors.Is(err, session.ErrNoSuchRule):
			fail("that rule no longer exists - nothing was applied")
		case errors.Is(err, session.ErrRuleChanged):
			fail("that rule changed since you reviewed it - nothing was applied; open it again and re-review")
		case err != nil:
			fail("the session engine refused the change: " + truncateForDisplay(err.Error(), 200))
		default:
			// Install-then-persist, the API PUT's ordering.
			s.persistSessionRules()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(ui2Exec("session.html", s.ui2SessionView(entry.note))))
		}
		return
	}
	req := newReq(entry.method, entry.url)
	if entry.body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(entry.body)))
	}
	req.Header.Set(ConfirmHeader, token)
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)
	switch {
	case rec.Code == http.StatusPreconditionRequired:
		fail("confirmation required (428) - the review and the dispatch disagree; review again")
	case rec.Code == http.StatusConflict:
		fail("that rule changed since you reviewed it - nothing was applied; open it again and re-review")
	case rec.Code == http.StatusNotFound:
		fail("that rule no longer exists - nothing was applied")
	case rec.Code != http.StatusOK && rec.Code != http.StatusAccepted:
		fail("the session API refused the change: " + truncateForDisplay(strings.TrimSpace(rec.Body.String()), 200))
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("session.html", s.ui2SessionView(entry.note))))
	}
}

func ui2OnOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
