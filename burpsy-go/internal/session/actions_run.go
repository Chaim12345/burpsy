package session

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/internal/jsexec"
)

// ---- Running a rule's actions -------------------------------------------------------------------
//
// The walk is flat and ordered, with conditionality nesting only under a validity check — Burp's own
// shape. Four properties are decisions rather than accidents, and each one is here because the
// alternative is a rule that reports success and did not apply:
//
//   - **The request is threaded through the walk, not rebuilt from the original at each step.** A
//     SetParam followed by a Replace operates on the parameter the first action set, which is what
//     "actions are carried out in sequence" means. Rebuilding would make every action independent
//     and the order decorative.
//
//   - **A changed request is re-sent, and the caller is told.** An action that rewrote the request
//     and then had the request dropped on the floor is the decorative-control failure this project
//     keeps finding; there is a specific outcome kind for the resend (RecoveryRuleApplied) so it is
//     never mistaken for a login.
//
//   - **An action that cannot run says so in the trace and the walk continues** — unless it is a
//     macro that failed, which ends the walk. The distinction is what the action is *for*: a
//     SetParam whose value could not be resolved leaves the placeholder verbatim, which is
//     visible on the wire; a macro that could not be run means there is no session to handle, and
//     continuing would press on with a request the operator has just said is unauthenticated.
//
//   - **Nothing here mutates the rule.** Every action writes into a copy of the request held by the
//     walk, so two concurrent recoveries for one rule cannot see each other's rewrites.

// ActionRan is one action the walk performed, or declined to perform, for a report the operator can
// read. It exists so "the rule has a set-header action" and "the rule's set-header action ran and
// changed the request" are different statements, which is the only way to tell a rule that is
// working from one that is misconfigured and silent.
type ActionRan struct {
	// Index is the action's 1-based position in the walk, in the order it was reached — nested
	// sub-actions are numbered by when they ran, not by where they sit in the tree, because the
	// report is a log of what happened.
	Index int
	Kind  ActionKind
	Label string
	// Detail is what this action did or why it did nothing, in the operator's terms.
	Detail string
	// Changed is whether the action altered the request.
	Changed bool
	// Skipped is non-empty when the action did not run at all (disabled, or in the branch a
	// validity check did not take).
	Skipped string
}

// actionWalk is one run of a rule's action list.
type actionWalk struct {
	c        *Coordinator
	rule     *SessionRule
	runner   MacroStepRunner
	request  MacroStep
	response *StepResult
	// values are the {{name}} values the most recent macro run produced. Shared with anything the
	// walk runs afterwards, which is the whole point: the CSRF recipe is a macro that extracts a
	// token followed by an action that writes it into the request.
	values map[string]string
	// validity is the verdict the last check reached, and checked is whether one ran at all.
	validity ValidityState
	checked  bool
	// branchValidity is the validity rule of the check whose branch is being walked, so a macro
	// nested under that check satisfies *that* condition rather than the rule's own. Nil means no
	// enclosing check, and the retry loop then falls back to the rule's validity rule.
	branchValidity *ValidityRule
	// macroRan records whether any macro action ran, so the caller can tell a re-login from a
	// rewrite when it decides what the outcome means.
	macroRan bool
	// macroOutcome is the last macro outcome, kept so a failed macro can end the walk with the
	// reason rather than only a count.
	macroOutcome LoginOutcome
	// changed is whether the request as a whole differs from the one the walk was handed.
	changed bool
	// stopped is set by an action carrying "no further actions".
	stopped bool
	// promptDeclined is set when a browser-recovery prompt ended without the session being
	// recovered — by a decline, a timeout, or there being nobody to ask. The walk stops in every
	// one of those cases, and the flag is how the caller tells "the gate held and nothing was
	// sent" from "nothing needed doing", which a stopped walk with no other change would
	// otherwise read as. See promptForBrowserRecovery and RecoveryPromptDeclined.
	promptDeclined bool
	// promptSucceeded is set when the operator confirmed the session was recovered. The request
	// bytes did not change, but the session did — the jar the resend carries is the one the
	// operator's browser just established — so the walk reports the resend the same way a
	// changed request or a successful macro does. Without it a prompt-only rule would report
	// AlreadyValid and drop the request the operator was asked to recover the session for.
	promptSucceeded bool
	// cookieOverrides are the cookies set_cookie actions named, in the order they were set, carried
	// to the send so the jar cannot overwrite them. See applyJarWith.
	cookieOverrides []CookieOverride
	trace           []ActionRan
	next            int
}

func (w *actionWalk) record(kind ActionKind, detail string, changed bool) {
	w.next++
	w.trace = append(w.trace, ActionRan{
		Index: w.next, Kind: kind, Label: ActionKindLabel(kind), Detail: detail, Changed: changed,
	})
}

func (w *actionWalk) recordSkipped(kind ActionKind, reason string) {
	w.next++
	w.trace = append(w.trace, ActionRan{
		Index: w.next, Kind: kind, Label: ActionKindLabel(kind), Skipped: reason,
	})
}

// actionResult is what one walk of a rule's actions produced.
//
// Structured rather than a trace the caller reads back: the trace is what an operator is shown, and
// a caller that decided its outcome by matching text in that trace would be agreeing with the
// display by construction — a report that cannot disagree with the evidence beside it is not a
// report. (The first draft of this file did exactly that. It is worth saying out loud, because the
// test that would have caught it is the one that reads a *different* field.)
type actionResult struct {
	// Request is the request the walk arrived at, which is what the caller re-sends.
	Request MacroStep
	// CookieOverrides are the cookies set_cookie actions named. Separate from Request.Headers
	// because the send path rebuilds the Cookie header from the jar and would otherwise drop them.
	CookieOverrides []CookieOverride
	// Trace is what each action did, in the order it was reached.
	Trace []ActionRan
	// Changed is whether Request differs from the request the walk was handed.
	Changed bool
	// Checked is whether a validity check reached a verdict, and Validity is that verdict. A rule
	// whose actions never check has Checked false — and is not credited with a Valid one.
	Checked  bool
	Validity ValidityState
	// MacroRan is whether any macro action ran, and MacroOutcome is the last one's result.
	MacroRan     bool
	MacroOutcome LoginOutcome
	// PromptDeclined is whether a browser-recovery prompt ended without the session being
	// recovered. The caller reads it as RecoveryPromptDeclined, which is the difference
	// between "the operator was asked and the answer was no" and "the session was already
	// fine" — a stopped walk with no macro and no changes is otherwise indistinguishable from
	// the second.
	PromptDeclined bool
	// PromptSucceeded is whether the operator confirmed the session was recovered. The caller
	// reads it as a reason to re-send the request: the bytes are unchanged but the session is
	// not, and the resend is the entire point of having asked.
	PromptSucceeded bool
}

// runActions walks a rule's actions over one request and reports what came of it.
//
// `response` is the observed response the rule is reacting to, and may be nil — a rule whose actions
// never check validity has nothing to read, and forcing a caller to invent an empty StepResult would
// be inventing a measurement.
func (c *Coordinator) runActions(rule *SessionRule, request MacroStep, response *StepResult, runner MacroStepRunner) actionResult {
	w := &actionWalk{
		c: c, rule: rule, runner: runner,
		request: request, response: response,
		values: make(map[string]string),
	}
	original := cloneMacroStep(request)
	// One request, one count: every validity check in this walk reads the same number, so two
	// checks on one rule can never disagree about which request is due.
	w.c.noteValidityCheckRequest(w.c.ruleIDOf(rule))
	w.walk(rule.EffectiveActions())
	return actionResult{
		Request:         w.request,
		CookieOverrides: w.cookieOverrides,
		Trace:           w.trace,
		Changed:         !sameMacroStep(original, w.request),
		Checked:         w.checked,
		Validity:        w.validity,
		MacroRan:        w.macroRan,
		MacroOutcome:    w.macroOutcome,
		PromptDeclined:  w.promptDeclined,
		PromptSucceeded: w.promptSucceeded,
	}
}

func (w *actionWalk) walk(actions []*Action) {
	for _, a := range actions {
		if w.stopped {
			w.recordSkipped(a.Kind, "an earlier action stated that no further actions apply")
			continue
		}
		if a == nil {
			continue
		}
		if !a.Enabled {
			w.recordSkipped(a.Kind, "disabled")
			continue
		}
		w.perform(a)
		if a.Stop {
			w.stopped = true
			// Said in the trace rather than implied by the next action being skipped: the last
			// action's own "no further actions" would otherwise leave no evidence it was honoured.
			w.recordSkipped(a.Kind, "stated that no further actions apply")
		}
	}
}

func (w *actionWalk) perform(a *Action) {
	switch a.Kind {
	case ActionCheckValidity:
		w.checkValidity(a)
	case ActionRunMacro, ActionRunPostRequestMacro:
		w.runMacro(a)
	case ActionAddCookiesFromJar:
		before := cloneMacroStep(w.request)
		w.request = w.c.applyJar(w.request)
		w.record(a.Kind, "attached the session cookie jar's cookies for this request",
			!sameMacroStep(before, w.request))
	case ActionSetCookie:
		w.setCookie(a)
	case ActionSetParam:
		w.setParam(a)
	case ActionSetHeader:
		w.setHeader(a)
	case ActionReplace:
		w.replace(a)
	case ActionInvokeExtension:
		w.invokeExtension(a)
	case ActionPromptForBrowserRecovery:
		w.promptForBrowserRecovery(a)
	case ActionRunScript:
		w.runScript(a)
	default:
		// Unreachable through ValidateRule, which refuses an unknown kind. Recorded rather than
		// ignored because this is the branch a kind added to the enum but not to this switch would
		// fall into, and a rule action that silently does nothing is the failure mode the whole
		// action model exists to make impossible.
		w.record(a.Kind, fmt.Sprintf("this build has no executor for action kind %d", int(a.Kind)), false)
	}
}

// ---- the actions --------------------------------------------------------------------------------

// checkValidity evaluates the response and walks the branch the verdict selects.
//
// Indeterminate takes the Else branch, which is the pre-action behaviour preserved exactly: the old
// code took the recovery path for anything that was not Valid, on the stated grounds that reading "I
// could not tell whether this session is alive" as "it is fine" is the wrong direction to fail. A
// rule whose check cannot decide must keep trying to authenticate.
func (w *actionWalk) checkValidity(a *Action) {
	rules := a.Validity
	if rules == nil {
		rules = w.rule.Validity
	}
	if rules == nil {
		w.record(a.Kind, "no validity rule is stated, so the check cannot decide anything; taking the "+
			"not-valid branch", false)
		w.walk(a.Else)
		return
	}
	// Burp's "validate the session after a set number of requests" (validate_every_num_requests,
	// recovered from burp.Zcfs). Off this request, the check is treated as not run — not as
	// "valid" and not as "invalid": a rule that never checked cannot claim a verdict, and walking
	// the Else branch anyway would fire a login macro every Nth request for a session that is
	// almost always fine, which is the cost the field exists to avoid. The Then branch runs
	// instead, because "the session is presumed alive" is the only reading that asks for no request.
	if !w.dueForValidityCheck(a) {
		w.record(a.Kind, fmt.Sprintf(
			"not checking the session on this request: the rule validates every %d request(s) (us12)",
			a.ValidateEvery), false)
		w.walk(a.Then)
		return
	}
	verdict := rules.Evaluate(statusOf(w.response), headersOf(w.response), bodyOf(w.response), urlOf(w.response))
	w.validity, w.checked = verdict, true
	branch, name := a.Then, "then"
	if verdict != Valid {
		branch, name = a.Else, "else"
	}
	w.record(a.Kind, fmt.Sprintf("the session is %s, so the %s branch runs", verdictName(verdict), name), false)
	// The branch is walked under this check's condition, so a macro inside it has to satisfy the
	// condition the operator wrote for this check. Restored afterwards so a sibling check that states
	// nothing falls back to the rule's own rule rather than inheriting this one.
	previous := w.branchValidity
	w.branchValidity = rules
	w.walk(branch)
	w.branchValidity = previous
}

// dueForValidityCheck answers whether this check is due on the request being handled.
//
// The counter is per rule, not per action or per walk, and that is the whole reading of Burp's
// wording: "validate the session after a set number of requests" counts the requests the rule
// handles, so two checks on one rule share one count and a check nested under another does not keep
// its own. Zero means due every time, which is what every rule that predates the field means.
//
// A counter that resets on process restart is the honest reading — the count is a running cost
// decision, not session state, and restoring it from the database would make a rule's behaviour
// depend on when the process last stopped.
func (w *actionWalk) dueForValidityCheck(a *Action) bool {
	if a.ValidateEvery <= 0 {
		return true
	}
	return w.c.dueForValidityCheck(w.c.ruleIDOf(w.rule), a.ValidateEvery)
}

// dueForValidityCheck is the coordinator half: one counter per rule, advanced once per handled
// request, and the check is due when that request's count is a multiple of the interval.
//
// The count is advanced by the WALK, not by this function. A rule may hold two checks (Burp nests
// them freely), and a per-call increment would make the second check see a different count from
// the first — so on request 1 the first would skip and the second would run, which is neither Burp's
// behaviour nor anything an operator could reason about. Per rule, per request, decided once.
func (c *Coordinator) dueForValidityCheck(id RuleID, every int) bool {
	if every <= 0 {
		return true
	}
	c.validityCountersMu.Lock()
	defer c.validityCountersMu.Unlock()
	return c.validityCounters[id]%int64(every) == 0
}

// noteValidityCheckRequest advances the rule's request count for this walk, so every check in one
// walk reads the same number. Called once per action list run, before the first check is reached.
func (c *Coordinator) noteValidityCheckRequest(id RuleID) {
	c.validityCountersMu.Lock()
	defer c.validityCountersMu.Unlock()
	if c.validityCounters == nil {
		c.validityCounters = make(map[RuleID]int64)
	}
	c.validityCounters[id]++
}

// runMacro runs a macro through the coordinator's single-flight login, so a rule whose macro action
// is reached by N concurrent observers still causes one login — and so the bounded retry
// (`max_attempts`) that the pre-action shape had is preserved rather than reimplemented here.
//
// The validity rule handed to the retry loop is the *enclosing check's* when there is one, not the
// rule's: an action that states its own validity condition and then satisfies a different one would
// report success for a check nobody ran.
func (w *actionWalk) runMacro(a *Action) {
	if a.Kind == ActionRunPostRequestMacro {
		// Burp's ordering: "this issues the current request, and then executes a further macro".
		// The response it earns becomes what a later check reads, which is the only way the action
		// is distinguishable from a plain macro followed by a retry.
		if _, err := w.c.sendWithJar(w.runner, w.request); err != nil {
			w.record(a.Kind, "the current request could not be sent: "+err.Error(), false)
			w.stopped = true
			return
		}
	}
	validity := w.enclosingValidity()
	outcome := w.c.ensureLoggedIn(w.c.ruleIDOf(w.rule), w.rule, w.runner, validity)
	w.macroRan, w.macroOutcome = true, outcome
	switch outcome.Kind {
	case LoginSucceeded:
		for k, v := range outcome.Values {
			w.values[k] = v
		}
		w.record(a.Kind, fmt.Sprintf("ran the macro: %d attempt(s), %d extracted value(s)",
			outcome.Attempts, len(outcome.Values)), true)
	case LoginGaveUp:
		w.record(a.Kind, fmt.Sprintf("ran the macro %d time(s) and the session never became valid",
			outcome.Attempts), false)
	case LoginMacroFailed:
		w.record(a.Kind, "the macro could not be run: "+outcome.Failure.String(), false)
		// The one action that ends the walk when it fails. Continuing would send a request the
		// operator has just been told cannot be authenticated.
		w.stopped = true
	}
}

// enclosingValidity is the check this macro is nested under, if any — see runMacro.
func (w *actionWalk) enclosingValidity() *ValidityRule {
	if w.branchValidity != nil {
		return w.branchValidity
	}
	return w.rule.Validity
}

func (w *actionWalk) setCookie(a *Action) {
	value := actionsSubstituteValues(a.Value, w.values)
	before := cloneMacroStep(w.request)
	if w.request.Headers == nil {
		w.request.Headers = make(map[string]string)
	}
	w.request.Headers["Cookie"] = setCookiePair(w.request.Headers["Cookie"], a.Name, value)
	// Also recorded out-of-band, because writing the header is not enough to make this action real:
	// the send path's applyJar replaces the whole Cookie header with the jar's, which used to delete
	// this cookie between the trace saying it was set and the request going out. See applyJarWith.
	w.cookieOverrides = append(w.cookieOverrides, CookieOverride{Name: a.Name, Value: value})
	w.record(a.Kind, fmt.Sprintf("set cookie %s=%s", a.Name, value),
		!sameMacroStep(before, w.request))
}

func (w *actionWalk) setHeader(a *Action) {
	value := actionsSubstituteValues(a.Value, w.values)
	before := cloneMacroStep(w.request)
	if w.request.Headers == nil {
		w.request.Headers = make(map[string]string)
	}
	// Case-insensitively replaced rather than blindly set: two headers differing only in case is a
	// request no origin agrees on, and Go's map is case-sensitive while HTTP is not.
	replaced := false
	for k := range w.request.Headers {
		if strings.EqualFold(k, a.Name) {
			w.request.Headers[k] = value
			replaced = true
			break
		}
	}
	if !replaced {
		w.request.Headers[a.Name] = value
	}
	w.record(a.Kind, fmt.Sprintf("set header %s: %s", a.Name, value), !sameMacroStep(before, w.request))
}

// setParam writes one named parameter, honouring the action's `in` when it states one.
//
// # Where "unspecified" means
//
//	the parameter where it already is, and the query string when it is nowhere
//
// That is the CSRF case in both of its spellings — the token is already a form field on one target
// and a query parameter on another — and it is also the only reading under which an action whose
// purpose is to make the request *carry* a value cannot silently fail to add it.
//
// # Why a stated "body" on a non-form body is refused rather than attempted
//
// A JSON body is not a set of named parameters, and appending `csrf=abc` to one produces a body no
// origin can parse and no error anywhere. The action records that it could not do what it was asked,
// which is a fact the operator can act on.
func (w *actionWalk) setParam(a *Action) {
	value := actionsSubstituteValues(a.Value, w.values)
	in := a.In
	if in == "" {
		switch {
		case urlHasParam(w.request.URL, a.Name):
			in = "query"
		case bodyHasFormParam(w.request.Body, a.Name):
			in = "body"
		default:
			in = "query"
		}
	}
	before := cloneMacroStep(w.request)
	switch in {
	case "query":
		w.request.URL = setURLParam(w.request.URL, a.Name, value)
	case "body":
		if !looksFormEncoded(w.request.Body) {
			w.record(a.Kind, fmt.Sprintf("could not set the parameter %q in the body: the body is not "+
				"form-encoded, and adding a form field to it would produce a request no origin can read",
				a.Name), false)
			return
		}
		w.request.Body = setFormParam(w.request.Body, a.Name, value)
	}
	w.record(a.Kind, fmt.Sprintf("set parameter %s=%s in the %s", a.Name, value, in),
		!sameMacroStep(before, w.request))
}

// replace rewrites matching text in the request, over the same field set resolveStep covers: the
// URL, every header's name and value, and the body. A header *name* is included because that is
// where a rule matching a header-shaped pattern expects to look, and leaving it out would make the
// action quietly narrower than the pattern it was given.
func (w *actionWalk) replace(a *Action) {
	match := a.Match
	apply := func(s string) string {
		if a.Regex {
			re, err := regexp.Compile(match)
			if err != nil {
				return s
			}
			return re.ReplaceAllString(s, a.Replacement)
		}
		if !strings.Contains(s, match) {
			return s
		}
		return strings.ReplaceAll(s, match, a.Replacement)
	}
	before := cloneMacroStep(w.request)
	w.request.URL = apply(w.request.URL)
	w.request.Body = apply(w.request.Body)
	if len(w.request.Headers) > 0 {
		next := make(map[string]string, len(w.request.Headers))
		names := make([]string, 0, len(w.request.Headers))
		for k := range w.request.Headers {
			names = append(names, k)
		}
		// Sorted so a rule whose pattern can match two header names rewrites them in a fixed order:
		// map iteration would make the result depend on a runtime seed.
		sort.Strings(names)
		for _, k := range names {
			next[apply(k)] = apply(w.request.Headers[k])
		}
		w.request.Headers = next
	}
	w.record(a.Kind, fmt.Sprintf("replaced matching text in the request (%s)", matchDescription(a)),
		!sameMacroStep(before, w.request))
}

func matchDescription(a *Action) string {
	if a.Regex {
		return "regex " + a.Match
	}
	return "literal " + a.Match
}

// invokeExtension hands the request and the observed response to a loaded plugin and takes back the
// request it wants sent.
//
// With no invoker attached the action records a refusal, which is the important half: an operator who
// wrote an invoke-extension action on a build with no extension host must be told that nothing was
// invoked, rather than watching a rule report success while sending the request it would have sent
// anyway. The invoker is a seam because internal/extension sits above this package in the dependency
// direction — this package must not import it.
func (w *actionWalk) invokeExtension(a *Action) {
	if w.c.extensionInvoker == nil {
		w.record(a.Kind, "no extension host is attached, so nothing was invoked; start the console's "+
			"extension host (or attach one through SetSessionActionInvoker) to use this action", false)
		return
	}
	next, err := w.c.extensionInvoker.InvokeSessionAction(SessionActionRequest{
		Registration: a.Extension,
		Request:      w.request,
		Response:     w.response,
		Values:       copyValues(w.values),
	})
	if err != nil {
		w.record(a.Kind, "the extension refused or could not be reached: "+err.Error(), false)
		return
	}
	before := cloneMacroStep(w.request)
	w.request = next
	w.record(a.Kind, fmt.Sprintf("invoked extension registration %q", a.Extension),
		!sameMacroStep(before, w.request))
}

// runScript runs a pre-request script over the request (burpsy-react-ui-ydmj).
//
// On a script error the request is left exactly as it was and the trace says why: a script that threw
// halfway through recomputing a signature has produced a request that LOOKS signed and is not, which
// is worse than the unsigned request it started from. The walk carries on — the same as an action
// that changed nothing — rather than refusing to send, because a pre-request script is a rewrite, not
// a gate; a rule that must not send without it can follow it with a validity check.
func (w *actionWalk) runScript(a *Action) {
	ruleID := w.c.ruleIDOf(w.rule)
	req := jsexec.ScriptRequest{Method: w.request.Method, URL: w.request.URL, Headers: copyHeaders(w.request.Headers), Body: w.request.Body}
	var resp *jsexec.ScriptResponse
	if w.response != nil {
		resp = &jsexec.ScriptResponse{Status: w.response.Status, Headers: copyHeaders(w.response.Headers), Body: string(w.response.Body)}
	}
	result, err := jsexec.RunRequestScript(a.Script, req, resp, w.c.scriptStore(ruleID))
	logNote := ""
	if len(result.Log) > 0 {
		logNote = "; log: " + strings.Join(result.Log, " | ")
	}
	if err != nil {
		w.record(a.Kind, "the pre-request script failed and the request was left unchanged: "+err.Error()+logNote, false)
		return
	}
	w.c.setScriptStore(ruleID, result.Store)
	before := cloneMacroStep(w.request)
	w.request = MacroStep{Method: result.Request.Method, URL: result.Request.URL, Headers: result.Request.Headers, Body: result.Request.Body}
	changed := !sameMacroStep(before, w.request)
	msg := "ran the pre-request script; the request is unchanged"
	if changed {
		msg = "ran the pre-request script; it rewrote the request"
	}
	w.record(a.Kind, msg+logNote, changed)
}

// scriptStore returns a copy of a rule's script store, so a script run never holds scriptMu.
func (c *Coordinator) scriptStore(id RuleID) map[string]string {
	c.scriptMu.Lock()
	defer c.scriptMu.Unlock()
	out := make(map[string]string, len(c.scriptStores[id]))
	for k, v := range c.scriptStores[id] {
		out[k] = v
	}
	return out
}

// setScriptStore replaces a rule's script store with what a successful run left. Bounded so a script
// cannot grow it without limit across requests: past the bound the run's writes are refused whole
// and the previous store stands.
func (c *Coordinator) setScriptStore(id RuleID, next map[string]string) {
	const maxEntries, maxBytes = 64, 64 * 1024
	total := 0
	for k, v := range next {
		total += len(k) + len(v)
	}
	if len(next) > maxEntries || total > maxBytes {
		return
	}
	c.scriptMu.Lock()
	defer c.scriptMu.Unlock()
	if c.scriptStores == nil {
		c.scriptStores = make(map[RuleID]map[string]string)
	}
	c.scriptStores[id] = next
}

func copyHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// promptForBrowserRecovery is Burp's "prompt the user for in-browser session recovery", and the one
// action whose executor is a question rather than a rewrite.
//
// # What burpsy's counterpart is, and is not
//
// Burp opens a browser window on the failing response so the operator can log in by hand, then
// tells the rule to carry on. burpsy has no window it can open — the console is a page the
// operator opens themselves — so the prompt is a modal on that page, and the task blocks on the
// SessionPrompter seam until the operator answers. The session the operator establishes in their
// browser reaches the retried request the same way Burp's does: through the proxy, into the jar,
// and out on the Cookie header. Nothing in this action reads the operator's browser directly; it
// only asks, waits, and carries on.
//
// # Why every non-success stops the walk
//
// The action's whole job is to gate the send on a human being's answer. A request that goes out
// after a decline — or after the prompt could not be asked at all — makes the action a lie, which
// is the decorative-control failure this whole unit exists to prevent. So the walk stops on
// every path that is not an explicit "the session is recovered", and the outcome says so
// (RecoveryPromptDeclined) rather than reading as AlreadyValid — "the session was already fine"
// is the opposite of what happened: the operator was asked whether it is, and the answer was no.
func (w *actionWalk) promptForBrowserRecovery(a *Action) {
	if w.c.sessionPrompter == nil {
		w.record(a.Kind, "no console is attached, so the operator was never asked; the request "+
			"was not sent — a rule that gates its sends on a prompt cannot be honoured by a "+
			"process with nobody at the console", false)
		w.stopped = true
		w.promptDeclined = true
		return
	}
	recovered, err := w.c.sessionPrompter.PromptForBrowserRecovery(w.rule.Name, w.request.URL)
	switch {
	case err != nil:
		w.record(a.Kind, "the browser-recovery prompt could not be completed: "+err.Error(), false)
		w.stopped = true
		w.promptDeclined = true
	case !recovered:
		w.record(a.Kind, "the operator was asked to recover the session in the browser and "+
			"declined; the request was not sent", false)
		w.stopped = true
		w.promptDeclined = true
	default:
		w.record(a.Kind, "the operator recovered the session in the browser; the task resumed "+
			"and the request goes out with the jar as the browser left it", false)
		w.promptSucceeded = true
	}
}

// ---- the extension seam -------------------------------------------------------------------------

// SessionActionRequest is what an extension session action is handed: the request as the rule has
// rewritten it so far, the response the rule is reacting to (nil when the rule has not observed
// one), and the {{name}} values a macro action has extracted.
type SessionActionRequest struct {
	Registration string
	Request      MacroStep
	Response     *StepResult
	Values       map[string]string
}

// SessionActionInvoker is the extension host as this package sees it: one method, named after the
// extension point rather than after Burp's API, so a host that is not a Burp-shaped host can satisfy
// it. Implemented by internal/extension's host through a small adapter in internal/web.
type SessionActionInvoker interface {
	// InvokeSessionAction runs one plugin-registered session action and returns the request it wants
	// sent. An error means the plugin refused or could not be reached, and the walk leaves the
	// request alone rather than guessing.
	InvokeSessionAction(SessionActionRequest) (MacroStep, error)
}

// SetSessionActionInvoker attaches the extension host.
//
// Separate from the coordinator's constructor for the reason intercept.Engine.SetScope is separate
// from its toggle: the host is wired once, by whoever owns it, and a rule may name an extension long
// before one is loaded. Nil is a valid state and is reported by the action rather than by silence.
func (c *Coordinator) SetSessionActionInvoker(inv SessionActionInvoker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.extensionInvoker = inv
}

// ExtensionAttached reports whether an extension host is wired, so a surface can say why an
// invoke-extension action would do nothing rather than offering a control that silently does nothing
// — the same contract intercept.Engine.ScopeAttached exists for.
func (c *Coordinator) ExtensionAttached() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.extensionInvoker != nil
}

// ---- the console-prompt seam ------------------------------------------------------------------------

// SessionPrompter is the console's "ask the operator" surface as this package sees it: one method,
// named after the rule action it serves. Implemented by internal/web, which owns the console the
// operator is looking at — the same seam reasoning as SessionActionInvoker, and for the same
// reason: the prompt UI sits above this package in the dependency direction, so this package
// declares the one method it needs and the console adapts its modal to it.
type SessionPrompter interface {
	// PromptForBrowserRecovery suspends the calling task until the operator has recovered the
	// session in their own browser. The bool reports whether the session was recovered — the
	// task resumes — or not; a non-nil error means the prompt could not be completed at all (a
	// timeout, or a console that could not be reached), which the action reports verbatim rather
	// than reading as a decline the operator never made.
	//
	// Implementations must not return (false, nil) on a timeout: a timeout is not a decline, and
	// the two are different things for an operator to read in the trace.
	PromptForBrowserRecovery(ruleName string, requestURL string) (recovered bool, err error)
}

// SetSessionPrompter attaches the console's prompt surface. Separate from the coordinator's
// constructor for the reason SetSessionActionInvoker is: the console is wired once, by whoever
// owns it, and a rule may name the prompt long before one exists. Nil is a valid state and is
// reported by the action rather than by silence.
func (c *Coordinator) SetSessionPrompter(p SessionPrompter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionPrompter = p
}

// PrompterAttached reports whether a console prompt surface is wired, so a surface can say why a
// prompt-for-browser-recovery action would do nothing rather than offering a control that
// silently does nothing — the same contract ExtensionAttached exists for.
func (c *Coordinator) PrompterAttached() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionPrompter != nil
}

// ---- small helpers ------------------------------------------------------------------------------

func copyValues(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// sameMacroStep reports whether two steps are byte-for-byte the same request, which is how the walk
// answers "did this action change anything" and "does this rule's request need re-sending".
// cloneMacroStep copies a step deeply enough to compare against after a mutation.
//
// MacroStep is a struct, so `before := w.request` reads like a snapshot and is not one: Headers is a
// map, and the copy shares it. Every "did this action change anything" test in this file was
// therefore comparing a map with itself and answering no. That was not cosmetic. recover() reads the
// same answer at the whole-walk level and returns AlreadyValid *without sending* when nothing
// changed, so a rule whose actions only set headers or cookies — the CSRF recipe this issue is
// about — did all its work and then never put it on the wire.
func cloneMacroStep(s MacroStep) MacroStep {
	if s.Headers != nil {
		h := make(map[string]string, len(s.Headers))
		for k, v := range s.Headers {
			h[k] = v
		}
		s.Headers = h
	}
	return s
}

func sameMacroStep(a, b MacroStep) bool {
	if a.Method != b.Method || a.URL != b.URL || a.Body != b.Body {
		return false
	}
	if len(a.Headers) != len(b.Headers) {
		return false
	}
	for k, v := range a.Headers {
		if b.Headers[k] != v {
			return false
		}
	}
	return true
}

func statusOf(r *StepResult) int {
	if r == nil {
		return 0
	}
	return r.Status
}

func headersOf(r *StepResult) map[string]string {
	if r == nil {
		return nil
	}
	return r.Headers
}

func bodyOf(r *StepResult) []byte {
	if r == nil {
		return nil
	}
	return r.Body
}

func urlOf(r *StepResult) string {
	if r == nil {
		return ""
	}
	return r.FinalURL
}

// setCookiePair sets one cookie in a Cookie header value, replacing a pair by name and appending
// when there is none. Appended pairs are sorted for the reason cookieJar.cookieHeader sorts: a header
// whose pairs reshuffle between requests is one an operator cannot diff.
func setCookiePair(header, name, value string) string {
	pairs := make(map[string]string)
	var order []string
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if _, seen := pairs[k]; !seen {
			order = append(order, k)
		}
		pairs[k] = v
	}
	if _, seen := pairs[name]; !seen {
		order = append(order, name)
	}
	pairs[name] = value

	var out []string
	for _, k := range order {
		out = append(out, k+"="+pairs[k])
	}
	return strings.Join(out, "; ")
}

// urlHasParam reports whether the URL's query string carries a parameter with this name.
func urlHasParam(rawURL, name string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	_, ok := u.Query()[name]
	return ok
}

// setURLParam sets one query parameter, replacing every occurrence of the name and adding one when
// it is absent.
//
// Returns the URL unchanged when it does not parse: a request whose URL cannot be read is not one to
// guess a query string onto, and the caller records the outcome from the returned bytes rather than
// from an error this function could only describe in the same words.
func setURLParam(rawURL, name, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// looksFormEncoded reports whether a body is a set of named parameters, which is what a body-directed
// SetParam action needs it to be.
//
// An empty body counts: a request with no body has no parameters in it and nothing for a form field
// to corrupt, so adding one is exactly what the action asked for. Anything else must look like
// `k=v` pairs — the presence of an `=` and the absence of a JSON or XML shape. Deliberately narrow:
// the cost of being wrong here is a body no origin can parse.
func looksFormEncoded(body string) bool {
	if strings.TrimSpace(body) == "" {
		return true
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "<") {
		return false
	}
	return strings.Contains(body, "=")
}

// bodyHasFormParam reports whether a form-shaped body already carries this parameter name.
func bodyHasFormParam(body, name string) bool {
	if !looksFormEncoded(body) {
		return false
	}
	for _, pair := range strings.Split(body, "&") {
		k, _, _ := strings.Cut(pair, "=")
		if k == name {
			return true
		}
	}
	return false
}

// setFormParam sets one parameter in a form-encoded body, replacing every occurrence of the name and
// appending one when it is absent. Form fields are permissively unencoded here for the same reason
// the rest of this package is: the operator's value is sent as they wrote it, and re-encoding a token
// they had already encoded is the kind of change that makes a real request fail for a reason nobody
// can see in the rule.
func setFormParam(body, name, value string) string {
	pairs := strings.Split(body, "&")
	found := false
	for i, pair := range pairs {
		if pair == "" {
			continue
		}
		k, _, _ := strings.Cut(pair, "=")
		if k == name {
			pairs[i] = name + "=" + value
			found = true
		}
	}
	out := strings.Join(pairs, "&")
	if found {
		return out
	}
	if out != "" && !strings.HasSuffix(out, "&") {
		out += "&"
	}
	return out + name + "=" + value
}

func verdictName(v ValidityState) string {
	switch v {
	case Valid:
		return "valid"
	case Invalid:
		return "invalid"
	default:
		return "indeterminate"
	}
}
