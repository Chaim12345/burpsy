package session

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ---- outcome types ------------------------------------------------------------------------------
//
// These exist so a caller can tell "this is working" from "this has quietly stopped trying"
// without reading logs, which is what the Rust coordinator's named outcome types demand. The three
// failure modes they guard against are the same three the Rust crate documents:
//
//   - Looping: a macro whose own final response is invalid must not run forever. `max_attempts`
//     bounds it, and GaveUp carries exactly how many attempts were made.
//   - Piling on: if N requests notice session loss at once, reacting to each independently would
//     fire N logins at the target. `ensureLoggedIn` is single-flight *per rule*.
//   - Guessing which login applies: a response for a target no rule covers is reported as
//     NoRuleApplies, never treated as AlreadyValid.

// LoginOutcomeKind is what one attempt to run a rule's whole login macro produced.
type LoginOutcomeKind int

const (
	LoginSucceeded LoginOutcomeKind = iota
	LoginGaveUp
	LoginMacroFailed
)

// LoginOutcome is the result of one login attempt (running the whole macro to term, in order, up
// to max_attempts times). It is the value shared through a rule's in-flight loginRun.
type LoginOutcome struct {
	Kind     LoginOutcomeKind
	Attempts int               // Succeeded / GaveUp: how many attempts were made
	Attempt  int               // MacroFailed: the 1-based attempt that failed
	Failure  *MacroStepFailure // MacroFailed
	// Values are the {{name}} values the successful run extracted, shared with every caller that
	// joined this run and with the actions that follow a macro action in the same rule.
	//
	// Published from the winning attempt only. A gave-up run's values are the tokens of a login that
	// did not work, and handing them to an action that writes one into an outgoing request would send
	// a credential the target has already refused — the same reasoning recordObserved applies to
	// promoting a macro's steps.
	Values map[string]string
}

// MacroStepFailure names one macro step that produced no usable result — it could not be sent, or
// what came back cannot yield a value the macro needs. Carrying the step index lets an operator be
// told *which* part of the recorded flow drifted, which is exactly what "update macro" repairs.
type MacroStepFailure struct {
	StepIndex int
	Error     string
}

func (f *MacroStepFailure) String() string {
	if f == nil {
		return "<nil>"
	}
	return fmt.Sprintf("login macro step %d failed: %s", f.StepIndex, f.Error)
}

// RecoveryOutcomeKind is what handling one observed response produced.
type RecoveryOutcomeKind int

const (
	// RecoveryNoRuleApplies: no rule's scope covers the request's host; nothing was checked.
	RecoveryNoRuleApplies RecoveryOutcomeKind = iota
	// RecoveryAlreadyValid: the response already satisfied the rule's validity rule.
	RecoveryAlreadyValid
	// RecoveryRecovered: re-login succeeded and retrying the original request used a valid session.
	RecoveryRecovered
	// RecoveryStillInvalidAfterRelogin: re-login completed, but retrying the original is still
	// invalid by the operator's rule — e.g. the macro authenticates a different account.
	RecoveryStillInvalidAfterRelogin
	// RecoveryGaveUp: the macro ran `Attempts` times and never satisfied the validity rule.
	RecoveryGaveUp
	// RecoveryMacroFailed: the login macro itself could not be run to completion.
	RecoveryMacroFailed
	// RecoveryRetryFailed: re-login succeeded, but resending the original request failed to send.
	RecoveryRetryFailed
	// RecoveryRuleApplied: the rule's actions rewrote the request and it was re-sent; no login was
	// attempted. A kind of its own rather than a flavour of Recovered, because the two are different
	// facts an operator acts on differently: "a session was established" and "a header was set".
	// Validity carries the rule's own check of the answer when it states one, Indeterminate
	// otherwise — including for a rule whose actions never check, which has no verdict to report.
	RecoveryRuleApplied
	// RecoveryPromptDeclined: a "prompt for browser recovery" action ended without the session
	// being recovered — the operator declined, the prompt timed out, or no console was attached to
	// ask. The request was not sent. A kind of its own because the nearest existing one,
	// AlreadyValid, is the opposite of what happened: the operator was asked whether the session
	// is alive and the answer was no (or there was nobody to ask), which is not "the session was
	// already fine". The action's trace carries which of the three it was.
	RecoveryPromptDeclined
)

// RecoveryOutcome is what handling one observed response produced. Every variant is reachable and
// distinct on purpose, so a caller can act on each without parsing an error string.
type RecoveryOutcome struct {
	Kind          RecoveryOutcomeKind
	URL           string            // NoRuleApplies
	LoginAttempts int               // Recovered / StillInvalid / GaveUp / RetryFailed
	Validity      ValidityState     // StillInvalid / RuleApplied
	Response      *StepResult       // Recovered / StillInvalid / RuleApplied
	Attempt       int               // MacroFailed: 1-based attempt
	Failure       *MacroStepFailure // MacroFailed
	Error         string            // RetryFailed
	// Actions is what the rule's action list did, in the order it was reached — including the
	// actions that were skipped and why. Present on every outcome the walk produced, so an operator
	// can see that a rule whose macro failed also has a header action that did run, which is the
	// difference between a rule to fix and a rule to delete.
	Actions []ActionRan
}

// UpdateMacroOutcomeKind is what Coordinator.UpdateMacro did. An enum rather than a bool because
// the ways it can decline are different things for a caller to say to an operator.
type UpdateMacroOutcomeKind int

const (
	UpdateMacroUpdated UpdateMacroOutcomeKind = iota
	UpdateMacroNoSuchRule
	UpdateMacroNothingObserved
	UpdateMacroInvalid
)

// UpdateMacroOutcome reports what Coordinator.UpdateMacro did.
type UpdateMacroOutcome struct {
	Kind  UpdateMacroOutcomeKind
	Steps []MacroStep
	Error string
}

// ---- one login in flight per rule --------------------------------------------------------------
//
// Rust uses parking_lot's Mutex/Condvar with an explicit catch_unwind so a panicking sender
// degrades to one honestly-reported failed attempt rather than wedging every later re-login. Go's
// sync.Cond has the same shape, and the recover in ensureLoggedIn is the catch_unwind.
type loginRun struct {
	mu      sync.Mutex
	cv      *sync.Cond
	set     bool
	outcome LoginOutcome
}

func newLoginRun() *loginRun {
	r := &loginRun{}
	r.cv = sync.NewCond(&r.mu)
	return r
}

// publish stores the result and wakes every caller blocked in wait.
func (r *loginRun) publish(out LoginOutcome) {
	r.mu.Lock()
	r.outcome = out
	r.set = true
	r.cv.Broadcast()
	r.mu.Unlock()
}

// wait blocks until publish has been called, then returns its outcome.
func (r *loginRun) wait() LoginOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	for !r.set {
		r.cv.Wait()
	}
	return r.outcome
}

// ensureLoggedIn is single-flight per rule: the first caller to arrive while no login for `id` is
// running installs a fresh loginRun and becomes its leader, actually sending. Everyone who arrives
// for the same rule while that run is registered blocks in wait instead of starting one of its own,
// which is "N concurrent observers, one login" without any request beyond the first ever reaching
// the runner.
// validity is the condition an attempt must satisfy to count as a successful login. It is a
// parameter rather than always `rule.Validity` because a rule's actions can nest a macro under a
// validity check that states its own condition (Burp's "perform sub-actions conditionally on the
// result"): satisfying the rule's rule there would report success for a check nobody ran.
func (c *Coordinator) ensureLoggedIn(id RuleID, rule *SessionRule, runner MacroStepRunner, validity *ValidityRule) LoginOutcome {
	c.runsMu.Lock()
	run, alreadyRunning := c.runs[id]
	if !alreadyRunning {
		run = newLoginRun()
		c.runs[id] = run
	}
	c.runsMu.Unlock()

	if alreadyRunning {
		// Someone else's login for this rule is in flight; share its result instead of
		// piling a second one onto the target.
		return run.wait()
	}

	// Isolated so a runner that panics instead of returning an error still yields one honestly
	// reported MacroFailed rather than leaving every follower blocked forever.
	outcome := func() (out LoginOutcome) {
		defer func() {
			if r := recover(); r != nil {
				out = LoginOutcome{
					Kind:    LoginMacroFailed,
					Attempt: 0,
					Failure: &MacroStepFailure{StepIndex: 0, Error: fmt.Sprintf("login macro panicked: %v", r)},
				}
			}
		}()
		return c.runWithRetries(id, rule, runner, validity)
	}()

	run.publish(outcome)
	// Clear the run so the *next* session drop starts a fresh attempt instead of replaying this
	// one forever. Guarded by identity so a future mutator of `runs` fails loudly rather than
	// clobbering a run it did not start.
	c.runsMu.Lock()
	if cur, present := c.runs[id]; present && cur == run {
		delete(c.runs, id)
	}
	c.runsMu.Unlock()
	return outcome
}

func (c *Coordinator) runWithRetries(id RuleID, rule *SessionRule, runner MacroStepRunner, validity *ValidityRule) LoginOutcome {
	for attempt := 1; attempt <= c.maxAttempts(rule); attempt++ {
		resp, sent, values, failure := c.runMacroOnce(rule, runner)
		if failure != nil {
			return LoginOutcome{Kind: LoginMacroFailed, Attempt: attempt, Failure: failure}
		}
		if validity == nil || validity.Evaluate(resp.Status, resp.Headers, resp.Body, resp.FinalURL) == Valid {
			// Only a successful run is promoted; a failed run must never overwrite a working macro.
			c.recordObserved(id, sent)
			return LoginOutcome{Kind: LoginSucceeded, Attempts: attempt, Values: values}
		}
		// The macro completed but its own response says we still are not authenticated. Loop
		// again, bounded by max_attempts.
	}
	return LoginOutcome{Kind: LoginGaveUp, Attempts: c.maxAttempts(rule)}
}

func (c *Coordinator) maxAttempts(rule *SessionRule) int {
	if rule != nil && rule.MaxAttempts >= 1 {
		return rule.MaxAttempts
	}
	return DefaultMaxAttempts
}

// runMacroOnce runs every step in order, threading extracted values forward, and returns the final
// response together with the requests actually produced (untemplated back to their placeholders).
//
// The value map starts empty on every attempt: a token scraped during a login that did not work is
// stale by the time the next attempt sends it, and reusing it would make attempt 2 a replay of
// attempt 1's mistake rather than a fresh try.
//
// Unlike the web-facing RunMacro, this is the strict recovery path: a step that cannot be sent ends
// the attempt with a MacroStepFailure rather than a nil sentinel row.
// The fourth return value is the extraction map the run built, handed back so an action *after* a
// macro action can write one of those values into the request — the second half of the CSRF recipe,
// which is the reason this whole unit exists. It is returned on the failure paths as nil: a
// half-built map from an attempt that never completed its steps names values whose provenance the
// caller cannot verify.
func (c *Coordinator) runMacroOnce(rule *SessionRule, runner MacroStepRunner) (*StepResult, []MacroStep, map[string]string, *MacroStepFailure) {
	if rule == nil || len(rule.Steps) == 0 {
		return nil, nil, nil, &MacroStepFailure{StepIndex: 0, Error: "login macro has no steps to run"}
	}
	values := make(map[string]string)
	sent := make([]MacroStep, 0, len(rule.Steps))
	var last *StepResult
	for stepIndex, step := range rule.Steps {
		// Resolved immediately before the send, so a step sees every value the steps before it
		// produced and none that do not exist yet.
		resolved := resolveStep(step, values)
		resp, err := c.sendWithJar(runner, resolved)
		if err != nil {
			return nil, nil, nil, &MacroStepFailure{StepIndex: stepIndex, Error: err.Error()}
		}
		// Recorded with this run's extracted values turned back into their placeholders, so
		// promoting it later reinstates a template rather than a one-time secret.
		sent = append(sent, untemplateStep(resolved, values))
		// Run this step's own extractions against its response so later steps can use the values.
		if resp.Status >= 200 && resp.Status < 400 {
			for _, ex := range rule.extractionsFor(stepIndex) {
				out := ex.RunResult(resp.Headers, resp.Body)
				c.logExtraction(rule, stepIndex, ex, out)
				// A value that did not resolve leaves its {{name}} in the step verbatim rather than being
				// substituted with "", which is the existing behaviour and the more debuggable of the two:
				// a login that sent a literal "{{csrf}}" says what went wrong in the request itself, where
				// one that sent an empty parameter looks like the application rejecting a real attempt.
				// logExtraction is what makes the reason available without reading the wire.
				if out.Outcome.Resolved() && out.Value != "" {
					values[ex.Name] = out.Value
				}
			}
		}
		last = resp
	}
	return last, sent, values, nil
}

// sendWithJar sends `step` with the jar's current cookie for its host attached, then absorbs any
// Set-Cookie headers the response carries back into the jar. Used for both a macro's own steps and
// the retried original request, which is how a session cookie a login step sets reaches the request
// that needed it.
func (c *Coordinator) sendWithJar(runner MacroStepRunner, step MacroStep) (*StepResult, error) {
	return c.sendWithJarAnd(runner, step, nil)
}

// sendWithJarAnd is sendWithJar carrying the cookies a rule's set_cookie actions named. See
// applyJarWith for why they have to travel this far rather than being written into the request's
// headers by the action itself.
func (c *Coordinator) sendWithJarAnd(runner MacroStepRunner, step MacroStep, overrides []CookieOverride) (*StepResult, error) {
	effective := c.applyJarWith(step, overrides)
	resp, err := runner(effective)
	if err != nil {
		return nil, err
	}
	host, port, tls := authorityOf(step.URL)
	c.absorb.attach(SourceMacro)
	c.absorb.responses.Add(1)
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Set-Cookie") {
			c.jarMgr.AbsorbSetCookie(host, port, tls, v)
			c.absorb.cookies.Add(1)
		}
	}
	return resp, nil
}

// applyJar returns a copy of `step` with any hardcoded Cookie header replaced by the jar's current
// one for its host. The jar is the single source of truth for session state across steps, so a
// recorded step's own Cookie header (stale the moment it was captured) never reaches the wire.
func (c *Coordinator) applyJar(step MacroStep) MacroStep {
	return c.applyJarWith(step, nil)
}

// applyJarWith is applyJar plus the cookies a rule's Set-a-specific-cookie actions named, overlaid on
// top of the jar's.
//
// The overlay exists because the two cookies are not the same kind of fact and the jar-wins rule
// above is right for only one of them. A recorded macro step's Cookie header is a stale capture, so
// discarding it is correct. A set_cookie action is the operator stating, now, that this request
// carries this cookie — and it was being discarded by the same line. The action wrote the header, the
// trace said "set cookie flavour=oatmeal", and applyJar deleted it on the way to the wire: an action
// that reported success and did nothing, which is the one outcome this package refuses to produce.
// Verified against a live target before and after; the received Cookie header went from
// `sid=sess-abc123` to `sid=sess-abc123; flavour=oatmeal`.
//
// Overlaid rather than replacing wholesale, and applied after the jar, so a rule can both carry its
// session and override one named cookie within it — which is what Burp's action does. A cookie the
// operator named wins over the jar's value for the same name, because the operator naming it is the
// later and more specific statement.
func (c *Coordinator) applyJarWith(step MacroStep, overrides []CookieOverride) MacroStep {
	if len(step.Headers) > 0 {
		filtered := make(map[string]string, len(step.Headers))
		for k, v := range step.Headers {
			if strings.EqualFold(k, "Cookie") {
				continue
			}
			filtered[k] = v
		}
		step.Headers = filtered
	}
	host, port, tls := authorityOf(step.URL)
	// The step's own path, so the jar's §5.4 path-match decides which cookies this step
	// actually carries — the same rule the wire applies, rather than every cookie the
	// authority ever set.
	cookie := c.jarMgr.CookieHeader(host, port, tls, pathOf(step.URL))
	for _, o := range overrides {
		cookie = setCookiePair(cookie, o.Name, o.Value)
	}
	if cookie != "" {
		if step.Headers == nil {
			step.Headers = make(map[string]string)
		}
		step.Headers["Cookie"] = cookie
	}
	return step
}

// CookieOverride is one cookie a rule's set_cookie action named, carried from the action walk to the
// send so the jar cannot erase it. Name and value are already placeholder-substituted.
type CookieOverride struct {
	Name  string
	Value string
}

func (c *Coordinator) recordObserved(id RuleID, sent []MacroStep) {
	c.observedMu.Lock()
	c.observed[id] = append([]MacroStep(nil), sent...)
	c.observedMu.Unlock()
}

// --- public recovery API ------------------------------------------------------

// HandleRecovery evaluates `response` against the validity rule of whichever rule owns `original`'s
// URL and, if it is not valid (or the rule could not tell), recovers: run that rule's login macro
// (once, or share an already-running one) and retry `original` with the freshly-authenticated jar.
//
// The rule lookup uses the step's full URL identity, not its host (7nh2), plus the tool that made it
// (so3): a rule scoped to a path, port or scheme would otherwise claim a step outside its own stated
// scope and fire a login macro at an endpoint the operator excluded in the rule editor, and a rule
// restricted to the crawler would fire for traffic the operator deliberately kept it away from — the
// re-login rule that corrupts an Intruder attack fuzzing the session cookie is exactly this case.
//
// Anything other than Valid — including Indeterminate — takes the recovery path, matching the Rust
// crate's refusal to treat "the rule could not tell" as fail-open.
// `tool` names the tool that made the original request, in toollog's vocabulary, or "" when the
// caller cannot attribute it — see RequestIdentity.Tool for why an unattributed request still
// matches a tool-restricted rule, and MatchTools for the direction that reading protects.
//
// It is a parameter rather than something derived from `original` because a MacroStep cannot
// support it: a step carries a method, a URL and headers, and nothing in it says which tool sent
// it. A recovery path that guessed the tool would be inventing the one fact the tools scope exists
// to constrain (so3), and the guess would be invisible — the rule would simply fire, or not, for a
// reason no row in the log records.
func (c *Coordinator) HandleRecovery(tool string, original MacroStep, response *StepResult, runner MacroStepRunner) RecoveryOutcome {
	identity := identityOf(original.URL)
	identity.Tool = tool
	id, rule := c.matchingRuleID(identity)
	if rule == nil {
		return RecoveryOutcome{Kind: RecoveryNoRuleApplies, URL: original.URL}
	}
	out := c.recover(id, rule, original, response, runner)
	// The session-handling tracer (burpsy-react-ui-n29) records the handled request: this is
	// Burp's "every request where at least one session rule has been applied", and the
	// entry rides the outcome's own action walk. recordTrace is a no-op while the tracer is
	// off — one atomic load, nothing else, on this per-response path.
	c.recordTrace(tool, original, id, rule, out)
	return out
}

// EnsureLoggedIn is the public single-flight re-login for a rule: it runs the rule's macro (once,
// or joins an in-flight run) and returns the outcome, without wrapping a retried original request.
func (c *Coordinator) EnsureLoggedIn(rule *SessionRule, runner MacroStepRunner) LoginOutcome {
	if rule == nil {
		return LoginOutcome{Kind: LoginGaveUp, Attempts: 0}
	}
	id := c.ruleIDOf(rule)
	return c.ensureLoggedIn(id, rule, runner, rule.Validity)
}

// matchingRuleID returns the id and rule of the first enabled rule whose URL scope covers `req`.
//
// It runs the same scan MatchingRuleForRequest does, under its own read lock, because the match
// happens inside the package and the coordinator's lock is not reentrant. Sharing matchRequestLocked
// is what keeps the two lookups from drifting apart — a rule that MatchingRuleForRequest would skip
// cannot be the one recovery picks.
func (c *Coordinator) matchingRuleID(req RequestIdentity) (RuleID, *SessionRule) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, id := range c.order {
		r := c.rules[id]
		if r == nil || !r.Enabled {
			continue
		}
		if r.MatchRequest(req, c.suitePredicateLocked(req)) {
			return id, r
		}
	}
	return 0, nil
}

// ruleIDOf returns the id currently held for `rule`, or 0 if it is not a registered rule. Used so
// recovery can address a rule by identity in the single-flight map.
func (c *Coordinator) ruleIDOf(rule *SessionRule) RuleID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for id, r := range c.rules {
		if r == rule {
			return id
		}
	}
	return 0
}

// recover runs the rule's action list over the request and reports what came of it.
//
// # What changed when actions arrived, and what did not
//
// The pre-action flow was two hardcoded steps — evaluate validity, and if it is not Valid run the
// macro to term — plus a resend of the original request when the macro succeeded. That flow is now
// the *synthesised* action list (see EffectiveActions: a validity check whose Else branch runs the
// macro), which is why every outcome below still means what it always meant for a rule nobody has
// edited: a rule with a validity rule and a macro produces AlreadyValid, Recovered,
// StillInvalidAfterRelogin, GaveUp or MacroFailed exactly as before.
//
// Three things the walk adds:
//
//   - Actions other than the login run at all. A rule can set a header, add the jar's cookies, set a
//     parameter from a value a macro extracted, or rewrite part of the request — in the order the
//     operator put them, with a macro anywhere in that order.
//   - A request the actions changed is re-sent, and that resend is reported as RecoveryRuleApplied
//     rather than as a recovery: no login was attempted, and saying "recovered" would tell an
//     operator that a session was established when what happened is that a header was set.
//   - A failed macro ends the walk, because there is no session to handle and continuing would send
//     a request the rule has just been told cannot be authenticated.
func (c *Coordinator) recover(id RuleID, rule *SessionRule, original MacroStep, response *StepResult, runner MacroStepRunner) RecoveryOutcome {
	res := c.runActions(rule, original, response, runner)

	if res.MacroRan {
		switch res.MacroOutcome.Kind {
		case LoginMacroFailed:
			return RecoveryOutcome{
				Kind:    RecoveryMacroFailed,
				Attempt: res.MacroOutcome.Attempt, Failure: res.MacroOutcome.Failure, Actions: res.Trace,
			}
		case LoginGaveUp:
			return RecoveryOutcome{
				Kind: RecoveryGaveUp, LoginAttempts: res.MacroOutcome.Attempts, Actions: res.Trace,
			}
		}
	}

	// Two reasons to re-send, and the second is not the first: a macro that succeeded left the bytes
	// identical and changed the *jar*, and the retried request has to carry the new cookies or the
	// login was performed for nothing. The pre-action flow resent on a successful login for exactly
	// this reason, so leaving the jar out here would silently break every re-login.
	macroSucceeded := res.MacroRan && res.MacroOutcome.Kind == LoginSucceeded
	// A prompt that ended without recovery stops the walk before anything is sent, and is reported
	// here rather than falling into AlreadyValid below: "the session was already fine" is precisely
	// the opposite of what happened — the operator was asked whether it is, and the answer was no,
	// or there was nobody to ask. The request is not re-sent, which is the action working as written.
	if res.PromptDeclined {
		return RecoveryOutcome{Kind: RecoveryPromptDeclined, Actions: res.Trace}
	}
	// A successful prompt is a third reason to re-send, alongside a changed request and a successful
	// macro: the bytes are identical but the session is not, and the resend is the entire point of
	// having asked. Without this a prompt-only rule would report AlreadyValid and drop the request
	// the operator was asked to recover the session for.
	if !res.Changed && !macroSucceeded && !res.PromptSucceeded {
		return RecoveryOutcome{Kind: RecoveryAlreadyValid, Actions: res.Trace}
	}

	// res.CookieOverrides, not just res.Request: the walk wrote its set_cookie values into the
	// request's Cookie header, and applyJar is about to drop that header on the floor. Carrying them
	// separately is what makes the action real on the wire rather than only in the trace.
	resp, err := c.sendWithJarAnd(runner, res.Request, res.CookieOverrides)
	if err != nil {
		return RecoveryOutcome{Kind: RecoveryRetryFailed, LoginAttempts: res.MacroOutcome.Attempts,
			Error: err.Error(), Actions: res.Trace}
	}

	// Only when the rule states a check. A rule whose actions never look at validity has no verdict
	// to report, and inventing a Valid one would tell an operator the session is alive on the
	// strength of a check the rule does not make.
	verdict := Indeterminate
	if rule.Validity != nil {
		verdict = rule.Validity.Evaluate(resp.Status, resp.Headers, resp.Body, resp.FinalURL)
	}
	switch {
	case macroSucceeded && (rule.Validity == nil || verdict == Valid):
		return RecoveryOutcome{Kind: RecoveryRecovered, LoginAttempts: res.MacroOutcome.Attempts,
			Response: resp, Actions: res.Trace}
	case macroSucceeded:
		return RecoveryOutcome{Kind: RecoveryStillInvalidAfterRelogin, LoginAttempts: res.MacroOutcome.Attempts,
			Validity: verdict, Response: resp, Actions: res.Trace}
	default:
		// The actions rewrote the request and no login was attempted, so this is not a recovery and
		// the validity field only says what the rule's own check made of the answer — which the
		// caller renders as such.
		return RecoveryOutcome{Kind: RecoveryRuleApplied, Validity: verdict, Response: resp, Actions: res.Trace}
	}
}

// UpdateMacro overwrites a rule's recorded steps with the requests its last *successful* login
// actually sent — Burp's "update macro" action. Promoting the last successful run only means this
// can never replace a working macro with the steps of one that failed.
func (c *Coordinator) UpdateMacro(id RuleID) UpdateMacroOutcome {
	rule := c.Rule(id)
	if rule == nil {
		return UpdateMacroOutcome{Kind: UpdateMacroNoSuchRule}
	}
	c.observedMu.Lock()
	sent, ok := c.observed[id]
	c.observedMu.Unlock()
	if !ok {
		return UpdateMacroOutcome{Kind: UpdateMacroNothingObserved}
	}
	steps := append([]MacroStep(nil), sent...)
	updated := *rule
	updated.Steps = steps
	// Reachable rather than defensive, which is why UpdateMacroInvalid exists: a run that sent fewer
	// steps than the rule stores (a step skipped for being out of scope) would leave an extraction
	// naming a step that no longer exists. Rust refuses the same case in `SessionRule::with_steps` —
	// "extractions belong to a step by position" — because silently dropping what a vanished step
	// extracted is how a macro comes back looking repaired and still unable to log in.
	if err := c.UpdateRule(id, &updated); err != nil {
		return UpdateMacroOutcome{Kind: UpdateMacroInvalid, Error: err.Error()}
	}
	return UpdateMacroOutcome{Kind: UpdateMacroUpdated, Steps: steps}
}

// --- substitution (sorted and deterministic; inverse for "update macro") ------------------------

// resolveStep returns `step` with every {{name}} replaced by its extracted value, applied to the
// URL, header names and values, and body. Names are visited in sorted order so the result is
// identical across runs whatever the map's iteration order happened to be.
func resolveStep(step MacroStep, values map[string]string) MacroStep {
	if len(values) == 0 {
		return step
	}
	step.URL = resolveAll(step.URL, values)
	step.Body = resolveAll(step.Body, values)
	if len(step.Headers) > 0 {
		h := make(map[string]string, len(step.Headers))
		for k, v := range step.Headers {
			h[resolveAll(k, values)] = resolveAll(v, values)
		}
		step.Headers = h
	}
	return step
}

func resolveAll(s string, values map[string]string) string {
	for _, name := range sortedNames(values) {
		s = strings.ReplaceAll(s, "{{"+name+"}}", values[name])
	}
	return s
}

func sortedNames(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for k := range values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// untemplateStep is the inverse of resolveStep: every extracted value is written back as its
// {{name}}. This is what makes "update macro" safe — overwriting a stored step with the request
// that was actually sent would bake in the one-time token this run extracted, and the *next* run
// would replay a stale token, turning a repair into a breakage. Longest value first, so a value
// that contains another is restored whole rather than having its own substring tokenised out from
// under it.
func untemplateStep(step MacroStep, values map[string]string) MacroStep {
	if len(values) == 0 {
		return step
	}
	var pairs []stringPair
	for n, v := range values {
		if v != "" {
			pairs = append(pairs, stringPair{n, v})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].v) != len(pairs[j].v) {
			return len(pairs[i].v) > len(pairs[j].v)
		}
		return pairs[i].n < pairs[j].n
	})
	for _, p := range pairs {
		token := "{{" + p.n + "}}"
		step.URL = strings.ReplaceAll(step.URL, p.v, token)
		step.Body = strings.ReplaceAll(step.Body, p.v, token)
		if len(step.Headers) > 0 {
			h := make(map[string]string, len(step.Headers))
			for k, v := range step.Headers {
				h[strings.ReplaceAll(k, p.v, token)] = strings.ReplaceAll(v, p.v, token)
			}
			step.Headers = h
		}
	}
	return step
}

type stringPair struct {
	n string
	v string
}
