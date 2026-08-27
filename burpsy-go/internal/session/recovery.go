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
)

// RecoveryOutcome is what handling one observed response produced. Every variant is reachable and
// distinct on purpose, so a caller can act on each without parsing an error string.
type RecoveryOutcome struct {
	Kind          RecoveryOutcomeKind
	URL           string            // NoRuleApplies
	LoginAttempts int               // Recovered / StillInvalid / GaveUp / RetryFailed
	Validity      ValidityState     // StillInvalid
	Response      *StepResult       // Recovered / StillInvalid
	Attempt       int               // MacroFailed: 1-based attempt
	Failure       *MacroStepFailure // MacroFailed
	Error         string            // RetryFailed
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
func (c *Coordinator) ensureLoggedIn(id RuleID, rule *SessionRule, runner MacroStepRunner) LoginOutcome {
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
		return c.runWithRetries(id, rule, runner)
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

func (c *Coordinator) runWithRetries(id RuleID, rule *SessionRule, runner MacroStepRunner) LoginOutcome {
	for attempt := 1; attempt <= c.maxAttempts(rule); attempt++ {
		resp, sent, failure := c.runMacroOnce(rule, runner)
		if failure != nil {
			return LoginOutcome{Kind: LoginMacroFailed, Attempt: attempt, Failure: failure}
		}
		if rule.Validity == nil || rule.Validity.Evaluate(resp.Status, resp.Headers, resp.Body) == Valid {
			// Only a successful run is promoted; a failed run must never overwrite a working macro.
			c.recordObserved(id, sent)
			return LoginOutcome{Kind: LoginSucceeded, Attempts: attempt}
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
func (c *Coordinator) runMacroOnce(rule *SessionRule, runner MacroStepRunner) (*StepResult, []MacroStep, *MacroStepFailure) {
	if rule == nil || len(rule.Steps) == 0 {
		return nil, nil, &MacroStepFailure{StepIndex: 0, Error: "login macro has no steps to run"}
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
			return nil, nil, &MacroStepFailure{StepIndex: stepIndex, Error: err.Error()}
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
	return last, sent, nil
}

// sendWithJar sends `step` with the jar's current cookie for its host attached, then absorbs any
// Set-Cookie headers the response carries back into the jar. Used for both a macro's own steps and
// the retried original request, which is how a session cookie a login step sets reaches the request
// that needed it.
func (c *Coordinator) sendWithJar(runner MacroStepRunner, step MacroStep) (*StepResult, error) {
	effective := c.applyJar(step)
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
	if cookie := c.jarMgr.CookieHeader(host, port, tls); cookie != "" {
		if step.Headers == nil {
			step.Headers = make(map[string]string)
		}
		step.Headers["Cookie"] = cookie
	}
	return step
}

func (c *Coordinator) recordObserved(id RuleID, sent []MacroStep) {
	c.observedMu.Lock()
	c.observed[id] = append([]MacroStep(nil), sent...)
	c.observedMu.Unlock()
}

// --- public recovery API ------------------------------------------------------

// HandleRecovery evaluates `response` against the validity rule of whichever rule owns `original`'s
// host and, if it is not valid (or the rule could not tell), recovers: run that rule's login macro
// (once, or share an already-running one) and retry `original` with the freshly-authenticated jar.
//
// Anything other than Valid — including Indeterminate — takes the recovery path, matching the Rust
// crate's refusal to treat "the rule could not tell" as fail-open.
func (c *Coordinator) HandleRecovery(original MacroStep, response *StepResult, runner MacroStepRunner) RecoveryOutcome {
	id, rule := c.matchingRuleID(hostOf(original.URL))
	if rule == nil {
		return RecoveryOutcome{Kind: RecoveryNoRuleApplies, URL: original.URL}
	}
	if response != nil && rule.Validity != nil && rule.Validity.Evaluate(response.Status, response.Headers, response.Body) == Valid {
		return RecoveryOutcome{Kind: RecoveryAlreadyValid}
	}
	return c.recover(id, rule, original, runner)
}

// EnsureLoggedIn is the public single-flight re-login for a rule: it runs the rule's macro (once,
// or joins an in-flight run) and returns the outcome, without wrapping a retried original request.
func (c *Coordinator) EnsureLoggedIn(rule *SessionRule, runner MacroStepRunner) LoginOutcome {
	if rule == nil {
		return LoginOutcome{Kind: LoginGaveUp, Attempts: 0}
	}
	id := c.ruleIDOf(rule)
	return c.ensureLoggedIn(id, rule, runner)
}

// matchingRuleID returns the id and rule of the first enabled rule whose scope covers `host`.
func (c *Coordinator) matchingRuleID(host string) (RuleID, *SessionRule) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, id := range c.order {
		r := c.rules[id]
		if r.Enabled && r.MatchHost(host) {
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

func (c *Coordinator) recover(id RuleID, rule *SessionRule, original MacroStep, runner MacroStepRunner) RecoveryOutcome {
	outcome := c.ensureLoggedIn(id, rule, runner)
	switch outcome.Kind {
	case LoginSucceeded:
		resp, err := c.sendWithJar(runner, original)
		if err != nil {
			return RecoveryOutcome{Kind: RecoveryRetryFailed, LoginAttempts: outcome.Attempts, Error: err.Error()}
		}
		if rule.Validity == nil || rule.Validity.Evaluate(resp.Status, resp.Headers, resp.Body) == Valid {
			return RecoveryOutcome{Kind: RecoveryRecovered, LoginAttempts: outcome.Attempts, Response: resp}
		}
		return RecoveryOutcome{
			Kind:          RecoveryStillInvalidAfterRelogin,
			LoginAttempts: outcome.Attempts,
			Validity:      rule.Validity.Evaluate(resp.Status, resp.Headers, resp.Body),
			Response:      resp,
		}
	case LoginGaveUp:
		return RecoveryOutcome{Kind: RecoveryGaveUp, LoginAttempts: outcome.Attempts}
	case LoginMacroFailed:
		return RecoveryOutcome{Kind: RecoveryMacroFailed, Attempt: outcome.Attempt, Failure: outcome.Failure}
	}
	return RecoveryOutcome{Kind: RecoveryGaveUp}
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
