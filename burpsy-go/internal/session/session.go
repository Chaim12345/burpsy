// Package session implements session handling rules for authenticated scanning.
package session

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// ---- Validity -----

type ValidityState int

const (
	Valid ValidityState = iota
	Invalid
	Indeterminate
)

type ValidityRule struct {
	StatusIs        *int            `json:"status_is,omitempty"`
	BodyContains    string          `json:"body_contains,omitempty"`
	BodyNotContains string          `json:"body_not_contains,omitempty"`
	HeaderPresent   string          `json:"header_present,omitempty"`
	HeaderAbsent    string          `json:"header_absent,omitempty"`
	All             []*ValidityRule `json:"all,omitempty"`
	Any             []*ValidityRule `json:"any,omitempty"`
	Not             *ValidityRule   `json:"not,omitempty"`
}

func (vr *ValidityRule) Evaluate(status int, hdrs map[string]string, body []byte) ValidityState {
	if vr == nil {
		return Indeterminate
	}
	if vr.StatusIs != nil {
		if status == 0 {
			return Indeterminate
		}
		if status == *vr.StatusIs {
			return Valid
		}
		return Invalid
	}
	if vr.BodyContains != "" {
		if bytes.Contains(body, []byte(vr.BodyContains)) {
			return Valid
		}
		return Invalid
	}
	if vr.BodyNotContains != "" {
		if bytes.Contains(body, []byte(vr.BodyNotContains)) {
			return Invalid
		}
		return Valid
	}
	if vr.HeaderPresent != "" {
		for k := range hdrs {
			if strings.EqualFold(k, vr.HeaderPresent) {
				return Valid
			}
		}
		return Invalid
	}
	if vr.HeaderAbsent != "" {
		for k := range hdrs {
			if strings.EqualFold(k, vr.HeaderAbsent) {
				return Invalid
			}
		}
		return Valid
	}
	if vr.All != nil {
		allV := true
		for _, s := range vr.All {
			r := s.Evaluate(status, hdrs, body)
			if r == Invalid {
				return Invalid
			}
			if r == Indeterminate {
				allV = false
			}
		}
		if allV {
			return Valid
		}
		return Indeterminate
	}
	if vr.Any != nil {
		best := Invalid
		for _, s := range vr.Any {
			r := s.Evaluate(status, hdrs, body)
			if r == Valid {
				return Valid
			}
			if r == Indeterminate {
				best = Indeterminate
			}
		}
		return best
	}
	if vr.Not != nil {
		r := vr.Not.Evaluate(status, hdrs, body)
		if r == Valid {
			return Invalid
		}
		if r == Indeterminate {
			return Indeterminate
		}
		return Valid
	}
	return Indeterminate
}

// --- Extraction ---

// Extraction lifts one value out of a macro step's response so a *later* step can refer to it as
// {{name}} — the CSRF token a login form hands out, a bearer token a token endpoint returns.
//
// Rust keeps each extraction inside the `MacroItem` whose response produces it
// (crates/session/src/rule.rs) and deliberately keeps extractions *out* of `MacroStep`, because
// `MacroStep` is also the type of the request being repaired and of the probe /api/session/login
// hands in — neither of which has anything to extract. This port keeps `MacroStep` wire-shaped for
// the same reason and holds a rule's extractions in one flat list, so the owning step has to be
// named here instead: `Step` is the index of the macro step whose response this reads. Without it
// there would be no way to answer "which response does this value come from", which is exactly what
// config-time validation needs in order to refuse a step referring to a value no earlier step
// produces (see validate.go).
type Extraction struct {
	Name string `json:"name"`
	// From is "body" or "header"; anything else extracts nothing, which ValidateRule refuses rather
	// than letting a rule run with a placeholder that can never resolve.
	From string `json:"from"`
	// Header is the response header to read when From is "header". Empty means Pattern doubles as
	// the header *selector* as well as the value matcher — the behaviour this port had before the
	// name could be carried, kept working because a saved rule may still rely on it.
	Header  string `json:"header,omitempty"`
	Pattern string `json:"pattern"`
	Group   int    `json:"group"`
	// Step is the index of the macro step whose response this reads. Zero — the first step — is the
	// common case and the value a rule stored before this field existed restores as.
	Step int `json:"step"`
	re   *regexp.Regexp
}

func NewExtraction(name, from, pattern string, group int) (*Extraction, error) {
	e := &Extraction{Name: name, From: from, Pattern: pattern, Group: group}
	if err := e.Recompile(); err != nil {
		return nil, err
	}
	return e, nil
}

// Recompile rebuilds the matcher that an Extraction restored from storage cannot carry — a compiled
// regexp is not serialisable, so unmarshalling one leaves it inert and silently extracting nothing.
//
// Storage restores an extraction by unmarshalling it and calling this, rather than by feeding the
// handful of fields it happens to know about back through NewExtraction: a field added to this
// struct later would otherwise be dropped on every load, which is precisely how a rule comes back
// "restored" and unable to log in.
func (e *Extraction) Recompile() error {
	if e == nil {
		return nil
	}
	re, err := regexp.Compile(e.Pattern)
	if err != nil {
		return err
	}
	e.re = re
	return nil
}

func (e *Extraction) Run(hdrs map[string]string, body []byte) string {
	if e == nil || e.re == nil {
		return ""
	}
	switch e.From {
	case "body":
		m := e.re.FindSubmatch(body)
		if m != nil && e.Group < len(m) {
			return string(m[e.Group])
		}
	case "header":
		for k, v := range hdrs {
			// A named header is selected by its name, and the pattern is applied only to its value.
			// With no name stated the pattern selects the header too, which is what this port did
			// before an extraction could carry the name.
			if e.Header != "" {
				if !strings.EqualFold(k, e.Header) {
					continue
				}
			} else if !e.re.MatchString(k) {
				continue
			}
			m := e.re.FindStringSubmatch(v)
			if m != nil && e.Group < len(m) {
				return m[e.Group]
			}
		}
	}
	return ""
}

// --- MacroStep ---

type MacroStep struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// --- CookieJar ---

type cookieJar struct {
	sync.RWMutex
	m map[string]string
}

func newCookieJar() *cookieJar { return &cookieJar{m: make(map[string]string)} }

func (j *cookieJar) cookieHeader() string {
	j.RLock()
	defer j.RUnlock()
	if len(j.m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(j.m))
	for k := range j.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+j.m[k])
	}
	return strings.Join(parts, "; ")
}

func (j *cookieJar) absorb(val string) {
	j.Lock()
	defer j.Unlock()
	for _, chunk := range strings.Split(val, ";") {
		chunk = strings.TrimSpace(chunk)
		if idx := strings.IndexByte(chunk, '='); idx >= 0 {
			j.m[strings.TrimSpace(chunk[:idx])] = strings.TrimSpace(chunk[idx+1:])
		}
	}
}

type CookieJarManager struct {
	mu   sync.RWMutex
	jars map[string]*cookieJar
}

func NewCookieJarManager() *CookieJarManager {
	return &CookieJarManager{jars: make(map[string]*cookieJar)}
}

func (cjm *CookieJarManager) CookieHeader(host string, port uint16, tls bool) string {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.RLock()
	jar := cjm.jars[key]
	cjm.mu.RUnlock()
	if jar == nil {
		return ""
	}
	return jar.cookieHeader()
}

func (cjm *CookieJarManager) AbsorbSetCookie(host string, port uint16, tls bool, val string) {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.Lock()
	jar := cjm.jars[key]
	if jar == nil {
		jar = newCookieJar()
		cjm.jars[key] = jar
	}
	cjm.mu.Unlock()
	jar.absorb(val)
}

// --- SessionRule ---

type RuleID int64

const DefaultMaxAttempts = 3

type SessionRule struct {
	ID          RuleID        `json:"id"`
	Name        string        `json:"name"`
	Enabled     bool          `json:"enabled"`
	ScopeHosts  []string      `json:"scope_hosts"`
	Steps       []MacroStep   `json:"macro"`
	Validity    *ValidityRule `json:"validity"`
	MaxAttempts int           `json:"max_attempts"`
	Extractions []*Extraction `json:"extractions"`
}

// MatchHost says whether this rule's scope covers `host`.
//
// A rule with no scope hosts applies **everywhere**. That is Rust's model — `SessionRuleSpec::scope`
// is an `Option<Scope>` whose `None` arm means "applies everywhere" (crates/session/src/rule.rs,
// `applies_to`) — and it is the only reading under which the common case works at all: a rule created
// without a scope restriction ends up with no hosts, so answering `false` for it made every such
// rule dead on arrival — enabled, listed in the UI, and unable to match a single host. That is the
// worst kind of failure for a session rule to have, because nothing reports it: requests simply keep
// going out unauthenticated.
//
// An explicitly *stated* but empty scope is a different thing and is refused at configuration time
// instead (see ValidateRuleStatedScope): saying "restrict this rule to nothing" is a mistake worth
// naming, while omitting the restriction is not.
func (r *SessionRule) MatchHost(host string) bool {
	if r == nil {
		return false
	}
	if len(r.ScopeHosts) == 0 {
		return true
	}
	for _, h := range r.ScopeHosts {
		if host == h {
			return true
		}
	}
	return false
}

// extractionsFor returns the extractions that read step `index`'s response.
//
// An extraction runs against its own step's response and no other, matching Rust's per-`MacroItem`
// extraction list. Running every extraction against every response instead would let a pattern
// meant for the token endpoint fire on the login form's response, so which value a {{name}} carried
// would depend on which response happened to match first — and the config-time rule that a
// reference must be produced by an *earlier* step would be enforcing an order the runner ignored.
func (r *SessionRule) extractionsFor(index int) []*Extraction {
	if r == nil || len(r.Extractions) == 0 {
		return nil
	}
	var out []*Extraction
	for _, ex := range r.Extractions {
		if ex != nil && ex.Step == index {
			out = append(out, ex)
		}
	}
	return out
}

// NewSessionRule builds the inert form of a rule: holding one proves nothing has been checked, the
// same way Rust's `SessionRuleSpec` is separate from the validated `SessionRule`. Deliberately
// permissive, because a caller assembling a rule field by field (the CLI, a DTO conversion) needs to
// finish assembling before anything can be judged. ValidateRule is where every mistake that can be
// caught without a network is caught, and Coordinator.AddRule / UpdateRule run it so no rule can be
// installed behind validation's back.
func NewSessionRule(name string, hosts []string, steps []MacroStep) *SessionRule {
	if steps == nil {
		steps = make([]MacroStep, 0)
	}
	return &SessionRule{
		Name: name, Enabled: true,
		ScopeHosts: hosts, Steps: steps, MaxAttempts: DefaultMaxAttempts,
	}
}

// --- Coordinator ---

type Coordinator struct {
	mu     sync.RWMutex
	rules  map[RuleID]*SessionRule
	order  []RuleID
	nextID int64
	jarMgr *CookieJarManager
	logger *zap.Logger

	// runs holds the login currently in flight for a rule. If N requests notice
	// session loss at once — realistic under any concurrency — reacting to each
	// independently would fire N logins at the engagement target. The first
	// caller runs the macro and every other caller for the same rule waits and
	// shares its result. Per rule rather than globally, because two rules are two
	// different logins: collapsing an admin login into a staging-host login would
	// hand a caller a session for a target it never asked about.
	runsMu sync.Mutex
	runs   map[RuleID]*loginRun

	// observed holds the steps the last *successful* login for a rule actually
	// sent. UpdateMacro promotes only these, so a failed run can never overwrite
	// a working macro with a broken one.
	observedMu sync.Mutex
	observed   map[RuleID][]MacroStep
}

func NewCoordinator(logger *zap.Logger) *Coordinator {
	return &Coordinator{
		rules:    make(map[RuleID]*SessionRule),
		jarMgr:   NewCookieJarManager(),
		logger:   logger,
		runs:     make(map[RuleID]*loginRun),
		observed: make(map[RuleID][]MacroStep),
	}
}

// ErrNoSuchRule is what UpdateRule returns for an id the coordinator does not hold, so a caller can
// tell "the rule you edited is gone" (a 404) from "the edit is not a valid rule" (a 400) without
// matching on an error string.
var ErrNoSuchRule = errors.New("no session rule with that id")

// AddRule validates `rule` and appends it to the evaluation order, returning its new id.
//
// Validation lives here, not only in the HTTP handler, because every path that installs a rule — the
// web API, the CLI, and restoring a saved project — has to earn the same refusals. A rule that skips
// them surfaces later as "the log-in button did nothing", with the reason buried in whichever step
// silently produced no value.
func (c *Coordinator) AddRule(rule *SessionRule) (RuleID, error) {
	if err := ValidateRule(rule); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id := RuleID(atomic.AddInt64(&c.nextID, 1))
	rule.ID = id
	c.rules[id] = rule
	c.order = append(c.order, id)
	return id, nil
}

func (c *Coordinator) RemoveRule(id RuleID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.rules, id)
	for i, iter := range c.order {
		if iter == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// UpdateRule replaces a rule's mutable fields in place, keeping its identity (ID and position in
// the evaluation order). This is the write path behind PUT /api/session/rules/{id}.
//
// Validated for the same reason AddRule is: an edit is as capable of installing an unrunnable rule
// as a create, and the rule it replaces was working. Returns ErrNoSuchRule for an unknown id and a
// *RuleError for an edit that does not validate, so the two can be answered differently.
func (c *Coordinator) UpdateRule(id RuleID, rule *SessionRule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cur, ok := c.rules[id]
	if !ok {
		return ErrNoSuchRule
	}
	rule.ID = cur.ID
	c.rules[id] = rule
	return nil
}

func (c *Coordinator) AllRules() []*SessionRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*SessionRule, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.rules[id])
	}
	return out
}

func (c *Coordinator) Rule(id RuleID) *SessionRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rules[id]
}

func (c *Coordinator) MatchingRule(host string) *SessionRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, id := range c.order {
		r := c.rules[id]
		if r.Enabled && r.MatchHost(host) {
			return r
		}
	}
	return nil
}

func (c *Coordinator) HandleResponse(host string, port uint16, tls bool, status int, hdrs map[string]string, body []byte) {
	for k, v := range hdrs {
		if strings.EqualFold(k, "Set-Cookie") {
			c.jarMgr.AbsorbSetCookie(host, port, tls, v)
		}
	}
	rule := c.MatchingRule(host)
	if rule != nil && rule.Validity != nil {
		state := rule.Validity.Evaluate(status, hdrs, body)
		if state == Invalid {
			c.logger.Debug("session invalid", zap.String("rule", rule.Name), zap.String("host", host))
		}
	}
}

// CookieHeader returns the cookie header for the authority.
func (c *Coordinator) CookieHeader(host string, port uint16, tls bool) string {
	return c.jarMgr.CookieHeader(host, port, tls)
}

// ---- Macro execution ---------------------------------------------------------------------------

// StepResult is what a macro step produced. Headers are the response headers
// (Set-Cookie is absorbed; extraction reads them and the body).
type StepResult struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

// MacroStepRunner sends one macro step and returns its response. It is the
// trait seam that keeps this package free of the sender: the web layer supplies
// a closure over the shared sender (and its tool log + scope chokepoint), and
// the CLI could supply one over the same engines without importing them here.
type MacroStepRunner func(step MacroStep) (*StepResult, error)

// RunMacro replays a rule's macro against its scope, threading cookies and
// extractions through the steps: each step runs with any cookies the previous
// steps' responses set (the runner is a pure sender; this coordinator owns the
// jar), and a step's {{name}} markers are replaced by the values extracted from
// earlier responses.
//
// It returns the steps that were sent (post-extraction), the per-step results
// (nil for a step that was skipped for being out of scope or that failed to
// send), and the overall validity state.
func (c *Coordinator) RunMacro(rule *SessionRule, runner MacroStepRunner) ([]MacroStep, []*StepResult, ValidityState) {
	if rule == nil {
		return nil, nil, Indeterminate
	}

	extracted := make(map[string]string)
	sent := make([]MacroStep, 0, len(rule.Steps))
	results := make([]*StepResult, 0, len(rule.Steps))

	for stepIndex, step := range rule.Steps {
		// Interpolate extractions from earlier responses into this step.
		step = interpolateStep(step, extracted)
		sent = append(sent, step)
		if !rule.MatchHost(hostOf(step.URL)) {
			results = append(results, nil)
			continue
		}
		// Attach the cookies the jar holds for this step's authority.
		host, port, tls := authorityOf(step.URL)
		if cookie := c.CookieHeader(host, port, tls); cookie != "" {
			if step.Headers == nil {
				step.Headers = make(map[string]string)
			}
			if _, exists := step.Headers["Cookie"]; !exists {
				step.Headers["Cookie"] = cookie
			}
		}
		res, err := runner(step)
		if err != nil {
			results = append(results, nil)
			continue
		}
		results = append(results, res)
		// Absorb cookies set by this step.
		for k, v := range res.Headers {
			if strings.EqualFold(k, "Set-Cookie") {
				c.jarMgr.AbsorbSetCookie(host, port, tls, v)
			}
		}
		// Run this step's own extractions against its response.
		if res.Status >= 200 && res.Status < 400 {
			for _, ex := range rule.extractionsFor(stepIndex) {
				if v := ex.Run(res.Headers, res.Body); v != "" {
					extracted[ex.Name] = v
				}
			}
		}
	}

	// Overall validity: evaluate the validity rule against the last successful step.
	var last *StepResult
	for i := len(results) - 1; i >= 0; i-- {
		if results[i] != nil {
			last = results[i]
			break
		}
	}
	state := Indeterminate
	if last != nil && rule.Validity != nil {
		state = rule.Validity.Evaluate(last.Status, last.Headers, last.Body)
	}
	return sent, results, state
}

// interpolateStep replaces {{name}} markers with previously extracted values.
func interpolateStep(step MacroStep, extracted map[string]string) MacroStep {
	replace := func(s string) string {
		if s == "" || len(extracted) == 0 {
			return s
		}
		out := s
		for name, val := range extracted {
			out = strings.ReplaceAll(out, "{{"+name+"}}", val)
		}
		return out
	}
	step.URL = replace(step.URL)
	step.Body = replace(step.Body)
	if len(step.Headers) > 0 {
		h := make(map[string]string, len(step.Headers))
		for k, v := range step.Headers {
			h[k] = replace(v)
		}
		step.Headers = h
	}
	return step
}

func hostOf(url string) string {
	host, _, _ := authorityOf(url)
	return host
}

func authorityOf(url string) (host string, port uint16, tls bool) {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme := strings.ToLower(rest[:i])
		tls = scheme == "https"
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	if h, p, err := netSplitHostPort(rest); err == nil {
		return h, p, tls
	}
	if rest != "" {
		if tls {
			return rest, 443, tls
		}
		return rest, 80, tls
	}
	return "", 0, tls
}

func netSplitHostPort(s string) (string, uint16, error) {
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i+1:], ":") {
		var p uint16
		if n, err := fmt.Sscanf(s[i+1:], "%d", &p); err == nil && n == 1 {
			return s[:i], p, nil
		}
	}
	return "", 0, fmt.Errorf("no port")
}
