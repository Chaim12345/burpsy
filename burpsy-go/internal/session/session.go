// Package session implements session handling rules for authenticated scanning.
package session

import (
	"bytes"
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

type Extraction struct {
	Name    string `json:"name"`
	From    string `json:"from"` // "body" | "header"
	Pattern string `json:"pattern"`
	Group   int    `json:"group"`
	re      *regexp.Regexp
}

func NewExtraction(name, from, pattern string, group int) (*Extraction, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &Extraction{Name: name, From: from, Pattern: pattern, Group: group, re: re}, nil
}

func (e *Extraction) Run(hdrs map[string]string, body []byte) string {
	if e == nil || e.re == nil {
		return ""
	}
	if e.From == "body" {
		m := e.re.FindSubmatch(body)
		if m != nil && e.Group < len(m) {
			return string(m[e.Group])
		}
	}
	if e.From == "header" {
		for k, v := range hdrs {
			if e.re.MatchString(k) {
				m := e.re.FindStringSubmatch(v)
				if m != nil && e.Group < len(m) {
					return m[e.Group]
				}
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

func (r *SessionRule) MatchHost(host string) bool {
	if r == nil || len(r.ScopeHosts) == 0 {
		return false
	}
	for _, h := range r.ScopeHosts {
		if host == h {
			return true
		}
	}
	return false
}

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

func (c *Coordinator) AddRule(rule *SessionRule) RuleID {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := RuleID(atomic.AddInt64(&c.nextID, 1))
	rule.ID = id
	c.rules[id] = rule
	c.order = append(c.order, id)
	return id
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
func (c *Coordinator) UpdateRule(id RuleID, rule *SessionRule) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur, ok := c.rules[id]
	if !ok {
		return false
	}
	rule.ID = cur.ID
	c.rules[id] = rule
	return true
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

	for _, step := range rule.Steps {
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
		// Run this step's extractions against the response.
		if res.Status >= 200 && res.Status < 400 {
			for _, ex := range rule.Extractions {
				if ex == nil {
					continue
				}
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
