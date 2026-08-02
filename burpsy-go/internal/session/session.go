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
	Valid         ValidityState = iota
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
	if vr == nil { return Indeterminate }
	if vr.StatusIs != nil {
		if status == 0 { return Indeterminate }
		if status == *vr.StatusIs { return Valid }
		return Invalid
	}
	if vr.BodyContains != "" {
		if bytes.Contains(body, []byte(vr.BodyContains)) { return Valid }
		return Invalid
	}
	if vr.BodyNotContains != "" {
		if bytes.Contains(body, []byte(vr.BodyNotContains)) { return Invalid }
		return Valid
	}
	if vr.HeaderPresent != "" {
		for k := range hdrs {
			if strings.EqualFold(k, vr.HeaderPresent) { return Valid }
		}
		return Invalid
	}
	if vr.HeaderAbsent != "" {
		for k := range hdrs {
			if strings.EqualFold(k, vr.HeaderAbsent) { return Invalid }
		}
		return Valid
	}
	if vr.All != nil {
		allV := true
		for _, s := range vr.All {
			r := s.Evaluate(status, hdrs, body)
			if r == Invalid { return Invalid }
			if r == Indeterminate { allV = false }
		}
		if allV { return Valid }
		return Indeterminate
	}
	if vr.Any != nil {
		best := Invalid
		for _, s := range vr.Any {
			r := s.Evaluate(status, hdrs, body)
			if r == Valid { return Valid }
			if r == Indeterminate { best = Indeterminate }
		}
		return best
	}
	if vr.Not != nil {
		r := vr.Not.Evaluate(status, hdrs, body)
		if r == Valid { return Invalid }
		if r == Indeterminate { return Indeterminate }
		return Valid
	}
	return Indeterminate
}

// --- Extraction ---

type Extraction struct {
	Name    string        `json:"name"`
	From    string        `json:"from"` // "body" | "header"
	Pattern string        `json:"pattern"`
	Group   int           `json:"group"`
	re      *regexp.Regexp
}

func NewExtraction(name, from, pattern string, group int) (*Extraction, error) {
	re, err := regexp.Compile(pattern)
	if err != nil { return nil, err }
	return &Extraction{Name: name, From: from, Pattern: pattern, Group: group, re: re}, nil
}

func (e *Extraction) Run(hdrs map[string]string, body []byte) string {
	if e == nil || e.re == nil { return "" }
	if e.From == "body" {
		m := e.re.FindSubmatch(body)
		if m != nil && e.Group < len(m) { return string(m[e.Group]) }
	}
	if e.From == "header" {
		for k, v := range hdrs {
			if e.re.MatchString(k) {
				m := e.re.FindStringSubmatch(v)
				if m != nil && e.Group < len(m) { return m[e.Group] }
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
	j.RLock(); defer j.RUnlock()
	if len(j.m) == 0 { return "" }
	keys := make([]string, 0, len(j.m))
	for k := range j.m { keys = append(keys, k) }
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+j.m[k])
	}
	return strings.Join(parts, "; ")
}

func (j *cookieJar) absorb(val string) {
	j.Lock(); defer j.Unlock()
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

func NewCookieJarManager() *CookieJarManager { return &CookieJarManager{jars: make(map[string]*cookieJar)} }

func (cjm *CookieJarManager) CookieHeader(host string, port uint16, tls bool) string {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.RLock(); jar := cjm.jars[key]; cjm.mu.RUnlock()
	if jar == nil { return "" }
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
	ID          RuleID         `json:"id"`
	Name        string         `json:"name"`
	Enabled     bool           `json:"enabled"`
	ScopeHosts  []string       `json:"scope_hosts"`
	Steps       []MacroStep    `json:"macro"`
	Validity    *ValidityRule  `json:"validity"`
	MaxAttempts int            `json:"max_attempts"`
	Extractions []*Extraction  `json:"extractions"`
}

func (r *SessionRule) MatchHost(host string) bool {
	if r == nil || len(r.ScopeHosts) == 0 { return false }
	for _, h := range r.ScopeHosts {
		if host == h { return true }
	}
	return false
}

func NewSessionRule(name string, hosts []string, steps []MacroStep) *SessionRule {
	if steps == nil { steps = make([]MacroStep, 0) }
	return &SessionRule{
		Name: name, Enabled: true,
		ScopeHosts: hosts, Steps: steps, MaxAttempts: DefaultMaxAttempts,
	}
}

// --- Coordinator ---

type Coordinator struct {
	mu       sync.RWMutex
	rules    map[RuleID]*SessionRule
	order    []RuleID
	nextID   int64
	jarMgr   *CookieJarManager
	logger   *zap.Logger
}

func NewCoordinator(logger *zap.Logger) *Coordinator {
	return &Coordinator{
		rules:  make(map[RuleID]*SessionRule),
		jarMgr: NewCookieJarManager(),
		logger: logger,
	}
}

func (c *Coordinator) AddRule(rule *SessionRule) RuleID {
	c.mu.Lock(); defer c.mu.Unlock()
	id := RuleID(atomic.AddInt64(&c.nextID, 1))
	rule.ID = id
	c.rules[id] = rule
	c.order = append(c.order, id)
	return id
}

func (c *Coordinator) RemoveRule(id RuleID) {
	c.mu.Lock(); defer c.mu.Unlock()
	delete(c.rules, id)
	for i, iter := range c.order {
		if iter == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

func (c *Coordinator) AllRules() []*SessionRule {
	c.mu.RLock(); defer c.mu.RUnlock()
	out := make([]*SessionRule, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.rules[id])
	}
	return out
}

func (c *Coordinator) Rule(id RuleID) *SessionRule {
	c.mu.RLock(); defer c.mu.RUnlock()
	return c.rules[id]
}

func (c *Coordinator) MatchingRule(host string) *SessionRule {
	c.mu.RLock(); defer c.mu.RUnlock()
	for _, id := range c.order {
		r := c.rules[id]
		if r.Enabled && r.MatchHost(host) { return r }
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