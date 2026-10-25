package session

// The project-level extraction+injection set (burpsy-react-ui-xe82).
//
// # What it is for
//
// A session rule's macro+extraction threads values only inside that rule's login: the value lives
// for the macro run and reaches requests the rule rewrites. Multi-step auth beyond that shape - a
// CSRF token every form response re-issues, a bearer token a login response returns once - needs
// the same two halves with no macro at all: watch every observed response for a value, and write
// the latest value into later requests. That is the TokenRule: one extraction (the same
// Extraction the macro engine runs) plus where the value goes on a matching request.
//
// # What it refuses to do
//
// A request goes out untouched when no value has been captured yet: an injected header with an
// empty or invented value would send the request under a lie the response then has to explain.
// Capture and injection each honour the rule's scope - a response from a host the rule does not
// cover never overwrites the value, and a tool outside the rule's tools scope never receives it.

import (
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
)

// TokenRule is one project-level capture-and-inject pair.
type TokenRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// ScopeHosts and ScopeTools mirror the session rule's host and tools axes, with the same
	// reading: empty covers everything.
	ScopeHosts []string `json:"scope_hosts,omitempty"`
	ScopeTools []string `json:"scope_tools,omitempty"`
	// Extract lifts the value from any observed response whose request the rule covers. Its Step
	// field is meaningless here - there is no macro to index into - and stays zero.
	Extract Extraction `json:"extract"`
	// InjectHeader names the header a covered request gains or replaces; InjectValue is its
	// template, with {{name}} resolving to the captured value ("Bearer {{token}}"). Both or
	// neither: a header with no template injects nothing.
	InjectHeader string `json:"inject_header,omitempty"`
	InjectValue  string `json:"inject_value,omitempty"`
	// InjectParam names a URL query parameter a covered request gains or replaces with the
	// captured value.
	InjectParam string `json:"inject_param,omitempty"`
}

// matchHost reads the scope the way SessionRule.MatchHost does: empty covers every host.
func (r *TokenRule) matchHost(host string) bool {
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

// matchTool reads the tools axis the way MatchTools does: empty covers every tool, and an
// unattributed request is not turned away - see MatchTools for why that direction is the safe one.
func (r *TokenRule) matchTool(tool string) bool {
	if len(r.ScopeTools) == 0 || tool == "" {
		return true
	}
	for _, t := range r.ScopeTools {
		if tool == t {
			return true
		}
	}
	return false
}

// validate refuses a rule that can never capture or never inject.
func (r *TokenRule) validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("token rule needs a name")
	}
	if err := r.Extract.Recompile(); err != nil {
		return fmt.Errorf("token rule %q: %w", r.Name, err)
	}
	if strings.TrimSpace(r.Extract.Name) == "" {
		return fmt.Errorf("token rule %q: the extraction needs a name, so the template can reference it", r.Name)
	}
	if (r.InjectHeader == "") != (r.InjectValue == "") {
		return fmt.Errorf("token rule %q: inject_header and inject_value come as a pair", r.Name)
	}
	if r.InjectHeader == "" && r.InjectParam == "" {
		return fmt.Errorf("token rule %q: nothing to inject - name a header or a parameter", r.Name)
	}
	if r.InjectValue != "" && !strings.Contains(r.InjectValue, "{{"+r.Extract.Name+"}}") {
		return fmt.Errorf("token rule %q: the template never references {{%s}}", r.Name, r.Extract.Name)
	}
	return nil
}

// tokenSeq numbers token rule IDs within one coordinator.
var tokenSeq atomic.Int64

// AddTokenRule validates and registers one rule, returning its ID.
func (c *Coordinator) AddTokenRule(rule *TokenRule) (string, error) {
	if rule == nil {
		return "", fmt.Errorf("no token rule")
	}
	if err := rule.validate(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if rule.ID == "" {
		rule.ID = fmt.Sprintf("token-%d", tokenSeq.Add(1))
	}
	if c.tokenRules == nil {
		c.tokenRules = map[string]*TokenRule{}
	}
	c.tokenRules[rule.ID] = rule
	c.tokenOrder = append(c.tokenOrder, rule.ID)
	return rule.ID, nil
}

// TokenRules is the registered set, in insertion order.
func (c *Coordinator) TokenRules() []*TokenRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*TokenRule, 0, len(c.tokenOrder))
	for _, id := range c.tokenOrder {
		out = append(out, c.tokenRules[id])
	}
	return out
}

// TokenValue is the latest value captured under one extraction name.
func (c *Coordinator) TokenValue(name string) (string, bool) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	v, ok := c.tokenValues[name]
	return v, ok
}

// observeTokenRules runs every enabled, in-scope rule's extraction over one observed response and
// keeps the values it resolves. Called from handleResponseFor, after the jar and the validity
// check - the response is observed once, and everything that reads it reads the same bytes.
func (c *Coordinator) observeTokenRules(req RequestIdentity, hdrs map[string]string, body []byte) {
	for _, rule := range c.TokenRules() {
		if rule == nil || !rule.Enabled || !rule.matchHost(req.Host) || !rule.matchTool(req.Tool) {
			continue
		}
		out := rule.Extract.RunResult(hdrs, body)
		if !out.Outcome.Resolved() || out.Value == "" {
			continue
		}
		c.tokenMu.Lock()
		if c.tokenValues == nil {
			c.tokenValues = map[string]string{}
		}
		c.tokenValues[rule.Extract.Name] = out.Value
		c.tokenMu.Unlock()
	}
}

// ApplyTokenRules writes every captured value an enabled, in-scope rule covers into the request:
// the header its template resolves to, the query parameter it names. A rule with no value captured
// yet changes nothing.
func (c *Coordinator) ApplyTokenRules(tool string, step MacroStep) MacroStep {
	host := ""
	if u, err := url.Parse(step.URL); err == nil {
		host = u.Hostname()
	}
	for _, rule := range c.TokenRules() {
		if rule == nil || !rule.Enabled || !rule.matchHost(host) || !rule.matchTool(tool) {
			continue
		}
		value, ok := c.TokenValue(rule.Extract.Name)
		if !ok {
			continue
		}
		if rule.InjectHeader != "" {
			if step.Headers == nil {
				step.Headers = map[string]string{}
			}
			step.Headers[rule.InjectHeader] = strings.ReplaceAll(rule.InjectValue, "{{"+rule.Extract.Name+"}}", value)
		}
		if rule.InjectParam != "" {
			step.URL = replaceQueryParam(step.URL, rule.InjectParam, value)
		}
	}
	return step
}

// replaceQueryParam sets one query parameter on a URL, replacing it when present.
func replaceQueryParam(raw, name, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}
