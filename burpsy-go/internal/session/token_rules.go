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
	"bytes"
	"errors"
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

// ErrDuplicateTokenRuleID is a restore that would install two rules under one persisted ID.
var ErrDuplicateTokenRuleID = errors.New("a token rule with this ID already exists")

// RestoreTokenRule installs one persisted rule, keeping its ID: a saved rule must come back as the
// rule the database meant, the same reason session rules restore by id rather than being re-minted.
// The extraction's matcher is recompiled here - storage carries its source, not the compiled form -
// and the rule is re-validated, so a rule written before a check existed is refused on load rather
// than silently weakening. Appends in call order, which is how Restore preserves the persisted order.
func (c *Coordinator) RestoreTokenRule(rule *TokenRule) error {
	if rule == nil {
		return fmt.Errorf("no token rule")
	}
	if rule.ID == "" {
		return fmt.Errorf("a restored token rule needs its persisted ID")
	}
	if err := rule.validate(); err != nil {
		return err
	}
	if err := rule.Extract.Recompile(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokenRules == nil {
		c.tokenRules = map[string]*TokenRule{}
	}
	if _, dup := c.tokenRules[rule.ID]; dup {
		return ErrDuplicateTokenRuleID
	}
	c.tokenRules[rule.ID] = rule
	c.tokenOrder = append(c.tokenOrder, rule.ID)
	return nil
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

// ObserveTokenResponse runs ONLY the token-rule half of response observation: the extractions of
// every enabled, in-scope rule over one response. It is the capture point for tools whose responses
// are observed traffic but whose cookie handling is not the proxy's - the repeater absorbs cookies
// through its own monitored-source toggle, and funnelling its responses through HandleResponseFor
// would absorb Set-Cookie into the jar whether or not the operator monitors the repeater. The jar
// and the session-rule validity check stay on HandleResponseFor, which the proxy path keeps calling.
func (c *Coordinator) ObserveTokenResponse(req RequestIdentity, hdrs map[string]string, body []byte) {
	c.observeTokenRules(req, hdrs, body)
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

// ApplyTokenRulesToRawRequest is ApplyTokenRules for a tool whose requests leave as raw bytes
// (the repeater's wire half): the bytes are parsed as a macro step, the same rules run, and what
// they resolved is spliced back into the ORIGINAL bytes - an injected header's line replaced (or
// appended when the operator's request did not carry the header), an injected parameter set on the
// request-target's query. Every byte the rules did not change - header order and duplicates, the
// HTTP version, the body - is exactly what the operator typed, because no re-render gets the
// chance to drift it. A request that does not parse, or that no rule with a captured value
// covers, goes out unchanged: the no-value silence is the same rule as on the step path.
func (c *Coordinator) ApplyTokenRulesToRawRequest(tool string, raw []byte, host string, port uint16, tls bool) []byte {
	step, err := MacroStepFromRequest(raw, host, port, tls)
	if err != nil {
		return raw
	}
	// ApplyTokenRules rewrites the step's header map IN PLACE, so the before-picture has to be
	// a copy: a struct copy alone would share the map and every edit would look already-made.
	beforeURL := step.URL
	beforeHeaders := make(map[string]string, len(step.Headers))
	for name, val := range step.Headers {
		beforeHeaders[name] = val
	}
	step = c.ApplyTokenRules(tool, step)
	var headerEdits map[string]string
	for name, val := range step.Headers {
		if beforeHeaders[name] != val {
			if headerEdits == nil {
				headerEdits = map[string]string{}
			}
			headerEdits[name] = val
		}
	}
	queryChanged := beforeURL != step.URL
	if len(headerEdits) == 0 && !queryChanged {
		return raw
	}

	// Split at the message's own separator so the reassembly is byte-true outside the edits.
	sepSep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sepSep)
	if idx < 0 {
		sepSep = []byte("\n\n")
		idx = bytes.Index(raw, sepSep)
	}
	var head, body []byte
	if idx < 0 {
		head = raw
	} else {
		head, body = raw[:idx], raw[idx+len(sepSep):]
	}
	lineSep := "\n"
	if bytes.Contains(head, []byte("\r\n")) {
		lineSep = "\r\n"
	}
	lines := strings.Split(string(head), lineSep)

	// The request line: a parameter injection rewrites the target's query, keeping the form the
	// operator used - origin-form stays origin-form, absolute stays absolute. Any other form
	// (authority, asterisk) is left as sent rather than guessed at.
	if queryChanged && len(lines) > 0 {
		if parts := strings.SplitN(lines[0], " ", 3); len(parts) == 3 {
			if u, uerr := url.Parse(step.URL); uerr == nil {
				switch {
				case strings.HasPrefix(parts[1], "http://") || strings.HasPrefix(parts[1], "https://"):
					parts[1] = step.URL
				case strings.HasPrefix(parts[1], "/"):
					parts[1] = u.RequestURI()
				}
				lines[0] = strings.Join(parts, " ")
			}
		}
	}

	// The header lines: replace the line naming the injected header (the operator's casing of
	// the name is kept), or append the header the request did not carry.
	for i := 1; i < len(lines); i++ {
		name, _, found := strings.Cut(lines[i], ":")
		if !found {
			continue
		}
		for edit, val := range headerEdits {
			if _, done := headerEdits[edit]; !done {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(name), edit) {
				lines[i] = strings.TrimSpace(name) + ": " + val
				delete(headerEdits, edit)
			}
		}
	}
	for edit, val := range headerEdits {
		lines = append(lines, edit+": "+val)
	}

	out := []byte(strings.Join(lines, lineSep))
	if idx >= 0 {
		out = append(out, sepSep...)
		out = append(out, body...)
	}
	return out
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
