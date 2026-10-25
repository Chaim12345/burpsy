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
// A token rule carries a credential, and the failures that matter here are the ones that send a
// credential somewhere it was never meant to go. So:
//
//   - A rule names its hosts. There is no broad default: an empty scope_hosts is refused at the
//     door, and the only way to cover every host is to say so - "*" in the list. A session rule's
//     empty scope fails inert (a rewrite that never fires); a token rule's empty scope is a
//     credential offered to any origin that asks, so the two reading rules differ on purpose.
//   - A captured value belongs to ONE rule, keyed by the rule's identity - never by the
//     extraction's name, which any number of rules can share.
//   - A value never crosses the origin it was captured from: scheme, host and port all have to
//     match the request it would ride on. A scope can narrow that further; it can never widen it.
//   - An edit or a removal drops the captured value at once. The credential the old rule held is
//     stale the moment the rule that scoped it changes.
//   - A request goes out untouched when no value has been captured yet: an injected header with
//     an empty or invented value would send the request under a lie the response then has to
//     explain.
//
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
	// ScopeHosts names the hosts whose responses may re-issue this rule's value and whose
	// requests may receive it. Empty is REFUSED - the rule would otherwise default to every
	// host, and a credential with a broad default is a leak waiting for a cross-origin request.
	// The deliberate every-host choice is the "*" entry.
	ScopeHosts []string `json:"scope_hosts,omitempty"`
	// ScopeTools mirrors the session rule's tools axis, with the same reading: empty covers
	// every tool, and an unattributed request is not turned away (see MatchTools).
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

// matchHost answers whether the rule covers one host. An empty list covers NOTHING - the
// fail-closed half of the scope rule, kept here as well as at validate so a rule that reached
// the set unvalidated still cannot fire. "*" is the operator's explicit every-host choice.
func (r *TokenRule) matchHost(host string) bool {
	for _, h := range r.ScopeHosts {
		if h == "*" || host == h {
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

// validate refuses a rule that can never capture, never inject, or would hold a credential
// under a broader authority than the operator named.
func (r *TokenRule) validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("token rule needs a name")
	}
	if len(r.ScopeHosts) == 0 {
		return fmt.Errorf("token rule %q: scope_hosts names no hosts - list the hosts this credential may reach, or \"*\" for every host, deliberately", r.Name)
	}
	if err := r.Extract.Recompile(); err != nil {
		return fmt.Errorf("token rule %q: %w", r.Name, err)
	}
	if strings.TrimSpace(r.Extract.Name) == "" {
		return fmt.Errorf("token rule %q: the extraction needs a name, so the template can reference it", r.Name)
	}
	// "body" and "header" are the only sources an extraction reads; anything else is a rule that
	// can never capture, refused at the door rather than carried as an inert placeholder - the
	// refusal ValidateRule gives a session rule's extraction, for the same reason.
	if r.Extract.From != "body" && r.Extract.From != "header" {
		return fmt.Errorf("token rule %q: the extraction source must be \"body\" or \"header\", not %q", r.Name, r.Extract.From)
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

// ReplaceTokenRules swaps the whole set at once, keeping each rule's ID and the order the caller
// passes. Values captured by rules the new set drops go with them. This is the rollback half of
// the web handlers' write-through: when the store refuses a change, the coordinator goes back to
// exactly the set the store kept, so nothing injects from state the project never saved.
func (c *Coordinator) ReplaceTokenRules(rules []*TokenRule) error {
	for _, r := range rules {
		if r == nil || r.ID == "" {
			return fmt.Errorf("a replacement token rule needs its ID")
		}
		if err := r.validate(); err != nil {
			return err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[string]*TokenRule, len(rules))
	order := make([]string, 0, len(rules))
	for _, r := range rules {
		if _, dup := next[r.ID]; dup {
			return ErrDuplicateTokenRuleID
		}
		next[r.ID] = r
		order = append(order, r.ID)
	}
	c.tokenRules = next
	c.tokenOrder = order
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	for id := range c.tokenValues {
		if _, kept := next[id]; !kept {
			delete(c.tokenValues, id)
		}
	}
	return nil
}

// ErrNoSuchTokenRule names an edit or delete addressed at a rule that is not registered.
var ErrNoSuchTokenRule = errors.New("no such token rule")

// TokenRule is one registered rule by ID, or nil.
func (c *Coordinator) TokenRule(id string) *TokenRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tokenRules[id]
}

// UpdateTokenRule replaces one registered rule, keeping its ID and its place in the order: an
// edit is not a re-add, and the capture order the operator arranged must not shuffle under one.
// The value the pre-edit rule captured is dropped with it - the rule that scoped that credential
// no longer exists, so the credential must not survive it.
func (c *Coordinator) UpdateTokenRule(id string, rule *TokenRule) error {
	if rule == nil {
		return fmt.Errorf("no token rule")
	}
	if err := rule.validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.tokenRules[id]; !ok {
		return ErrNoSuchTokenRule
	}
	rule.ID = id
	c.tokenRules[id] = rule
	c.tokenMu.Lock()
	delete(c.tokenValues, id)
	c.tokenMu.Unlock()
	return nil
}

// RemoveTokenRule deletes one registered rule and the value it captured, reporting whether the
// rule existed.
func (c *Coordinator) RemoveTokenRule(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.tokenRules[id]; !ok {
		return false
	}
	delete(c.tokenRules, id)
	for i, rid := range c.tokenOrder {
		if rid == id {
			c.tokenOrder = append(c.tokenOrder[:i], c.tokenOrder[i+1:]...)
			break
		}
	}
	c.tokenMu.Lock()
	delete(c.tokenValues, id)
	c.tokenMu.Unlock()
	return true
}

// capturedToken is one rule's latest captured value and the origin it came from. The origin is
// the value's travel permit: it is injected only into requests to the same scheme, host and
// port, whatever the rule's scope would otherwise allow.
type capturedToken struct {
	Value  string
	Scheme string
	Host   string
	Port   uint16
}

// TokenValue is the latest value the rule with this ID captured, keyed by rule identity - two
// rules extracting the same name each keep their own.
func (c *Coordinator) TokenValue(ruleID string) (string, bool) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	v, ok := c.tokenValues[ruleID]
	return v.Value, ok
}

// defaultPort normalizes an unset port to its scheme's default, so a value captured from
// https://app.test (no port on the wire identity) and a request to https://app.test:443 are the
// same origin. A scheme that is not http or https normalizes to no port: it cannot match, which
// is the fail-closed reading of an origin the rule never heard of.
func defaultPort(scheme string, port uint16) uint16 {
	if port != 0 {
		return port
	}
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// requestOrigin reads scheme, host and normalized port off a request URL, failing closed: a URL
// that does not parse to an http(s) origin is no destination a captured value may ride to.
func requestOrigin(rawURL string) (scheme, host string, port uint16, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", "", 0, false
	}
	var p uint16
	if u.Port() != "" {
		var n int
		if _, err := fmt.Sscanf(u.Port(), "%d", &n); err != nil || n < 1 || n > 65535 {
			return "", "", 0, false
		}
		p = uint16(n)
	}
	return u.Scheme, u.Hostname(), defaultPort(u.Scheme, p), true
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
// keeps the values it resolves, each under its own rule's identity with the response's origin
// attached. Called from handleResponseFor, after the jar and the validity check - the response is
// observed once, and everything that reads it reads the same bytes.
func (c *Coordinator) observeTokenRules(req RequestIdentity, hdrs map[string]string, body []byte) {
	scheme := "http"
	if req.TLS {
		scheme = "https"
	}
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
			c.tokenValues = map[string]capturedToken{}
		}
		c.tokenValues[rule.ID] = capturedToken{
			Value:  out.Value,
			Scheme: scheme,
			Host:   req.Host,
			Port:   defaultPort(scheme, req.Port),
		}
		c.tokenMu.Unlock()
	}
}

// ApplyTokenRules writes every captured value an enabled, in-scope rule covers into the request:
// the header its template resolves to, the query parameter it names. A rule with no value captured
// yet changes nothing, and a value captured from another origin - another scheme, host or port -
// changes nothing either: the credential goes only where it was captured, never further.
func (c *Coordinator) ApplyTokenRules(tool string, step MacroStep) MacroStep {
	reqScheme, reqHost, reqPort, ok := requestOrigin(step.URL)
	if !ok {
		return step
	}
	for _, rule := range c.TokenRules() {
		if rule == nil || !rule.Enabled || !rule.matchHost(reqHost) || !rule.matchTool(tool) {
			continue
		}
		c.tokenMu.Lock()
		captured, ok := c.tokenValues[rule.ID]
		c.tokenMu.Unlock()
		if !ok {
			continue
		}
		if captured.Scheme != reqScheme || captured.Host != reqHost || captured.Port != reqPort {
			continue
		}
		if rule.InjectHeader != "" {
			if step.Headers == nil {
				step.Headers = map[string]string{}
			}
			step.Headers[rule.InjectHeader] = strings.ReplaceAll(rule.InjectValue, "{{"+rule.Extract.Name+"}}", captured.Value)
		}
		if rule.InjectParam != "" {
			step.URL = replaceQueryParam(step.URL, rule.InjectParam, captured.Value)
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
