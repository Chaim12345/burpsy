// Package matchreplace implements ordered rewrite rules for proxied requests
// and responses. Mirrors the Rust burpsy-tools matchreplace module: compiled
// regex rules applied on the proxy hot path, with per-rule scope and the
// Burp-compatible rule_type taxonomy.
package matchreplace

import (
	"bytes"
	"regexp"
	"strconv"
	"sync"
)

// Target names match Burp's rule_type config values.
type Target int

const (
	TargetRequestHeader Target = iota
	TargetRequestBody
	TargetRequestFirstLine
	TargetRequestParamName
	TargetRequestParamValue
	TargetResponseHeader
	TargetResponseBody
	// The two WebSocket targets rewrite a whole message payload rather than part of an HTTP
	// message. A frame has no headers, no first line and no parameters, so there is nothing to
	// address inside it — the payload IS the addressable unit, which is why these two need no
	// header/body split of their own.
	TargetWebSocketToServer
	TargetWebSocketToClient
	// TargetCount is how many Targets the taxonomy has, and it must stay last.
	//
	// It exists so tests can walk the enum instead of a hand-written list. The round-trip test
	// in internal/web used to iterate a literal slice of seven while its own comment claimed it
	// "walks every declared Target" — so an eighth Target added here would have left both the
	// wire-name mapping and the accepted-vocabulary parser silently incomplete, with the test
	// still green. Same shape as fieldCount in internal/query and changeKindCount in
	// internal/web/events.go.
	TargetCount = iota
)

// Category is how string_match is interpreted.
type Category int

const (
	CategoryLiteral Category = iota
	CategoryRegex
)

// Rule is a compiled, runnable rewrite rule.
type Rule struct {
	Enabled       bool
	Target        Target
	Category      Category
	StringMatch   string
	StringReplace string
	Comment       string
	re            *regexp.Regexp
}

// NewRule compiles a rule. For CategoryRegex the pattern is compiled.
func NewRule(target Target, cat Category, match, replace, comment string) (*Rule, error) {
	r := &Rule{
		Enabled:       true,
		Target:        target,
		Category:      cat,
		StringMatch:   match,
		StringReplace: replace,
		Comment:       comment,
	}
	if cat == CategoryRegex {
		re, err := regexp.Compile(match)
		if err != nil {
			return nil, err
		}
		r.re = re
	}
	return r, nil
}

// Direction is which half of the exchange we are rewriting.
type Direction int

const (
	DirRequest Direction = iota
	DirResponse
	DirWebSocketToServer
	DirWebSocketToClient
	// DirCount must stay last, for the same reason TargetCount does: it lets targetDirections be
	// an array the compiler sizes, so a direction added without a mapping is a build failure
	// rather than a silent fallthrough.
	DirCount = iota
)

// IsWebSocket reports whether this direction carries WebSocket message payloads rather than HTTP
// messages. Callers use it to skip anything HTTP-shaped — recomputing Content-Length on a frame,
// for instance, which has none.
func (d Direction) IsWebSocket() bool {
	return d == DirWebSocketToServer || d == DirWebSocketToClient
}

// RuleSet is an ordered set of compiled rules.
type RuleSet struct {
	mu                  sync.RWMutex
	rules               []*Rule
	updateContentLength bool
}

func NewRuleSet() *RuleSet { return &RuleSet{} }

// SetRules replaces the entire rule set (atomic from the caller's perspective).
func (rs *RuleSet) SetRules(rules []*Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = rules
}

// SetUpdateContentLength controls whether the request/response Content-Length header is
// recomputed after rules that changed a body.
func (rs *RuleSet) SetUpdateContentLength(update bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.updateContentLength = update
}

// UpdateContentLength reports whether body rewrites should fix Content-Length.
func (rs *RuleSet) UpdateContentLength() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.updateContentLength
}

// AddRule appends a rule.
func (rs *RuleSet) AddRule(r *Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = append(rs.rules, r)
}

// Rules returns a snapshot of the current rules.
func (rs *RuleSet) Rules() []*Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]*Rule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// Affects returns true if any enabled rule targets this direction.
//
// Reads the same targetDirections table Apply does, so "this direction has rules" and "this rule
// runs in this direction" cannot disagree. They previously had separate if-chains listing the
// targets by hand, which is two places to forget a new one.
func (rs *RuleSet) Affects(dir Direction) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	for _, r := range rs.rules {
		if !r.Enabled {
			continue
		}
		if targetsDir(r.Target, dir) {
			return true
		}
	}
	return false
}

// Apply runs all enabled rules that match the direction over raw,
// returning the rewritten bytes. If no rule fires, raw is returned
// unchanged (no copy). When UpdateContentLength is enabled, the
// Content-Length header is recomputed after a body rewrite.
func (rs *RuleSet) Apply(dir Direction, raw []byte) []byte {
	rs.mu.RLock()
	rules := rs.rules
	updateCL := rs.updateContentLength
	rs.mu.RUnlock()
	if len(rules) == 0 {
		return raw
	}
	out := raw
	changed := false
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if !targetsDir(r.Target, dir) {
			continue
		}
		applied := applyOne(r, out)
		if applied != nil {
			out = applied
			changed = true
		}
	}
	if !changed {
		return raw
	}
	// Not for WebSocket. A frame has no Content-Length, and fixContentLength looks for a
	// header/body separator — which a payload that happens to contain a blank line would appear to
	// have, at which point it would inject a Content-Length header into the middle of application
	// data. Skipped by direction rather than by inspecting the bytes, because the direction is a
	// fact and the bytes are a guess.
	if updateCL && !dir.IsWebSocket() {
		out = fixContentLength(out)
	}
	return out
}

// applyWholePayload rewrites the entire input, for targets whose addressable unit is the whole
// thing. Returns nil when the rule did not fire, which is applyOne's contract.
func applyWholePayload(r *Rule, raw []byte) []byte {
	if r.Category == CategoryRegex {
		if r.re == nil || !r.re.Match(raw) {
			return nil
		}
		return r.re.ReplaceAll(raw, []byte(r.StringReplace))
	}
	if r.StringMatch == "" || !bytes.Contains(raw, []byte(r.StringMatch)) {
		return nil
	}
	return bytes.ReplaceAll(raw, []byte(r.StringMatch), []byte(r.StringReplace))
}

// fixContentLength recomputes the Content-Length header to match the actual body length.
// It replaces the header if present, and appends one when a body exists without it.
func fixContentLength(raw []byte) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		sep = []byte("\n\n")
		idx = bytes.Index(raw, sep)
		if idx < 0 {
			return raw // no body section to measure
		}
	}
	headers := raw[:idx]
	body := raw[idx+len(sep):]
	length := strconv.Itoa(len(body))

	lines := bytes.Split(headers, []byte("\r\n"))
	found := false
	for i, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("content-length:")) {
			colon := bytes.IndexByte(line, ':')
			if colon < 0 {
				continue
			}
			// bytes.Split returns subslices that share the backing array of raw,
			// so append(line[:colon+1], ...) would overwrite adjacent header lines
			// — and, when Content-Length is the last header, the separator and
			// body — whenever the recomputed length string is longer than the
			// original. Build a fresh slice instead.
			lines[i] = []byte("Content-Length: " + length)
			found = true
		}
	}
	var out bytes.Buffer
	for i, line := range lines {
		if i > 0 {
			out.WriteString("\r\n")
		}
		out.Write(line)
	}
	out.Write(sep)
	out.Write(body)
	if !found && len(body) > 0 {
		// No Content-Length header; append one so downstream honors the body.
		// Insert before the separator by rewriting: easier to splice into the tail.
		msg := out.Bytes()
		sepLen := len(sep)
		head := msg[:len(msg)-len(body)-sepLen]
		tail := msg[len(msg)-len(body):]
		var b bytes.Buffer
		b.Write(head)
		b.WriteString("\r\nContent-Length: ")
		b.WriteString(length)
		b.Write(sep)
		b.Write(tail)
		return b.Bytes()
	}
	return out.Bytes()
}

// targetDirections says which direction each target belongs to.
//
// An array rather than the if-chain this used to be. That chain read `if dir == DirRequest { ...five
// targets... } return ...two targets...`, so every direction that was not DirRequest was treated as
// a response — which meant adding the WebSocket directions would have silently matched WebSocket
// payloads against the *response* target list. Same failure the intercept package's Direction had,
// and fixed the same way: the compiler sizes this array, so a target added without a row here does
// not build.
var targetDirections = [TargetCount]Direction{
	TargetRequestHeader:     DirRequest,
	TargetRequestBody:       DirRequest,
	TargetRequestFirstLine:  DirRequest,
	TargetRequestParamName:  DirRequest,
	TargetRequestParamValue: DirRequest,
	TargetResponseHeader:    DirResponse,
	TargetResponseBody:      DirResponse,
	TargetWebSocketToServer: DirWebSocketToServer,
	TargetWebSocketToClient: DirWebSocketToClient,
}

func targetsDir(t Target, dir Direction) bool {
	if t < 0 || int(t) >= TargetCount {
		// An out-of-range target matches nothing. Refusing here rather than indexing keeps a
		// corrupt rule inert instead of routing it to whichever direction sits at that offset.
		return false
	}
	return targetDirections[t] == dir
}

func applyOne(r *Rule, raw []byte) []byte {
	switch r.Target {
	case TargetRequestBody, TargetResponseBody:
		return applyBody(r, raw)
	case TargetRequestHeader, TargetResponseHeader:
		return applyHeaders(r, raw)
	case TargetRequestFirstLine:
		return applyFirstLine(r, raw)
	case TargetWebSocketToServer, TargetWebSocketToClient:
		return applyWholePayload(r, raw)
	default:
		// An unimplemented target did not fire. `nil` is this function's contract for that —
		// see Apply, which only sets `changed` when applyOne returns non-nil.
		//
		// This used to be `return applyBody(r, raw)`. Five of the seven Targets have a case
		// above; TargetRequestParamName and TargetRequestParamValue have none, so both fell
		// here and were applied as **whole-body substring rewrites**. A param-name rule
		// replacing "secret" with "harmless" against
		// `user=admin&secret=hunter2&nonsecret=keep` produced
		// `user=admin&harmless=hunter2&nonharmless=keep` — it renamed `nonsecret`, an
		// unrelated parameter, because a body rewrite has no concept of a field boundary.
		//
		// `nil` and not `raw`: an earlier attempt at this fix returned `raw`, which is
		// non-nil and therefore reads as "the rule fired". That would have marked the
		// message changed, counted a modification that never happened, and run
		// fixContentLength over an untouched body — trading a wrong rewrite for a wrong
		// count. It was reverted, correctly.
		//
		// `targetsDir` still lists the param targets as request-direction. That is a true
		// statement about direction and not a claim that they can be applied; conflating
		// those two is what produced the original defect.
		return nil
	}
}

func applyBody(r *Rule, raw []byte) []byte {
	if r.Category == CategoryLiteral {
		if !bytes.Contains(raw, []byte(r.StringMatch)) {
			return nil
		}
		return bytes.ReplaceAll(raw, []byte(r.StringMatch), []byte(r.StringReplace))
	}
	if r.re == nil {
		return nil
	}
	if !r.re.Match(raw) {
		return nil
	}
	return r.re.ReplaceAll(raw, []byte(r.StringReplace))
}

func applyHeaders(r *Rule, raw []byte) []byte {
	// Split at the first blank line: headers end, body starts.
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	var headers, body []byte
	if idx >= 0 {
		headers = raw[:idx]
		body = raw[idx:]
	} else {
		headers = raw
	}
	lines := bytes.Split(headers, []byte("\r\n"))
	changed := false
	for i, line := range lines {
		if i == 0 {
			continue // request/status line
		}
		var rewritten []byte
		if r.Category == CategoryLiteral {
			if bytes.Contains(line, []byte(r.StringMatch)) {
				rewritten = bytes.ReplaceAll(line, []byte(r.StringMatch), []byte(r.StringReplace))
			}
		} else if r.re != nil && r.re.Match(line) {
			rewritten = r.re.ReplaceAll(line, []byte(r.StringReplace))
		}
		if rewritten != nil {
			if len(rewritten) == 0 {
				lines[i] = nil // drop line; rebuilt without nils
			} else {
				lines[i] = rewritten
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	var out bytes.Buffer
	for i, line := range lines {
		if line == nil {
			continue
		}
		if i > 0 {
			out.WriteString("\r\n")
		}
		out.Write(line)
	}
	if body != nil {
		out.Write(body)
	}
	return out.Bytes()
}

func applyFirstLine(r *Rule, raw []byte) []byte {
	idx := bytes.Index(raw, []byte("\r\n"))
	if idx < 0 {
		return nil
	}
	firstLine := raw[:idx]
	rest := raw[idx:]
	var rewritten []byte
	if r.Category == CategoryLiteral {
		if !bytes.Contains(firstLine, []byte(r.StringMatch)) {
			return nil
		}
		rewritten = bytes.ReplaceAll(firstLine, []byte(r.StringMatch), []byte(r.StringReplace))
	} else if r.re != nil {
		if !r.re.Match(firstLine) {
			return nil
		}
		rewritten = r.re.ReplaceAll(firstLine, []byte(r.StringReplace))
	}
	if rewritten == nil {
		return nil
	}
	return append(rewritten, rest...)
}
