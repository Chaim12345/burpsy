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

// Evaluate decides whether a response shows a still-valid session.
//
// # Every stated clause is evaluated, and they compose as a conjunction
//
// This used to be a first-stated-field-wins if-chain: each clause `return`ed
// unconditionally, so in a rule stating more than one condition only the first was ever
// read and the rest were dead code.
//
// That was the worst defect in the parity audit, because of what reads this. `recovery.go`
// gates re-login on `Evaluate(...) == Valid` in four places, so an operator writing
//
//	{"status_is": 200, "body_not_contains": "Please log in"}
//
// meaning "200 **and** not the login page" got only the status check. A logged-out login
// page answers 200, so the rule reported Valid, the scanner never re-authenticated, and an
// authenticated scan silently degraded into an unauthenticated one — while still reporting
// `state=audited, skipped=0`. A clean bill of health over work that never happened.
//
// # Why conjunction rather than refusing the flat form
//
// The audit proposed refusing a flat multi-field rule and directing the operator to `All{}`.
// That is smaller, but it makes the intuitive spelling permanently unusable and it breaks
// any such rule already sitting in persisted config — rules that are broken today, so the
// refusal would surface real breakage, but it would also refuse the reading the operator
// plainly intended.
//
// Conjunction is not a guess about that intent: `All{}` in this same file already defines
// the tri-state composition, and this reuses it verbatim. A rule stating one clause behaves
// exactly as before, so nothing that works today changes. A rule stating several now means
// what it says.
//
// Precedence follows `All{}`: a definite Invalid wins over an Indeterminate, because a clause
// that positively disproves the session is more informative than one that could not be
// decided. A rule stating nothing at all is still Indeterminate — silence is not consent.
func (vr *ValidityRule) Evaluate(status int, hdrs map[string]string, body []byte) ValidityState {
	if vr == nil {
		return Indeterminate
	}

	stated := 0
	verdict := Valid
	// note folds one clause's verdict into the running conjunction. Invalid is sticky and
	// outranks Indeterminate; both outrank Valid.
	note := func(s ValidityState) {
		stated++
		switch {
		case s == Invalid:
			verdict = Invalid
		case s == Indeterminate && verdict != Invalid:
			verdict = Indeterminate
		}
	}

	if vr.StatusIs != nil {
		// A response with no status is not evidence either way — it is an unmeasured clause,
		// not a failed one.
		switch {
		case status == 0:
			note(Indeterminate)
		case status == *vr.StatusIs:
			note(Valid)
		default:
			note(Invalid)
		}
	}
	if vr.BodyContains != "" {
		note(boolState(bytes.Contains(body, []byte(vr.BodyContains))))
	}
	if vr.BodyNotContains != "" {
		note(boolState(!bytes.Contains(body, []byte(vr.BodyNotContains))))
	}
	if vr.HeaderPresent != "" {
		note(boolState(hasHeader(hdrs, vr.HeaderPresent)))
	}
	if vr.HeaderAbsent != "" {
		note(boolState(!hasHeader(hdrs, vr.HeaderAbsent)))
	}
	if vr.All != nil {
		note(evaluateAll(vr.All, status, hdrs, body))
	}
	if vr.Any != nil {
		note(evaluateAny(vr.Any, status, hdrs, body))
	}
	if vr.Not != nil {
		note(negate(vr.Not.Evaluate(status, hdrs, body)))
	}

	if stated == 0 {
		return Indeterminate
	}
	return verdict
}

func boolState(ok bool) ValidityState {
	if ok {
		return Valid
	}
	return Invalid
}

func hasHeader(hdrs map[string]string, name string) bool {
	for k := range hdrs {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// evaluateAll is the original All{} semantics, extracted unchanged so the top-level
// conjunction above and an explicit All{} block cannot drift apart.
func evaluateAll(subs []*ValidityRule, status int, hdrs map[string]string, body []byte) ValidityState {
	allV := true
	for _, s := range subs {
		switch s.Evaluate(status, hdrs, body) {
		case Invalid:
			return Invalid
		case Indeterminate:
			allV = false
		}
	}
	if allV {
		return Valid
	}
	return Indeterminate
}

func evaluateAny(subs []*ValidityRule, status int, hdrs map[string]string, body []byte) ValidityState {
	best := Invalid
	for _, s := range subs {
		switch s.Evaluate(status, hdrs, body) {
		case Valid:
			return Valid
		case Indeterminate:
			best = Indeterminate
		}
	}
	return best
}

func negate(s ValidityState) ValidityState {
	switch s {
	case Valid:
		return Invalid
	case Indeterminate:
		return Indeterminate
	default:
		return Valid
	}
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
	// JSONPath, when non-empty, lifts the value by walking the source as JSON instead of by matching
	// Pattern against it. Exactly one of the two says how this extraction works, and ValidateRule
	// refuses a rule that states both or neither — an extraction that could be read either way is one
	// whose behaviour depends on which branch happens to be tested first.
	//
	// The supported path grammar is a deliberate subset (see jsonpath.go), and everything outside it is
	// refused when the rule is configured rather than resolving to nothing at login time.
	//
	// Added after Pattern existed, so an extraction saved before this field did loads with it empty and
	// goes on being a regex extraction.
	JSONPath string `json:"json_path,omitempty"`
	re       *regexp.Regexp
	path     jsonPath
}

func NewExtraction(name, from, pattern string, group int) (*Extraction, error) {
	e := &Extraction{Name: name, From: from, Pattern: pattern, Group: group}
	if err := e.Recompile(); err != nil {
		return nil, err
	}
	return e, nil
}

// NewJSONPathExtraction builds the json-path form: the value is found by walking the source as JSON
// rather than by matching a regex over its text.
//
// The path is parsed here, so a path outside the supported subset is an error the operator sees while
// saving the rule — naming the construct that is unsupported — rather than an extraction that looks
// configured and resolves nothing when the login runs. Group is deliberately not a parameter: a
// capture group is a property of a regex, and offering one here would be offering a field that is
// silently ignored.
func NewJSONPathExtraction(name, from, path string) (*Extraction, error) {
	// Refused here rather than left to Recompile, which reads an empty JSONPath as "this is a regex
	// extraction" and would compile the equally-empty Pattern into a matcher that resolves the empty
	// string against anything. A caller that asked for a json path must never be handed that.
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("extraction %q: %w", name, errEmptyJSONPath)
	}
	e := &Extraction{Name: name, From: from, JSONPath: path}
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
	if e.JSONPath != "" {
		// Both stated is refused here as well as in ValidateRule, because Recompile is what a restore
		// path calls and it must not pick a winner: an extraction that would run as a regex on one build
		// and as a json path on another is a rule whose behaviour depends on the reader.
		if e.Pattern != "" {
			return fmt.Errorf("extraction %q states both a regex pattern %q and a json path %q; it can only work one way",
				e.Name, e.Pattern, e.JSONPath)
		}
		p, err := parseJSONPath(e.JSONPath)
		if err != nil {
			return fmt.Errorf("extraction %q: %w", e.Name, err)
		}
		e.path = p
		e.re = nil
		return nil
	}
	re, err := regexp.Compile(e.Pattern)
	if err != nil {
		return err
	}
	e.re = re
	e.path = nil
	return nil
}

// ExtractOutcome is what one extraction produced, beyond the value itself.
//
// It exists because a bare string cannot say the thing that matters. Every failure mode of an
// extraction used to arrive as "", the same value a response that genuinely carries an empty token
// produces — so an operator whose login stopped working could not tell a wrong path from a wrong
// response from a body that was not JSON at all, and the three have completely different fixes. This
// is the same distinction scanner.CoverageState draws between "never dispatched" and "ran clean".
type ExtractOutcome int

const (
	// ExtractResolved: a value was found. It may be the empty string, and that is a real answer about
	// the response rather than a failure of the extraction.
	ExtractResolved ExtractOutcome = iota
	// ExtractNoValue: the source was read and the value is not in it — the regex did not match, or the
	// json path does not resolve against this document. Result.Detail says where it stopped.
	ExtractNoValue
	// ExtractNullValue: a json path resolved and the value is JSON null. Apart from ExtractNoValue
	// because "the server sent null" is an answer about the target and "that key is absent" is an
	// answer about the path.
	ExtractNullValue
	// ExtractSourceNotJSON: a json-path extraction was pointed at text that is not JSON. The single
	// most useful outcome to keep distinct: it usually means the step returned an error page, and every
	// other reading of it blames the path.
	ExtractSourceNotJSON
	// ExtractNotAScalar: the json path resolved to an object or an array, which is not something a
	// {{placeholder}} can carry.
	ExtractNotAScalar
	// ExtractNoSuchHeader: the extraction reads a header and the response carries no header that
	// matches. Distinct from a header that is present and does not match the pattern.
	ExtractNoSuchHeader
	// ExtractInert: the extraction cannot run as configured — its matcher was never compiled (restored
	// without Recompile), or it reads from something that is neither the body nor a header. Never a
	// statement about the response. ValidateRule refuses every rule that could produce this, so it
	// firing means something installed a rule behind validation's back.
	ExtractInert
)

// ExtractOutcomeAll is every outcome, so a caller can render a legend or a histogram without
// hard-coding the set — the same reason ScanSkipAll and SkipAll exist.
var ExtractOutcomeAll = [7]ExtractOutcome{
	ExtractResolved,
	ExtractNoValue,
	ExtractNullValue,
	ExtractSourceNotJSON,
	ExtractNotAScalar,
	ExtractNoSuchHeader,
	ExtractInert,
}

func (o ExtractOutcome) String() string {
	switch o {
	case ExtractResolved:
		return "resolved"
	case ExtractNoValue:
		return "no-value"
	case ExtractNullValue:
		return "null-value"
	case ExtractSourceNotJSON:
		return "source-not-json"
	case ExtractNotAScalar:
		return "not-a-scalar"
	case ExtractNoSuchHeader:
		return "no-such-header"
	case ExtractInert:
		return "inert"
	}
	return "unknown"
}

// Explanation is one line an operator can act on.
func (o ExtractOutcome) Explanation() string {
	switch o {
	case ExtractResolved:
		return "the value was found"
	case ExtractNoValue:
		return "the source was read and does not carry this value"
	case ExtractNullValue:
		return "the json path resolved and the value is null"
	case ExtractSourceNotJSON:
		return "the json path was applied to text that is not JSON, so nothing could be looked up in it"
	case ExtractNotAScalar:
		return "the json path resolved to an object or an array, which is not a single value"
	case ExtractNoSuchHeader:
		return "the response carries no header this extraction could read"
	case ExtractInert:
		return "the extraction cannot run as configured, so it never looked at the response"
	}
	return "unknown outcome"
}

// Resolved reports whether a value was found. Derived from the outcome rather than from the value
// being non-empty, because an empty value that *was* found is a different thing from one that was not.
func (o ExtractOutcome) Resolved() bool { return o == ExtractResolved }

// ExtractResult is one extraction's whole answer: the value, why it is what it is, and a line naming
// what went wrong when it is not a value.
type ExtractResult struct {
	Outcome ExtractOutcome
	// Value is meaningful only when Outcome is ExtractResolved; every other outcome carries "".
	Value string
	// Detail is the specific thing that happened — the key that was absent, the JSON parse error, the
	// header that was looked for. Empty when there is nothing to add to the outcome.
	Detail string
}

// Run returns the extracted value, or "" for every outcome that is not a resolved value.
//
// Kept as-is for the callers that only thread values forward. RunResult is the one to use when the
// difference between "empty" and "not there" matters, which is any path that reports to an operator.
func (e *Extraction) Run(hdrs map[string]string, body []byte) string {
	return e.RunResult(hdrs, body).Value
}

// RunResult runs the extraction and says exactly what happened.
func (e *Extraction) RunResult(hdrs map[string]string, body []byte) ExtractResult {
	if e == nil {
		return ExtractResult{Outcome: ExtractInert, Detail: "there is no extraction to run"}
	}
	if e.JSONPath != "" {
		return e.runJSONPath(hdrs, body)
	}
	if e.re == nil {
		return ExtractResult{Outcome: ExtractInert, Detail: fmt.Sprintf(
			"extraction %q has an uncompiled pattern; build it with NewExtraction or call Recompile after "+
				"unmarshalling one, so what runs is what was validated", e.Name)}
	}
	switch e.From {
	case "body":
		m := e.re.FindSubmatch(body)
		if m == nil {
			return ExtractResult{Outcome: ExtractNoValue, Detail: "the pattern did not match the response body"}
		}
		if e.Group >= len(m) {
			return ExtractResult{Outcome: ExtractNoValue, Detail: fmt.Sprintf(
				"the pattern matched the body but has %d capture group(s), so there is no group %d", len(m)-1, e.Group)}
		}
		return ExtractResult{Outcome: ExtractResolved, Value: string(m[e.Group])}
	case "header":
		selected := ""
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
			selected = k
			m := e.re.FindStringSubmatch(v)
			if m != nil && e.Group < len(m) {
				return ExtractResult{Outcome: ExtractResolved, Value: m[e.Group]}
			}
		}
		if selected == "" {
			return ExtractResult{Outcome: ExtractNoSuchHeader, Detail: e.headerWanted()}
		}
		return ExtractResult{Outcome: ExtractNoValue, Detail: fmt.Sprintf(
			"header %q is present and its value does not yield group %d of the pattern", selected, e.Group)}
	}
	return ExtractResult{Outcome: ExtractInert, Detail: fmt.Sprintf(
		"extraction %q reads from %q, which is neither \"body\" nor \"header\"", e.Name, e.From)}
}

// runJSONPath is the json-path arm of RunResult: pick the source text, then walk it.
func (e *Extraction) runJSONPath(hdrs map[string]string, body []byte) ExtractResult {
	if e.path == nil {
		return ExtractResult{Outcome: ExtractInert, Detail: fmt.Sprintf(
			"extraction %q has an unparsed json path %q; call Recompile after unmarshalling one, so what runs "+
				"is what was validated", e.Name, e.JSONPath)}
	}
	var src []byte
	switch e.From {
	case "body":
		src = body
	case "header":
		// A json path over a header needs the header named: with a regex the pattern doubles as the
		// selector, and a json path cannot select anything. ValidateRule refuses the nameless form, so
		// this is the belt to that braces.
		if strings.TrimSpace(e.Header) == "" {
			return ExtractResult{Outcome: ExtractInert, Detail: fmt.Sprintf(
				"extraction %q reads a json path from a header without naming which header", e.Name)}
		}
		found := false
		for k, v := range hdrs {
			if strings.EqualFold(k, e.Header) {
				src = []byte(v)
				found = true
				break
			}
		}
		if !found {
			return ExtractResult{Outcome: ExtractNoSuchHeader, Detail: e.headerWanted()}
		}
	default:
		return ExtractResult{Outcome: ExtractInert, Detail: fmt.Sprintf(
			"extraction %q reads from %q, which is neither \"body\" nor \"header\"", e.Name, e.From)}
	}
	value, outcome, detail, isJSON := walkJSON(src, e.path)
	if !isJSON {
		return ExtractResult{Outcome: ExtractSourceNotJSON, Detail: detail}
	}
	switch outcome {
	case jsonWalkFound:
		return ExtractResult{Outcome: ExtractResolved, Value: value}
	case jsonWalkNull:
		return ExtractResult{Outcome: ExtractNullValue, Detail: detail}
	case jsonWalkNotAValue:
		return ExtractResult{Outcome: ExtractNotAScalar, Detail: detail}
	}
	return ExtractResult{Outcome: ExtractNoValue, Detail: detail}
}

// headerWanted names what the extraction was looking for, so "no such header" says which one.
func (e *Extraction) headerWanted() string {
	if strings.TrimSpace(e.Header) != "" {
		return fmt.Sprintf("no response header is named %q", e.Header)
	}
	return fmt.Sprintf("no response header's name matches the pattern %q, which is also this extraction's "+
		"header selector because it names no header", e.Pattern)
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
	// The authority this jar belongs to, kept alongside the cookies rather than recovered from the
	// map key. The key is `fmt.Sprintf("%s:%d_%v", host, port, tls)` and splitting it back apart is
	// lossy: an IPv6 literal host contains colons of its own, so `[::1]:8080_true` has no unambiguous
	// last-colon rule that also survives a hostname. Storing the tuple once, when it is still three
	// typed values, means enumeration never has to guess.
	host string
	port uint16
	tls  bool
	m    map[string]string
}

func newCookieJar(host string, port uint16, tls bool) *cookieJar {
	return &cookieJar{host: host, port: port, tls: tls, m: make(map[string]string)}
}

// CookieJarEntry is one authority's jar, flattened for reporting.
type CookieJarEntry struct {
	Host    string
	Port    uint16
	TLS     bool
	Cookies map[string]string
}

// Jars returns every jar that holds at least one cookie, sorted by authority.
//
// This exists because /api/session/cookies had no way to ask. It answered `{"wired": true,
// "cookies": []}` unconditionally, which is a true statement before any authenticated flow and a
// false one after: the coordinator had absorbed cookies and was attaching them to outgoing requests
// while the operator's cookie table said there were none. "Wired with nothing in it" and "wired and
// hiding what is in it" are indistinguishable to the reader, and the second is the one that hides a
// live session from the person responsible for it.
//
// Empty jars are omitted: a jar is created on the first Set-Cookie for an authority and may end up
// empty if the header carried no name=value pair, and an authority listed with no cookies under it
// reads as a claim about that authority rather than an artefact of how jars are allocated.
func (cjm *CookieJarManager) Jars() []CookieJarEntry {
	cjm.mu.RLock()
	jars := make([]*cookieJar, 0, len(cjm.jars))
	for _, jar := range cjm.jars {
		jars = append(jars, jar)
	}
	cjm.mu.RUnlock()

	out := make([]CookieJarEntry, 0, len(jars))
	for _, jar := range jars {
		// Copied under the jar's own lock: handing the caller the live map would let a concurrent
		// absorb() race a JSON encoder walking it.
		jar.RLock()
		if len(jar.m) > 0 {
			cookies := make(map[string]string, len(jar.m))
			for name, value := range jar.m {
				cookies[name] = value
			}
			out = append(out, CookieJarEntry{Host: jar.host, Port: jar.port, TLS: jar.tls, Cookies: cookies})
		}
		jar.RUnlock()
	}
	// Deterministic order, because map iteration is not and a cookie table that reshuffles itself on
	// every refresh is unreadable.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return !out[i].TLS && out[j].TLS
	})
	return out
}

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

// absorb takes one Set-Cookie header value.
//
// A Set-Cookie header is `name=value` followed by *attributes* — `Path`, `Domain`, `Expires`,
// `Max-Age`, `SameSite`, `Secure`, `HttpOnly` — separated by semicolons (RFC 6265 §4.1.1). Only the
// first pair is a cookie. This used to loop over every semicolon-separated chunk and store each
// `k=v` it found, so `Set-Cookie: SESSION=abc; Path=/; SameSite=Lax` deposited three "cookies", and
// cookieHeader() then sent `Path=/; SameSite=Lax; SESSION=abc` back to the server on every
// subsequent request. Nothing reported it, because nothing could enumerate the jar; the honesty fix
// that made the jar readable is what made this visible.
//
// Attributes are dropped rather than modelled: nothing in this port acts on Path, Domain or Expires
// yet, and a jar that stored them would imply a scoping and expiry policy it does not enforce.
// Cookies therefore persist for the life of the process, which is wrong in the same direction Burp's
// own session-handling cookie jar is wrong, and is stated here rather than implied.
func (j *cookieJar) absorb(val string) {
	first, _, _ := strings.Cut(val, ";")
	name, value, ok := strings.Cut(first, "=")
	if !ok {
		// `Set-Cookie: HttpOnly` and friends carry no pair at all. Storing nothing is the whole
		// response; an empty-named cookie would be worse than the header being ignored.
		return
	}
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if name == "" {
		return
	}
	j.Lock()
	defer j.Unlock()
	j.m[name] = value
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
		jar = newCookieJar(host, port, tls)
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

	// absorb records which surfaces feed the cookie jar and how much traffic they have offered it,
	// so an empty jar can be told apart from a jar nothing is watching. See internal/session/absorb.go.
	absorb absorption
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

// Cookies reports every cookie the coordinator is holding, per authority. The jar manager is
// private, so this is how /api/session/cookies asks — see CookieJarManager.Jars for why the route
// could not previously answer honestly.
func (c *Coordinator) Cookies() []CookieJarEntry { return c.jarMgr.Jars() }

// ErrNoSuchRule is what UpdateRule returns for an id the coordinator does not hold, so a caller can
// tell "the rule you edited is gone" (a 404) from "the edit is not a valid rule" (a 400) without
// matching on an error string.
var ErrNoSuchRule = errors.New("no session rule with that id")

// ErrRuleAtEdge is what MoveRule returns when the requested move would take the rule past the top
// or the bottom of the evaluation order. Named so the HTTP layer can answer it distinctly from an
// unknown id (a 400 naming the edge, not a 404) — and so the operator is told the move did nothing
// because they are at the edge, rather than being shown a success that moved nothing.
var ErrRuleAtEdge = errors.New("rule is already at that edge of the evaluation order")

// ErrDuplicateRuleID is what RestoreRule returns when the id a restored rule carries is already
// held. Named so a restore path can count and report id collisions apart from rules that simply no
// longer validate: the two say completely different things about the saved project.
var ErrDuplicateRuleID = errors.New("a session rule with that id is already installed")

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

// RestoreRule installs a rule that an earlier run already gave an id, **keeping that id**.
//
// # Why AddRule is the wrong door for a saved rule
//
// AddRule mints a fresh id from this coordinator's own counter. That is right for a rule an operator
// has just typed and wrong for one coming back from storage: a rule that was id 3 when the project
// was saved comes back as id 1, and every RuleID recorded anywhere else — an operator's note, a log
// line, a `POST /api/session/rules/3/run` in someone's shell history, a saved reference in another
// tool — then names a *different* rule. That is worse than an error, because the call still succeeds:
// it runs the wrong login macro against a live target and reports success for having done so.
//
// # Order is the caller's, and it is the evaluation order
//
// This appends to the same `order` slice AddRule does, and `order` is what MatchingRule walks to
// decide which rule owns a host. So a restore path must call this in the order the rules were
// persisted in, not in whatever order its query happened to return, or the *first* rule matching a
// host after a restart can be a different rule than before it. internal/persist keeps an explicit
// order column for exactly that reason.
//
// # Two loud refusals rather than a silent win
//
//   - An id of zero or below is not an id a persisted rule can carry (AddRule mints from 1), so it is
//     refused rather than quietly renumbered into something an operator's notes do not name.
//   - An id already installed is ErrDuplicateRuleID. Installing it would drop one of the two rules
//     while reporting success, and which one lost would depend on load order.
//
// nextID is advanced past every restored id, so a rule added *after* a restore can never be minted
// onto an id a restored rule already holds — which would be the same silent collision arriving later.
func (c *Coordinator) RestoreRule(rule *SessionRule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}
	if rule.ID <= 0 {
		return &RuleError{
			Rule: ruleLabel(rule),
			Message: fmt.Sprintf("this rule was restored carrying id %d, which is not an id any rule was ever "+
				"saved with: installing it would mean renumbering it, and anything that recorded its old id "+
				"would then name a different rule", int64(rule.ID)),
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if held, clash := c.rules[rule.ID]; clash {
		return fmt.Errorf("%w: id %d is held by %q, so restoring %q at it would drop one of the two",
			ErrDuplicateRuleID, int64(rule.ID), held.Name, rule.Name)
	}
	c.rules[rule.ID] = rule
	c.order = append(c.order, rule.ID)
	if int64(rule.ID) > atomic.LoadInt64(&c.nextID) {
		atomic.StoreInt64(&c.nextID, int64(rule.ID))
	}
	return nil
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

// MoveRule moves a rule within the evaluation order by a signed offset and reports its new
// position. This is the write path behind POST /api/session/rules/{id}/move.
//
// # Why a move has to exist at all
//
// `order` is what MatchingRule walks, and MatchingRule returns the *first* enabled rule whose
// MatchHost matches — so which login runs for a host covered by two rules is decided entirely
// by position. Until now the only way to change that was delete + re-add, which mints a fresh
// id: every reference to the old id (an operator's note, a saved /api/session/rules/{id}/run
// URL, a log line) then names a different rule, and the rule that used to be evaluated second
// silently starts going first. Moving keeps the id, exactly as RestoreRule keeps the id a
// saved rule carries.
//
// # UpdateRule is deliberately not enough
//
// UpdateRule keeps a rule's position by design ("keeping its identity (ID and position in the
// evaluation order)"), so an edit can never change precedence. This method is the only thing
// that can, and it touches nothing but `order`.
//
// # A signed offset, and refusals rather than clamps
//
// The move is an offset (-1 = up one, +1 = down one) rather than an absolute index: a rule
// added or removed between the operator loading the table and clicking an arrow then shifts
// this rule relative to the same neighbours, instead of swapping it with whatever now sits at
// the target index. ErrNoSuchRule for an id the coordinator does not hold; ErrRuleAtEdge when
// the move would run past either end — a refused move tells the operator they are at the edge,
// whereas a silently clamped one reports success and does nothing, the worst answer available.
// offset 0 is a no-op read that reports the current position.
func (c *Coordinator) MoveRule(id RuleID, offset int) (int, error) {
	if offset == 0 {
		return c.rulePosition(id)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pos := -1
	for i, candidate := range c.order {
		if candidate == id {
			pos = i
			break
		}
	}
	if pos < 0 {
		return -1, ErrNoSuchRule
	}
	target := pos + offset
	if target < 0 || target >= len(c.order) {
		return pos, fmt.Errorf("%w: the move would take rule %d past the %s of the list (%d rule(s))",
			ErrRuleAtEdge, int64(id), map[bool]string{true: "top", false: "bottom"}[target < 0], len(c.order))
	}
	c.order[pos] = c.order[target]
	c.order[target] = id
	return target, nil
}

// rulePosition reports a rule's current index in the evaluation order, or ErrNoSuchRule.
// Split out of MoveRule so the offset-0 read does not take the write lock.
func (c *Coordinator) rulePosition(id RuleID) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i, candidate := range c.order {
		if candidate == id {
			return i, nil
		}
	}
	return -1, ErrNoSuchRule
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

// HandleResponse absorbs this response's cookies and evaluates the matching rule's validity check.
//
// `hdrs` is a map, so it carries at most one Set-Cookie: a response that set two cookies arrives here
// having already lost one, before this function is entered. Callers that hold the raw response bytes
// must use AbsorbResponseCookies instead, which reads every line. This signature is kept for the
// callers that only ever had a parsed map to give.
func (c *Coordinator) HandleResponse(host string, port uint16, tls bool, status int, hdrs map[string]string, body []byte) {
	c.absorb.responses.Add(1)
	for k, v := range hdrs {
		if strings.EqualFold(k, "Set-Cookie") {
			c.jarMgr.AbsorbSetCookie(host, port, tls, v)
			c.absorb.cookies.Add(1)
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

// logExtraction records what one extraction produced, so an extraction that lifted nothing is
// visible without reading the wire.
//
// Both macro runners drop a value that did not resolve, which is right — a stale or empty token must
// not be threaded into the next step — but dropping it silently is how a login turns into "the button
// did nothing". A resolved value is logged at debug and never logged *itself*: it is a session token
// by construction, and putting one in a log file is a credential leak with a long tail. Everything
// else is a warning naming the rule, the step, the extraction and the reason.
func (c *Coordinator) logExtraction(rule *SessionRule, stepIndex int, ex *Extraction, out ExtractResult) {
	if c.logger == nil || ex == nil {
		return
	}
	fields := []zap.Field{
		zap.String("rule", ruleLabel(rule)),
		zap.Int("step", stepIndex),
		zap.String("extraction", ex.Name),
		zap.String("outcome", out.Outcome.String()),
	}
	if out.Detail != "" {
		fields = append(fields, zap.String("detail", out.Detail))
	}
	if out.Outcome.Resolved() {
		fields = append(fields, zap.Int("value_len", len(out.Value)))
		c.logger.Debug("session extraction resolved", fields...)
		return
	}
	fields = append(fields, zap.String("why", out.Outcome.Explanation()))
	c.logger.Warn("session extraction lifted no value", fields...)
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
		c.absorb.attach(SourceMacro)
		c.absorb.responses.Add(1)
		for k, v := range res.Headers {
			if strings.EqualFold(k, "Set-Cookie") {
				c.jarMgr.AbsorbSetCookie(host, port, tls, v)
				c.absorb.cookies.Add(1)
			}
		}
		// Run this step's own extractions against its response.
		if res.Status >= 200 && res.Status < 400 {
			for _, ex := range rule.extractionsFor(stepIndex) {
				out := ex.RunResult(res.Headers, res.Body)
				c.logExtraction(rule, stepIndex, ex, out)
				if out.Outcome.Resolved() && out.Value != "" {
					extracted[ex.Name] = out.Value
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

// MacroStepReport is one step's record in a dry-run: what was sent (post-interpolation),
// what came back (nil when the step was skipped for scope or failed to send), and what each
// of the step's extractions lifted. It is the Test-macro wire row (burpsy-react-ui-7zdm):
// Burp's Test macro "displays all requests and responses, the values of any cookies received,
// and the details of any parameters that Burp attempted to derive values for" — the detail
// runMacroOnce returns internally but RunMacro's three parallel slices cannot express.
type MacroStepReport struct {
	// Index is the step's position in the rule (0-based), stable even when a step is skipped.
	Index int `json:"index"`
	// Sent is the step as it went out: {{name}} markers already replaced by extracted values.
	Sent MacroStep `json:"sent"`
	// SentCookie is the Cookie header the jar attached, "" when none was attached or the step
	// carried its own. A dry-run shows what would leave, so the cookie threading is visible.
	SentCookie string `json:"sent_cookie,omitempty"`
	// Skipped states why no response exists: "" when one does, "out of scope" or the send
	// error otherwise. Skipped and Response are mutually exclusive by construction.
	Skipped string `json:"skipped,omitempty"`
	// Response is what came back; nil with a non-empty Skipped. SentCookie on the report is the
	// request-side cookie; Response.SetCookies lists what the response set back.
	Response *StepResult `json:"response,omitempty"`
	// SetCookies is every Set-Cookie header the response carried, in wire order — the jar
	// absorbs them in this order too.
	SetCookies []string `json:"set_cookies,omitempty"`
	// Extractions is this step's extraction results: one row per configured extraction on this
	// step, resolved or not. A dry-run that hides a failed extraction hides the exact thing an
	// operator tests a macro to find.
	Extractions []MacroExtractionReport `json:"extractions,omitempty"`
}

// MacroExtractionReport is one extraction's outcome in a dry-run. Value is "" unless Resolved;
// Detail carries the why when it is not.
type MacroExtractionReport struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"` // ExtractOutcome.String()
	Value   string `json:"value,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// MacroRunReport is a Test-macro dry-run's whole answer: per-step reports plus the overall
// validity state, computed the same way RunMacro computes it.
type MacroRunReport struct {
	Steps  []MacroStepReport `json:"steps"`
	Status ValidityState     `json:"status"`
}

// RunMacroDetailed is RunMacro's dry-run twin: identical stepping, cookie threading,
// interpolation, scope gating and extraction logic — literally the same loop shape — but every
// step's full story is reported instead of collapsed into three parallel slices. It is what the
// Test-macro UI calls (burpsy-react-ui-7zdm); RunMacro stays as-is because its three-slice shape
// is what the login engine consumes.
//
// Both paths share one risk, answered here by construction: a dry-run must not diverge from the
// real run, or the operator tests one macro and runs another. Any behavioural change to
// RunMacro's loop must be mirrored here, and vice versa — the two tests that pin the same
// scenario against both entry points are the tripwire.
func (c *Coordinator) RunMacroDetailed(rule *SessionRule, runner MacroStepRunner) MacroRunReport {
	report := MacroRunReport{Status: Indeterminate}
	if rule == nil || len(rule.Steps) == 0 {
		return report
	}

	extracted := make(map[string]string)
	var last *StepResult

	for stepIndex, step := range rule.Steps {
		row := MacroStepReport{Index: stepIndex, Sent: interpolateStep(step, extracted)}

		if !rule.MatchHost(hostOf(row.Sent.URL)) {
			row.Skipped = "out of scope"
			report.Steps = append(report.Steps, row)
			continue
		}
		host, port, tls := authorityOf(row.Sent.URL)
		if cookie := c.CookieHeader(host, port, tls); cookie != "" {
			if _, exists := row.Sent.Headers["Cookie"]; !exists {
				if row.Sent.Headers == nil {
					row.Sent.Headers = make(map[string]string)
				}
				row.Sent.Headers["Cookie"] = cookie
			}
		}
		row.SentCookie = row.Sent.Headers["Cookie"]

		res, err := runner(row.Sent)
		if err != nil {
			row.Skipped = err.Error()
			report.Steps = append(report.Steps, row)
			continue
		}
		row.Response = res
		last = res
		for k, v := range res.Headers {
			if strings.EqualFold(k, "Set-Cookie") {
				row.SetCookies = append(row.SetCookies, v)
				c.jarMgr.AbsorbSetCookie(host, port, tls, v)
				c.absorb.attach(SourceMacro)
				c.absorb.responses.Add(1)
				c.absorb.cookies.Add(1)
			}
		}
		if res.Status >= 200 && res.Status < 400 {
			for _, ex := range rule.extractionsFor(stepIndex) {
				out := ex.RunResult(res.Headers, res.Body)
				c.logExtraction(rule, stepIndex, ex, out)
				rowRow := MacroExtractionReport{Name: ex.Name, Outcome: out.Outcome.String(), Detail: out.Detail}
				if out.Outcome.Resolved() && out.Value != "" {
					rowRow.Value = out.Value
					extracted[ex.Name] = out.Value
				}
				row.Extractions = append(row.Extractions, rowRow)
			}
		}
		report.Steps = append(report.Steps, row)
	}

	if last != nil && rule.Validity != nil {
		report.Status = rule.Validity.Evaluate(last.Status, last.Headers, last.Body)
	}
	return report
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
