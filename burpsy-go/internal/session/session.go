// Package session implements session handling rules for authenticated scanning.
package session

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	StatusIs        *int   `json:"status_is,omitempty"`
	BodyContains    string `json:"body_contains,omitempty"`
	BodyNotContains string `json:"body_not_contains,omitempty"`
	HeaderPresent   string `json:"header_present,omitempty"`
	HeaderAbsent    string `json:"header_absent,omitempty"`
	// Regex flips BodyContains/BodyNotContains from literal substring to regular-expression
	// matching, and CaseSensitive disables the case-folding a literal (and a regex, unless
	// the pattern itself carries (?i)) would otherwise get — Burp's validity search offers
	// exactly these two dials (burpsy-react-ui-9prk). The flags apply to both body clauses:
	// an operator stating one body condition has stated their matching intent for the check.
	Regex         bool `json:"regex,omitempty"`
	CaseSensitive bool `json:"case_sensitive,omitempty"`
	// URLContains matches the redirection target's absolute URL — Burp's "the URL of any
	// redirection target" (session-handling-rules.html). The macro runner reports where a
	// redirect chain landed (StepResult.FinalURL); matching is literal unless Regex says
	// otherwise, under the same CaseSensitive dial. Absent FinalURL ("no redirect
	// happened") is an unmeasured clause — Indeterminate, like a status nobody measured —
	// not a failed one, because a response that did not redirect is not evidence about a
	// redirect target.
	URLContains string          `json:"url_contains,omitempty"`
	All         []*ValidityRule `json:"all,omitempty"`
	Any         []*ValidityRule `json:"any,omitempty"`
	Not         *ValidityRule   `json:"not,omitempty"`
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
func (vr *ValidityRule) Evaluate(status int, hdrs map[string]string, body []byte, finalURL string) ValidityState {
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
		note(boolState(bodyMatches(vr, body, vr.BodyContains, false)))
	}
	if vr.BodyNotContains != "" {
		note(boolState(!bodyMatches(vr, body, vr.BodyNotContains, false)))
	}
	if vr.HeaderPresent != "" {
		note(boolState(hasHeader(hdrs, vr.HeaderPresent)))
	}
	if vr.HeaderAbsent != "" {
		note(boolState(!hasHeader(hdrs, vr.HeaderAbsent)))
	}
	if vr.URLContains != "" {
		// A response that did not redirect has no target to test: an unmeasured clause, not a
		// failed one — the same treatment a missing status gets above. Burp reads the redirect
		// target only when there is one.
		switch {
		case finalURL == "":
			note(Indeterminate)
		default:
			note(boolState(bodyMatches(vr, []byte(finalURL), vr.URLContains, false)))
		}
	}
	if vr.All != nil {
		note(evaluateAll(vr.All, status, hdrs, body, finalURL))
	}
	if vr.Any != nil {
		note(evaluateAny(vr.Any, status, hdrs, body, finalURL))
	}
	if vr.Not != nil {
		note(negate(vr.Not.Evaluate(status, hdrs, body, finalURL)))
	}

	if stated == 0 {
		return Indeterminate
	}
	return verdict
}

// bodyMatches runs one body-or-URL condition under the rule's matching dials: a literal
// substring, case-folded unless CaseSensitive, or a compiled regex when Regex is set. `invert`
// is reserved (both call sites already negate in Go) and exists so the signature says what the
// caller asks rather than relying on reading the ! at the call.
//
// A regex that does not compile reports no match rather than panicking: a validity rule is
// configuration, and configuration that crashes the login check would take a whole scan's
// re-authentication with it. Compile-per-call is deliberate — Evaluate runs a handful of times
// per login attempt, not per response on the wire, and caching compiled patterns on the rule
// would need an invalidation story every JSON round-trip would have to honour.
func bodyMatches(vr *ValidityRule, raw []byte, pattern string, invert bool) bool {
	_ = invert
	if vr == nil || pattern == "" {
		return false
	}
	if vr.Regex {
		expr := pattern
		if !vr.CaseSensitive {
			// The prefix is unconditional, because RE2's flag groups compose: `(?i)(?s)x`
			// means both, and an operator's own later flag still wins over this one
			// (`(?i)(?-i)x` stays case-sensitive). An earlier version skipped the prefix for
			// ANY expression beginning `(?`, which silently ignored the Case sensitive
			// checkbox for `(?s)…` and for named groups like `(?P<tok>…)` — the two shapes
			// most likely to open a real pattern — while preventing nothing.
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return false
		}
		return re.Match(raw)
	}
	if vr.CaseSensitive {
		return bytes.Contains(raw, []byte(pattern))
	}
	return bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(pattern)))
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
func evaluateAll(subs []*ValidityRule, status int, hdrs map[string]string, body []byte, finalURL string) ValidityState {
	allV := true
	for _, s := range subs {
		switch s.Evaluate(status, hdrs, body, finalURL) {
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

func evaluateAny(subs []*ValidityRule, status int, hdrs map[string]string, body []byte, finalURL string) ValidityState {
	best := Invalid
	for _, s := range subs {
		switch s.Evaluate(status, hdrs, body, finalURL) {
		case Valid:
			return Valid
		case Indeterminate:
			best = Indeterminate
		}
	}
	return best
}

// ValidateValidityPatterns checks every regex a validity tree states, recursively — All, Any,
// Not all carry their own leaves. Returns the first uncompilable pattern named, or nil.
//
// Why not trust Evaluate's no-match-on-error path: a validity regex that never compiles
// reports no match forever, which reads as "session invalid" or "session valid" depending on
// which clause it sits in — a rule that lies by omission, silently re-logging-in or never
// re-logging-in. Refusing it at the door puts the error where the operator is typing.
func ValidateValidityPatterns(v *ValidityRule) error {
	if v == nil {
		return nil
	}
	if v.Regex {
		for _, pattern := range []string{v.BodyContains, v.BodyNotContains, v.URLContains} {
			if pattern == "" {
				continue
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("validity regex %q does not compile: %w", pattern, err)
			}
		}
	}
	for _, sub := range v.All {
		if err := ValidateValidityPatterns(sub); err != nil {
			return err
		}
	}
	for _, sub := range v.Any {
		if err := ValidateValidityPatterns(sub); err != nil {
			return err
		}
	}
	return ValidateValidityPatterns(v.Not)
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
	// Prefix, Suffix and URLEncoded are Burp's "Define Custom Parameter" fields for a macro item's
	// custom parameter (burpsy-react-ui-355h): "Parameter value prefix (optional)", "Parameter
	// value suffix (optional)" and "Extracted value is URL-encoded" (url_encoded). The value a later
	// step receives is prefix + extracted + suffix. URLEncoded is a pointer so a rule saved before it
	// existed keeps substituting the value literally: true says the value is already URL-encoded
	// (literal, as before); false says it is raw, so it is percent-encoded where it is substituted.
	Prefix     string `json:"prefix,omitempty"`
	Suffix     string `json:"suffix,omitempty"`
	URLEncoded *bool  `json:"url_encoded,omitempty"`
	re         *regexp.Regexp
	path       jsonPath
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
	out := e.runRaw(hdrs, body)
	if e != nil && out.Outcome.Resolved() && out.Value != "" {
		value := e.Prefix + out.Value + e.Suffix
		if e.URLEncoded != nil && !*e.URLEncoded {
			value = url.QueryEscape(value)
		}
		out.Value = value
	}
	return out
}

// runRaw is RunResult before the custom-parameter prefix, suffix and encoding are applied.
func (e *Extraction) runRaw(hdrs map[string]string, body []byte) ExtractResult {
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

// jarCookie is one stored cookie with the attributes RFC 6265 §5.3 says a storage model keeps:
// its path and domain (which decide where it is sent), its expiry, and the Secure flag (which
// decides whether it is sent at all on a plaintext connection).
//
// Attributes were dropped when the jar was name->value, with a comment disclosing the
// simplification. The disclosure was honest and the state it described was not fixable in the UI:
// two cookies differing only by path cannot be held in a map keyed on name, so there was nothing
// to display. This struct is the fix the disclosure asked for — the jar now *has* the attributes
// and enforces them, so a column can report a fact rather than imply one. An operator reading
// "Path=/admin" in the table now has the jar's actual behaviour behind it, which is the difference
// between a column and a lie.
type jarCookie struct {
	Value string
	Path  string
	// Domain is the cookie's own Domain attribute, verbatim minus the leading dot; empty means
	// host-only. The jar key is (domain, path, name) per §5.3's storage model, so this is the key
	// component, not a display extra.
	Domain string
	// Expires is zero for a session cookie. A zero time is not "never" in RFC 6265 terms — a
	// Max-Age or Expires in the past is a deletion instruction — and expiryFilter keeps that
	// distinction by only judging cookies that carry a real time.
	Expires time.Time
	// Secure keeps the cookie out of plaintext requests (§5.4 step 1). Stored rather than assumed,
	// because the flag travels with the Set-Cookie that carried it and the jar's authority key
	// already includes a tls bool of its own: the two are different facts, one about the cookie and
	// one about the connection the cookie was learned on.
	Secure bool
	// HttpOnly has no send-time behaviour to enforce — it constrains document.cookie, not the
	// Cookie header, and burpsy has no document. It is kept anyway: the jar is also the operator's
	// view of what the server set, and a flag a real server set disappearing between the response
	// and the table is a lie told for tidiness.
	HTTPOnly bool
}

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
	// m is keyed (domain|path|name) — the three components §5.3 says distinguish two cookies. The
	// separator is a control character that cannot appear in any of the three, so a cookie named
	// with a pipe in it cannot alias another cookie's key.
	m map[string]jarCookie
}

func newCookieJar(host string, port uint16, tls bool) *cookieJar {
	return &cookieJar{host: host, port: port, tls: tls, m: make(map[string]jarCookie)}
}

// jarKey is the (domain, path, name) storage key. Name-last so that a two-cookie family
// (same domain and path, different names) is adjacent in iteration order and, more to the
// point, so that RemoveCookie(name) can find every cookie the name covers — two authorities'
// jars are separate maps, but within one jar a name can exist at several paths.
func jarKey(domain, path, name string) string {
	return domain + "\x01" + path + "\x01" + name
}

// CookieJarEntry is one authority's jar, flattened for reporting.
// CookieAttrs is one cookie as the wire and the table see it: the name, the value, and every
// §5.3 attribute the jar models. The value-only shape this replaces could say that a cookie
// existed and nothing else — which made a Path column impossible, because the jar held no
// path to report (burpsy-react-ui-d18r).
//
// Name is on the row itself, not carried by a map key, because the jar's storage key is
// (domain, path, name) and two cookies share a name while differing on the other two — the
// exact case d18r's key was built to preserve. The old map[name]CookieAttrs projection here
// overwrote one of every such pair before the API ever serialized it: a live fixture sending
// DISPLAY_CHECK at Path=/ and at Path=/admin produced one table row where the jar held two
// (burpsy-react-ui-loa1). A slice with the name inside keeps both.
type CookieAttrs struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Path  string `json:"path,omitempty"`
	// Domain is the cookie's Domain attribute (empty = host-only), not the jar's authority. Both
	// are reported because they differ for a domain cookie and the difference is the point.
	Domain   string    `json:"domain,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	HTTPOnly bool      `json:"http_only,omitempty"`
}

type CookieJarEntry struct {
	Host    string
	Port    uint16
	TLS     bool
	Cookies []CookieAttrs
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
			// A slice, not a map: the map keyed by name is what collapsed two same-name
			// path-scoped cookies into one row. The name rides on the row, and the sort is
			// (name, domain, path) so a name's path variants stay adjacent — the order an
			// operator scanning for "which paths is my session cookie good for" reads.
			cookies := make([]CookieAttrs, 0, len(jar.m))
			for k, c := range jar.m {
				name := k[strings.LastIndex(k, "\x01")+1:]
				cookies = append(cookies, CookieAttrs{
					Name: name, Value: c.Value, Path: c.Path, Domain: c.Domain,
					Expires: c.Expires, Secure: c.Secure, HTTPOnly: c.HTTPOnly,
				})
			}
			sort.Slice(cookies, func(a, b int) bool {
				if cookies[a].Name != cookies[b].Name {
					return cookies[a].Name < cookies[b].Name
				}
				if cookies[a].Domain != cookies[b].Domain {
					return cookies[a].Domain < cookies[b].Domain
				}
				return cookies[a].Path < cookies[b].Path
			})
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

// cookieHeader builds the Cookie header for a request to this authority's host and path.
//
// RFC 6265 §5.4, the four rules that make a cookie belong to a request rather than to an
// authority: domain-match, path-match, expiry, and Secure-only-over-TLS. All four act here,
// per request, because every one of them is a decision about THIS request — a jar that
// pre-filtered at absorb time would have to guess the request's path, scheme and clock, and
// would be right only by accident.
//
// Ordering: name-sorted within the jar's copy, the same stable order cookieHeader has always
// produced. §5.4's longer-paths-first rule is a SHOULD for user agents, and the difference it
// makes — which of two name-equal path-matching cookies wins — cannot arise here, because
// the storage key includes the path and the header emits both.
func (j *cookieJar) cookieHeader(path string) string {
	return j.cookieHeaderFor(j.host, j.port, j.tls, path)
}

// cookieHeaderFor answers for a request to (host, tls, path) using this jar's cookies. The
// authority split exists so the operator's table can group by authority; it is not a §5.4
// boundary. A Domain=.app.test cookie set at app.test belongs to sub.app.test's requests too,
// and the rule that says so compares the cookie's own Domain attribute against the request's
// host — never the jar's. The jar's own tls flag is likewise not the request's: the manager
// calls this for the exact authority when no other jar matches, and then jar and request agree,
// but a domain cookie crossing jars must be judged by the request the header is being built for.
// cookieHeaderPairs collects the (name, value) pairs this jar would contribute to a request to
// (host, port, tls, path), after the full §5.4 filter. Shared by cookieHeaderFor (the string
// form) and CookieJarManager.CookieHeader (the cross-jar scan, which needs pairs so it can
// dedupe names).
func (j *cookieJar) cookieHeaderPairs(host string, port uint16, tls bool, path string) []cookiePair {
	j.RLock()
	defer j.RUnlock()
	pairs := make([]cookiePair, 0, len(j.m))
	now := time.Now()
	for k, c := range j.m {
		if c.Domain == "" {
			// §5.3: a cookie with no Domain attribute is host-only — it matches exactly the
			// authority it was set on (host, port, tls), which is this jar's own and never a
			// cross-jar one. The port and TLS separation is the engagement boundary this jar
			// has always enforced: a session set on 443 must not ride a request to the same
			// host on 8080, which is a different service, or over plaintext, which is the
			// same service failing its own Secure policy.
			if !strings.EqualFold(strings.TrimSpace(host), j.host) || port != j.port || tls != j.tls {
				continue
			}
		} else if !domainMatches(c.Domain, host) {
			continue
		}
		if !pathMatches(c.Path, path) {
			continue
		}
		if !c.Expires.IsZero() && !now.Before(c.Expires) {
			continue
		}
		if c.Secure && !tls {
			continue
		}
		// The name is the third component of the jar key, after the last separator.
		name := k[strings.LastIndex(k, "\x01")+1:]
		pairs = append(pairs, cookiePair{name, c.Value})
	}
	sort.Slice(pairs, func(a, b int) bool { return pairs[a].name < pairs[b].name })
	return pairs
}

// cookieHeaderFor answers for a request to (host, tls, path) using this jar's cookies. The
// authority split exists so the operator's table can group by authority; it is not a §5.4
// boundary. A Domain=.app.test cookie set at app.test belongs to sub.app.test's requests too,
// and the rule that says so compares the cookie's own Domain attribute against the request's
// host — never the jar's. The request's tls flag judges Secure, not the jar's own.
func (j *cookieJar) cookieHeaderFor(host string, port uint16, tls bool, path string) string {
	pairs := j.cookieHeaderPairs(host, port, tls, path)
	if len(pairs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.name+"="+p.value)
	}
	return strings.Join(parts, "; ")
}

// domainMatches implements RFC 6265 §5.1.3. An empty domain is a host-only cookie: it matches
// exactly the host it was set on and nothing else, which is also what §5.3 says a cookie with no
// Domain attribute is. A set domain matches itself and any subdomain of itself, case-insensitively
// (hostnames are). The IP-literal exception (a Domain that is an IP matches only exactly) is not
// special-cased because a dotted IP is nobody's subdomain under the string rule: it fails the
// last-dot boundary and reads as no-match, which is the same answer.
func domainMatches(domain, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		// A host-only cookie matches exactly the host it was set on, and this function does
		// not know that host — only the caller's jar does. Answering false here is what keeps
		// a host-only cookie from leaking across authorities in the manager's cross-jar scan;
		// the caller handles the empty-domain case itself before ever calling this.
		return false
	}
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// pathMatches implements RFC 6265 §5.1.4: exact, or the cookie's path is a prefix of the request's
// path that ends on a boundary. The default-path rule (§5.1.4 defaults a cookie with no Path
// attribute to the set's directory) is applied at absorb time, so an empty Path here is the
// attribute's own empty string — a cookie explicitly set with `Path=` — and §5.1.4's answer for
// an empty cookie-path is "matches everything", which is what the fallthrough gives.
func pathMatches(cookiePath, requestPath string) bool {
	if cookiePath == "" {
		return true
	}
	if cookiePath == requestPath {
		return true
	}
	if strings.HasPrefix(requestPath, cookiePath) {
		if strings.HasSuffix(cookiePath, "/") {
			return true
		}
		if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true
		}
	}
	return false
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
// set writes one cookie, replacing any previous value for the name. Same lock discipline as
// absorb: the jar's own mutex, because a concurrent response absorb and an operator edit race
// on the same map.
// updateSent sets the value of every cookie named name that this jar would send with a request to
// (host, port, tls, path), by cookieHeaderPairs' matching rules. It reports whether any matched.
func (j *cookieJar) updateSent(host string, port uint16, tls bool, path, name, value string) bool {
	j.Lock()
	defer j.Unlock()
	now := time.Now()
	found := false
	for k, c := range j.m {
		if k[strings.LastIndex(k, "\x01")+1:] != name {
			continue
		}
		if c.Domain == "" {
			if !strings.EqualFold(strings.TrimSpace(host), j.host) || port != j.port || tls != j.tls {
				continue
			}
		} else if !domainMatches(c.Domain, host) {
			continue
		}
		if !pathMatches(c.Path, path) || (!c.Expires.IsZero() && !now.Before(c.Expires)) || (c.Secure && !tls) {
			continue
		}
		c.Value = value
		j.m[k] = c
		found = true
	}
	return found
}

func (j *cookieJar) set(name, value string) {
	j.Lock()
	j.m[jarKey("", "/", name)] = jarCookie{Value: value, Path: "/"}
	j.Unlock()
}

// remove deletes one cookie and reports whether it was there.
func (j *cookieJar) remove(name string) bool {
	// Every cookie the name covers, not one: with path-scoped cookies a name can exist at several
	// paths, and "remove" that left the other paths behind would answer true while the jar still
	// sent a cookie the operator believes they deleted.
	j.Lock()
	defer j.Unlock()
	found := false
	for k := range j.m {
		if name == k[strings.LastIndex(k, "\x01")+1:] {
			delete(j.m, k)
			found = true
		}
	}
	return found
}

// clear empties the jar's map, keeping the jar itself for the authority.
func (j *cookieJar) clear() {
	j.Lock()
	j.m = make(map[string]jarCookie)
	j.Unlock()
}

func (j *cookieJar) absorb(val string) {
	// §5.3: the name/value pair first, then the attributes. The old absorb stopped at the first
	// semicolon and stored the pair — the fix for the bug where every attribute became its own
	// cookie — and the comment on it disclosed that attributes were dropped. This pass keeps them,
	// because keeping them is what makes the jar's own §5.4 rules enforceable and its table
	// truthful. An attribute this reader does not model (SameSite, Priority) is skipped by name:
	// skipping silently is right here, since §5.3 says a storage model keeps what it can use and
	// ignores the rest, and inventing a partial SameSite would be worse than not holding it.
	first, rest, _ := strings.Cut(val, ";")
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
	c := jarCookie{Value: value, Path: defaultPath("/", j.host)}
	for part := rest; ; {
		var attr string
		attr, part, _ = strings.Cut(part, ";")
		attr = strings.TrimSpace(attr)
		if attr == "" {
			if part == "" {
				break
			}
			continue
		}
		key, av, hasValue := strings.Cut(attr, "=")
		key = strings.TrimSpace(key)
		lowerKey := strings.ToLower(key)
		switch lowerKey {
		case "path":
			// §5.1.4: a Path that does not start with / is ignored and the default stands.
			if hasValue && strings.HasPrefix(av, "/") {
				c.Path = av
			}
		case "domain":
			// §5.3: strip one leading dot, case-fold. A domain the host cannot match is kept
			// anyway: §5.1.3 rejects it at *send* time, and rejecting it at absorb time would
			// delete a cookie the server really set — the jar is the record of what the server
			// said as well as the thing that sends cookies.
			if hasValue {
				c.Domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(av), "."))
			}
		case "expires":
			// RFC 6265 §5.1.1's cookie-date grammar. Go's time package parses the two forms the
			// grammar's three permitted separators and two year spellings produce (RFC 1123 and
			// the asctime form), which is every date a real Set-Cookie carries.
			if hasValue {
				if t, err := http.ParseTime(strings.TrimSpace(av)); err == nil {
					c.Expires = t
				}
			}
		case "max-age":
			// §5.2.2: seconds from now. §5.3's "a Max-Age of 0 or negative deletes": a zero or
			// negative value marks the cookie as already-expired rather than deleting it in place,
			// so the table shows a cookie the server withdrew and the header stops sending it —
			// the same observable behaviour as deleting, but not silent about what happened.
			if hasValue {
				if n, err := strconv.Atoi(strings.TrimSpace(av)); err == nil {
					if n <= 0 {
						c.Expires = time.Now().Add(-1 * time.Second)
					} else {
						c.Expires = time.Now().Add(time.Duration(n) * time.Second)
					}
				}
			}
		case "secure":
			c.Secure = true
		case "httponly":
			c.HTTPOnly = true
		}
		if part == "" {
			break
		}
	}
	j.Lock()
	defer j.Unlock()
	j.m[jarKey(c.Domain, c.Path, name)] = c
}

// defaultPath is §5.1.4's default-path: the directory of the request URI that carried the
// Set-Cookie, or "/" when the URI has no "/". This jar is created per authority on the first
// Set-Cookie it sees and the wire path of that first response is not kept — the jar's contract is
// host-keyed — so the default is "/" and the honest statement is that the jar sends cookies to
// every path until a Path attribute narrows them, which is exactly what §5.1.4 with a "/" default
// does. A cookie carrying its own Path attribute is never defaulted.
func defaultPath(_, _ string) string { return "/" }

// cookiePair is one name=value the jar would send. A tiny named type rather than a closure-local
// struct because the manager's cross-jar scan needs to dedupe by name across jars, and a local
// type would make the pairs unnameable outside this function.
type cookiePair struct{ name, value string }

type CookieJarManager struct {
	mu   sync.RWMutex
	jars map[string]*cookieJar
}

func NewCookieJarManager() *CookieJarManager {
	return &CookieJarManager{jars: make(map[string]*cookieJar)}
}

// CookieHeader answers for a request to this authority and path. The exact-authority jar is
// consulted first and separately, because a host-only cookie's domain-match is judged against
// the jar's own host — but the authority split is not a §5.4 boundary. A Domain=.app.test cookie
// absorbed at app.test belongs to sub.app.test's requests too, so after the exact jar every
// other jar is scanned and each cookie's own Domain attribute is judged against the request's
// host. Cookies from the exact jar are added first and a name must appear at most once in a
// Cookie header: the exact jar wins a name clash, and among other jars the low-authority host
// (the jar whose host is the longest suffix match — the cookie was set deepest in the tree)
// has no precedence rule in RFC 6265, so the stable order is jar creation order under the
// manager's sorted jar list, and the first claim on a name wins.
func (cjm *CookieJarManager) CookieHeader(host string, port uint16, tls bool, path string) string {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.RLock()
	jar := cjm.jars[key]
	// Snapshot the other jars under the manager lock, then judge each outside it: a jar's own
	// mutex is the one that serialises absorb against this read, not the manager's.
	others := make([]*cookieJar, 0, len(cjm.jars))
	for k, other := range cjm.jars {
		if k != key && other != nil {
			others = append(others, other)
		}
	}
	cjm.mu.RUnlock()
	var b strings.Builder
	taken := make(map[string]bool)
	if jar != nil {
		for _, p := range jar.cookieHeaderPairs(host, port, tls, path) {
			b.WriteString(p.name)
			b.WriteByte('=')
			b.WriteString(p.value)
			b.WriteString("; ")
			taken[p.name] = true
		}
	}
	// Sorted for determinism: jar iteration order is Go map order, and a header whose pairs
	// reshuffle between requests is one an operator cannot diff.
	slices.SortFunc(others, func(a, bb *cookieJar) int {
		if a.host != bb.host {
			return strings.Compare(a.host, bb.host)
		}
		if a.port != bb.port {
			return int(a.port) - int(bb.port)
		}
		if a.tls != bb.tls {
			if a.tls {
				return -1
			}
			return 1
		}
		return 0
	})
	for _, other := range others {
		for _, pr := range other.cookieHeaderPairs(host, port, tls, path) {
			if taken[pr.name] {
				continue
			}
			taken[pr.name] = true
			b.WriteString(pr.name)
			b.WriteByte('=')
			b.WriteString(pr.value)
			b.WriteString("; ")
		}
	}
	out := b.String()
	// The exact jar's list and each other jar's list both end with "; " separators; the join
	// convention this jar has always used is "n=v; n=v" — trim the final separator.
	if strings.HasSuffix(out, "; ") {
		out = strings.TrimSuffix(out, "; ")
	}
	return out
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

// SetCookie writes one cookie into the authority's jar, creating the jar when it does not
// exist — the same creation rule AbsorbSetCookie applies. This is the operator's hand behind
// the jar (dkb): Burp's cookie jar dialog says "you can edit cookies manually", and the
// writer-side value here is exactly what AbsorbSetCookie would have stored from a response's
// Set-Cookie: name -> value, attributes deliberately dropped (the same disclosed
// simplification — see the attribute note on the jar).
// AbsorbRequestCookie records one cookie the browser sent on a request to (host, port, tls, path)
// (sm1k). Every jar cookie that would be sent with this request under this name takes the browser's
// value and keeps its attributes. When none would be, the cookie is added to the authority's own jar,
// host-only at Path=/.
func (cjm *CookieJarManager) AbsorbRequestCookie(host string, port uint16, tls bool, path, name, value string) {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.Lock()
	jar := cjm.jars[key]
	if jar == nil {
		jar = newCookieJar(host, port, tls)
		cjm.jars[key] = jar
	}
	all := make([]*cookieJar, 0, len(cjm.jars))
	for _, j := range cjm.jars {
		if j != nil {
			all = append(all, j)
		}
	}
	cjm.mu.Unlock()
	updated := false
	for _, j := range all {
		if j.updateSent(host, port, tls, path, name, value) {
			updated = true
		}
	}
	if !updated {
		jar.set(name, value)
	}
}

func (cjm *CookieJarManager) SetCookie(host string, port uint16, tls bool, name, value string) {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.Lock()
	jar := cjm.jars[key]
	if jar == nil {
		jar = newCookieJar(host, port, tls)
		cjm.jars[key] = jar
	}
	cjm.mu.Unlock()
	jar.set(name, value)
}

// RemoveCookie deletes one cookie by name from the authority's jar and reports whether it was
// there. Deleting a jar's last cookie does NOT delete the jar: an empty jar is a fact about an
// authority the operator has visited (and the GET view skips empty jars anyway), while a
// missing jar would make "remove" on a stale authority look like a silent success.
func (cjm *CookieJarManager) RemoveCookie(host string, port uint16, tls bool, name string) bool {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.RLock()
	jar := cjm.jars[key]
	cjm.mu.RUnlock()
	if jar == nil {
		return false
	}
	return jar.remove(name)
}

// ClearJar empties one authority's jar and reports whether it existed. It is the jar's
// contents that the operator empties — "empty the jar altogether" (Burp's cookie jar dialog)
// — not the authority's record; the next response's Set-Cookie re-creates whatever it likes
// either way.
func (cjm *CookieJarManager) ClearJar(host string, port uint16, tls bool) bool {
	key := fmt.Sprintf("%s:%d_%v", host, port, tls)
	cjm.mu.Lock()
	jar := cjm.jars[key]
	if jar == nil {
		cjm.mu.Unlock()
		return false
	}
	cjm.mu.Unlock()
	jar.clear()
	return true
}

// --- SessionRule ---

type RuleID int64

const DefaultMaxAttempts = 3

type SessionRule struct {
	ID         RuleID   `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	ScopeHosts []string `json:"scope_hosts"`
	// ScopeParams is Burp's parameter scope (session-handling-rules.html): when set, the rule
	// applies only to requests carrying every named parameter — "update a certain parameter
	// across all requests, such as a CSRF token". Nil/empty is the unrestricted rule, exactly
	// what every rule built before this field existed means, so MatchParams reads an empty
	// list as "always applies" the same way MatchHost reads empty hosts.
	ScopeParams []string `json:"scope_params,omitempty"`
	// ScopeMode is Burp's URL-scope radio (7nh2), from Zgw7's own labels: "all" = Include all
	// URLs, "suite" = Use suite scope [defined in Target tab], "custom" = Use custom scope.
	// Empty means "all" — every rule built before the field existed applies everywhere, which is
	// exactly what MatchHost's empty-hosts reading already said, so the two emptinesses agree.
	ScopeMode string `json:"scope_mode,omitempty"`
	// ScopePathPrefix limits a custom-scope rule to requests whose path starts with it;
	// ScopePort to one port; ScopeProtocol to one scheme. All three optional — a custom
	// rule with none of them is the historical host-pattern-only scope, unchanged.
	ScopePathPrefix string  `json:"scope_path_prefix,omitempty"`
	ScopePort       *uint16 `json:"scope_port,omitempty"`
	ScopeProtocol   string  `json:"scope_protocol,omitempty"`
	// ScopeTools is Burp's tools scope (so3): when non-empty, the rule applies only to requests
	// attributed to one of the named tools; empty means every tool, the same reading MatchHost
	// gives an empty host list. The names are toollog's tool names ("repeater", "intruder",
	// "scanner", "sequencer", "crawler", "proxy", …) and this package treats them as opaque
	// strings it compares for equality, exactly as it treats a host pattern — the vocabulary
	// belongs to internal/toollog and is enforced where the wire and the durable mirror meet.
	//
	// Describing the axis as names rather than ordinals is deliberate: an ordinal from another
	// package's enum would be a number this package's persisted JSON and SQLite rows could not
	// be read back from once that enum's order changed, which toollog's own Tool doc says is
	// exactly why a new tool goes on the end and never in the middle.
	ScopeTools []string `json:"scope_tools,omitempty"`
	// Actions is the ordered list of actions this rule performs, Burp's own model — see
	// actions.go for the nine kinds, the one declined, and why the list is a flat ordered walk with
	// conditionality nesting only inside a validity check.
	//
	// Empty is not "a rule that does nothing": EffectiveActions synthesises the pre-action shape
	// (check validity, then run the macro) from Steps/Validity/MaxAttempts, and NormaliseActions
	// writes that list on at the door every rule enters through. So a rule loaded from a project
	// written before actions existed runs exactly what it ran before, and an operator who writes a
	// rule from scratch always has an explicit list to edit.
	Actions []*Action `json:"actions,omitempty"`
	// Steps is the rule's macro: what a RunMacro action with no Macro of its own runs, and what
	// every rule that predates actions keeps as its login flow. Kept rather than folded into the
	// action list so a saved project's macro, its extractions and "update macro" all go on working.
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

// RequestIdentity is what a session rule needs to know about one request to answer the scope
// question: the host is the axis MatchingRule always had; Path, Port and TLS carry the custom-scope
// arms Burp's URL-matching rules specify (protocol/host/port/path, 7nh2); Tool carries the tools
// scope (so3).
type RequestIdentity struct {
	Host string
	Path string
	Port uint16
	TLS  bool
	// Tool names the tool making this request, in toollog's vocabulary, or "" when the caller
	// cannot say.
	//
	// Empty is not "some other tool" and must not be read as one: an unattributed request still
	// matches a tool-restricted rule (see MatchTools), because the alternative is the failure mode
	// MatchHost's doc calls the worst a session rule can have — a rule that is enabled, listed,
	// and silently never fires. Every caller in this tree that can attribute a request does so;
	// the host-only convenience entry points (MatchingRule, MatchingRuleFor, HandleResponse)
	// cannot, and a rule restricted to the crawler must not stop handling a request those paths
	// carry.
	Tool string
}

// MatchRequest answers the URL-scope question for one request. Suite mode delegates to the
// caller's suite-scope verdict — the session package cannot see the Target scope, so the web
// layer passes scopeContains and this method only routes; custom mode adds the path/port/
// protocol arms to the host axis; all mode is the historical everywhere rule.
//
// The suite delegation is a parameter rather than a field because the suite scope is live
// state the Target tab can change while a rule exists; capturing it on the rule would freeze a
// scope snapshot into session handling and quietly diverge from what the operator sees.
func (r *SessionRule) MatchRequest(req RequestIdentity, scopeContains func() bool) bool {
	if r == nil {
		return false
	}
	// The tool axis is checked before the mode branch rather than inside MatchCustomArms,
	// because it is orthogonal to the URL axis: a rule in "Use suite scope" mode is still
	// restricted to the tools it names, and routing the check through the custom arms would
	// have left every suite-mode rule applying to every tool — a tool restriction that holds
	// only half the time, which reads to an operator as the restriction being ignored.
	if !r.MatchTools(req.Tool) {
		return false
	}
	if r.ScopeMode == "suite" {
		if scopeContains == nil {
			// A rule configured for the suite scope in a process with no scope answer has
			// nothing to match; refusing is the honest answer and the web layer always
			// supplies the predicate.
			return false
		}
		return scopeContains()
	}
	// "custom" and the default ("all", plus the empty pre-field reading) are the rule's own stated
	// arms: a host list, optionally narrowed by a path prefix, a port and a scheme.
	return r.MatchCustomArms(req)
}

// MatchTools says whether this rule's tools scope covers a request made by `tool` (so3).
//
// Empty ScopeTools applies everywhere, for the reason MatchHost's empty host list does: the rules
// every operator already has state no tools scope, and reading their silence as "matches no tool"
// would leave each of them enabled, listed, and unable to fire.
//
// An empty `tool` also applies, and that direction is the deliberate one. "" is a caller saying it
// does not know which tool made the request — the host-only entry points that predate this axis —
// not a claim that the tool was something out of scope. Refusing would make a tool-restricted rule
// vanish for those callers, which is a silent loss of session handling on traffic the rule was
// written to handle; over-matching here is visible (the rule fires where the operator named it) and
// recoverable, while under-matching is not visible at all. Every caller that *can* attribute a
// request in this tree does, so the hole is a narrow one rather than the common path.
//
// Comparison is exact, and expected to be: tool names are a closed vocabulary whose owner
// (internal/toollog) refuses to resolve anything unrecognised via ToolFromName, so a near-miss
// cannot be spelled here — an unrecognised name is refused at the wire instead of being compared
// loosely and matching by accident.
func (r *SessionRule) MatchTools(tool string) bool {
	if r == nil {
		return false
	}
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

// MatchCustomArms answers the URL-scope question from the rule's own stated arms alone (7nh2),
// without the suite-mode delegation — hence "custom", which is Burp's own name for the mode these
// arms belong to.
//
// RunMacro needs the distinction: a suite-mode rule delegates the scope question to the Target
// scope, but a macro's steps are the operator's explicit configuration, so judging them against the
// Target scope would skip the login POST whenever the login URL happened to sit outside it, leaving
// a rule that is configured, matched, and can never log in. The arms a rule states about itself are
// the only scope a step may be skipped for.
func (r *SessionRule) MatchCustomArms(req RequestIdentity) bool {
	if r == nil {
		return false
	}
	if !r.MatchHost(req.Host) {
		return false
	}
	if r.ScopePathPrefix != "" && !strings.HasPrefix(req.Path, r.ScopePathPrefix) {
		return false
	}
	if r.ScopePort != nil && req.Port != *r.ScopePort {
		return false
	}
	if r.ScopeProtocol != "" {
		scheme := "http"
		if req.TLS {
			scheme = "https"
		}
		if !strings.EqualFold(r.ScopeProtocol, scheme) {
			return false
		}
	}
	return true
}

// StatesURLArms reports whether the rule's own URL-scope arms restrict anything (7nh2): a path
// prefix, a port or a scheme.
//
// Exported because two other layers ask the same question: validate.go's stated-but-empty refusal,
// which used to be a question about the host list alone ("no hosts" stopped being the same as
// "states nothing" once a rule could be scoped by path or port with no host restriction), and the
// web layer's ruleToDto, which must not drop a scope block that holds only arms.
func (r *SessionRule) StatesURLArms() bool {
	return r != nil && (r.ScopePathPrefix != "" || r.ScopePort != nil || r.ScopeProtocol != "")
}

// MatchParams says whether this rule's parameter scope covers a request whose parsed parameters
// are named in `present`. Every name in ScopeParams must be carried by the request; an empty
// scope applies everywhere, for the same reason MatchHost's empty list does — a rule built
// without the restriction cannot be allowed to silently stop matching.
//
// The comparison is case-insensitive: HTTP parameter names have no case-sensitivity contract,
// and Burp treats csrf_token and CSRF_Token as the same parameter here. A name that arrives
// with different casing is the same parameter the operator named.
func (r *SessionRule) MatchParams(present []string) bool {
	if r == nil || len(r.ScopeParams) == 0 {
		return true
	}
	have := make(map[string]bool, len(present))
	for _, p := range present {
		have[strings.ToLower(p)] = true
	}
	for _, want := range r.ScopeParams {
		if !have[strings.ToLower(want)] {
			return false
		}
	}
	return true
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
// NewSessionRule builds the inert spec for a rule: name, scope, macro. It does not add an action
// list — a caller that wants the list materialised calls NormaliseActions, and Coordinator.AddRule
// does it at the door. Leaving it out here is deliberate: this constructor is also what tests and
// DTO conversions use to build a rule field by field, and a list materialised at construction would
// then be stale the moment the caller set Validity or MaxAttempts afterwards.
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
	mu    sync.RWMutex
	rules map[RuleID]*SessionRule
	// tokenRules is the project-level extraction+injection set (burpsy-react-ui-xe82); tokenValues
	// holds the latest value each rule's extraction captured, guarded by tokenMu like the script
	// stores - a response being observed must not hold the rule table's lock.
	tokenRules  map[string]*TokenRule
	tokenOrder  []string
	tokenMu     sync.Mutex
	tokenValues map[string]string
	// scriptStores is each rule's pre-request script store (burpsy-react-ui-ydmj): the small string
	// map a RunScript action reads and writes through `store`, kept across requests so a token
	// captured from one response is there for the next request. Per rule, so two rules' scripts
	// cannot read each other's captured credentials. Guarded by scriptMu, not mu — a script run must
	// not hold the rule table's lock.
	scriptMu     sync.Mutex
	scriptStores map[RuleID]map[string]string
	order        []RuleID
	nextID       int64
	jarMgr       *CookieJarManager
	logger       *zap.Logger

	// tracer is the opt-in session-handling tracer (burpsy-react-ui-n29). Off by default —
	// see tracer.go for why an always-on tracer is the wrong default — and while off its
	// only per-request cost is one atomic load.
	tracer traceRing

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

	// suiteScope is the live suite-scope (Target scope) verdict, installed once by whichever console
	// owns a Target scope (7nh2). It exists because the in-package match sites — HandleRecovery above
	// all — run inside this package, where no scope handle is in reach, and a suite-scoped rule must
	// not become silently unreachable from them. A caller that owns a scope passes its own predicate
	// to MatchingRuleForRequest instead; that one wins, because the caller is closer to the request.
	suiteScope func(RequestIdentity) bool

	// extensionInvoker is the extension host, when one is attached, for the invoke-extension rule
	// action. A seam rather than an import: internal/extension sits above this package in the
	// dependency direction, so this package declares the one method it needs and the console adapts
	// its host to it. Nil is a valid state, and the action reports it rather than doing nothing
	// quietly — see actionWalk.invokeExtension.
	extensionInvoker SessionActionInvoker

	// sessionPrompter is the console's "ask the operator" surface, when one is attached, for the
	// prompt-for-browser-recovery rule action. Same seam reasoning as extensionInvoker: the console
	// sits above this package in the dependency direction, so this package declares the one method
	// it needs and the console adapts its prompt UI to it. Nil is a valid state — a headless
	// process has nobody to ask — and the action reports that rather than waiting on a person who
	// was never asked. See actionWalk.promptForBrowserRecovery.
	sessionPrompter SessionPrompter

	// validityCounters counts the requests each rule has handled, for Burp's
	// `validate_every_num_requests` (us12): a check with an interval of N evaluates the session only
	// on every Nth request. Per rule, because the field counts the requests the RULE handles, so two
	// checks on one rule advance the same count once.
	//
	// Session state, not durable state: the count is a running cost decision, and restoring it from
	// the database would make a rule's behaviour depend on when the process last stopped. A restart
	// begins again at the first request, which is the safe direction — the next check comes no later
	// than one interval.
	validityCounters   map[RuleID]int64
	validityCountersMu sync.Mutex
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

// SetSuiteScopePredicate installs the live suite-scope verdict that suite-mode rules are matched
// against (7nh2).
//
// A function read at match time rather than a bool captured at install time, and consulted per
// request rather than stored on a rule: the Target tab can change the scope while a rule exists, and
// freezing a snapshot into session handling would have the rule keep matching a scope the operator
// has since narrowed — the divergence this feature exists to remove. Nil (the default) leaves a
// suite-mode rule matching nothing, which is the honest answer for a process with no Target scope;
// MatchRequest's refusal is documented there.
func (c *Coordinator) SetSuiteScopePredicate(f func(RequestIdentity) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.suiteScope = f
}

// Cookies reports every cookie the coordinator is holding, per authority. The jar manager is
// private, so this is how /api/session/cookies asks — see CookieJarManager.Jars for why the route
// could not previously answer honestly.
func (c *Coordinator) Cookies() []CookieJarEntry { return c.jarMgr.Jars() }

// AbsorbCookie stores one Set-Cookie value through the jar (test and tooling seam over
// jarMgr.AbsorbSetCookie, which the response paths call directly).
func (c *Coordinator) AbsorbCookie(host string, port uint16, tls bool, val string) {
	c.jarMgr.AbsorbSetCookie(host, port, tls, val)
}

// SetCookie writes one cookie into an authority's jar (dkb) — the operator's hand behind the
// jar, Burp's "edit cookies manually". Creation rule identical to AbsorbSetCookie's.
func (c *Coordinator) SetCookie(host string, port uint16, tls bool, name, value string) {
	c.jarMgr.SetCookie(host, port, tls, name, value)
}

// RemoveCookie deletes one cookie from an authority's jar (dkb) and reports whether it was there.
func (c *Coordinator) RemoveCookie(host string, port uint16, tls bool, name string) bool {
	return c.jarMgr.RemoveCookie(host, port, tls, name)
}

// ClearJar empties one authority's jar (dkb) — Burp's "empty the jar altogether" — and reports
// whether the authority had a jar at all.
func (c *Coordinator) ClearJar(host string, port uint16, tls bool) bool {
	return c.jarMgr.ClearJar(host, port, tls)
}

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
	// Materialised at the door, after validation and before the rule is reachable: from here on
	// there is exactly one shape of rule in the tree, so the executor, the persisted row and the
	// wire answer all describe the same list (see NormaliseActions).
	rule.NormaliseActions()
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
	// The second door, and the one a project written before actions comes through: a rule whose
	// `actions` column is absent loads with an empty list and acquires the synthesised one here, so
	// the migration happens once per stored rule rather than in every reader.
	rule.NormaliseActions()
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
	rule.NormaliseActions()
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

// AddExtraction appends one extraction to a rule (burpsy-react-ui-e23c — the apply half of
// Re-analyze). Built as its own method rather than "read, mutate, UpdateRule" in a caller,
// because UpdateRule replaces the whole rule and two racing applies would drop each other's
// extractions; the add is one lock hold, and a name that is already there is refused rather
// than duplicated — a duplicate would make {{name}} resolve to whichever extraction the map
// happened to hold last, which is a resolution nobody can debug.
func (c *Coordinator) AddExtraction(id RuleID, ex *Extraction) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rule := c.rules[id]
	if rule == nil {
		return fmt.Errorf("%w: %d", ErrNoSuchRule, id)
	}
	if ex == nil || strings.TrimSpace(ex.Name) == "" {
		return fmt.Errorf("an extraction needs a name")
	}
	for _, existing := range rule.Extractions {
		if existing != nil && existing.Name == ex.Name {
			return fmt.Errorf("rule already extracts %q", ex.Name)
		}
	}
	if err := ex.Recompile(); err != nil {
		return err
	}
	rule.Extractions = append(rule.Extractions, ex)
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

// MatchingRule returns the first enabled rule whose scopes cover this request: host by name,
// and — when the caller can supply them — parameter scope by the names the request carries.
// The parameter axis is optional (`params` nil means "unknown"): a caller that has not parsed
// the request cannot evaluate a parameter restriction, and refusing the rule on evidence it
// does not have would make every parameter-scoped rule unreachable from that caller. Callers
// that DO hold the request's parameters pass them; that is where Burp's "update this parameter
// across all requests" restriction does its work.
func (c *Coordinator) MatchingRuleFor(host string, params []string) *SessionRule {
	// A host-only identity, deliberately: the parameter axis is optional for the callers this
	// serves, and the URL-scope arms are not evaluable without a path — a rule scoped to a path
	// must not claim a request whose path nobody read. That is the safe direction (a rule that
	// does not fire) rather than the dangerous one (a login macro fired at a URL the rule's own
	// editor excludes). Callers that hold a path pass a full RequestIdentity instead.
	return c.MatchingRuleForRequest(RequestIdentity{Host: host}, params, nil)
}

// MatchingRuleForRequest is the URL-scope-aware match (7nh2): the first enabled rule whose
// URL scope (suite or custom arms) AND parameter scope cover the request. scopeContains is the
// caller's live suite-scope verdict for the request, consulted only by rules configured for
// suite mode; nil falls back to the predicate installed by SetSuiteScopePredicate, which is how
// the in-package callers that own no scope handle keep suite-mode rules reachable.
func (c *Coordinator) MatchingRuleForRequest(req RequestIdentity, params []string, scopeContains func() bool) *SessionRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if scopeContains == nil {
		scopeContains = c.suitePredicateLocked(req)
	}
	return c.matchRequestLocked(req, params, scopeContains)
}

// matchRequestLocked is the scan both MatchingRuleForRequest and the in-package callers that must
// hold their own read lock (recovery's rule lookup) run, so predicate resolution and the ordering
// rule live in one place instead of two.
func (c *Coordinator) matchRequestLocked(req RequestIdentity, params []string, scopeContains func() bool) *SessionRule {
	for _, id := range c.order {
		r := c.rules[id]
		if r == nil || !r.Enabled {
			continue
		}
		if r.MatchRequest(req, scopeContains) && r.MatchParams(params) {
			return r
		}
	}
	return nil
}

// suitePredicateLocked adapts the installed suite-scope predicate to one request. The caller must
// hold the read lock; the closure it returns reads `live` — the console's own function, which
// consults the Target scope rather than any state this package holds — so "live" means exactly
// that: the operator's scope as it stands when the request is matched.
func (c *Coordinator) suitePredicateLocked(req RequestIdentity) func() bool {
	live := c.suiteScope
	if live == nil {
		return nil
	}
	return func() bool { return live(req) }
}

// MatchingRule is MatchingRuleFor with no parameter information: the host axis only, which is
// every caller's behaviour before parameter scope existed. Kept as its own name so the
// call sites that could pass parameters but do not are visible in a grep.
func (c *Coordinator) MatchingRule(host string) *SessionRule {
	return c.MatchingRuleFor(host, nil)
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
	c.handleResponseFor(RequestIdentity{Host: host, Port: port, TLS: tls}, status, hdrs, body, nil)
}

// HandleResponseFor is HandleResponse with the full request identity the scope axes need: the path
// and port a custom-scope rule matches on (7nh2), the requesting tool a tools-scoped rule matches on
// (so3), and the caller's live suite-scope verdict.
//
// The identity travels as a struct rather than four loose parameters plus a tool. The loose form was
// already the reason a response could reach this far carrying no tool at all, and each new axis
// widened the same call. HandleResponse keeps its host-only signature (the crawler interface
// implements it) and delegates with a bare identity — a rule scoped to a path or a tool cannot claim
// a response whose request is only known by its host, so the omitted arms fail such a rule honestly
// rather than over-matching.
func (c *Coordinator) HandleResponseFor(req RequestIdentity, status int, hdrs map[string]string, body []byte, scopeContains func() bool) {
	c.handleResponseFor(req, status, hdrs, body, scopeContains)
}

func (c *Coordinator) handleResponseFor(req RequestIdentity, status int, hdrs map[string]string, body []byte, scopeContains func() bool) {
	c.absorb.responses.Add(1)
	for k, v := range hdrs {
		if strings.EqualFold(k, "Set-Cookie") {
			c.jarMgr.AbsorbSetCookie(req.Host, req.Port, req.TLS, v)
			c.absorb.cookies.Add(1)
		}
	}
	rule := c.MatchingRuleForRequest(req, nil, scopeContains)
	if rule != nil && rule.Validity != nil {
		// Live proxy traffic: no redirect chain is followed here, so the redirect-target clause is unmeasured.
		state := rule.Validity.Evaluate(status, hdrs, body, "")
		if state == Invalid {
			c.logger.Debug("session invalid", zap.String("rule", rule.Name), zap.String("host", req.Host))
		}
	}
	// The project-level capture half (xe82): any observed response can re-issue a value the later
	// requests of covered tools then carry.
	c.observeTokenRules(req, hdrs, body)
}

// StepResult is what a macro step produced. Headers are the response headers
// (Set-Cookie is absorbed; extraction reads them and the body).
//
// FinalURL is where a redirect chain that began at this response landed — the last hop's
// absolute URL — or "" when the response did not redirect. The macro runner fills it by
// resolving the Location the way the sender's redirect follower does — reading a target, not
// sending to one — so the validity check can match the redirection target the way Burp's
// validity search does (burpsy-react-ui-9prk) without a follow that no operator asked for.
type StepResult struct {
	Status   int
	Headers  map[string]string
	Body     []byte
	FinalURL string
}

// logExtraction records what one extraction produced, so an extraction that lifted nothing is
// visible without reading the wire.
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
func (c *Coordinator) CookieHeader(host string, port uint16, tls bool, path string) string {
	return c.jarMgr.CookieHeader(host, port, tls, path)
}

// ---- Macro execution ---------------------------------------------------------------------------

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
		if !rule.MatchCustomArms(identityOf(step.URL)) {
			results = append(results, nil)
			continue
		}
		// Attach the cookies the jar holds for this step's authority.
		host, port, tls := authorityOf(step.URL)
		if cookie := c.CookieHeader(host, port, tls, pathOf(step.URL)); cookie != "" {
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
		state = rule.Validity.Evaluate(last.Status, last.Headers, last.Body, last.FinalURL)
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
		if cookie := c.CookieHeader(host, port, tls, pathOf(row.Sent.URL)); cookie != "" {
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
		report.Status = rule.Validity.Evaluate(last.Status, last.Headers, last.Body, last.FinalURL)
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

// identityOf is the URL-scope identity of one macro step's URL (7nh2): authorityOf's host, port and
// scheme, plus the path a custom-scope path prefix is matched against.
//
// The path is "/" when the URL states none, which is what an empty path means in HTTP rather than a
// convenience: a rule scoped to "/api" must not claim a request to the bare origin, and "" would
// match that prefix if the rule's prefix were empty. A query or fragment is not part of the path
// Burp's URL-matching rule compares, so it is cut here rather than left to make "/api?x=1" fail a
// "/api" prefix.
func identityOf(url string) RequestIdentity {
	host, port, tls := authorityOf(url)
	id := RequestIdentity{Host: host, Port: port, TLS: tls, Path: "/"}
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		path := rest[i:]
		if j := strings.IndexAny(path, "?#"); j >= 0 {
			path = path[:j]
		}
		if path != "" {
			id.Path = path
		}
	}
	return id
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

// pathOf extracts the request path from a step's URL for the jar's §5.4 path-match. The
// step's URL is a wire path the macro runner built (or the operator typed), not a parsed
// *url.URL, so the split is manual: everything after the authority, up to the query or
// fragment. A URL whose shape cannot be read answers "/" rather than an error, because the
// jar's path-match treats "/" as matching every path — the safe direction is a cookie the
// jar sends, not one it silently drops.
func pathOf(rawURL string) string {
	// strip scheme://
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	// strip authority
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[i:]
	} else {
		return "/"
	}
	// strip query and fragment
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "/"
	}
	return rest
}
