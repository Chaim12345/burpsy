package session

// Recorded login sequences (burpsy-react-ui-xhtk).
//
// # What Burp has
//
// A recorded login is an ordered list of browser actions the scanner replays in its own browser to
// log in — the answer for single sign-on, multi-step logins, extra fields and TOTP, none of which a
// username/password pair or an HTTP macro can express. Burp's editor offers six step kinds — Click,
// Type, TOTP, Key press, Go to and Wait (Zf50 in the 2026.7.1 teardown) — plus a status check (a URL
// and the confirmation text that only appears when logged in; Zg5_, "Required when using TOTP
// steps"). Sequences are recorded by the "Login Recorder for Burp Suite" Chrome extension, which
// copies a JSON event script to the clipboard, and pasted into the editor; "See as JSON" shows the
// script for direct editing.
//
// # What this file is
//
// The model, the importers and the redaction. The replay itself is internal/domexec (a browser), and
// the crawl wiring is internal/crawler; neither needs to know where a sequence came from.
//
// Two importers, because two recorders are in operators' hands:
//
//   - Burp's Login Recorder event script: a top-level JSON array whose first element is the
//     {"eventType":"start"} header, followed by goto / click / typing / keyboard / wait events. The
//     field names are the extension's own (Recorder.js and recorder-service-worker.js in Burp's
//     bundled NavigationRecorder), read for the schema only.
//   - Chrome DevTools Recorder JSON: {"title":…,"steps":[{"type":"navigate"|"click"|"change"|…}]}.
//
// Every recorded event that does not become a step is reported by name in the import notes. A login
// that silently lost its third step replays two steps, fails, and leaves the operator nothing to go
// on; a note saying "scroll at event 7 was not imported, and why" is the difference.
//
// # Secrets
//
// A value typed into a password field and a TOTP secret are credentials. They live on LoginStep,
// which is persisted with the project like the platform-authentication store, and never leave this
// process through a view: RecordedLoginView and LoginStepView have no field a secret could be copied
// into, only has_value / has_secret, so a handler that serialises a view cannot leak one by
// accident. An edit that round-trips a view back keeps the stored secret (MergeSecrets) rather than
// wiping it, which is what makes "See as JSON" safe to use.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LoginStepKind is one of Burp's six recorded-login step kinds.
type LoginStepKind string

const (
	StepGoto  LoginStepKind = "goto"
	StepClick LoginStepKind = "click"
	StepType  LoginStepKind = "type"
	StepTOTP  LoginStepKind = "totp"
	StepKey   LoginStepKind = "key"
	StepWait  LoginStepKind = "wait"
)

// LoginStepKinds is every kind, in the order Burp's "insert event" selector lists them.
func LoginStepKinds() []LoginStepKind {
	return []LoginStepKind{StepClick, StepType, StepTOTP, StepKey, StepGoto, StepWait}
}

// MaxLoginSteps bounds one sequence. A login is a handful of actions; a thousand-step "login" is a
// recording of a browsing session, and replaying it before every crawl and every re-login is traffic
// nobody asked for.
const MaxLoginSteps = 200

// MaxLoginWait caps one wait step, Burp's own recorder clamp (maxDelay = 1e4 ms in Recorder.js).
const MaxLoginWait = 10 * time.Second

// LoginStep is one action.
type LoginStep struct {
	Kind LoginStepKind `json:"kind"`
	// URL is the page a goto step navigates to.
	URL string `json:"url,omitempty"`
	// Selector is a CSS selector for the element a click, type or totp step acts on.
	Selector string `json:"selector,omitempty"`
	// XPath is the recorder's absolute XPath for the same element — the fallback when the selector
	// matches nothing, and the only locator when the element had no id or name.
	XPath string `json:"xpath,omitempty"`
	// Value is the text a type step enters.
	Value string `json:"value,omitempty"`
	// Secret marks Value as a credential: it is redacted from every view and description.
	Secret bool `json:"secret,omitempty"`
	// Key is the key a key step presses: "Enter", "Tab", "Escape", …
	Key string `json:"key,omitempty"`
	// WaitMS is how long a wait step waits.
	WaitMS int `json:"wait_ms,omitempty"`
	// TOTP is a totp step's generator.
	TOTP *TOTPConfig `json:"totp,omitempty"`
}

// StatusCheck is how a replay proves it logged in: after the steps, load URL and look for Text.
// Burp's "Status Check" — a URL and "Confirmation Text" — and required when the sequence has a TOTP
// step, because a TOTP login that "ran every step" and was refused for a stale code looks exactly
// like one that worked until something reads the page.
type StatusCheck struct {
	URL  string `json:"url"`
	Text string `json:"text"`
}

// RecordedLogin is one saved sequence.
type RecordedLogin struct {
	ID          string       `json:"id"`
	Label       string       `json:"label"`
	Steps       []LoginStep  `json:"steps"`
	StatusCheck *StatusCheck `json:"status_check,omitempty"`
	// Source names where it came from: "burp-login-recorder", "chrome-recorder" or "burpsy".
	Source  string    `json:"source,omitempty"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// NewRecordedLoginID mints an opaque id.
func NewRecordedLoginID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// HasTOTP reports whether any step is a TOTP step.
func (r *RecordedLogin) HasTOTP() bool {
	for _, s := range r.Steps {
		if s.Kind == StepTOTP {
			return true
		}
	}
	return false
}

// Validate refuses a sequence that cannot be replayed, naming the step.
func (r *RecordedLogin) Validate() error {
	if strings.TrimSpace(r.Label) == "" {
		return errors.New("a recorded login needs a label")
	}
	if len(r.Steps) == 0 {
		return errors.New("a recorded login needs at least one step")
	}
	if len(r.Steps) > MaxLoginSteps {
		return fmt.Errorf("a recorded login may have at most %d steps; this one has %d", MaxLoginSteps, len(r.Steps))
	}
	// The browser starts on a blank page, so the first thing a replay does has to be loading one.
	// Burp's recorder always opens with the address-bar goto; a sequence edited to lose it would
	// click on nothing.
	if r.Steps[0].Kind != StepGoto {
		return errors.New("step 1 must be a goto: the replay browser starts on a blank page")
	}
	for i, s := range r.Steps {
		if err := s.validate(); err != nil {
			return fmt.Errorf("step %d (%s): %w", i+1, s.Kind, err)
		}
	}
	if r.StatusCheck != nil {
		if err := absoluteHTTP(r.StatusCheck.URL); err != nil {
			return fmt.Errorf("status check URL: %w", err)
		}
		if strings.TrimSpace(r.StatusCheck.Text) == "" {
			return errors.New("status check: the confirmation text is empty, so every page would pass")
		}
	} else if r.HasTOTP() {
		return errors.New("a status check is required when using TOTP steps")
	}
	return nil
}

func (s LoginStep) validate() error {
	switch s.Kind {
	case StepGoto:
		return absoluteHTTP(s.URL)
	case StepClick, StepType, StepTOTP:
		if strings.TrimSpace(s.Selector) == "" && strings.TrimSpace(s.XPath) == "" {
			return errors.New("needs a selector or an XPath to find its element")
		}
		if s.Kind == StepTOTP {
			if s.TOTP == nil {
				return errors.New("has no TOTP configuration")
			}
			return s.TOTP.Validate()
		}
		return nil
	case StepKey:
		if strings.TrimSpace(s.Key) == "" {
			return errors.New("names no key")
		}
		if _, ok := replayKeys[s.Key]; !ok && len([]rune(s.Key)) != 1 {
			return fmt.Errorf("key %q is not one this replay can press", s.Key)
		}
		return nil
	case StepWait:
		if s.WaitMS < 0 || time.Duration(s.WaitMS)*time.Millisecond > MaxLoginWait {
			return fmt.Errorf("wait must be between 0 and %d ms", MaxLoginWait.Milliseconds())
		}
		return nil
	}
	return fmt.Errorf("unknown step kind %q", s.Kind)
}

// replayKeys are the named keys a key step may press. Burp's recorder records these as "keyboard"
// events (Recorder.js's keydown switch); printable characters are typing, not key presses.
var replayKeys = map[string]bool{
	"Enter": true, "Tab": true, "Escape": true, "Backspace": true, "Delete": true,
	"ArrowDown": true, "ArrowUp": true, "ArrowLeft": true, "ArrowRight": true,
	"Home": true, "End": true, "PageUp": true, "PageDown": true, "Space": true,
}

// ReplayKeyNames lists the named keys, for the editor.
func ReplayKeyNames() []string {
	return []string{"Enter", "Tab", "Escape", "Backspace", "Delete", "ArrowDown", "ArrowUp",
		"ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown", "Space"}
}

func absoluteHTTP(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	return nil
}

// Target names the element a step acts on, for a description.
func (s LoginStep) Target() string {
	if s.Selector != "" {
		return s.Selector
	}
	return s.XPath
}

// Describe is the step as one line, in Burp's own phrasing (Zwy8). A secret value is never in it.
func (s LoginStep) Describe() string {
	switch s.Kind {
	case StepGoto:
		return "Navigate to " + s.URL
	case StepClick:
		return "Click on " + s.Target()
	case StepType:
		if s.Secret {
			return "Type a secret value into " + s.Target()
		}
		return "Type '" + s.Value + "' into " + s.Target()
	case StepTOTP:
		return "Type TOTP code into " + s.Target()
	case StepKey:
		return "Press " + s.Key + " key"
	case StepWait:
		return "Wait for " + strconv.Itoa(s.WaitMS) + "ms"
	}
	return string(s.Kind)
}

// ---- views ------------------------------------------------------------------------------------

// TOTPView is a TOTP configuration without its secret.
type TOTPView struct {
	Algorithm TOTPAlgorithm `json:"algorithm"`
	Period    int           `json:"period"`
	Digits    int           `json:"digits"`
	HasSecret bool          `json:"has_secret"`
}

// LoginStepView is a step as it leaves the process. There is no secret-bearing field on it.
type LoginStepView struct {
	Kind     LoginStepKind `json:"kind"`
	URL      string        `json:"url,omitempty"`
	Selector string        `json:"selector,omitempty"`
	XPath    string        `json:"xpath,omitempty"`
	// Value is the typed text of a NON-secret type step. A secret step's value is never copied here.
	Value    string    `json:"value,omitempty"`
	Secret   bool      `json:"secret,omitempty"`
	HasValue bool      `json:"has_value,omitempty"`
	Key      string    `json:"key,omitempty"`
	WaitMS   int       `json:"wait_ms,omitempty"`
	TOTP     *TOTPView `json:"totp,omitempty"`
	// Description is Describe(), so the console shows Burp's wording without re-deriving it.
	Description string `json:"description"`
}

// RecordedLoginView is a sequence as it leaves the process.
type RecordedLoginView struct {
	ID          string          `json:"id"`
	Label       string          `json:"label"`
	Steps       []LoginStepView `json:"steps"`
	StatusCheck *StatusCheck    `json:"status_check"`
	Source      string          `json:"source,omitempty"`
	HasTOTP     bool            `json:"has_totp"`
	Created     time.Time       `json:"created"`
	Updated     time.Time       `json:"updated"`
}

// View redacts.
func (r *RecordedLogin) View() RecordedLoginView {
	steps := make([]LoginStepView, 0, len(r.Steps))
	for _, s := range r.Steps {
		v := LoginStepView{
			Kind: s.Kind, URL: s.URL, Selector: s.Selector, XPath: s.XPath, Secret: s.Secret,
			HasValue: s.Value != "", Key: s.Key, WaitMS: s.WaitMS, Description: s.Describe(),
		}
		if !s.Secret {
			v.Value = s.Value
		}
		if s.TOTP != nil {
			v.TOTP = &TOTPView{Algorithm: s.TOTP.Algorithm, Period: s.TOTP.Period, Digits: s.TOTP.Digits,
				HasSecret: s.TOTP.Secret != ""}
		}
		steps = append(steps, v)
	}
	return RecordedLoginView{
		ID: r.ID, Label: r.Label, Steps: steps, StatusCheck: r.StatusCheck, Source: r.Source,
		HasTOTP: r.HasTOTP(), Created: r.Created, Updated: r.Updated,
	}
}

// IncomingStep is a step as an editor sends it: a LoginStep plus the view's presence flags, so a
// round-tripped view can say "keep the stored secret" without carrying it.
type IncomingStep struct {
	LoginStep
	HasValue bool `json:"has_value,omitempty"`
	// TOTPHasSecret is read from totp.has_secret.
	TOTPHasSecret bool `json:"-"`
}

// UnmarshalJSON reads totp.has_secret beside the LoginStep fields.
func (s *IncomingStep) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &s.LoginStep); err != nil {
		return err
	}
	var flags struct {
		HasValue bool `json:"has_value"`
		TOTP     *struct {
			HasSecret bool `json:"has_secret"`
		} `json:"totp"`
	}
	if err := json.Unmarshal(b, &flags); err != nil {
		return err
	}
	s.HasValue = flags.HasValue
	s.TOTPHasSecret = flags.TOTP != nil && flags.TOTP.HasSecret
	return nil
}

// MergeSecrets turns an edited step list into stored steps, keeping each redacted secret from the
// stored step at the same position.
//
// The rule is positional and kind-checked on purpose. A secret step that arrives with no value but
// has_value set is the view coming back unchanged; the value is taken from `stored` at the same
// index when that step is the same kind and was itself secret. Anything else — the step moved, its
// kind changed, there is no stored sequence — is refused by name rather than saved with an empty
// password, because a sequence that silently lost its password replays, fails at the login form,
// and reports a login failure the operator would debug as the target's fault.
func MergeSecrets(incoming []IncomingStep, stored []LoginStep) ([]LoginStep, error) {
	out := make([]LoginStep, 0, len(incoming))
	for i, in := range incoming {
		s := in.LoginStep
		if s.Kind == StepType && s.Secret && s.Value == "" && in.HasValue {
			if i >= len(stored) || stored[i].Kind != StepType || !stored[i].Secret || stored[i].Value == "" {
				return nil, fmt.Errorf("step %d: the secret value was redacted and there is no stored secret at this position to keep; type the value again", i+1)
			}
			s.Value = stored[i].Value
		}
		if s.Kind == StepTOTP && s.TOTP != nil && s.TOTP.Secret == "" && in.TOTPHasSecret {
			if i >= len(stored) || stored[i].Kind != StepTOTP || stored[i].TOTP == nil || stored[i].TOTP.Secret == "" {
				return nil, fmt.Errorf("step %d: the TOTP secret was redacted and there is no stored secret at this position to keep; enter the secret again", i+1)
			}
			s.TOTP.Secret = stored[i].TOTP.Secret
		}
		out = append(out, s)
	}
	return out, nil
}

// ---- import -----------------------------------------------------------------------------------

// ImportNote is one recorded event that did not become a step as recorded, and why.
type ImportNote struct {
	// Event is the 1-based position in the recorded script.
	Event int `json:"event"`
	// EventType is the recorder's own name for it.
	EventType string `json:"event_type"`
	// Outcome is "dropped" (no step was made) or "warning" (a step was made; read the detail).
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// ImportResult is what an import produced.
type ImportResult struct {
	Format string       `json:"format"`
	Steps  []LoginStep  `json:"-"`
	Notes  []ImportNote `json:"notes"`
	// Name is the recording's own name where the format carries one.
	Name string `json:"name,omitempty"`
}

// ImportScript reads a pasted script in any format this build knows, or refuses it naming them.
func ImportScript(raw []byte) (ImportResult, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ImportResult{}, errors.New("the script is empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		return importBurpRecorder([]byte(trimmed))
	}
	var probe struct {
		Steps  []map[string]json.RawMessage `json:"steps"`
		Events json.RawMessage              `json:"events"`
	}
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return ImportResult{}, fmt.Errorf("the script is not JSON: %v", err)
	}
	if len(probe.Events) > 0 {
		return importBurpRecorder(probe.Events)
	}
	if len(probe.Steps) > 0 {
		if _, native := probe.Steps[0]["kind"]; native {
			return importNative([]byte(trimmed))
		}
		if _, chrome := probe.Steps[0]["type"]; chrome {
			return importChromeRecorder([]byte(trimmed))
		}
	}
	return ImportResult{}, errors.New("unrecognised script: expected a Login Recorder for Burp Suite event array, " +
		"a Chrome DevTools Recorder export ({\"steps\":[{\"type\":…}]}), or a burpsy sequence ({\"steps\":[{\"kind\":…}]})")
}

// burpEvent is the subset of a Login Recorder event this importer reads (Recorder.js createEvent,
// createKeyboardEvent; the service worker's start/goto).
type burpEvent struct {
	EventType        string `json:"eventType"`
	Name             string `json:"name"`
	URL              string `json:"url"`
	FromAddressBar   bool   `json:"fromAddressBar"`
	TagName          string `json:"tagName"`
	ID               string `json:"id"`
	ElementName      string `json:"-"`
	XPath            string `json:"xPath"`
	TypedValue       string `json:"typedValue"`
	ElementType      string `json:"elementType"`
	Key              string `json:"key"`
	DurationInMillis int    `json:"durationInMillis"`
	IsShadowElement  bool   `json:"isShadowElement"`
	FrameID          int    `json:"frameId"`
	OpensNewContext  bool   `json:"opensNewContext"`
	CreatedTabID     *int   `json:"createdTabId"`
	Placeholder      string `json:"placeholder"`
}

// decodeBurpEvent reads one event. "name" is the recorder's name on the start event and the element's
// name attribute on every other, so it is copied to ElementName for the element readers.
func decodeBurpEvent(raw json.RawMessage) (burpEvent, error) {
	var e burpEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, err
	}
	e.ElementName = e.Name
	return e, nil
}

// possibleTOTPField matches the field names a one-time-code input is usually given.
var possibleTOTPField = regexp.MustCompile(`(?i)otp|totp|mfa|2fa|one.?time|verif|auth.?code|^code$|token`)
var digitsOnly = regexp.MustCompile(`^[0-9]{6,8}$`)

func importBurpRecorder(raw []byte) (ImportResult, error) {
	var events []json.RawMessage
	if err := json.Unmarshal(raw, &events); err != nil {
		return ImportResult{}, fmt.Errorf("the Burp recorder script is not a JSON array of events: %v", err)
	}
	res := ImportResult{Format: "burp-login-recorder", Notes: []ImportNote{}}
	for i, rawEvent := range events {
		n := i + 1
		e, err := decodeBurpEvent(rawEvent)
		if err != nil {
			return ImportResult{}, fmt.Errorf("event %d is not an object: %v", n, err)
		}
		note := func(outcome, detail string) {
			res.Notes = append(res.Notes, ImportNote{Event: n, EventType: e.EventType, Outcome: outcome, Detail: detail})
		}
		if e.FrameID != 0 && (e.EventType == "click" || e.EventType == "typing") {
			note("dropped", "the element is inside an iframe; this replay acts on the top-level document only")
			continue
		}
		if e.IsShadowElement {
			note("dropped", "the element is inside a shadow root, which the recorder locates without an XPath; this replay cannot find it")
			continue
		}
		switch e.EventType {
		case "start":
			res.Name = e.Name
		case "goto":
			if err := absoluteHTTP(e.URL); err != nil {
				note("dropped", "the navigation has no usable URL: "+err.Error())
				continue
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepGoto, URL: e.URL})
		case "click":
			sel := burpSelector(e)
			if sel == "" && e.XPath == "" {
				note("dropped", "can not click on element with no identifying attributes")
				continue
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepClick, Selector: sel, XPath: e.XPath})
		case "typing":
			sel := burpSelector(e)
			if sel == "" && e.XPath == "" {
				note("dropped", "can not type into element with no identifying attributes")
				continue
			}
			step := LoginStep{Kind: StepType, Selector: sel, XPath: e.XPath, Value: e.TypedValue,
				Secret: strings.EqualFold(e.ElementType, "password")}
			res.Steps = append(res.Steps, step)
			if digitsOnly.MatchString(e.TypedValue) && (possibleTOTPField.MatchString(e.ID) ||
				possibleTOTPField.MatchString(e.Name) || possibleTOTPField.MatchString(e.Placeholder)) {
				note("warning", fmt.Sprintf("step %d types a %d-digit code into a field that looks like a one-time-code input; "+
					"if it is a TOTP code, change the step to a TOTP step and give it the secret — a recorded code is stale on replay",
					len(res.Steps), len(e.TypedValue)))
			}
		case "keyboard":
			if e.Key == "" {
				note("dropped", "the key event names no key")
				continue
			}
			key := e.Key
			if key == " " {
				key = "Space"
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepKey, Key: key})
		case "wait":
			ms := e.DurationInMillis
			if ms > int(MaxLoginWait.Milliseconds()) {
				note("warning", fmt.Sprintf("a %d ms wait was clamped to %d ms", ms, MaxLoginWait.Milliseconds()))
				ms = int(MaxLoginWait.Milliseconds())
			}
			if ms < 0 {
				ms = 0
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepWait, WaitMS: ms})
		case "scroll":
			note("dropped", "scrolling is not replayed; a click scrolls its own element into view")
		case "rightClick":
			note("dropped", "right-clicks open a context menu and are not replayed")
		case "userNavigate", "clientSideRedirect":
			note("dropped", "a navigation the page made itself as a result of the previous action; it happens again on replay when that action runs")
		default:
			note("dropped", "this event type is not one the replay knows")
		}
		if e.OpensNewContext || e.CreatedTabID != nil {
			note("warning", "this action opened a new tab or window; the replay runs in one tab and does not follow it, so later steps act on the original page")
		}
	}
	if len(res.Steps) == 0 {
		return ImportResult{}, errors.New("the Burp recorder script produced no replayable steps")
	}
	return res, nil
}

// burpSelector builds a CSS selector from the recorded element's identifying attributes: its id,
// else tag plus name. Empty when it had neither, and the XPath is then the only locator.
func burpSelector(e burpEvent) string {
	if e.ID != "" && cssIdent.MatchString(e.ID) {
		return "#" + e.ID
	}
	tag := strings.ToLower(e.TagName)
	if tag == "" {
		tag = "*"
	}
	if e.ID != "" {
		return tag + `[id="` + cssString(e.ID) + `"]`
	}
	if e.ElementName != "" {
		return tag + `[name="` + cssString(e.ElementName) + `"]`
	}
	return ""
}

var cssIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

func cssString(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// chromeStep is the subset of a DevTools Recorder step this importer reads.
type chromeStep struct {
	Type      string     `json:"type"`
	URL       string     `json:"url"`
	Selectors [][]string `json:"selectors"`
	Value     string     `json:"value"`
	Key       string     `json:"key"`
	Target    string     `json:"target"`
}

func importChromeRecorder(raw []byte) (ImportResult, error) {
	var doc struct {
		Title string            `json:"title"`
		Steps []json.RawMessage `json:"steps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ImportResult{}, err
	}
	res := ImportResult{Format: "chrome-recorder", Name: doc.Title, Notes: []ImportNote{}}
	for i, rawStep := range doc.Steps {
		n := i + 1
		var s chromeStep
		if err := json.Unmarshal(rawStep, &s); err != nil {
			return ImportResult{}, fmt.Errorf("step %d is not an object: %v", n, err)
		}
		note := func(outcome, detail string) {
			res.Notes = append(res.Notes, ImportNote{Event: n, EventType: s.Type, Outcome: outcome, Detail: detail})
		}
		if s.Target != "" && s.Target != "main" {
			note("dropped", "the step targets another tab or frame ("+s.Target+"); this replay acts on one tab")
			continue
		}
		css, xpath := chromeLocators(s.Selectors)
		switch s.Type {
		case "navigate":
			if err := absoluteHTTP(s.URL); err != nil {
				note("dropped", err.Error())
				continue
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepGoto, URL: s.URL})
		case "click", "doubleClick":
			if css == "" && xpath == "" {
				note("dropped", "no CSS or XPath selector; aria/text/pierce selectors are not supported")
				continue
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepClick, Selector: css, XPath: xpath})
		case "change":
			if css == "" && xpath == "" {
				note("dropped", "no CSS or XPath selector; aria/text/pierce selectors are not supported")
				continue
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepType, Selector: css, XPath: xpath, Value: s.Value,
				Secret: possiblePasswordSelector.MatchString(css + " " + xpath)})
		case "keyDown":
			if s.Key == "" {
				note("dropped", "names no key")
				continue
			}
			res.Steps = append(res.Steps, LoginStep{Kind: StepKey, Key: s.Key})
		case "keyUp":
			// The key step presses and releases; the release is part of the keyDown step above.
		case "setViewport":
			note("dropped", "the replay browser's viewport is fixed")
		default:
			note("dropped", "this step type is not one the replay knows")
		}
	}
	if len(res.Steps) == 0 {
		return ImportResult{}, errors.New("the Chrome recorder export produced no replayable steps")
	}
	return res, nil
}

var possiblePasswordSelector = regexp.MustCompile(`(?i)passw|pwd|secret`)

func chromeLocators(groups [][]string) (css, xpath string) {
	for _, g := range groups {
		if len(g) != 1 {
			continue // a multi-part selector crosses frames or shadow roots
		}
		sel := g[0]
		switch {
		case strings.HasPrefix(sel, "xpath/"):
			if xpath == "" {
				xpath = strings.TrimPrefix(sel, "xpath/")
			}
		case strings.HasPrefix(sel, "aria/"), strings.HasPrefix(sel, "text/"), strings.HasPrefix(sel, "pierce/"):
		default:
			if css == "" {
				css = sel
			}
		}
	}
	return css, xpath
}

func importNative(raw []byte) (ImportResult, error) {
	var doc struct {
		Label string      `json:"label"`
		Steps []LoginStep `json:"steps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ImportResult{}, err
	}
	return ImportResult{Format: "burpsy", Name: doc.Label, Steps: doc.Steps, Notes: []ImportNote{}}, nil
}
