package session

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/jsexec"
)

// ---- Rule actions -------------------------------------------------------------------------------
//
// Burp's session-handling rule is an ordered list of actions, run in sequence, where any action may
// say that no further actions apply to the request (session-handling-rules.html, "Rule actions").
// This port had the shape Burp reaches last: a rule whose only behaviour was "check validity, and if
// invalid replay the macro", with the two halves hardcoded in recovery.go and no way to express
// either as one step among several.
//
// That is the whole of the cost. The canonical Burp recipe for a CSRF-token application is *run a
// macro to fetch the token, then set that token as a named parameter on the outgoing request* — two
// actions in one rule, the second of which did not exist in any form. An operator could fetch the
// token and had nowhere to put it.
//
// # Burp's nine actions, and this port's tenth kind
//
// Burp lists nine. Ten kinds here, because Burp presents "Set a specific cookie or parameter value"
// as one action with a type selector and this port splits it: a cookie is written into the Cookie
// header and a parameter into the query string or the form body, which is different code with a
// different failure mode, and keeping them apart means each kind's validation is total instead of a
// switch inside a switch.
//
// "Prompt the user for in-browser session recovery" is burpsy's counterpart of Burp's ninth,
// implemented rather than declined: Burp opens a browser window on the failing response so the
// operator can log in by hand and then tells the rule to carry on. burpsy has no window it can
// open — the console is a page the operator opens themselves — so the prompt is a modal on that
// page and the task blocks until the operator answers. The one thing kept from the earlier
// decline is the honesty: this is a real question with a real answer, never a silent wait. If
// there is nobody at the console to ask, the action says so and stops the walk rather than
// sending a request the operator put the action there to gate.
//
// "Invoke an extension" is implemented against this tree's own extension host (internal/extension),
// which is a local JSON-RPC plugin rather than Burp's Java API — so the *authoring* model is
// different and the capability is real.

// ActionKind is one rule action. The zero value is ActionRunMacro so a Rule built without actions —
// every rule in a project written before this existed — runs its macro, which is the half of the old
// hardcoded behaviour that did the work.
type ActionKind int

const (
	// ActionRunMacro runs a macro: the rule's own Steps, or this action's Macro when it names one.
	ActionRunMacro ActionKind = iota
	// ActionRunPostRequestMacro issues the request being processed and *then* runs the macro —
	// Burp's "this issues the current request, and then executes a further macro". Distinct from
	// ActionRunMacro, which never sends the current request.
	ActionRunPostRequestMacro
	// ActionCheckValidity evaluates a validity rule against the last observed response and runs
	// Then or Else. This is Burp's "Check whether the current session is valid, and perform
	// sub-actions conditionally on the result", and it is the only kind with children.
	ActionCheckValidity
	// ActionAddCookiesFromJar attaches the session-handling cookie jar's cookies for the request's
	// own authority. Implicit before this existed — the jar was attached by the recovery path
	// itself, per call site, which is why a rule could not say *when* to do it relative to a macro.
	ActionAddCookiesFromJar
	// ActionSetCookie sets one cookie on the outgoing request's Cookie header.
	ActionSetCookie
	// ActionSetParam sets one named parameter's value. In selects where: a param that already
	// exists where it is, the query string, or the form body.
	ActionSetParam
	// ActionSetHeader sets one request header.
	ActionSetHeader
	// ActionReplace rewrites part of the outgoing request, by literal match or by regex — the
	// per-rule, ordered, conditional form of what internal/matchreplace does globally.
	ActionReplace
	// ActionInvokeExtension hands the request and the last response to a loaded plugin and takes
	// back the request it wants sent. The last action with a host to talk to.
	ActionInvokeExtension
	// ActionPromptForBrowserRecovery suspends the task until the operator has recovered the session
	// in their own browser — Burp's "prompt the user for in-browser session recovery" (Zgr9.java,
	// build 51467), which opens a window on the failing response so an operator can log in by hand.
	// burpsy has no window it can open: the console is a page the operator opens themselves, so the
	// prompt is a modal on that page and the task blocks until the operator answers. On success the
	// task resumes — the retried request carries the jar as the operator's browser left it, which is
	// the same mechanism Burp's own prompt relies on. On decline, or with no console attached to
	// ask, the walk stops without sending: the action exists to gate the send on a human being's
	// answer, and a request that goes out anyway makes the action a lie.
	ActionPromptForBrowserRecovery
	// ActionRunScript runs a short sandboxed JavaScript pre-request script (burpsy-react-ui-ydmj) with
	// the outgoing request as a mutable object, read access to the last response and a small per-rule
	// store — so refreshing a JWT, recomputing a signature or stamping a nonce is a few lines rather
	// than a plugin. Burp's Montoya pre-request handling; Caido's pre-request scripts. No network, no
	// filesystem: see internal/jsexec.RunRequestScript.
	ActionRunScript
	// ActionKindCount must stay last. It exists so tests can walk the enum and so
	// actionKindNames can be an array the compiler sizes: a kind added without a wire name is then
	// a build failure rather than a rule that reads back as something else. Same shape as
	// matchreplace.TargetCount.
	ActionKindCount = iota
)

// The wire names, in the enum's own order. `action_kind` on the wire is one of these, and the two
// directions share the list so they cannot drift.
var actionKindNames = [ActionKindCount]string{
	ActionRunMacro:                 "run_macro",
	ActionRunPostRequestMacro:      "run_post_request_macro",
	ActionCheckValidity:            "check_validity",
	ActionAddCookiesFromJar:        "add_cookies_from_jar",
	ActionSetCookie:                "set_cookie",
	ActionSetParam:                 "set_param",
	ActionSetHeader:                "set_header",
	ActionReplace:                  "replace",
	ActionInvokeExtension:          "invoke_extension",
	ActionPromptForBrowserRecovery: "prompt_for_browser_recovery",
	ActionRunScript:                "run_script",
}

// actionKindLabels are Burp's own words for each action, so the editor reads like the documentation
// the operator is following rather than like this port's enum.
var actionKindLabels = [ActionKindCount]string{
	ActionRunMacro:                 "Run a macro",
	ActionRunPostRequestMacro:      "Run a post-request macro",
	ActionCheckValidity:            "Check whether the current session is valid, and perform sub-actions conditionally",
	ActionAddCookiesFromJar:        "Add cookies from the session handling cookie jar",
	ActionSetCookie:                "Set a specific cookie value",
	ActionSetParam:                 "Set a specific parameter value",
	ActionSetHeader:                "Set a specific header value",
	ActionReplace:                  "Replace matching part of the request",
	ActionInvokeExtension:          "Invoke an extension",
	ActionPromptForBrowserRecovery: "Prompt the user for in-browser session recovery",
	ActionRunScript:                "Run a pre-request script",
}

// ActionKindName is the wire name for a kind. An out-of-range kind says so rather than naming the
// kind at that offset, for the reason matchReplaceTargetName's comment gives: answering with a real
// name would let a broken rule reach the operator disguised as a working one.
func ActionKindName(k ActionKind) string {
	if k < 0 || int(k) >= ActionKindCount {
		return fmt.Sprintf("unrecognised_action_%d", int(k))
	}
	return actionKindNames[k]
}

// ActionKindLabel is the operator-facing name, used by the UI and by this package's own reports.
func ActionKindLabel(k ActionKind) string {
	if k < 0 || int(k) >= ActionKindCount {
		return fmt.Sprintf("Unrecognised action %d", int(k))
	}
	return actionKindLabels[k]
}

// ParseActionKind maps a wire name onto a kind, refusing anything outside the vocabulary. The
// refusal carries the accepted list because the vocabulary otherwise exists only in this source
// file, and a rule that silently became a *different action* is the failure this whole package is
// written against — a session rule that does the wrong thing sends real credentials to a real
// target.
func ParseActionKind(name string) (ActionKind, error) {
	for i := 0; i < ActionKindCount; i++ {
		if actionKindNames[i] == name {
			return ActionKind(i), nil
		}
	}
	return 0, fmt.Errorf("unknown action kind %q; accepted values are %s",
		name, strings.Join(actionKindNames[:], ", "))
}

// Action is one step of a rule.
//
// # One struct with per-kind fields, not a sum type
//
// Go has no sum type, and the two alternatives here are an interface per kind (which would make the
// wire shape, the persisted JSON and the editor all reflect a Go-language construct rather than the
// rule) or one struct whose fields are documented per kind and validated per kind. This is the
// second, and ValidateRule is what makes it safe: every kind's required fields are checked when the
// rule is installed, so an action cannot reach the executor in a state its kind does not define.
// The cost is that an unused field can be set on the wrong kind — hence `Enabled`-style validation
// that *refuses* a field the kind does not use, rather than ignoring it.
type Action struct {
	Kind ActionKind `json:"kind"`
	// Enabled is per-action, like Burp's per-action checkbox. A disabled action is skipped and the
	// list continues.
	Enabled bool `json:"enabled"`
	// Stop is Burp's "no further actions should be applied to the request": this action is the last
	// one that runs, whether or not it changed anything.
	Stop bool `json:"stop,omitempty"`

	// Macro is the steps a RunMacro / RunPostRequestMacro action runs. Empty means the rule's own
	// Steps, which is what a rule migrated from the pre-action shape means and what keeps one
	// recorded login flow usable as the default for every macro in the rule.
	Macro []MacroStep `json:"macro,omitempty"`

	// The run-macro action's "after the macro" choices (burpsy-react-ui-8gk8), under Burp's own key
	// names (burp.Zcft / burp.Zcfx). Every one reads, when absent, as what burpsy did before they
	// existed, so a stored rule keeps its behaviour:
	//
	//   - UpdateWithParams: "Update current request with parameters matched from final macro
	//     response". Absent = false, because nothing updated parameters before; the editor sets it
	//     true on a new action, as Burp does.
	//   - MatchParams / Params: "Update all parameters except for" (all_params_except, the default)
	//     or "Update only the following parameters" (specified_params), and the names.
	//   - TolerateURLMismatch: match a parameter by name alone rather than by name and URL.
	//   - UpdateWithCookies: "Update current request with cookies from session handling cookie jar".
	//     A pointer because absent must mean true: the jar's cookies always reached the retried
	//     request, and a stored rule must not silently lose its session cookie.
	//   - MatchCookies / Cookies: all_cookies_except (the default) or specified_cookies, and the names.
	UpdateWithParams    bool     `json:"update_with_params,omitempty"`
	MatchParams         string   `json:"match_params,omitempty"`
	Params              []string `json:"params,omitempty"`
	TolerateURLMismatch bool     `json:"tolerate_url_mismatch,omitempty"`
	UpdateWithCookies   *bool    `json:"update_with_cookies,omitempty"`
	MatchCookies        string   `json:"match_cookies,omitempty"`
	Cookies             []string `json:"cookies,omitempty"`

	// Validity overrides the rule's own validity rule for a CheckValidity action. Nil means the
	// rule's.
	Validity *ValidityRule `json:"validity,omitempty"`
	// ValidateEvery is Burp's `validate_every_num_requests` (recovered from burp.Zcfs in
	// map_root.tsv, beside `issue_current_request` and `match_indicates`): validate the session
	// only on every Nth request the rule handles, rather than on every one. The docs give the reason
	// — "this helps you to avoid making unnecessary requests in cases where the application rarely
	// invalidates your session" — which is a cost decision, so it is an opt-in on the check that
	// spends the request.
	//
	// Zero means check every time, which is the pre-field behaviour and therefore every rule that
	// predates it. A negative value is refused at configuration time rather than read as "every
	// time" or "never", because "validate never" is a rule that silently stopped protecting the
	// session — see ValidateRule.
	ValidateEvery int `json:"validate_every,omitempty"`
	// Then / Else are the sub-actions of a CheckValidity action: Then runs when the session is
	// Valid, Else when it is Invalid *or* the check could not tell (Indeterminate). Burp's model
	// nests here and nowhere else, which is exactly where conditionality belongs.
	Then []*Action `json:"then,omitempty"`
	Else []*Action `json:"else,omitempty"`

	// Name and Value are SetCookie's cookie name and value, SetParam's parameter name and value, and
	// SetHeader's header name and value. A Value may carry {{name}} placeholders resolved from the
	// values a macro action extracted earlier in the same list — that is the CSRF recipe, and it is
	// the reason the run context carries an extraction map rather than only a jar.
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
	// In is a SetParam action's target: "" (wherever the parameter already is, else the query
	// string), "query", or "body".
	In string `json:"in,omitempty"`

	// Match / Replacement / Regex are a Replace action's rewrite.
	Match       string `json:"match,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Regex       bool   `json:"regex,omitempty"`

	// Extension is an InvokeExtension action's target: the plugin registration name as the host
	// lists it, and whether that registration is a session action rather than a context-menu item.
	Extension        string `json:"extension,omitempty"`
	ExtensionSession string `json:"extension_session,omitempty"`
	// Script is a RunScript action's JavaScript source. It sees `request` (method, url, headers,
	// body — mutable), `response` (the last observed response, frozen, or null), `store` (get/set/
	// delete, kept per rule across requests — where a captured token lives), `log(...)`, and the pure
	// helpers on `burpsy` (hmacSha256Hex/Base64, sha256Hex, base64Encode/UrlEncode/Decode, randomHex).
	Script string `json:"script,omitempty"`
}

// ValidateAction refuses an action whose fields do not describe the kind it claims to be.
//
// `path` names the action's position for the message ("action 2", "action 2 → else 1"), because a
// rule with a nested check has more than one numbering an operator could mean and a refusal that
// cannot be located is one an operator works around instead of fixing.
func ValidateAction(a *Action, path string) error {
	if a == nil {
		return fmt.Errorf("%s: is missing", path)
	}
	if a.Kind < 0 || int(a.Kind) >= ActionKindCount {
		return fmt.Errorf("%s: unknown action kind %d", path, int(a.Kind))
	}
	require := func(field, name string) error {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("%s (%s): a %q is required", path, ActionKindLabel(a.Kind), name)
		}
		return nil
	}
	if err := validateMacroUpdate(a, path); err != nil {
		return err
	}
	switch a.Kind {
	case ActionSetCookie:
		if err := require(a.Name, "cookie name"); err != nil {
			return err
		}
	case ActionSetHeader:
		if err := require(a.Name, "header name"); err != nil {
			return err
		}
	case ActionSetParam:
		if err := require(a.Name, "parameter name"); err != nil {
			return err
		}
		switch a.In {
		case "", "query", "body":
		default:
			return fmt.Errorf("%s (%s): in must be query or body, got %q",
				path, ActionKindLabel(a.Kind), a.In)
		}
	case ActionReplace:
		if err := require(a.Match, "match"); err != nil {
			return err
		}
		if a.Regex {
			// Refused here rather than at rewrite time: a pattern that does not compile would
			// otherwise surface as "the parameter was not replaced", which blames the target for a
			// typo in the rule — the same reasoning validate.go gives for extraction patterns.
			if _, err := regexp.Compile(a.Match); err != nil {
				return fmt.Errorf("%s (%s): the match regex does not compile: %v",
					path, ActionKindLabel(a.Kind), err)
			}
		}
	case ActionInvokeExtension:
		if err := require(a.Extension, "extension registration name"); err != nil {
			return err
		}
	case ActionRunScript:
		// Compiled at install time: a syntax error refused here names itself, where one found at send
		// time would fail every request the rule covers with the same message.
		if err := jsexec.CheckRequestScript(a.Script); err != nil {
			return fmt.Errorf("%s (%s): %v", path, ActionKindLabel(a.Kind), err)
		}
	case ActionCheckValidity:
		// A negative interval is refused rather than read as "always" (the zero value's job) or
		// "never": "validate never" is a rule that has silently stopped protecting the session, and
		// an operator who types -1 to mean something cannot see what the rule will do.
		if a.ValidateEvery < 0 {
			return fmt.Errorf("%s (%s): validate every must be 0 (check every request) or a positive "+
				"number of requests, got %d", path, ActionKindLabel(a.Kind), a.ValidateEvery)
		}
	case ActionRunMacro, ActionRunPostRequestMacro, ActionAddCookiesFromJar, ActionPromptForBrowserRecovery:
		// Nothing beyond the kind and its switches. The prompt asks the operator, not the rule, for
		// what comes next — there is no field to state.
	}
	if a.Kind != ActionRunScript && strings.TrimSpace(a.Script) != "" {
		// Refused rather than ignored, the same rule as every other kind-specific field: a script on a
		// set-header action would read as though it ran.
		return fmt.Errorf("%s (%s): only a pre-request script action carries a script",
			path, ActionKindLabel(a.Kind))
	}
	if a.Kind != ActionCheckValidity && (len(a.Then) > 0 || len(a.Else) > 0) {
		return fmt.Errorf("%s (%s): only a validity check has conditional sub-actions",
			path, ActionKindLabel(a.Kind))
	}
	for i, child := range a.Then {
		if err := ValidateAction(child, fmt.Sprintf("%s → then %d", path, i+1)); err != nil {
			return err
		}
	}
	for i, child := range a.Else {
		if err := ValidateAction(child, fmt.Sprintf("%s → else %d", path, i+1)); err != nil {
			return err
		}
	}
	return nil
}

// ValidateActions refuses a whole ordered list, naming the position of the first bad entry.
func ValidateActions(actions []*Action) error {
	for i, a := range actions {
		if err := ValidateAction(a, fmt.Sprintf("action %d", i+1)); err != nil {
			return err
		}
	}
	return nil
}

// EffectiveActions is the list this rule runs: the explicit list when it has one, and otherwise the
// list the pre-action shape is equivalent to.
//
// # Why the synthesised list is the *old* behaviour, exactly
//
//   - "check whether the current session is valid" comes first, because the old code decided
//     whether to do anything at all by evaluating the response against the rule's validity.
//   - "run a macro" is its `else` branch, because the old code ran the macro only when the session
//     was not valid — including when the check could not tell, which is why Indeterminate takes the
//     Else branch in the executor too. A rule whose validity check is Indeterminate must keep
//     attempting a login: that was the old behaviour and it is the safe direction — the alternative
//     reads "I could not tell whether this session is alive" as "it is fine".
//
// Nothing else is synthesised. In particular no cookie-jar action is added: the jar is attached by
// the send path itself (see Coordinator.sendWithJar), so a migrated rule behaves precisely as it did
// before, and an operator who wants the attach to be an explicit, ordered step can add one.
func (r *SessionRule) EffectiveActions() []*Action {
	if r == nil {
		return nil
	}
	if len(r.Actions) > 0 {
		return r.Actions
	}
	return []*Action{{
		Kind:    ActionCheckValidity,
		Enabled: true,
		Else: []*Action{{
			Kind:    ActionRunMacro,
			Enabled: true,
		}},
	}}
}

// NormaliseActions materialises the synthesised list onto the rule, so what is persisted and what is
// served are the same list the executor runs.
//
// Called by every path that installs a rule and by the restore path, which is the point: a rule is
// converted once, at the moment it enters the tree, rather than by each reader remembering that an
// empty list means something. A rule read back from a project written before actions existed comes
// into the coordinator through the same door and acquires the same explicit list.
//
// The rule's own Steps/Validity/MaxAttempts are *kept*, not cleared. They are still what the
// synthesised actions fall back to (an action with no Macro of its own runs the rule's), so clearing
// them would change a migrated rule's behaviour — the one thing a migration must not do.
func (r *SessionRule) NormaliseActions() {
	if r == nil || len(r.Actions) > 0 {
		return
	}
	r.Actions = r.EffectiveActions()
}

// actionsSubstituteValues rewrites {{name}} occurrences using `values`, leaving an unresolvable
// placeholder verbatim.
//
// Verbatim rather than empty, matching resolveStep for macro steps and for the same reason: a
// parameter sent as the literal string "{{csrf}}" says what went wrong in the request itself, where
// one sent as an empty value looks like the application rejecting a real attempt.
func actionsSubstituteValues(s string, values map[string]string) string {
	if s == "" || len(values) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	return placeholderToken.ReplaceAllStringFunc(s, func(match string) string {
		name := strings.TrimSpace(match[2 : len(match)-2])
		if v, ok := values[name]; ok && v != "" {
			return v
		}
		return match
	})
}

// actionPlaceholders returns every {{name}} an action's own fields refer to, deduplicated and in a
// stable order, including its children's.
//
// It exists so the same config-time check that refuses a macro step referring to a value no earlier
// step extracts also covers a SetParam whose value is `{{csrf}}`. Without it the CSRF recipe's second
// half — the half this whole unit exists to make expressible — would be the one field in a rule that
// could name a value that never arrives, and it would go out on the wire as the literal string, or
// as an empty parameter, twenty minutes into a scan.
//
// Only the fields a kind reads are walked, because a field the kind ignores is refused by
// ValidateAction rather than silently searched.
func actionPlaceholders(a *Action) []string {
	if a == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(text string) {
		for _, name := range placeholderNames(MacroStep{Body: text}) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	switch a.Kind {
	case ActionSetCookie, ActionSetParam, ActionSetHeader:
		add(a.Value)
	case ActionReplace:
		add(a.Replacement)
	}
	for _, child := range a.Then {
		for _, name := range actionPlaceholders(child) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	for _, child := range a.Else {
		for _, name := range actionPlaceholders(child) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
