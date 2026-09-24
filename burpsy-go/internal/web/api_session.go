package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- wire shapes (mirror session.ts) ------------------------------------------------------------

// sessionStepDto mirrors the UI's StepDto: headers as a [k,v] list, extracts omitted when absent.
type sessionStepDto struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers [][2]string         `json:"headers"`
	Body    string              `json:"body"`
	Extract []sessionExtractDto `json:"extract,omitempty"`
}

// sessionExtractDto mirrors the UI's ExtractionDto (internal/web/ui/src/session.ts) exactly, and both
// of its fields are unions, so both are held as raw JSON and decoded by hand:
//
//	type ExtractFrom = "body" | { header: string }
//	type ExtractHow  = { regex: { pattern: string; group?: number } } | { json_path: string } | "whole"
//
// Declaring `from` as a plain Go string — which is what this DTO used to do — makes
// `{"header": "X-Token"}` fail to unmarshal into it, and since the whole struct was never read
// anyway the mismatch went unnoticed. Decoding the real shape is what lets an extraction the operator
// typed reach the rule instead of being dropped between the browser and the coordinator.
type sessionExtractDto struct {
	Name string `json:"name"`
	// Absent means the body, matching the UI's optional field.
	From json.RawMessage `json:"from,omitempty"`
	How  json.RawMessage `json:"how"`
}

// wholeValuePattern is how the UI's `how: "whole"` is expressed to an extractor that only knows
// regexes: match everything including newlines, and take group 0. Kept as a named constant because
// ruleToDto reads it back to decide whether an extraction started life as "whole" — so the UI's
// dropdown comes back on the option the operator chose rather than showing them a regex they never
// typed.
const wholeValuePattern = `(?s)^.*$`

// extractFrom decodes ExtractFrom into the ("body"|"header", header name) pair session.Extraction
// holds.
func (d sessionExtractDto) extractFrom() (from string, header string, err error) {
	if len(d.From) == 0 || string(d.From) == "null" {
		return "body", "", nil
	}
	var asString string
	if err := json.Unmarshal(d.From, &asString); err == nil {
		if asString != "body" {
			return "", "", fmt.Errorf("extraction %q reads from %q; the only bare source is \"body\" "+
				"(a header is stated as {\"header\": name})", d.Name, asString)
		}
		return "body", "", nil
	}
	var asHeader struct {
		Header *string `json:"header"`
	}
	if err := json.Unmarshal(d.From, &asHeader); err != nil || asHeader.Header == nil {
		return "", "", fmt.Errorf("extraction %q reads from %s, which is neither \"body\" nor "+
			"{\"header\": name}", d.Name, string(d.From))
	}
	if strings.TrimSpace(*asHeader.Header) == "" {
		return "", "", fmt.Errorf("extraction %q reads from a header with no name", d.Name)
	}
	return "header", *asHeader.Header, nil
}

// extractHowSpec is the decoded ExtractHow: either a regex with a capture group, or a json path.
// Exactly one of Pattern and JSONPath is set, which is the same invariant session.Extraction holds.
type extractHowSpec struct {
	Pattern  string
	Group    int
	JSONPath string
}

// extractHow decodes ExtractHow into the form this port's extractor runs.
//
// All three arms of the UI's union are now implemented: `whole` as a match-everything regex, `regex`
// as itself, and `json_path` by the hand-rolled walker in internal/session/jsonpath.go. That walker
// covers a deliberate subset of JSONPath — dotted keys and array indices, no recursive descent, no
// wildcards, no slices, no filters — and refuses anything outside it while the rule is being saved,
// naming the construct that is unsupported. A path is never quietly compiled as a regex: it would
// match nothing while looking configured, which is the failure this whole file exists to avoid.
func (d sessionExtractDto) extractHow() (extractHowSpec, error) {
	if len(d.How) == 0 || string(d.How) == "null" {
		return extractHowSpec{}, fmt.Errorf("extraction %q does not say how to extract; state a regex, a json path, or \"whole\"", d.Name)
	}
	var asString string
	if err := json.Unmarshal(d.How, &asString); err == nil {
		if asString != "whole" {
			return extractHowSpec{}, fmt.Errorf("extraction %q extracts by %q, which is not a known method", d.Name, asString)
		}
		return extractHowSpec{Pattern: wholeValuePattern}, nil
	}
	var tagged struct {
		Regex *struct {
			Pattern string `json:"pattern"`
			Group   *int   `json:"group"`
		} `json:"regex"`
		JSONPath *string `json:"json_path"`
	}
	if err := json.Unmarshal(d.How, &tagged); err != nil {
		return extractHowSpec{}, fmt.Errorf("extraction %q: cannot read how it extracts from %s: %w", d.Name, string(d.How), err)
	}
	switch {
	case tagged.Regex != nil && tagged.JSONPath != nil:
		// The union admits one arm. Refused rather than resolved by precedence, because whichever arm a
		// precedence rule dropped would be the one the operator was looking at in the form.
		return extractHowSpec{}, fmt.Errorf("extraction %q states both a regex and a json path; state one",
			d.Name)
	case tagged.Regex != nil:
		// A blank group means the UI's own default of 1 (the first capture), not group 0.
		group := 1
		if tagged.Regex.Group != nil {
			group = *tagged.Regex.Group
		}
		return extractHowSpec{Pattern: tagged.Regex.Pattern, Group: group}, nil
	case tagged.JSONPath != nil:
		if strings.TrimSpace(*tagged.JSONPath) == "" {
			return extractHowSpec{}, fmt.Errorf("extraction %q extracts by an empty json path, so there is "+
				"nothing to look up", d.Name)
		}
		return extractHowSpec{JSONPath: *tagged.JSONPath}, nil
	default:
		return extractHowSpec{}, fmt.Errorf("extraction %q: %s names no extraction method", d.Name, string(d.How))
	}
}

// extractionToDto is the inverse: what a stored extraction looks like on the wire, so a rule the
// operator saved reads back as the rule they typed.
func extractionToDto(ex *session.Extraction) sessionExtractDto {
	d := sessionExtractDto{Name: ex.Name}
	if ex.From == "header" {
		d.From = json.RawMessage(mustJSON(map[string]string{"header": ex.Header}))
	} else {
		d.From = json.RawMessage(`"body"`)
	}
	if ex.JSONPath != "" {
		d.How = json.RawMessage(mustJSON(map[string]string{"json_path": ex.JSONPath}))
		return d
	}
	if ex.Pattern == wholeValuePattern && ex.Group == 0 {
		d.How = json.RawMessage(`"whole"`)
		return d
	}
	d.How = json.RawMessage(mustJSON(map[string]interface{}{
		"regex": map[string]interface{}{"pattern": ex.Pattern, "group": ex.Group},
	}))
	return d
}

// mustJSON marshals a map built from strings and ints, which cannot fail. The fallback is `null`
// rather than a panic so a marshalling bug degrades to one visibly empty field instead of taking the
// whole API process down.
func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`null`)
	}
	return b
}

// sessionRuleDto mirrors the UI's RuleDto. scope is the shared ScopeInfo body (allow_all/rules);
// validity is the free-form validity JSON the UI edits as text.
type sessionRuleDto struct {
	ID      *int64          `json:"id,omitempty"`
	Name    string          `json:"name"`
	Enabled bool            `json:"enabled"`
	Scope   json.RawMessage `json:"scope,omitempty"`
	// ScopeParams is Burp's parameter scope (burpsy-react-ui-9hip): when set, the rule applies
	// only to requests carrying every named parameter. Nil is the unrestricted rule.
	ScopeParams []string `json:"scope_params,omitempty"`
	// ScopeTools is Burp's tools scope (so3): the tools this rule applies to, from the same
	// vocabulary the Logger's filter uses (toollog's tool names).
	//
	// A pointer so that "the operator unchecked every tool" is distinguishable from "this client
	// never sent a tools scope". They must not be the same value: absent means every tool, and
	// nothing checked means the rule applies to no request at all — dtoToRule refuses that rather
	// than silently widening it back to every tool, which is the reading that would let a
	// restriction the operator deliberately stated be quietly dropped.
	ScopeTools  *[]string        `json:"scope_tools,omitempty"`
	Steps       []sessionStepDto `json:"steps"`
	Validity    json.RawMessage  `json:"validity"`
	MaxAttempts *int             `json:"max_attempts,omitempty"`
	// Actions is the rule's ordered action list — Burp's rule shape (burpsy-react-ui-ayi), and the
	// list the executor actually runs.
	//
	// Served as the *effective* list, never a bare r.Actions: a rule installed before this existed,
	// or one whose row predates the column, behaves as the synthesised validity-check-plus-macro, and
	// an empty table here would draw a rule that does nothing while the proxy was doing what the
	// operator's macro said. EffectiveActions is the same value validate.go and actions_run.go read,
	// so what the editor shows and what the walk runs cannot disagree.
	//
	// Not omitempty: an absent field and an empty list are the same JSON, and "this rule does
	// nothing" is not a thing a rule can be.
	Actions []sessionActionDto `json:"actions"`
}

// sessionActionDto is one rule action on the wire, recursive where Burp recurses: a CheckValidity
// action's Then/Else are lists of the same shape. Depth is bounded by session.ValidateActions, which
// walks the whole tree, so the recursion cannot be used to make an unbounded document.
type sessionActionDto struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Stop    bool   `json:"stop,omitempty"`
	// Label is the operator-facing name (session.ActionKindLabel) — Burp's own words for the action.
	// Served with the palette below for the reason the tools list is served: a copy of the vocabulary
	// in the UI is a second vocabulary, and the failure it produces is silent — an editor that offers
	// a kind the API refuses, or spells one the API does not accept.
	Label string             `json:"label"`
	Macro []sessionStepDto   `json:"macro,omitempty"`
	Then  []sessionActionDto `json:"then,omitempty"`
	Else  []sessionActionDto `json:"else,omitempty"`

	Name        string `json:"name,omitempty"`
	Value       string `json:"value,omitempty"`
	In          string `json:"in,omitempty"`
	Match       string `json:"match,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Regex       bool   `json:"regex,omitempty"`
	Extension   string `json:"extension,omitempty"`
	// ValidateEvery is Burp's `validate_every_num_requests` (us12): check the session only on every
	// Nth request the rule handles. Zero is omitted from the wire, which is the pre-field behaviour
	// and what a client reading an older server's rules sees.
	ValidateEvery int `json:"validate_every,omitempty"`
}

// sessionActionKindDto is one entry of the action palette.
type sessionActionKindDto struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// sessionDeclinedActionDto records a Burp action this build deliberately does not implement.
type sessionDeclinedActionDto struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// sessionRulesResp mirrors the UI's RulesResp.
type sessionRulesResp struct {
	Wired bool             `json:"wired"`
	Rules []sessionRuleDto `json:"rules"`
	Hint  string           `json:"hint,omitempty"`
	// Tools is every tool name a rule's tools scope may name (so3), served so the editor's checklist
	// is built from the list this server actually enforces rather than a copy of it. A copy in the
	// UI would be a second vocabulary, and the failure it produces is silent in the direction that
	// matters: the editor offers a tool the API refuses, or omits one it accepts, and neither shows
	// up as an error anywhere.
	//
	// Never omitempty, for the reason the cookies response's AbsorbingFrom is not: an absent field
	// and an empty list are the same JSON, and "this server knows of no tools" is precisely the
	// fact a client must not confuse with "the server is too old to say".
	Tools []string `json:"tools"`
	// ActionKinds is the action palette, built from this build's own vocabulary rather than a copy in
	// the UI — same reasoning and same failure mode as Tools above.
	ActionKinds []sessionActionKindDto `json:"action_kinds"`
	// DeclinedActions names the Burp actions this port does not implement, with the reason it does
	// not. Served so the editor can show them with the reason attached: an action that is simply
	// absent from the palette reads as one the operator has not found yet, and this is the difference
	// between "burpsy does not do this" and "burpsy forgot".
	//
	// Never omitempty, for the same reason Tools is not: an empty list would then be
	// indistinguishable from a client that is too old to be told.
	DeclinedActions []sessionDeclinedActionDto `json:"declined_actions"`
}

// sessionCookiesResp mirrors the UI's CookiesResp.
type sessionCookiesResp struct {
	Wired   bool                 `json:"wired"`
	Cookies []sessionHostCookies `json:"cookies,omitempty"`
	Hint    string               `json:"hint,omitempty"`
	// Monitored is the monitored-tool set in force (burpsy-react-ui-sn3j): which surfaces may
	// absorb cookies. Reported beside AbsorbingFrom so the UI can render "attached" and
	// "absorbing" as the two different facts they are — a source switched off shows attached
	// in AbsorbingFrom and absent here.
	Monitored []string `json:"monitored,omitempty"`
	// AbsorbingFrom names the surfaces registered to feed the jar: "proxy", "macro", "crawler". This
	// is what makes an empty table readable. Three states render identically without it — the jar is
	// watched and nothing has flowed, the jar is watched and no origin has set a cookie, and nothing
	// is watching the jar at all — and only the third means the operator's next action cannot work.
	//
	// Never omitempty. An absent field and an empty list are the same JSON to a client, and "nothing
	// feeds this jar" is precisely the fact that must not be indistinguishable from "the server is
	// too old to say".
	AbsorbingFrom []string `json:"absorbing_from"`
	// ResponsesObserved is how many responses were offered to the jar, and SetCookiesAbsorbed how
	// many Set-Cookie header lines were found in them. Both are counted per offer, so
	// `responses_observed > 0` with `set_cookies_absorbed == 0` says "traffic flowed and no origin
	// set a cookie" — a measurement, not an absence of one.
	ResponsesObserved  uint64 `json:"responses_observed"`
	SetCookiesAbsorbed uint64 `json:"set_cookies_absorbed"`
}

type sessionHostCookies struct {
	// Host carries the full authority ("example.com:443"), not the bare hostname. A jar is keyed by
	// (host, port, tls), so two jars can share a hostname; rendering only the name would show two
	// rows that look like duplicates of each other while holding different cookies.
	Host    string              `json:"host"`
	Port    uint16              `json:"port"`
	TLS     bool                `json:"tls"`
	Cookies []sessionCookiePair `json:"cookies"`
}

// sessionCookiePair is one cookie as the Session page's table renders it. The value-only shape
// could not show the jar's scoping facts at all, and d18r's whole defect was that the table
// implied the jar had none: a cookie set with Path=/admin was displayed identically to one set
// for the whole site, and the jar sent both everywhere. The attributes here are the jar's own
// (RFC 6265 §5.3 model), so what the table says is what the jar does.
type sessionCookiePair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Path  string `json:"path,omitempty"`
	// Domain is the cookie's Domain attribute, empty for a host-only cookie. It is not the jar's
	// authority: an .example.com cookie lives in example.com's jar and can be sent to
	// subdomains, and the table is where that difference is visible.
	Domain   string    `json:"domain,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	Secure   bool      `json:"secure,omitempty"`
	HTTPOnly bool      `json:"http_only,omitempty"`
}

// sessionLoginReq mirrors the UI's login probe.
type sessionLoginReq struct {
	Probe sessionStepDto `json:"probe"`
}

// sessionLoginResp mirrors the UI's LoginResp, and carries one field per thing a RecoveryOutcome can
// say.
//
// Every outcome gets its own `outcome` tag rather than collapsing into ok/error, for the reason the
// coordinator's own docs give: a caller has to be able to tell "this is working" from "this has
// quietly stopped trying". That is the shape crates/web/src/routes/session.rs's `outcome_body`
// serves, and these fields are its union — only the ones an outcome actually carries are emitted.
type sessionLoginResp struct {
	// Outcome is one of: "no_rule_applies", "already_valid", "recovered", "rule_applied",
	// "still_invalid_after_relogin", "gave_up", "macro_failed", "retry_failed", "probe_failed".
	Outcome string `json:"outcome,omitempty"`
	Rule    string `json:"rule,omitempty"`
	RuleID  *int64 `json:"rule_id,omitempty"`
	// URL / Rules / Hint: no_rule_applies. The rule count and the hint are there because "nothing
	// happened" with no reason is the least actionable answer a login button can give.
	URL   string `json:"url,omitempty"`
	Rules *int   `json:"rules,omitempty"`
	Hint  string `json:"hint,omitempty"`
	// LoginAttempts: recovered / still_invalid_after_relogin / gave_up / retry_failed. How many times
	// the macro ran, so "worked first time" and "worked on the third try" are distinguishable.
	LoginAttempts *int `json:"login_attempts,omitempty"`
	// Attempt / StepIndex: macro_failed — the 1-based attempt and the step within it that could not
	// be sent, which is exactly what "update macro" repairs.
	Attempt   *int `json:"attempt,omitempty"`
	StepIndex *int `json:"step_index,omitempty"`
	// Validity: still_invalid_after_relogin — "valid" | "invalid" | "indeterminate".
	Validity string `json:"validity,omitempty"`
	// Response: recovered / still_invalid_after_relogin — what the retried original request returned.
	Response *sessionLoginResponseView `json:"response,omitempty"`
	// Error: macro_failed / retry_failed / probe_failed.
	Error string `json:"error,omitempty"`
	// Actions is what the matched rule's action list did, in the order it was reached, including the
	// actions that were skipped and why. On every outcome the coordinator produced: a rule is a list
	// of actions now, so "which of them ran" is part of the answer rather than a debugging extra —
	// and it is what makes a rule whose macro failed but whose header action worked legible as a
	// rule to fix rather than one to delete.
	Actions []sessionActionRanView `json:"actions,omitempty"`
}

// sessionActionRanView is one entry of that trace.
type sessionActionRanView struct {
	Index   int    `json:"index"`
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Detail  string `json:"detail,omitempty"`
	Changed bool   `json:"changed,omitempty"`
	Skipped string `json:"skipped,omitempty"`
}

func sessionActionsView(trace []session.ActionRan) []sessionActionRanView {
	if len(trace) == 0 {
		return nil
	}
	out := make([]sessionActionRanView, 0, len(trace))
	for _, a := range trace {
		out = append(out, sessionActionRanView{
			Index: a.Index, Kind: session.ActionKindName(a.Kind), Label: a.Label,
			Detail: a.Detail, Changed: a.Changed, Skipped: a.Skipped,
		})
	}
	return out
}

// sessionLoginResponseView is the retried original request's response, mirroring Rust's
// `response_view`.
type sessionLoginResponseView struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

// ---- conversions --------------------------------------------------------------------------------

// toolNames is every tool name burpsy has, in toollog's order, for the refusal below to name the
// alternatives. Built here rather than spelled as a literal so a tool added to toollog cannot be
// missing from the list an operator is shown when they mistype one — the shape of the drift this
// whole vocabulary-in-one-place arrangement exists to prevent.
func toolNames() []string {
	out := make([]string, 0, len(toollog.ToolAll))
	for _, t := range toollog.ToolAll {
		out = append(out, t.String())
	}
	return out
}

// scopeToolNames validates Burp's tools scope (so3) against the one vocabulary of tool names, which
// internal/toollog owns: `ToolFromName` is the same resolver the tool log's own wire round-trip
// uses, so the rule editor and the Logger's filter cannot disagree about what "crawler" means.
//
// A stated-but-empty list is refused rather than read as "every tool". Both readings are defensible
// in the abstract and only one is defensible here: a rule whose editor showed every tool unchecked
// and which then applied to every tool would be doing the opposite of what its own form said, and
// the operator has no way to tell. Refusing costs them one click; the other reading costs them the
// restriction they deliberately stated.
func scopeToolNames(sent *[]string) ([]string, error) {
	if sent == nil {
		return nil, nil
	}
	if len(*sent) == 0 {
		return nil, fmt.Errorf("the tools scope names no tools, so no request could ever trigger this rule; "+
			"omit scope_tools to apply the rule to every tool, or name at least one of %s", strings.Join(toolNames(), ", "))
	}
	for _, name := range *sent {
		if _, ok := toollog.ToolFromName(name); !ok {
			return nil, fmt.Errorf("the tools scope names %q, which is not a tool burpsy has; the tools are %s",
				name, strings.Join(toolNames(), ", "))
		}
	}
	// Stored exactly as sent, in the order sent: this is a set for matching, but the editor's own
	// order is what it renders back, and reordering it here would show the operator a list they
	// did not write.
	return append([]string(nil), (*sent)...), nil
}

// ruleToDto converts a stored rule into the UI wire shape. Scope is expressed with the same
// ScopeInfo body as /api/scope so the UI's scopeSummary renders it the same way.
func ruleToDto(r *session.SessionRule) sessionRuleDto {
	dto := sessionRuleDto{
		Name:     r.Name,
		Enabled:  r.Enabled,
		Steps:    make([]sessionStepDto, 0, len(r.Steps)),
		Validity: json.RawMessage(`{}`),
	}
	if r.ID > 0 {
		id := int64(r.ID)
		dto.ID = &id
	}
	if r.MaxAttempts > 0 {
		ma := r.MaxAttempts
		dto.MaxAttempts = &ma
	}
	if r.Validity != nil {
		if b, err := json.Marshal(r.Validity); err == nil {
			dto.Validity = b
		}
	}
	// Scope: express ScopeHosts as rules in the ScopeInfo shape, and the URL-scope mode and arms
	// beside them (7nh2). The arms have to be emitted here or the editor lies: dtoToRule reads
	// them back, so a rule saved as "Use custom scope" with a path prefix would come back as
	// "Include all URLs" with the arms blank — and the next save from that form would write the
	// blanks over the stored arms. That is the same restore-drops-a-field defect this file already
	// names for extractions, and it is worse here because the form keeps showing the operator a
	// scope their rule no longer has.
	// Emitted whenever the rule states anything about its scope, not only when it lists hosts: a
	// suite-mode rule and a custom rule scoped by path alone both carry no hosts, and keying the
	// block off ScopeHosts dropped their whole scope on the way out — the form reopened on
	// "Include all URLs" and the arms existed only until the next save.
	if r.ScopeHosts != nil || r.ScopeMode != "" || r.StatesURLArms() {
		hosts := make([]map[string]interface{}, 0, len(r.ScopeHosts))
		for _, h := range r.ScopeHosts {
			hosts = append(hosts, map[string]interface{}{"kind": "Include", "host": h})
		}
		scope := map[string]interface{}{
			// A suite-mode rule carries no hosts of its own; allow_all is what the suite reading
			// is, so the flag follows the mode rather than the host list alone.
			"allow_all": len(hosts) == 0 || r.ScopeMode == "suite",
			"rules":     hosts,
		}
		if r.ScopeMode != "" {
			scope["mode"] = r.ScopeMode
		}
		if r.ScopePathPrefix != "" {
			scope["path"] = r.ScopePathPrefix
		}
		if r.ScopePort != nil {
			scope["port"] = *r.ScopePort
		}
		if r.ScopeProtocol != "" {
			scope["protocol"] = r.ScopeProtocol
		}
		if b, err := json.Marshal(scope); err == nil {
			dto.Scope = b
		}
	}
	// Parameter scope rides its own field: it constrains by request content, not by origin,
	// so folding it into the hosts-shaped scope would be a type lie.
	if len(r.ScopeParams) > 0 {
		dto.ScopeParams = r.ScopeParams
	}
	// The tools scope likewise (so3): it constrains by which tool asked, which is neither an
	// origin nor the request's content. Emitted whenever the rule names a tool, so a save from
	// the editor cannot write the empty list over a restriction the operator stated — the same
	// restore-drops-a-field defect this function already names for extractions and the URL arms.
	if len(r.ScopeTools) > 0 {
		tools := append([]string(nil), r.ScopeTools...)
		dto.ScopeTools = &tools
	}
	// Extractions are stored in one flat list naming the step each one reads (session.Extraction.Step)
	// and are served back attached to that step, because that is the shape the UI edits them in — a
	// row under the step whose response they scrape. Emitting them was missing entirely, so a rule
	// with extractions read back as a rule without any, and the next save from the UI would have
	// silently dropped them for real.
	for i, step := range r.Steps {
		d := macroStepToDto(step)
		for _, ex := range r.Extractions {
			if ex != nil && ex.Step == i {
				d.Extract = append(d.Extract, extractionToDto(ex))
			}
		}
		dto.Steps = append(dto.Steps, d)
	}
	// The effective list, not r.Actions — see the field's comment: a rule whose row predates the
	// actions column would otherwise read back as a rule with no actions while the proxy ran its
	// macro, and the operator's next save from that form would make the empty table real.
	for _, a := range r.EffectiveActions() {
		dto.Actions = append(dto.Actions, actionToDto(a))
	}
	return dto
}

// actionToDto renders one action, recursively for a check's branches.
func actionToDto(a *session.Action) sessionActionDto {
	d := sessionActionDto{
		Kind:        session.ActionKindName(a.Kind),
		Label:       session.ActionKindLabel(a.Kind),
		Enabled:     a.Enabled,
		Stop:        a.Stop,
		Name:        a.Name,
		Value:       a.Value,
		In:          a.In,
		Match:       a.Match,
		Replacement: a.Replacement,
		Regex:       a.Regex,
		Extension:   a.Extension,
		// Only a check carries it, so only a check reports it: a non-zero value on any other kind is
		// refused by session.ValidateAction, and a rule that could not have been installed must not
		// read back as carrying a setting.
		ValidateEvery: validityCheckEvery(a),
	}
	// A macro action's own steps are emitted only when it carries them. An empty Macro means "the
	// rule's own Steps", and emitting the rule's steps here instead would launder that reference into
	// a copy — so an operator editing the rule's macro afterwards would find this action still
	// running the old text, with nothing in the editor saying so.
	for _, step := range a.Macro {
		d.Macro = append(d.Macro, macroStepToDto(step))
	}
	for _, child := range a.Then {
		d.Then = append(d.Then, actionToDto(child))
	}
	for _, child := range a.Else {
		d.Else = append(d.Else, actionToDto(child))
	}
	return d
}

// validityCheckEvery is the interval a check carries, or 0 for any other action kind.
func validityCheckEvery(a *session.Action) int {
	if a == nil || a.Kind != session.ActionCheckValidity {
		return 0
	}
	return a.ValidateEvery
}

// actionsToModel is the read direction. An unrecognised kind is an error rather than a skipped
// action: session.ParseActionKind's refusal names the accepted list, and silently dropping the entry
// would leave a rule that looks like the operator's while missing the step that authenticated it.
func actionsToModel(dtos []sessionActionDto) ([]*session.Action, error) {
	out := make([]*session.Action, 0, len(dtos))
	for i, d := range dtos {
		kind, err := session.ParseActionKind(d.Kind)
		if err != nil {
			return nil, fmt.Errorf("action %d: %w", i+1, err)
		}
		a := &session.Action{
			Kind:          kind,
			Enabled:       d.Enabled,
			Stop:          d.Stop,
			Name:          d.Name,
			Value:         d.Value,
			In:            d.In,
			Match:         d.Match,
			Replacement:   d.Replacement,
			Regex:         d.Regex,
			ValidateEvery: d.ValidateEvery,
			Extension:     d.Extension,
		}
		for _, s := range d.Macro {
			headers := make(map[string]string, len(s.Headers))
			for _, kv := range s.Headers {
				headers[kv[0]] = kv[1]
			}
			a.Macro = append(a.Macro, session.MacroStep{
				Method: s.Method, URL: s.URL, Headers: headers, Body: s.Body,
			})
		}
		if a.Then, err = actionsToModel(d.Then); err != nil {
			return nil, fmt.Errorf("action %d → then: %w", i+1, err)
		}
		if a.Else, err = actionsToModel(d.Else); err != nil {
			return nil, fmt.Errorf("action %d → else: %w", i+1, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// macroStepToDto renders one step. Headers are emitted in sorted order: a Go map has none, and an
// order that changes between two GETs of the same rule shows the operator a diff they did not make.
func macroStepToDto(step session.MacroStep) sessionStepDto {
	d := sessionStepDto{Method: step.Method, URL: step.URL, Body: step.Body}
	keys := make([]string, 0, len(step.Headers))
	for k := range step.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d.Headers = append(d.Headers, [2]string{k, step.Headers[k]})
	}
	return d
}

// dtoToRule converts the UI shape into a stored rule, then validates it. Validity and scope are
// parsed from their free-form JSON; a malformed validity block is refused because a broken validity
// rule silently re-logging in on every request would be worse than an error.
//
// The returned error is meant to be shown to the operator verbatim as a 400 — it is either a JSON
// parse failure, an extraction this port cannot run, or a *session.RuleError naming the rule and the
// exact thing wrong with it.
func dtoToRule(dto sessionRuleDto) (*session.SessionRule, error) {
	var validity *session.ValidityRule
	if len(dto.Validity) > 0 {
		if err := json.Unmarshal(dto.Validity, &validity); err != nil {
			return nil, err
		}
	}
	// Rust's scope is an Option<Scope>: omitted means "applies everywhere", and only a scope that was
	// *stated* and empty is refused (crates/session/src/rule.rs). Both collapse into the same empty
	// []string on a Go SessionRule, so which of the two this was has to be settled here, while the
	// wire form still says, and handed to validation — otherwise "allow_all" and "restrict me to
	// nothing" become indistinguishable and one of the two has to be answered wrongly.
	var scopeHosts []string
	scopeStated := false
	if len(dto.Scope) > 0 {
		var scope struct {
			AllowAll bool `json:"allow_all"`
			Rules    []struct {
				Kind     string  `json:"kind"`
				Host     *string `json:"host"`
				Path     *string `json:"path"`
				Port     *uint16 `json:"port"`
				Protocol *string `json:"protocol"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(dto.Scope, &scope); err != nil {
			return nil, err
		}
		scopeStated = !scope.AllowAll
		if !scope.AllowAll {
			for _, r := range scope.Rules {
				if r.Host != nil {
					scopeHosts = append(scopeHosts, *r.Host)
				}
			}
		}
	}
	tools, err := scopeToolNames(dto.ScopeTools)
	if err != nil {
		return nil, err
	}
	rule := session.NewSessionRule(dto.Name, scopeHosts, nil)
	rule.Enabled = dto.Enabled
	rule.ScopeParams = dto.ScopeParams
	rule.ScopeTools = tools
	// Burp's URL-scope radio (7nh2): the DTO carries the mode and the custom-scope arms; the
	// arms ride the scope block's first rule (the scope builder above flattens to hosts for the
	// host axis, and these three fields are the URL-matching arms Burp's editor holds per rule).
	if len(dto.Scope) > 0 {
		var arms struct {
			Mode     string  `json:"mode"`
			Path     string  `json:"path"`
			Port     *uint16 `json:"port"`
			Protocol string  `json:"protocol"`
		}
		if err := json.Unmarshal(dto.Scope, &arms); err == nil {
			if arms.Mode == "suite" || arms.Mode == "custom" {
				rule.ScopeMode = arms.Mode
			}
			// Stored exactly as sent. An earlier line trimmed the empty prefix, which is a no-op
			// spelled like a normalisation — the kind of line a later reader "fixes" into trimming
			// a leading slash and thereby changes which paths a rule covers. Burp's path arm is a
			// prefix of the request path, so the operator's own spelling is what is compared.
			rule.ScopePathPrefix = arms.Path
			rule.ScopePort = arms.Port
			if arms.Protocol == "http" || arms.Protocol == "https" {
				rule.ScopeProtocol = arms.Protocol
			}
		}
	}
	rule.Validity = validity
	// Omitted means the default, which NewSessionRule already applied. Overwriting it with 1 — as
	// this did — turned the UI's "default" placeholder into "one attempt only", so a login that
	// needed a second try to absorb a redirect race gave up where the Rust crate would have retried.
	if dto.MaxAttempts != nil {
		rule.MaxAttempts = *dto.MaxAttempts
	}
	// A stated list replaces the migrated shape outright, and a *stated but empty* list is refused
	// rather than accepted. Accepting it would be the worst of the three options: NormaliseActions
	// materialises the pre-action flow for any rule with an empty list, so an operator who deleted
	// every action would get the check-validity-and-replay-a-login rule back, silently — the editor
	// would then show a list they did not write. A nil field, which is what every client written
	// before this sends, means "not stated" and keeps the migrated reading.
	if dto.Actions != nil {
		if len(dto.Actions) == 0 {
			return nil, fmt.Errorf("actions is present but empty: a rule with no actions does nothing, " +
				"and a rule that quietly runs a login instead of nothing is worse than a refusal")
		}
		actions, err := actionsToModel(dto.Actions)
		if err != nil {
			return nil, err
		}
		rule.Actions = actions
	}
	for i, s := range dto.Steps {
		headers := make(map[string]string, len(s.Headers))
		for _, kv := range s.Headers {
			headers[kv[0]] = kv[1]
		}
		rule.Steps = append(rule.Steps, session.MacroStep{
			Method:  s.Method,
			URL:     s.URL,
			Headers: headers,
			Body:    s.Body,
		})
		// Every step's extractions, tagged with the step whose response they read. This was missing
		// outright: the DTO carried them, and nothing ever looked at the field, so an operator could
		// type a CSRF extraction, save, see it accepted, and get a macro that sent "{{csrf}}" as a
		// literal string.
		for _, e := range s.Extract {
			from, header, err := e.extractFrom()
			if err != nil {
				return nil, fmt.Errorf("step %d: %w", i, err)
			}
			how, err := e.extractHow()
			if err != nil {
				return nil, fmt.Errorf("step %d: %w", i, err)
			}
			// A pattern that does not compile, or a json path outside the supported subset, is the
			// operator's to fix and it has to be an error: an extraction dropped for being unusable
			// leaves a rule that looks configured and cannot log in. Both are refused here, while the
			// operator is looking at the form, rather than at login time where an unwalkable path would
			// report as "the token was not in the response".
			var ex *session.Extraction
			if how.JSONPath != "" {
				ex, err = session.NewJSONPathExtraction(e.Name, from, how.JSONPath)
				if err != nil {
					return nil, fmt.Errorf("step %d: extraction %q cannot use the json path %q: %w",
						i, e.Name, how.JSONPath, err)
				}
			} else {
				ex, err = session.NewExtraction(e.Name, from, how.Pattern, how.Group)
				if err != nil {
					return nil, fmt.Errorf("step %d: extraction %q has an unusable pattern %q: %w",
						i, e.Name, how.Pattern, err)
				}
			}
			ex.Header = header
			ex.Step = i
			rule.Extractions = append(rule.Extractions, ex)
		}
	}
	if err := session.ValidateRuleStatedScope(rule, scopeStated); err != nil {
		return nil, err
	}
	// A validity rule with Regex set states its patterns as regexes: compiling them HERE is
	// what turns "an uncompilable validity regex silently never fires" — a control that lies
	// by omission, the same rule the auto-pause follows — into a 400 naming the pattern.
	if err := session.ValidateValidityPatterns(rule.Validity); err != nil {
		return nil, err
	}
	return rule, nil
}

// ---- handlers -----------------------------------------------------------------------------------

func (s *Server) handleSessionRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.sessionRulesGet(w, r)
	case http.MethodPost:
		s.sessionRulesPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) sessionRulesGet(w http.ResponseWriter, r *http.Request) {
	rules := s.sessionCoordinator.AllRules()
	dtos := make([]sessionRuleDto, 0, len(rules))
	for _, rule := range rules {
		dtos = append(dtos, ruleToDto(rule))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionRulesResp{
		Wired:           true,
		Rules:           dtos,
		Tools:           toolNames(),
		ActionKinds:     sessionActionKinds(),
		DeclinedActions: sessionDeclinedActions(),
	})
}

// sessionActionKinds is the action palette, walked off the enum rather than written out here so a
// kind added to session without a label shows up as an empty label in the editor (visible) instead
// of as a kind the editor never offers (invisible, and read as "burpsy does not have it").
func sessionActionKinds() []sessionActionKindDto {
	out := make([]sessionActionKindDto, 0, session.ActionKindCount)
	for i := 0; i < int(session.ActionKindCount); i++ {
		kind := session.ActionKind(i)
		out = append(out, sessionActionKindDto{Kind: session.ActionKindName(kind), Label: session.ActionKindLabel(kind)})
	}
	return out
}

// sessionDeclinedActions is the Burp actions this build does not implement, named with the reason.
//
// One entry, and it is here rather than in a comment because Burp's own rule editor shows nine
// actions and this one shows eight: an operator following Burp's documentation would otherwise be
// left to conclude the ninth was overlooked. Each reason states what burpsy has instead, so the
// operator can reach a decision rather than only learning a thing is missing.
func sessionDeclinedActions() []sessionDeclinedActionDto {
	return []sessionDeclinedActionDto{{
		Name: "Prompt the user for in-browser session recovery",
		Reason: "burpsy has no browser window to open for the operator: the console is a page the " +
			"operator opens themselves, and the headless engine this port owns (internal/domexec) " +
			"confirms findings rather than asking a person a question. Nothing here will silently wait " +
			"for someone who was never asked. Use the intercept hold queue to hand-edit the next request, " +
			"or an Invoke-an-extension action against a plugin that can do it.",
	}}
}

func (s *Server) sessionRulesPost(w http.ResponseWriter, r *http.Request) {
	var dto sessionRuleDto
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// No separate name check here any more: dtoToRule validates the whole rule, and the name is one of
	// the things it checks. Two checks for the same thing is two wordings that can drift apart, and
	// the operator would be told about a missing name in one voice and about everything else in
	// another.
	rule, err := dtoToRule(dto)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := s.sessionCoordinator.AddRule(rule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.persistSessionRules()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"rule": ruleToDto(s.sessionCoordinator.Rule(id))})
}

func (s *Server) handleSessionRuleDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/session/rules/")
	idStr = strings.TrimSuffix(idStr, "/")
	if strings.HasSuffix(idStr, "/update-macro") {
		s.sessionRuleUpdateMacro(w, r, idStr[:len(idStr)-len("/update-macro")])
		return
	}
	if strings.HasSuffix(idStr, "/run") {
		s.sessionRuleRunMacro(w, r, idStr[:len(idStr)-len("/run")])
		return
	}
	if strings.HasSuffix(idStr, "/test") {
		s.sessionRuleTestMacro(w, r, idStr[:len(idStr)-len("/test")])
		return
	}
	// Re-analyze (burpsy-react-ui-e23c): a dry-run plus the parameter-relationship
	// analysis over its responses. Read-only like /test — the apply is a separate route,
	// so an operator can look at what the analyzer found without committing to it.
	if strings.HasSuffix(idStr, "/analyze") {
		s.sessionRuleAnalyzeMacro(w, r, idStr[:len(idStr)-len("/analyze")])
		return
	}
	// Apply: add the chosen suggestions to the rule as extractions. The write is what
	// separates this from /analyze, and the split is the same one Test macro vs update-macro
	// already draws: look first, commit separately.
	if strings.HasSuffix(idStr, "/apply-extractions") {
		s.sessionRuleApplyExtractions(w, r, idStr[:len(idStr)-len("/apply-extractions")])
		return
	}
	if strings.HasSuffix(idStr, "/move") {
		s.sessionRuleMove(w, r, idStr[:len(idStr)-len("/move")])
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var dto sessionRuleDto
		if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		rule, err := dtoToRule(dto)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// "The rule is gone" and "the edit is not a valid rule" are different answers, so they get
		// different codes rather than one generic failure.
		if err := s.sessionCoordinator.UpdateRule(session.RuleID(id), rule); err != nil {
			if errors.Is(err, session.ErrNoSuchRule) {
				http.Error(w, "Rule not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.persistSessionRules()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"rule": ruleToDto(s.sessionCoordinator.Rule(session.RuleID(id)))})
	case http.MethodDelete:
		if s.sessionCoordinator.Rule(session.RuleID(id)) == nil {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}
		s.sessionCoordinator.RemoveRule(session.RuleID(id))
		s.persistSessionRules()
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// sessionLoginRuns tracks what a login run most recently replayed per rule, so "update macro" can
// promote the observed steps back onto the rule. Kept in the web layer: the coordinator owns rules,
// not the observation of a one-off probe.
type sessionLoginRuns struct {
	mu    chan struct{}
	steps map[int64][]sessionStepDto
}

func newSessionLoginRuns() *sessionLoginRuns {
	return &sessionLoginRuns{mu: make(chan struct{}, 1), steps: map[int64][]sessionStepDto{}}
}

// remember stores the steps a successful run replayed for a rule.
func (lr *sessionLoginRuns) remember(ruleID int64, steps []sessionStepDto) {
	lr.mu <- struct{}{}
	defer func() { <-lr.mu }()
	lr.steps[ruleID] = steps
}

// observed returns the steps last observed for a rule, or nil.
func (lr *sessionLoginRuns) observed(ruleID int64) []sessionStepDto {
	lr.mu <- struct{}{}
	defer func() { <-lr.mu }()
	return lr.steps[ruleID]
}

// handleSessionLogin is POST /api/session/login — the operator's "log in again" button.
//
// The order of operations is the point, and mirrors crates/web/src/routes/session.rs's `run_login`:
//
//  1. Resolve the rule covering the probe *before* sending anything. With no rule there is no macro
//     to run with whatever comes back, so sending the probe would cost a live target a request to no
//     purpose.
//  2. Send the probe with the coordinator's jar attached, so a probe that is *already* authenticated
//     looks authenticated. Sent outside the jar it would look permanently logged out and
//     "already_valid" would be unreachable in practice.
//  3. Hand the response to the coordinator's recovery path, which is what actually runs the login
//     macro (single-flight per rule, bounded by max_attempts) and retries the probe with the fresh
//     session.
//
// What this used to do instead: evaluate validity inline and, for anything other than Valid, report
// `outcome: "recovered"` without running the macro at all. The button reported success for having
// established nothing — the single worst answer available, because the operator moves on believing
// they are logged in. HandleRecovery and EnsureLoggedIn were fully implemented and tested with no
// caller outside their own package; this is the caller.
func (s *Server) handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req sessionLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	probe := req.Probe
	if strings.TrimSpace(probe.URL) == "" {
		http.Error(w, "A probe URL is required", http.StatusBadRequest)
		return
	}
	host, port, tls, err := targetParts(probe.URL)
	if err != nil {
		http.Error(w, "Invalid probe URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	probePath := "/"
	if u, perr := url.Parse(probe.URL); perr == nil && u.Path != "" {
		probePath = u.Path
	}
	step := stepDtoToMacroStep(probe)

	// (1) Nothing is sent until a rule is known to own this target — including parameter
	// scope (burpsy-react-ui-9hip) and the URL-scope arms (7nh2): the probe's own parameters
	// are what a parameter-restricted rule is judged against, and the probe's full identity
	// (host, path, port, scheme) is what a custom-scope or suite-scope rule is judged against.
	// The suite verdict is live Target-scope state, decided here rather than frozen on the rule.
	// The requesting tool is stated (so3), not left empty: these probes are the Session tool's own
	// traffic — the same attribution the tool log already records for them (toollog.ToolSession) —
	// so a rule restricted to, say, the crawler must not fire for them, and a rule restricted to
	// the session tool must.
	rule := s.sessionCoordinator.MatchingRuleForRequest(
		session.RequestIdentity{Host: host, Path: probePath, Port: port, TLS: tls, Tool: toollog.ToolSession.String()},
		probeParamNames(probe),
		func() bool { return s.scope.MayContainHost(host, port, tls) })
	if rule == nil {
		count := len(s.sessionCoordinator.AllRules())
		writeJSON(w, http.StatusOK, sessionLoginResp{
			Outcome: "no_rule_applies",
			URL:     probe.URL,
			Rules:   &count,
			Hint:    "no enabled rule's scope covers this url; add one, widen its scope, or enable it",
		})
		return
	}
	id := int64(rule.ID)

	runner := s.macroRunner(r.Context())

	// (2) The probe goes out through the same runner the macro's own steps use, so cookie handling and
	// tool-log recording are identical for both.
	response, err := runner(step)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, sessionLoginResp{
			Outcome: "probe_failed", Rule: rule.Name, RuleID: &id, Error: err.Error(),
		})
		return
	}

	// (3) The coordinator decides whether this counts as a valid session and, if not, runs the macro.
	outcome := s.sessionCoordinator.HandleRecovery(toollog.ToolSession.String(), step, response, runner)

	// Nothing is written to s.loginRuns here on purpose. A successful login already recorded what it
	// sent inside the coordinator (recordObserved, untemplated), and that is what
	// sessionRuleUpdateMacro now promotes. This used to remember the *probe* as the observed macro,
	// so pressing "update macro" afterwards replaced the operator's recorded login with a single GET
	// of the page they were checking — a button that destroyed the thing it claimed to repair.
	status, resp := loginOutcomeResponse(outcome)
	resp.Rule = rule.Name
	resp.RuleID = &id
	writeJSON(w, status, resp)
}

// loginOutcomeResponse is the faithful RecoveryOutcome -> (HTTP status, body) mapping, mirroring
// crates/web/src/routes/session.rs's `outcome_body`.
//
// 502 is used only for the two outcomes where a request could not be sent at all (macro_failed,
// retry_failed). Every outcome that reached a definite conclusion — including gave_up — is a 200 whose
// body says which, because "the login was attempted and did not work" is an answer, not a transport
// failure.
func loginOutcomeResponse(o session.RecoveryOutcome) (int, sessionLoginResp) {
	attempts := o.LoginAttempts
	switch o.Kind {
	case session.RecoveryNoRuleApplies:
		// Unreachable from handleSessionLogin, which resolves the rule before sending. Mapped anyway
		// rather than left to fall through, so a future caller that skips that step is answered
		// honestly instead of being told the login worked.
		return http.StatusOK, sessionLoginResp{Outcome: "no_rule_applies", URL: o.URL}
	case session.RecoveryAlreadyValid:
		return http.StatusOK, sessionLoginResp{
			Outcome: "already_valid",
			Actions: sessionActionsView(o.Actions),
		}
	case session.RecoveryRuleApplied:
		// No login was attempted; the rule's actions rewrote the request and it was re-sent. The
		// validity field is present when the rule states a check, and absent for a rule that does not
		// — which is not the same as a rule whose check passed.
		resp := sessionLoginResp{
			Outcome:  "rule_applied",
			Response: responseView(o.Response),
			Actions:  sessionActionsView(o.Actions),
		}
		if o.Validity != session.Indeterminate {
			resp.Validity = validityName(o.Validity)
		}
		return http.StatusOK, resp
	case session.RecoveryRecovered:
		return http.StatusOK, sessionLoginResp{
			Outcome:       "recovered",
			LoginAttempts: &attempts,
			Response:      responseView(o.Response),
			Actions:       sessionActionsView(o.Actions),
		}
	case session.RecoveryStillInvalidAfterRelogin:
		return http.StatusOK, sessionLoginResp{
			Outcome:       "still_invalid_after_relogin",
			LoginAttempts: &attempts,
			Validity:      validityName(o.Validity),
			Response:      responseView(o.Response),
			Actions:       sessionActionsView(o.Actions),
		}
	case session.RecoveryGaveUp:
		return http.StatusOK, sessionLoginResp{
			Outcome: "gave_up", LoginAttempts: &attempts, Actions: sessionActionsView(o.Actions),
		}
	case session.RecoveryMacroFailed:
		resp := sessionLoginResp{
			Outcome: "macro_failed", Attempt: &o.Attempt, Actions: sessionActionsView(o.Actions),
		}
		if o.Failure != nil {
			idx := o.Failure.StepIndex
			resp.StepIndex = &idx
			resp.Error = o.Failure.Error
		}
		return http.StatusBadGateway, resp
	case session.RecoveryRetryFailed:
		return http.StatusBadGateway, sessionLoginResp{
			Outcome: "retry_failed", LoginAttempts: &attempts, Error: o.Error,
			Actions: sessionActionsView(o.Actions),
		}
	}
	// A RecoveryOutcomeKind this mapping does not know is reported as such rather than silently
	// answered as a success: a variant added to the coordinator must be mapped here, and the honest
	// failure is what makes that visible.
	return http.StatusInternalServerError, sessionLoginResp{
		Outcome: "unmapped_outcome",
		Error:   fmt.Sprintf("recovery outcome kind %d has no wire mapping", int(o.Kind)),
	}
}

// probeParamNames lists the parameter names a login probe carries: its URL query, plus its
// body when the content type is form-urlencoded — the two places Burp's parameter scope reads.
// Headers/cookies are not parameters in Burp's sense here, and a JSON body has no parameter
// names without a schema to name them.
func probeParamNames(step sessionStepDto) []string {
	var names []string
	if u, err := url.Parse(step.URL); err == nil {
		names = append(names, queryParamNames(u.RawQuery)...)
	}
	// Form-urlencoded, decided by the step's own Content-Type rather than by looking for "=" in
	// the body. A JSON body such as {"redirect_uri":"...?csrf_token=abc&state=xyz"} carries "="
	// and would otherwise yield spurious parameter names from the query inside its string values,
	// and a param-scoped session rule would then match requests it should not. The step carries
	// its headers, so the answer is in hand; a step with no Content-Type gets no body parameters,
	// which is the same treatment Burp's parameter scope gives an unlabelled body.
	if contentTypeOfStep(step) == "application/x-www-form-urlencoded" {
		names = append(names, queryParamNames(step.Body)...)
	}
	return names
}

// contentTypeOfStep reads the Content-Type header off a step's own header list, lower-cased,
// or "" when there is none.
func contentTypeOfStep(step sessionStepDto) string {
	for _, h := range step.Headers {
		if strings.EqualFold(h[0], "Content-Type") {
			return strings.ToLower(strings.TrimSpace(h[1]))
		}
	}
	return ""
}

func responseView(r *session.StepResult) *sessionLoginResponseView {
	if r == nil {
		return nil
	}
	return &sessionLoginResponseView{Status: r.Status, Headers: r.Headers, Body: string(r.Body)}
}

func validityName(v session.ValidityState) string {
	switch v {
	case session.Valid:
		return "valid"
	case session.Invalid:
		return "invalid"
	default:
		return "indeterminate"
	}
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// stepDtoToMacroStep converts one wire step into the coordinator's shape. Headers arrive as an ordered
// [k,v] list and become a map, which is what session.MacroStep holds.
func stepDtoToMacroStep(step sessionStepDto) session.MacroStep {
	headers := make(map[string]string, len(step.Headers))
	for _, kv := range step.Headers {
		headers[kv[0]] = kv[1]
	}
	return session.MacroStep{Method: step.Method, URL: step.URL, Headers: headers, Body: step.Body}
}

// macroRunner is the session package's MacroStepRunner seam bound to this server's sender: it sends
// one step, records it in the tool log, and absorbs any Set-Cookie into the coordinator's jar.
//
// One implementation shared by the login probe, the recovery macro it triggers, and the manual
// "run macro" button, because these three must behave identically — a probe that dropped the headers
// the operator typed (which the old bespoke probe path did: it built a request carrying only `Host`)
// would evaluate a *different* request than the macro replays, so the validity verdict driving
// recovery would be about a request nobody asked to send.
//
// Every step leaves through an AuthorisedSender bound to that step's own authority, so the
// engagement scope decides about each step's request line before the dial (HARD-03). It used to call
// Sender.Send directly, which authorises nothing: a login macro pointed outside the engagement — by
// a typo, a stale saved rule, or a {{placeholder}} interpolating into a path — sent credentials to
// whatever it named. A fresh sender per step rather than one per macro because a macro's steps may
// name different authorities, and a sender bound to the first one would be the wrong gate for the
// rest; internal/crawler binds per hop for the same reason.
func (s *Server) macroRunner(ctx context.Context) session.MacroStepRunner {
	return func(step session.MacroStep) (*session.StepResult, error) {
		host, port, tls, err := targetParts(step.URL)
		if err != nil {
			return nil, err
		}
		if s.sender == nil {
			// Reported rather than dereferenced: a server assembled without a sender can still serve
			// the rules list, and the honest answer here is that nothing can be sent.
			return nil, fmt.Errorf("no HTTP sender is wired, so no session macro step can be sent")
		}
		if s.scope == nil {
			// Fail closed: a step that cannot be authorised is not sent. The alternative — treating a
			// missing scope as permission — is the whole defect this gate exists to prevent.
			return nil, fmt.Errorf("no engagement scope is wired, so no session macro step can be authorised")
		}
		method := strings.ToUpper(step.Method)
		if method == "" {
			method = "GET"
		}
		path := step.URL
		if i := strings.Index(step.URL, "://"); i >= 0 {
			if j := strings.Index(step.URL[i+3:], "/"); j >= 0 {
				path = step.URL[i+3+j:]
			} else {
				path = "/"
			}
		}
		req := &sender.Request{
			Method:  method,
			Host:    host,
			Path:    path,
			Headers: map[string]string{"Host": host},
			Body:    []byte(step.Body),
			TLS:     tls,
			Port:    port,
		}
		for k, v := range step.Headers {
			req.Headers[k] = v
		}
		// The coordinator attaches the jar's cookie to a step it owns; only fill one in when the step
		// did not carry one (the operator's own probe, typed by hand).
		if _, has := req.Headers["Cookie"]; !has {
			if cookie := s.sessionCoordinator.CookieHeader(host, port, tls, path); cookie != "" {
				req.Headers["Cookie"] = cookie
			}
		}
		resp, err := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls).SendRequest(ctx, req)
		if err != nil {
			// nil: the step never got a response to measure.
			s.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, 0, nil, 0, err.Error(), nil)
			return nil, err
		}
		hdrs := make(map[string]string, len(resp.Headers))
		for k, v := range resp.Headers {
			hdrs[k] = v
			if strings.EqualFold(k, "Set-Cookie") {
				// The step's own request identity (7nh2), including the tool that sent it (so3): a
				// path-, port- or tool-scoped rule is judged against the request that actually
				// produced this response.
				s.sessionCoordinator.HandleResponseFor(
					session.RequestIdentity{Host: host, Path: path, Port: port, TLS: tls, Tool: toollog.ToolSession.String()},
					resp.StatusCode, map[string]string{"Set-Cookie": v}, resp.Body,
					func() bool { return s.scope.MayContainHost(host, port, tls) })
			}
		}
		// The body's length, because a session step goes out through SendRequest, which returns a parsed
		// sender.Response and keeps no raw form: the header block's bytes were never retained and cannot
		// be re-derived without inventing them. So this is a real count of received bytes that
		// understates the wire by the headers — narrower than a repeater row's, and still a measurement,
		// which nil would not be.
		s.toolLog.Record(toollog.ToolSession, host, port, tls, method, path, resp.StatusCode,
			toollog.Bytes(len(resp.Body)), uint64(resp.Duration.Milliseconds()), "", nil)
		// FinalURL: where a redirect at this step points — the absolute resolution of the
		// Location header against the step's own URL, exactly the arithmetic the sender's
		// redirect follower uses. Resolved here, NOT followed: reading the target is what the
		// validity check needs (burpsy-react-ui-9prk); sending to it is a hop, and a hop is a
		// decision the operator or the redirect policy makes, never a side effect of a login
		// check.
		finalURL := ""
		if location, isRedirect := redirectTargetOf(resp.StatusCode, hdrs); isRedirect && location != "" {
			if base, perr := url.Parse(step.URL); perr == nil {
				if ref, rerr := url.Parse(location); rerr == nil {
					finalURL = base.ResolveReference(ref).String()
				}
			}
		}
		return &session.StepResult{Status: resp.StatusCode, Headers: hdrs, Body: resp.Body, FinalURL: finalURL}, nil
	}
}

// redirectTargetOf mirrors sender.redirectLocation's status list: the five redirects that
// carry a target. Kept local rather than exported from sender because the answer here is a
// string to compare, not a chain to follow — exporting the reader would invite a caller to
// treat "resolved" as "sent".
func redirectTargetOf(status int, hdrs map[string]string) (string, bool) {
	switch status {
	case 301, 302, 303, 307, 308:
	default:
		return "", false
	}
	for name, value := range hdrs {
		if strings.EqualFold(name, "Location") {
			return strings.TrimSpace(value), true
		}
	}
	return "", true
}

func (s *Server) sessionRuleUpdateMacro(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	// The coordinator's own observation comes first, because it is the better one: it holds the steps a
	// *successful* login actually sent, with this run's extracted values written back as their
	// {{placeholders}}. The web-layer mirror below holds them post-interpolation, so promoting it would
	// bake the one-time token this run scraped into the stored macro and the next login would replay a
	// stale one — turning a repair into a breakage. Coordinator.UpdateMacro had no caller outside its
	// own package before this; it does now.
	switch promoted := s.sessionCoordinator.UpdateMacro(session.RuleID(id)); promoted.Kind {
	case session.UpdateMacroUpdated:
		s.persistSessionRules()
		steps := make([]sessionStepDto, 0, len(promoted.Steps))
		for _, st := range promoted.Steps {
			steps = append(steps, macroStepToDto(st))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"steps": steps})
		return
	case session.UpdateMacroNoSuchRule:
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	case session.UpdateMacroInvalid:
		// A promotion the rule cannot hold — a run that sent fewer steps than the rule stores leaves an
		// extraction naming a step that no longer exists. Rust refuses the same case in `with_steps`
		// ("extractions belong to a step by position") because silently dropping what a vanished step
		// extracted is how a macro comes back looking repaired and still unable to log in.
		http.Error(w, promoted.Error, http.StatusConflict)
		return
	case session.UpdateMacroNothingObserved:
		// No login has run for this rule, but the manual "run macro" button may still have left a trace
		// in the web-layer mirror. Fall through to it rather than refusing something that is available.
	}

	steps := s.loginRuns.observed(id)
	if len(steps) == 0 {
		// Nothing observed since the server started; refuse rather than offer a button that can
		// only fail.
		http.Error(w, "no macro run observed for this rule", http.StatusConflict)
		return
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	stepsCopy := make([]session.MacroStep, 0, len(steps))
	for _, st := range steps {
		stepsCopy = append(stepsCopy, stepDtoToMacroStep(st))
	}
	// A copy, so a refused promotion leaves the working rule exactly as it was rather than mutating it
	// in place and then failing to install it.
	promoted := *rule
	promoted.Steps = stepsCopy
	if err := s.sessionCoordinator.UpdateRule(session.RuleID(id), &promoted); err != nil {
		if errors.Is(err, session.ErrNoSuchRule) {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.persistSessionRules()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"steps": steps})
}

// sessionRunResp mirrors what a macro run reports: the steps actually sent (post-extraction), the
// per-step status codes, and the overall validity outcome.
type sessionRunResp struct {
	Outcome string           `json:"outcome"` // "valid" | "invalid" | "indeterminate" | "failed"
	Steps   []sessionRunStep `json:"steps"`
	Rule    string           `json:"rule,omitempty"`
	RuleID  *int64           `json:"rule_id,omitempty"`
}

type sessionRunStep struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status *int   `json:"status,omitempty"` // nil when the step was skipped or failed to send
}

// sessionRuleRunMacro replays a rule's full macro through the sender, threading cookies and
// extractions. The run also leaves its trace in the login-run memory so "update macro" can promote
// what actually happened.
func (s *Server) sessionRuleRunMacro(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}

	// The same runner the login probe and its recovery macro use, so all three send identically.
	sent, results, state := s.sessionCoordinator.RunMacro(rule, s.macroRunner(r.Context()))

	steps := make([]sessionRunStep, 0, len(sent))
	observed := make([]sessionStepDto, 0, len(sent))
	for i, st := range sent {
		var status *int
		if i < len(results) && results[i] != nil {
			sc := results[i].Status
			status = &sc
		}
		steps = append(steps, sessionRunStep{Method: st.Method, URL: st.URL, Status: status})
		if status != nil {
			observed = append(observed, macroStepToDto(st))
		}
	}
	// Remember what actually ran so "update macro" can promote it.
	if len(observed) > 0 {
		s.loginRuns.remember(id, observed)
	}

	outcome := "indeterminate"
	switch state {
	case session.Valid:
		outcome = "valid"
	case session.Invalid:
		outcome = "invalid"
	}
	resp := sessionRunResp{Outcome: outcome, Steps: steps, Rule: rule.Name, RuleID: &id}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// sessionRuleTestMacro serves POST /api/session/rules/{id}/test — Burp's "Test macro"
// (burpsy-react-ui-7zdm): a dry-run of the rule's steps, reporting each step's sent form (with the
// jar's Cookie threading visible), its response, the cookies the response set, and every
// extraction's outcome. Deliberately NOT the /run path: RunMacro also feeds the login-run memory
// so "update macro" can promote what ran, and a dry-run must not pollute that — an operator
// testing a macro is not logging in.
func (s *Server) sessionRuleTestMacro(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	report := s.sessionCoordinator.RunMacroDetailed(rule, s.macroRunner(r.Context()))
	status := "indeterminate"
	switch report.Status {
	case session.Valid:
		status = "valid"
	case session.Invalid:
		status = "invalid"
	}
	// The report's Response is session.StepResult, which has no json tags — raw, it would wire
	// "Status"/"Headers"/"Body" (and base64 body bytes), and TypeScript's case-sensitive reads
	// would see undefined everywhere. Project to an explicit lowercase DTO; the body rides as
	// text because a macro response is a login exchange the operator reads, not binary evidence.
	w.Header().Set("Content-Type", "application/json")
	steps := make([]sessionTestStepView, 0, len(report.Steps))
	for _, s0 := range report.Steps {
		view := sessionTestStepView{
			Index: s0.Index, Sent: s0.Sent, SentCookie: s0.SentCookie,
			Skipped: s0.Skipped, SetCookies: s0.SetCookies, Extractions: s0.Extractions,
		}
		if s0.Response != nil {
			view.Response = &sessionTestResponseView{
				Status:  s0.Response.Status,
				Headers: s0.Response.Headers,
				Body:    string(s0.Response.Body),
			}
		}
		steps = append(steps, view)
	}
	json.NewEncoder(w).Encode(map[string]any{"rule": rule.Name, "rule_id": id, "status": status, "steps": steps})
}

// sessionTestStepView is the lowercase wire shape of session.MacroStepReport for /test; see the
// handler for why the projection exists.
type sessionTestStepView struct {
	Index       int                             `json:"index"`
	Sent        session.MacroStep               `json:"sent"`
	SentCookie  string                          `json:"sent_cookie,omitempty"`
	Skipped     string                          `json:"skipped,omitempty"`
	Response    *sessionTestResponseView        `json:"response,omitempty"`
	SetCookies  []string                        `json:"set_cookies,omitempty"`
	Extractions []session.MacroExtractionReport `json:"extractions,omitempty"`
}

type sessionTestResponseView struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// sessionRuleAnalyzeMacro serves POST /api/session/rules/{id}/analyze — Burp's "Re-analyze
// macro" (burpsy-react-ui-e23c). It runs the same dry-run /test runs, then reads the responses
// for the three parameter-relationship classes Burp's own docs name (hidden form fields,
// Set-Cookie names, query strings in links) and returns the extractions that would capture
// them. Read-only: nothing is written to the rule, the login-run memory, or the jar beyond
// what the dry-run itself already does.
func (s *Server) sessionRuleAnalyzeMacro(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	report := s.sessionCoordinator.RunMacroDetailed(rule, s.macroRunner(r.Context()))
	suggestions := session.AnalyzeMacro(rule, report)
	// The suggestions carry the step index they were found in; the UI shows them beside the
	// dry-run it just watched, so the step's own response is the context the operator reads.
	if suggestions == nil {
		suggestions = []session.ExtractionSuggestion{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"rule_id":     id,
		"suggestions": suggestions,
		// The honest count Burp's dialog implies: how many relationships were found that the
		// rule does not already capture. Same number as the list; carried so a caller can say
		// "found 3" without re-deriving it.
		"found": len(suggestions),
	})
}

// sessionRuleApplyExtractions serves POST /api/session/rules/{id}/apply-extractions — the
// apply half of Re-analyze. The body names which suggested extractions to add, by name, so
// the operator picks from the list they were shown; the server rebuilds each extraction from
// its own suggestion (the client never posts an extraction shape, which would let a stale
// suggestion overwrite a good one).
func (s *Server) sessionRuleApplyExtractions(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	rule := s.sessionCoordinator.Rule(session.RuleID(id))
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	var req struct {
		Names []string `json:"names"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Names) == 0 {
		http.Error(w, "Nothing to apply: name the suggestions to add", http.StatusBadRequest)
		return
	}
	// Re-run the analysis the operator saw, and match by name. The suggestions are rebuilt
	// server-side from the same dry-run that produced them, so what lands in the rule is a
	// working extraction, not whatever shape arrived on the wire.
	report := s.sessionCoordinator.RunMacroDetailed(rule, s.macroRunner(r.Context()))
	suggestions := session.AnalyzeMacro(rule, report)
	applied := make([]string, 0, len(req.Names))
	for _, want := range req.Names {
		for i := range suggestions {
			if suggestions[i].Name != want {
				continue
			}
			ex, err := session.NewExtraction(suggestions[i].Name, suggestions[i].From, suggestions[i].Pattern, suggestions[i].Group)
			if err != nil {
				http.Error(w, fmt.Sprintf("Suggestion %q does not compile: %v", want, err), http.StatusBadRequest)
				return
			}
			ex.Header = suggestions[i].Header
			ex.Step = suggestions[i].Step
			if err := s.sessionCoordinator.AddExtraction(session.RuleID(id), ex); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			applied = append(applied, want)
			break
		}
	}
	if len(applied) == 0 {
		// A name that matches no current suggestion is a stale list: the responses changed
		// between the analyze and the apply, and silently ignoring that would let the UI
		// claim a wiring that did not happen.
		http.Error(w, "No named suggestion is current — the responses changed since the analysis; re-analyze", http.StatusConflict)
		return
	}
	s.persistSessionRules()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"rule_id": id,
		"applied": applied,
		"rule":    ruleToDto(s.sessionCoordinator.Rule(session.RuleID(id))),
	})
}

// handleSessionTrace serves GET /api/session/trace and POST /api/session/trace/enable
// (burpsy-react-ui-n29) — Burp's session-handling tracer.
//
// GET answers the recorded entries plus whether the tracer is on. POST {enabled: bool} turns
// it on or off; turning it off keeps what was recorded (see traceRing.setEnabled) because the
// entries are the evidence the operator enabled the tracer to collect.
//
// The routes are one subtree: /api/session/trace and /api/session/trace/enable. Two doors on
// one store is how every other toggle here is served (the jar's monitor action lives beside
// its reads), and a separate enable endpoint would be a second route file for one boolean.
func (s *Server) handleSessionTrace(w http.ResponseWriter, r *http.Request) {
	if s.sessionCoordinator == nil {
		http.Error(w, "the session tracer is not attached to this process: no session coordinator is running", http.StatusServiceUnavailable)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/session/trace")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		// ActionRan has no json tags — raw, the wire would spell "Index"/"Kind" and the UI's
		// case-sensitive reads would see undefined everywhere (the same projection discipline
		// sessionTestStepView exists for). Projected here to the lowercase shape the UI holds.
		entries := s.sessionCoordinator.TracerEntries()
		views := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			view := map[string]any{
				"at": e.At, "tool": e.Tool, "host": e.Host, "path": e.Path,
				"rule": e.Rule, "rule_id": e.RuleID, "kind": e.Kind,
			}
			actions := make([]map[string]any, 0, len(e.Actions))
			for _, a := range e.Actions {
				actions = append(actions, map[string]any{
					"index": a.Index, "kind": session.ActionKindName(a.Kind), "label": a.Label,
					"detail": a.Detail, "changed": a.Changed, "skipped": a.Skipped,
				})
			}
			view["actions"] = actions
			views = append(views, view)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"enabled": s.sessionCoordinator.TracerEnabled(),
			"entries": views,
			// The bound is stated with the data because Burp's own overhead warning is the
			// reason for both: an operator reading 200 entries should know that is the cap,
			// not the total, and that the oldest were dropped.
			"capacity": 200,
		})
	case rest == "/enable" && r.Method == http.MethodPost:
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
			http.Error(w, "body must be JSON {enabled: bool}", http.StatusBadRequest)
			return
		}
		s.sessionCoordinator.SetTracerEnabled(req.Enabled)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"enabled": s.sessionCoordinator.TracerEnabled(),
		})
	default:
		http.Error(w, "Method not allowed: GET /api/session/trace, POST /api/session/trace/enable {enabled}", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSessionCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.handleSessionCookiesMutate(w, r)
		return
	}
	// This used to answer `{"wired": true, "cookies": []}` unconditionally, explaining that the jar
	// had no enumeration API. That was accurate about the code and wrong about the session: after any
	// authenticated flow the coordinator holds cookies and attaches them to outgoing requests, so the
	// operator's cookie table asserted "no cookies" about a live session. The jar now enumerates
	// (session.CookieJarManager.Jars), so the honest answer is available and is given.
	//
	// Wired is no longer a constant either. It reports whether a coordinator is attached at all,
	// which is the question the UI's "the cookie jar is not attached to this process" state asks; a
	// hardcoded true answered it wrongly for every server built without one.
	w.Header().Set("Content-Type", "application/json")
	if s.sessionCoordinator == nil {
		json.NewEncoder(w).Encode(sessionCookiesResp{
			Wired:         false,
			Hint:          "No session coordinator is attached to this server, so no cookie jar exists to read.",
			AbsorbingFrom: []string{},
		})
		return
	}
	entries := s.sessionCoordinator.Cookies()
	out := make([]sessionHostCookies, 0, len(entries))
	for _, entry := range entries {
		// The jar projection is already a name-sorted slice (loa1), so the loop is a straight
		// copy — the sort that used to live here was a patch over the map's lack of one.
		pairs := make([]sessionCookiePair, 0, len(entry.Cookies))
		for _, attrs := range entry.Cookies {
			pairs = append(pairs, sessionCookiePair{Name: attrs.Name, Value: attrs.Value, Path: attrs.Path, Domain: attrs.Domain, Expires: attrs.Expires, Secure: attrs.Secure, HTTPOnly: attrs.HTTPOnly})
		}
		out = append(out, sessionHostCookies{
			Host:    net.JoinHostPort(entry.Host, strconv.Itoa(int(entry.Port))),
			Port:    entry.Port,
			TLS:     entry.TLS,
			Cookies: pairs,
		})
	}
	obs := s.sessionCoordinator.Observation()
	sources := make([]string, 0, len(obs.Sources))
	for _, src := range obs.Sources {
		sources = append(sources, string(src))
	}
	resp := sessionCookiesResp{
		Wired:              true,
		Cookies:            out,
		AbsorbingFrom:      sources,
		ResponsesObserved:  obs.ResponsesObserved,
		SetCookiesAbsorbed: obs.SetCookiesAbsorbed,
		Monitored:          s.sessionCoordinator.MonitoredSources(),
	}
	if len(out) == 0 {
		// An empty table, an unread one and an unwatched one look the same on screen, so the empty
		// case says which it is — and says it from the counters rather than from a belief about how
		// the process was wired. The three branches are the three distinct facts; collapsing them is
		// what let "send authenticated traffic through the proxy" ship as advice while no code on the
		// proxy path absorbed anything.
		switch {
		case len(sources) == 0:
			resp.Hint = "The cookie jar is attached and nothing feeds it: no surface in this process " +
				"is registered to absorb Set-Cookie, so it will stay empty no matter what traffic flows."
		case obs.ResponsesObserved == 0:
			resp.Hint = "The cookie jar is attached and empty, and no response has reached it yet. " +
				"Absorbing from: " + strings.Join(sources, ", ") + "."
		default:
			resp.Hint = fmt.Sprintf(
				"The cookie jar is attached and empty: %d response(s) reached it and none carried a "+
					"Set-Cookie. Absorbing from: %s.", obs.ResponsesObserved, strings.Join(sources, ", "))
		}
	}
	json.NewEncoder(w).Encode(resp)
}

// handleSessionCookiesMutate is the cookie jar's write surface (dkb): Burp's cookie jar dialog
// — "you can edit cookies manually, remove cookies from the jar, or empty the jar altogether".
// One route, three actions, because they are three verbs over the same resource and a fourth
// wire shape for each would be three more manifest rows to keep honest.
//
// The authority comes from the request body (host/port/tls) rather than the URL, matching the
// read side's flat list: an operator edits what the table showed them, and the table's rows
// carry exactly these three fields. Every action refuses when no coordinator is attached — the
// read side reports wired=false for that case, and a write that succeeds against a jar nobody
// reads would be the same lie the GET endpoint's old constant-true was.
//
// Edit and remove are per-cookie (name required); clear empties one authority's jar. All three
// report what changed, because a silence that reads as success is how a stale cookie survives
// an operator's attempt to kill it.
func (s *Server) handleSessionCookiesMutate(w http.ResponseWriter, r *http.Request) {
	if s.sessionCoordinator == nil {
		http.Error(w, "the cookie jar is not attached to this process: no session coordinator is running, so there is nothing to edit", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed: POST {action: set | remove | clear, host, port, tls, name, value}", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action string `json:"action"`
		Host   string `json:"host"`
		Port   uint16 `json:"port"`
		TLS    bool   `json:"tls"`
		Name   string `json:"name"`
		Value  string `json:"value"`
		// Tools is the monitored-tool set for the "monitor" action (burpsy-react-ui-sn3j) —
		// Burp's "configure the cookie jar to monitor any of the following tools". Not read
		// by any other action; a nil field keeps the current set.
		Tools []string `json:"tools"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "body must be JSON", http.StatusBadRequest)
		return
	}
	// The monitor action answers before the host check: it configures the jar as a whole,
	// not one authority's cookies. An empty tools list is refused (see SetMonitoredSources)
	// — un-monitoring every surface is a jar that can only stay empty, and the empty field is
	// also what a client that never heard of this action sends for every other action.
	if req.Action == "monitor" {
		if len(req.Tools) == 0 {
			http.Error(w, "tools is required to configure monitoring: name at least one surface for the jar to monitor", http.StatusBadRequest)
			return
		}
		s.sessionCoordinator.SetMonitoredSources(req.Tools)
		writeJSON(w, http.StatusOK, map[string]any{
			"action": "monitor",
			// Echoed from the coordinator rather than the request: the set in force is the
			// answer, and a trimmed name or a default the caller did not know about must show.
			"monitoring": s.sessionCoordinator.MonitoredSources(),
		})
		return
	}
	if strings.TrimSpace(req.Host) == "" {
		http.Error(w, "host is required: the jar is per-authority", http.StatusBadRequest)
		return
	}
	switch req.Action {
	case "set":
		if strings.TrimSpace(req.Name) == "" {
			http.Error(w, "name is required to set a cookie", http.StatusBadRequest)
			return
		}
		s.sessionCoordinator.SetCookie(req.Host, req.Port, req.TLS, req.Name, req.Value)
		writeJSON(w, http.StatusOK, map[string]any{"action": "set", "host": req.Host, "name": req.Name, "ok": true})
	case "remove":
		if strings.TrimSpace(req.Name) == "" {
			http.Error(w, "name is required to remove a cookie", http.StatusBadRequest)
			return
		}
		ok := s.sessionCoordinator.RemoveCookie(req.Host, req.Port, req.TLS, req.Name)
		writeJSON(w, http.StatusOK, map[string]any{"action": "remove", "host": req.Host, "name": req.Name, "removed": ok})
	case "clear":
		ok := s.sessionCoordinator.ClearJar(req.Host, req.Port, req.TLS)
		writeJSON(w, http.StatusOK, map[string]any{"action": "clear", "host": req.Host, "cleared": ok})
	default:
		http.Error(w, fmt.Sprintf("unknown action %q: want set, remove or clear", req.Action), http.StatusBadRequest)
	}
}

// sessionRuleMove serves POST /api/session/rules/{id}/move — rule precedence.
//
// Precedence is not cosmetic here: MatchingRule runs the first enabled rule whose scope covers a
// host, walking the coordinator's order slice, so when two rules both cover a host their order
// decides which login actually runs. PUT deliberately keeps a rule's position (an edit must not
// silently re-prioritise it), which is why changing the order needs its own endpoint.
//
// The three refusals are kept apart, the way MoveRule keeps its two sentinels apart: an unknown id
// is 404, a move that would run off either end is 400 naming the edge, and a wrong verb is 405 with
// an Allow header. Collapsing the edge case into a generic 400 would tell an operator "bad request"
// about a request that was well-formed and simply had nowhere to go.
func (s *Server) sessionRuleMove(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid rule id", http.StatusBadRequest)
		return
	}
	var body struct {
		Offset int `json:"offset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	position, err := s.sessionCoordinator.MoveRule(session.RuleID(id), body.Offset)
	switch {
	case errors.Is(err, session.ErrNoSuchRule):
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	case errors.Is(err, session.ErrRuleAtEdge):
		// The sentinel's own text names the edge and the list length, so it is passed through
		// rather than restated.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The order is part of what a restart must restore: a rule that wins today has to win after a
	// restart, or precedence silently resets to creation order.
	s.persistSessionRules()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "position": position})
}
