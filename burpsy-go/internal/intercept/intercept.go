// Package intercept implements the request/response hold queue that lets an
// operator pause live proxy traffic, inspect it, and forward or drop it.
//
// Two rule lists (requests and responses) decide what gets held. Each list is
// either off, unconditional (on with no enabled rules — hold everything in that
// direction), or selective (on with enabled rules — hold only matching
// messages). A held message blocks its proxy connection until the operator
// resolves it; the resolution carries the possibly-edited raw bytes back to the
// proxy, which is the only channel through which an edited message ever reaches
// the wire.
package intercept

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Direction names one rule list / hold queue.
//
// # Why WebSocket is two directions and not one
//
// Burp intercepts WebSocket frames per direction, because the operator's reason for holding
// one is asymmetric: a client→server frame is the thing they want to tamper with, and a
// server→client frame is the thing they want to read before the page sees it. Collapsing them
// into a single "websocket" list would mean an operator who wants to edit outgoing frames also
// has every incoming frame stop in front of them, which on a chatty socket is unusable.
type Direction int

const (
	DirectionRequest Direction = iota
	DirectionResponse
	// DirectionWebSocketToServer is a frame the client sent, held before it is relayed upstream.
	DirectionWebSocketToServer
	// DirectionWebSocketToClient is a frame the origin sent, held before it reaches the browser.
	DirectionWebSocketToClient
	// DirectionCount is how many directions exist and must stay last. The Engine sizes its list
	// array from it, so adding a direction above without extending anything is a compile error
	// rather than a silent misroute.
	DirectionCount = iota
)

// directionNames is indexed by Direction, so a new direction that is not named here fails the
// exhaustiveness test rather than borrowing a neighbour's label.
var directionNames = [DirectionCount]string{
	DirectionRequest:           "request",
	DirectionResponse:          "response",
	DirectionWebSocketToServer: "websocket_to_server",
	DirectionWebSocketToClient: "websocket_to_client",
}

// String names the direction.
//
// It used to be `if d == DirectionRequest { "request" }; return "response"` — a two-value
// assumption that would have reported every WebSocket direction as "response" the moment one
// existed, in the API, in the held queue and in the logs. Indexed now, and out-of-range says so
// rather than guessing.
func (d Direction) String() string {
	if d < 0 || int(d) >= DirectionCount {
		return "unknown_direction"
	}
	return directionNames[d]
}

// IsWebSocket reports whether this direction carries WebSocket frames rather than HTTP
// messages. Callers that can only handle one or the other ask this instead of comparing against
// a list of constants they would have to keep in step.
func (d Direction) IsWebSocket() bool {
	return d == DirectionWebSocketToServer || d == DirectionWebSocketToClient
}

// Field is what a rule matches against.
type Field int

const (
	FieldHost Field = iota
	FieldPath
	FieldExtension
	FieldMethod
	FieldURL
	FieldStatusCode
	FieldContentType
	// The four below are the axes burpsy had no way to write a rule about, so "hold requests to
	// port 8443" and "hold the response whose body contains X" were not expressible at all
	// (burpsy-react-ui-1cuc). Burp's rule dialog offers 18 match types (Zero.java:18-54, an 18-case
	// factory; the dialog's own labels at map_root.tsv:27646-27661) and burpsy had seven.
	//
	// Appended, never inserted: a Field is a wire value, and an operator's saved rule names one.
	// Re-numbering the existing seven would silently re-point every rule already written.
	//
	// Port and Protocol are request-shaped facts the message already carries. RequestBody and
	// ResponseBody read the message's own bytes, and are the only additions that make a rule's
	// DEPEND on content — which is the point: in a high-volume stream the response that matters is
	// usually the one carrying a token or a stack trace, and a rule that cannot see bodies cannot
	// hold it.
	FieldPort
	FieldProtocol
	FieldRequestBody
	FieldResponseBody
)

func (f Field) String() string {
	switch f {
	case FieldHost:
		return "host"
	case FieldPath:
		return "path"
	case FieldExtension:
		return "extension"
	case FieldMethod:
		return "method"
	case FieldURL:
		return "url"
	case FieldStatusCode:
		return "status_code"
	case FieldPort:
		return "port"
	case FieldProtocol:
		return "protocol"
	case FieldRequestBody:
		return "request_body"
	case FieldResponseBody:
		return "response_body"
	default:
		return "content_type"
	}
}

// ParseField maps the wire name (intercept.ts's MatchField) to a Field.
func ParseField(s string) (Field, error) {
	switch s {
	case "host":
		return FieldHost, nil
	case "path":
		return FieldPath, nil
	case "extension":
		return FieldExtension, nil
	case "method":
		return FieldMethod, nil
	case "url":
		return FieldURL, nil
	case "status_code":
		return FieldStatusCode, nil
	case "content_type":
		return FieldContentType, nil
	case "port":
		return FieldPort, nil
	case "protocol":
		return FieldProtocol, nil
	case "request_body":
		return FieldRequestBody, nil
	case "response_body":
		return FieldResponseBody, nil
	default:
		return FieldHost, fmt.Errorf("unknown match field %q", s)
	}
}

// Category is how a rule's pattern is interpreted.
type Category int

const (
	CategoryRegex Category = iota
	CategoryLiteral
)

// Action is what a matching rule does: Burp's per-rule "Do intercept" versus
// "Don't intercept". The zero value holds, so every rule written before this
// field existed keeps doing what it always did.
type RuleAction int

const (
	// RuleActionHold stalls a matching message in the queue.
	RuleActionHold RuleAction = iota
	// RuleActionPass lets a matching message through without holding it.
	RuleActionPass RuleAction = iota
)

// ParseRuleAction maps the wire/UI name to an Action. Anything else is refused at
// save time, like a malformed regex: a rule that silently held when the operator
// asked it to pass (or the reverse) would be a coin flip on the wire.
func ParseRuleAction(s string) (RuleAction, error) {
	switch s {
	case "hold", "intercept", "":
		return RuleActionHold, nil
	case "pass", "dont_intercept", "don't intercept":
		return RuleActionPass, nil
	default:
		return RuleActionHold, fmt.Errorf("unknown rule action %q: want \"hold\" or \"pass\"", s)
	}
}

func (a RuleAction) String() string {
	if a == RuleActionPass {
		return "pass"
	}
	return "hold"
}

// RuleOp is how one rule combines with the rules ABOVE it in the list.
//
// Burp has this column and this is why (settings/tools/proxy.html:246-268): "Each rule is
// combined to the rules above in order, using the selected boolean operator." Without it a
// conjunction cannot be written at all — "hold requests to host A and path /admin" is two rules
// that evaluate as a disjunction, so the operator either over-holds or writes one brittle rule
// that has to enumerate both facts in a single matcher. It is the most-written interception rule
// after "hold on this host".
//
// The default is RuleOpOr, and that default is not a convenience: it is what every list written
// before this field existed evaluates as, so the fold below reproduces the old first-matching-rule
// behaviour exactly when no rule says AND. See evaluate.
type RuleOp int

const (
	// RuleOpOr combines with the rules above by disjunction. The zero value, and therefore the
	// answer for a rule decoded from a document written before the field existed.
	RuleOpOr RuleOp = iota
	// RuleOpAnd combines by conjunction: every rule up to and including this one must match.
	RuleOpAnd
)

func (o RuleOp) String() string {
	if o == RuleOpAnd {
		return "and"
	}
	return "or"
}

// ParseRuleOp reads the wire spelling, defaulting anything unrecognised to OR.
//
// Defaulting rather than refusing is the same choice the action parser makes, and for the same
// reason: an unknown operator in a saved list must not stop the list working, and OR is the
// behaviour every pre-existing list has.
func ParseRuleOp(s string) RuleOp {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "and":
		return RuleOpAnd
	default:
		return RuleOpOr
	}
}

// Rule is one hold condition. Enabled rules are ANDed with the list switch;
// a list with any enabled rule holds only matching messages, a list with no
// enabled rules holds everything (unconditional).
type Rule struct {
	Field       Field
	Category    Category
	StringMatch string
	Enabled     bool
	Comment     string
	Action      RuleAction
	// Op combines THIS rule with the rules above it. It is ignored for the first enabled rule, which
	// has nothing above it — there is nothing to combine with — so setting AND on the top rule is
	// ignored rather than an error, which is what an operator who typed it expects.
	Op RuleOp

	re *regexp.Regexp
}

// NewRule compiles a rule, refusing a malformed regex (matching Burp, which
// reports a bad pattern when the list is saved rather than when it fires).
func NewRule(field Field, cat Category, match string, enabled bool, comment string, action RuleAction) (*Rule, error) {
	r := &Rule{
		Field:       field,
		Category:    cat,
		StringMatch: match,
		Enabled:     enabled,
		Comment:     comment,
		Action:      action,
	}
	if cat == CategoryRegex && match != "" {
		re, err := regexp.Compile(match)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", match, err)
		}
		r.re = re
	}
	return r, nil
}

// Match tests a message against the rule. Rules whose field a direction cannot
// have (a request has no status code) never match, which is the honest reading:
// a response rule left in the request list is dead weight, not an error.
func (r *Rule) Match(m *Message) bool {
	if !r.Enabled || r.StringMatch == "" {
		return false
	}
	value := m.FieldValue(r.Field)
	if value == "" {
		return false
	}
	if r.Category == CategoryLiteral {
		return strings.Contains(strings.ToLower(value), strings.ToLower(r.StringMatch))
	}
	return r.re.MatchString(value)
}

// List is one direction's rule set plus its master switch.
type List struct {
	Active bool
	Rules  []*Rule
}

// Unconditional reports whether the list, when active, holds every message in
// its direction: on with no rules at all. (On with rules but all disabled holds
// nothing, which is a different and named state.)
func (l *List) Unconditional() bool {
	return l.Active && len(l.Rules) == 0
}

// EnabledRules returns the rules that could match (enabled and non-empty).
func (l *List) EnabledRules() []*Rule {
	var out []*Rule
	for _, r := range l.Rules {
		if r.Enabled && r.StringMatch != "" {
			out = append(out, r)
		}
	}
	return out
}

// Message is the per-exchange view the proxy hands the engine. Raw is the
// verbatim bytes so the held message can be edited and forwarded unchanged.
type Message struct {
	Direction   Direction
	Host        string
	Port        uint16
	TLS         bool
	Method      string
	Path        string
	Status      *int
	ContentType string
	Raw         []byte
	// Opcode is the WebSocket frame opcode's name ("text", "binary", …) and is
	// empty for HTTP, which has no equivalent. It is carried because "text" and
	// "binary" are different editing contexts: an operator handed a binary frame
	// with no marking will reasonably treat the payload as text, and an edit made
	// on that assumption goes on the wire as a valid frame with a corrupted body.
	// Burp labels the frame type for the same reason.
	Opcode string
}

// DirectionHasField reports whether a message in direction d can supply field f at all.
//
// This is the dead-weight rule: a rule naming a field its direction cannot supply matches NOTHING,
// silently, and a rule that can never match is indistinguishable from a target that never sends it.
// So the two are told apart here and the caller can say so — a response list whose rule matches on
// RequestBody is a rule the operator wrote wrong, not a quiet one.
//
// The request/response split is the shape that matters: a request has no status code, content type
// or response body, and a response has no request body. Port, protocol, host, path, extension,
// method and url are supplied by BOTH, so a rule on those works in either list.
func (d Direction) HasField(f Field) bool {
	switch f {
	case FieldStatusCode, FieldContentType, FieldResponseBody:
		return d == DirectionResponse
	case FieldRequestBody:
		return d == DirectionRequest
	case FieldHost, FieldPath, FieldExtension, FieldMethod, FieldURL, FieldPort, FieldProtocol:
		return true
	default:
		return false
	}
}

// FieldValue returns the message's value for a rule field, or "" when the
// direction has none (a request has no status code or content type).
func (m *Message) FieldValue(f Field) string {
	// A field this direction cannot supply is "" before any lookup, so every caller gets the same
	// answer and the dead-weight check above is the only place that has to know the split.
	if !m.Direction.HasField(f) {
		return ""
	}
	switch f {
	case FieldHost:
		return m.Host
	case FieldPath:
		return m.Path
	case FieldExtension:
		return extensionOf(m.Path)
	case FieldMethod:
		return m.Method
	case FieldURL:
		return m.URL()
	case FieldStatusCode:
		if m.Status == nil {
			return ""
		}
		return strconv.Itoa(*m.Status)
	case FieldContentType:
		return m.ContentType
	case FieldPort:
		if m.Port == 0 {
			return ""
		}
		return strconv.Itoa(int(m.Port))
	case FieldProtocol:
		// "http" or "https", which is the axis an operator means by protocol when holding traffic
		// to one service rather than the other. A WebSocket frame's own protocol is not this: the
		// question a rule asks is which listener received it.
		if m.TLS {
			return "https"
		}
		return "http"
	case FieldRequestBody:
		return bodyOf(m.Raw, DirectionRequest)
	case FieldResponseBody:
		return bodyOf(m.Raw, DirectionResponse)
	default:
		return ""
	}
}

// bodyOf is the body half of a raw HTTP message, or "" when the bytes are not an HTTP message at
// all (a WebSocket frame, an unreadable message).
//
// A bounded read rather than the whole tail: a rule matching a body is asking a question about
// content, and a 12 MB upload answered with a copy of itself per evaluation is a cost a LIST endpoint
// is not supposed to pay. The bound is generous enough for the JSON, HTML and stack-trace bodies
// these rules are written for, and a body past it matches nothing rather than matching its prefix —
// which is stated rather than silent because a rule that stops matching at 1 MB would otherwise look
// like the target changed.
const ruleBodyReadLimit = 1 << 20

func bodyOf(raw []byte, want Direction) string {
	dir, body, ok := splitRawMessage(raw)
	if !ok || dir != want {
		return ""
	}
	if len(body) > ruleBodyReadLimit {
		body = body[:ruleBodyReadLimit]
	}
	return string(body)
}

// splitRawMessage answers which direction a raw message is and where its body starts, reusing the
// same tolerant CRLF-or-LF split the engine parses with — two splitters would eventually disagree
// about where a body begins, and a body rule matching one boundary while the capture used the other is
// a rule that works in testing and not against a real target.
func splitRawMessage(raw []byte) (Direction, []byte, bool) {
	headEnd, sep := indexCRLFCRLF(raw), 4
	if headEnd < 0 {
		// Bare LF, because a client that does not use CRLF is a real one and its body must be
		// matchable — a body rule that worked in testing against a hand-written fixture and never
		// against that client is worse than no rule, because it reads as configured.
		headEnd, sep = indexLFLF(raw), 2
	}
	if headEnd < 0 {
		return DirectionRequest, nil, false
	}
	dir := DirectionRequest
	if bytes.HasPrefix(raw, []byte("HTTP/")) {
		dir = DirectionResponse
	}
	return dir, raw[headEnd+sep:], true
}

// URL reconstructs the absolute URL for the url field.
func (m *Message) URL() string {
	scheme := "http"
	if m.TLS {
		scheme = "https"
	}
	host := m.Host
	if m.Port != 0 && !(scheme == "http" && m.Port == 80) && !(scheme == "https" && m.Port == 443) {
		host = netJoinHostPort(m.Host, m.Port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host + m.Path
}

func netJoinHostPort(host string, port uint16) string {
	// IPv6 needs brackets; plain hosts do not.
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// extensionOf returns the final path segment's extension without the dot
// ("/img/logo.png" -> "png"), or "" for a path without one.
func extensionOf(path string) string {
	if i := strings.LastIndex(path, "/"); i != -1 {
		path = path[i+1:]
	}
	if i := strings.LastIndex(path, "."); i != -1 {
		return path[i+1:]
	}
	return ""
}

// Action is how a held message is resolved.
type Action int

const (
	ActionForward Action = iota
	ActionDrop
)

// Target is a destination an operator has retargeted a held message to.
//
// Burp's intercept header bar carries an "Edit target" pencil beside the authority label
// (BurpClass9694.java: proxyInterceptEditTargetButton, tooltip "Click to modify"), which lets the
// operator send the item they are holding to a different host, port or scheme than the one the
// client asked for. burpsy rendered the authority twice and read-only, and the wire carried no
// destination at all, so the capability was absent end to end rather than merely unrendered
// (burpsy-react-ui-akv).
//
// # Why it is a value the caller must be given rather than a field anyone may read
//
// A retarget changes where bytes land, which is the one thing the engagement scope exists to decide.
// The proxy therefore has to see the edited destination *before* it authorises the request, and it
// cannot get that by reading a field off the hold whenever it likes — a field read after the
// decision would be an authorisation answered about one host and applied to another. So the target
// is returned from Wait, alongside the bytes, as part of one decision, and the proxy re-runs its
// scope check against what came back.
type Target struct {
	Host string
	Port uint16
	TLS  bool
}

// SameAs reports whether this target is the destination the message already had, so a caller can
// treat "the operator retyped the same host" exactly like "the operator changed nothing" — a
// distinction that matters because the retargeted path dials a fresh connection when the original
// connection is still usable.
func (t Target) SameAs(host string, port uint16, tls bool) bool {
	return t.Host == host && t.Port == port && t.TLS == tls
}

// Held is one queued message. The proxy blocks on Wait until the operator
// resolves it; the result carries the edited bytes for forwarding.
type Held struct {
	ID        uint64
	Direction Direction
	Host      string
	Port      uint16
	TLS       bool
	Method    string
	Path      string
	Status    *int
	Raw       []byte
	HeldAt    time.Time
	// Opcode mirrors Message.Opcode: the WebSocket frame type, empty for HTTP.
	Opcode string

	// Comment and Highlight are the operator's annotation on the held message
	// (burpsy-react-ui-5q8u). They live on the hold, not on any exchange — a held
	// message has no exchange yet — and they ride forward: when the hold resolves
	// into a recorded exchange, the proxy carries them to Record so the annotation
	// appears in HTTP history against the bytes the operator was looking at, which
	// is exactly Burp's "annotations that you make also appear against the item in
	// the HTTP history".
	Comment   string
	Highlight string

	done     chan struct{}
	mu       sync.Mutex
	resolved bool
	action   Action
	outRaw   []byte
	// target is the operator's edited destination, nil when they left it alone. Set only by Forward:
	// a dropped message has no destination, and inventing one would let a drop carry a retarget into
	// the history row of an exchange that never happened.
	target *Target
	// userEdited says the operator's edit buffer differed from the bytes the message arrived with,
	// which is Burp's history "Edited" column: "Flag whether the request or response were modified by
	// the user" (ProxyHttpRequestResponse.edited()).
	//
	// # Why this is decided here and not by whoever reads the bytes back
	//
	// The console sends the editor's current contents on *every* forward — intercept.tsx forwards
	// row.raw, the same buffer it rendered — so "a buffer was supplied" is not an edit, and a caller
	// downstream cannot tell an untouched buffer from a retyped one without comparing against
	// something it does not have. This struct is the only place holding both the bytes the operator
	// was shown (Raw) and the bytes they sent back.
	//
	// It is deliberately *not* derived from the recorded bytes differing from an earlier stage of
	// them. That reading counts burpsy's own rewrites as the operator's work: a request whose
	// Proxy-Connection header an egress option strips, or whose Content-Length fixContentLength
	// corrects, differs from the client's bytes without anyone having edited anything — and history
	// then reported "Edited" for traffic nobody had touched (burpsy-react-ui-sd0d).
	userEdited bool
	reason     string
}

// Wait blocks until the operator forwards or drops the message. It is safe to
// call once; the returned bytes are the possibly-edited message to put on the
// wire (forward) or nil (drop).
//
// The target is the operator's edited destination, nil when they left it alone. It is returned here
// rather than exposed as an accessor because it has to reach the caller as part of the same
// decision as the bytes: the proxy authorises the request against the destination it is about to
// use, and a destination fetched separately could be read before the operator's edit landed. The
// last value, userEdited, is returned for the same reason — it is the operator's decision about
// *this* message, and it is what history's "Edited" column must be told, not recomputed.
func (h *Held) Wait() (Action, []byte, *Target, bool) {
	<-h.done
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.action, h.outRaw, h.target, h.userEdited
}

// resolve marks the message resolved exactly once; a second resolve (e.g. an
// API request arriving twice) is ignored so the proxy cannot act on a stale
// decision.
func (h *Held) resolve(a Action, raw []byte, target *Target, userEdited bool, reason string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.resolved {
		return false
	}
	h.resolved = true
	h.action = a
	h.outRaw = raw
	h.target = target
	h.userEdited = userEdited
	h.reason = reason
	close(h.done)
	return true
}

// Engine is the intercept controller shared by the proxy and the web API.
type Engine struct {
	mu      chan struct{}
	enabled bool
	// lists is indexed by Direction rather than being one named field per direction.
	//
	// It was `requests` and `responses`, selected with `if d == DirectionRequest { … } else { … }`
	// in three places. That else is a silent misroute waiting for a third direction: a WebSocket
	// frame would have been matched against the response rules and held or released on the wrong
	// operator's intent. Indexing makes the direction the address instead of a branch, so adding
	// one cannot land in the wrong list.
	lists [DirectionCount]List
	// newlines is Burp's pair of newline corrections for an edited interception, both OFF by default
	// because each one rewrites bytes the operator wrote and neither is a correction anyone would
	// want applied to a request they did not edit (burpsy-react-ui-80tg). It is an engine setting
	// rather than a per-forward argument for the same reason fixContentLength is a per-forward
	// argument and these are not: they are part of how the interception tool behaves, an operator sets
	// them once, and threading them through Forward would put a setting on every call site that could
	// forget it.
	newlines NewlineCorrection
	nextID   uint64
	held     map[uint64]*Held
	// pending one-shot response holds (burpsy-react-ui-v6jw): Burp's "Do intercept >
	// Response to this request". Each names the request it was armed from; the first
	// response with identical attributes is held and the entry consumed, so arming
	// never leaks onto later unrelated traffic.
	pending []pendingResponse
	// onChange is an optional signal that the queue or the switch changed (see OnChange).
	onChange func()

	// inScopeOnly is Burp's "Only intercept in-scope messages" (burpsy-react-ui-cz1). Off by default,
	// matching Burp and matching the safer reading: a queue that silently skipped traffic would make
	// an operator think interception was broken rather than filtered.
	inScopeOnly bool
	// scope answers whether a message's authority is in the engagement scope. Nil means no scope was
	// attached, and see shouldHold for why that makes inScopeOnly refuse to filter rather than
	// filter everything out.
	scope ScopeChecker
}

// ScopeChecker is the engagement scope, narrowed to the one question this package asks.
//
// An interface rather than a *core.Scope so internal/intercept keeps no dependency on the store's
// package, and — more usefully — so a test can pin the in-scope-only behaviour without building a
// scope. It matches core.Scope.Contains exactly.
type ScopeChecker interface {
	Contains(host string, port uint16, path string, isTLS bool) bool
}

// pendingResponse is one armed "hold the response to this request".
type pendingResponse struct {
	// holdID is the held request this was armed from. Drop(id) retracts the arming,
	// because a dropped request has no response coming and a stale entry would fire
	// on a later unrelated request with identical attributes.
	holdID uint64
	host   string
	port   uint16
	method string
	path   string
}

// maxPendingResponses bounds armed-but-unforwarded response holds. Arming without
// forwarding would otherwise grow this list without bound, one entry per click.
const maxPendingResponses = 256

// NewEngine creates an intercept engine with both lists off.
func NewEngine() *Engine {
	return &Engine{
		mu:   make(chan struct{}, 1),
		held: make(map[uint64]*Held),
	}
}

// ArmResponseHold arms a one-shot hold for the response to one held request
// (burpsy-react-ui-v6jw). Only a held request qualifies: arming from anything else
// names a response that cannot be paired with anything.
func (e *Engine) ArmResponseHold(id uint64) error {
	e.mu <- struct{}{}
	defer e.signalChange()
	defer func() { <-e.mu }()
	h := e.held[id]
	if h == nil {
		return fmt.Errorf("no held message %d", id)
	}
	if h.Direction != DirectionRequest {
		return fmt.Errorf("message %d is not a held request", id)
	}
	if len(e.pending) >= maxPendingResponses {
		return fmt.Errorf("too many armed response holds (%d)", len(e.pending))
	}
	e.pending = append(e.pending, pendingResponse{
		holdID: h.ID,
		host:   h.Host,
		port:   h.Port,
		method: h.Method,
		path:   h.Path,
	})
	return nil
}

// PendingResponses counts armed one-shot response holds. Read by tests and by any
// surface that wants to say an arming is outstanding rather than silently holding one.
func (e *Engine) PendingResponses() int {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	return len(e.pending)
}

// OnChange installs the signal called after the held queue or the intercept switch changes, or nil to
// remove it. Single slot, so re-installing replaces rather than doubling.
//
// It exists for the live-update stream, and the held queue is the reason that stream is worth having:
// an operator sitting on the Intercept tab is *waiting* for a held request, and every millisecond
// between the hold and the row appearing is a millisecond they spend looking at nothing. It carries no
// message — the consumer tells the browser that /api/intercept is stale and that handler renders the
// queue.
//
// It is never called with the engine's lock held: a held message blocks its proxy connection, and a
// signal that could order against this lock would put a subscriber's business in front of the next
// message the proxy wants to hold.
func (e *Engine) OnChange(fn func()) {
	if e == nil {
		return
	}
	e.mu <- struct{}{}
	e.onChange = fn
	<-e.mu
}

// signalChange fires the change signal, if one is installed. Takes the lock only to read the slot, and
// calls out with it released — see OnChange.
func (e *Engine) signalChange() {
	e.mu <- struct{}{}
	fn := e.onChange
	<-e.mu
	if fn != nil {
		fn()
	}
}

// SetScope attaches the engagement scope, which the in-scope-only filter consults.
//
// Separate from SetInScopeOnly because they come from different places: the scope is wired once at
// construction and the filter is an operator toggle. Wiring them together would have made the
// toggle able to arrive before the scope did.
func (e *Engine) SetScope(s ScopeChecker) {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	e.scope = s
}

// InScopeOnly reports whether the queue is filtered to in-scope traffic.
func (e *Engine) InScopeOnly() bool {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	return e.inScopeOnly
}

// SetInScopeOnly turns Burp's "Only intercept in-scope messages" on or off.
//
// Held messages are untouched, exactly as SetEnabled leaves them: a message already held was held
// under the rules in force at the time, and dropping it now because the filter changed would discard
// traffic an operator is mid-decision on.
func (e *Engine) SetInScopeOnly(v bool) {
	e.mu <- struct{}{}
	e.inScopeOnly = v
	<-e.mu
	e.signalChange()
}

// ScopeAttached reports whether a scope is wired, so a surface can say why the in-scope-only toggle
// would not do anything rather than offering a control that silently does nothing.
func (e *Engine) ScopeAttached() bool {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	return e.scope != nil
}

// Enabled reports the master switch.
func (e *Engine) Enabled() bool {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	return e.enabled
}

// SetEnabled toggles the master switch. Held messages are untouched; they are
// resolved by the operator regardless of the switch's state.
func (e *Engine) SetEnabled(v bool) {
	e.mu <- struct{}{}
	// Registered before the unlock defer, so LIFO runs it after: the signal must never be delivered
	// with this lock held. Same two lines at every mutation below.
	defer e.signalChange()
	defer func() { <-e.mu }()
	e.enabled = v
}

// SetNewlineCorrection sets Burp's two newline fixes for edited interceptions
// (burpsy-react-ui-80tg). Both default off; see NewlineCorrection for why each is a separate switch
// and why the trailing-newline one only touches a urlencoded body.
func (e *Engine) SetNewlineCorrection(n NewlineCorrection) {
	e.mu <- struct{}{}
	// Registered before the unlock defer, so LIFO runs it after: the signal must never be delivered
	// with this lock held. Same two lines as every other mutation here.
	defer e.signalChange()
	defer func() { <-e.mu }()
	e.newlines = n
}

// NewlineCorrections reports the configured corrections, so a surface can show what is on rather
// than assuming the defaults.
func (e *Engine) NewlineCorrections() NewlineCorrection {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	return e.newlines
}

// SetRules replaces one direction's list. A malformed regex is refused and the
// list is left unchanged, matching Burp's save-time compilation.
func (e *Engine) SetRules(d Direction, active bool, rules []Rule) error {
	// Refused before any work, because the direction is now an array index. It arrives from a
	// decoded API request, so an out-of-range value must be an error rather than a panic on the
	// proxy's own goroutine — and an error naming the value rather than a silent write to
	// whichever list happened to be adjacent.
	if !d.valid() {
		return fmt.Errorf("unknown intercept direction %d", int(d))
	}
	compiled := make([]*Rule, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		if r.Category == CategoryRegex && r.StringMatch != "" {
			re, err := regexp.Compile(r.StringMatch)
			if err != nil {
				return fmt.Errorf("invalid regex %q: %w", r.StringMatch, err)
			}
			compiled = append(compiled, &Rule{
				Field:       r.Field,
				Category:    r.Category,
				StringMatch: r.StringMatch,
				Enabled:     r.Enabled,
				Comment:     r.Comment,
				Action:      r.Action,
				Op:          r.Op,
				re:          re,
			})
			continue
		}
		compiled = append(compiled, &Rule{
			Field:       r.Field,
			Category:    r.Category,
			StringMatch: r.StringMatch,
			Enabled:     r.Enabled,
			Comment:     r.Comment,
			Action:      r.Action,
			Op:          r.Op,
		})
	}

	e.mu <- struct{}{}
	defer e.signalChange()
	defer func() { <-e.mu }()
	e.lists[d] = List{Active: active, Rules: compiled}
	return nil
}

// Rules returns one direction's list. An unknown direction returns the zero list — inactive,
// no rules — rather than another direction's, because answering with a neighbour's rules is how
// the old two-field version would have misreported a WebSocket direction as the response list.
func (e *Engine) Rules(d Direction) List {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	if !d.valid() {
		return List{}
	}
	return copyList(e.lists[d])
}

// valid reports whether the direction addresses a real list. Every indexing site asks this, so
// an out-of-range Direction from a decoded API request cannot panic the proxy.
func (d Direction) valid() bool {
	return d >= 0 && int(d) < DirectionCount
}

func copyList(l List) List {
	out := List{Active: l.Active, Rules: make([]*Rule, len(l.Rules))}
	for i := range l.Rules {
		c := *l.Rules[i]
		out.Rules[i] = &c
	}
	return out
}

// shouldHold reports whether a message in direction d should be held. Off list
// or off switch never hold; an unconditional list (on with no rules at all)
// holds everything; a list whose rules are all disabled holds nothing; otherwise
// any enabled matching rule holds.
func (e *Engine) shouldHold(d Direction, m *Message) bool {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	if !e.enabled {
		return false
	}
	if !d.valid() {
		return false
	}
	// The in-scope-only filter, checked before the rules: it is a narrowing of what the queue may
	// contain at all, not another rule to match against.
	//
	// With no scope attached this does NOT filter. A nil scope means nothing has told this engine
	// what is in scope, and treating that as "nothing is in scope" would empty the queue while the
	// toggle claimed only to be narrowing it — an operator would see interception stop working and
	// have no way to connect it to a switch they flipped. ScopeAttached exists so a surface can say
	// so out loud instead.
	if e.inScopeOnly && e.scope != nil && !e.scope.Contains(m.Host, m.Port, m.Path, m.TLS) {
		return false
	}
	// One-shot response holds fire before the rule lists and consume themselves, so an
	// arming applies to exactly one response: the next one with identical attributes.
	if d == DirectionResponse {
		for i, p := range e.pending {
			if p.host == m.Host && p.port == m.Port && p.method == m.Method && p.path == m.Path {
				e.pending = append(e.pending[:i], e.pending[i+1:]...)
				return true
			}
		}
	}
	l := e.lists[d]
	if !l.Active {
		return false
	}
	if len(l.Rules) == 0 {
		return true
	}
	enabled := l.EnabledRules()
	if len(enabled) == 0 {
		return false
	}
	// Left-to-right fold over the enabled rules, each combined with what is above it by its own
	// operator (burpsy-react-ui-80tg, matching settings/tools/proxy.html:246-268).
	//
	// An all-OR list folds to exactly the old "first matching rule wins" behaviour (35i4): the first
	// rule that matches short-circuits and decides, and reaching the end means nothing matched. So
	// every list written before Op existed evaluates identically, which is why the default is OR and
	// not a special case in the code.
	//
	// An AND short-circuits the other way — a rule that does not match cannot be rescued by anything
	// below it — so the fold returns false as soon as one fails, rather than continuing to a later
	// rule that might hold.
	// A rule that combines with AND is only meaningful once something above it has held. Until then
	// there is no conjunction for it to extend, so it is treated as its own standalone condition
	// rather than silently becoming the accumulator: a lone "and path /admin" on an empty list above
	// it should read as "hold /admin", not as a chain with a missing first link.
	//
	// The accumulator is the OR-fold over everything reached so far. An AND rule ANDs into it: the
	// chain holds only if the accumulator is already true AND this rule matches.
	acc := false
	started := false
	for _, r := range enabled {
		matched := r.Match(m)
		if r.Op == RuleOpAnd && started {
			if !matched {
				return false
			}
			// Every rule so far matched and this one does too, so the hold stands. The action here is
			// irrelevant: an AND rule narrows an existing hold, it does not create one.
			continue
		}
		// First rule, or an OR rule: the accumulator is the disjunction of every OR-rule matched so
		// far. An OR rule that matches decides immediately when it HOLDS, which is what makes
		// "hold this host, but pass that path" expressible; a matching PASS rule short-circuits to
		// false, because a disjunction is satisfied by exactly one positive term.
		if matched {
			if r.Action == RuleActionPass && r.Op != RuleOpAnd {
				return false
			}
			acc = true
		}
		started = true
	}
	return acc
}

// Hold evaluates a message and, if it should be held, queues it and returns the
// Held handle the proxy blocks on. It returns nil when the message passes
// through.
func (e *Engine) Hold(m *Message) *Held {
	if !e.shouldHold(m.Direction, m) {
		return nil
	}
	e.mu <- struct{}{}
	defer e.signalChange()
	defer func() { <-e.mu }()
	e.nextID++
	h := &Held{
		ID:        e.nextID,
		Direction: m.Direction,
		Host:      m.Host,
		Port:      m.Port,
		TLS:       m.TLS,
		Method:    m.Method,
		Path:      m.Path,
		Status:    m.Status,
		Opcode:    m.Opcode,
		Raw:       append([]byte{}, m.Raw...),
		HeldAt:    time.Now(),
		done:      make(chan struct{}),
	}
	e.held[h.ID] = h
	return h
}

// SetAnnotation writes the operator's comment and highlight onto one held message.
// Empty highlight clears it — "" is the picker's no-colour value, the same
// vocabulary every other annotated surface uses. Unknown ids error rather than
// passing, so a stale queue render cannot believe it annotated a message that
// was already resolved.
func (e *Engine) SetAnnotation(id uint64, comment, highlight string) error {
	e.mu <- struct{}{}
	h := e.held[id]
	if h == nil {
		<-e.mu
		return fmt.Errorf("no held message %d", id)
	}
	h.Comment = comment
	h.Highlight = highlight
	<-e.mu
	// signalChange after the lock is released: it takes the same mutex-channel itself, and
	// calling it with the slot held deadlocks the caller against its own acquire (the same
	// rule OnChange documents — the signal is never delivered with the lock held).
	e.signalChange()
	return nil
}

// Held returns a snapshot of the queue for the API, newest last.
func (e *Engine) Held() []*Held {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	out := make([]*Held, 0, len(e.held))
	for _, h := range e.held {
		out = append(out, h)
	}
	return out
}

// Get returns one held message by id, or nil.
func (e *Engine) Get(id uint64) *Held {
	e.mu <- struct{}{}
	defer func() { <-e.mu }()
	return e.held[id]
}

// Forward resolves a held message as forwarded, carrying the operator's edited
// bytes (the original when empty) to the proxy. fixContentLength rewrites the
// Content-Length header to match the body, since editing a body without fixing
// its length produces a corrupt exchange.
// Forward resolves a held message as forwarded.
//
// edited nil means "unchanged" and sends the bytes as held. A non-nil pointer replaces them,
// including a pointer to the empty string, which clears the payload.
//
// # Why a pointer
//
// This took a plain string, and treated "" as "unchanged". For HTTP that is harmless: an empty
// request or response is meaningless, so nobody could want one. For a WebSocket frame an empty
// payload is ordinary — a keepalive, a cleared field — and an operator who selected the payload and
// deleted it got the ORIGINAL forwarded instead, with a 200 and no indication their edit had been
// discarded. "Absent" and "empty" are different requests and are now different values.
//
// # Why fixContentLength is ignored for WebSocket
//
// The console's toggle defaults to on (intercept.tsx), and rewriteContentLength splits on the first
// CRLFCRLF. A frame payload has no Content-Length, but a payload that happens to contain a blank
// line looks like a header block to that function — so forwarding a held WebSocket message with the
// default settings would have injected a Content-Length header into the middle of application data.
// Skipped by direction, because the direction is a fact and the bytes are a guess.
//
// # The target
//
// nil means "send it where the client asked", which is what every caller that has no opinion gets.
// A non-nil Target replaces the destination for this one request — Burp's "Edit target" pencil,
// which is per-item and not a repointing of the connection. A target equal to the one the message
// already has collapses to nil, so the console can send the authority it is showing without
// changing the path the proxy takes.
//
// A target the engine cannot dial is refused with the hold left unresolved: resolving it and then
// failing to dial would either drop the request or send it to the original destination, and both
// are the opposite of the instruction.
func (e *Engine) Forward(id uint64, edited *string, fixContentLength bool, target *Target) error {
	e.mu <- struct{}{}
	h := e.held[id]
	<-e.mu
	if h == nil {
		return fmt.Errorf("no held message %d", id)
	}
	raw := h.Raw
	if edited != nil {
		raw = []byte(*edited)
	}
	// Burp's two newline corrections (settings/tools/proxy.html:273-292), and only on an EDITED
	// message. Untouched traffic is already well-formed by construction — it came off the wire — so
	// rewriting it could only change bytes the target accepted as they were. An edit is where the
	// operator introduces the defect: dropping the blank line after the headers, or leaving a trailing
	// newline in a form body.
	if edited != nil && !h.Direction.IsWebSocket() {
		raw = e.newlines.Apply(raw)
	}
	if fixContentLength && !h.Direction.IsWebSocket() {
		raw = rewriteContentLength(raw)
	}
	// A destination the engine cannot dial is refused here rather than at the dial, and the hold is
	// left untouched so the operator can correct it: resolving the hold with a target that fails
	// would release the request down the original path, which is precisely not what they asked for.
	if target != nil {
		// Trimmed here rather than only at the API, because the engine is the last thing between an
		// operator's field and a dial: a host of " " is an empty host that the wire's own validation
		// would have caught, and a value that reaches this far by another route must be caught too.
		// Normalised on a copy so the caller's struct is left as it was passed.
		normalised := *target
		normalised.Host = strings.TrimSpace(normalised.Host)
		if normalised.Host == "" {
			return fmt.Errorf("a retarget needs a host: an empty one would dial the local machine")
		}
		if normalised.Port == 0 {
			return fmt.Errorf("a retarget needs a port in 1..65535")
		}
		if h.Direction.IsWebSocket() {
			return fmt.Errorf("a WebSocket frame has no destination of its own; retarget the handshake instead")
		}
		// The unchanged case collapses to no target at all, so a caller that always sends the current
		// authority (the console does, because the operator may have retyped it) still takes the
		// ordinary path and reuses the connection the proxy already has.
		if normalised.SameAs(h.Host, h.Port, h.TLS) {
			target = nil
		} else {
			target = &normalised
		}
	}
	// The bytes the operator was shown versus the bytes they handed back, decided against the
	// operator's own buffer rather than against what goes on the wire below. The rewrite between them
	// is burpsy's, not the operator's: fixContentLength recomputes a header the operator may not even
	// have looked at, and counting it as a manual edit would mark every forward of a request whose
	// framing burpsy corrected. See Held.userEdited for why no caller can make this call.
	userEdited := edited != nil && !bytes.Equal([]byte(*edited), h.Raw)
	// A second way to modify an item by hand, and it leaves the bytes alone: Burp's "Edit target".
	// `target` is nil both when the operator named no destination and when they named the one the
	// message already had (the collapse above), so what survives is a destination the client did not
	// ask for — an item that is not the one the client sent even when it is byte-for-byte the same.
	// See core.Exchange.UserEdited, which names this case.
	if target != nil {
		userEdited = true
	}
	if !h.resolve(ActionForward, raw, target, userEdited, "") {
		return fmt.Errorf("message %d was already resolved", id)
	}
	// Remove from the hold map so a long-running proxy does not leak one full
	// raw message per intercepted exchange. resolve is the once-only gate: by
	// the time we get here the message is resolved, so deleting is safe.
	e.mu <- struct{}{}
	delete(e.held, id)
	<-e.mu
	e.signalChange()
	return nil
}

// Drop resolves a held message as dropped. The proxy's Wait returns nil bytes,
// which closes the connection (or forwards nothing) without reaching upstream.
func (e *Engine) Drop(id uint64, reason string) error {
	e.mu <- struct{}{}
	h := e.held[id]
	<-e.mu
	if h == nil {
		return fmt.Errorf("no held message %d", id)
	}
	if !h.resolve(ActionDrop, nil, nil, false, reason) {
		return fmt.Errorf("message %d was already resolved", id)
	}
	e.mu <- struct{}{}
	kept := e.pending[:0]
	for _, p := range e.pending {
		if p.holdID != id {
			kept = append(kept, p)
		}
	}
	e.pending = kept
	<-e.mu
	// Remove from the hold map; see Forward for why.
	e.mu <- struct{}{}
	delete(e.held, id)
	<-e.mu
	e.signalChange()
	return nil
}

// ForwardAll resolves every held message as forwarded, unmodified, in one pass
// and returns how many this call forwarded. It is the safe half of the pair
// DropAll is the destructive half of — Burp ships both from one dropdown
// (proxyForwardOptionsButton: "Forward" / "Forward all", mirrored by "Drop" /
// "Drop all") — and it exists because a queue that can only be emptied by
// dropping teaches the operator to stop queueing traffic at all.
//
// "Unmodified" is the point and the difference from per-id Forward: no edited
// bytes and no content-length rewrite, because a bulk action never had a human
// read what it is forwarding. Each message resolves through the same once-only
// gate Drop applies per id, so a message resolved elsewhere (another operator,
// a client that gave up waiting) is left to whoever resolved it and is not
// counted. One change signal fires at the end no matter how many were
// forwarded: N forwards are one queue event, not N, so the live-update fan-out
// sees a single change for one operator action instead of one per message.
func (e *Engine) ForwardAll() int {
	e.mu <- struct{}{}
	all := make([]*Held, 0, len(e.held))
	for _, h := range e.held {
		all = append(all, h)
	}
	<-e.mu
	forwarded := make([]*Held, 0, len(all))
	for _, h := range all {
		// h.Raw, not nil: the resolve payload IS the proxy side's answer, and nil
		// reads as an empty message there — a forward of nothing. The client's own
		// held bytes are the unmodified content this method promises.
		// false, not a comparison: "unmodified" is this method's contract, so there is nothing an
		// operator edited here to notice.
		if h.resolve(ActionForward, h.Raw, nil, false, "") {
			forwarded = append(forwarded, h)
		}
	}
	if len(forwarded) == 0 {
		return 0
	}
	// Remove what this call resolved, then signal with the lock released —
	// the same two-step shape as Forward, batched over the queue.
	e.mu <- struct{}{}
	for _, h := range forwarded {
		delete(e.held, h.ID)
	}
	<-e.mu
	e.signalChange()
	return len(forwarded)
}

// DropAll resolves every held message as dropped in one pass and returns how
// many this call dropped. A message already resolved elsewhere (another
// operator, a client that gave up waiting) is left to whoever resolved it and
// is not counted — the same once-only resolve gate Drop applies per id. One
// change signal fires at the end no matter how many dropped: N drops are one
// queue event, not N, so the live-update fan-out sees a single change for one
// operator action instead of one per message.
func (e *Engine) DropAll(reason string) int {
	e.mu <- struct{}{}
	all := make([]*Held, 0, len(e.held))
	for _, h := range e.held {
		all = append(all, h)
	}
	<-e.mu
	dropped := make([]*Held, 0, len(all))
	for _, h := range all {
		if h.resolve(ActionDrop, nil, nil, false, reason) {
			dropped = append(dropped, h)
		}
	}
	if len(dropped) == 0 {
		return 0
	}
	// Remove what this call resolved, then signal with the lock released —
	// the same two-step shape as Drop, batched over the queue.
	e.mu <- struct{}{}
	for _, h := range dropped {
		delete(e.held, h.ID)
	}
	<-e.mu
	e.signalChange()
	return len(dropped)
}

// NewlineCorrection is Burp's pair of newline fixes for an edited interception
// (settings/tools/proxy.html:273-292): add a missing blank line after the headers, and remove
// trailing newlines from a URL-encoded body.
//
// # Why both, and why they are not one setting
//
// They are two different defects with two different symptoms, and an operator who has edited a
// request and watched the target reject it has no way to tell which they made. The missing blank
// line is a framing error — the target reads the first body byte as a header name. The trailing
// newline in a form body is a value error — the field parses with a trailing CR or LF glued to the
// last character, which a signature or an equality check then fails. Fixing one does not fix the
// other, so they are separate switches and either can be on alone.
//
// # Why the trailing-newline fix is scoped to urlencoded
//
// Because that is what Burp scopes it to, and the scoping is the point: a trailing newline in a
// JSON body is ordinary and meaningful inside a string, and silently trimming it would corrupt
// payloads the operator wrote deliberately. The Content-Type decides, not the body — an
// unparseable or absent header is left alone rather than guessed at, because guessing wrong here
// changes bytes without saying so.
type NewlineCorrection struct {
	// AddMissingBlankLine inserts the CRLFCRLF an edit dropped between the headers and the body.
	AddMissingBlankLine bool
	// TrimTrailingNewlinesInURLEncodedBody strips trailing CR/LF from a urlencoded body only.
	TrimTrailingNewlinesInURLEncodedBody bool
}

// Apply runs the enabled corrections over a raw HTTP message, in the order that makes them
// independent: the blank line is restored first, because the trailing-newline fix reads the body
// boundary and would otherwise see headers where there should be a body.
func (n NewlineCorrection) Apply(raw []byte) []byte {
	if !n.AddMissingBlankLine && !n.TrimTrailingNewlinesInURLEncodedBody {
		return raw
	}
	headEnd := indexCRLFCRLF(raw)
	if headEnd < 0 {
		// No blank line anywhere, which is exactly the case AddMissingBlankLine exists for: an edit
		// that dropped it leaves the header block running into the body with nothing to separate them.
		// The LAST CRLF is the boundary -- everything before it is headers, everything after is what
		// the target would misread as a header name.
		//
		// A message with no CRLF at all is not an HTTP message this can repair, and inventing a
		// boundary would produce bytes no client wrote.
		if !n.AddMissingBlankLine {
			return raw
		}
		// The boundary is the LAST line ending of the header block. Header lines are
		// "Name: value" or continuations, so the run of lines that all look like headers ends at the
		// first line that does not -- and that line is the start of the body.
		//
		// Guessing "last CRLF" instead truncates the body by two bytes, which is worse than the
		// defect being repaired: the operator would see a request whose body silently lost its first
		// characters and no reason why. Guessing "first CRLF" throws the headers away. So this walks
		// the lines and asks what each one is.
		text := string(raw)
		head, body, ok := splitAtHeaderBlockEnd(text)
		if !ok {
			// Nothing that looks like a header block, so there is no boundary to restore and
			// inventing one would produce bytes no client wrote.
			return raw
		}
		// Content-Length is recomputed here too: a body the target could not previously find has
		// usually also been mis-measured, and announcing the old length would be a second rejection
		// on top of the first.
		if rewritten, ok := setContentLength(head, len(body)); ok {
			head = rewritten
		}
		return append([]byte(head+"\r\n\r\n"), body...)
	}
	head := string(raw[:headEnd])
	body := raw[headEnd+4:]
	changed := false

	if n.TrimTrailingNewlinesInURLEncodedBody && isURLEncoded(head) {
		if trimmed := trimTrailingNewlines(body); len(trimmed) != len(body) {
			body = trimmed
			changed = true
		}
	}
	// Content-Length is recomputed after every body change, or a trimmed body would be announced
	// with the length of the untrimmed one. Rewriting it here rather than leaving it to the
	// caller's toggle is deliberate: a correction that changes the body and leaves a now-wrong
	// length behind is a request the target will reject for a reason the operator cannot see.
	if changed {
		if rewritten, ok := setContentLength(head, len(body)); ok {
			head = rewritten
		}
	}
	if !changed {
		return raw
	}
	return append([]byte(head+"\r\n\r\n"), body...)
}

// isURLEncoded reports whether the header block declares a urlencoded body.
//
// Only the exact media types Burp's own setting is about: application/x-www-form-urlencoded and the
// multipart form type that shares its trailing-newline sensitivity. Anything else — including a
// missing Content-Type — is false, because this correction rewrites bytes and must not do that to a
// body whose format it has not recognised.
func isURLEncoded(head string) bool {
	for _, line := range strings.Split(head, "\r\n") {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(line[:colon]), "content-type") {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(line[colon+1:]))
		mediaType := value
		if semi := strings.Index(value, ";"); semi >= 0 {
			mediaType = strings.TrimSpace(value[:semi])
		}
		return mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data"
	}
	return false
}

// trimTrailingNewlines removes trailing CR and LF bytes, and nothing else. A body that is nothing
// but newlines becomes empty rather than keeping one, because a form with no fields is empty and a
// form with a newline is a field whose name is a line break.
func trimTrailingNewlines(body []byte) []byte {
	end := len(body)
	for end > 0 && (body[end-1] == '\r' || body[end-1] == '\n') {
		end--
	}
	return body[:end]
}

// setContentLength rewrites the header's Content-Length to n, reporting whether there was one to
// rewrite. A message with no Content-Length is left alone: this is a correction to what the operator
// wrote, not a decision to start framing their request.
func setContentLength(head string, n int) (string, bool) {
	lines := strings.Split(head, "\r\n")
	for i, line := range lines {
		if len(line) >= 15 && strings.EqualFold(strings.TrimSpace(line[:15]), "Content-Length:") {
			lines[i] = "Content-Length: " + strconv.Itoa(n)
			return strings.Join(lines, "\r\n"), true
		}
	}
	return head, false
}

// splitAtHeaderBlockEnd splits a message whose blank line is missing into its header block and its
// body, reporting false when there is no header block to find.
//
// A header line is "Name: value" — a colon before any space that would make it a body line — or a
// folded continuation, which begins with whitespace. The block ends at the first line that is
// neither, or at the end of the message when every line is a header.
func splitAtHeaderBlockEnd(text string) (head, body string, ok bool) {
	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 {
		return "", "", false
	}
	// The request line is not a header line and must not end the block.
	sawHeader := false
	for idx := 1; idx < len(lines); idx++ {
		line := lines[idx]
		if line == "" {
			// An explicit empty line IS the boundary — the message was well formed after all and this
			// function was called on a path that already knew otherwise.
			return strings.Join(lines[:idx], "\r\n"), strings.Join(lines[idx+1:], "\r\n"), true
		}
		if isHeaderLine(line) {
			sawHeader = true
			continue
		}
		return strings.Join(lines[:idx], "\r\n"), strings.Join(lines[idx:], "\r\n"), sawHeader
	}
	if !sawHeader {
		return "", "", false
	}
	return strings.Join(lines, "\r\n"), "", true
}

// isHeaderLine reports whether one line of a request head looks like a header rather than the first
// line of a body.
//
// The colon test is deliberately strict: a body line like "name=bob" has no colon and is correctly
// not a header, while a JSON body's opening line "{"a":"b"}" has a colon and would be misread — which
// is why the caller only reaches this for a message that ALREADY has no blank line, where the
// alternative is a request the target cannot parse at all.
func isHeaderLine(line string) bool {
	if line == "" {
		return false
	}
	if line[0] == ' ' || line[0] == '\t' {
		return true // folded continuation
	}
	colon := strings.Index(line, ":")
	if colon <= 0 {
		return false
	}
	// A space or tab BEFORE the colon means it is not a header name — that is how a body line like
	// "a b: c" avoids being read as one.
	return strings.IndexAny(line[:colon], " \t") < 0
}

// fixContentLength rewrites the Content-Length header to match the body. If the
// message is chunked or has no Content-Length at all, it is returned unchanged:
// inventing a length for a framing we do not own would corrupt the exchange.
func rewriteContentLength(raw []byte) []byte {
	headEnd := indexCRLFCRLF(raw)
	if headEnd < 0 {
		return raw
	}
	head := string(raw[:headEnd])
	body := raw[headEnd+4:]
	lines := strings.Split(head, "\r\n")
	hasCL := false
	for i, line := range lines {
		if len(line) >= 15 && strings.EqualFold(strings.TrimSpace(line[:15]), "Content-Length:") {
			lines[i] = "Content-Length: " + strconv.Itoa(len(body))
			hasCL = true
			break
		}
	}
	if !hasCL {
		return raw
	}
	return append([]byte(strings.Join(lines, "\r\n")+"\r\n\r\n"), body...)
}

// indexLFLF finds a bare-LF header terminator, for the client that does not use CRLF. Scanned only
// after indexCRLFCRLF has failed, so a well-formed message never pays for it.
func indexLFLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		// A CRLF contains an LF, so the byte BEFORE a candidate is checked to avoid finding the tail
		// of a CRLFCRLF that indexCRLFCRLF already rejected for a different reason.
		if b[i] == '\n' && b[i+1] == '\n' && (i == 0 || b[i-1] != '\r') {
			return i
		}
	}
	return -1
}

func indexCRLFCRLF(b []byte) int {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return i
		}
	}
	return -1
}

// HTTP helpers ------------------------------------------------------------------------------------

// ContentTypeOf extracts the Content-Type value from a raw HTTP response.
func ContentTypeOf(raw []byte) string {
	headEnd := indexCRLFCRLF(raw)
	if headEnd < 0 {
		return ""
	}
	head := string(raw[:headEnd])
	for _, line := range strings.Split(head, "\r\n") {
		// Require the header name to be exactly "Content-Type" followed by a
		// colon, so "Content-Type-Options" (or any other prefix-extended header)
		// is not misread as a content type.
		if len(line) > 13 && strings.EqualFold(line[:12], "Content-Type") && line[12] == ':' {
			return strings.TrimSpace(line[13:])
		}
	}
	return ""
}

// StatusOf extracts the status code from a raw HTTP response head, or nil.
func StatusOf(raw []byte) *int {
	headEnd := indexCRLFCRLF(raw)
	if headEnd < 0 {
		return nil
	}
	head := string(raw[:headEnd])
	line := strings.SplitN(head, "\r\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil
	}
	return &code
}

// ParseMessage builds the Message the proxy hands to Hold, deriving the
// response-only fields (status, content type) from the raw bytes.
func ParseMessage(dir Direction, host string, port uint16, tls bool, method, path string, raw []byte) *Message {
	m := &Message{
		Direction: dir,
		Host:      host,
		Port:      port,
		TLS:       tls,
		Method:    method,
		Path:      path,
		Raw:       raw,
	}
	if dir == DirectionResponse {
		m.Status = StatusOf(raw)
		m.ContentType = ContentTypeOf(raw)
	}
	return m
}

// StatusText is a tiny helper so the proxy can respond identically for a
// dropped request in both the plain and TLS paths.
var StatusText = http.StatusText
