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

// Rule is one hold condition. Enabled rules are ANDed with the list switch;
// a list with any enabled rule holds only matching messages, a list with no
// enabled rules holds everything (unconditional).
type Rule struct {
	Field       Field
	Category    Category
	StringMatch string
	Enabled     bool
	Comment     string

	re *regexp.Regexp
}

// NewRule compiles a rule, refusing a malformed regex (matching Burp, which
// reports a bad pattern when the list is saved rather than when it fires).
func NewRule(field Field, cat Category, match string, enabled bool, comment string) (*Rule, error) {
	r := &Rule{
		Field:       field,
		Category:    cat,
		StringMatch: match,
		Enabled:     enabled,
		Comment:     comment,
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
}

// FieldValue returns the message's value for a rule field, or "" when the
// direction has none (a request has no status code or content type).
func (m *Message) FieldValue(f Field) string {
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
	default:
		return ""
	}
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

	done     chan struct{}
	mu       sync.Mutex
	resolved bool
	action   Action
	outRaw   []byte
	reason   string
}

// Wait blocks until the operator forwards or drops the message. It is safe to
// call once; the returned bytes are the possibly-edited message to put on the
// wire (forward) or nil (drop).
func (h *Held) Wait() (Action, []byte) {
	<-h.done
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.action, h.outRaw
}

// resolve marks the message resolved exactly once; a second resolve (e.g. an
// API request arriving twice) is ignored so the proxy cannot act on a stale
// decision.
func (h *Held) resolve(a Action, raw []byte, reason string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.resolved {
		return false
	}
	h.resolved = true
	h.action = a
	h.outRaw = raw
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
	lists  [DirectionCount]List
	nextID uint64
	held   map[uint64]*Held
	// onChange is an optional signal that the queue or the switch changed (see OnChange).
	onChange func()
}

// NewEngine creates an intercept engine with both lists off.
func NewEngine() *Engine {
	return &Engine{
		mu:   make(chan struct{}, 1),
		held: make(map[uint64]*Held),
	}
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
	for _, r := range enabled {
		if r.Match(m) {
			return true
		}
	}
	return false
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
		Raw:       append([]byte{}, m.Raw...),
		HeldAt:    time.Now(),
		done:      make(chan struct{}),
	}
	e.held[h.ID] = h
	return h
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
func (e *Engine) Forward(id uint64, edited string, fixContentLength bool) error {
	e.mu <- struct{}{}
	h := e.held[id]
	<-e.mu
	if h == nil {
		return fmt.Errorf("no held message %d", id)
	}
	raw := h.Raw
	if edited != "" {
		raw = []byte(edited)
	}
	if fixContentLength {
		raw = rewriteContentLength(raw)
	}
	if !h.resolve(ActionForward, raw, "") {
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
	if !h.resolve(ActionDrop, nil, reason) {
		return fmt.Errorf("message %d was already resolved", id)
	}
	// Remove from the hold map; see Forward for why.
	e.mu <- struct{}{}
	delete(e.held, id)
	<-e.mu
	e.signalChange()
	return nil
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
		if h.resolve(ActionDrop, nil, reason) {
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
