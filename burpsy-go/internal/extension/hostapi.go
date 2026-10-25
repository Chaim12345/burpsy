package extension

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// The plugin->host service methods: the half of the Montoya surface where a plugin asks
// the host to do something, as opposed to the host invoking a plugin.
//
//	event.raise     raiseDebug/Info/Error/CriticalEvent          (burpsy-react-ui-rvq2)
//	storage.*       persistence().extensionData()/preferences()  (burpsy-react-ui-97dk)
//	ai.prompt       ai().prompt()                                (burpsy-react-ui-xpuh)
//	http.send       http().sendRequest()                         (burpsy-react-ui-p81m)
//
// Two controls sit in front of every one of them. A per-plugin grant, named on the
// operator's command line: a plugin the operator never granted gets CodeNoGrant and the
// service is not reached. And an injected Services value: this package does not know what
// the traffic store, the event log, the AI endpoint or the sender are, so each method
// answers CodeNotWired until the process wiring supplies the service.

// Grant names are the plugin->host method names, one grant per method.
var grantable = []string{
	"event.raise", "storage.get", "storage.set", "storage.delete", "ai.prompt", "http.send",
	"traffic.query", "scope.check",
}

// ErrUnknownGrant is a grant naming something that is not a plugin->host method.
var ErrUnknownGrant = errors.New("not a grantable host method")

// ErrOutOfScope is what Services.Send returns for a request the engagement scope refuses.
// It is answered to the plugin as CodeRefused and counted, never silently dropped.
var ErrOutOfScope = errors.New("request is outside the engagement scope")

// GrantableMethods lists the names a grant may use.
func GrantableMethods() []string { return append([]string(nil), grantable...) }

// ValidateGrants checks an operator's {plugin: [method...]} map, so a misspelt grant is
// refused at start-up rather than silently granting nothing.
func ValidateGrants(grants map[string][]string) error {
	names := make([]string, 0, len(grants))
	for name := range grants {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, g := range grants[name] {
			if !isGrantable(g) {
				return fmt.Errorf("plugin %q: grant %q: %w (valid: %v)", name, g, ErrUnknownGrant, grantable)
			}
		}
	}
	return nil
}

func isGrantable(g string) bool {
	for _, m := range grantable {
		if m == g {
			return true
		}
	}
	return false
}

// Distinct JSON-RPC error codes, so a plugin can tell "the operator has not allowed this"
// from "this build has no service for it" from "the scope refused it".
const (
	CodeNoGrant       = -32001
	CodeNotWired      = -32002
	CodeRefused       = -32003
	CodeServiceFailed = -32004
	CodeInvalidParams = -32602
)

// EventLevel is Montoya's four event-log severities.
type EventLevel string

const (
	EventDebug    EventLevel = "debug"
	EventInfo     EventLevel = "info"
	EventError    EventLevel = "error"
	EventCritical EventLevel = "critical"
)

// StorageScope picks Persistence.extensionData (project) or Persistence.preferences.
type StorageScope string

const (
	ScopeProject     StorageScope = "project"
	ScopePreferences StorageScope = "preferences"
)

// Storage is the persistence service. Values are opaque JSON.
type Storage interface {
	Get(plugin string, scope StorageScope, key string) (value json.RawMessage, found bool, err error)
	Set(plugin string, scope StorageScope, key string, value json.RawMessage) error
	Delete(plugin string, scope StorageScope, key string) error
}

// Services is what the process wires behind the host methods. Any field may be nil; the
// matching methods then answer CodeNotWired.
type Services struct {
	// RaiseEvent puts an event in the dashboard log, attributed to the plugin.
	RaiseEvent func(plugin string, level EventLevel, message string)
	Storage    Storage
	// Prompt sends one prompt through the operator-configured AI endpoint.
	Prompt func(ctx context.Context, plugin, system, prompt string) (string, error)
	// Send performs one request through the authorised sender. It must return
	// ErrOutOfScope (wrapped is fine) for a request the engagement scope refuses.
	Send func(ctx context.Context, plugin string, req SessionRequest) (SessionResponse, error)
	// Traffic is read access to the proxy history, site map and organizer, and the scope.
	Traffic TrafficReader
}

// TrafficSource names which store a traffic.query reads (Montoya proxy().history(),
// siteMap().requestResponses(), organizer().items()).
type TrafficSource string

const (
	TrafficProxy     TrafficSource = "proxy"
	TrafficSitemap   TrafficSource = "sitemap"
	TrafficOrganizer TrafficSource = "organizer"
)

// Page bounds for traffic.query.
const (
	DefaultTrafficPage = 50
	MaxTrafficPage     = 200
)

// TrafficQuery is one filtered, paged read. Empty filters match everything.
type TrafficQuery struct {
	Source        TrafficSource
	Host          string
	Method        string
	Status        int // 0 matches any
	Contains      string
	Offset, Limit int
	IncludeBodies bool
}

// TrafficItem is one stored exchange. Request and Response are raw message text, set only
// when the query asked for bodies.
type TrafficItem struct {
	ID       int    `json:"id"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
}

// TrafficPage is one page and the store's total match count.
type TrafficPage struct {
	Items []TrafficItem `json:"items"`
	Total int           `json:"total"`
}

// TrafficReader is the read-only window onto the stores. It must not mutate anything.
type TrafficReader interface {
	Query(ctx context.Context, plugin string, q TrafficQuery) (TrafficPage, error)
	InScope(ctx context.Context, url string) (bool, error)
}

// Bounds on what a plugin may hand the host in one call.
const (
	MaxStorageKeyBytes   = 256
	MaxStorageValueBytes = 1 << 20
	MaxPromptBytes       = 256 << 10
	MaxEventBytes        = 8 << 10
	maxConcurrentHost    = 4
)

// hostAPI is one session's view of the grants and services.
type hostAPI struct {
	plugin   string
	grants   map[string]bool
	services Services

	sem     chan struct{}
	mu      sync.Mutex
	counts  map[string]int
	refused atomic.Int64
}

func newHostAPI(plugin string, grants []string, svc Services) *hostAPI {
	a := &hostAPI{plugin: plugin, grants: map[string]bool{}, services: svc,
		sem: make(chan struct{}, maxConcurrentHost), counts: map[string]int{}}
	for _, g := range grants {
		a.grants[g] = true
	}
	return a
}

func (a *hostAPI) grantList() []string {
	out := make([]string, 0, len(a.grants))
	for g := range a.grants {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func (a *hostAPI) countsCopy() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int, len(a.counts))
	for k, v := range a.counts {
		out[k] = v
	}
	return out
}

// hostCall runs one plugin->host request. The handler runs off the reader goroutine so a
// slow service cannot stop the host reading the plugin's replies; at most
// maxConcurrentHost run at once, and a request past that is answered CodeServiceFailed.
func (s *session) hostCall(method string, msg rpcMessage, run func(ctx context.Context, params json.RawMessage) (any, *rpcError)) {
	if msg.ID == nil {
		// These are requests. A notification has nobody to answer, so it is a violation.
		s.protocolErrors.Add(1)
		s.console.append(StreamError, SourceProtocol, method+" is a request; it was sent as a notification and ignored")
		return
	}
	id := msg.ID
	api := s.api
	if api == nil || !api.grants[method] {
		if api != nil {
			api.refused.Add(1)
		}
		s.console.append(StreamError, SourceHost, method+" refused: the operator has not granted it to this plugin (-plugin-grants)")
		s.reply(id, nil, &rpcError{Code: CodeNoGrant, Message: method + " is not granted to this plugin"})
		return
	}
	select {
	case api.sem <- struct{}{}:
	default:
		s.reply(id, nil, &rpcError{Code: CodeServiceFailed, Message: "too many host calls in flight"})
		return
	}
	api.mu.Lock()
	api.counts[method]++
	api.mu.Unlock()
	go func() {
		defer func() { <-api.sem }()
		ctx, cancel := context.WithTimeout(s.ctx, s.callTimeout)
		defer cancel()
		res, rerr := run(ctx, msg.Params)
		if rerr != nil {
			if rerr.Code == CodeRefused {
				api.refused.Add(1)
			}
			s.reply(id, nil, rerr)
			return
		}
		enc, err := json.Marshal(res)
		if err != nil {
			s.reply(id, nil, &rpcError{Code: CodeServiceFailed, Message: "encoding the answer: " + err.Error()})
			return
		}
		if len(enc)+128 > s.maxMessageBytes {
			// An answer the transport would refuse to write would leave the plugin waiting forever.
			s.reply(id, nil, &rpcError{Code: CodeServiceFailed,
				Message: fmt.Sprintf("the answer is %d bytes, over the %d-byte message bound; ask for less", len(enc), s.maxMessageBytes)})
			return
		}
		s.reply(id, enc, nil)
	}()
}

func invalid(format string, args ...any) *rpcError {
	return &rpcError{Code: CodeInvalidParams, Message: fmt.Sprintf(format, args...)}
}

func notWired(method string) *rpcError {
	return &rpcError{Code: CodeNotWired, Message: method + " has no service behind it in this build"}
}

func failed(err error) *rpcError {
	if errors.Is(err, ErrOutOfScope) {
		return &rpcError{Code: CodeRefused, Message: err.Error()}
	}
	return &rpcError{Code: CodeServiceFailed, Message: err.Error()}
}

func scopeOf(raw string) (StorageScope, *rpcError) {
	switch StorageScope(raw) {
	case ScopeProject, ScopePreferences:
		return StorageScope(raw), nil
	}
	return "", invalid("scope %q is not \"project\" or \"preferences\"", raw)
}

func keyOf(key string) *rpcError {
	if key == "" {
		return invalid("key is empty")
	}
	if len(key) > MaxStorageKeyBytes {
		return invalid("key is %d bytes, limit %d", len(key), MaxStorageKeyBytes)
	}
	return nil
}

func hostEventRaise(s *session, msg rpcMessage) {
	s.hostCall("event.raise", msg, func(_ context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct {
			Level   EventLevel `json:"level"`
			Message string     `json:"message"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalid("unreadable params: %v", err)
		}
		switch p.Level {
		case EventDebug, EventInfo, EventError, EventCritical:
		default:
			return nil, invalid("level %q is not debug, info, error or critical", p.Level)
		}
		if p.Message == "" || len(p.Message) > MaxEventBytes {
			return nil, invalid("message must be 1 to %d bytes", MaxEventBytes)
		}
		if s.api.services.RaiseEvent == nil {
			return nil, notWired("event.raise")
		}
		s.api.services.RaiseEvent(s.name, p.Level, p.Message)
		return struct{}{}, nil
	})
}
func hostStorageGet(s *session, msg rpcMessage) {
	s.hostCall("storage.get", msg, func(_ context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct{ Scope, Key string }
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalid("unreadable params: %v", err)
		}
		scope, rerr := scopeOf(p.Scope)
		if rerr != nil {
			return nil, rerr
		}
		if rerr := keyOf(p.Key); rerr != nil {
			return nil, rerr
		}
		if s.api.services.Storage == nil {
			return nil, notWired("storage.get")
		}
		v, found, err := s.api.services.Storage.Get(s.name, scope, p.Key)
		if err != nil {
			return nil, failed(err)
		}
		if !found {
			return map[string]any{"found": false}, nil
		}
		return map[string]any{"found": true, "value": v}, nil
	})
}
func hostStorageSet(s *session, msg rpcMessage) {
	s.hostCall("storage.set", msg, func(_ context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct {
			Scope string          `json:"scope"`
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalid("unreadable params: %v", err)
		}
		scope, rerr := scopeOf(p.Scope)
		if rerr != nil {
			return nil, rerr
		}
		if rerr := keyOf(p.Key); rerr != nil {
			return nil, rerr
		}
		if len(p.Value) == 0 {
			return nil, invalid("value is missing")
		}
		if len(p.Value) > MaxStorageValueBytes {
			return nil, invalid("value is %d bytes, limit %d", len(p.Value), MaxStorageValueBytes)
		}
		if s.api.services.Storage == nil {
			return nil, notWired("storage.set")
		}
		if err := s.api.services.Storage.Set(s.name, scope, p.Key, p.Value); err != nil {
			return nil, failed(err)
		}
		return struct{}{}, nil
	})
}
func hostStorageDelete(s *session, msg rpcMessage) {
	s.hostCall("storage.delete", msg, func(_ context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct{ Scope, Key string }
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalid("unreadable params: %v", err)
		}
		scope, rerr := scopeOf(p.Scope)
		if rerr != nil {
			return nil, rerr
		}
		if rerr := keyOf(p.Key); rerr != nil {
			return nil, rerr
		}
		if s.api.services.Storage == nil {
			return nil, notWired("storage.delete")
		}
		if err := s.api.services.Storage.Delete(s.name, scope, p.Key); err != nil {
			return nil, failed(err)
		}
		return struct{}{}, nil
	})
}
func hostAIPrompt(s *session, msg rpcMessage) {
	s.hostCall("ai.prompt", msg, func(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct {
			System string `json:"system"`
			Prompt string `json:"prompt"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalid("unreadable params: %v", err)
		}
		if p.Prompt == "" || len(p.Prompt)+len(p.System) > MaxPromptBytes {
			return nil, invalid("prompt must be 1 to %d bytes with its system text", MaxPromptBytes)
		}
		if s.api.services.Prompt == nil {
			return nil, notWired("ai.prompt")
		}
		text, err := s.api.services.Prompt(ctx, s.name, p.System, p.Prompt)
		if err != nil {
			return nil, failed(err)
		}
		return map[string]any{"text": text}, nil
	})
}
func hostHTTPSend(s *session, msg rpcMessage) {
	s.hostCall("http.send", msg, func(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct {
			Request SessionRequest `json:"request"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalid("unreadable params: %v", err)
		}
		if p.Request.URL == "" || p.Request.Method == "" {
			return nil, invalid("request needs a method and an absolute url")
		}
		if s.api.services.Send == nil {
			return nil, notWired("http.send")
		}
		resp, err := s.api.services.Send(ctx, s.name, p.Request)
		if err != nil {
			return nil, failed(err)
		}
		return map[string]any{"response": resp}, nil
	})
}

func hostTrafficQuery(s *session, msg rpcMessage) {
	s.hostCall("traffic.query", msg, func(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct {
			Source        TrafficSource `json:"source"`
			Host          string        `json:"host"`
			Method        string        `json:"method"`
			Status        int           `json:"status"`
			Contains      string        `json:"contains"`
			Offset        int           `json:"offset"`
			Limit         int           `json:"limit"`
			IncludeBodies bool          `json:"include_bodies"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, invalid("unreadable params: %v", err)
		}
		switch p.Source {
		case TrafficProxy, TrafficSitemap, TrafficOrganizer:
		default:
			return nil, invalid("source %q is not proxy, sitemap or organizer", p.Source)
		}
		if p.Offset < 0 || p.Limit < 0 || p.Status < 0 {
			return nil, invalid("offset, limit and status must not be negative")
		}
		if p.Limit == 0 {
			p.Limit = DefaultTrafficPage
		}
		if p.Limit > MaxTrafficPage {
			p.Limit = MaxTrafficPage
		}
		if s.api.services.Traffic == nil {
			return nil, notWired("traffic.query")
		}
		page, err := s.api.services.Traffic.Query(ctx, s.name, TrafficQuery{
			Source: p.Source, Host: p.Host, Method: p.Method, Status: p.Status, Contains: p.Contains,
			Offset: p.Offset, Limit: p.Limit, IncludeBodies: p.IncludeBodies,
		})
		if err != nil {
			return nil, failed(err)
		}
		if page.Items == nil {
			page.Items = []TrafficItem{}
		}
		if !p.IncludeBodies {
			items := make([]TrafficItem, len(page.Items))
			copy(items, page.Items)
			for i := range items {
				items[i].Request, items[i].Response = "", ""
			}
			page.Items = items
		}
		return page, nil
	})
}

func hostScopeCheck(s *session, msg rpcMessage) {
	s.hostCall("scope.check", msg, func(ctx context.Context, raw json.RawMessage) (any, *rpcError) {
		var p struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(raw, &p); err != nil || p.URL == "" {
			return nil, invalid("scope.check needs a url")
		}
		if s.api.services.Traffic == nil {
			return nil, notWired("scope.check")
		}
		in, err := s.api.services.Traffic.InScope(ctx, p.URL)
		if err != nil {
			return nil, failed(err)
		}
		return map[string]any{"in_scope": in}, nil
	})
}
