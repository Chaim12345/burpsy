// Package mcp is the Model Context Protocol (stdio) transport over burpsy's risk-gated HTTP API
// (burpsy-react-ui-q31t).
//
// # What this is, and what it deliberately is not
//
// burpsy's console server already answers every question an MCP tool surface needs. Every route is
// classified with a riskClass (internal/web/route_manifest.go), the classification is enforced
// server-side for an unattended caller (internal/web/confirm_gate.go), and the routes are already
// flattened into agent-facing descriptors (internal/web/agent_tools.go). What was missing was the
// wire protocol an external assistant speaks: MCP clients — Claude Desktop, Cursor, an SDK agent —
// could drive ZAP and Caido in 2026 and could not drive burpsy at all.
//
// This package is therefore a TRANSPORT, not a policy layer, and the distinction is the whole
// design:
//
//   - tools/list is derived from web.MCPRoutes(), which is the manifest itself. The tool count, the
//     per-tool risk class and the confirmation requirement are read from the same map the gate
//     reads, so a tool descriptor cannot disagree with what the server will actually enforce.
//   - tools/call forwards the request over HTTP to the running console. It never decides whether a
//     call is permitted. A gated call without a confirmation gets the server's own 428 refusal,
//     which this layer surfaces verbatim as an isError tool result; a gated call WITH a
//     confirmation is spent by the server's real confirmStore. There is no second gate here to
//     drift from the first — which is the failure the acceptance criterion names explicitly.
//   - The one thing this layer refuses locally is a call that would reach a DIFFERENT route than
//     the tool names (see resolvePath), because that is not policy but the meaning of the tool
//     name. It uses the gate's own resolver to decide.
//
// # The confirmation flow, and why the mint is a separate visible tool
//
// A gated call with no confirmation is answered with the gate's refusal. Recovering from it is an
// explicit, separate step: the client calls the burpsy_confirm tool with the tool and the exact
// arguments of the call it wants confirmed, which POSTs the resolved request to the console's own
// mint endpoint and returns the console's preview of that request with a one-time token bound to it,
// and then re-issues the original call, unchanged, with that token. Nothing here mints a token
// automatically, and nothing retries a refused call.
//
// The token authorises that one request and no other (burpsy-react-ui-e0yq): the gate compares the
// method, path, query and body of the spending call with what was minted, so a host that showed its
// human the confirm call's arguments — or the preview it returned — showed them what will run.
//
// That is a deliberate choice with an honest limit. The gate's own comment states the argument:
// "an agent that can supply the confirm itself has learned nothing from being asked". A server
// cannot tell a human from an unattended agent — an MCP host that hands its model both tools hands
// it both halves of the ritual. What the separate tool does buy is auditability: the mint is one
// distinct call in the host's transcript, so an operator reading the transcript, or a host that
// requires approval per tool, sees the escalation as its own act rather than as a field the model
// filled in. The enforcement point is the host and the operator; burpsy's contribution is that the
// dangerous call is never reached by accident, and never reached by a tool acting on an earlier,
// unrelated instruction.
//
// # Framing
//
// Newline-delimited JSON-RPC 2.0, one message per line, which is what MCP's stdio transport
// specifies. stdout carries protocol messages and nothing else — a stray print would corrupt the
// stream, so diagnostics go to the caller's stderr.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/web"
)

// Version is the server version reported in initialize. It is a variable so the binary can set it
// from its own build metadata; a hardcoded string in a package is a version that goes stale.
var Version = "dev"

// maxMessageBytes caps one inbound JSON-RPC line. Generous because a tool call carries its payload
// inline — an apiscan call carries a whole OpenAPI document — but bounded, because a stdio server
// that buffers without limit is a memory leak with a socket attached.
const maxMessageBytes = 16 << 20

// maxResultBytes caps how much of an HTTP response one tool result carries. `/api/history` on a
// long engagement is larger than any model's context, and a transport that read it whole would
// hold it in memory and hand a model a truncated prompt to boot. The cut is REPORTED (see
// readCapped) rather than silent: a result that looks complete and is not is the defect this
// project treats as worse than an error.
const maxResultBytes = 1 << 20

// protocolVersions are the MCP revisions this server knows how to speak, newest last. The
// initialize result echoes the client's own version when it is one of these, so a client that
// pinned 2024-11-05 is not told it is talking to a newer revision it may not implement.
var protocolVersions = []string{"2024-11-05", "2025-03-26", "2025-06-18"}

// ---- JSON-RPC 2.0 -------------------------------------------------------------------------------

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the message expects no reply. A JSON-RPC notification omits `id`
// entirely; `id: null` is a request whose id is null and does get one.
func (r request) isNotification() bool { return len(r.ID) == 0 }

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// The JSON-RPC error codes this server produces.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// ---- server -------------------------------------------------------------------------------------

// Options configures a Server. Everything has a working default except BaseURL.
type Options struct {
	// BaseURL is the running console, e.g. "http://127.0.0.1:8081". Required.
	BaseURL string
	// Routes is the manifest to expose. Nil means web.MCPRoutes(): the real manifest. A caller
	// supplies a list only to test the transport against a fabricated surface.
	Routes []web.MCPRouteInfo
	// HTTP is the client used for tool calls. Nil means a client with Timeout.
	HTTP *http.Client
	// Timeout bounds one tool call. A single audit can legitimately run for minutes, so the default
	// is generous; it exists so a hung console cannot wedge the MCP session forever.
	Timeout time.Duration
	// In and Out are the stdio ends. Nil means os.Stdin / os.Stdout.
	In  io.Reader
	Out io.Writer
	// Surface picks the tool list: SurfaceGrouped (the default) or SurfaceRoutes.
	Surface Surface
	// MaxConcurrent bounds the tools/call handled at once. 0 means 8.
	MaxConcurrent int
	// SyncWindow is how long a call that started a console task waits for it before answering with a
	// task handle instead. 0 means 15 s, Burp's own window.
	SyncWindow time.Duration
	// NoNotifications turns off the console watcher that pushes task completion and High findings as
	// notifications/message.
	NoNotifications bool
}

// Surface is which tool list tools/list publishes.
type Surface string

const (
	// SurfaceGrouped is the default: capability-grouped tools (groups.go), each fronting a few
	// operations of one risk class, with no asset routes and no subtree spellings.
	SurfaceGrouped Surface = "grouped"
	// SurfaceRoutes is one tool per manifest pattern, named by normalising the pattern
	// ("/api/history" -> "api_history"). Kept for debugging and for clients pinned to those names;
	// it lists every route, the console's own assets included.
	SurfaceRoutes Surface = "routes"
)

// Server is a stdio MCP server over one burpsy console.
type Server struct {
	baseURL string
	http    *http.Client
	in      io.Reader
	out     io.Writer
	surface Surface

	// routes is the exposed manifest, in the order it will be listed.
	routes []web.MCPRouteInfo
	// tools is the descriptor list, parallel to routes plus the one transport-level burpsy_confirm
	// tool. byName maps a tool name back to its descriptor; byPattern maps a manifest pattern to it.
	tools     []tool
	byName    map[string]tool
	byPattern map[string]web.MCPRouteInfo

	// The concurrent session (burpsy-react-ui-wdza).
	enc        *json.Encoder
	writeMu    sync.Mutex
	slots      chan struct{}
	inflightMu sync.Mutex
	inflight   map[string]context.CancelFunc
	session    context.Context
	syncWindow time.Duration
	// events is the client for the console's SSE stream: no timeout, because the stream never ends;
	// its lifetime is the session's context.
	events    *http.Client
	notify    bool
	watchOnce sync.Once
	watchers  sync.WaitGroup
	levelMu   sync.Mutex
	level     string
}

// New builds a server. It validates the options that would otherwise fail on the first tool call,
// because a transport that starts and then fails every call is harder to diagnose than one that
// refuses to start.
func New(opts Options) (*Server, error) {
	base := strings.TrimSpace(opts.BaseURL)
	if base == "" {
		return nil, fmt.Errorf("mcp: a console base URL is required")
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	base = strings.TrimSuffix(base, "/")

	routes := opts.Routes
	if routes == nil {
		routes = web.MCPRoutes()
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("mcp: the route manifest is empty, which cannot be right")
	}

	client := opts.HTTP
	if client == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			// A crawl returns immediately (it answers 202 with a task id), but an audit runs
			// synchronously and a large one takes minutes. Refusing a real audit at 30 seconds
			// would make the transport look broken rather than patient.
			timeout = 10 * time.Minute
		}
		client = &http.Client{Timeout: timeout}
	}

	// The stdio ends default to the process's own, which is what the documented default says and
	// what a caller launching this as a subprocess expects. Leaving them nil cost a startup: the
	// first inline smoke run exited immediately with "no input stream", because the tests always
	// set both and nothing else did.
	in := opts.In
	if in == nil {
		in = os.Stdin
	}
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	surface := opts.Surface
	switch surface {
	case "":
		surface = SurfaceGrouped
	case SurfaceGrouped, SurfaceRoutes:
	default:
		return nil, fmt.Errorf("mcp: unknown tool surface %q (want %q or %q)", surface, SurfaceGrouped, SurfaceRoutes)
	}

	maxConc := opts.MaxConcurrent
	if maxConc <= 0 {
		maxConc = 8
	}
	window := opts.SyncWindow
	if window <= 0 {
		window = 15 * time.Second
	}

	s := &Server{
		slots:      make(chan struct{}, maxConc),
		syncWindow: window,
		events:     &http.Client{},
		notify:     !opts.NoNotifications,
		level:      "info",
		baseURL:    base,
		http:       client,
		in:         in,
		out:        out,
		surface:    surface,
		routes:     routes,
		byName:     make(map[string]tool, len(routes)+1),
		byPattern:  make(map[string]web.MCPRouteInfo, len(routes)),
	}
	for _, r := range routes {
		s.byPattern[r.Pattern] = r
	}
	tools, err := s.buildTools()
	if err != nil {
		return nil, err
	}
	s.tools = tools
	return s, nil
}

// BaseURL is the console this server drives.
func (s *Server) BaseURL() string { return s.baseURL }

// RouteCount is how many manifest routes are exposed. Used by tests and by the caller's startup
// banner so an operator can see the surface is the real one.
func (s *Server) RouteCount() int { return len(s.routes) }

// ToolCount is how many tools tools/list publishes on this server's surface, burpsy_confirm included.
func (s *Server) ToolCount() int { return len(s.tools) }

// ToolNames lists the published tool names in tools/list order.
func (s *Server) ToolNames() []string {
	out := make([]string, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, t.Name)
	}
	return out
}

// Surface is the tool surface this server publishes.
func (s *Server) Surface() Surface { return s.surface }

// Serve reads newline-delimited JSON-RPC from in and writes replies to out until the input closes
// or ctx is cancelled. It returns the read error, if any.
//
// # Concurrency (burpsy-react-ui-wdza)
//
// tools/call is dispatched on its own goroutine, bounded by MaxConcurrent, so a long call — an audit
// inside its sync window, a long-poll — does not stop the session answering ping, tools/list or
// another call. Every other method is answered inline, in arrival order. All writes go through one
// mutex-serialised encoder, because replies and notifications now come from several goroutines and
// two interleaved writes would be one corrupt line. At end of input Serve waits for the calls in
// flight to answer before it returns, so no reply is lost to a closing stream.
func (s *Server) Serve(ctx context.Context) error {
	in := s.in
	if in == nil {
		return fmt.Errorf("mcp: no input stream")
	}
	if s.out == nil {
		return fmt.Errorf("mcp: no output stream")
	}
	s.enc = json.NewEncoder(s.out)

	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()
	s.session = sessionCtx

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64<<10), maxMessageBytes)
	var calls sync.WaitGroup
	defer func() {
		calls.Wait()
		stopSession()
		s.watchers.Wait()
	}()

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			// A blank line is not a JSON-RPC message. Skipping rather than answering a parse error
			// keeps a stray newline from turning into a protocol error the client cannot attribute.
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			// The id is unreadable by construction, so the reply carries null: the spec's
			// requirement is that a parse error is still answered, not that it is attributable.
			if werr := s.send(response{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: codeParseError, Message: "parse error: " + err.Error()},
			}); werr != nil {
				return werr
			}
			continue
		}

		if req.isNotification() {
			s.notification(req)
			continue
		}
		if req.Method == "tools/call" {
			callCtx, cancel := context.WithCancel(sessionCtx)
			key := string(req.ID)
			s.track(key, cancel)
			calls.Add(1)
			s.slots <- struct{}{}
			go func(req request) {
				defer calls.Done()
				defer func() { <-s.slots }()
				defer s.untrack(key)
				defer cancel()
				reply := s.callTool(callCtx, req)
				if callCtx.Err() != nil && sessionCtx.Err() == nil {
					// notifications/cancelled: the spec says not to answer a cancelled request.
					return
				}
				_ = s.send(reply)
			}(req)
			continue
		}
		reply, ok := s.handle(sessionCtx, req)
		if !ok {
			continue
		}
		if err := s.send(reply); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// send writes one message under the write lock.
func (s *Server) send(v any) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.enc == nil {
		return fmt.Errorf("mcp: not serving")
	}
	return s.enc.Encode(v)
}

// track and untrack keep the cancel function of each call in flight, keyed by its JSON-RPC id, for
// notifications/cancelled.
func (s *Server) track(key string, cancel context.CancelFunc) {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	if s.inflight == nil {
		s.inflight = map[string]context.CancelFunc{}
	}
	s.inflight[key] = cancel
}

func (s *Server) untrack(key string) {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	delete(s.inflight, key)
}

// notification handles a message that expects no reply. Only two mean anything here:
// notifications/initialized starts the console watcher (task completion and High findings, pushed as
// notifications/message), and notifications/cancelled cancels the named call in flight — which, for a
// call waiting on a console task, also cancels that task.
func (s *Server) notification(req request) {
	switch req.Method {
	case "notifications/initialized":
		s.startWatcher()
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(req.Params, &p) != nil || len(p.RequestID) == 0 {
			return
		}
		s.inflightMu.Lock()
		cancel := s.inflight[string(p.RequestID)]
		s.inflightMu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}

// handle answers one request. ok is false for a notification, which by definition gets no reply.
func (s *Server) handle(ctx context.Context, req request) (response, bool) {
	// Every notification is ignored, before any method dispatch. A notification is not a request
	// with a missing reply — it is a message no reply is expected for, and answering one (a)
	// violates the spec and (b) makes a client that reuses ids mis-attribute the reply.
	if req.isNotification() {
		return response{}, false
	}
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return s.fail(req, codeInvalidRequest, "unsupported jsonrpc version %q", req.JSONRPC), true
	}

	switch req.Method {
	case "initialize":
		return s.initialize(req), true
	case "ping":
		// The spec's liveness probe. An empty result object is the whole answer.
		return s.ok(req, map[string]any{}), true
	case "tools/list":
		return s.listTools(req), true
	case "tools/call":
		return s.callTool(ctx, req), true
	case "logging/setLevel":
		return s.setLevel(req), true
	case "prompts/list":
		return s.listPrompts(ctx, req), true
	case "prompts/get":
		return s.getPrompt(ctx, req), true
	default:
		return s.fail(req, codeMethodNotFound, "method %q is not implemented", req.Method), true
	}
}

// ---- result helpers -----------------------------------------------------------------------------

func (s *Server) ok(req request, result any) response {
	return response{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *Server) fail(req request, code int, format string, args ...any) response {
	return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: fmt.Sprintf(format, args...)}}
}

func (s *Server) parseParams(req request, into any) *response {
	if len(req.Params) == 0 {
		return nil
	}
	if err := json.Unmarshal(req.Params, into); err != nil {
		r := s.fail(req, codeInvalidParams, "could not read params: %v", err)
		return &r
	}
	return nil
}

// ---- initialize ---------------------------------------------------------------------------------

type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      serverInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions,omitempty"`
}

type capabilities struct {
	Tools toolsCapability `json:"tools"`
	// Logging is advertised when the console watcher is on: task completion and High findings arrive
	// as notifications/message, and logging/setLevel filters them.
	Logging *struct{} `json:"logging,omitempty"`
	// Prompts publishes the console's skill library (burpsy-react-ui-ulsy).
	Prompts promptsCapability `json:"prompts"`
}

type toolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

// instructions is the standing guidance returned by initialize. It is the one place a client is
// told how the risk classes and the confirmation flow work before it calls anything, so it says
// what the classes mean and what a refusal means — and it says plainly that minting a confirmation
// is the caller's own act.
const instructions = `burpsy is an HTTP testing proxy with a risk-gated API. Every tool reaches routes of that API and carries their risk class: read, local-write, egress, attack, scope, credential, destructive, asset, execute. A grouped tool fronts several operations of ONE risk class; pick one with "op", spelled "VERB /route" exactly as the tool lists it, and give a subtree operation (route ending in "/") its "id" or "path".

Calling a tool is calling the route. Nothing here is simulated: an "attack" tool sends real traffic to the engagement target, and a "destructive" tool discards evidence.

Routes whose risk class requires confirmation (scope, attack, credential, destructive) refuse a MUTATING call that carries no confirmation. The refusal is HTTP 428 and is returned to you as an isError tool result. To proceed you must make the escalation its own step:
  1. call burpsy_confirm with {"tool": <the tool>, "arguments": <the exact arguments of the call>} — the refusal prints this for you. It returns a preview of the resolved request (method, URL, body) and a one-time token bound to that request;
  2. re-issue the original tool call, unchanged, with that token in its "confirm" argument.
A token authorises exactly one call, expires in 60 seconds, and is refused (and burned) on a call whose method, path, query or body differs from the one it was minted for.

Only mint a confirmation when a human has asked you to perform that specific action. An agent that mints its own confirmations has turned a checkpoint into a formality, and the refusal exists because these classes send unbounded traffic, widen the engagement's scope, or hand out credentials.`

func (s *Server) initialize(req request) response {
	var params initializeParams
	if r := s.parseParams(req, &params); r != nil {
		return *r
	}
	version := protocolVersions[len(protocolVersions)-1]
	for _, known := range protocolVersions {
		if params.ProtocolVersion == known {
			version = known
			break
		}
	}
	return s.ok(req, initializeResult{
		ProtocolVersion: version,
		Capabilities:    s.capabilities(),
		ServerInfo:      serverInfo{Name: "burpsy", Version: Version},
		Instructions:    instructions,
	})
}
