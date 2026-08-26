// Package extension hosts burpsy plugins as JSON-RPC child processes.
//
// # Why a child process and not a plugin API
//
// Burp's extension surface is `MontoyaApi`, a Java interface loaded from a jar
// into Burp's own JVM. There is no JVM here and nothing in this tree is binary-
// or source-compatible with it, so a Burp extension cannot be pointed at burpsy
// and never will be — that is stated in ROADMAP.md rather than left implied,
// because leaving it implied invites exactly the wrong expectation. The two
// alternatives to a child process were embedding a JVM (a runtime the size of the
// rest of the tool, for source compatibility we still would not have) and
// embedding WASM (a sandbox, but one where every capability has to be re-exported
// through an ABI before a plugin can use it). A child process speaking JSON-RPC
// over its own stdin/stdout is the substrate the roadmap picks: a plugin can be
// written in whatever language its author already knows, and Caido's experience
// is the cited evidence that this is what lowers the barrier.
//
// # What a plugin can register, and what it deliberately cannot
//
// `userInterface()` has thirteen registration points. Ten of them contribute
// Swing objects — `registerSuiteTab`, `applyThemeToComponent`, `swingUtils`,
// `currentDisplayFont`, menu-bar component insertion — and there is no honest web
// analogue for a Swing component. A "component" JSON schema whose only consumer
// is the thing that defined it is a fiction, so those ten are not implemented and
// are not counted as coverage. Three have real analogues and are the three
// KindContextMenu, KindMenu and KindEditorTab below.
//
// The editor tab is the one that needs its reason stated, because
// `registerHttpRequestEditorProvider` is listed as out of scope: Burp exposes the
// caret position and the live selection to that provider, and a request/response
// round trip cannot carry either. What is honest is the other half of the same
// idea — a named, read-only tab that renders a derived view of a whole message.
// That is what KindEditorTab is, and `editor.render` takes a message rather than
// a caret for that reason.
//
// # Framing
//
// One JSON value per line, `\n`-terminated, UTF-8: newline-delimited JSON-RPC
// 2.0. Chosen over LSP-style `Content-Length` headers because a plugin in any
// language can produce a line with one print statement, and because a bound on a
// line is a bound on a message — which this host needs anyway and would have had
// to impose on top of a header scheme. A JSON encoder never emits a bare newline
// inside a value, so the framing costs a plugin author nothing.
package extension

import (
	"encoding/json"
	"time"
)

// ProtocolVersion is the version the host announces in `initialize` and expects
// echoed back. A plugin that answers with a different number is refused rather
// than tolerated: the alternative is a plugin that half-works and reports
// nothing about which half.
const ProtocolVersion = 1

// Defaults for every bound this host imposes. Each exists because the child is
// operator-supplied code that this process cannot reason about, so nothing it
// produces may be unbounded — the same posture as scanner.NewToolRunner, which is
// the in-tree precedent for running an operator's binary at all.
const (
	// DefaultLoadTimeout bounds spawn plus handshake. Short: a plugin that cannot
	// answer `initialize` in ten seconds is broken, and a load that hangs is worse
	// than a load that fails, because the operator has nothing to read.
	DefaultLoadTimeout = 10 * time.Second
	// DefaultCallTimeout bounds one invocation.
	DefaultCallTimeout = 30 * time.Second
	// DefaultShutdownGrace is how long a plugin gets to exit after `shutdown`
	// before its stdin is closed and, failing that, it is killed.
	DefaultShutdownGrace = 2 * time.Second
	// DefaultMaxConsoleLines bounds each console, per plugin. Eviction is
	// oldest-first and counted — see console.append.
	DefaultMaxConsoleLines = 500
	// DefaultMaxConsoleLineBytes truncates one console line.
	DefaultMaxConsoleLineBytes = 8 << 10 // 8 KiB
	// DefaultMaxMessageBytes bounds one JSON-RPC line in either direction. A line
	// over the bound ends the session, because after a truncated read the stream
	// position is unknown and resynchronising would mean guessing.
	DefaultMaxMessageBytes = 1 << 20 // 1 MiB
	// DefaultMaxRegistrations bounds what one plugin may register. A manifest with
	// ten thousand menu items is not a feature.
	DefaultMaxRegistrations = 64
)

// Kind is one of the three registration points that have an honest web analogue.
type Kind string

const (
	// KindContextMenu is the analogue of registerContextMenuItemsProvider: an
	// action offered against a selected exchange.
	KindContextMenu Kind = "context-menu"
	// KindMenu is the analogue of registerMenuBarItem: an action with no selection.
	KindMenu Kind = "menu"
	// KindEditorTab is a named read-only tab over one message — the honest half of
	// registerHttpRequestEditorProvider. See the package doc for why the other half
	// (caret position, live selection) is not represented.
	KindEditorTab Kind = "editor-tab"
)

// validKinds is the closed set. A registration naming anything else is refused
// and counted rather than accepted as an inert row, because an inert row in the
// UI is indistinguishable from a working one.
var validKinds = map[Kind]bool{KindContextMenu: true, KindMenu: true, KindEditorTab: true}

// Registration is one thing a plugin declared at handshake.
type Registration struct {
	// ID is the plugin's own handle for this registration, echoed back on invoke.
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Label is what an operator sees. Required: an unlabelled action is a button
	// with no name.
	Label string `json:"label"`
	Hint  string `json:"hint,omitempty"`
}

// Manifest is what a plugin answers `initialize` with.
type Manifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Type is what the plugin says it is — "node", "python", a runtime name. It is
	// reported verbatim and never inferred: Burp's Extensions table has a Type
	// column, and guessing it from a file extension would put a fact in that column
	// that nothing established.
	Type          string         `json:"type"`
	Protocol      int            `json:"protocol"`
	Registrations []Registration `json:"registrations"`
}

// InitializeParams is what the host sends with `initialize`.
type InitializeParams struct {
	Protocol int    `json:"protocol"`
	Host     string `json:"host"`
	Plugin   string `json:"plugin"`
}

// ShutdownParams tells the plugin why it is being stopped, so its own log can say
// "asked to stop" rather than leaving the last line before an exit ambiguous.
type ShutdownParams struct {
	Reason string `json:"reason"`
}

// InvokeParams is the payload for all three invocation methods.
//
// One struct for three methods because the three differ only in which fields are
// meaningful, and omitempty makes an absent field absent on the wire rather than
// present-and-zero. Exchange 0 and message 0 are real ids in this engine (the
// stores are position-is-the-id counters from zero), which is why these are
// pointers: `"exchange": 0` and no exchange at all must not serialise the same.
type InvokeParams struct {
	Registration string `json:"registration"`
	Exchange     *int   `json:"exchange,omitempty"`
	Message      *int   `json:"message,omitempty"`
	// Raw is the message bytes for editor.render, as text. Carried in the call
	// rather than fetched by the plugin because a plugin has no route to this
	// process's traffic store, and giving it one would be a second egress path.
	Raw       string `json:"raw,omitempty"`
	Selection string `json:"selection,omitempty"`
}

// InvokeResult is what a plugin answers an invocation with. `editor.render` fills
// Text; the two menu methods fill Output. Both optional: a menu action whose whole
// effect was to log something has nothing to return, and inventing a status for it
// would be a fabricated result.
type InvokeResult struct {
	Text   string `json:"text,omitempty"`
	Output string `json:"output,omitempty"`
}

// LogParams is the one notification a plugin sends the host.
type LogParams struct {
	Stream  Stream `json:"stream"`
	Message string `json:"message"`
}

// ---- JSON-RPC envelope ---------------------------------------------------------------------

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return e.Message }

// rpcMessage is request, response and notification in one shape, which is what
// reading a bidirectional stream needs: the reader does not know which of the
// three the next line is until it has parsed it.
//
// ID is a *json.RawMessage so a plugin's request id is echoed back verbatim.
// JSON-RPC allows a string or a number there, and normalising it to int64 would
// answer a string-id request with a number-id response.
type rpcMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

// codeMethodNotFound is JSON-RPC's own code for it. Sent rather than invented so a
// plugin's client library recognises the answer.
const codeMethodNotFound = -32601

// ---- the documented method set ------------------------------------------------------------

// Direction says which side originates a method.
type Direction string

const (
	// HostToPlugin: the host calls, the plugin answers.
	HostToPlugin Direction = "host-to-plugin"
	// PluginToHost: the plugin sends, the host consumes.
	PluginToHost Direction = "plugin-to-host"
)

// MethodSpec is one method of the protocol, with the reason it exists.
type MethodSpec struct {
	Name      string    `json:"name"`
	Direction Direction `json:"direction"`
	// Call is "request" (an answer is required) or "notification" (no answer, and
	// none is read).
	Call string `json:"call"`
	// Kind is set on the three invocation methods and names the registration kind
	// each one serves. It is the only mapping from kind to method: Host.Invoke
	// switches on the kind with the same three literals, and a test drives a real
	// plugin to confirm the pairing rather than asserting the table against itself.
	Kind   Kind   `json:"kind,omitempty"`
	Params string `json:"params"`
	Result string `json:"result"`
	Why    string `json:"why"`
}

// MethodSpecs is the whole protocol, and it is the source the APIs tab renders.
//
// It is not documentation *about* the implementation, it is checked against it:
// Test_the_documented_method_set_is_the_dispatched_method_set parses this
// package's own source for the method names actually passed to session.call and
// registered in the inbound table, and fails if either set disagrees with this
// one. That is the same technique internal/web/route_manifest_test.go uses to keep
// its route manifest honest, and it exists for the same reason — hand-written
// prose about a wire protocol drifts, and the drift is invisible until someone
// writes a plugin against it.
var MethodSpecs = []MethodSpec{
	{
		Name: "initialize", Direction: HostToPlugin, Call: "request",
		Params: `{"protocol": 1, "host": "burpsy", "plugin": "<allowlist name>"}`,
		Result: `{"name": string, "version": string, "type": string, "protocol": 1, ` +
			`"registrations": [{"id": string, "kind": "context-menu"|"menu"|"editor-tab", "label": string, "hint"?: string}]}`,
		Why: "The handshake, and the only place registrations are declared. A protocol number " +
			"that does not match the host's refuses the load rather than half-working.",
	},
	{
		Name: "shutdown", Direction: HostToPlugin, Call: "request",
		Params: `{"reason": string}`,
		Result: `{}`,
		Why: "Asks the plugin to exit so its own log can record an orderly stop. The host does not " +
			"depend on the answer: stdin is closed after the grace period and the process killed after that.",
	},
	{
		Name: "contextMenu.invoke", Direction: HostToPlugin, Call: "request", Kind: KindContextMenu,
		Params: `{"registration": string, "exchange": int, "raw"?: string}`,
		Result: `{"output"?: string}`,
		Why: "The analogue of registerContextMenuItemsProvider: an action against a selected " +
			"exchange. The exchange id and its bytes are passed in, because a plugin has no route to " +
			"this process's traffic store.",
	},
	{
		Name: "menu.invoke", Direction: HostToPlugin, Call: "request", Kind: KindMenu,
		Params: `{"registration": string}`,
		Result: `{"output"?: string}`,
		Why:    "The analogue of registerMenuBarItem: an action with no selection behind it.",
	},
	{
		Name: "editor.render", Direction: HostToPlugin, Call: "request", Kind: KindEditorTab,
		Params: `{"registration": string, "message": int, "raw": string}`,
		Result: `{"text": string}`,
		Why: "A named read-only tab over one message. Deliberately not the whole of " +
			"registerHttpRequestEditorProvider: Burp gives that provider the caret position and the live " +
			"selection, and a request/response round trip cannot carry either, so the editing half is " +
			"not offered rather than offered and broken.",
	},
	{
		Name: "log", Direction: PluginToHost, Call: "notification",
		Params: `{"stream": "output"|"error", "message": string}`,
		Result: `—`,
		Why: "The plugin's two consoles. Needed because stdout is the transport here, so unlike " +
			"Montoya's PrintStreams a plugin cannot simply print — and a line it does print on stdout " +
			"is recorded as a protocol violation instead of being read as output.",
	},
}

// Unsupported records what a plugin deliberately cannot do in this build, so the
// APIs tab states it rather than leaving an operator to infer it from a missing
// method. Reported on the wire for the same reason the scanner counts its gated
// checks: an absent capability that is named is a decision, an absent capability
// that is silent is a bug.
type Unsupported struct {
	What string `json:"what"`
	Why  string `json:"why"`
}

// Unsupported is the closed list of things this protocol does not offer.
var UnsupportedCapabilities = []Unsupported{
	{
		What: "A plugin cannot originate an HTTP request through burpsy",
		Why: "Every request this process sends goes through sender.AuthorisedSender so the " +
			"engagement scope decides about the bytes before the dial. A plugin send method is real work " +
			"— it has to bind that authority per call — and it is not wired here. A method that " +
			"answered without sending would turn every plugin that used it into a silent false negative.",
	},
	{
		What: "A plugin cannot contribute a UI component",
		Why: "Ten of Montoya's thirteen userInterface() registration points hand Burp a Swing " +
			"object. A JSON schema for a 'component' whose only consumer is the thing that defined it " +
			"is a fiction, so those ten are not represented at all.",
	},
	{
		What: "There is no plugin registry, store, or install path",
		Why: "Burp's BApp Store is a hosted catalogue. Nothing here fetches, resolves or installs " +
			"anything: a plugin is a local executable the operator names on the command line with " +
			"-plugins. A store tab listing nothing would imply a catalogue exists.",
	},
	{
		What: "A plugin cannot see the caret or the selection in a message editor",
		Why: "editor.render is given a whole message. The interactive half of " +
			"registerHttpRequestEditorProvider needs live editor state that a request/response round " +
			"trip does not carry.",
	},
}
