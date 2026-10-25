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
	"slices"
	"strings"
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
	// DefaultReloadInterval is how often Config.AutoReload stats each loaded plugin's executable
	// looking for a rebuild (burpsy-react-ui-1ye7). One second: fast enough that an author who has
	// just rebuilt sees the reload before they switch windows, slow enough that the watch costs one
	// stat per allowlisted plugin per second, which is nothing against a watch set that is a
	// handful of paths by construction.
	DefaultReloadInterval = time.Second
)

// Kind is one of the registration points that have an honest web analogue.
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
	// KindSessionAction is the analogue of registerSessionHandlingAction: a rule's
	// "Invoke an extension" action. Distinct from KindContextMenu because the input
	// and the output are different: a context-menu item is handed a selected
	// exchange and may return text, while a session action is handed the request a
	// session rule has built so far and returns the request that should be sent.
	//
	// The return value is why this is a kind rather than a menu item the operator
	// triggers by hand: without it the rule could ask a plugin a question and then
	// send its own request unchanged, which is a rule reporting success while doing
	// nothing — the failure the invoke-extension action refuses rather than hides.
	KindSessionAction Kind = "session-action"
	// KindHotKey is the analogue of registerHotKeyHandler: a chord that invokes a
	// registration without a selection, the way Burp's own hotkeys do. The chord is
	// declared at the handshake in Burp's Settings spelling ("Ctrl+Shift+P" — see
	// burp.api.montoya.ui.hotkey.HotKey: "Hotkeys are defined in the same format as
	// within Burp's Settings"), and the host normalises it to the web console's
	// vocabulary (mod/alt/shift+key) before installing it, refusing what it cannot
	// spell rather than installing a chord that would never fire.
	//
	// Burp's five HotKeyContexts (HTTP message editor, Proxy history, Intruder
	// results, Organizer entries, Site map) are not carried: the console's global
	// dispatch cannot scope a DOM keydown to one table's rows without each surface
	// opting in, and a hotkey that fires only sometimes — or worse, fires on the
	// page the operator did not mean — is worse than one that fires everywhere. A
	// hotkey here is a suite-wide binding, which is also what Burp's context-less
	// overload means ("it will fire for any supported context").
	KindHotKey Kind = "hotkey"
)

// validKinds is the closed set. A registration naming anything else is refused
// and counted rather than accepted as an inert row, because an inert row in the
// UI is indistinguishable from a working one.
var validKinds = map[Kind]bool{
	KindContextMenu: true, KindMenu: true, KindEditorTab: true, KindSessionAction: true,
	KindHotKey: true,
}

// NormaliseChord spells a Burp-Settings hotkey ("Ctrl+Shift+P") in the console's own
// vocabulary ("mod+shift+p"), or returns "" for a binding this console cannot install.
//
// The console's rule is validateChord's, in Go: a binding must carry mod (Ctrl/Cmd) or alt,
// because a bare key would fire while the operator types, and it may add shift, and it names
// exactly one non-modifier key. Burp's spelling is lenient about case, order and the separators
// (+, -, space, or none — "Ctrl+Shift+P", "ctrl shiftp" and "ctrl-shift p" all name one
// binding), so this reads modifiers by prefix rather than by splitting: "ctrlp" is ctrl+p and
// not some key called "ctrlp".
//
// What is refused, and why that is the honest answer: Burp's meta key ("Cmd" on macOS) has no
// web spelling the console can promise cross-platform — mod is already the platform's own
// primary modifier, so a plugin asking for meta is asking for a chord that would silently
// never fire. F5 and friends (function keys, media keys) are refused for the same reason the
// shipped bindings avoid them: the browser or the OS owns them. A refused chord is counted on
// the wire like every other refused registration, rather than installed as a binding that
// looks registered and never fires.
//
// A second non-modifier token is refused rather than overwriting the first: "Ctrl+K+J" is
// not a chord this console can install, and silently binding it to "mod+j" would be a
// binding the operator did not ask for. Key names are checked against the set the keymap
// can dispatch — "Ctrl+Banana" is refused, not bound to a key that will never fire.
func NormaliseChord(burp string) string {
	rest := strings.ToLower(strings.TrimSpace(burp))
	if rest == "" {
		return ""
	}
	var mods []string
	var key string
	for rest != "" {
		// Modifiers: prefix-matched, longest first so "control" wins over "ctrl".
		matched := false
		for _, m := range []struct{ prefix, mod string }{
			{"control", "mod"}, {"ctrl", "mod"}, {"cmd", "mod"},
			{"shift", "shift"},
			{"option", "alt"}, {"alt", "alt"},
			{"meta", ""}, {"super", ""}, {"windows", ""},
		} {
			if strings.HasPrefix(rest, m.prefix) {
				if m.mod == "" {
					return "" // meta/super/windows: no web spelling
				}
				rest = strings.TrimPrefix(rest, m.prefix)
				if !slices.Contains(mods, m.mod) {
					mods = append(mods, m.mod)
				}
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		// The key: everything up to the next separator, or the whole remainder.
		sep := strings.IndexAny(rest, "+- ")
		if sep == 0 {
			// A leading separator the modifier scan did not consume: skip it, it names nothing.
			rest = rest[1:]
			continue
		}
		// A second non-modifier token is a refusal, not an overwrite.
		if key != "" {
			return ""
		}
		if sep < 0 {
			key, rest = rest, ""
		} else {
			key, rest = rest[:sep], rest[sep:]
		}
	}
	if key == "" {
		return ""
	}
	// Exactly one non-modifier key, and it must not itself be a modifier name ("ctrl+shift" is
	// not a binding).
	switch key {
	case "ctrl", "cmd", "control", "shift", "alt", "option", "meta", "super", "windows":
		return ""
	}
	// Function and media keys are the browser's and the OS's; a plugin cannot have them.
	if len(key) == 2 && key[0] == 'f' && key[1] >= '1' && key[1] <= '9' {
		return ""
	}
	if key == "f10" || key == "f11" || key == "f12" {
		return ""
	}
	// The key must be one the keymap can dispatch.
	if !dispatchableKeys[key] {
		return ""
	}
	if !slices.Contains(mods, "mod") && !slices.Contains(mods, "alt") {
		return ""
	}
	// Refuse editing keys: clipboard (c/v/x), undo (z), and any chord with both
	// mod and alt (AltGr combinations like Ctrl+Alt+Q = '@' on German layouts).
	// These belong to the browser and the editor, not to plugins.
	if slices.Contains(mods, "mod") && slices.Contains(mods, "alt") {
		return ""
	}
	switch key {
	case "c", "v", "x", "z":
		return ""
	}
	order := []string{"mod", "alt", "shift"}
	var out []string
	for _, m := range order {
		if slices.Contains(mods, m) {
			out = append(out, m)
		}
	}
	return strings.Join(append(out, key), "+")
}

// dispatchableKeys is the set of key names the keymap can actually dispatch. A chord
// naming a key outside this set would be bound and never fire — the exact defect this
// normaliser exists to prevent.
var dispatchableKeys = map[string]bool{
	// Letters
	"a": true, "b": true, "c": true, "d": true, "e": true, "f": true, "g": true,
	"h": true, "i": true, "j": true, "k": true, "l": true, "m": true, "n": true,
	"o": true, "p": true, "q": true, "r": true, "s": true, "t": true, "u": true,
	"v": true, "w": true, "x": true, "y": true, "z": true,
	// Digits
	"0": true, "1": true, "2": true, "3": true, "4": true, "5": true, "6": true,
	"7": true, "8": true, "9": true,
	// Punctuation and symbols (spelled by name, not character)
	"comma": true, "period": true, "slash": true, "backslash": true,
	"semicolon": true, "quote": true, "bracketleft": true, "bracketright": true,
	"minus": true, "equal": true, "backquote": true, "space": true,
	"enter": true, "tab": true, "backspace": true, "delete": true,
	"escape": true, "capslock": true,
	// Arrow keys
	"arrowup": true, "arrowdown": true, "arrowleft": true, "arrowright": true,
	"up": true, "down": true, "left": true, "right": true,
	// Navigation
	"home": true, "end": true, "pageup": true, "pagedown": true,
	// Numpad
	"numpad0": true, "numpad1": true, "numpad2": true, "numpad3": true,
	"numpad4": true, "numpad5": true, "numpad6": true, "numpad7": true,
	"numpad8": true, "numpad9": true, "numpadenter": true,
	"numpadadd": true, "numpadsubtract": true, "numpadmultiply": true,
	"numpaddivide": true, "numpaddecimal": true,
}

// Registration is one thing a plugin declared at handshake.
type Registration struct {
	// ID is the plugin's own handle for this registration, echoed back on invoke.
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Label is what an operator sees. Required: an unlabelled action is a button
	// with no name.
	Label string `json:"label"`
	Hint  string `json:"hint,omitempty"`
	// Chord is the keyboard binding a hotkey registration asks for, in Burp's
	// Settings spelling ("Ctrl+Shift+P"). Only KindHotKey reads it; the host
	// refuses a hotkey registration whose chord is missing or unspellable, and
	// ignores the field on the other kinds rather than letting it imply a
	// binding that was never installed.
	Chord string `json:"chord,omitempty"`
	// Binding is the normalised chord in the console's vocabulary, set by the
	// host at load time. The UI installs this field verbatim — no second
	// normaliser, no disagreement possible.
	Binding string `json:"binding,omitempty"`
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
	// Request, Response and Values are sessionAction.invoke's payload: the request the rule has built
	// so far, the response the rule is reacting to (nil when it has not observed one), and the
	// {{name}} values a macro action extracted earlier in the same rule.
	//
	// Structured fields rather than one raw message, unlike editor.render's `raw`. The reason is the
	// return value: a plugin answers with a *request*, and a raw round trip would need an HTTP
	// serialiser and a parser on both sides of a JSON-RPC boundary, each able to disagree with the
	// sender that actually dials. The fields are the sender's own vocabulary (method, absolute URL,
	// ordered headers, body), so nothing has to be re-encoded on the way in or out.
	Request  *SessionRequest   `json:"request,omitempty"`
	Response *SessionResponse  `json:"response,omitempty"`
	Values   map[string]string `json:"values,omitempty"`
	// Raw is the message bytes for editor.render, as text. Carried in the call
	// rather than fetched by the plugin because a plugin has no route to this
	// process's traffic store, and giving it one would be a second egress path.
	Raw       string `json:"raw,omitempty"`
	Selection string `json:"selection,omitempty"`
	// Selected and Editor are hotkey.invoke's payload (burpsy-react-ui-gqvg): the rows the
	// operator had highlighted and the message open in the editor when the chord fired, the
	// analogue of HotKeyEvent.selectedRequestResponses and messageEditorRequestResponse.
	// Host.Invoke forwards them to hotkey.invoke only; every other method's documented params
	// omit them. Both are absent from the wire when empty, so a plugin written before this
	// sees the old shape.
	Selected []SelectedExchange `json:"selected,omitempty"`
	Editor   *EditorMessage     `json:"editor,omitempty"`
}

// MaxHotkeySelection bounds the rows one hotkey invocation may carry. The caller already
// holds the bytes, so the bound protects the plugin pipe, not the traffic store.
const MaxHotkeySelection = 100

// SelectedExchange is one highlighted row. Exchange is a pointer for the same reason
// InvokeParams.Exchange is: 0 is a real id. Raw is optional because the caller may hold only
// the id.
type SelectedExchange struct {
	Exchange *int   `json:"exchange"`
	Raw      string `json:"raw,omitempty"`
}

// EditorMessage is the message open in an editor when the hotkey fired. Message is a pointer
// because message 0 is a real id.
type EditorMessage struct {
	Message *int   `json:"message,omitempty"`
	Raw     string `json:"raw,omitempty"`
}

// InvokeResult is what a plugin answers an invocation with. `editor.render` fills
// Text; the two menu methods fill Output. Both optional: a menu action whose whole
// effect was to log something has nothing to return, and inventing a status for it
// would be a fabricated result.
type InvokeResult struct {
	Text   string `json:"text,omitempty"`
	Output string `json:"output,omitempty"`
	// Request is what a session-action's plugin wants sent — sessionAction.invoke's only functional
	// answer. Omitted means "send what the rule already built", which is a real and useful answer
	// (a plugin that only observes, or only rewrote the jar through burpsy's cookies), and is
	// therefore distinguished from an empty object only by being absent.
	Request *SessionRequest `json:"request,omitempty"`
}

// SessionRequest is one request inside a sessionAction.invoke call, in the sender's own vocabulary.
//
// Headers are an ordered list of pairs rather than a map: a Go map has no order and a JSON object
// has none either, so a plugin handed a map could only answer with an order it invented, and header
// order is part of the request the target receives. The pair-array shape is the one this tree
// already uses for the same reason (sessionStepDto.Headers, and the console's header editors).
type SessionRequest struct {
	Method  string     `json:"method"`
	URL     string     `json:"url"`
	Headers [][]string `json:"headers,omitempty"`
	Body    string     `json:"body,omitempty"`
}

// SessionResponse is the observed response a session action is shown. Status is carried as the
// number that was on the wire, including 0 when no response arrived — which is a fact about the
// request rather than a missing value.
type SessionResponse struct {
	Status  int        `json:"status"`
	Headers [][]string `json:"headers,omitempty"`
	Body    string     `json:"body,omitempty"`
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
			`"registrations": [{"id": string, "kind": "context-menu"|"menu"|"editor-tab"|"session-action"|"hotkey", "label": string, "hint"?: string, "chord"?: string}]}`,
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
		Name: "sessionAction.invoke", Direction: HostToPlugin, Call: "request", Kind: KindSessionAction,
		Params: `{"registration": string, "request": {method, url, headers, body}, "response"?: {status, headers, body}, "values"?: {name: value}}`,
		Result: `{"request"?: {method, url, headers, body}, "output"?: string}`,
		Why: "The analogue of registerSessionHandlingAction: a session rule's Invoke-an-extension action. " +
			"The plugin is handed the request the rule has built so far — after its earlier actions ran, " +
			"including any macro — and answers with the request it wants sent. Request and response are " +
			"structured rather than raw because the answer is a request: a raw round trip would need a " +
			"serialiser and a parser on each side of the boundary, each able to disagree with the sender " +
			"that actually dials.",
	},
	{
		Name: "hotkey.invoke", Direction: HostToPlugin, Call: "request", Kind: KindHotKey,
		Params: `{"registration": string, "selected"?: [{"exchange": int, "raw"?: string}], "editor"?: {"message"?: int, "raw"?: string}}`,
		Result: `{"output"?: string}`,
		Why: "The analogue of registerHotKeyHandler: the console dispatches the registration's " +
			"declared chord to this method. selected is the rows the operator had highlighted " +
			"(HotKeyEvent.selectedRequestResponses) and editor the message open in an editor " +
			"(messageEditorRequestResponse); both are omitted when there was none, which is the " +
			"menu.invoke shape. At most 100 rows are carried. The ids and bytes are handed in " +
			"because a plugin has no route to the traffic store.",
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
