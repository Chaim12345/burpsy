package extension

// The wire shapes the API serves.
//
// They live here rather than in internal/web because every honest-counting field
// on them — the state breakdown, the refused-registration count, the dropped-line
// counts — is computed by this package, and a view type owned by the HTTP layer
// invites a handler that recomputes one of them slightly differently. This is the
// same arrangement internal/dash uses for the dashboard's counts.

// PluginView is one allowlisted plugin as served.
type PluginView struct {
	// Name is the allowlist key — the identity the operator chose and the one every
	// route takes. DeclaredName below is what the plugin calls itself, which is a
	// different fact and is reported separately rather than overwriting this one.
	Name string   `json:"name"`
	Path string   `json:"path"`
	Args []string `json:"args,omitempty"`

	State State `json:"state"`
	// Detail is why the plugin is in this state, when the state needs a reason. A
	// failed or crashed row without one would be the "something went wrong" of
	// error messages.
	Detail string `json:"detail,omitempty"`

	DeclaredName string `json:"declared_name,omitempty"`
	Version      string `json:"version,omitempty"`
	// Type is what the plugin says it is, verbatim, and empty until it has said so.
	// Burp's Extensions table has a Type column; inferring one from a file
	// extension would put a fact there that nothing established.
	Type     string `json:"type,omitempty"`
	Protocol int    `json:"protocol,omitempty"`

	// Registrations are the ones that passed validation, and RegistrationsRefused
	// counts the ones that did not. Two numbers because "4 registered" and
	// "4 registered, 2 refused" are different answers and one field cannot give
	// both — the refusals are on the error console with their reasons.
	Registrations        []Registration `json:"registrations"`
	RegistrationsRefused int            `json:"registrations_refused"`

	LoadedAtMs int64     `json:"loaded_at_ms,omitempty"`
	Exit       *ExitInfo `json:"exit,omitempty"`

	// Console and invocation counters for the current load. A reload starts a new
	// session, so these describe that session and not the plugin's whole history —
	// carrying them across would make "0 failures" mean "none since the last
	// restart", which reads as "none ever".
	OutputLines        int `json:"output_lines"`
	ErrorLines         int `json:"error_lines"`
	OutputDropped      int `json:"output_dropped"`
	ErrorDropped       int `json:"error_dropped"`
	ProtocolErrors     int `json:"protocol_errors"`
	Invocations        int `json:"invocations"`
	InvocationFailures int `json:"invocation_failures"`
}

// ListView is every allowlisted plugin plus the breakdown across them.
//
// There is no "total" field. Allowlisted is the size of the operator's allowlist
// and the five state counts partition it exactly — asserted by a test — so a total
// would be a second way to say the same thing and a place for the two to disagree.
// internal/dash's Breakdown omits its total for the same reason.
type ListView struct {
	Extensions  []PluginView `json:"extensions"`
	Allowlisted int          `json:"allowlisted"`
	Loaded      int          `json:"loaded"`
	Loading     int          `json:"loading"`
	Unloaded    int          `json:"unloaded"`
	Failed      int          `json:"failed"`
	Crashed     int          `json:"crashed"`
	// Detail states the counts in words, and its job is the empty case: a table
	// with no rows must say "nothing is allowlisted, here is how to allowlist one"
	// rather than leaving an operator to guess whether the feature is missing.
	Detail string     `json:"detail"`
	Policy PolicyView `json:"policy"`
}

// PolicyView is the admission rule and every bound in force in this process.
//
// Served rather than documented so the Options tab shows what this process is
// doing. A page that printed the defaults from the source would be wrong for any
// operator who changed one, and right in a way that could not be checked.
type PolicyView struct {
	// Flag is the exact command-line form that admits a plugin.
	Flag        string `json:"flag"`
	Allowlisted int    `json:"allowlisted"`

	LoadTimeoutMs   int64 `json:"load_timeout_ms"`
	CallTimeoutMs   int64 `json:"call_timeout_ms"`
	ShutdownGraceMs int64 `json:"shutdown_grace_ms"`

	MaxConsoleLines     int `json:"max_console_lines"`
	MaxConsoleLineBytes int `json:"max_console_line_bytes"`
	MaxMessageBytes     int `json:"max_message_bytes"`
	MaxRegistrations    int `json:"max_registrations"`

	ProtocolVersion int `json:"protocol_version"`

	// EnvironmentPassed is which of the host's environment variables a child sees.
	EnvironmentPassed []string `json:"environment_passed"`
	// Shell is always false and is stated rather than assumed: the executable is
	// run directly, so an argument containing shell metacharacters is data.
	Shell bool `json:"shell"`

	// Registry is null, always, and RegistryDetail says why. A field that could
	// hold a URL and holds none is a machine-readable "there is no store", which is
	// what a caller needs; omitting it would leave the absence to be inferred.
	Registry       *string `json:"registry"`
	RegistryDetail string  `json:"registry_detail"`
}

// APIView is the protocol contract, generated from the same table the dispatcher
// is checked against.
type APIView struct {
	ProtocolVersion int    `json:"protocol_version"`
	Transport       string `json:"transport"`
	Framing         string `json:"framing"`
	Handshake       string `json:"handshake"`
	// Kinds is the closed set of registration points, each paired with the method
	// that invokes it — read out of Methods below rather than restated, so the two
	// cannot disagree.
	Kinds       []KindView    `json:"kinds"`
	Methods     []MethodSpec  `json:"methods"`
	Unsupported []Unsupported `json:"unsupported"`
}

// KindView pairs a registration kind with the method that invokes it.
type KindView struct {
	Kind    Kind   `json:"kind"`
	Method  string `json:"method"`
	Label   string `json:"label"`
	Montoya string `json:"montoya"`
}

// API returns the contract to serve.
func API() APIView {
	return APIView{
		ProtocolVersion: ProtocolVersion,
		Transport: "The plugin is a child process. The host writes requests to its stdin and reads " +
			"replies and notifications from its stdout; stderr is captured verbatim onto the error console.",
		Framing: "Newline-delimited JSON-RPC 2.0: one JSON value per line, \\n-terminated, UTF-8. " +
			"Chosen over LSP-style Content-Length headers because a plugin in any language can produce a " +
			"line with one print statement, and a bound on a line is the bound on a message this host needs anyway.",
		Handshake: "The host sends `initialize` first and reads the manifest. A plugin that answers " +
			"with a protocol number other than the host's is stopped and the load reported as failed, " +
			"rather than continued with a plugin that may disagree about every later method.",
		Kinds:       kindViews(),
		Methods:     MethodSpecs,
		Unsupported: UnsupportedCapabilities,
	}
}

// KindCount is how many registration points the protocol offers.
//
// Exported so a caller can assert the contract view carries all of them without restating the
// number. The hardcoded 4 this replaced was already stale — KindHotKey landed (burpsy-react-ui-wsu4)
// and the assertion kept counting four, so a correct implementation read as a broken one. That is
// the shape of a pin against a literal where a table exists: it cannot tell "the route dropped one"
// from "the table gained one", and it fails for the second.
//
// Derived from kindLabels rather than from validKinds, because kindLabels is what the view is BUILT
// from (kindViews) — asserting against the input rather than the source of the rendering.
func KindCount() int { return len(kindLabels) }

// kindLabels and kindMontoya name each registration point for an operator and say
// which Montoya call it is the analogue of, so the APIs tab can be read next to
// Burp's own documentation.
var kindLabels = map[Kind]string{
	KindContextMenu:   "Context-menu item",
	KindMenu:          "Menu action",
	KindEditorTab:     "Message-editor tab",
	KindSessionAction: "Session-handling action",
	KindHotKey:        "Hotkey",
}

var kindMontoya = map[Kind]string{
	KindContextMenu:   "registerContextMenuItemsProvider",
	KindMenu:          "registerMenuBarItem",
	KindEditorTab:     "registerHttpRequestEditorProvider (read-only half only)",
	KindSessionAction: "registerSessionHandlingAction",
	KindHotKey:        "registerHotKeyHandler",
}

func kindViews() []KindView {
	out := make([]KindView, 0, len(MethodSpecs))
	for _, spec := range MethodSpecs {
		if spec.Kind == "" {
			continue
		}
		out = append(out, KindView{
			Kind:    spec.Kind,
			Method:  spec.Name,
			Label:   kindLabels[spec.Kind],
			Montoya: kindMontoya[spec.Kind],
		})
	}
	return out
}
