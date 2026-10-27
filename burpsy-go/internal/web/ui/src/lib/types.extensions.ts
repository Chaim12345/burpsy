// The EXTENDER wire shapes, mirroring internal/extension/views.go.
//
// Every count here is deliberately a separate field rather than something the UI derives: the Go side
// computes them, and a second implementation in TypeScript is a second place for "4 registered" and
// "4 registered, 2 refused" to disagree.

/** Where one allowlisted plugin stands. Five states, because the four ways of not being loaded are
 *  the ones an operator needs told apart. */
export type ExtensionState = "unloaded" | "loading" | "loaded" | "failed" | "crashed";

/** Which console a line belongs on. */
export type ConsoleStream = "output" | "error";

/** Who produced a console line. `plugin` is what it logged; the other three are not its words. */
export type ConsoleSource = "plugin" | "stderr" | "host" | "protocol";

/** The five registration points that have an honest web analogue. */
export type RegistrationKind =
 | "context-menu"
 | "menu"
 | "editor-tab"
 | "session-action"
 | "hotkey"
 | "payload-generator"
 | "payload-processor";

export interface Registration {
 id: string;
 kind: RegistrationKind;
 label: string;
 hint?: string;
 /** The binding a hotkey registration asked for, in Burp's Settings spelling ("Ctrl+Shift+P").
  * The host refuses a hotkey registration whose chord it cannot install, so a hotkey row that
  * reaches the console always carries one. */
 chord?: string;
 /** The same chord in this console's vocabulary ("mod+shift+p"), computed by the host's
  * NormaliseChord at load time. Installed verbatim — there is no second normaliser on this side,
  * so a chord the host accepted is a chord the keymap can bind (burpsy-react-ui-wsu4.2). */
 binding?: string;
}

export interface ExitInfo {
 at_ms: number;
 code: number;
 /** Set when a signal ended the process, in which case `code` is -1 and is not on its own an answer. */
 signal?: string;
 /** Set when the wait itself failed rather than the process exiting. */
 detail?: string;
}

export interface ExtensionView {
 /** The allowlist key: the identity the operator chose, and what every route takes. */
 name: string;
 path: string;
 args?: string[];

 state: ExtensionState;
 /** Why the plugin is in this state. A failed or crashed row without one would be "something went wrong". */
 detail?: string;

 /** What the plugin calls itself — a different fact from `name`, never overwriting it. */
 declared_name?: string;
 version?: string;
 /** Reported verbatim and never inferred from the file's name. */
 type?: string;
 protocol?: number;

 registrations: Registration[];
 registrations_refused: number;

 loaded_at_ms?: number;
 exit?: ExitInfo;

 output_lines: number;
 error_lines: number;
 output_dropped: number;
 error_dropped: number;
 protocol_errors: number;
 invocations: number;
 invocation_failures: number;

 /** The plugin->host methods the operator allowed this plugin; [] when none. */
 grants: string[];
 /** Granted calls per method for the current load ({} when none). */
 host_calls: Record<string, number>;
 /** Calls refused for want of a grant or by the engagement scope. */
 refused_host_calls: number;

 /**
  * Traffic-hook counters for the current load: hooks called, hooks that
  * failed (error, invalid answer, timeout), and whether the plugin is
  * suspended from hooks after repeated failures.
  */
 hook_calls: number;
 hook_failures: number;
 hook_suspended: boolean;
}

/** The admission rule and every bound in force in the running process, not the defaults in the source. */
export interface ExtensionPolicy {
 flag: string;
 allowlisted: number;
 load_timeout_ms: number;
 call_timeout_ms: number;
 shutdown_grace_ms: number;
 max_console_lines: number;
 max_console_line_bytes: number;
 max_message_bytes: number;
 max_registrations: number;
 protocol_version: number;
 environment_passed: string[];
 /** Always false: the executable is run directly, so an argument with shell metacharacters is data. */
 shell: boolean;
 /** Always null. A field that could hold a URL and holds none is a machine-readable "there is no store". */
 registry: string | null;
 registry_detail: string;
}

export interface ExtensionList {
 extensions: ExtensionView[];
 allowlisted: number;
 loaded: number;
 loading: number;
 unloaded: number;
 failed: number;
 crashed: number;
 /** The counts in words. Its job is the empty case. */
 detail: string;
 policy: ExtensionPolicy;
}

export interface ConsoleLine {
 at_ms: number;
 stream: ConsoleStream;
 source: ConsoleSource;
 text: string;
}

export interface ConsoleView {
 output: ConsoleLine[];
 error: ConsoleLine[];
 output_dropped: number;
 error_dropped: number;
 truncated: number;
 /** The per-stream bound, so "200 lines" can be told from "the bound is 200". */
 limit: number;
}

export interface MethodSpec {
 name: string;
 direction: "host-to-plugin" | "plugin-to-host";
 call: "request" | "notification";
 kind?: RegistrationKind;
 params: string;
 result: string;
 why: string;
}

export interface KindView {
 kind: RegistrationKind;
 method: string;
 label: string;
 /** The Montoya call this stands in for, so the tab reads next to Burp's own documentation. */
 montoya: string;
}

export interface UnsupportedCapability {
 what: string;
 why: string;
}

export interface ExtensionApis {
 protocol_version: number;
 transport: string;
 framing: string;
 handshake: string;
 kinds: KindView[];
 methods: MethodSpec[];
 unsupported: UnsupportedCapability[];
}

export interface InvokeResult {
 text?: string;
 output?: string;
}
