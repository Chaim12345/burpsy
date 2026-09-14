/**
 * Wire types for the policy surfaces (match/replace, session, organizer, settings).
 * Field names mirror the Go json tags exactly; see internal/web/api_toolkit.go,
 * api_session.go, api_capture.go, api_protocol.go and events.go.
 */

/* --- match & replace ------------------------------------------------------- */

/**
 * The targets targetToCategory() in api_toolkit.go accepts. Anything else is refused with a 400
 * naming the accepted vocabulary — it does not compile to a no-op rule, which it used to.
 *
 * The two WebSocket targets rewrite a whole message payload. A frame has no headers, no first line
 * and no parameters, so the payload is the only addressable unit.
 */
export type MatchReplaceTarget =
 | "request_first_line"
 | "request_header"
 | "request_body"
 | "request_param_name"
 | "request_param_value"
 | "response_header"
 | "response_body"
 | "websocket_to_server"
 | "websocket_to_client";

/** matchReplaceCategoryName(): the server knows exactly these two. */
export type MatchReplaceCategory = "literal" | "regex";

export type MatchReplaceDirection = "request" | "response" | "websocket";

/** What /api/tools/rules/test answers with; `output` is the server's bytesView shape. */
export interface BytesView {
 text: string;
 len: number;
 utf8: boolean;
 truncated: boolean;
}

export interface MatchReplaceTestRequest {
 input: string;
 direction: MatchReplaceDirection;
 /** Compiled and applied inline; the persisted rule set is never touched. */
 draft_rules: MatchReplaceRuleSpec[];
}

export interface MatchReplaceTestResponse {
 changed: boolean;
 output: BytesView;
}

/**
 * One rule as the wire carries it: exactly Burp's own rule model, which is rule_type, enabled,
 * category, string_match, string_replace and comment and nothing else.
 *
 * # What is deliberately not here
 *
 * The Rust-era shape carried `scope` and `query` per rule. Burp's model has neither — its rule
 * table has seven columns and no scope (CoreComponent5002), and its serializer writes those six
 * fields (Zejh.ZY) — so the server refuses a rule carrying either rather than saving it without
 * the condition, and never serves one back. Declaring them here would advertise a payload the
 * server rejects.
 */
export interface MatchReplaceRuleSpec {
 rule_type: MatchReplaceTarget;
 enabled: boolean;
 string_match: string;
 string_replace: string;
 category: MatchReplaceCategory;
 comment: string;
}

/* --- session -------------------------------------------------------------- */

/** ExtractFrom: the bare string "body", or a named header. */
export type SessionExtractFrom = "body" | { header: string };

/** ExtractHow: exactly one arm. "whole" is the server's match-everything regex. */
export type SessionExtractHow = { regex: { pattern: string; group?: number } } | { json_path: string } | "whole";

export interface SessionExtraction {
 name: string;
 from?: SessionExtractFrom;
 how: SessionExtractHow;
}

export interface SessionMacroStep {
 method: string;
 url: string;
 /** [name, value] pairs; the server sorts them, so a re-read is stable. */
 headers: [string, string][];
 body: string;
 extract?: SessionExtraction[];
}

/**
 * ValidityRule is a struct, not a tagged union: the flat fields combine, and
 * all/any/not nest. The editor drives the flat fields and preserves the nested
 * ones verbatim rather than dropping what it cannot draw.
 */
export interface SessionValidity {
 status_is?: number;
 body_contains?: string;
 body_not_contains?: string;
 header_present?: string;
 header_absent?: string;
 /** When set, body_contains / body_not_contains / url_contains are regexes, not literals. */
 regex?: boolean;
 /** Disables the case-folding a literal (and a flagless regex) would otherwise get. */
 case_sensitive?: boolean;
 /** The URL of any redirection target: matched where the last step's redirect lands. */
 url_contains?: string;
 all?: SessionValidity[];
 any?: SessionValidity[];
 not?: SessionValidity;
}

/** The scope document a session rule carries. */
export interface SessionScopeRule {
 kind: "Include" | "Exclude";
 host: string | null;
 /** Custom-scope URL arms (7nh2): the host pattern plus optional path prefix / port / protocol —
  *  Burp's URL-matching rules are per full URL, and these are the arms this rule's host pattern
  *  is narrowed by. */
 path?: string;
 port?: number;
 protocol?: "http" | "https";
}

export interface SessionScope {
 allow_all: boolean;
 rules: SessionScopeRule[];
 /** Burp's URL-scope radio (7nh2): "suite" = Use suite scope [defined in Target tab],
  *  "custom" = Use custom scope; absent/other = Include all URLs (the historical shape). */
 mode?: "suite" | "custom";
 /** Custom-scope arms carried at the scope-block level (the server reads them from here): a
  *  path prefix, one port, one protocol. */
 path?: string;
 port?: number;
 protocol?: "http" | "https";
}

export interface SessionRuleFull {
 id?: number;
 name: string;
 enabled: boolean;
 /** Omitted means "applies everywhere"; a stated but empty scope is refused. */
 scope?: SessionScope;	/**
	 * Burp's parameter scope (burpsy-react-ui-9hip): the rule applies only where every named
	 * parameter exists. Omitted = unrestricted, like the host scope.
	 */
	scope_params?: string[];
	/**
	 * Burp's tools scope (so3): the rule applies only to requests made by one of these tools,
	 * named as the Logger's capture filter names them. Omitted = every tool. An empty array is
	 * refused by the server rather than read as "every tool" — an operator who unchecked every
	 * box meant the opposite of that, and the form shows the meaning either way.
	 */
	scope_tools?: string[];
 steps: SessionMacroStep[];
 validity: SessionValidity;
 max_attempts?: number;
}export interface SessionRulesResponse {
	wired: boolean;
	rules: SessionRuleFull[];
	hint?: string;
	/**
	 * Every tool name a rule's tools scope may name (so3), served by the API so this checklist
	 * cannot drift from what the server enforces. Always present: the server sends it even when
	 * the rules list is empty.
	 */
	tools: string[];
}

export interface SessionCookiePair {
 name: string;
 value: string;
}

export interface SessionHostCookies {
 /** The full authority ("example.com:443"). A jar is keyed by host, port and TLS, so two jars can
  *  share a hostname — showing the bare name would render them as duplicate rows. */
 host: string;
 port: number;
 /** Whether this jar's authority is the TLS one. Two jars for the same host:port differ only here. */
 tls: boolean;
 cookies: SessionCookiePair[];
}

export interface SessionCookiesResponse {
 wired: boolean;
 cookies?: SessionHostCookies[];
 hint?: string;
}

export interface SessionLoginResponseView {
 status: number;
 headers?: Record<string, string>;
 body: string;
}

/**
 * Every outcome the coordinator distinguishes. "the login ran and did not work"
 * (gave_up) is a different answer from "the macro could not be sent" (macro_failed),
 * and the operator has to be able to tell them apart.
 */
export type SessionLoginOutcome =
 | "no_rule_applies"
 | "already_valid"
 | "recovered"
 | "still_invalid_after_relogin"
 | "gave_up"
 | "macro_failed"
 | "retry_failed"
 | "probe_failed";

export interface SessionLoginResponse {
 outcome?: SessionLoginOutcome;
 rule?: string;
 rule_id?: number;
 url?: string;
 rules?: number;
 hint?: string;
 login_attempts?: number;
 attempt?: number;
 step_index?: number;
 validity?: "valid" | "invalid" | "indeterminate";
 response?: SessionLoginResponseView;
 error?: string;
}

/** One step of a Test-macro dry-run (burpsy-react-ui-7zdm): what was sent (with the jar's cookie
 *  threading visible), what came back, what cookies the response set, and each extraction's
 *  outcome. Skipped carries why when no response exists (out of scope, send failure). */
export interface SessionTestExtraction {
 name: string;
 outcome: string;
 value?: string;
 detail?: string;
}

export interface SessionTestStep {
 index: number;
 sent: SessionMacroStep & { headers?: Record<string, string> };
 sent_cookie?: string;
 skipped?: string;
 response?: { status: number; headers?: Record<string, string>; body?: string };
 set_cookies?: string[];
 extractions?: SessionTestExtraction[];
}

export interface SessionTestResponse {
 rule: string;
 rule_id: number;
 status: "valid" | "invalid" | "indeterminate";
 steps: SessionTestStep[];
}

/* --- scope ---------------------------------------------------------------- */

/**
 * /api/scope. The Go handler reports each rule's full tuple — host pattern plus optional port
 * and path arms — so removal can target one rule without touching a same-host sibling.
 */
export interface ScopeRuleView {
 kind: "Include" | "Exclude";
 host: string | null;
 path?: string | null;
 port?: number | null;
 protocol?: string | null;
 /**
  * A disabled rule is stored, shown and togglable, but takes no part in any scope decision.
  * Always on the wire — the toggle has to read the current state, and a field present only
  * when false would make "active" indistinguishable from "absent".
  */
 enabled: boolean;
}

export interface ScopeView {
 allow_all: boolean;
 rules: ScopeRuleView[];
 empty: boolean;
 /**
  * Burp's "Out-of-scope request handling: Drop all out-of-scope requests". On, every scope
  * refusal becomes an egress refusal: requests to hosts the scope excludes are not issued.
  * Always on the wire — the switch has to read the state it toggles.
  */
 drop_out_of_scope: boolean;
}

/** POST /api/scope. Port, path and protocol are optional arms on include/exclude, and part of a remove's identity. */
export interface ScopeUpdate {
 action: "include" | "exclude" | "remove" | "edit" | "clear" | "toggle" | "drop_out_of_scope";
 kind?: "include" | "exclude";
 pattern?: string;
 path?: string;
 port?: number;
 protocol?: "http" | "https";
 /**
  * Required on "toggle" (the switch's target state). On "include"/"exclude" omitted means
  * the default — a rule is created active unless a caller says otherwise.
  */
 enabled?: boolean;
 /** On "edit": the tuple being replaced, as the table showed it (k5l). The replacement arms ride
  *  the same fields above — the usual edit narrows the host, so the old tuple cannot ride on it. */
 old_pattern?: string;
 old_kind?: "include" | "exclude";
 old_path?: string;
 old_port?: number;
 old_protocol?: "http" | "https";
}

/* --- protocols / diagnostics ---------------------------------------------- */

export interface ProtocolAuthority {
 authority: string;
 state: string;
 negotiated?: string;
}

/** /api/protocols reports on this tool's own sends, not on proxied traffic. */
export interface ProtocolReport {
 enabled: boolean;
 hint?: string;
 summary?: string;
 sent_as_http2?: number;
 sent_as_http1?: number;
 downgrades?: Record<string, number>;
 rewrites?: number;
 discovery_handshakes?: number;
 cache_hits?: number;
 authorities?: ProtocolAuthority[];
}

/** POST /api/http2/program. `frames` may be empty, which makes it a preface-and-listen probe. */
export interface FrameProgramRequest {
 host: string;
 port: number;
 tls: boolean;
 preface: boolean;
 read_for_ms: number;
 frames: { type: number; flags: number; stream: number; payload_base64?: string; declared_len?: number }[];
}

export interface FrameView {
 type: string;
 flags: number;
 stream: number;
 len: number;
}

export interface FrameProgramResponse {
 verdict: string;
 refusals: string[];
 violations: string[];
 negotiated: string;
 read_ended: boolean;
 sent: { octets: number; base64: string };
 reply: { octets: number; base64: string; frames: FrameView[] };
 duration_ms: number;
 error?: string;
}

export interface EventHubStats {
 subscribers: number;
 window_ms: number;
 frames: number;
 changes: number;
 merges: number;
 fanout_running: boolean;
 pending: Record<string, number>;
}

/** GET/POST/DELETE /api/proxy/passthrough — the live TLS passthrough host-pattern list. */
export interface PassthroughView {
 patterns: string[];
}

/* --- upstream proxy servers and SOCKS (Unit 9) ---------------------------- */

/**
 * One upstream proxy rule. `proxy` is always the server's redacted rendering
 * (`socks5://***@host:1080` when credentials are set) — the API never serves a
 * password back, so there is nothing here to accidentally put on screen.
 */
export interface NetworkProxyRule {
 pattern: string;
 proxy: string;
 kind: string;
 has_credentials: boolean;
 /** A rule that exempts its pattern from a broader default. */
 direct: boolean;
}

export interface NetworkProxyView {
 /** False means no policy object is wired, so an edit would be consulted by nothing. */
 wired: boolean;
 rules: NetworkProxyRule[];
 default: string;
 default_kind: string;
 default_has_credentials: boolean;
 /** Distinguishes "nothing configured" from "rules that all resolve to direct". */
 empty: boolean;
 /** Egress surfaces holding this policy: "sender", "proxy", "web". */
 attached: string[];
 /** Whether edits survive a restart (false with no -db). */
 persisted: boolean;
 credentials_supported: boolean;
 /** Accepted URL schemes, named by the server's own parser. */
 schemes: string[];
}

/** POST body. `default` omitted leaves the default alone; "" or "direct" clears it. */
export interface NetworkProxyUpdate {
 pattern?: string;
 proxy?: string;
 default?: string;
}
