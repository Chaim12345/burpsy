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
 /**
  * The rule's ordered action list (burpsy-react-ui-ayi) — Burp's rule shape, and what the executor
  * actually runs.
  *
  * Served as the *effective* list, never as a bare stored one: a rule written before actions
  * existed (or whose row predates the column) behaves as the synthesis "check validity, and if not
  * valid run the macro", and the server sends that list rather than an empty table. So this is
  * never empty, and an empty array in an editor means the client invented one — sending it back is
  * refused, because a rule with no actions does nothing and the server would otherwise silently
  * restore the login flow.
  */
 actions: SessionAction[];
}

/**
 * One rule action. Recursive only where Burp recurses: a CheckValidity action's `then`/`else` are
 * lists of the same shape, and its executor is the only kind that reads them.
 */
export interface SessionAction {
 /** One of `action_kinds[].kind` from the same response. */
 kind: string;
 /**
  * Burp's own words for the action, served by the server rather than spelled here. A copy in this
  * file would be a second vocabulary, and the failure it produces is silent: an editor that offers
  * a kind the API refuses, or spells one it does not accept.
  */
 label: string;
 /** Burp's per-action checkbox. A disabled action is skipped and the list continues. */
 enabled: boolean;
 /** Burp's "no further actions should be applied to the request". */
 stop?: boolean;
 /** A RunMacro action's own steps. Absent means the rule's own `steps`, not a copy of them. */
 macro?: SessionMacroStep[];
 then?: SessionAction[];
 else?: SessionAction[];
 /** SetCookie's cookie name / SetParam's parameter name / SetHeader's header name. */
 name?: string;
 /** A value that may carry {{name}} placeholders a macro action extracted earlier in the list. */
 value?: string;
 /** SetParam's target: absent (wherever it already is, else the query), "query" or "body". */
 in?: string;
 match?: string;
 replacement?: string;
 regex?: boolean;
 /** InvokeExtension's target: a plugin registration id, which the server resolves to a plugin. */
 extension?: string;
 /** A run_script action's JavaScript (burpsy-react-ui-ydmj). Compiled when the rule is saved. */
 script?: string;
 /**
  * Burp's `validate_every_num_requests` (us12): a CheckValidity action that checks the session
  * only on every Nth request the rule handles. Absent/0 is check every time, which is the
  * pre-field behaviour and what every rule written before it means.
  */
 validate_every?: number;
}

/** One entry of the action palette, served so the editor cannot drift from what the server accepts. */
export interface SessionActionKind {
 kind: string;
 label: string;
}
export interface SessionRulesResponse {
 wired: boolean;
 rules: SessionRuleFull[];
 hint?: string;
 /**
  * Every tool name a rule's tools scope may name (so3), served by the API so this checklist
  * cannot drift from what the server enforces. Always present: the server sends it even when
  * the rules list is empty.
  */
 tools: string[];
 /** The action palette, from the same source. Always present, same reason. */
 action_kinds: SessionActionKind[];
}

export interface SessionCookiePair {
 name: string;
 value: string;
 /** The cookie's own Path attribute. Absent means "/" — the jar's default-path. */
 path?: string;
 /** The cookie's own Domain attribute (empty = host-only), not the jar's authority. */
 domain?: string;
 /** Zero/absent for a session cookie; a Max-Age/Expires in the past is a deletion. */
 expires?: string;
 secure?: boolean;
 http_only?: boolean;
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
 /** The surfaces registered as feeding the jar (loa1's read-side honesty). */
 absorbing_from?: string[];
 /** The monitored-tool set in force (sn3j): which surfaces may absorb. Absent = every
  * attached surface (the default). */
 monitored?: string[];
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

/** One parameter relationship the macro analyzer found (e23c) — Burp's "identifying
 * parameters whose values can be determined from the preceding response". The fields mirror
 * the Go session.ExtractionSuggestion exactly; the server computes them, the UI only shows them. */
export interface ExtractionSuggestion {
 name: string;
 from: "body" | "header";
 header?: string;
 pattern: string;
 group: number;
 step: number;
 source: string;
 /** What the dry-run's response actually carried — shown so the operator can see the
  * relationship is real before applying it. */
 value: string;
}

/** POST /api/session/rules/{id}/analyze — Re-analyze (e23c). Read-only. */
export interface SessionAnalyzeResponse {
 rule_id: number;
 suggestions: ExtractionSuggestion[];
 found: number;
}

/** POST /api/session/rules/{id}/apply-extractions — the apply half of Re-analyze (e23c). */
export interface SessionApplyExtractionsResponse {
 rule_id: number;
 applied: string[];
 rule: SessionRuleFull;
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
 /**
  * The global SOCKS layer: a TCP hop EVERY outbound connection is opened through, beneath whichever
  * proxy a rule selected. Reported apart from `rules` because it answers a different question —
  * "which proxy carries this host" versus "what opens the socket to reach that proxy" — and showing
  * one without the other is how an operator concludes the other is covered (burpsy-react-ui-mr83
  * part 3).
  */
 carrier: NetworkCarrierView;
}

/** The global SOCKS layer as the panel sees it. */
export interface NetworkCarrierView {
 /** False when no hop is installed, which is every surface's state until an operator names one. */
 configured: boolean;
 /** The hop's redacted address, read from the live carrier rather than the settings document. */
 socks: string;
 /**
  * Destination host patterns that skip the hop, in the same language a rule uses.
  *
  * `null` when the hop has no bypass list: the server marshals a nil Go slice as null, and this is
  * read from the live carrier rather than from a synthesised settings document. Declared `| null`
  * because the panel crashed on exactly that (burpsy-react-ui-2qbi) — the type claimed an array, so
  * the `.join` on it was written unguarded and killed the whole Settings page behind the boundary.
  */
 bypass: string[] | null;
 /**
  * Ask the SOCKS server to resolve destination names, which is what makes an internal-only hostname
  * reachable through it. A SOCKS feature: the server refuses it for an HTTP hop rather than
  * ignoring it, because a switch that silently does nothing is worse than one that refuses.
  */
 remote_resolve: boolean;
 /** Egress surfaces holding this carrier, so the panel never implies coverage it cannot see. */
 attached: string[];
 /**
  * What the carrier does NOT cover, in the operator's terms. Reported by the server because the
  * limitation is a property of the dial path, not of the settings document: a panel that showed the
  * layer as configured without saying what it skips would be the same overclaim in a different place
  * (burpsy-react-ui-mr83 part 3).
  *
  * `null` for the same reason as `bypass`: a nil Go slice marshals as null, and this one is mapped
  * in the panel, so an unguarded `.map` on it would throw the same way.
  */
 limits: string[] | null;
}

/** POST body. `default` omitted leaves the default alone; "" or "direct" clears it. */
export interface NetworkProxyUpdate {
 pattern?: string;
 proxy?: string;
 default?: string;
 /**
  * The carrier is edited by the same POST as the rules but is a different LAYER, so the panel sends
  * it alone when only the layer changed. Sending it alongside a rule would apply the layer and then
  * possibly fail the rule, leaving a half-applied edit that looks saved.
  */
 carrier?: {
  /** Empty CLEARS the carrier, which is an operator removing the setting. */
  socks: string;
  bypass: string[];
  remote_resolve: boolean;
 };
}

/** One session-handling tracer entry (n29): a request a rule applied to, and what the
 * coordinator did about it. Mirrors session.TraceEntry. */
export interface SessionTraceEntry {
 at: string;
 tool?: string;
 host: string;
 path: string;
 rule: string;
 rule_id: number;
 kind: string;
 actions?: { index: number; kind: string; label: string; detail: string; changed: boolean; skipped?: string }[];
}

/** GET /api/session/trace. */
export interface SessionTraceResponse {
 enabled: boolean;
 entries: SessionTraceEntry[];
 capacity: number;
}

/** POST /api/session/trace/enable. */
export interface SessionTraceEnableResponse {
 enabled: boolean;
}

/* --- browser-recovery prompts (dq1g, landed by bkun) --------------------------------- */

/**
 * One pending browser-recovery prompt, mirroring the server's sessionPromptDto exactly. The task
 * that hit the "prompt for browser recovery" action is suspended server-side until an operator
 * answers, and this row is the operator-facing half of that wait.
 *
 * `id` is the number the resolve route takes, not a list index: the modal shows the oldest prompt
 * (prompts[0]) and resolves by id, so a second prompt appearing mid-answer cannot make the modal
 * resolve the wrong one.
 */
export interface SessionPromptView {
 id: number;
 rule_name: string;
 request_url: string;
 /** RFC 3339, as encoding/json writes time.Time. */
 created_at: string;
}

/** GET /api/session/prompts — the pending list, oldest first. */
export interface SessionPromptsResponse {
 prompts: SessionPromptView[];
}

/**
 * POST /api/session/prompts/{id}/resolve. `recovered` is the operator's whole answer: true means
 * the task resumes and the request goes out with the session the browser established; false means
 * the request is not sent, and the rule's trace records a decline rather than a session that was
 * never established.
 */
export interface SessionPromptResolveRequest {
 recovered: boolean;
}

/** The resolve route's confirmation: what the server did, not an echo of the request. */
export interface SessionPromptResolveResponse {
 resolved: boolean;
 recovered: boolean;
}
