/**
 * Wire types for the policy surfaces (match/replace, session, organizer, settings).
 * Field names mirror the Go json tags exactly; see internal/web/api_toolkit.go,
 * api_session.go, api_capture.go, api_protocol.go and events.go.
 */

/* --- match & replace ------------------------------------------------------- */

/** The five targets targetToCategory() in api_toolkit.go accepts. Anything else compiles to a no-op. */
export type MatchReplaceTarget =
  | "request_first_line"
  | "request_header"
  | "request_body"
  | "response_header"
  | "response_body";

/** matchReplaceCategoryName(): the server knows exactly these two. */
export type MatchReplaceCategory = "literal" | "regex";

export type MatchReplaceDirection = "request" | "response";

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
 * One rule as the wire carries it. `scope` and `query` are accepted by the Go decoder
 * but dropped by matchReplacePut, so a rule that arrives with either keeps it only
 * until the next save — surfaced read-only rather than silently round-tripped.
 */
export interface MatchReplaceRuleSpec {
  rule_type: MatchReplaceTarget;
  enabled: boolean;
  string_match: string;
  string_replace: string;
  category: MatchReplaceCategory;
  comment: string;
  scope?: unknown;
  query?: string;
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
  all?: SessionValidity[];
  any?: SessionValidity[];
  not?: SessionValidity;
}

/** The scope document a session rule carries. Only `host` is read server-side. */
export interface SessionScopeRule {
  kind: "Include" | "Exclude";
  host: string | null;
}

export interface SessionScope {
  allow_all: boolean;
  rules: SessionScopeRule[];
}

export interface SessionRuleFull {
  id?: number;
  name: string;
  enabled: boolean;
  /** Omitted means "applies everywhere"; a stated but empty scope is refused. */
  scope?: SessionScope;
  steps: SessionMacroStep[];
  validity: SessionValidity;
  max_attempts?: number;
}

export interface SessionRulesResponse {
  wired: boolean;
  rules: SessionRuleFull[];
  hint?: string;
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
}

export interface ScopeView {
  allow_all: boolean;
  rules: ScopeRuleView[];
  empty: boolean;
}

/** POST /api/scope. Port, path and protocol are optional arms on include/exclude, and part of a remove's identity. */
export interface ScopeUpdate {
  action: "include" | "exclude" | "remove" | "clear";
  kind?: "include" | "exclude";
  pattern?: string;
  path?: string;
  port?: number;
  protocol?: "http" | "https";
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
