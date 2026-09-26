/**
 * Attack-area wire types (Intercept, Scanner) that are richer than the shared trimmed views in
 * `types.ts`, plus the shapes that have no shared equivalent at all. Kept in their own module so this
 * work does not collide with concurrent edits to the shared `types.ts`. Field names mirror the Go
 * json tags exactly.
 */

import type { Advisory, Occurrence } from "./types";

/* --- intercept ------------------------------------------------------------ */

/**
 * Full held-message row. The shared `HeldMessage` carries only what a minimal list needs; the Go
 * `heldView` (api_intercept.go) also sends the port, whether the connection was TLS, the response
 * status for a held response, how long it has been held and its byte length — every column an
 * operator triages the queue by.
 */
export interface HeldMessageDetail {
 id: number;
 direction: string;
 host: string;
 port: number;
 tls: boolean;
 method: string;
 path: string;
 status: number | null;
 held_ms: number;
 len: number;
 raw: string;
 /** The operator's annotation on the hold (burpsy-react-ui-5q8u); empty = none. */
 comment?: string;
 highlight?: string;
 /**
  * WebSocket frame type — "text", "binary", or a control opcode. Absent for HTTP, which has no
  * equivalent, so this is optional rather than an empty string: "not applicable" and "unknown" are
  * different, and only one of them should render a badge.
  */
 opcode?: string;
}

/**
 * Full intercept status. Adds the two flags that make "interception is on and nothing is held"
 * legible: they report whether a direction's rule list is unconditional, which is otherwise
 * indistinguishable from a proxy that has stopped working.
 */
export interface InterceptStateDetail {
 enabled: boolean;
 wired: boolean;
 hint?: string;
 pending: number;
 held: HeldMessageDetail[];
 holds_every_request?: boolean;
 holds_every_response?: boolean;
 /** Burp's "Only intercept in-scope messages". */
 in_scope_only: boolean;
 /**
  * Whether the engine has a scope to consult. False makes `in_scope_only` inert, and the page says
  * so rather than offering a toggle that changes nothing — the same reason `wired` sits beside
  * `enabled`.
  */
 scope_attached: boolean;
}

/** One condition in an interception rule list. Mirrors intercept.ts's RuleSpec / `interceptRuleSpec`. */
export interface InterceptRuleSpec {
 field: "host" | "path" | "extension" | "method" | "url" | "status_code" | "content_type";
 category: "regex" | "literal";
 string_match: string;
 enabled: boolean;
 comment: string;
 /**
  * What a match does: Burp's per-rule Do/Don't intercept (burpsy-react-ui-35i4).
  * Absent means hold — the wire omits it and the server defaults it — so every list
  * written before actions existed reads back unchanged.
  */
 action?: "hold" | "pass";
 /**
  * How THIS rule combines with the rules above it: Burp's boolean column
  * (settings/tools/proxy.html:246-268 — "Each rule is combined to the rules above in order,
  * using the selected boolean operator").
  *
  * Absent means "or", the wire omits it, and the server defaults it — which is also the behaviour
  * every list written before this column existed evaluates as, so adding it changes nothing until an
  * operator opts in (burpsy-react-ui-80tg). Without it a conjunction cannot be written at all:
  * "hold host A AND path /admin" would be two rules behaving as a disjunction.
  */
 op?: "and" | "or";
}

/** GET/PUT body for /api/intercept/rules/{requests|responses} — Go's `interceptListState`. */
export interface InterceptListState {
 wired: boolean;
 active: boolean;
 unconditional: boolean;
 count: number;
 rules: InterceptRuleSpec[];
}

/* --- scanner findings ----------------------------------------------------- */

/**
 * Full finding row. The shared `Finding` omits `id` — which is the only stable row identity the
 * endpoint offers — and types `detail`/`remediation` as present when Go sends `*string`, so a
 * finding recorded with neither reads as the literal string "null" unless they are nullable here.
 */
export interface FindingDetail {
 id: number;
 check_name?: string;
 issue_name?: string | null;
 severity: string;
 confidence: string;
 host: string;
 detail: string | null;
 remediation: string | null;
 /** The parameter this finding was observed at; absent for resource-level findings. */
 param?: string;
 /**
  * Every parameter this finding covers. Findings of one type against one target are merged into a
  * single row, so a reflected XSS reachable through five parameters is one finding with five
  * entries here rather than five rows. `param` remains the first one observed; without this field
  * the merge would hide the other four, which would make it a loss of information rather than a
  * tidier list. Absent for a resource-level finding and for legacy rows.
  */
 params?: string[];
 times_seen: number;
 /**
  * The dashboard task that raised this finding, absent when nothing tracked it (a manual
  * recording, a collaborator's result imported from elsewhere).
  *
  * It is what scopes a finding to a run, and the console needs it: a task's detail pane answers
  * "what did that scan find?", and a project-wide feed under a task's name attributes another
  * run's work to it (burpsy-react-ui-xwxd). Sent by the server as `task_id` and previously
  * dropped here, so the pane could not have asked even if it wanted to.
  */
 task_id?: number;
 /**
  * When the finding was FIRST raised, in Unix milliseconds. Set by FindingStore.Add and never
  * rewritten by a merge: a later sighting of the same issue is evidence about the issue, not a new
  * time of day, and moving the timestamp would make an old finding look continuously re-discovered.
  *
  * Zero means the store has no time for it — rendered as an em dash rather than as 1970, because a
  * plausible-looking date in a column an operator orders by is worse than an obvious gap.
  */
 timestamp_unix_ms?: number;
 /**
  * What raised this finding: "scan" when a run did (task_id names which), "manual" when nothing
  * tracked it — a recording an operator added, or a result imported from elsewhere.
  *
  * Deliberately only two values. Burp splits this further into BCheck / Scan check / Extension /
  * manually generated, and this does not pretend to: the finding does not record which, and guessing
  * from the check name would put an unverifiable claim in a column an operator filters on.
  */
 source?: "scan" | "manual";
 occurrences: Occurrence[];
 /** The catalogue entry this check resolved to, when it resolved to one. */
 advisory?: Advisory | null;
 /** Present instead when it deliberately resolved to none, explaining why. */
 advisory_note?: string;
 /**
  * Operator triage (burpsy-react-ui-pwd). `severity`/`confidence` above are the *effective*
  * values — the override when one stands, the engine's report otherwise — so every view that
  * sorts or counts by severity keeps working unchanged. The override itself and the engine value
  * it replaced are present only when an override stands, which is what lets the UI tell "the
  * engine said High" from "an operator said High".
  */
 severity_override?: string;
 original_severity?: string;
 confidence_override?: string;
 original_confidence?: string;
 /** Always present: the wire has no omitempty on either, so a legacy row reads as unmarked. */
 false_positive: boolean;
 comment: string;
}

export interface IssuesDetail {
 enabled: boolean;
 hint?: string;
 loaded?: number;
 findings: FindingDetail[];
 counts?: Record<string, number>;
}

/* --- scanner: audit configurations --------------------------------------- */

/**
 * One resolved audit configuration. `max_requests` is nullable rather than a plain number because
 * Go's OptUint32 keeps "uncapped" and "capped at zero" apart, and those are opposite instructions.
 */
export interface AuditConfigView {
 time_budget_ms: number;
 max_requests: number | null;
 consecutive_check_failures_to_abandon_unit: number;
 consecutive_unit_failures_to_fail_item: number;
 pause_session_after_failed_items: number;
 pause_session_at_failed_item_percentage: number;
}

/** One key a shipped Burp configuration can carry. `set` false is not `value` 0: unset inherits the
 * base configuration, zero disables a breaker, and both spellings appear in Burp's own files. */
export interface BuiltInConfigKey {
 name: string;
 burp_key: string;
 what: string;
 value?: number;
 set: boolean;
}

export interface BuiltInConfigView {
 name: string;
 /** Empty for a saved configuration: it is a resolved config, not an overlay of preset keys. */
 keys: BuiltInConfigKey[];
 resolved: AuditConfigView;
 /** True for the configurations burpsy ships, which are read-only. The operator's own saved ones
  *  are false, and only those can be renamed, overwritten or deleted. */
 shipped: boolean;
 /** A saved configuration whose stored document cannot be parsed. Listed so it does not vanish,
  *  but never offered for a run — an audit under "whatever the default is", named as the
  *  operator's configuration, is the outcome the library exists to prevent. */
 damaged?: boolean;
}

/** GET /api/scanner/configs — the scan configurations an audit can run under: the shipped presets
 * AND the operator's own saved ones (burpsy-react-ui-uxcs), in one array, each marked `shipped`.
 * POST/PUT/DELETE on the same route save, clone, rename and delete a saved one; a shipped name is
 * read-only and every write refuses it. */
export interface ScannerConfigsResponse {
 configs: BuiltInConfigView[];
 default: AuditConfigView;
 shipped_by_burp: number;
 implemented_here: number;
 omitted_reason: string;
 how_to_run_under: string;
 applies_to_server: string;
}

/* --- scanner: passive coverage ------------------------------------------- */

export interface CoverageCheckView {
 name: string;
 ran: number;
 findings: number;
 errored: number;
 last_error?: string;
 state: string;
}

export interface CoveragePartitionView {
 state: string;
 count: number;
}

/** GET /api/scanner/coverage. Everything past `enabled`/`hint` is absent when no BCheck corpus is
 * loaded, which is the gated case the page must render honestly rather than as zeroes. */
export interface ScannerCoverage {
 enabled: boolean;
 hint?: string;
 loaded?: number;
 summary?: string;
 checks?: CoverageCheckView[];
 skips?: number;
 partition?: CoveragePartitionView[];
}

/* --- scanner: live active audit ------------------------------------------ */

/**
 * GET/POST /api/scanner/live — the live active-audit sweep.
 *
 * `behind`, `collapsed` and `ledger_resets` are deliberately not optional, matching the Go struct's
 * lack of `omitempty` on them: a zero backlog is the single most useful thing this endpoint says
 * ("the sweep is caught up"), and making it omittable would render caught-up indistinguishable from
 * a server that never reported a backlog at all.
 */
export interface LiveAuditState {
 wired: boolean;
 enabled: boolean;
 hint?: string;
 swept?: number;
 findings?: number;
 /** Exchanges the sweep gave up waiting on. Carried beside `swept`, never added to it. */
 skipped?: number;
 behind: number;
 /** How long that backlog has existed, in milliseconds, 0 while the sweep is caught up. Behind
  * alone cannot tell a sweep twenty seconds behind a burst from one that has been behind since the
  * crawl started — the age is the difference. Not optional, matching the Go struct's lack of
  * `omitempty`: zero is "caught up", and an absent field would make that indistinguishable from a
  * server too old to report an age. */
 behind_for_ms: number;
 /** The admission bound the last tick ran with: the baseline while the sweep keeps up, larger while
  * it is catching up, 0 before any tick has run. Carried so a catch-up burst reads as a decision
  * rather than as an unexplained jump in `swept`. */
 batch_limit: number;
 collapsed: number;
 ledger_resets: number;
 query?: string;
 /** The exchange id the cursor is blocked on, absent while it is moving. */
 stalled_at?: number;
 /** Exchanges audited on their second chance (iyqg): skipped when their response was
  * late, taken back when it landed. Reported beside skipped — "gave up on 3" and
  * "gave up on 3, took 1 back" are different coverage claims. */
 retried: number;
 /** In-scope exchanges the source gate skipped (zk35): "in scope, but not the tool you chose". */
 refused_source: number;
 /** The source choice in force: "proxy" (default) or "everything". Always present. */
 traffic_source: string;
}

/* --- scanner: targeted audit result -------------------------------------- */

/**
 * POST /api/audit/{id}. The legacy `started`/`exchange_id` pair is kept by the server for
 * compatibility; `config_name` and `config` are what prove the run honoured the preset that was
 * asked for. `outcome`/`dispositions`/`breakdown` are scanner-internal and deliberately left
 * unknown — their shape is not stable enough to mirror field-by-field, so they are rendered through
 * JsonView rather than a bespoke layout that would silently drop keys.
 */
export interface AuditResult {
 started: boolean;
 exchange_id: number;
 active_checks: number;
 unimplemented: number;
 config_name: string;
 config: AuditConfigView;
 summary?: string;
 outcome?: unknown;
 dispositions?: unknown;
 breakdown?: unknown;
 error?: string;
}

/** One investigated finding in the LLM triage run's answer (ei0v). */
export interface LLMTriageRunRow {
 finding_id: number;
 name: string;
 verdict: string;
 model: string;
}

/** POST /api/issues/triage's answer: the honest counts the pass owes. */
export interface LLMTriageRun {
 investigated: LLMTriageRunRow[];
 investigated_count: number;
 outside_gate: number;
 errors: { finding_id: number; name: string; error: string }[];
}

/** The LLM second look's note on one finding (ei0v): advice, never promotion. */
export interface TriageNote {
 verdict: string;
 reasoning: string;
 model: string;
 investigated_at: string;
}

/** GET/PUT /api/settings/triage (ei0v). api_key is write-only: GET omits it and answers
 * configured instead. */
export interface TriageSettingsView {
 enabled: boolean;
 base_url: string;
 model: string;
 api_key?: string;
 configured: boolean;
}
