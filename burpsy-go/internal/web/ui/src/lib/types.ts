/** Wire types for the burpsy HTTP API. Field names mirror the Go json tags exactly. */

/**
 * The highlight vocabulary an operator can paint on a row — an Exchange (Task 5 / UX-15) or an
 * OrganizerItem (organizer.tsx). "none" is the absence of a highlight, and it is a UI-only sentinel:
 * the wire never carries the string "none", it carries "" (see `Exchange.highlight` below and Go's
 * `core.ValidHighlights`). Moved here from organizer.tsx so both pages read one copy — see
 * .superpowers/task-5-report.md.
 */
export const HIGHLIGHTS = ["none", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"];

/**
 * Tone to render each highlight as when it needs a `Badge` rather than a swatch (Organizer's table).
 * `gray` and `none` are deliberately unmapped — neither reads as a severity/status colour, so callers
 * fall back to `"neutral"`.
 */
export const HIGHLIGHT_TONE: Record<string, "neutral" | "bad" | "warn" | "good" | "info" | "accent"> = {
 red: "bad",
 orange: "warn",
 yellow: "warn",
 green: "good",
 cyan: "info",
 blue: "info",
 pink: "accent",
 magenta: "accent",
};

export interface ScannerConfig {
 max_concurrency: number;
 timeout_ms: number;
 probe_timeout_ms: number;
 check_sqli: boolean;
 check_xss: boolean;
 check_path_traversal: boolean;
 check_ssrf: boolean;
 check_xxe: boolean;
 check_jwt_weak: boolean;
 check_js_vulns: boolean;
 check_headers: boolean;
 check_cache_poisoning: boolean;
 check_corpus: boolean;
 check_dom: boolean;
 check_extended_coverage: boolean;
 check_reflection_probes: boolean;
 check_host_discovery: boolean;
 check_response_dependence: boolean;
 check_passive_posture: boolean;
 check_passive_analysis: boolean;
 check_active_injection: boolean;
 check_extended_active: boolean;
 check_out_of_band: boolean;
 check_stored: boolean;
}

export interface Stats {
 exchanges: number;
 messages: number;
 stored_bytes: number;
 proxy_bind?: string;
 web_bind?: string;
 tls_interception?: boolean;
 /** The -dom value ("chrome", a path, a ws:// endpoint) or "off". */
 dom_engine?: string;
 /** Whether the audit engine can dispatch the DOM-based checks at all. */
 dom_checks?: boolean;
}

/** GET /api/project — which project this instance is (burpsy-react-ui-je3y). The -db file IS the
 *  project: the name travels with the database, and a process started with no -db has none of it. */
export interface ProjectInfo {
 name: string;
 /** True when the name is the "Unnamed" placeholder rather than one the operator set. */
 unnamed: boolean;
 /** The -db path this project lives in. Empty when this instance persists nothing. */
 database?: string;
 /** Set only in the no-persistence case, so it cannot render as an empty path. */
 database_note?: string;
 persisted: boolean;
 backupable: boolean;
}

export interface ScopeRule {
 host?: string;
 port?: number;
 protocol?: string;
 path_prefix?: string;
 include?: boolean;
}

export interface Scope {
 allow_all: boolean;
 rules: ScopeRule[];
}

export interface Exchange {
 id: number;
 /**
  * The message-store id of this exchange's request, or null when it has none.
  *
  * Null and not 0, and the reason is that the store's ids are a dense counter from zero — so 0 is
  * the first request the project ever captured and is a perfectly real id. A blind CONNECT tunnel
  * has no request bytes, and reading its 0 as an id made the detail pane render the project's first
  * request under the label Request for a row that has none: another exchange's bytes presented as
  * this one's, with nothing marking it (burpsy-react-ui-wtov).
  *
  * `response` has always been nullable for the same reason, so this is one rule for both halves
  * rather than two.
  */
 request: number | null;
 response: number | null;
 host: string;
 port: number;
 method: string;
 path: string;
 status: number | null;
 response_len: number;
 /**
  * How many parameters this request carries, in Burp's sense: the query string's plus a form body's
  * (burpsy-react-ui-7py5). The server computes it at the capture seam, because a history row is an
  * index entry and carries no request body.
  *
  * EXACT for a urlencoded or multipart body and a LOWER BOUND otherwise: a body this cannot parse
  * is counted as one rather than zero, because reporting zero would tell an operator a request has
  * no parameters when nobody examined it. So 0 means "certainly no parameters" and -1 means "this
  * row predates the count" — the filter must keep both, and must not treat either as a clean answer.
  */
 request_params: number;
 started_ms: number;
 duration_ms: number;
 /**
  * Burp's "Start response timer" — request out to the FIRST response byte — against
  * `duration_ms`'s "End response timer" for the complete response (burpsy-react-ui-jcdm). The pair
  * tells a slow-to-respond origin apart from a slow-BODY one; one total reads the same for both.
  *
  * null when the producer never timed the first byte (Repeater, Intruder, the crawler, and rows
  * stored before the field existed). Rendered as an em dash, never as 0 — a 0 here would claim an
  * instantaneous first byte for every exchange nobody timed.
  */
 ttfb_ms: number | null;
 /** Whether the exchange was carried over TLS. This — not `protocol` — decides http vs https. */
 tls: boolean;
 /** The HTTP version the exchange used: "Http1" or "Http2". Never "http"/"https". */
 protocol: string;
 /**
  * The response's media type, parameters stripped and lowercased — `"text/html"` for a response
  * whose header read `Content-Type: text/HTML; charset=utf-8`. Always present on the wire
  * (`api_types.go`'s `exchangeView` populates it unconditionally), so not optional — same as
  * `highlight` below.
  *
  * `""` is two different facts and must not be rendered as one. Either no response arrived, or a
  * response arrived declaring no usable Content-Type. `response === null` is what separates them,
  * and every consumer here goes through `mimeLabel` in `history.tsx` rather than deciding again.
  *
  * It was declared here as `mime?: string` for some time while nothing on the wire set it, which is
  * how a MIME column that rendered empty for every row, and a type filter that emptied the table
  * for every value, both passed as shipped features.
  */
 mime: string;
 source?: string;
 notes?: string | null;
 related?: number[];
 /**
  * "" means no highlight. One of the colours in `HIGHLIGHTS` minus its `"none"` sentinel — see Go's
  * `core.ValidHighlights` (UX-15). Always present on the wire (api_types.go's `exchangeView`
  * populates it unconditionally), not optional.
  */
 highlight: string;
 /** Cookie names the response set, in first-seen order. Empty when none were set; `response`
     being null is what separates that from "no response yet". Always on the wire. */
 cookies: string[] | null;
 /** The response's HTML title text, "" when it has none. Always on the wire. */
 title: string;
 /**
  * The destination server's resolved IP, Burp's history "IP" column. `""` when nothing recorded
  * one — a producer with no socket in hand, or a row from an older server.
  *
  * Recorded at capture, never re-resolved: the socket is closed by the time a row is listed, and
  * asking DNS again would answer where the name points now. For a round-robin or a failover that
  * is a different address, presented as a fact about this exchange.
  */
 server_ip: string;
 /**
  * The proxy listener port the request arrived on, Burp's "Listener port" column. `0` for every
  * exchange that did not come from a listener — Repeater, Intruder, the crawler, the scanner.
  */
 listener_port: number;
 /**
  * Burp's three readings of a message, per direction (burpsy-react-ui-c05).
  *
  * A non-null id means "this reading exists *and* differs from the bytes that travelled"; null means
  * one of two things the server deliberately does not distinguish, because the distinction does not
  * change what the viewer should do: nothing was modified, or the reading would show the same bytes
  * as `edited`. Either way the pane shows the row's own `request`/`response` id.
  *
  * Resolved server-side rather than exposed as the four raw stage ids, so the walk from "which stage
  * was stored" to "which message holds this reading" lives in one place (`core.Exchange.VariantFor`)
  * instead of being reimplemented here. Getting that walk wrong does not crash — it shows the
  * client's bytes under an "Auto-modified" label, which is indistinguishable from a rule that
  * genuinely changed nothing.
  */
 variants?: {
  request_original: number | null;
  request_auto_modified: number | null;
  response_original: number | null;
  response_auto_modified: number | null;
  /**
   * Whether the operator modified either direction by hand in Intercept — the History "Edited"
   * column, and Burp's `ProxyHttpRequestResponse.edited()`.
   *
   * Deliberately *not* "this row's bytes differ from the peer's": burpsy rewrites traffic of its own
   * accord after the hold (it strips the Proxy-* header family, it can force `Connection: close`), so
   * the two questions have different answers on ordinary traffic, and reading this one as that one
   * marked rows nobody had touched (burpsy-react-ui-sd0d). A rule rewriting a message does not raise
   * this either — that is what the `auto_modified` readings above are for.
   */
  edited: boolean;
 };
}

export interface MessageView {
 text: string;
 truncated?: boolean;
 len?: number;
 hex?: string;
 /** The body's exact octets, base64 — present when the body is not valid UTF-8 and `text`
  *  cannot carry it (a JSON string would arrive with those bytes already destroyed). */
 body_base64?: string;
}

export interface CoverageBreakdown {
 found: number;
 skipped: number;
 errored: number;
 gated: number;
 unaccounted: number;
 complete: boolean;
}

export interface CoverageSummary {
 label: string;
 unit: string;
 work_unit: string;
 breakdown: CoverageBreakdown;
}

export interface TaskResult {
 summary: string;
}

export interface TaskRow {
 id: number;
 kind: string;
 target: string;
 state: string;
 done: number;
 total: number;
 fraction: number;
 fraction_known: boolean;
 cancellable: boolean;
 note?: string;
 progress: string;
 elapsed_ms: number;
 result: TaskResult;
}

export interface ActivityRow {
 tool: string;
 method: string;
 path: string;
 status: number | null;
 started_ms: number;
 host?: string;
 port?: number;
}

export interface ToolEvent {
 kind: string;
 severity: string;
 detail: string;
 at_ms: number;
}

export interface Dashboard {
 summaries: CoverageSummary[];
 tasks: TaskRow[];
 tasks_running: number;
 activity: ActivityRow[];
 events: ToolEvent[];
 /** The event log as a WINDOW, the way the server already accounts for it (burpsy-react-ui-voc):
  *  how many rows came back, how many the log holds, and how many it has thrown away since it
  *  filled. The page renders every row it is sent and states these numbers, rather than slicing the
  *  list to a literal — a client-side cap hides rows the server was willing to show and says
  *  nothing, which is the bug this replaced. */
 events_shown: number;
 events_total: number;
 events_dropped: number;
 exchanges: number;
 messages: number;
 sources: Record<string, number>;
 /** The suite-wide task pause (burpsy-react-ui-8gw): Burp's "Pause all tasks" gate. */
 paused: boolean;
}

export interface Occurrence {
 exchange_id: number;
 path: string;
}

/** A titled URL from the issue-definition catalogue: further reading, or a CWE/CAPEC entry. */
export interface AdvisoryLink {
 title: string;
 url: string;
}

/**
 * The catalogue entry a finding resolved to. Prose arrives pre-split into plain-text paragraphs
 * rather than as markup, so the console renders it without dangerouslySetInnerHTML — the catalogue
 * is trusted and server-sanitised, but "structurally impossible" beats "defensible" for XSS in the
 * operator's own console. The downloadable report keeps the full markup.
 */
export interface Advisory {
 type_index: string;
 name: string;
 typical_severity: string;
 description_paragraphs?: string[];
 remediation_paragraphs?: string[];
 references?: AdvisoryLink[];
 classifications?: AdvisoryLink[];
}

export interface Finding {
 check_name?: string;
 issue_name?: string | null;
 severity: string;
 confidence: string;
 host: string;
 detail: string;
 remediation: string;
 /** The parameter this finding was observed at; absent for resource-level findings. */
 param?: string;
 times_seen: number;
 occurrences: Occurrence[];
 /** Present when the check resolved to a catalogue entry. */
 advisory?: Advisory | null;
 /** Present instead when it deliberately resolved to none, explaining why. */
 advisory_note?: string;
 /**
  * The DOM dynamic tier's machine verdict (m97j): "promoted" — a browser watched the static
  * candidate's source actually feed a dangerous sink — "retired", "unavailable" or
  * "unsupported-source". Absent for every finding the tier never saw, which is every
  * finding that did not come from the static DOM pass.
  */
 confirm?: string;
}

export interface Issues {
 enabled: boolean;
 hint?: string;
 findings: Finding[];
 counts?: Record<string, number>;
}

export interface HeldMessage {
 id: number;
 direction: string;
 host: string;
 method: string;
 path: string;
 raw: string;
}

export interface InterceptState {
 enabled: boolean;
 wired: boolean;
 hint?: string;
 pending: number;
 held: HeldMessage[];
}

/**
 * Per-send config overrides — Burp Repeater's config-override menu, carried on the send payload.
 * Mirrors internal/web/repeaterSendOptions exactly; every field is optional and absent means
 * "the standing behaviour". Deliberately absent from this shape: an ALPN override and a
 * cookies-on-redirect switch — the backend refuses to offer switches that cannot be honest.
 */
export interface RepeaterSendOptions {
 redirect_mode?: "" | "never" | "on_site" | "in_scope" | "always";
 protocol_preference?: "" | "auto" | "http1" | "http2";
 process_cookies?: boolean;
 strip_connection?: boolean;
 normalize_line_endings?: boolean;
 update_content_length?: boolean;
}

export interface RepeaterResult {
 status: number;
 duration_ms: number;
 response: string;
 exchange_id: number;  /**
   * The redirect chain this send produced, present only when the response was a 30x.
   *
   * `response` above stays the response to the request the operator wrote, so this
   * reports the chain rather than substituting it — the Location and Set-Cookie on a
   * 30x are usually the thing being looked at. Absent means "not a redirect"; present
   * with every hop unfollowed means the policy or the scope stopped it, and `reason`
   * says which.
   */
 redirects?: RepeaterRedirects;
}

/**
 * One position in a Repeater tab's response history: a send's result *paired with the request
 * that produced it*.
 *
 * The pair is the point. Repeater's whole method is "change one thing and compare", and a history
 * entry that carried only the response left the operator reading entry 2 of 5 beside whatever the
 * request pane happened to hold — the current draft, which is not what entry 2 was sent with.
 *
 * `request` is the draft text as the operator wrote it, captured client-side at send time. It is
 * NOT declared on `RepeaterResult` because the server does not return it: /api/repeater/send
 * answers with the response side plus ids, and claiming otherwise on the wire type would be a
 * contract this UI invented. Nor is it the exact bytes that went out — per-send overrides such as
 * `normalize_line_endings` and `update_content_length` are applied server-side — so this is "as
 * written", which is what an operator comparing two variations is actually looking for.
 */
export interface RepeaterHistoryEntry extends RepeaterResult {
 request: string;
 /**
  * How this entry was sent, when it was not an ordinary single Send. Absent means the Send button.
  *
  * Carried because a history entry that rode a shared socket is not comparable to one that dialled
  * fresh — that difference is the whole subject of a smuggling or desync test — and an operator
  * paging back through five entries has no other way to tell which was which.
  */
 group_mode?: RepeaterGroupSendMode;
 /**
  * False when `duration_ms` is not a measurement. Only a single-connection group send sets it:
  * sender.SendKeepAlive owns the write/read loop and reports no per-exchange timing, so the panel
  * renders the batch time instead of a zero that looks measured. Absent means measured.
  */
 duration_measured?: boolean;
 /** The HTTP/1.1 rule that delimited this response's body, for a single-connection group send only. */
 framing?: string;
 /** False when the response was not read to a boundary the server is confident of. */
 response_complete?: boolean;
}

/** A "ws" tab's send history entry (burpsy-react-ui-6ex): a ws send has no status code and no
 *  response body — it has the handshake line, the reply frames, and how the conversation ended.
 *  Its own shape rather than RepeaterResult-with-optional-fields, because a status of 0 would be
 *  a fabricated measurement. The response pane dispatches on `ws` being present. */
export interface RepeaterWsHistoryEntry {
 request: string;
 ws: WsRepeaterSendResult;
}

/**
 * How a Repeater tab group is sent — Burp's dropdown beside Send, which appears only when the active
 * tab belongs to a group.
 *
 * `sequence_single_conn` is HTTP/1.1 keep-alive: every request in tab order down one socket, which is
 * the only way a request-smuggling or client-side-desync test can be performed from Repeater at all.
 * It is NOT HTTP/2 multiplexing (burpsy-react-ui-745), and it does not follow redirects — a hop is a
 * new request on a new connection, which is the one thing that mode cannot do.
 */
export type RepeaterGroupSendMode = "sequence_single_conn" | "sequence_separate_conn" | "parallel";

/** One tab's request within a group send. `tab_id` is echoed back on the result that answers it. */
export interface RepeaterGroupSendItem {
 tab_id: string;
 target: string;
 protocol: string;
 request: string;
 from_exchange?: number;
 options?: RepeaterSendOptions;
}

/**
 * One tab's outcome. `result` is the same shape a single send returns, so results render with the
 * code that already exists.
 *
 * `result` and `error` are not exclusive: a response whose head arrived and whose body then failed to
 * delimit is the evidence a smuggling test is reading, so the bytes are reported *and* the failure is
 * named. `result` is null only when nothing came back at all.
 */
export interface RepeaterGroupItemResult {
 tab_id: string;
 result?: RepeaterResult;
 error?: string;
 /** "content-length", "chunked", "eof" or "none" — single-connection mode only. */
 framing?: string;
 /** Absent for the separate-connection modes, where there is no second take to compare against. */
 response_complete?: boolean;
 /** False when `result.duration_ms` is not a measurement. See RepeaterHistoryEntry.duration_measured. */
 duration_measured: boolean;
 /** Parallel mode only: 1 for the response whose first byte was read first, next for the next.
 * Absent for the sequence modes and for items that never got a response — an item with no
 * arrival has no ordinal, and a missing field must not be read as "arrived first". */
 arrival?: number;
}

export interface RepeaterGroupSendResult {
 mode: RepeaterGroupSendMode;
 /** One result per request, in the order they were sent — tab order, never completion order. */
 items: RepeaterGroupItemResult[];
 /** The authority the one socket addressed. Present only for `sequence_single_conn`. */
 shared_connection?: string;
 /** Wall time of the whole group send. The only honest timing a single-connection send has. */
 batch_duration_ms: number;
 /**
  * Whether each send's redirect policy was applied at all. False for `sequence_single_conn`, so
  * "no chain" never renders as "we looked and found none".
  */
 followed_redirects: boolean;
}

export interface RepeaterRedirectHop {
 from: string;
 status: number;
 location: string;
 to?: string;
 followed: boolean;
 reason?: string;
 /**
  * The hop's request and response bytes, present only when the hop was followed —
  * a hop that was never sent has no bytes, and absence says exactly that.
  */
 request?: string;
 response?: string;
}

export interface RepeaterRedirects {
 mode: string;
 /** Every request this exchange put on the wire, the operator's own included. */
 sent: number;
 /** False when the chain was still redirecting when it stopped. */
 complete: boolean;
 hops: RepeaterRedirectHop[];
 final_status: number;
 /** Set when the chain could not be evaluated at all, so "did not look" never renders as "nothing to follow". */
 error?: string;
}

export interface InsertionPoint {
 index: number;
 kind: string;
 label: string;
 current: string;
}

export interface SequencerReport {
 tokens: number;
 grade: string;
 verdict: string;
 warnings: string[];
 encoding: string;
 bits?: { bit_entropy?: number;[key: string]: unknown };
 chars?: Record<string, unknown>;
}

export interface WsConnection {
 exchange: number;
 host: string;
 port: number;
 path: string;
 messages: number;
 sent: number;
 received: number;
 last_ms: number;
}

export interface WsRow {
 id: number;
 /** The exchange whose upgrade opened the connection this frame belongs to; the resend's target. */
 exchange: number;
 direction: string;
 opcode: string;
 len: number;
 at_ms: number;
 truncated: boolean;
 /** Burp's "Edited" fact for this frame: the operator's own hold changed it before it was relayed
  *  (burpsy-react-ui-d7bu). Non-optional because the Go handler always emits it — "edited":false is a
  *  stated fact, not an absent key, so an older client cannot mistake "not edited" for "unknown". */
 edited: boolean;
 /** The connection's absolute URL, read off the handshake exchange (burpsy-react-ui-sf8o). Empty on a
  *  frame whose handshake row is gone — an orphan frame is real and its address is not, and a guessed
  *  URL would be worse than a blank. */
 url?: string;
 /** The handshake's scheme: wss frames show as TLS the same way history rows do. */
 tls: boolean;
 /** The listener port the connection came in on — the fact that distinguishes two listeners on one
  *  machine, which is why it is a column rather than a detail. Zero when unknown. */
 listener_port?: number;
 /** Burp's "WebSocket ID": the connection's own id (burpsy's handshake exchange id), shared by every
  *  frame on one connection and different between two connections to the same URL. Carried beside
  *  `exchange` — same number, the name an operator migrating from Burp looks for on screen. */
 socket_id: number;
}

export interface WsRepeaterSendResult {
 /** The recorded handshake exchange, so the result can offer "view in WebSockets history". */
 exchange_id: number;
 /** The 101's status line. */
 handshake: string;
 /** What the target sent back, in order. `payload` is the frame's bytes as text. */
 messages: { opcode: string; payload: string; len: number }[];
 closed_by_peer?: boolean;
 close_code?: number;
 close_reason?: string;
 elapsed_ms: number;
}

export interface WsHistory {
 total: number;
 rows: WsRow[];
}

export interface WsMessage {
 text?: string;
 hex?: string;
 close?: { code: number; reason: string };
}

export interface SiteNode {
 path: string;
 exchanges: number;
 subtree_exchanges: number;
 methods: string[];
 statuses: number[];
 children: SiteNode[];
}

export interface SiteMap {
 exchanges: number;
 nodes: number;
 synced: number;
 in_flight: number;
 tree: SiteNode[];
}

export interface LogEntry {
 tool: string;
 host: string;
 port: number;
 method: string;
 path: string;
 status: number | null;
 error?: string;
 started_ms: number;
 duration_ms: number;
}

export interface ToolLog {
 total: number;
 shown: number;
 dropped: number;
 entries: LogEntry[];
}

/**
 * The user-applied workflow status of one saved exchange — Burp's organizer "Statuses"
 * (New / In progress / Postponed / Done / Ignored): "which saved requests still need attention and
 * which ones you have already tested". This is the operator's decision and must not be confused
 * with `OrganizerItem.status`, the HTTP response code the server recorded — the page shows both as
 * separate columns, which is exactly how they get mistaken for one field.
 */
export const WORKFLOW_STATUSES = ["new", "in_progress", "postponed", "done", "ignored"] as const;
export type WorkflowStatus = (typeof WORKFLOW_STATUSES)[number];

/** Tone to render each workflow status as; "new" is deliberately unmapped (falls back to neutral). */
export const WORKFLOW_STATUS_TONE: Record<WorkflowStatus, "neutral" | "bad" | "warn" | "good" | "info" | "accent"> = {
 new: "neutral",
 in_progress: "info",
 postponed: "warn",
 done: "good",
 ignored: "neutral",
};

/** The human label for a workflow status; the wire values are underscore-separated. */
export const WORKFLOW_STATUS_LABEL: Record<WorkflowStatus, string> = {
 new: "New",
 in_progress: "In progress",
 postponed: "Postponed",
 done: "Done",
 ignored: "Ignored",
};

/**
 * The editable half of an organizer item: what a save sends back.
 *
 * Split from OrganizerItem because the read shape now carries resolved fields — status, MIME, scope
 * — that the server derives and a client must never send. Typing the save payload as the read shape
 * made a write claim to carry a status, which is not the client's to state.
 */
export interface OrganizerEdit {
 id: number;
 title: string;
 note: string;
 highlight: string;
}

/** One named group of saved exchanges; an item not in any group is in the inbox (collection 0). */
export interface OrganizerCollection {
 id: number;
 name: string;
 note: string;
}

/**
 * A saved exchange, plus what the server resolved about it so the page can filter.
 *
 * The first five fields are the item as stored. Everything after `resolved` is a join against the
 * traffic store and the scope, done server-side because that is where both live — see
 * internal/web/api_organizer_view.go.
 *
 * # `resolved` is the field to read first
 *
 * The organizer outlives the traffic store: an exchange saved a thousand requests ago can be
 * evicted while the note about it survives, which is much of the point of keeping notes. Such a row
 * has no status, no MIME and no scope answer, and every optional field below is absent rather than
 * zero — `status: 0`, `mime: ""` and `in_scope: false` are all *answers*, and this row has none to
 * give. A filter must therefore let unresolved rows through rather than judge them, or it hides a
 * note the operator wrote at exactly the moment they are looking for it.
 */
export interface OrganizerItem extends OrganizerEdit {
 exchange: number;

 /**
  * The workflow status the operator applied — a different axis from `status` below, which is the
  * HTTP response code. Absent means the item predates the field and reads as "new".
  */
 workflow_status?: WorkflowStatus;

 /** The collection this item sits in; 0 (or absent) means the inbox. */
 collection?: number;

 /** False when the exchange is no longer in the traffic store; every field below is then absent. */
 resolved: boolean;
 host?: string;
 port?: number;
 method?: string;
 path?: string;
 /** Absent when the exchange has no response. A request that never came back is not a status of 0. */
 status?: number;
 /**
  * Whether a response was recorded at all. This is what makes an empty `mime` readable: without it,
  * "no response yet" and "a response that named no usable Content-Type" are the same empty string.
  */
 has_response: boolean;
 /** Response media type, parameters stripped and lowercased ("text/html"). */
 mime?: string;
 /**
  * The Burp tool that originally generated the request — "proxy", "repeater", "intruder",
  * "scanner", "crawl", or "unattributed" for traffic nothing claimed (burpsy-react-ui-ldfk). Read
  * off `core.Exchange.Source`, set once at capture and never rewritten, so a note saved from
  * Logger still names the tool that actually sent the request rather than "logger" or "organizer".
  * Absent exactly when `resolved` is false.
  */
 tool?: string;
 /** Absent exactly when `resolved` is false — see the note above on why this is not a plain bool. */
 in_scope?: boolean;

 /**
  * Message-store ids for the saved exchange's request and response — the same shape History's
  * `Exchange.request`/`.response` already use, so the page reads them with the existing
  * `useMessage` hook rather than a second fetch path (burpsy-react-ui-i3l). Both absent exactly
  * when `resolved` is false: there is no message store id to read when the exchange is gone.
  * `response` is additionally absent when the exchange has no response yet (`has_response` false),
  * matching `Exchange.response`'s own null-means-none convention.
  */
 request?: number;
 response?: number;
}

export interface TrafficRule {
 rule_type: string;
 enabled: boolean;
 string_match: string;
 string_replace: string;
 category: string;
 comment?: string;
}

export interface MatchReplaceConfig {
 rules: TrafficRule[];
 update_content_length: boolean;
 /**
  * Burp's "Only apply to in-scope items": when on, a message whose target the scope
  * excludes is not rewritten. Named after the checkbox rather than the config key it is
  * persisted under (`proxy.match_replace_disable_out_of_scope`), which reads as its
  * opposite.
  */
 in_scope_only: boolean;
}

export interface MatchReplaceResponse {
 affects_requests: boolean;
 affects_responses: boolean;
 /**
  * Messages the rules declined to rewrite because they were out of scope — the live count,
  * since the last restart. Zero with the restriction off and zero with it on and nothing
  * excluded, which is why the page only reports it alongside the switch's state rather
  * than on its own.
  */
 scope_skipped: number;
 config: MatchReplaceConfig;
}

export interface SessionStep {
 method?: string;
 url?: string;
 headers?: string[][];
 body?: string;
}

export interface SessionRule {
 id?: number;
 name?: string;
 enabled: boolean;
 method?: string;
 url?: string;
 headers?: string[][];
 body?: string;
 steps?: SessionStep[];
}

export interface SessionRules {
 wired: boolean;
 rules: SessionRule[];
 hint?: string;
}

export interface ToolOutput {
 text: string;
 [key: string]: unknown;
}
