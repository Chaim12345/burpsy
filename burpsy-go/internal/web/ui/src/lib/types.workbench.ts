/**
 * Wire types for the Workbench tools (Decoder, Comparer, Sequencer, Tool log).
 * Field names mirror the Go json tags exactly — see internal/web/api_toolkit.go,
 * internal/web/api_tools.go and internal/sequencer/{report,fips}.go.
 */

/** The server's rendering of a byte string. `text` is lossy when `utf8` is false. */
export interface BytesView {
 text: string;
 len: number;
 utf8: boolean;
 truncated: boolean;
}

/* --- decoder / encoder / hash -------------------------------------------- */

/**
 * POST /api/tools/decode.
 *
 * The Go handler answers `mode: "explicit"` on both paths — including the
 * smart-detect path — so `layers` is the only record of what it actually
 * unwrapped. It is null when nothing decoded.
 */
export interface DecodeResponse {
 mode: string;
 layers: string[] | null;
 /** True when a compressed stream only partly decompressed: the output is a
  * prefix of the plaintext, so searching it can mislead. */
 partial?: boolean;
 output: BytesView;
}

export interface EncodeResponse {
 encoding: string;
 output: BytesView;
}

/** Digest is hex, so `output.len` is twice the digest size in bytes. */
export interface HashResponse {
 algorithm: string;
 output: BytesView;
}

/* --- transform pipeline (client-side composition of the three endpoints) -- */

export type TransformKind = "decode" | "encode" | "hash";

export interface TransformStep {
 /** Stable id: steps are reordered and removed, so an index is not a key. */
 id: string;
 kind: TransformKind;
 /** An encoding name, or a hash algorithm when `kind` is "hash". */
 value: string;
 /** Only meaningful for a smart decode; sent as `guess_alphabets`. */
 guess: boolean;
}

export interface TransformResult {
 stepId: string;
 kind: TransformKind;
 value: string;
 output: string;
 len: number;
 utf8: boolean;
 truncated: boolean;
 /** What a decode actually unwrapped. Null for encode and hash. */
 layers: string[] | null;
 /** Set when a compressed layer decompressed only partly. */
 partial?: boolean;
}

export interface TransformRun {
 results: TransformResult[];
 /** Index of the step that failed, or null when every step ran. */
 failedAt: number | null;
 message: string | null;
}

/* --- comparer ------------------------------------------------------------- */

/**
 * One aligned run from POST /api/tools/compare. Offsets are **byte** offsets, so
 * slicing them against a JS string needs a TextEncoder round trip.
 *
 * `text` carries the A-side bytes for "replace" and "delete" and the B-side
 * bytes for "insert"; "equal" carries none and must be sliced from the input.
 */
export interface CompareOp {
 kind: string;
 a_offset: number;
 a_len: number;
 b_offset: number;
 b_len: number;
 text?: string;
 /**
  * The difference lies entirely inside a header the operator asked burpsy to discount — W6
  * #81/#82. The op is still returned with its real offsets and text; the console dims it and
  * counts it rather than dropping it, because the bytes really do differ.
  */
 uninteresting?: boolean;
}

export interface CompareResponse {
 identical: boolean;
 /**
  * Every difference was inside a discounted header. Deliberately separate from `identical`,
  * which stays false — these messages are not identical, and conflating the two would tell the
  * operator the bytes matched when they did not.
  */
 identical_ignoring_uninteresting: boolean;
 /** How many ops were discounted, so a dimmed diff can say why it looks empty. */
 uninteresting_ops: number;
 /** The list actually applied, so the panel and the result cannot disagree about what was used. */
 uninteresting_headers_applied: string[];
 /** Counts trailing-only runs: a "replace" is in neither total. */
 deleted_tokens: number;
 inserted_tokens: number;
 truncated: boolean;
 ops_omitted: number;
 ops: CompareOp[];
}

/** Which discount list applies, and the surfaces that consult them. */
export interface UninterestingHeaders {
 request: string[];
 response: string[];
 default_response: string[];
 applies_to: string[];
}

/* --- sequencer ------------------------------------------------------------ */

export interface CharCount {
 label: string;
 byte: number;
 count: number;
 fraction: number;
}

export interface PositionStats {
 index: number;
 samples: number;
 distinct: number;
 entropy_bits: number;
 counts: CharCount[];
}

export interface CharacterAnalysis {
 tokens: number;
 min_len: number;
 max_len: number;
 alphabet_size: number;
 alphabet: string[];
 positions: PositionStats[];
 positions_truncated: boolean;
 entropy_bits_per_char: number;
 /** Sum of the per-position figures, which assumes positional independence. */
 total_entropy_bits: number;
 assumes_positional_independence: boolean;
 /** log2(tokens): what one position can show at this sample size, at best. */
 entropy_ceiling_bits: number;
 max_possible_bits: number;
}

export interface BitStats {
 bits: number;
 ones: number;
 zeros: number;
 bit_entropy: number;
 longest_run: number;
 runs_zeros: number[];
 runs_ones: number[];
}

export interface FipsTest {
 id: string;
 name: string;
 spec: string;
 requirement: string;
 passed: boolean;
 blocks_passed: number;
 blocks_failed: number;
 observed: string;
}

export interface FipsReport {
 bits_supplied: number;
 bits_tested: number;
 bits_untested: number;
 blocks_tested: number;
 block_bits: number;
 /** Null when not one whole block was supplied: no verdict beats a wrong one. */
 tests: FipsTest[] | null;
}

/** The full report from POST /api/sequencer/analyse. */
export interface SequencerAnalysis {
 tokens: number;
 encoding: "raw" | "hex" | "base64";
 encoding_detected: boolean;
 characters: CharacterAnalysis;
 /** The CLI's uniformity/duplicate group, now on the web report too (burpsy-react-ui-3sq). */
 extra_stats: {
  chi_square: number;
  serial_correlation: number;
  serial_correlation_label: string;
  monte_carlo_pi: number;
  monte_carlo_deviation: number;
  repeated_tokens: number;
  repeated_list?: string[];
 };
 bits: BitStats;
 fips: FipsReport;
 grade: "insufficient" | "pass" | "fail";
 verdict: string;
 warnings: string[] | null;
}

/** Where in a response the token lives. The operator declares it; the server never guesses. */
export type TokenLocationKind = "cookie" | "header" | "form_field" | "body_regex";

export interface TokenLocation {
 kind: TokenLocationKind;
 /** The cookie, header or form-field name, for those three kinds. Matched case-insensitively. */
 name?: string;
 /** An RE2 pattern for body_regex. Capture group 1 is the token when the pattern has one. */
 pattern?: string;
}

/** One response that carried no token at the declared location, with why. */
export interface CaptureMiss {
 attempt: number;
 reason: string;
}

/**
 * GET /api/sequencer/capture/{id}, and the reply to starting one.
 *
 * `requested` against `total` is the point of this shape: "40 tokens" alone cannot say whether the
 * sample is 40 of 40 or 40 of 200, and an entropy verdict over the two is not the same claim. Before
 * the capture loop existed this endpoint answered `{total: 0, tokens: []}` for everything, which
 * read as "this application's tokens could not be analysed" when nothing had ever been sent.
 */
export interface SequencerCapture {
 id: number;
 task_id: number;
 target: string;
 /** The token location, as one line — "cookie SESSIONID", "body /csrf=([a-f0-9]+)/". */
 location: string;
 capturing: boolean;
 /** Only meaningful while capturing: a finished capture is not paused, whatever the wire says. */
 paused: boolean;
 requested: number;
 /** Requests sent, as distinct from tokens collected. */
 attempts: number;
 total: number;
 tokens: string[] | null;
 /** Responses that carried no token. Non-zero is the difference between a sparse token and a
  *  misspelled location, and `miss_examples` is what tells those apart. */
 misses: number;
 miss_examples?: CaptureMiss[];
 misses_truncated: boolean;
 started_ms: number;
 ended_ms?: number;
 /** Why a short capture is short: stopped by the operator, or gave up on the location. */
 stop_reason?: string;
}

/** POST /api/sequencer/capture/stop. Honest about whether there was anything to stop. */
export interface StopCaptureResult {
 stopped: boolean;
 signalled: number;
 captures: SequencerCapture[];
 note: string;
}

/* --- tool log ------------------------------------------------------------- */

/**
 * One logged request. Wider than the shared `LogEntry` in types.ts, which omits
 * `id` and `response_len` even though the handler sends both.
 */
export interface ToolLogRow {
 id: number;
 tool: string;
 host: string;
 port: number;
 method: string;
 path: string;
 status: number | null;
 /**
  * How many response bytes came back, or null when no response was received —
  * a send that failed at the transport, or a row standing for a whole run
  * rather than one exchange. Nullable for the same reason `status` is, and it
  * has to be rendered as "no response", never as 0: the server used to send a
  * hardcoded 0 on every row, which made the Length column read as though every
  * response had been empty.
  */
 response_len: number | null;
 started_ms: number;
 duration_ms: number;
 error: string | null;
 /**
  * The traffic-store exchange this row's request/response bytes live under, or null when the row
  * has none to show: a send that failed at the transport received nothing to store, and a row
  * standing for a whole run (an audit) is not one exchange. Rows recorded before the link existed
  * are null too — they stay metadata-only rather than pretending. The detail pane resolves bytes
  * through this id on demand; the log never stores a second copy.
  */
 exchange: number | null;
 /** The operator's annotation, "" when unset. Distinct from error (the producer's note). */
 comment: string;
 /** The operator's colour tag, "" when unset. Same vocabulary as Organizer's and history's. */
 highlight: string;
}

export interface ToolLogView {
 /** How many matched the filter — not how many came back; that is `shown`. */
 total: number;
 shown: number;
 /** Entries the ring buffer discarded at capacity. Never silently hidden. */
 dropped: number;
 /** Per-tool histogram over every match, seeded with every known tool. */
 counts: Record<string, number>;
 /**
  * The capture axis: which tools are being recorded at all, distinct from the
  * display axis. A tool missing (false) has its requests sent and deliberately
  * not kept — see `uncaptured`. Not to be collapsed into `counts`: capture is
  * destructive, display is not.
  */
 capturing: Record<string, boolean>;
 /** Per-tool count of requests capture refused. Only ever moves forward. */
 uncaptured: Record<string, number>;
 /** Sum of `uncaptured`, so the count line can say the whole loss at once. */
 uncaptured_total: number;
 /** What the capture filter refused. Beside dropped, never merged into it. */
 filtered_total: number;
 /** The memory bound in rows. */
 capacity: number;
 /** Whether ScopeOnly can filter: without a scope it is inert. */
 scope_attached: boolean;
 /** The capture filter in force, echoed so the page renders what the server enforces. */
 filter: { status: number[]; term: string; regex: boolean; case_sensitive: boolean; negate: boolean; scope_only: boolean };
 entries: ToolLogRow[];
}
