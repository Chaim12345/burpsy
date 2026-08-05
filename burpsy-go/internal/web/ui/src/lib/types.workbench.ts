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
}

export interface CompareResponse {
  identical: boolean;
  /** Counts trailing-only runs: a "replace" is in neither total. */
  deleted_tokens: number;
  inserted_tokens: number;
  truncated: boolean;
  ops_omitted: number;
  ops: CompareOp[];
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
  bits: BitStats;
  fips: FipsReport;
  grade: "insufficient" | "pass" | "fail";
  verdict: string;
  warnings: string[] | null;
}

/**
 * GET /api/sequencer/capture/{id}. The Go port answers the shared capture
 * accumulator, which is empty until a capture loop exists to fill it.
 */
export interface SequencerCapture {
  total: number;
  tokens: string[] | null;
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
  response_len: number;
  started_ms: number;
  duration_ms: number;
  error: string | null;
}

export interface ToolLogView {
  /** How many matched the filter — not how many came back; that is `shown`. */
  total: number;
  shown: number;
  /** Entries the ring buffer discarded at capacity. Never silently hidden. */
  dropped: number;
  /** Per-tool histogram over every match, seeded with every known tool. */
  counts: Record<string, number>;
  entries: ToolLogRow[];
}
