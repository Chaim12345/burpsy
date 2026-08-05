/** Intruder wire types. Mirrors internal/intruder + internal/web/api_tools.go json tags. */

export type AttackMode = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";

export const ATTACK_MODES: { value: AttackMode; label: string; detail: string }[] = [
  { value: "sniper", label: "Sniper", detail: "One payload set, each position attacked in turn." },
  { value: "battering_ram", label: "Battering ram", detail: "One payload set, the same payload in every position." },
  { value: "pitchfork", label: "Pitchfork", detail: "One set per position, advanced in lockstep." },
  { value: "cluster_bomb", label: "Cluster bomb", detail: "One set per position, every combination." },
];

/** Payload processing rules, applied in order before a payload is sent. */
export type PayloadRuleName =
  | "add_prefix"
  | "add_suffix"
  | "replace"
  | "uppercase"
  | "lowercase"
  | "encode"
  | "decode"
  | "hash"
  | "skip_if_matches";

export const PAYLOAD_RULES: { value: PayloadRuleName; label: string; uses: ("text" | "pattern" | "replace" | "all" | "layer" | "algorithm")[] }[] = [
  { value: "add_prefix", label: "Add prefix", uses: ["text"] },
  { value: "add_suffix", label: "Add suffix", uses: ["text"] },
  { value: "replace", label: "Match and replace", uses: ["pattern", "replace", "all"] },
  { value: "uppercase", label: "Uppercase", uses: [] },
  { value: "lowercase", label: "Lowercase", uses: [] },
  { value: "encode", label: "Encode", uses: ["layer"] },
  { value: "decode", label: "Decode", uses: ["layer"] },
  { value: "hash", label: "Hash", uses: ["algorithm"] },
  { value: "skip_if_matches", label: "Skip if it matches", uses: ["pattern"] },
];

export const PAYLOAD_LAYERS = ["url", "html", "base64", "base64url", "hex", "gzip", "deflate"] as const;
export const HASH_ALGORITHMS = ["md5", "sha256"] as const;

export interface PayloadRuleSpec {
  rule: PayloadRuleName;
  text: string;
  pattern: string;
  replace: string;
  all: boolean;
  layer: string;
  algorithm: string;
}

export function emptyRule(rule: PayloadRuleName): PayloadRuleSpec {
  return { rule, text: "", pattern: "", replace: "", all: false, layer: "url", algorithm: "sha256" };
}

export interface PointView {
  index: number;
  kind: string;
  label: string;
  offset: number;
  len: number;
  current: string;
}

export interface DropReason {
  reason: string;
  count: number;
}

/** Per-set accounting: what was produced, bounded, truncated and dropped. */
export interface PayloadSetReport {
  kind: string;
  count: number;
  total: number;
  total_exact: boolean;
  truncated: boolean;
  max_count: number;
  skipped: number;
  dropped: DropReason[];
}

export interface ResultBucket {
  status: number | null;
  response_len: number;
  reflected: boolean;
  count: number;
  first_ordinal: number;
  example_response_id: number | null;
  grep_matches: number;
  grep_extract: string | null;
}

export interface ErrorBucket {
  error: string;
  count: number;
  first_ordinal: number | null;
}

export interface Attempt {
  ordinal: number;
  status: number | null;
  response_len: number;
  duration_ms: number;
  reflected: boolean;
  response_id: number | null;
  error: string | null;
  grep_matched: boolean | null;
  grep_extract: string | null;
}

export interface AttackReport {
  kind: AttackMode;
  combinations: number;
  combinations_exact: boolean;
  max_requests: number;
  truncated: boolean;
  planned: number;
  sent: number;
  failed: number;
  elapsed_ms: number;
  buckets: ResultBucket[];
  buckets_truncated: boolean;
  unbucketed: number;
  errors: ErrorBucket[];
  attempts: Attempt[];
  detail_limit: number;
  grep_matched: number;
  pool: string | null;
  auto_throttle_engaged: number;
}

export interface BucketExample {
  first_ordinal: number;
  payloads: string[];
}

export interface RunView {
  report: AttackReport;
  examples: BucketExample[];
  payload_sets: PayloadSetReport[];
}

/**
 * How many requests a configuration implies. The server enforces max_requests,
 * but showing the estimate first is what stops an operator launching a
 * cluster-bomb attack that would have run for hours.
 */
export function estimateRequests(mode: AttackMode, pointCount: number, setSizes: number[]): { count: number; exact: boolean } {
  const sizes = setSizes.map((size) => Math.max(0, size));
  const first = sizes[0] ?? 0;
  switch (mode) {
    case "sniper":
      return { count: first * Math.max(1, pointCount), exact: true };
    case "battering_ram":
      return { count: first, exact: true };
    case "pitchfork":
      return { count: sizes.length ? Math.min(...sizes) : 0, exact: true };
    case "cluster_bomb": {
      let product = 1;
      for (const size of sizes) product *= size;
      return { count: sizes.length ? product : 0, exact: true };
    }
    default:
      return { count: 0, exact: false };
  }
}
