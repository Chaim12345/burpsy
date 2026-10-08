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
  | "skip_if_matches"
  | "normalize";

export const PAYLOAD_RULES: { value: PayloadRuleName; label: string; uses: ("text" | "pattern" | "replace" | "all" | "layer" | "algorithm" | "form")[] }[] = [
  { value: "add_prefix", label: "Add prefix", uses: ["text"] },
  { value: "add_suffix", label: "Add suffix", uses: ["text"] },
  { value: "replace", label: "Match and replace", uses: ["pattern", "replace", "all"] },
  { value: "uppercase", label: "Uppercase", uses: [] },
  { value: "lowercase", label: "Lowercase", uses: [] },
  { value: "encode", label: "Encode", uses: ["layer"] },
  { value: "decode", label: "Decode", uses: ["layer"] },
  { value: "hash", label: "Hash", uses: ["algorithm"] },
  { value: "skip_if_matches", label: "Skip if it matches", uses: ["pattern"] },
  { value: "normalize", label: "Unicode normalization", uses: ["form"] },
];

/** The normalization forms a "normalize" rule can emit (burpsy-react-ui-d617). */
export const NORMALIZATION_FORMS = ["nfc", "nfd", "nfkc", "nfkd", "fullwidth", "homoglyph"] as const;

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
  form: string;
}

export function emptyRule(rule: PayloadRuleName): PayloadRuleSpec {
  return { rule, text: "", pattern: "", replace: "", all: false, layer: "url", algorithm: "sha256", form: "nfkc" };
}

export interface PointView {
  index: number;
  kind: string;
  label: string;
  offset: number;
  len: number;
  /** The position's base value: what a payload replaces, or — placement "append" — what it is added to. */
  current: string;
  /**
   * Burp's "Automatic payload placement" for this position (burpsy-react-ui-1krs). "append" means the
   * payload goes after `current` (offset/len is then the zero-length point at its end, or the whole
   * value for a nested container whose encoding is rebuilt); "replace" means it overwrites `current`.
   */
  placement: "replace" | "append";
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
  /**
   * The one stored exchange kept for this bucket — `first_ordinal`'s request and the response it
   * produced. `null` when the server did not store it: an older server sends no
   * `example_request_id` at all, and the results menu gates its handoffs on these rather than
   * offering an action that would resolve nothing.
   */
  example_request_id: number | null;
  example_response_id: number | null;
  grep_matches: number;
  grep_extract: string | null;
  /** Per-expression occurrence totals summed over this bucket's responses (irt), parallel to the
   *  expression list. Empty when no list was configured. */
  grep_match_totals: number[];
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
  /** The exact bytes this attempt sent, once the server stored them. `null` for a send that
   *  failed or was refused, and for every row on an older server. */
  request_id: number | null;
  /** Set only on the attempt that opened its bucket — the exemplar the engine stored. A later
   *  attempt in the same bucket is `null`, because status/length/reflection matching is not a
   *  claim that two response bodies are equal. */
  response_id: number | null;
  error: string | null;
  grep_matched: boolean | null;
  grep_extract: string | null;
  /** Per-expression occurrence count from the Grep - Match list (irt), parallel to the attack's
   *  expression list. Empty when no list was configured. */
  grep_match_counts: number[];
  /** The expressions as the operator typed them, in list order — the column headers. Present on
   *  the report when a list ran; never null. */
  grep_match_labels?: string[];
  /** When this attempt was dispatched — or, for a guard refusal, when it was refused. Burp's
   *  results table carries it as its own column ("the time of day the request was made"). An
   *  RFC 3339 string (Go's `time.Time` default encoding), never absent. */
  time_of_day: string;
  /** Names Set-Cookie carried in this attempt's response — Burp: "any cookies received in the
   *  response". Names only, never values (a session token belongs in the stored response, not
   *  a summary row). `[]`, never absent, even for a row with no response at all. */
  cookies: string[];
  /** True when `error` above is specifically the per-request deadline expiring, distinct from
   *  any other failure (connection refused, TLS failure, a guard refusal). Burp lists Timeout
   *  as its own column rather than folding it into Error. */
  timeout: boolean;
}

/** How an attack ended. "paused" only appears on a report built from a still-live attack. */
export type AttackStatus = "completed" | "stopped" | "paused";

export interface AttackReport {
  kind: AttackMode;
  combinations: number;
  combinations_exact: boolean;
  max_requests: number;
  truncated: boolean;
  planned: number;
  /**
   * How the attack ended, and why.
   *
   * Optional because an older server does not send them, and the difference matters too much to
   * paper over with a default that reads as "completed": an attack stopped at request 12 of 200,000
   * and an attack whose target refused 199,988 requests both report sent=12, and the second is a
   * finding about the target while the first is a fact about the operator's own button.
   */
  status?: AttackStatus;
  stop_reason?: string;
  /**
   * Plan positions the driver actually reached — the honest denominator for a stopped attack, where
   * `planned` is not. Equals `planned` on a completed one. Sent + failed can be smaller still,
   * because a stop lets in-flight sends land.
   */
  enumerated?: number;
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
  /** The Grep - Match expressions as typed (irt), in list order — the results-table headers for
   *  the per-expression count columns. Present only when a list ran. */
  grep_match_labels?: string[];
  /** How many retry sends the attack made (n39) — Burp's error-handling count. Zero unless the
   *  attack configured retries. */
  retries_used: number;
  /** True when the attack issued the unmodified template request as item 0 (v34) — "Baseline
   *  request (no payloads)". Every ordinal shifts by one; ordinal 0 carries no payloads. */
  baseline: boolean;
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
  /**
   * How many additional requests this attack sent chasing a 3xx (tirx), summed across every
   * attempt. Zero whenever `follow_redirects` was never sent (the default is not to follow) or
   * every hop was refused by policy or scope. Optional because an older server never sent it —
   * absent reads as 0, which is what every such server's behaviour actually was.
   */
  redirects_followed?: number;
  /**
   * What HTTP/1 connection reuse did (xhqr): sockets the attack dialled, and requests that completed
   * on a socket an earlier request had used. null when reuse was off — nothing was counted, every
   * request had its own connection. Optional because an older server never sent either.
   */
  connections_opened?: number | null;
  connections_reused?: number | null;
  /**
   * Update Host header to match target (ety8): whether it was applied, why not when it was asked for
   * and stood aside, and how many requests a payload left with other than one Host header (sent as
   * spliced). Optional because an older server never sent them.
   */
  host_header_updated?: boolean;
  host_header_skipped?: string;
  host_header_untouched?: number;
}

/** Burp's Intruder "Follow redirections" (tools/intruder/configure-attack/settings.html). */
export type FollowRedirectsMode = "never" | "on_site" | "in_scope" | "always";

export const FOLLOW_REDIRECTS_MODES: { value: FollowRedirectsMode; label: string }[] = [
  { value: "never", label: "Never" },
  { value: "on_site", label: "On-site only" },
  { value: "in_scope", label: "In-scope only" },
  { value: "always", label: "Always" },
];

/**
 * A running attack as the control routes see it (GET /api/intruder/attacks).
 *
 * Distinct from AttackStatus: this is the *live* state of an attack the process is still executing,
 * and "running" is a state the finished report never carries. `task_id` is the dashboard task id,
 * which is also the id POST /api/intruder/attacks/{id}/{pause|resume|stop} takes — one id space, so
 * the Dashboard's stop button and Intruder's address the same attack by the same name.
 */
export type IntruderAttackStatus = "running" | "paused" | "stopped";

export interface IntruderAttack {
  task_id: number;
  kind: AttackMode;
  target: string;
  planned: number;
  status: IntruderAttackStatus;
  stop_reason?: string;
  /** Sends settled so far — the same totals the eventual report carries. */
  sent: number;
  failed: number;
}

/** The list shape; `attacks` is never null, so absent cannot be misread as "none running". */
export interface IntruderAttacksResp {
  attacks: IntruderAttack[];
}

export type PayloadSourceType =
  | "list"
  | "numbers"
  | "file"
  | "brute_force"
  | "custom_iterator"
  | "dates"
  | "null"
  | "recursive_grep"
  | "collaborator"
  | "char_substitution"
  | "case_modification"
  | "illegal_unicode"
  | "character_blocks"
  | "bit_flipper"
  | "username"
  | "ecb_shuffler"
  | "character_frobber"
  | "copy_other";

export interface PayloadSourceList { type: "list"; items: string[] }
export interface PayloadSourceNumbers { type: "numbers"; from: number; to: number; step: number; order?: "sequential" | "random"; count?: number; base?: "decimal" | "hex"; pad_to?: number }
export interface PayloadSourceFile { type: "file"; filename: string }
export interface PayloadSourceBruteForce { type: "brute_force"; charset: string; min_len: number; max_len: number }
export interface PayloadSourceCustomIterator { type: "custom_iterator"; positions: string[][]; separator: string }
export interface PayloadSourceDates { type: "dates"; from: string; to: string; step: number; format: string }
export interface PayloadSourceNull { type: "null"; count: number }
/** Burp's Character substitution (2g13): base words, plus per-character substitutes. */
export interface PayloadSourceCharSubstitution { type: "char_substitution"; words: string[]; subs: Record<string, string>; max_per_word?: number }
/** Burp's Case modification (2g13): case variants of a word list. */
export interface PayloadSourceCaseModification { type: "case_modification"; words: string[]; lower?: boolean; upper?: boolean; capitalize?: boolean }
/** Burp's Illegal Unicode (2g13): overlong UTF-8 encodings of ASCII characters. */
export interface PayloadSourceIllegalUnicode { type: "illegal_unicode"; chars: string; forms: ("overlong2" | "overlong3" | "overlong4")[]; percent_encode?: boolean }
/**
 * Burp's Character blocks (2g13): one payload per length, Chars cycled to fill it.
 * NOT the Character frobber — that is a different generator over a different input, and
 * `PayloadSourceCharacterFrobber` is the one that walks a value's characters (cd00).
 */
export interface PayloadSourceCharacterBlocks { type: "character_blocks"; chars: string; min_len: number; max_len: number; step: number }
/** Burp's Bit flipper (2g13): one payload per bit of Base, that bit inverted. */
export interface PayloadSourceBitFlipper { type: "bit_flipper"; base: string }
/** Burp's Username generator (2g13): candidate usernames from a "First Last" list. */
export interface PayloadSourceUsername { type: "username"; names: string[]; formats?: string[] }
/** Burp's ECB block shuffler (2g13): permutations of a sample's cipher-block order. */
export interface PayloadSourceECBShuffler { type: "ecb_shuffler"; sample: string; encoding: "base64" | "hex"; block_size: number }
/**
 * Burp's Copy other payload (2g13): this position's payload is whatever `position` received
 * for the same request. Pitchfork only — see internal/intruder/payload.go's CopyOtherSource
 * doc and api_tools.go's handleIntruderRun for why cluster bomb cannot honour this exactly.
 */
/**
 * Burp's Character frobber (cd00): one payload per (character position × alphabet) of `base`,
 * with the rest of the value held fixed. NOT the same generator as character_blocks, which has
 * no input value to vary — the console once labelled that one "Character blocks (frobber)", and
 * the two names sharing a line is why the absence went unnoticed.
 */
export interface PayloadSourceCharacterFrobber { type: "character_frobber"; base: string; chars: string }
export interface PayloadSourceCopyOther { type: "copy_other"; position: number }
/**
 * Burp's Recursive grep (ztuu): the payload for request N+1 is extracted from the response to
 * request N. The server runs the chain serially (max_in_flight forced to 1, as Burp forces its
 * resource pool for these attacks) and the report carries the derived payloads per ordinal in
 * `chain_payloads` — the payload set itself holds only the initial value.
 */
export interface PayloadSourceRecursiveGrep { type: "recursive_grep"; initial: string; extract_re: string; stop_duplicate?: boolean }
/**
 * Burp's Intruder Collaborator payload type (hi8): each payload is a fresh out-of-band address,
 * minted at launch and recorded in the Collaborator page's hub, so the interaction is attributed
 * to the address the attack used. include_location=false yields the bare interaction id (Burp's
 * "Include Collaborator server location" unchecked) — an id with no domain cannot receive a
 * callback by itself.
 */
export interface PayloadSourceCollaborator { type: "collaborator"; count: number; include_location?: boolean }
export type PayloadSource =
  | PayloadSourceList
  | PayloadSourceNumbers
  | PayloadSourceFile
  | PayloadSourceBruteForce
  | PayloadSourceCustomIterator
  | PayloadSourceDates
  | PayloadSourceNull
  | PayloadSourceCharSubstitution
  | PayloadSourceCaseModification
  | PayloadSourceIllegalUnicode
  | PayloadSourceCharacterBlocks
  | PayloadSourceBitFlipper
  | PayloadSourceUsername
  | PayloadSourceECBShuffler
  | PayloadSourceCopyOther
  | PayloadSourceRecursiveGrep
  | PayloadSourceCollaborator;

/**
 * What a report's counts actually describe.
 *
 * A stopped attack describes a *prefix* of its payload sets, so `planned` is the wrong denominator:
 * "Sent 12 of 400 planned" asserts the target was asked 400 times and answered 12, when it was
 * asked 12. `reached` is the count the results are a prefix of.
 *
 * An older server sends neither `status` nor `enumerated`. Absent is read as completed, and
 * `reached` falls back to `planned` — sound only because no server that omits these fields could
 * stop an attack, so completed is what it always was. A future field that changes that must not
 * reuse the absence.
 */
export function attackProgress(report: AttackReport): { stopped: boolean; paused: boolean; reached: number } {
  const paused = report.status === "paused";
  return {
    stopped: report.status === "stopped" || paused,
    paused,
    reached: report.enumerated ?? report.planned,
  };
}

/**
 * A payload set's size, or `null` when the browser genuinely cannot know it.
 *
 * Only the `file` source is unknowable client-side: the file lives on the server and nothing in
 * the request body says how many lines it has. Every other source is arithmetic the browser can do
 * (burpsy-react-ui-1ww). `null` exists so an unknown size is displayed as unknown rather than
 * standing in as `1` — the whole defect that issue filed.
 */
export type SetSize = number | null;

/**
 * How many requests a configuration implies. The server enforces max_requests, but showing the
 * estimate first is what stops an operator launching a cluster-bomb attack that would have run for
 * hours.
 *
 * `exact` is false when an unknown-size set contributed, and `count` is then a floor: the unknown
 * set is counted as one payload, which is the smallest it can be. A floor is the only honest number
 * available, and callers must present it as one — the over-budget guard may fire on a floor that
 * already exceeds the cap, but silence from it proves nothing when `exact` is false.
 */
export function estimateRequests(mode: AttackMode, pointCount: number, setSizes: SetSize[]): { count: number; exact: boolean } {
  let exact = true;
  const sizes = setSizes.map((size) => {
    if (size === null) {
      exact = false;
      return 1;
    }
    return Math.max(0, size);
  });
  const first = sizes[0] ?? 0;
  // Only the sets the mode actually reads can affect the count: sniper and battering ram read set 0
  // and ignore the rest, so an unknown size in an unread set must not poison `exact`.
  const usedExact = (used: SetSize[]) => used.every((size) => size !== null);
  switch (mode) {
    case "sniper":
      return { count: first * Math.max(1, pointCount), exact: usedExact(setSizes.slice(0, 1)) };
    case "battering_ram":
      return { count: first, exact: usedExact(setSizes.slice(0, 1)) };
    case "pitchfork":
      return { count: sizes.length ? Math.min(...sizes) : 0, exact: sizes.length ? exact : true };
    case "cluster_bomb": {
      let product = 1;
      for (const size of sizes) product *= size;
      return { count: sizes.length ? product : 0, exact: sizes.length ? exact : true };
    }
    default:
      return { count: 0, exact: false };
  }
}

/**
 * Payloads a `dates` source produces: inclusive of both ends, stepping in whole days.
 *
 * Mirrors internal/intruder's date generator, which walks `from` forwards by `step` days while the
 * cursor is not past `to`. Returns null for an unparseable bound or a non-positive step rather than
 * guessing — the badge shows unknown, and the server is the one that rejects the configuration.
 */
export function dateSetSize(from: string, to: string, step: number): SetSize {
  const start = Date.parse(`${from.trim()}T00:00:00Z`);
  const end = Date.parse(`${to.trim()}T00:00:00Z`);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  if (!Number.isFinite(step) || step <= 0) return null;
  if (end < start) return 0;
  const days = Math.round((end - start) / 86_400_000);
  return Math.floor(days / step) + 1;
}

/** One `custom_iterator` line: comma-separated items, blanks dropped. Mirrors the page's parser. */
export function customIteratorSlots(positions: string): string[][] {
  return positions
    .split("\n")
    .map((line) => line.split(",").map((item) => item.trim()).filter(Boolean))
    .filter((slot) => slot.length > 0);
}

/**
 * Payloads a `custom_iterator` source produces: the product of its per-line item counts.
 *
 * Zero when no line carries an item — an iterator with nothing in it produces nothing, and the
 * hard-coded `4` this replaces claimed otherwise.
 */
export function customIteratorSize(positions: string): number {
  const slots = customIteratorSlots(positions);
  if (!slots.length) return 0;
  let product = 1;
  for (const slot of slots) product *= slot.length;
  return product;
}

/**
 * Escape a literal so Go's regexp treats it as text.
 *
 * Byte-for-byte the set `regexp.QuoteMeta` escapes (`\.+*?()|[]{}^$`), because the pattern is
 * compiled by RE2 on the server and not by JavaScript. This is what makes the grep fields' simple-
 * string mode honest: the operator types `root:` and burpsy sends a pattern that matches `root:`
 * (burpsy-react-ui-tpy).
 */
export function quoteRegex(literal: string): string {
  return literal.replace(/[\\.+*?()|[\]{}^$]/g, "\\$&");
}

// ---- resolving an attempt's payloads from its ordinal ------------------------------------------
//
// The server answers a run with `examples`, but only for each bucket's first ordinal, so an attempt
// row carried an ordinal and nothing else (burpsy-react-ui-fvx). The plan is pure arithmetic on the
// index — internal/intruder/plan.go's `Fill` doc comment says so, and that is exactly why it can be
// recomputed here from numbers the report already carries.

/** One (position, set, payload index) placement. Mirrors intruder.Slot. */
export interface PayloadSlot {
  point: number;
  set: number;
  payload: number;
}

/**
 * The set lengths a plan actually reads, mirroring NewAttackPlan's `setsUsed`.
 *
 * Sniper and battering ram read set 0 only; pitchfork and cluster bomb read one set per position,
 * truncated to however many sets exist.
 */
export function planSetLengths(mode: AttackMode, points: number, setCounts: number[]): number[] {
  switch (mode) {
    case "sniper":
    case "battering_ram":
      return setCounts.length ? setCounts.slice(0, 1) : [];
    case "pitchfork":
    case "cluster_bomb":
      return setCounts.slice(0, Math.max(0, Math.min(points, setCounts.length)));
    default:
      return [];
  }
}

/**
 * Where request `ordinal` put its payloads, or null when the ordinal is outside the plan.
 *
 * A faithful port of `(*AttackPlan).Fill`, including cluster bomb's mixed-radix decode with set 0 as
 * the *fastest*-varying digit — the lockout-safe spray ordering. Getting that direction wrong would
 * label every cluster-bomb row with the wrong payload, which is worse than the missing column was,
 * so it is pinned by test.
 */
export function assignmentAt(
  mode: AttackMode,
  points: number,
  setLengths: number[],
  planLen: number,
  ordinal: number,
): PayloadSlot[] | null {
  if (!Number.isInteger(ordinal) || ordinal < 0 || ordinal >= planLen) return null;
  switch (mode) {
    case "sniper": {
      const n = setLengths[0] ?? 0;
      if (n <= 0) return null;
      return [{ point: Math.floor(ordinal / n), set: 0, payload: ordinal % n }];
    }
    case "battering_ram": {
      if (points <= 0) return null;
      return Array.from({ length: points }, (_, point) => ({ point, set: 0, payload: ordinal }));
    }
    case "pitchfork":
      return setLengths.map((_, index) => ({ point: index, set: index, payload: ordinal }));
    case "cluster_bomb": {
      if (setLengths.some((length) => length <= 0)) return null;
      let weight = 1;
      return setLengths.map((length, index) => {
        const slot = { point: index, set: index, payload: Math.floor(ordinal / weight) % length };
        // Saturating, like plan.go's saturatingIntMul: once the weight exceeds any reachable
        // ordinal, ordinal/weight is 0, which is the correct digit anyway.
        weight = Math.min(weight * length, Number.MAX_SAFE_INTEGER);
        return slot;
      });
    }
    default:
      return null;
  }
}

/**
 * One resolved placement: the payload's text, or null when this browser cannot name it.
 *
 * `text: null` is not a failure and not an empty payload — it means the set's items never crossed
 * the wire (internal/intruder's PayloadSet tags Items `json:"-"`), so only the index is knowable.
 * The distinction is the point: a row that says "set 2 item #17" is useful, and one that invents a
 * payload is not.
 */
export interface ResolvedPayload {
  set: number;
  index: number;
  text: string | null;
}

/**
 * Resolve a plan assignment against whatever payload text this browser holds.
 *
 * `knownSets[i]` is the items of set `i` as the browser knows them, or null when it does not.
 * Callers must pass null for any set whose server-reported count disagrees with the list length —
 * a payload processing rule that skipped an item shifts every index after it, so a mismatch means
 * the browser's list is not the list the ordinals were computed against.
 */
export function resolvePayloads(slots: PayloadSlot[], knownSets: (string[] | null)[]): ResolvedPayload[] {
  return slots.map((slot) => {
    const items = knownSets[slot.set] ?? null;
    const text = items && slot.payload >= 0 && slot.payload < items.length ? items[slot.payload]! : null;
    return { set: slot.set, index: slot.payload, text };
  });
}

/**
 * Parses the Character substitution panel's "char=replacement" textarea (2g13) into the
 * `subs` map internal/intruder.CharSubstitution wants — one substitution per line. A line
 * with no `=`, or an empty character before it, is skipped rather than refused: the operator
 * is still typing, and a blank trailing line is the ordinary state of a textarea, not an error.
 * The replacement half is allowed to be empty (a substitution to nothing), which is why the
 * split is on the first `=` only — `indexOf`, not a regex split that would also break on a
 * literal `=` inside the replacement.
 */
export function parseCharSubstitutions(text: string): Record<string, string> {
  const subs: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const ch = line.slice(0, eq).trim();
    const rep = line.slice(eq + 1).trim();
    if (ch) subs[ch] = rep;
  }
  return subs;
}

/** One row of the wordlist inventory (kal). */
export interface WordlistEntry {
 /** What the operator selects. */
 name: string;
 /** "builtin" (bundled into the binary) or "upload" (the operator's own). */
 kind: "builtin" | "upload";
 /** The value a consuming tool takes: "builtin:<name>" or the stored path. */
 ref: string;
 /** The payload count the attack will see (blank lines already skipped). */
 lines: number;
}

/** GET /api/wordlists. */
export interface WordlistsResponse {
 wordlists: WordlistEntry[];
 note: string;
}
