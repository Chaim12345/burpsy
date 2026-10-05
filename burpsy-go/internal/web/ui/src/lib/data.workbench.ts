import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json, query } from "./api";
import { useResource } from "./data";
import type {
 CompareResponse,
 UninterestingHeaders,
 DecodeResponse,
 EncodeResponse,
 HashResponse,
 SequencerAnalysis,
 SequencerCapture,
 SequencerSettings,
 SequencerSettingsEdit,
 StopCaptureResult,
 TokenLocation,
 ToolLogView,
 TransformKind,
 TransformResult,
 TransformRun,
 TransformStep,
} from "./types.workbench";
import type { EffectiveEntropyReport } from "./sequencer-significance";

/**
 * Read hooks for the Workbench tools. Keys keep the "toollog" / "sequencer"
 * prefixes the event stream invalidates (see INVALIDATION in data.ts), so a
 * server event still refreshes these views.
 */
export const workbenchKeys = {
 /** Distinct from data.ts's keys.toolLog: that key omits `limit`, so sharing it
  *  would let the Dashboard's 20-row window and this page's full read collide. */
 toolLog: (filter: string, search: string, limit: number) => ["toollog", "logger", filter, search, limit] as const,
 sequencerCapture: (id: string) => ["sequencer", "capture", id] as const,
 sequencerSettings: ["sequencer", "settings"] as const,
};

/* --- supported values, read off the Go handlers --------------------------- */

/**
 * Layers `decodeLayer` in api_toolkit.go implements. It resolves the name through
 * the codec table (tools.ParseLayer) and answers 400 for anything outside it, so
 * an unknown layer is a visible error rather than a decode that never happened.
 * base64url uses the URL-safe alphabet here and on the encode side.
 */
/**
 * The decode layers the console offers.
 *
 * gzip and deflate were absent while `internal/tools/codec.go` had `LayerGzip` and `LayerDeflate`
 * and the handler already resolved the strings "gzip", "deflate" and "zlib" — so the capability
 * shipped and no operator could reach it (burpsy-react-ui-37b). Burp's own Operations list names
 * GZIP, and a compressed response is one of the commonest things to paste into a decoder.
 *
 * octal and binary (burpsy-react-ui-ku62) were the same shape of gap: Burp lists both as codecs
 * ("URL. HTML. Base64. ASCII hex. Hex. Octal. Binary. GZIP.") and `internal/tools/codec.go` had no
 * LayerOctal/LayerBinary at all until this bead — this is the pair's first landing, not a rewire of
 * an existing implementation, so there is no separate "was it wired" history to record here.
 *
 * Keep this in step with AllLayers() in codec.go. `internal/web/toolkit_codec_honesty_test.go`
 * already asserts against this array, which is why it lives here rather than in the page.
 */
export const DECODE_LAYERS = [
 "url",
 "html",
 "base64",
 "base64url",
 "hex",
 "octal",
 "binary",
 "gzip",
 "deflate",
 "jwt",
 "ascii",
] as const;

/**
 * Encodings `handleToolsEncode` implements, via the same codec table. Anything
 * else is a 400 naming the accepted set; there is no passthrough branch, so the
 * `encoding` echoed back always describes the bytes in `output`.
 */
/**
 * The encode directions the console offers.
 *
 * gzip and deflate are genuinely encodable — codec.go's Encode has `case LayerGzip` and
 * `case LayerDeflate` — unlike LayerJWT, which is decode-only by construction and is therefore
 * absent here on purpose. octal and binary (burpsy-react-ui-ku62) are genuinely encodable too —
 * `case LayerOctal` and `case LayerBinary` both return a value, never notReversible.
 */
export const ENCODE_ENCODINGS = [
 "url",
 "html",
 "base64",
 "base64url",
 "hex",
 "octal",
 "binary",
 "gzip",
 "deflate",
 "ascii",
 "rot13",
] as const;

/** Weakest first. These four are the whole accepted set; anything else is a 400. */
export const HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"] as const;

/** How the Sequencer may read a token's bits. Empty string means "let the server detect". */
export const SEQUENCER_ENCODINGS = ["hex", "base64", "raw"] as const;

/* --- sequencer ------------------------------------------------------------ */

/**
 * The analyse response, with the effective-entropy curve the Go report has
 * carried since burpsy-react-ui-boq.
 *
 * Intersected here rather than added to `SequencerAnalysis` because that
 * interface lives in types.workbench.ts, which another agent holds while this
 * lands; the field belongs there and should be folded in centrally. The
 * intersection makes it non-optional for every caller in the meantime, which is
 * the honest shape — the server sends it on every analyse, at a default level
 * when none was asked for.
 */
export type SequencerAnalysisWithEntropy = SequencerAnalysis & { effective_entropy: EffectiveEntropyReport };

/**
 * The operator's significance level, as the page holds it: "" means "let the
 * server use its default", exactly as "" means "detect" for the encoding. The
 * distinction survives to the report — `significance_defaulted` — so the page can
 * say "default" rather than implying a choice nobody made.
 */
export interface TokenHandling {
 /** "" or "none" leaves the sample as supplied; "start"/"end" is Burp's pad position. */
 padMode: string;
 /** The single character to pad with. Burp's own default is "0". */
 padByte: string;
 /** Burp's "Base64-decode before analyzing". Undefined while the saved setting has not loaded: the
  *  field is then omitted and the server applies the project's saved value. */
 base64Decode?: boolean;
}

function analyseBody(
 base: Record<string, unknown>,
 encoding: string,
 significancePercent: string,
 tokens?: TokenHandling,
): Record<string, unknown> {
 return {
  ...base,
  ...(encoding ? { encoding } : {}),
  ...(significancePercent ? { significance_percent: Number(significancePercent) } : {}),
  // Omitted when off, for the same reason an omitted encoding means "detect": the server's
  // default is the behaviour that existed before these controls did, and sending "none"
  // explicitly would be indistinguishable from an operator who chose it.
  ...(tokens && tokens.padMode && tokens.padMode !== "none"
   ? { pad_mode: tokens.padMode, ...(tokens.padByte ? { pad_byte: tokens.padByte } : {}) }
   : {}),
  // Sent explicitly whenever the page knows the saved setting (the checkbox is bound to it): an
  // omitted field means "the saved setting decides", and a PUT still in flight when Analyse is
  // clicked would otherwise run under the previous value.
  ...(tokens && tokens.base64Decode !== undefined ? { base64_decode: tokens.base64Decode } : {}),
 };
}

export function useSequencerAnalyse() {
 return useMutation<
  SequencerAnalysisWithEntropy,
  Error,
  { text: string; encoding: string; significancePercent: string; tokens?: TokenHandling }
 >({
  // An omitted encoding is what makes the server detect one; sending "" is an error there.
  mutationFn: ({ text, encoding, significancePercent, tokens }) =>
   api<SequencerAnalysisWithEntropy>("/api/sequencer/analyse", json("POST", analyseBody({ text }, encoding, significancePercent, tokens))),
 });
}

/** Analyse an already-collected token list rather than a pasted blob. */
export function useSequencerAnalyseTokens() {
 return useMutation<
  SequencerAnalysisWithEntropy,
  Error,
  { tokens: string[]; encoding: string; significancePercent: string; handling?: TokenHandling }
 >({
  mutationFn: ({ tokens, encoding, significancePercent, handling }) =>
   api<SequencerAnalysisWithEntropy>("/api/sequencer/analyse", json("POST", analyseBody({ tokens }, encoding, significancePercent, handling))),
 });
}

/**
 * GET /api/sequencer/settings — which tests an analysis runs, and the base64 token handling.
 * Saved with the project; an analysis that does not name its own tests (this page never does)
 * runs what these leave on.
 */
export const useSequencerSettings = (): UseQueryResult<SequencerSettings> =>
 useQuery({
  queryKey: workbenchKeys.sequencerSettings,
  queryFn: ({ signal }) => api<SequencerSettings>("/api/sequencer/settings", { signal }),
 });

/** PUT /api/sequencer/settings with a partial edit. The confirmed full view goes into the cache. */
export function useSaveSequencerSettings() {
 const client = useQueryClient();
 return useMutation<SequencerSettings, Error, SequencerSettingsEdit>({
  mutationFn: (edit) => api<SequencerSettings>("/api/sequencer/settings", json("PUT", edit)),
  onSuccess: (confirmed) => client.setQueryData(workbenchKeys.sequencerSettings, confirmed),
 });
}

/**
 * Poll one live capture. Capture progress is not on the event stream, so this is
 * the one Workbench read that polls, matching Intercept's cadence.
 */
export function useSequencerCapture(id: string, pollMs = 1_000): UseQueryResult<SequencerCapture> {
 return useQuery({
  queryKey: workbenchKeys.sequencerCapture(id),
  queryFn: ({ signal }) => api<SequencerCapture>(`/api/sequencer/capture/${encodeURIComponent(id)}`, { signal }),
  enabled: id !== "",
  refetchInterval: pollMs,
  staleTime: 0,
 });
}

/** The body POST /api/sequencer/capture takes. `count` defaults to 100 server-side. */
export interface SequencerCaptureRequest {
 target: string;
 protocol?: "http" | "https";
 request: string;
 count?: number;
 /** Milliseconds between sends. A capture is the one tool that deliberately hammers one endpoint,
  *  so this is how an operator stays under a rate limit. */
 delay_ms?: number;
 /** Burp's "Ignore token whose length deviates by X characters": when enabled, tokens whose
  *  length differs from the running average by more than chars are dropped and counted as gated. */
 length_deviates?: { enable: boolean; chars: number };
 location: TokenLocation;
}

/** Start a real capture: N sends of one request, one token extracted per response. */
export function useStartSequencerCapture() {
 const client = useQueryClient();
 return useMutation<SequencerCapture, Error, SequencerCaptureRequest>({
  mutationFn: (body) => api<SequencerCapture>("/api/sequencer/capture", json("POST", body)),
  onSuccess: () => void client.invalidateQueries({ queryKey: ["sequencer", "capture"] }),
 });
}

export function useStopSequencerCapture() {
 const client = useQueryClient();
 return useMutation<StopCaptureResult, Error, void>({
  mutationFn: () => api<StopCaptureResult>("/api/sequencer/capture/stop", json("POST", {})),
  onSuccess: () => void client.invalidateQueries({ queryKey: ["sequencer", "capture"] }),
 });
}

/** Pause or resume the newest live capture (burpsy-react-ui-5kx). The server operates on the
 * capture in front of the operator — the newest running one — like Burp's own pause button. */
export function usePauseSequencerCapture(paused: boolean) {
 const client = useQueryClient();
 return useMutation<{ captured: SequencerCapture[]; note: string }, Error, void>({
  mutationFn: () => api(`/api/sequencer/capture/${paused ? "pause" : "resume"}`, json("POST", {})),
  onSuccess: () => void client.invalidateQueries({ queryKey: ["sequencer", "capture"] }),
 });
}

/* --- decoder pipeline ----------------------------------------------------- */

let stepSequence = 0;

export function newTransformStep(kind: TransformKind, value: string): TransformStep {
 stepSequence += 1;
 return { id: `s${stepSequence}`, kind, value, guess: kind === "decode" };
}

/** Run one step against the server and normalise the three response shapes. */
async function runStep(input: string, step: TransformStep): Promise<TransformResult> {
 const base = { stepId: step.id, kind: step.kind, value: step.value };
 if (step.kind === "decode") {
  // "auto" is the smart path: the handler treats "" and "auto" alike and
  // reports what it unwrapped in `layers`.
  const response = await api<DecodeResponse>(
   "/api/tools/decode",
   json("POST", { input, encoding: step.value === "auto" ? "auto" : step.value, guess_alphabets: step.guess }),
  );
  return { ...base, ...viewFields(response.output), layers: response.layers ?? [], partial: response.partial ?? false };
 }
 if (step.kind === "encode") {
  const response = await api<EncodeResponse>("/api/tools/encode", json("POST", { input, encoding: step.value }));
  return { ...base, ...viewFields(response.output), layers: null };
 }
 const response = await api<HashResponse>("/api/tools/hash", json("POST", { input, algorithm: step.value }));
 return { ...base, ...viewFields(response.output), layers: null };
}

function viewFields(view: { text: string; len: number; utf8: boolean; truncated: boolean }) {
 return { output: view.text, len: view.len, utf8: view.utf8, truncated: view.truncated };
}

/**
 * Chain the decode/encode/hash endpoints, feeding each step's output into the
 * next. A failing step stops the chain but does not discard the steps that
 * already ran — the intermediate results are the point of the pipeline.
 *
 * Nothing to invalidate: all three endpoints are pure transforms that take no
 * server state and are not recorded in the tool log.
 */
export function useTransformPipeline() {
 return useMutation<TransformRun, Error, { input: string; steps: TransformStep[] }>({
  mutationFn: async ({ input, steps }) => {
   const results: TransformResult[] = [];
   let current = input;
   for (const [index, step] of steps.entries()) {
    try {
     const result = await runStep(current, step);
     results.push(result);
     current = result.output;
    } catch (error) {
     return {
      results,
      failedAt: index,
      message: error instanceof Error ? error.message : String(error),
     };
    }
   }
   return { results, failedAt: null, message: null };
  },
 });
}

/* --- comparer ------------------------------------------------------------- */

/**
 * The header names the Comparer discounts — Burp's `configPanelUninterestingRequestHeaders` and
 * `configPanelUninterestingResponseHeaders` (W6 #81/#82), which had no counterpart here at all.
 *
 * Comparing two responses is how an operator decides whether an input changed behaviour, and the
 * comparison is drowned by headers that differ on every request and mean nothing: `Date` always
 * differs, `ETag` and `Age` usually do, a request-id differs by construction.
 *
 * Nothing is ever hidden. The backend labels differences that fall inside a discounted header and
 * reports both verdicts — see `CompareResponse.identical_ignoring_uninteresting`.
 */
export const useUninterestingHeaders = () =>
 useResource<UninterestingHeaders>(["uninteresting-headers"], "/api/headers/uninteresting");

/** Replace the discount lists. Omit a direction to leave it untouched. */
export function useSetUninterestingHeaders() {
 const client = useQueryClient();
 return useMutation<UninterestingHeaders, Error, { request?: string[]; response?: string[] }>({
  mutationFn: (body) =>
   api<UninterestingHeaders>("/api/headers/uninteresting", json("PUT", body)),
  onSuccess: () => void client.invalidateQueries({ queryKey: ["uninteresting-headers"] }),
 });
}

/**
 * Compares two messages, byte-by-byte or word-by-word.
 *
 * `granularity` is the operator's choice (Burp's two compare modes). It is sent explicitly rather
 * than defaulted here, because the result is labelled with the mode that produced it and a label
 * that can disagree with what ran is worse than no label; the endpoint echoes the mode back.
 */
export function useCompare() {
 return useMutation<
  CompareResponse,
  Error,
  { a: string; b: string; response?: boolean; granularity?: "bytes" | "words" }
 >({
  // `response` selects which uninteresting-header list applies (W6 #81/#82). Omitted means the
  // request list, which is empty unless the operator populated it — so leaving it out reproduces
  // the behaviour this endpoint had before the field existed.
  mutationFn: ({ a, b, response, granularity }) =>
   api<CompareResponse>("/api/tools/compare", json("POST", { a, b, response, granularity })),
 });
}

/** Fetch stored message bytes on demand, for loading a Comparer slot by id. */
export function useLoadMessage() {
 return useMutation<{ text: string }, Error, number>({
  mutationFn: (id) => api<{ text: string }>(`/api/message/${id}`),
 });
}

/* --- tool log ------------------------------------------------------------- */

export const useToolLogView = (filter: string, search: string, limit = 1_000) =>
 useResource<ToolLogView>(workbenchKeys.toolLog(filter, search, limit), `/api/tools/log${query({ limit, filter, search })}`);

/**
 * Toggle one tool's capture axis. This is the destructive arm, so the UI must
 * show it as such — turning capture off means that tool's next requests are
 * sent and deliberately not recorded, and only the `uncaptured` counter will
 * say so. Mutates via POST /api/tools/log; invalidates the logger read (and
 * the dashboard's, under the same "toollog" prefix) so the new axis is shown.
 */
export const useSetToolLogCapture = () => {
 const queryClient = useQueryClient();
 return useMutation<
  Record<string, boolean>,
  Error,
  {
   tool?: string;
   on?: boolean;
   filter?: { status: number[]; term: string; regex: boolean; case_sensitive: boolean; negate: boolean; scope_only: boolean };
   capacity?: number;
  }
 >({
  mutationFn: (body) => api<Record<string, boolean>>("/api/tools/log", json("POST", body)),
  onSuccess: () => {
   // Invalidate every filter/search combination under the "toollog" prefix,
   // matching workbenchKeys.toolLog's shape, so the refreshed read reflects
   // the new capture axis regardless of the currently-selected filters.
   void queryClient.invalidateQueries({ queryKey: ["toollog"] });
  },
 });
};

/**
 * Annotate one log entry (burpsy-react-ui-5da). Empty clears. Unknown ids 404 rather
 * than succeeding quietly, so a comment addressed at a trimmed row cannot read as saved.
 */
export const useSetToolLogComment = () => {
 const queryClient = useQueryClient();
 return useMutation<unknown, Error, { id: number; comment: string; highlight?: string }>({
  mutationFn: ({ id, comment, highlight = "" }) => api<unknown>(`/api/tools/log/${id}`, json("PATCH", { comment, highlight })),
  onSuccess: () => {
   void queryClient.invalidateQueries({ queryKey: ["toollog"] });
  },
 });
};
