import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json, query } from "./api";
import { useResource } from "./data";
import type {
  CompareResponse,
  DecodeResponse,
  EncodeResponse,
  HashResponse,
  SequencerAnalysis,
  SequencerCapture,
  StopCaptureResult,
  TokenLocation,
  ToolLogView,
  TransformKind,
  TransformResult,
  TransformRun,
  TransformStep,
} from "./types.workbench";

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
};

/* --- supported values, read off the Go handlers --------------------------- */

/**
 * Layers `decodeLayer` in api_toolkit.go implements. It resolves the name through
 * the codec table (tools.ParseLayer) and answers 400 for anything outside it, so
 * an unknown layer is a visible error rather than a decode that never happened.
 * base64url uses the URL-safe alphabet here and on the encode side.
 */
export const DECODE_LAYERS = ["url", "html", "base64", "base64url", "hex", "jwt", "ascii"] as const;

/**
 * Encodings `handleToolsEncode` implements, via the same codec table. Anything
 * else is a 400 naming the accepted set; there is no passthrough branch, so the
 * `encoding` echoed back always describes the bytes in `output`.
 */
export const ENCODE_ENCODINGS = ["url", "html", "base64", "base64url", "hex", "ascii", "rot13"] as const;

/** Weakest first. These four are the whole accepted set; anything else is a 400. */
export const HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"] as const;

/** How the Sequencer may read a token's bits. Empty string means "let the server detect". */
export const SEQUENCER_ENCODINGS = ["hex", "base64", "raw"] as const;

/* --- sequencer ------------------------------------------------------------ */

export function useSequencerAnalyse() {
  return useMutation<SequencerAnalysis, Error, { text: string; encoding: string }>({
    // An omitted encoding is what makes the server detect one; sending "" is an error there.
    mutationFn: ({ text, encoding }) =>
      api<SequencerAnalysis>("/api/sequencer/analyse", json("POST", encoding ? { text, encoding } : { text })),
  });
}

/** Analyse an already-collected token list rather than a pasted blob. */
export function useSequencerAnalyseTokens() {
  return useMutation<SequencerAnalysis, Error, { tokens: string[]; encoding: string }>({
    mutationFn: ({ tokens, encoding }) =>
      api<SequencerAnalysis>("/api/sequencer/analyse", json("POST", encoding ? { tokens, encoding } : { tokens })),
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
 * The handler reads flat `a` / `b` strings and has no granularity parameter, so
 * every comparison is byte-level.
 */
export function useCompare() {
  return useMutation<CompareResponse, Error, { a: string; b: string }>({
    mutationFn: ({ a, b }) => api<CompareResponse>("/api/tools/compare", json("POST", { a, b })),
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
