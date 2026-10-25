/**
 * Query hooks for /api/proxy/options — the proxy's live response-modification
 * switches and the counters that say what they did. PUT takes a flat map of
 * keys to booleans and answers with the confirmed state, so the panel renders
 * what the relay is actually in.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

export interface ProxyOptionsState {
  options: Record<string, boolean>;
  counters: {
    responses_considered: number;
    responses_modified: number;
    responses_unchanged: number;
    /** Compressed responses no rule reached: unpacking was off, or it could not decode them. */
    skipped_compressed: number;
    /** The subset of skipped_compressed where unpacking was ON and could not help: a chain
     *  of encodings, or a body that failed to decompress (proxy.Counters.SkippedUnsupportedEncoding). */
    skipped_unsupported_encoding: number;
    /** Messages actually decompressed by unpack_compressed_requests / _responses — not messages seen
     *  while the switch was on. */
    unpacked_requests: number;
    unpacked_responses: number;
    skipped_not_html: number;
    skipped_unframed: number;
    relayed_http2: number;
    accept_encoding_stripped: number;
    dechunked: number;
    exchanges_dropped_out_of_scope: number;
  };
  keys: string[];
}

export function useProxyOptions(): ReturnType<typeof useQuery<ProxyOptionsState>> {
  return useQuery({
    queryKey: keys.proxyOptions,
    queryFn: ({ signal }) => api<ProxyOptionsState>("/api/proxy/options", { signal }),
    refetchInterval: 4_000,
  });
}

export function useSetProxyOptions() {
  const client = useQueryClient();
  return useMutation<ProxyOptionsState, Error, Record<string, boolean>>({
    mutationFn: (set) => api<ProxyOptionsState>("/api/proxy/options", json("PUT", set)),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.proxyOptions }),
  });
}
