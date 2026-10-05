// Data hooks for the custom history extractor columns (burpsy-react-ui-28n8).
//
// Two resources, split exactly as the server splits them (internal/web/api_history_extractors.go):
//
//   /api/history/extractors  GET/PUT   the saved column definitions, replaced wholesale, project-scoped
//   /api/history/extract     POST      the saved extractors' values for a named set of exchange ids
//
// The definitions are the column set; the values are run per visible page. Values are NOT a field on
// the history row, because /api/history serves an index row that never touches a response body —
// running an extractor needs the response bytes, so it is asked for only the rows on screen.

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";
import { MAX_EXTRACT_ROWS, type HistoryExtractor } from "./extractors";

// Deliberately NOT under the "history" prefix: every captured exchange invalidates ["history"] (the
// server-push INVALIDATION map in data.ts), and under it each capture would re-run every extractor
// over every loaded response. Nothing a capture does changes these answers — a new row is a new id
// set, so a new key — and a project switch resets every query regardless of prefix.
export const extractorKeys = {
 defs: ["historyExtractors"] as const,
 /** One cache entry per (definition signature, id set). The signature is part of the key so editing
  *  a definition refetches; the id set is part of it so a different page of rows is a different
  *  entry rather than a stale reuse. */
 values: (signature: string, ids: string) => ["historyExtract", signature, ids] as const,
 /** The prefix the PUT invalidates so every value entry refetches against the new definitions. */
 valuesPrefix: ["historyExtract"] as const,
};

interface ExtractorsResponse {
 extractors: HistoryExtractor[];
}

/** The saved extractor column definitions. */
export function useHistoryExtractors(): UseQueryResult<ExtractorsResponse> {
 return useQuery({
  queryKey: extractorKeys.defs,
  queryFn: ({ signal }) => api<ExtractorsResponse>("/api/history/extractors", { signal }),
 });
}

/**
 * Replace the whole saved set. riskLocal, so api() mints no confirmation — this writes burpsy's own
 * view configuration and sends nothing. On success the server echoes the saved set (its own
 * normalisation), which seeds the cache, and the value cache is dropped so the columns refill
 * against the new definitions.
 */
export function useSaveHistoryExtractors() {
 const client = useQueryClient();
 return useMutation<ExtractorsResponse, Error, HistoryExtractor[]>({
  mutationFn: (extractors) => api<ExtractorsResponse>("/api/history/extractors", json("PUT", { extractors })),
  onSuccess: (saved) => {
   client.setQueryData(extractorKeys.defs, saved);
   void client.invalidateQueries({ queryKey: extractorKeys.valuesPrefix });
  },
 });
}

/** id -> { extractor name -> value | null }. A null is an honest "this response did not yield that
 *  value" (no match, no such header), distinct from "" which the extractor really captured. An id
 *  with no stored response is simply absent from the map. */
export type ExtractValues = Record<string, Record<string, string | null>>;

/**
 * The extractors' values for `ids`, run against each id's stored response.
 *
 * `ids` must be the caller's already-stable list (deduped, in a fixed order) of the rows it is
 * showing that HAVE a response — a row with no response yields nothing, so asking for it is wasted
 * work, and including the response presence in the id list is what makes a row that was pending and
 * later answered re-run rather than stay empty. The list is chunked at the server's per-call cap so
 * a large loaded page cannot exceed it; `signature` keys the cache to the current definitions.
 *
 * `enabled` is false when no extractor is defined — no columns, no reason to fetch. `placeholderData`
 * keeps the previous values visible while a new page loads, so scrolling or a filter edit does not
 * blank every derived cell for a beat.
 */
export function useHistoryExtractValues(
 ids: readonly number[],
 signature: string,
 enabled: boolean,
): UseQueryResult<ExtractValues> {
 const idKey = ids.join(",");
 return useQuery({
  queryKey: extractorKeys.values(signature, idKey),
  enabled: enabled && ids.length > 0,
  queryFn: async ({ signal }) => {
   const out: ExtractValues = {};
   for (let i = 0; i < ids.length; i += MAX_EXTRACT_ROWS) {
    const chunk = ids.slice(i, i + MAX_EXTRACT_ROWS);
    const res = await api<{ values: ExtractValues }>("/api/history/extract", { ...json("POST", { ids: chunk }), signal });
    Object.assign(out, res.values);
   }
   return out;
  },
  // The values are a snapshot of stored responses; they do not change unless the capture or the
  // definitions do, both of which change the key. A short stale window avoids a refetch storm while
  // the operator scrolls.
  staleTime: 30_000,
  // Keep the previous page's values visible while the next id-set loads, so scrolling or a filter
  // edit does not blank every derived cell for a beat — BUT only across an id-set change, never
  // across a DEFINITION change. The signature is queryKey[1]; when it differs, the old values are
  // about different columns, so they are dropped rather than shown stale under the new definitions.
  placeholderData: (previous, previousQuery) =>
   (previousQuery?.queryKey as readonly unknown[] | undefined)?.[1] === signature ? previous : undefined,
 });
}
