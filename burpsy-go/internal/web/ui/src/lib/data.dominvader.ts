// The operator-side DOM auditor (burpsy-react-ui-wl94), served by internal/web/api_dominvader.go at
// /api/dominvader (GET/PUT) and /api/dominvader/hits (DELETE). The browser extension reports hits to
// /api/dominvader/hit, which the console never calls.

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";

/** One reported flow: the canary seen in a source, or reaching a sink. */
export interface DomInvaderHit {
 id: number;
 /** "source" (the canary entered the page) or "sink" (it reached a sink). */
 kind: "source" | "sink";
 /** The sink tag for a sink hit, or the source name for a source hit. */
 sink: string;
 /** The browser-readable sources carrying the canary when the hit fired. */
 sources: string[];
 /** The value around the canary, bounded. */
 excerpt: string;
 /** The JS stack at the sink. */
 stack: string;
 url: string;
 frame: string;
 ts: number;
 received_unix_ms: number;
}

export interface DomInvaderView {
 canary: string;
 enabled: boolean;
 hits: DomInvaderHit[];
 report_url: string;
 launch_note: string;
}

const domInvaderKey = ["dominvader"] as const;

export function useDomInvader(): UseQueryResult<DomInvaderView> {
 return useQuery({
  queryKey: domInvaderKey,
  queryFn: ({ signal }) => api<DomInvaderView>("/api/dominvader", { signal }),
 });
}

export function useSetDomInvader() {
 const client = useQueryClient();
 return useMutation<DomInvaderView, Error, { canary?: string; enabled?: boolean }>({
  mutationFn: (body) => api<DomInvaderView>("/api/dominvader", json("PUT", body)),
  onSuccess: (view) => client.setQueryData(domInvaderKey, view),
 });
}

export function useClearDomInvaderHits() {
 const client = useQueryClient();
 return useMutation<void, Error, void>({
  mutationFn: () => api<void>("/api/dominvader/hits", json("DELETE")),
  onSuccess: () => void client.invalidateQueries({ queryKey: domInvaderKey }),
 });
}
