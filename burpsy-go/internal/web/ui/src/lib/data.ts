import { QueryClient, useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { create } from "zustand";
import { api, json, query } from "./api";
import type {
  Dashboard,
  Exchange,
  InterceptState,
  Issues,
  MatchReplaceConfig,
  MatchReplaceResponse,
  MessageView,
  OrganizerItem,
  Scope,
  SessionRule,
  SessionRules,
  SiteMap,
  Stats,
  ToolLog,
  WsConnection,
  WsHistory,
  WsMessage,
} from "./types";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The API is on localhost: retries mostly hide real errors, and window-focus
      // refetching fights the SSE stream that already tells us what changed.
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 2_000,
      gcTime: 5 * 60_000,
    },
  },
});

export const keys = {
  stats: ["stats"] as const,
  scope: ["scope"] as const,
  dashboard: ["dashboard"] as const,
  history: (q: string, limit: number) => ["history", q, limit] as const,
  message: (id: number) => ["message", id] as const,
  exchange: (id: number) => ["exchange", id] as const,
  issues: ["issues"] as const,
  intercept: ["intercept"] as const,
  sitemap: ["sitemap"] as const,
  crawls: ["crawls"] as const,
  wsConnections: ["ws", "connections"] as const,
  wsHistory: (exchange: number) => ["ws", "history", exchange] as const,
  wsMessage: (id: number) => ["ws", "message", id] as const,
  toolLog: (filter: string, search: string) => ["toollog", filter, search] as const,
  organizer: ["organizer"] as const,
  rules: ["rules"] as const,
  sessionRules: ["session", "rules"] as const,
  sessionCookies: ["session", "cookies"] as const,
  protocols: ["protocols"] as const,
  scannerConfigs: ["scanner", "configs"] as const,
  scannerCoverage: ["scanner", "coverage"] as const,
  scannerLive: ["scanner", "live"] as const,
  networkProxy: ["network", "proxy"] as const,
};

/**
 * Which caches a server event invalidates. Keys are prefixes, so one entry
 * covers every parameterised variant of a resource.
 */
const INVALIDATION: Record<string, string[][]> = {
  history: [["history"], ["stats"], ["sitemap"], ["dashboard"]],
  capture: [["history"], ["stats"], ["sitemap"], ["dashboard"]],
  issues: [["issues"], ["dashboard"], ["scanner"]],
  scanner: [["issues"], ["dashboard"], ["scanner"]],
  toollog: [["toollog"], ["dashboard"]],
  dashboard: [["dashboard"]],
  task: [["dashboard"]],
  tasks: [["dashboard"]],
  ws: [["ws"], ["stats"], ["dashboard"]],
  intercept: [["intercept"]],
  scope: [["scope"]],
  session: [["session"]],
  sitemap: [["sitemap"], ["dashboard"]],
  organizer: [["organizer"]],
  rules: [["rules"]],
};

const FALLBACK: string[][] = [["dashboard"], ["stats"]];

interface ConnectionState {
  live: boolean;
  lastEventAt: number | null;
  eventCount: number;
  setLive: (live: boolean) => void;
  noteEvent: () => void;
}

export const useConnection = create<ConnectionState>((set) => ({
  live: false,
  lastEventAt: null,
  eventCount: 0,
  setLive: (live) => set({ live }),
  noteEvent: () => set((state) => ({ lastEventAt: Date.now(), eventCount: state.eventCount + 1 })),
}));

/**
 * Single server-sent-events subscription for the whole console.
 *
 * Bursts are coalesced into one invalidation pass: a crawl can emit hundreds of
 * frames a second, and invalidating per frame turned the stream into a request
 * storm in the previous implementation.
 */
export function useEventStream(): void {
  const client = useQueryClient();
  const setLive = useConnection((state) => state.setLive);
  const noteEvent = useConnection((state) => state.noteEvent);

  useEffect(() => {
    let stream: EventSource | null = null;
    let flushTimer: number | null = null;
    let retryTimer: number | null = null;
    let closed = false;
    const pending = new Set<string>();

    const flush = () => {
      flushTimer = null;
      const kinds = [...pending];
      pending.clear();
      const prefixes = new Set<string>();
      for (const kind of kinds) {
        for (const key of INVALIDATION[kind] ?? FALLBACK) prefixes.add(JSON.stringify(key));
      }
      for (const prefix of prefixes) {
        void client.invalidateQueries({ queryKey: JSON.parse(prefix) as string[] });
      }
    };

    const connect = () => {
      if (closed) return;
      stream = new EventSource("/api/events");

      stream.onopen = () => setLive(true);

      stream.onmessage = (event) => {
        setLive(true);
        let kind = "";
        try {
          const frame = JSON.parse(event.data) as { kind?: string };
          kind = frame.kind ?? "";
        } catch {
          // A malformed frame still proves the stream is alive; treat it as a
          // generic change rather than dropping it silently.
        }
        if (kind === "hello" || kind === "ping") return;
        noteEvent();
        pending.add(kind);
        if (flushTimer === null) flushTimer = window.setTimeout(flush, 350);
      };

      stream.onerror = () => {
        setLive(false);
        stream?.close();
        stream = null;
        // EventSource retries on its own only for some failures; an explicit
        // backoff keeps the badge honest and recovers after a server restart.
        if (!closed && retryTimer === null) {
          retryTimer = window.setTimeout(() => {
            retryTimer = null;
            connect();
          }, 3_000);
        }
      };
    };

    connect();

    return () => {
      closed = true;
      if (flushTimer !== null) window.clearTimeout(flushTimer);
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      stream?.close();
      setLive(false);
    };
  }, [client, setLive, noteEvent]);
}

/** Debounce a fast-changing value (search boxes) so we do not fetch per keystroke. */
export function useDebounced<T>(value: T, delayMs = 250): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);
  return settled;
}

/**
 * Shared read hook. Area-specific modules (data.observe.ts, data.attack.ts, …)
 * build on this so concurrent work does not all land in one file.
 */
export function useResource<T>(key: readonly unknown[], url: string, enabled = true): UseQueryResult<T> {
  return useQuery({
    queryKey: key,
    // The signal makes an in-flight request abort when the key changes, so a
    // slow earlier response can never overwrite a newer one.
    queryFn: ({ signal }) => api<T>(url, { signal }),
    enabled,
  });
}

/* --- reads --------------------------------------------------------------- */

export const useStats = () => useResource<Stats>(keys.stats, "/api/stats");
export const useScope = () => useResource<Scope>(keys.scope, "/api/scope");
export const useDashboard = () => useResource<Dashboard>(keys.dashboard, "/api/dashboard");
export const useIssues = () => useResource<Issues>(keys.issues, "/api/issues");
export const useSitemap = () => useResource<SiteMap>(keys.sitemap, "/api/sitemap");
export const useOrganizer = () => useResource<{ items: OrganizerItem[] }>(keys.organizer, "/api/tools/organizer");
export const useMatchReplace = () => useResource<MatchReplaceResponse>(keys.rules, "/api/tools/rules");
export const useSessionRules = () => useResource<SessionRules>(keys.sessionRules, "/api/session/rules");
export const useWsConnections = () => useResource<WsConnection[]>(keys.wsConnections, "/api/ws/connections");

export const useHistory = (q: string, limit = 500) =>
  useResource<Exchange[]>(keys.history(q, limit), `/api/history${query({ limit, q })}`);

// `id >= 0`, not `id > 0`: the stores are position-is-the-id counters from zero, so message 0,
// exchange 0 and ws message 0 are all real rows. Guarding on `> 0` disabled the fetch for the
// first thing ever captured, and the editor rendered "No request bytes captured" for a message
// the server would have served — visible on the very first exchange of a fresh session.
export const useMessage = (id: number | null | undefined) =>
  useResource<MessageView>(keys.message(id ?? -1), `/api/message/${id ?? 0}`, typeof id === "number" && id >= 0);

export const useWsHistory = (exchange: number | null | undefined, limit = 500) =>
  useResource<WsHistory>(
    keys.wsHistory(exchange ?? -1),
    `/api/ws/history${query({ exchange: exchange ?? 0, limit })}`,
    typeof exchange === "number",
  );

export const useWsMessage = (id: number | null | undefined) =>
  useResource<WsMessage>(keys.wsMessage(id ?? -1), `/api/ws/message/${id ?? 0}`, typeof id === "number" && id >= 0);

export const useToolLog = (filter: string, search: string, limit = 300) =>
  useResource<ToolLog>(keys.toolLog(filter, search), `/api/tools/log${query({ limit, filter, search })}`);

/**
 * Intercept is the one resource that still polls: held messages must appear
 * within a beat of being trapped even if the event stream is unavailable.
 */
export function useIntercept(pollMs = 1_500): UseQueryResult<InterceptState> {
  return useQuery({
    queryKey: keys.intercept,
    queryFn: ({ signal }) => api<InterceptState>("/api/intercept", { signal }),
    refetchInterval: pollMs,
    staleTime: 0,
  });
}

/* --- writes -------------------------------------------------------------- */

/** Invalidate by key prefix after a mutation lands. */
export function useInvalidate(): (prefixes: readonly (readonly unknown[])[]) => void {
  const client = useQueryClient();
  return (prefixes) => {
    for (const prefix of prefixes) void client.invalidateQueries({ queryKey: prefix });
  };
}

export function useSaveMatchReplace() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (config: MatchReplaceConfig) => api<unknown>("/api/tools/rules", json("PUT", config)),
    onSuccess: () => invalidate([keys.rules]),
  });
}

export function useSaveSessionRule() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (rule: SessionRule) =>
      rule.id === undefined
        ? api<{ rule: SessionRule }>("/api/session/rules", json("POST", rule))
        : api<{ rule: SessionRule }>(`/api/session/rules/${rule.id}`, json("PUT", rule)),
    onSuccess: () => invalidate([["session"]]),
  });
}

export function useDeleteSessionRule() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (id: number) => api<unknown>(`/api/session/rules/${id}`, { method: "DELETE" }),
    onSuccess: () => invalidate([["session"]]),
  });
}

export function useOrganizerMutations() {
  const invalidate = useInvalidate();
  const done = () => invalidate([keys.organizer]);
  return {
    add: useMutation({
      mutationFn: (exchange: number) => api<OrganizerItem>("/api/tools/organizer", json("POST", { exchange })),
      onSuccess: done,
    }),
    save: useMutation({
      mutationFn: (item: OrganizerItem) => api<unknown>(`/api/tools/organizer/${item.id}`, json("POST", item)),
      onSuccess: done,
    }),
    remove: useMutation({
      mutationFn: (id: number) => api<unknown>(`/api/tools/organizer/${id}`, { method: "DELETE" }),
      onSuccess: done,
    }),
  };
}

/**
 * PATCH /api/exchange/:id (UX-15). `notes: undefined` leaves notes untouched, matching the Go
 * handler's "omitted field is unchanged" contract; pass `notes: null` explicitly to clear it.
 * Invalidates `keys.history` so every open history query (any filter/limit) refetches and picks up
 * the new highlight/notes on its next render, the same prefix-invalidation shape `useOrganizerMutations`
 * uses for `keys.organizer`.
 */
export function useAnnotateExchange() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: ({ id, notes, highlight }: { id: number; notes?: string | null; highlight?: string }) =>
      api<Exchange>(`/api/exchange/${id}`, json("PATCH", { notes, highlight })),
    // ["history"] is a prefix: it matches keys.history(q, limit) for every q/limit combination in
    // the cache, the same pattern the server-push INVALIDATION map above already uses.
    onSuccess: () => invalidate([["history"]]),
  });
}

export function useClearToolLog() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: () => api<unknown>("/api/tools/log", { method: "DELETE" }),
    onSuccess: () => invalidate([["toollog"], keys.dashboard]),
  });
}

export function useInterceptControls() {
  const invalidate = useInvalidate();
  const done = () => invalidate([keys.intercept]);
  return {
    setEnabled: useMutation({
      mutationFn: (enabled: boolean) => api<unknown>("/api/intercept/enable", json("POST", { enabled })),
      onSuccess: done,
    }),
    forward: useMutation({
      mutationFn: ({ id, raw }: { id: number; raw: string }) =>
        api<unknown>(`/api/intercept/${id}/forward`, json("POST", { raw, fix_content_length: true })),
      onSuccess: done,
    }),
    drop: useMutation({
      mutationFn: (id: number) =>
        api<unknown>(`/api/intercept/${id}/drop`, json("POST", { reason: "dropped by operator" })),
      onSuccess: done,
    }),
  };
}
