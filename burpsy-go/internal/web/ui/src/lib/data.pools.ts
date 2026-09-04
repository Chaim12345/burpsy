/**
 * Query hooks for /api/pools and /api/schedules — Burp's resource-pool and
 * scheduled-task panels.
 *
 * Every mutation answers with the whole confirmed state, so each hook writes
 * that answer straight into the cache rather than refetching: the panel then
 * renders what the server confirmed, never an optimistic guess. A pool decides
 * how hard every tool that names it may hit the target, so a panel showing
 * limits the engine is not in is the one failure worth designing against.
 *
 * `support` and `unhonoured_bounds` are why the GET is more than a list: the
 * crawler cannot honour a pool's concurrency ceiling (its loop is sequential),
 * and that exception is served as data so the console can state it instead of
 * leaving an operator to infer it.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

export interface PoolThrottle {
  increment_ms: number;
  statuses?: number[];
  after?: number;
  recover_after?: number;
}

export interface Pool {
  name: string;
  max_concurrent: number;
  delay_ms: number;
  /** Absent or null is automatic throttling off. */
  throttle?: PoolThrottle | null;
}

/** Which of a pool's three bounds one tool path actually enforces. */
export interface PoolSupport {
  tool: string;
  route: string;
  max_concurrent: boolean;
  delay: boolean;
  throttle: boolean;
  /** Why any of the three above is false. Empty only when all three are true. */
  detail?: string;
}

export interface PoolsState {
  pools: Pool[];
  count: number;
  /** What a New dialog opens on, served so the console cannot drift from it. */
  default: Pool;
  support: PoolSupport[];
  unhonoured_bounds: number;
  /** Pool name to the schedules referencing it: why a delete can be refused. */
  in_use: Record<string, string[]>;
}

export interface Schedule {
  name: string;
  kind: string;
  enabled: boolean;
  first_ms: number;
  interval_secs: number;
  pool?: string;
  params?: unknown;
  next_ms: number;
  last_run_ms: number;
  runs: number;
  /** A subset of runs: fired and returned an error. Both are needed — 30 runs
   * with 30 failures is a schedule failing every night, and either number on
   * its own reads as healthy. */
  failures: number;
  missed: number;
  last_note?: string;
}

export interface SchedulesState {
  schedules: Schedule[];
  count: number;
  kinds: string[];
  pools: string[];
  totals: { fired: number; failed: number; missed: number; unstarted: number };
  missed_window_policy: string;
  /** Whether anything is consulting the clock. False means nothing can fire. */
  running: boolean;
}

export function usePools(): ReturnType<typeof useQuery<PoolsState>> {
  return useQuery({
    queryKey: keys.pools,
    queryFn: ({ signal }) => api<PoolsState>("/api/pools", { signal }),
  });
}

export function useSavePool() {
  const client = useQueryClient();
  return useMutation<PoolsState, Error, Pool>({
    mutationFn: (pool) => api<PoolsState>("/api/pools", json("POST", pool)),
    onSuccess: (state) => client.setQueryData(keys.pools, state),
  });
}

export function useUpdatePool() {
  const client = useQueryClient();
  return useMutation<PoolsState, Error, { name: string; pool: Pool }>({
    // The path names the pool to replace and the body says what it becomes, so
    // the two may differ: that is how a rename is expressed.
    mutationFn: ({ name, pool }) =>
      api<PoolsState>(`/api/pools/${encodeURIComponent(name)}`, json("PUT", pool)),
    onSuccess: (state) => client.setQueryData(keys.pools, state),
  });
}

export function useDeletePool() {
  const client = useQueryClient();
  return useMutation<PoolsState, Error, string>({
    mutationFn: (name) => api<PoolsState>(`/api/pools/${encodeURIComponent(name)}`, { method: "DELETE" }),
    onSuccess: (state) => client.setQueryData(keys.pools, state),
  });
}

export function useSchedules(): ReturnType<typeof useQuery<SchedulesState>> {
  return useQuery({
    queryKey: keys.schedules,
    queryFn: ({ signal }) => api<SchedulesState>("/api/schedules", { signal }),
    // Polled, unlike pools: a schedule's counters move on their own when the
    // clock fires one, and there is no change event for it.
    refetchInterval: 15_000,
  });
}

export function useSaveSchedule() {
  const client = useQueryClient();
  return useMutation<SchedulesState, Error, Partial<Schedule>>({
    mutationFn: (schedule) => api<SchedulesState>("/api/schedules", json("POST", schedule)),
    onSuccess: (state) => {
      client.setQueryData(keys.schedules, state);
      // A new schedule changes which pools are referenced, and therefore which
      // can be deleted.
      void client.invalidateQueries({ queryKey: keys.pools });
    },
  });
}

export function useUpdateSchedule() {
  const client = useQueryClient();
  return useMutation<SchedulesState, Error, { name: string; schedule: Partial<Schedule> }>({
    mutationFn: ({ name, schedule }) =>
      api<SchedulesState>(`/api/schedules/${encodeURIComponent(name)}`, json("PUT", schedule)),
    onSuccess: (state) => {
      client.setQueryData(keys.schedules, state);
      void client.invalidateQueries({ queryKey: keys.pools });
    },
  });
}

export function useDeleteSchedule() {
  const client = useQueryClient();
  return useMutation<SchedulesState, Error, string>({
    mutationFn: (name) =>
      api<SchedulesState>(`/api/schedules/${encodeURIComponent(name)}`, { method: "DELETE" }),
    onSuccess: (state) => {
      client.setQueryData(keys.schedules, state);
      void client.invalidateQueries({ queryKey: keys.pools });
    },
  });
}
