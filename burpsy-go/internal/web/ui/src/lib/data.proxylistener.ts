/**
 * Query hooks for /api/proxy/listener — the proxy's listeners as the accept loops actually
 * serve them.
 *
 * Scope (1) of burpsy-react-ui-77m was one re-bindable listener; burpsy-react-ui-pfeg made it
 * Burp's collection: a list of listeners, each with its own redirect target, force-TLS and
 * invisible-proxying setting. GET answers both — `bind`/`previous_bind` for the boot listener
 * the legacy panel reports, and `listeners` for the whole set with every address resolved, so
 * an ephemeral bind comes back pointing somewhere real.
 *
 * The collection is addressed by ?id= on this one route rather than by /api/proxy/listeners/{id}:
 * the Go mux registers this path as an exact match, in a file that change did not own. The Go
 * side documents the same thing at the top of api_proxylistener.go.
 *
 * Nothing here is persisted. A restart reverts to -proxy-bind and a single listener, which the
 * panel says in its section copy.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

/** One listener. `invisible` is nullable on purpose: null means "inherit the process-wide
 * invisible-proxying switch", which is what the boot listener is, and is what lets the panel
 * tell "inherit" apart from an explicit off. */
export interface ProxyListenerRow {
  id: string;
  bind: string;
  bound_addr: string;
  redirect_host: string;
  redirect_port: number;
  force_tls: boolean;
  invisible: boolean | null;
  removable: boolean;
}

export interface ProxyListenerState {
  bind: string;
  previous_bind?: string;
  listeners: ProxyListenerRow[];
}

/** The fields a POST or an id-addressed PUT carries. */
export interface ProxyListenerBody {
  bind: string;
  redirect_host: string;
  redirect_port: number;
  force_tls: boolean;
  invisible: boolean | null;
}

export function useProxyListener(): ReturnType<typeof useQuery<ProxyListenerState>> {
  return useQuery({
    queryKey: keys.proxyListener,
    queryFn: ({ signal }) => api<ProxyListenerState>("/api/proxy/listener", { signal }),
    refetchInterval: 4_000,
  });
}

export function useRebindProxyListener() {
  const client = useQueryClient();
  return useMutation<ProxyListenerState, Error, string>({
    mutationFn: (bind) => api<ProxyListenerState>("/api/proxy/listener", json("PUT", { bind })),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.proxyListener }),
  });
}

export function useAddProxyListener() {
  const client = useQueryClient();
  return useMutation<ProxyListenerRow, Error, ProxyListenerBody>({
    mutationFn: (body) => api<ProxyListenerRow>("/api/proxy/listener", json("POST", body)),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.proxyListener }),
  });
}

export function useUpdateProxyListener() {
  const client = useQueryClient();
  return useMutation<ProxyListenerRow, Error, { id: string; body: ProxyListenerBody }>({
    mutationFn: ({ id, body }) =>
      api<ProxyListenerRow>(`/api/proxy/listener?id=${encodeURIComponent(id)}`, json("PUT", body)),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.proxyListener }),
  });
}

export function useRemoveProxyListener() {
  const client = useQueryClient();
  return useMutation<ProxyListenerState, Error, string>({
    mutationFn: (id) =>
      api<ProxyListenerState>(`/api/proxy/listener?id=${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.proxyListener }),
  });
}
