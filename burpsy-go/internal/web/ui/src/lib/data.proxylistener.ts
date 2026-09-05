/**
 * Query hooks for /api/proxy/listener — the proxy listener's bind address as the
 * accept loop actually serves it (burpsy-react-ui-77m, scope (1): one re-bindable
 * listener). GET answers the resolved host:port, so an ephemeral bind comes back
 * pointing somewhere real; PUT re-binds the listener live and answers with the
 * confirmed address and the one it moved from. The bind is not persisted: a
 * restart reverts to -proxy-bind, which the panel says in the section copy.
 *
 * The invisible-proxying switch is NOT here: it is a relay behaviour, not a socket
 * property, and it rides /api/proxy/options with the other live knobs.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

export interface ProxyListenerState {
  bind: string;
  previous_bind?: string;
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
