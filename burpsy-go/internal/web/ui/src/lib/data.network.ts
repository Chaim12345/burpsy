import { useMutation, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useInvalidate, useResource } from "./data";
import type { NetworkProxyUpdate, NetworkProxyView } from "./types.policy";

/**
 * The upstream proxy / SOCKS chain (Unit 9), for the Settings panel.
 *
 * Every write here re-reads the whole view rather than patching the cache: the
 * server's response *is* the new state, and it carries fields no client-side
 * merge could reproduce — `attached`, `empty`, and the redacted `proxy` renderings.
 * Guessing at those is how a panel starts claiming coverage the server never
 * reported.
 */
export const useNetworkProxy = (): UseQueryResult<NetworkProxyView> =>
  useResource<NetworkProxyView>(keys.networkProxy, "/api/network/proxy");

/** POST /api/network/proxy — upsert a rule by pattern, and/or replace the default. */
export function useSaveNetworkProxy() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (update: NetworkProxyUpdate) =>
      api<NetworkProxyView>("/api/network/proxy", json("POST", update)),
    onSuccess: () => invalidate([keys.networkProxy]),
  });
}

/**
 * DELETE /api/network/proxy?pattern=… — exact-match removal.
 *
 * The server answers 404 when no rule carries the pattern, and that error is
 * deliberately allowed to surface: a double-clicked remove should say "no such
 * rule" rather than quietly succeeding, which would make one rule look like two.
 */
export function useRemoveNetworkProxyRule() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (pattern: string) =>
      api<NetworkProxyView>(`/api/network/proxy?pattern=${encodeURIComponent(pattern)}`, {
        method: "DELETE",
      }),
    onSuccess: () => invalidate([keys.networkProxy]),
  });
}

/** DELETE /api/network/proxy?all=true — drop every rule and the default. */
export function useClearNetworkProxy() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: () => api<NetworkProxyView>("/api/network/proxy?all=true", { method: "DELETE" }),
    onSuccess: () => invalidate([keys.networkProxy]),
  });
}
