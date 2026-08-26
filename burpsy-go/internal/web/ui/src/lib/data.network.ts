/**
 * Query hooks for /api/network/settings — Burp's Settings → Network, live.
 *
 * PUT is a partial patch over the nested document: a section the body omits is
 * untouched, a key a section omits is untouched. That shape is why the panel
 * sends `{timeouts: {read_ms: 4000}}` rather than the whole settings object —
 * a full-document PUT from a stale cache would silently revert a change made
 * in another tab, and the server cannot tell the difference.
 *
 * The mutation writes the server's confirmed answer into the cache rather than
 * the draft it sent, so the panel only ever shows a state the sender has
 * actually entered. An unknown key is a 400 naming the key, and the error text
 * is surfaced verbatim: the server's refusals name the field and the limit, and
 * flattening them into "save failed" would throw away the only thing that
 * tells the operator what to fix.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

export type ResolutionPolicy = "system" | "resolver";
export type RedirectMode = "never" | "on_site" | "in_scope" | "always";

export interface HostOverride {
  host: string;
  address: string;
  enabled: boolean;
}

export interface NetworkSettings {
  resolution: {
    overrides: HostOverride[] | null;
    policy: ResolutionPolicy;
    resolver: string;
    timeout_ms: number;
  };
  timeouts: {
    connect_ms: number;
    read_ms: number;
    total_ms: number;
  };
  redirects: {
    mode: RedirectMode;
    max_hops: number;
  };
  continue: {
    understand_100_continue: boolean;
    remove_expect_header: boolean;
    expect_continue_timeout_ms: number;
  };
  streaming: {
    hosts: string[] | null;
    timeout_ms: number;
  };
}

/** What the server will accept, travelling with the state so the panel does not hardcode the arms. */
export interface NetworkAccepted {
  resolution_policies: ResolutionPolicy[];
  redirect_modes: RedirectMode[];
  max_timeout_ms: number;
  max_redirect_hops: number;
  max_host_overrides: number;
  max_streaming_hosts: number;
  keys: string[];
}

export interface NetworkSettingsState {
  settings: NetworkSettings;
  accepted: NetworkAccepted;
}

/**
 * A patch is a partial of the document, two levels deep. Typed as a deep partial
 * rather than `Record<string, unknown>` so a misspelled section or key fails at
 * the call site instead of coming back as a 400 the operator has to read.
 */
export type NetworkPatch = {
  [S in keyof NetworkSettings]?: Partial<NetworkSettings[S]>;
};

export function useNetworkSettings(): ReturnType<typeof useQuery<NetworkSettingsState>> {
  return useQuery({
    queryKey: keys.networkSettings,
    queryFn: ({ signal }) => api<NetworkSettingsState>("/api/network/settings", { signal }),
  });
}

export function useSaveNetworkSettings() {
  const client = useQueryClient();
  return useMutation<NetworkSettingsState, Error, NetworkPatch>({
    mutationFn: (patch) => api<NetworkSettingsState>("/api/network/settings", json("PUT", patch)),
    // The confirmed answer, not the draft: the server normalises (hostnames lowercased, a zero hop
    // count filled with the default) so what it returns can differ from what was sent, and the panel
    // has to show the difference rather than hide it.
    onSuccess: (confirmed) => client.setQueryData(keys.networkSettings, confirmed),
  });
}

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
