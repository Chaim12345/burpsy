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
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useInvalidate, useResource } from "./data";
import type { NetworkProxyUpdate, NetworkProxyView } from "./types.policy";

export type ResolutionPolicy = "system" | "resolver";
/** Which address family a resolved host is filtered to. `system` is the resolver's own order. */
export type AddressFamily = "system" | "ipv4" | "ipv6";
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
    /**
     * Which address family a hostname's answer is filtered to. `system` leaves the resolver's order
     * alone, which is the default: that order encodes the machine's own routing preferences.
     *
     * `null` on a document written before the field existed — a panel must not read `ipv4` off a
     * missing key, nor infer a preference the operator never set.
     */
    family: AddressFamily | null;
  };
  timeouts: {
    connect_ms: number;
    read_ms: number;
    total_ms: number;
  };
  redirects: {
    mode: RedirectMode;
    max_hops: number;
    /**
     * Whether a followed chain resubmits the cookies each hop's response set (Burp's "Follow
     * redirections and resubmit cookies"). Off by default: a cookie the target set mid-chain is not
     * something the operator asked to send. `null` on a document written before the field existed,
     * so a panel must not read `false` off a missing key and claim the operator declined it.
     */
    replay_cookies?: boolean | null;
    /**
     * Burp's "Allowed redirect types": which responses count as a redirect to follow. The server
     * always answers the types in force, Burp's defaults included. JavaScript-driven is refused if
     * set: following it would mean running the page's script.
     */
    types?: RedirectTypes;
  };
  /**
   * Burp's project-wide protocol defaults. The server always answers them, Burp's defaults
   * included: keep-alive off, HTTP/2 on.
   */
  http1?: { enable_keep_alive: boolean };
  http2?: { enable_http2: boolean };
  continue: {
    understand_100_continue: boolean;
    remove_expect_header: boolean;
    expect_continue_timeout_ms: number;
  };
  streaming: {
    hosts: string[] | null;
    timeout_ms: number;
    /**
     * Burp's streaming_responses switches (burpsy-react-ui-609d / -v52t). `store` is optional on the wire:
     * absent means ON (a document saved before the switch existed), so a panel must read a missing key as
     * on — never as the operator having turned storage off.
     */
    store?: boolean | null;
    strip_chunked_encoding_metadata?: boolean;
    use_text_event_stream_header?: boolean;
  };
  /**
   * How the certificate the TARGET presents is treated. `verify` defaults to true and was false on
   * every intercepted connection before burpsy-react-ui-f365, with nothing anywhere able to change it.
   */
  tls: {
    verify: boolean;
    /** PEM bundle added to the system pool, so a private issuer is reachable without turning verification off. */
    root_ca_path: string;
    /** The lowest TLS version accepted, as a version number. 0 means Go's default. */
    min_version: number;
  };
}

/** What the server will accept, travelling with the state so the panel does not hardcode the arms. */
export interface NetworkAccepted {
  resolution_policies: ResolutionPolicy[];
  /** Read from the engine, so the selector can only offer a family the server accepts. */
  resolution_families: AddressFamily[];
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

export interface RedirectTypes {
  understand_3xx_status_code: boolean;
  understand_any_status_code_with_location_header: boolean;
  understand_refresh_header: boolean;
  understand_meta_refresh_tag: boolean;
  understand_javascript_driven: boolean;
}

/** Burp's shipped defaults, for a document from a server that predates the types. */
export const DEFAULT_REDIRECT_TYPES: RedirectTypes = {
  understand_3xx_status_code: true,
  understand_any_status_code_with_location_header: false,
  understand_refresh_header: true,
  understand_meta_refresh_tag: true,
  understand_javascript_driven: false,
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
