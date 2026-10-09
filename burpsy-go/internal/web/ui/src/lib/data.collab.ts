/**
 * Wire shapes and query hooks for the out-of-band channels: the Collaborator
 * (interactsh) tool surface and the blind-XSS callback listener. The server owns
 * the truth — a status object that says why there is no channel counts as an
 * answer, so every hook here renders that reason rather than an empty table that
 * would read as "nothing happened".
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys } from "./data";

export interface CollaboratorPayload {
  address: string;
  marker: string;
  minted_at_ms: number;
  interactions: number;
}

export interface CollaboratorStatus {
  state: string;
  configured: boolean;
  hint?: string;
  server?: string;
  default_pool: boolean;
  domain?: string;
  /** The channel's identity is kept across restarts (d657): payloads minted here are still polled after one. */
  identity_kept: boolean;
  /** The open channel resumed an identity an earlier run saved. */
  resumed: boolean;
  payloads: CollaboratorPayload[];
  interactions: { total: number; by_type: Record<string, number> } | null;
  last_read: { at_ms: number; ok: boolean; error?: string } | null;
  gated_checks: number | null;
  polling: string;
  client: string;
}

export interface CollaboratorInteractionRow {
  id: number;
  interaction_id: string;
  type: string;
  client_ip: string;
  at_ms: number;
  q_type?: string;
  payload?: string;
  collapsed: boolean;
}

export interface CollaboratorInteractionDetail extends CollaboratorInteractionRow {
  correlation_id: string;
  client_ip_means: string;
  raw_request: string;
  raw_response: string;
}

export function useCollaboratorStatus(): ReturnType<typeof useQuery<CollaboratorStatus>> {
  return useQuery({
    queryKey: keys.collaborator,
    queryFn: ({ signal }) => api<CollaboratorStatus>("/api/collaborator/status", { signal }),
    refetchInterval: 5_000,
  });
}

export function useCollaboratorInteractions(options: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: keys.collaboratorInteractions,
    enabled: options.enabled ?? true,
    queryFn: ({ signal }) =>
      api<{ rows: CollaboratorInteractionRow[]; interactions: CollaboratorStatus["interactions"]; configured: boolean; state: string; hint?: string }>(
        "/api/collaborator/interactions",
        { signal },
      ),
    refetchInterval: 5_000,
    select: (data) => data.rows,
  });
}

export function useCollaboratorInteraction(id: number | null) {
  return useQuery({
    queryKey: [...keys.collaboratorInteractions, id],
    queryFn: ({ signal }) => api<CollaboratorInteractionDetail>(`/api/collaborator/interaction/${id}`, { signal }),
    enabled: id !== null,
  });
}

// The mint response carries the single address the old client reads plus, for a batch,
// every address and marker (burpsy-react-ui-v8q). markers is what an operator correlates a
// callback to, so the batch list is useful as text rather than just a count.
export interface CollaboratorMintResult {
  address: string;
  marker: string;
  domain?: string;
  addresses: string[];
  markers: string[];
}

// Payloads to generate: 1 by default, bounded by the server's batch ceiling.
export function useMintPayload() {
  const client = useQueryClient();
  return useMutation<CollaboratorMintResult, Error, { count?: number }>({
    mutationFn: ({ count }: { count?: number }) =>
      api<CollaboratorMintResult>("/api/collaborator/payload", json("POST", { count: count ?? 1 })),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.collaborator }),
  });
}

/**
 * Point this installation at an interaction server without restarting it — Burp's
 * `configPanelCollaboratorServer`.
 *
 * The capability was real and reachable only from the command line, so an operator who started
 * burpsy without `-collaborator-server` had every out-of-band check refuse for the rest of the
 * session, with a restart — and the loss of their captured traffic — as the only remedy.
 *
 * `server` takes an interaction-server URL or the literal `"public"` for interactsh's own pool,
 * matching the flag. An empty string is refused by the server rather than silently meaning
 * "public": a blank box is much more likely to be an accident than a decision to send out-of-band
 * traffic to a public third party.
 *
 * Returns the fresh status rather than a bare ok, and the distinction is the point: 200 means
 * *configured*, never *reachable*. The provider is lazy, so whether the server answers and whether
 * the interactsh-client binary can be found are only discovered when a payload is first minted.
 *
 * Expect a 409 when a channel has already registered a domain — see the comment on the button.
 */
export function useSetCollaboratorServer() {
  const client = useQueryClient();
  return useMutation<CollaboratorStatus, Error, { server: string; client_path?: string }>({
    mutationFn: (body) => api<CollaboratorStatus>("/api/collaborator/server", json("POST", body)),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.collaborator });
      void client.invalidateQueries({ queryKey: keys.collaboratorInteractions });
    },
  });
}

/** One row of Burp's "Run health check" (burpsy-react-ui-8e3n), under Burp's own label. */
export interface CollaboratorHealthItem {
  name: string;
  protocol: "dns" | "http" | "smtp";
  /** A capture row can also be "not_triggered": every trigger for the protocol failed, so nothing was sent. */
  status: "ok" | "error" | "not_triggered";
  detail: string;
  /** Null when the item did not complete. */
  latency_ms: number | null;
}

export interface CollaboratorHealthReport {
  /** Decided by the capture rows: did each protocol's interaction come back through polling. */
  status: "healthy" | "degraded" | "failed";
  summary: string;
  server?: string;
  domain: string;
  address: string;
  connections: CollaboratorHealthItem[];
  captures: CollaboratorHealthItem[];
  waited_ms: number;
  polling: string;
}

/** POST /api/collaborator/health. It may register the channel (an explicit click) and takes up to ~30s. */
export function useCollaboratorHealth() {
  const client = useQueryClient();
  return useMutation<CollaboratorHealthReport, Error>({
    mutationFn: () => api<CollaboratorHealthReport>("/api/collaborator/health", json("POST", {})),
    onSettled: () => void client.invalidateQueries({ queryKey: keys.collaborator }),
  });
}

export interface CollaboratorUnsetResult {
  status: CollaboratorStatus;
  orphaned_payloads: number;
  was_configured: boolean;
  closed_domain?: string;
  close_error?: string;
}

/**
 * Burp's "Don't use Burp Collaborator" (8e3n): DELETE /api/collaborator/server. With a registered
 * channel the server answers 409 unless `discardOpenChannel` is set, because the payloads minted from it
 * would point at a server nobody polls. The caller asks the operator first.
 */
export function useUnsetCollaboratorServer() {
  const client = useQueryClient();
  return useMutation<CollaboratorUnsetResult, Error, { discardOpenChannel: boolean }>({
    mutationFn: ({ discardOpenChannel }) =>
      api<CollaboratorUnsetResult>(
        "/api/collaborator/server",
        json("DELETE", discardOpenChannel ? { discard_open_channel: true } : {}),
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.collaborator });
      void client.invalidateQueries({ queryKey: keys.collaboratorInteractions });
    },
  });
}

export function usePollNow() {
  const client = useQueryClient();
  return useMutation<{ interactions: number }, Error>({
    mutationFn: () => api<{ interactions: number }>("/api/collaborator/poll", json("POST", {})),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.collaborator });
      void client.invalidateQueries({ queryKey: keys.collaboratorInteractions });
    },
  });
}

/**
 * A callback as the listener records it. Field names follow blindxss.Hit's json tags —
 * including the camelCase ones, which deliberately differ from the snake_case used
 * elsewhere because they are the payload script's own report vocabulary. ReceivedAt is a
 * RFC 3339 string on the wire.
 */
export interface BlindXSSHit {
  token: string;
  cookies: string;
  dom: string;
  truncated: boolean;
  location: string;
  referrer: string;
  userAgent: string;
  headerUserAgent: string;
  remoteAddress: string;
  receivedAt: string;
}

export interface BlindXSSPayload {
  token: string;
  script_url: string;
  script_tag: string;
  minted_at: string;
  outstanding: boolean;
  hits: BlindXSSHit[];
}

export interface BlindXSSState {
  configured: boolean;
  listening: boolean;
  reason?: string;
  addr?: string;
  base_url?: string;
  payloads: BlindXSSPayload[];
  counts: { payloads: number; hits: number; fired: number; outstanding: number };
  verdict: string;
}

export function useBlindXSS(): ReturnType<typeof useQuery<BlindXSSState>> {
  return useQuery({
    queryKey: keys.blindxss,
    queryFn: ({ signal }) => api<BlindXSSState>("/api/blindxss", { signal }),
    refetchInterval: 5_000,
  });
}

export function useMintBlindXSSPayload() {
  const client = useQueryClient();
  // The mint endpoint answers { payload, base_url, caveat } rather than the payload
  // itself; only the payload is needed here, and the caveat is rendered by the state
  // poll that follows.
  return useMutation<{ payload: BlindXSSPayload }, Error>({
    mutationFn: () => api<{ payload: BlindXSSPayload }>("/api/blindxss/payload", json("POST", {})),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.blindxss }),
  });
}
