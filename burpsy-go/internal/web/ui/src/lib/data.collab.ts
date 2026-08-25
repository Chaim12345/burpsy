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

export function useCollaboratorInteractions() {
  return useQuery({
    queryKey: keys.collaboratorInteractions,
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

export function useMintPayload() {
  const client = useQueryClient();
  return useMutation<CollaboratorPayload, Error>({
    mutationFn: () => api<CollaboratorPayload>("/api/collaborator/payload", json("POST", {})),
    onSuccess: () => void client.invalidateQueries({ queryKey: keys.collaborator }),
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
