import { useMutation, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json, query } from "./api";
import { keys, useResource } from "./data";

/**
 * Settings → Network: per-host HTTP credentials and per-host TLS client identities.
 *
 * Every type here mirrors what the Go handlers actually serve (internal/web/api_network.go),
 * and none of them has a password or passphrase field — not because this module chose to
 * leave them out, but because the wire shapes have nowhere for one to be. A secret travels
 * to the server on a POST and is never sent back.
 */

/** One platform-authentication rule as the API serves it: redacted, in match order. */
export interface PlatformAuthRule {
  host: string;
  scheme: string;
  username: string;
  realm?: string;
  /**
   * Whether a password is stored — never its length. This is what the panel shows in place
   * of the secret: a blank field would read as "no credential configured" for a rule that is
   * in fact live.
   */
  has_password: boolean;
}

export interface PlatformAuthResponse {
  rules: PlatformAuthRule[];
  /** Distinguishes "no rules" from a failed load, which an empty array alone cannot. */
  empty: boolean;
  /** What the scheme selector may offer. Read from the server so it cannot offer one that does nothing. */
  schemes: string[];
  /** Schemes Burp has and this build does not, so the panel can say so rather than leaving an absence. */
  unsupported: string[];
  /** Whether the sender these rules reach was actually built with them. False means stored but not presented. */
  presented_on_egress: boolean;
}

/** One client-certificate binding: metadata read off the leaf, no key material. */
export interface ClientCertBinding {
  host: string;
  path: string;
  subject: string;
  issuer: string;
  not_after: string;
  /** SHA-256 of the leaf DER — the value to compare against what the server's logs say it received. */
  fingerprint: string;
  has_passphrase: boolean;
}

export interface ClientCertsResponse {
  bindings: ClientCertBinding[];
  empty: boolean;
  /** One line per persisted binding that could not be rebuilt at startup. */
  restore_failures: string[];
  /** Always false: PKCS#11 hardware tokens are out of scope, and stated rather than omitted. */
  pkcs11_supported: boolean;
  presented_on_egress: boolean;
}

export interface PlatformAuthDraft {
  host: string;
  scheme: string;
  username: string;
  password: string;
  realm?: string;
}

export interface ClientCertDraft {
  host: string;
  path: string;
  passphrase: string;
}

/* --- reads --------------------------------------------------------------- */

export const usePlatformAuth = (): UseQueryResult<PlatformAuthResponse> =>
  useResource<PlatformAuthResponse>(keys.networkAuth, "/api/network/auth");

export const useClientCerts = (): UseQueryResult<ClientCertsResponse> =>
  useResource<ClientCertsResponse>(keys.networkClientCerts, "/api/network/client-certs");

/* --- writes -------------------------------------------------------------- */

function useInvalidate(): (prefixes: readonly (readonly unknown[])[]) => void {
  const client = useQueryClient();
  return (prefixes) => {
    for (const prefix of prefixes) void client.invalidateQueries({ queryKey: prefix });
  };
}

/**
 * Add or replace one platform-authentication rule.
 *
 * The reply carries the redacted rule the server stored, not an echo of what was sent, so
 * the panel shows the rule as the engine holds it — host trimmed, scheme canonicalised —
 * rather than as it was typed.
 */
export function useSavePlatformAuth() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (draft: PlatformAuthDraft) =>
      api<{ rule: PlatformAuthRule; replaced: boolean }>("/api/network/auth", json("POST", draft)),
    onSuccess: () => invalidate([keys.networkAuth]),
  });
}

/**
 * Remove the rule with exactly this host pattern and scheme.
 *
 * Both are in the identity: (host, scheme) is what the server keys on, so removing
 * basic@example.com must not take digest@example.com with it. A pattern that is not there
 * answers 404, which surfaces as an ApiError rather than a silent success — a DELETE that
 * quietly succeeded would make a double-click look like two rules had existed.
 */
export function useDeletePlatformAuth() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: ({ host, scheme }: { host: string; scheme: string }) =>
      api<unknown>(`/api/network/auth${query({ host, scheme })}`, { method: "DELETE" }),
    onSuccess: () => invalidate([keys.networkAuth]),
  });
}

/**
 * Bind a PKCS#12 identity to a host pattern.
 *
 * The server reads and decrypts the file during this call, so a wrong passphrase or an
 * unreadable file comes back as a 400 naming which of the two it was — reported while the
 * operator is still looking at the form, rather than surfacing later as a rejected
 * handshake.
 */
export function useSaveClientCert() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (draft: ClientCertDraft) =>
      api<{ binding: ClientCertBinding; replaced: boolean }>("/api/network/client-certs", json("POST", draft)),
    onSuccess: () => invalidate([keys.networkClientCerts]),
  });
}

export function useDeleteClientCert() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (host: string) =>
      api<unknown>(`/api/network/client-certs${query({ host })}`, { method: "DELETE" }),
    onSuccess: () => invalidate([keys.networkClientCerts]),
  });
}
