import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
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
 /** Set on a rule whose scheme is a weak downgrade (ntlmv1): shown on the row where it is configured. */
 warning?: string;
}

/** One host where a weak handshake (every NTLMv1 one, opted into on the rule) was performed. */
export interface PlatformAuthWarning {
 host: string;
 /** "NTLMv1" or "NTLMv1 (ESS)". */
 scheme: string;
 /** The header it travelled in: "NTLM" or "Negotiate". */
 wire: string;
 warning: string;
 count: number;
 first_seen: string;
 last_seen: string;
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
 /**
  * Whether the PROXY leg was built with them, so browser traffic through the listener presents
  * these rules. Separate from `presented_on_egress` because a server can be assembled with one and
  * not the other, and a panel claiming "configured" while the proxy is the surface the operator is
  * watching would be the defect burpsy-react-ui-trcy records.
  */
 presented_on_proxy: boolean;
 /** Burp's "Prompt for credentials on platform authentication failure". Off by default. */
 prompt_on_authentication_failure?: boolean;
 /** Weak-authentication handshakes performed, most recent first. Recorded whatever the prompt says. */
 warnings?: PlatformAuthWarning[];
}

/** One host whose platform-authentication challenge failed while the prompt was on. */
export interface PlatformAuthFailure {
 host: string;
 /** The scheme the host challenged with: Basic, Digest, NTLM or Negotiate. */
 scheme: string;
 realm?: string;
 reason: "no_credential" | "rejected";
 count: number;
 first_seen: string;
 last_seen: string;
}

export interface PlatformAuthFailuresResponse {
 prompt_on_authentication_failure: boolean;
 failures: PlatformAuthFailure[];
 warnings?: PlatformAuthWarning[];
}

/**
 * The rule scheme a challenged scheme maps to, or null when this build cannot answer it. NTLM and
 * Negotiate map to ntlmv2 (Negotiate is answered with raw NTLM inside it). Never ntlmv1: that weak
 * downgrade is only ever the operator's explicit choice on the rule, not a prompt's default.
 */
export function ruleSchemeFor(challenged: string): "basic" | "digest" | "ntlmv2" | null {
 switch (challenged.toLowerCase()) {
  case "basic":
   return "basic";
  case "digest":
   return "digest";
  case "ntlm":
  case "negotiate":
   return "ntlmv2";
  default:
   return null;
 }
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

/**
 * The failures waiting for credentials. Polled only while the prompt is on, so a console that
 * never turned it on asks the server nothing.
 */
export function usePlatformAuthFailures(enabled: boolean): UseQueryResult<PlatformAuthFailuresResponse> {
 return useQuery({
  queryKey: [...keys.networkAuth, "failures"],
  queryFn: ({ signal }) => api<PlatformAuthFailuresResponse>("/api/network/auth/failures", { signal }),
  enabled,
  refetchInterval: enabled ? 4_000 : false,
 });
}

/** One certificate a target server presented (burpsy-react-ui-t75m). */
export interface ServerCertificate {
 subject: string;
 issuer: string;
 serial_number: string;
 dns_names: string[];
 ip_addresses: string[];
 not_before: string;
 not_after: string;
 sha256: string;
 /** Presented as the server's own certificate on at least one connection. */
 leaf: boolean;
 seen_on: string[];
 count: number;
 first_seen: string;
 last_seen: string;
}

export interface ServerCertificatesResponse {
 /** Whether a store is wired, so an empty list from a server without one does not read as "none seen". */
 attached: boolean;
 max: number;
 certificates: ServerCertificate[];
}

export function useServerCertificates(): UseQueryResult<ServerCertificatesResponse> {
 return useQuery({
  queryKey: [...keys.networkAuth, "server-certificates"],
  queryFn: ({ signal }) => api<ServerCertificatesResponse>("/api/network/server-certificates", { signal }),
  refetchInterval: 10_000,
 });
}

/* --- writes -------------------------------------------------------------- */

export function useClearServerCertificates() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: () => api<unknown>("/api/network/server-certificates", { method: "DELETE" }),
  onSuccess: () => invalidate([[...keys.networkAuth, "server-certificates"]]),
 });
}

export function useSetPlatformAuthPrompt() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (on: boolean) =>
   api<{ prompt_on_authentication_failure: boolean }>("/api/network/auth", json("PUT", { prompt_on_authentication_failure: on })),
  onSuccess: () => invalidate([keys.networkAuth]),
 });
}

export function useDismissPlatformAuthFailure() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (host: string) => api<unknown>(`/api/network/auth/failures${query({ host })}`, { method: "DELETE" }),
  onSuccess: () => invalidate([keys.networkAuth]),
 });
}

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
  mutationFn: (draft: PlatformAuthDraft) => api<{ rule: PlatformAuthRule; replaced: boolean }>("/api/network/auth", json("POST", draft)),
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
  mutationFn: (host: string) => api<unknown>(`/api/network/client-certs${query({ host })}`, { method: "DELETE" }),
  onSuccess: () => invalidate([keys.networkClientCerts]),
 });
}
