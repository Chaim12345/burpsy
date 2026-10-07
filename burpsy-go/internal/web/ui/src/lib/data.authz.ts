// Access-control testing (burpsy-react-ui-cr37): re-send a request under named identities and read
// the per-identity verdict. Served by internal/web/api_authz.go — /api/authz/identities (GET/PUT,
// riskLocal) and /api/authz/test (POST, riskAttack).

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";

export interface AuthzIdentity {
 label: string;
 baseline: boolean;
 cookie: string;
 headers: Record<string, string>;
 strip_cookie: boolean;
 /** When set, the identity is sourced from this session rule (burpsy-react-ui-q7f8): the rule's login
  *  macro is run before the test and the cookie its jar would attach becomes this identity's cookie.
  *  Cookie/strip_cookie are ignored; extra headers still apply. */
 session_rule_id?: number;
}

export interface AuthzVerdict {
 label: string;
 /** Baseline | Enforced | Bypassed | Ambiguous. */
 verdict: string;
 status: number;
 body_len: number;
 reasons?: string[];
 request_id?: number;
 response_id?: number;
 error?: string;
}

export interface AuthzTestResult {
 exchange_id: number;
 samples: number;
 verdicts: AuthzVerdict[];
}

const authzKey = ["authz", "identities"] as const;

export function useAuthzIdentities(): UseQueryResult<{ identities: AuthzIdentity[] }> {
 return useQuery({ queryKey: authzKey, queryFn: ({ signal }) => api<{ identities: AuthzIdentity[] }>("/api/authz/identities", { signal }) });
}

export function useSaveAuthzIdentities() {
 const client = useQueryClient();
 return useMutation<{ identities: AuthzIdentity[] }, Error, AuthzIdentity[]>({
  mutationFn: (identities) => api<{ identities: AuthzIdentity[] }>("/api/authz/identities", json("PUT", { identities })),
  onSuccess: (res) => client.setQueryData(authzKey, res),
 });
}

export function useRunAuthzTest() {
 return useMutation<AuthzTestResult, Error, { exchange_id: number; samples?: number }>({
  mutationFn: (body) => api<AuthzTestResult>("/api/authz/test", json("POST", body)),
 });
}
