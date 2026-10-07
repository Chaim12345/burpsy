// Secret detection over captured responses (burpsy-react-ui-8j0d), served by
// internal/web/api_scanner_secrets.go at /api/scanner/secrets (GET/PUT, riskLocal).

import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json } from "./api";

export interface SecretDetectionView {
 enabled: boolean;
 /** The embedded rule corpus, e.g. "gitleaks v8.30.1". */
 corpus: string;
 /** How many corpus rules run. */
 rules: number;
 /** Corpus rules never reported, with the reason. */
 excluded: Record<string, string>;
 /** Provider rules burpsy runs beside the corpus. */
 extra: string[];
}

const secretsKey = ["scanner", "secrets"] as const;

export function useSecretDetection(): UseQueryResult<SecretDetectionView> {
 return useQuery({ queryKey: secretsKey, queryFn: ({ signal }) => api<SecretDetectionView>("/api/scanner/secrets", { signal }) });
}

export function useSetSecretDetection() {
 const client = useQueryClient();
 return useMutation<SecretDetectionView, Error, boolean>({
  mutationFn: (enabled) => api<SecretDetectionView>("/api/scanner/secrets", json("PUT", { enabled })),
  onSuccess: (view) => client.setQueryData(secretsKey, view),
 });
}
