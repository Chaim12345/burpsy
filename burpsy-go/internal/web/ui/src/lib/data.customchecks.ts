// Console authoring of custom scan checks (burpsy-react-ui-kbu1): Validate, Import/Save,
// Export/Delete, Reload and Run test over /api/scanner/checks/*. Every write invalidates the corpus
// list, so a row reflects what the server loaded rather than what was clicked.

import { useMutation } from "@tanstack/react-query";
import { api, json } from "./api";
import { keys, useInvalidate } from "./data";

export interface CheckParseError {
 message: string;
 line?: number;
 column?: number;
}

export type CheckKind = "passive" | "active" | "insertion_point" | "tool" | "collaborator";

export interface CheckValidation {
 valid: boolean;
 name?: string;
 kind?: CheckKind;
 error?: CheckParseError;
 /** Set when a loaded check already has this name: "file" makes Save a conflict, "console" a replace. */
 existing_origin?: "console" | "file";
}

export interface CheckSource {
 name: string;
 origin: "console" | "file";
 file?: string;
 source: string;
 kind: CheckKind;
}

export interface CheckTestFinding {
 name: string;
 severity: string;
 confidence: string;
 param?: string;
 evidence?: string;
}

export interface CheckTestResult {
 exchange_id: number;
 url: string;
 findings: CheckTestFinding[];
 sent: number;
 refused: number;
 unresolved: string[];
 declined: string[];
 unsupported?: string;
 error?: string;
}

export interface CheckTestRun {
 name: string;
 kind: CheckKind;
 results: CheckTestResult[];
}

export function validateCheck(source: string): Promise<CheckValidation> {
 return api<CheckValidation>("/api/scanner/checks/validate", json("POST", { source }));
}

export function fetchCheckSource(name: string): Promise<CheckSource> {
 return api<CheckSource>(`/api/scanner/checks/source?name=${encodeURIComponent(name)}`);
}

export function useImportCheck() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (body: { source: string; replace: boolean }) =>
   api<{ name: string; kind: CheckKind; origin: "console"; persisted: boolean; persist_error?: string }>(
    "/api/scanner/checks/import",
    json("POST", body),
   ),
  onSuccess: () => invalidate([keys.scannerChecks]),
 });
}

export function useDeleteCheck() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: (name: string) => api<void>(`/api/scanner/checks/source?name=${encodeURIComponent(name)}`, { method: "DELETE" }),
  onSuccess: () => invalidate([keys.scannerChecks]),
 });
}

export function useReloadChecks() {
 const invalidate = useInvalidate();
 return useMutation({
  mutationFn: () =>
   api<{ summary: string; errors: { file: string; error: string }[]; shadowed: string[] }>("/api/scanner/checks/reload", json("POST", {})),
  onSuccess: () => invalidate([keys.scannerChecks]),
 });
}

export function useTestCheck() {
 return useMutation({
  mutationFn: (body: { source: string; exchange_ids: number[] }) => api<CheckTestRun>("/api/scanner/checks/test", json("POST", body)),
 });
}

/** Starting drafts for New — one per `given` shape an operator most often writes. */
export const CHECK_TEMPLATES: { id: string; label: string; source: string }[] = [
 {
  id: "passive",
  label: "Passive: match a response",
  source: `metadata:
    language: v2-beta
    name: "New passive check"
    description: "Reports responses that contain a marker"
    author: ""

given response then
    if {latest.response.body} matches "(?i)stack trace" then
        report issue:
            severity: low
            confidence: firm
            detail: \`The response contains a stack trace.\`
    end if
`,
 },
 {
  id: "host",
  label: "Active: request a path once per host",
  source: `metadata:
    language: v2-beta
    name: "New host check"
    description: "Requests a path on each host and reports a 200"
    author: ""

given host then
    send request called probe:
        method: "GET"
        path: "/.git/HEAD"

    if {probe.response.status_code} is "200" and {probe.response.body} matches "^ref:" then
        report issue:
            severity: medium
            confidence: firm
            detail: \`{probe.request.url} exposes a Git repository.\`
    end if
`,
 },
 {
  id: "insertion",
  label: "Active: payload at each insertion point",
  source: `metadata:
    language: v2-beta
    name: "New insertion point check"
    description: "Sends a payload at each insertion point and looks for its reflection"
    author: ""

given insertion point then
    send payload called probe:
        appending: "'\\"><bsy{random_str(6)}>"

    if {probe.response.body} matches "<bsy[a-z0-9]{6}>" then
        report issue:
            severity: medium
            confidence: tentative
            detail: \`The payload was reflected unencoded.\`
    end if
`,
 },
];
