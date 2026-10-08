import { useMutation, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, json, query } from "./api";
import { useResource } from "./data";

/**
 * Recorded login sequences (burpsy-react-ui-xhtk): Burp's "Recorded login sequences" for crawl —
 * import a Login Recorder script, edit its steps, Replay it, and pick it for a crawl.
 *
 * Every type here mirrors internal/session's views. None has a secret field: a typed password and a
 * TOTP secret go to the server on a save and never come back. `has_value` / `has_secret` say that one
 * is stored, so the editor can show "stored" instead of an empty box that reads as "none".
 */

export const recordedLoginsKey = ["crawl", "logins"] as const;

export type LoginStepKind = "goto" | "click" | "type" | "totp" | "key" | "wait";

export interface TOTPView {
  algorithm: string;
  period: number;
  digits: number;
  has_secret: boolean;
}

export interface LoginStepView {
  kind: LoginStepKind;
  url?: string;
  selector?: string;
  xpath?: string;
  /** A non-secret type step's text. A secret step's text never arrives here. */
  value?: string;
  secret?: boolean;
  has_value?: boolean;
  key?: string;
  wait_ms?: number;
  totp?: TOTPView;
  /** Burp's own wording for the step, already free of secrets. */
  description: string;
}

export interface StatusCheck {
  url: string;
  text: string;
}

export interface RecordedLoginView {
  id: string;
  label: string;
  steps: LoginStepView[];
  status_check: StatusCheck | null;
  source?: string;
  has_totp: boolean;
  created: string;
  updated: string;
}

export interface RecordedLoginsResponse {
  logins: RecordedLoginView[];
  empty: boolean;
  step_kinds: LoginStepKind[];
  keys: string[];
  restore_note?: string;
}

export interface ImportNote {
  event: number;
  event_type: string;
  outcome: "dropped" | "warning";
  detail: string;
}

export interface SaveReply {
  login: RecordedLoginView;
  replaced: boolean;
  format: string;
  notes: ImportNote[];
}

/**
 * A step as the editor sends it. The view's fields plus, for a TOTP step, a `totp.secret` the
 * operator typed. A secret type step sent with no `value` and `has_value: true` keeps the stored
 * secret — that is how an edit round-trips without the console ever holding the password.
 */
export interface StepDraft {
  kind: LoginStepKind;
  url?: string;
  selector?: string;
  xpath?: string;
  value?: string;
  secret?: boolean;
  has_value?: boolean;
  key?: string;
  wait_ms?: number;
  totp?: { algorithm?: string; period: number; digits: number; secret?: string; has_secret?: boolean };
}

export interface SaveDraft {
  id?: string;
  label: string;
  script?: string;
  steps?: StepDraft[];
  status_check?: StatusCheck | null;
}

export interface LoginStepResult {
  index: number;
  kind: string;
  description: string;
  ok: boolean;
  error?: string;
  url?: string;
  elapsed_ms: number;
}

export interface LoginReplay {
  succeeded: boolean;
  reason?: string;
  steps: LoginStepResult[];
  final_url?: string;
  status_check?: { url: string; found: boolean; error?: string };
  blocked: string[];
  elapsed_ms: number;
}

export interface ReplayReply {
  id: string;
  label: string;
  replay: LoginReplay;
  cookie_names: string[];
  /** The final page as a data: URL, "" when no screenshot could be taken. */
  screenshot: string;
}

export const useRecordedLogins = (): UseQueryResult<RecordedLoginsResponse> =>
  useResource<RecordedLoginsResponse>(recordedLoginsKey, "/api/crawl/logins");

export function useSaveRecordedLogin() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (draft: SaveDraft) => api<SaveReply>("/api/crawl/logins", json("POST", draft)),
    onSuccess: () => void client.invalidateQueries({ queryKey: recordedLoginsKey }),
  });
}

export function useDeleteRecordedLogin() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<unknown>(`/api/crawl/logins${query({ id })}`, { method: "DELETE" }),
    onSuccess: () => void client.invalidateQueries({ queryKey: recordedLoginsKey }),
  });
}

/** Burp's "Replay": runs the sequence in an isolated, scope-gated browser and reports every step. */
export function useReplayRecordedLogin() {
  return useMutation({
    mutationFn: (id: string) => api<ReplayReply>("/api/crawl/logins/replay", json("POST", { id })),
  });
}

/** A view turned back into a draft, keeping every secret by reference rather than by value. */
export function draftFromView(step: LoginStepView): StepDraft {
  const draft: StepDraft = {
    kind: step.kind,
    url: step.url,
    selector: step.selector,
    xpath: step.xpath,
    value: step.secret ? undefined : step.value,
    secret: step.secret,
    has_value: step.has_value,
    key: step.key,
    wait_ms: step.wait_ms,
  };
  if (step.totp) {
    draft.totp = { algorithm: step.totp.algorithm, period: step.totp.period, digits: step.totp.digits, has_secret: step.totp.has_secret };
  }
  return draft;
}

/** The editor's one-line description of a draft step, matching the server's Describe(). */
export function describeDraft(step: StepDraft): string {
  const target = step.selector || step.xpath || "(no element)";
  switch (step.kind) {
    case "goto":
      return `Navigate to ${step.url ?? ""}`;
    case "click":
      return `Click on ${target}`;
    case "type":
      return step.secret ? `Type a secret value into ${target}` : `Type '${step.value ?? ""}' into ${target}`;
    case "totp":
      return `Type TOTP code into ${target}`;
    case "key":
      return `Press ${step.key ?? ""} key`;
    case "wait":
      return `Wait for ${step.wait_ms ?? 0}ms`;
  }
}

/** The step a new row starts as, per kind. */
export function blankStep(kind: LoginStepKind): StepDraft {
  switch (kind) {
    case "goto":
      return { kind, url: "" };
    case "key":
      return { kind, key: "Enter" };
    case "wait":
      return { kind, wait_ms: 1000 };
    case "totp":
      return { kind, selector: "", totp: { algorithm: "SHA1", period: 30, digits: 6, secret: "" } };
    case "type":
      return { kind, selector: "", value: "" };
    case "click":
      return { kind, selector: "" };
  }
}
