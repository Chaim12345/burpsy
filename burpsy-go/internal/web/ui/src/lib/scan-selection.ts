/**
 * The per-issue selection and parameter skip lists of one saved scan configuration, as an editable
 * draft (burpsy-react-ui-saq3.3.1).
 *
 * Pure functions over plain data so the rules below are tested without a browser, and so the
 * settings page holds one draft object rather than five pieces of state that can disagree.
 *
 * # The two lists, and why they stay two
 *
 * `issue_types` is an ALLOW list and `disabled_issue_types` a DENY list, and the server keeps them
 * apart because Burp does: a file in "scan only selected issues" mode lists a whitelist, and a listed
 * entry with `enabled: false` is denied on top of it. An empty allow list means NO restriction, not
 * "nothing selected" — which is why "Run only the selected issue types" is its own switch here, and
 * why saving it on with nothing ticked is refused instead of quietly running everything.
 */
import type { AuditConfigSettings, AuditConfigView, IssueDetectionMethod, IssueTypeRow } from "./types.attack";

export interface SelectionDraft {
  /** "Scan only selected issues": the allow list is in force. */
  onlySelected: boolean;
  /** The allow list. Meaningful only while `onlySelected` is on. */
  issueTypes: number[];
  disabledTypes: number[];
  disabledMethods: IssueDetectionMethod[];
  skipAll: string[];
  skipServerSide: string[];
}

export function draftFrom(view: AuditConfigView): SelectionDraft {
  const issueTypes = view.issue_types ?? [];
  return {
    onlySelected: issueTypes.length > 0,
    issueTypes: [...issueTypes],
    disabledTypes: [...(view.disabled_issue_types ?? [])],
    disabledMethods: (view.disabled_detection_methods ?? []).map((m) => ({ type_index: m.type_index, method: m.method })),
    // The skip-all list reads null when empty and the server-side one []; both are "no exemptions".
    skipAll: [...(view.skip_all_tests_for_parameters ?? [])],
    skipServerSide: [...(view.skip_server_side_injection_for_parameters ?? [])],
  };
}

/** The type index the way Burp's files spell it. */
export function hexIndex(typeIndex: number): string {
  return "0x" + typeIndex.toString(16).padStart(8, "0");
}

/** Whether a run under this draft dispatches the type's checks at all. */
export function typeRuns(draft: SelectionDraft, typeIndex: number): boolean {
  if (draft.disabledTypes.includes(typeIndex)) return false;
  return !draft.onlySelected || draft.issueTypes.includes(typeIndex);
}

export function setTypeRuns(draft: SelectionDraft, typeIndex: number, runs: boolean): SelectionDraft {
  const disabledTypes = draft.disabledTypes.filter((t) => t !== typeIndex);
  if (runs) {
    const issueTypes =
      draft.onlySelected && !draft.issueTypes.includes(typeIndex) ? [...draft.issueTypes, typeIndex] : draft.issueTypes;
    return { ...draft, issueTypes, disabledTypes };
  }
  if (draft.onlySelected) {
    // Leaving the allow list is how a type stops running in this mode. It is not ALSO added to the
    // deny list: that would survive switching the mode off, and the operator only unticked it here.
    return { ...draft, issueTypes: draft.issueTypes.filter((t) => t !== typeIndex), disabledTypes };
  }
  return { ...draft, disabledTypes: [...disabledTypes, typeIndex] };
}

/**
 * Switching the allow list on starts it EMPTY rather than seeded with every running type: a list
 * of every catalogue type is the same run as no list, and the operator would have to untick their way to
 * the handful they meant. Switching it off clears it, because an allow list that is kept but not in
 * force is not a state the server has.
 */
export function setOnlySelected(draft: SelectionDraft, on: boolean): SelectionDraft {
  return { ...draft, onlySelected: on, issueTypes: [] };
}

export function methodEnabled(draft: SelectionDraft, typeIndex: number, method: string): boolean {
  return !draft.disabledMethods.some((m) => m.type_index === typeIndex && m.method === method);
}

export function setMethodEnabled(draft: SelectionDraft, typeIndex: number, method: string, on: boolean): SelectionDraft {
  const rest = draft.disabledMethods.filter((m) => !(m.type_index === typeIndex && m.method === method));
  return { ...draft, disabledMethods: on ? rest : [...rest, { type_index: typeIndex, method }] };
}

/**
 * Adds one parameter name to a skip list, or says why it cannot. Matching on the server is
 * case-insensitive, so a name already present in another case is a duplicate, not a second entry.
 */
export function addParameter(list: string[], raw: string): { list: string[]; error?: string } {
  const name = raw.trim();
  if (name === "") return { list, error: "Type a parameter name first." };
  if (list.some((existing) => existing.toLowerCase() === name.toLowerCase())) {
    return { list, error: `${name} is already in this list (names match case-insensitively).` };
  }
  return { list: [...list, name] };
}

/** Why the draft cannot be saved as it stands, or null when it can. */
export function saveBlocker(draft: SelectionDraft): string | null {
  if (draft.onlySelected && draft.issueTypes.length === 0) {
    return "“Run only the selected issue types” is on and none is ticked. An empty selection means no restriction, so saving it would run every issue type — tick at least one, or switch it off.";
  }
  return null;
}

const sameNumbers = (a: number[], b: number[]): boolean => {
  if (a.length !== b.length) return false;
  const sortedB = [...b].sort((x, y) => x - y);
  return [...a].sort((x, y) => x - y).every((v, i) => v === sortedB[i]);
};

const methodKey = (m: IssueDetectionMethod): string => `${m.type_index}\u0000${m.method}`;

const sameMethods = (a: IssueDetectionMethod[], b: IssueDetectionMethod[]): boolean => {
  if (a.length !== b.length) return false;
  const keys = new Set(a.map(methodKey));
  return b.every((m) => keys.has(methodKey(m)));
};

const sameStrings = (a: string[], b: string[]): boolean => a.length === b.length && a.every((v, i) => v === b[i]);

/**
 * The settings block for a save: only the keys the draft CHANGED from what was loaded. Sending the
 * whole view back would overwrite whatever another tab saved in between for keys this editor never
 * touched; sending only the changed ones keeps an edit an edit.
 */
export function settingsPatch(base: SelectionDraft, draft: SelectionDraft): AuditConfigSettings {
  const patch: AuditConfigSettings = {};
  const allow = (d: SelectionDraft): number[] => (d.onlySelected ? d.issueTypes : []);
  if (!sameNumbers(allow(base), allow(draft))) patch.issue_types = allow(draft);
  if (!sameNumbers(base.disabledTypes, draft.disabledTypes)) patch.disabled_issue_types = draft.disabledTypes;
  if (!sameMethods(base.disabledMethods, draft.disabledMethods)) patch.disabled_detection_methods = draft.disabledMethods;
  if (!sameStrings(base.skipAll, draft.skipAll)) patch.skip_all_tests_for_parameters = draft.skipAll;
  if (!sameStrings(base.skipServerSide, draft.skipServerSide)) {
    patch.skip_server_side_injection_for_parameters = draft.skipServerSide;
  }
  return patch;
}

export type SelectionFilter = "all" | "running" | "not-running" | "changed";

/** Whether a catalogue row departs from "runs, every method on". */
export function rowChanged(draft: SelectionDraft, row: IssueTypeRow): boolean {
  return !typeRuns(draft, row.type_index) || row.detection_methods.some((m) => !methodEnabled(draft, row.type_index, m));
}

/**
 * The rows a search and filter leave. Every word must appear in the name, or the term is the type
 * index in either spelling — an operator pasting 0x00100200 out of a Burp file finds SQL injection.
 */
export function filterIssueTypes(
  rows: IssueTypeRow[],
  draft: SelectionDraft,
  term: string,
  filter: SelectionFilter,
): IssueTypeRow[] {
  const words = term.toLowerCase().split(/\s+/).filter(Boolean);
  return rows.filter((row) => {
    if (filter === "running" && !typeRuns(draft, row.type_index)) return false;
    if (filter === "not-running" && typeRuns(draft, row.type_index)) return false;
    if (filter === "changed" && !rowChanged(draft, row)) return false;
    if (words.length === 0) return true;
    const name = row.name.toLowerCase();
    if (words.every((word) => name.includes(word))) return true;
    const hex = hexIndex(row.type_index);
    return words.length === 1 && (hex === words[0] || hex.slice(2) === words[0] || String(row.type_index) === words[0]);
  });
}
