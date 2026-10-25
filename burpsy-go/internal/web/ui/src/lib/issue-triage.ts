import type { MenuGroup } from "../ui/menu";
import type { FindingDetail } from "./types.attack";

/**
 * Operator triage (burpsy-react-ui-pwd): the decisions an issue row carries and the write the UI
 * sends for them. Field names and emptiness semantics are the backend PUT /api/issues/{id}
 * contract's — a present `severity` sets an override, an empty string clears it back to the
 * engine's word, `false_positive` and `comment` replace their value wholesale.
 */
export interface IssueTriagePatch {
 severity?: string;
 confidence?: string;
 false_positive?: boolean;
 comment?: string;
}

/** The callbacks the menu needs to be pure: the page owns the mutation, the prompts, the toasts. */
export interface TriageCallbacks {
 apply: (patch: IssueTriagePatch, message: string) => void;
 editComment: (current: string) => void;
 remove: () => void;
}

export const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Informational"];
export const CONFIDENCE_OPTIONS = ["Certain", "Firm", "Tentative"];

/**
 * The issue-triage menu, shared by the tree leaf's context menu.
 *
 * Burp's issue menu carries Set severity, Set confidence, Add comment, False positive and Delete
 * issue; this builds the same five, as pickers-over-a-row. An entry for the value a finding
 * already shows is disabled rather than hidden, so the menu says what was chosen even when the
 * choice changed nothing — a greyed item is evidence the override landed, a missing one is
 * indistinguishable from a broken control. "Engine default" exists only when an override stands:
 * with none, clearing would be an action that does nothing.
 */
export function triageMenuGroups(finding: FindingDetail, cb: TriageCallbacks): MenuGroup[] {
 const severityItems = [
  {
   id: "severity-clear",
   label: "Engine default (clear override)",
   disabled: finding.original_severity === undefined,
   onSelect: () => cb.apply({ severity: "" }, `Severity override cleared — engine severity restored`),
  },
  ...SEVERITY_OPTIONS.map((name) => ({
   id: `severity-${name.toLowerCase()}`,
   label: name,
   disabled: finding.severity === name,
   onSelect: () => cb.apply({ severity: name }, `${findingName(finding)} set to ${name}`),
  })),
 ];
 const confidenceItems = [
  {
   id: "confidence-clear",
   label: "Engine default (clear override)",
   disabled: finding.original_confidence === undefined,
   onSelect: () => cb.apply({ confidence: "" }, `Confidence override cleared — engine confidence restored`),
  },
  ...CONFIDENCE_OPTIONS.map((name) => ({
   id: `confidence-${name.toLowerCase()}`,
   label: name,
   disabled: finding.confidence === name,
   onSelect: () => cb.apply({ confidence: name }, `${findingName(finding)} set to ${name} confidence`),
  })),
 ];
 return [
  {
   id: "triage",
   title: "Triage",
   actions: [
    {
     id: "severity",
     label: "Set severity",
     submenu: [{ id: "severity-options", actions: severityItems }],
     onSelect: () => {},
    },
    {
     id: "confidence",
     label: "Set confidence",
     submenu: [{ id: "confidence-options", actions: confidenceItems }],
     onSelect: () => {},
    },
    {
     id: "comment",
     label: finding.comment ? "Edit comment" : "Add comment",
     onSelect: () => cb.editComment(finding.comment),
    },
    {
     id: "false-positive",
     label: finding.false_positive ? "Unmark false positive" : "Mark false positive",
     disabled: false,
     onSelect: () =>
      cb.apply(
       { false_positive: !finding.false_positive },
       finding.false_positive ? `False positive mark removed` : `Marked false positive`,
      ),
    },
    {
     id: "delete",
     label: "Delete issue",
     danger: true,
     onSelect: () => cb.remove(),
    },
   ],
  },
 ];
}

function findingName(f: FindingDetail): string {
 return f.issue_name ?? f.check_name ?? "Unnamed finding";
}
