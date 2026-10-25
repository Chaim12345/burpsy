import { describe, expect, test } from "bun:test";
import { SEVERITY_OPTIONS, triageMenuGroups, type IssueTriagePatch, type TriageCallbacks } from "./issue-triage";
import type { FindingDetail } from "./types.attack";

function finding(overrides: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 7,
    check_name: "SQL injection",
    severity: "High",
    confidence: "Firm",
    host: "shop.test",
    detail: null,
    remediation: null,
    times_seen: 1,
    occurrences: [],
    false_positive: false,
    comment: "",
    ...overrides,
  };
}

function recording(): { cb: TriageCallbacks; patches: Array<[IssueTriagePatch, string]>; comments: string[]; removals: () => number } {
  const patches: Array<[IssueTriagePatch, string]> = [];
  const comments: string[] = [];
  let removals = 0;
  return {
    patches,
    comments,
    // A getter, not a copied property: the primitive would be snapshotted at
    // creation and every assertion would read 0 however many times delete fired.
    removals: () => removals,
    cb: {
      apply: (patch, message) => patches.push([patch, message]),
      editComment: (current) => comments.push(current),
      remove: () => {
        removals += 1;
      },
    },
  };
}

function triageActions(f: FindingDetail, cb: TriageCallbacks) {
  const groups = triageMenuGroups(f, cb);
  const triage = groups.find((g) => g.id === "triage");
  if (!triage) throw new Error("triage group missing");
  const byId = new Map(triage.actions.map((a) => [a.id, a]));
  return { groups, triage, byId };
}

// burpsy-react-ui-pwd: the menu is the operator's only route to the triage writes, so its shape is
// pinned here — the vocabulary the pickers offer, the clear-override entries appearing only when an
// override stands, the false-positive toggle's both directions, and the exact patch each entry
// sends, since an empty-string severity is "clear" on the wire and any other misspelling is a 400.

describe("triageMenuGroups", () => {
  test("offers the full severity vocabulary under Set severity", () => {
    const { byId } = triageActions(finding(), recording().cb);
    const severity = byId.get("severity");
    expect(severity?.submenu?.[0]?.actions.map((a) => a.label)).toEqual(
      ["Engine default (clear override)", ...SEVERITY_OPTIONS],
    );
  });

  test("the clear-override entry is disabled until an override stands", () => {
    const plain = triageActions(finding(), recording().cb);
    const clear = plain.byId.get("severity")?.submenu?.[0]?.actions.find((a) => a.id === "severity-clear");
    expect(clear?.disabled).toBe(true);

    const overridden = triageActions(finding({ severity: "Low", original_severity: "High" }), recording().cb);
    const clearWhenOverridden = overridden.byId.get("severity")?.submenu?.[0]?.actions.find((a) => a.id === "severity-clear");
    expect(clearWhenOverridden?.disabled).toBe(false);
  });

  test("the entry for the severity a finding already shows is disabled, the others are not", () => {
    const { byId } = triageActions(finding({ severity: "High" }), recording().cb);
    const actions = byId.get("severity")?.submenu?.[0]?.actions ?? [];
    const high = actions.find((a) => a.id === "severity-high");
    const low = actions.find((a) => a.id === "severity-low");
    expect(high?.disabled).toBe(true);
    expect(low?.disabled).toBe(false);
  });

  test("setting a severity sends the Title-case word the wire vocabulary wants", () => {
    const state = recording();
    const { byId } = triageActions(finding(), state.cb);
    const medium = byId.get("severity")?.submenu?.[0]?.actions.find((a) => a.id === "severity-medium");
    medium?.onSelect();
    expect(state.patches[0]?.[0]).toEqual({ severity: "Medium" });
  });

  test("clearing the severity override sends the empty string the wire reads as clear", () => {
    const state = recording();
    const { byId } = triageActions(finding({ severity: "Low", original_severity: "High" }), state.cb);
    const clear = byId.get("severity")?.submenu?.[0]?.actions.find((a) => a.id === "severity-clear");
    clear?.onSelect();
    expect(state.patches[0]?.[0]).toEqual({ severity: "" });
  });

  test("the false-positive entry flips with the finding's current state", () => {
    const clean = recording();
    const { byId: cleanById } = triageActions(finding(), clean.cb);
    expect(cleanById.get("false-positive")?.label).toBe("Mark false positive");
    cleanById.get("false-positive")?.onSelect();
    expect(clean.patches[0]?.[0]).toEqual({ false_positive: true });

    const marked = recording();
    const { byId: markedById } = triageActions(finding({ false_positive: true }), marked.cb);
    expect(markedById.get("false-positive")?.label).toBe("Unmark false positive");
    markedById.get("false-positive")?.onSelect();
    expect(marked.patches[0]?.[0]).toEqual({ false_positive: false });
  });

  test("the comment entry hands the current comment to the editor callback and its label tracks one existing", () => {
    const state = recording();
    const bare = triageActions(finding(), state.cb);
    expect(bare.byId.get("comment")?.label).toBe("Add comment");
    bare.byId.get("comment")?.onSelect();
    expect(state.comments).toEqual([""]);

    const annotated = triageActions(finding({ comment: "duplicate of #12" }), state.cb);
    expect(annotated.byId.get("comment")?.label).toBe("Edit comment");
    annotated.byId.get("comment")?.onSelect();
    expect(state.comments).toEqual(["", "duplicate of #12"]);
  });

  test("confidence entries mirror severity: vocabulary, current-value disable, clear only when overridden", () => {
    const state = recording();
    const { byId } = triageActions(finding({ confidence: "Firm", original_confidence: "Certain" }), state.cb);
    const actions = byId.get("confidence")?.submenu?.[0]?.actions ?? [];
    expect(actions.map((a) => a.label)).toEqual(["Engine default (clear override)", "Certain", "Firm", "Tentative"]);
    expect(actions.find((a) => a.id === "confidence-firm")?.disabled).toBe(true);
    expect(actions.find((a) => a.id === "confidence-certain")?.disabled).toBe(false);
    actions.find((a) => a.id === "confidence-clear")?.onSelect();
    expect(state.patches[0]?.[0]).toEqual({ confidence: "" });
  });

  test("delete routes to the removal callback", () => {
    const state = recording();
    const { byId } = triageActions(finding(), state.cb);
    const del = byId.get("delete");
    expect(del?.danger).toBe(true);
    del?.onSelect();
    expect(state.removals()).toBe(1);
  });
});
