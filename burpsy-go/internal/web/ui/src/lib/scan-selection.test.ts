/**
 * Tests for the scan-configuration selection draft (burpsy-react-ui-saq3.3.1). Run with
 * `bun run test:lib`.
 *
 * The rules under test: the allow and deny lists stay separate; an empty allow list is never saved
 * as though it were a selection; a save carries only the keys that changed; and the two skip lists
 * read the same whether the server sent null or [].
 */
import { describe, expect, test } from "bun:test";
import {
 addParameter,
 draftFrom,
 filterIssueTypes,
 hexIndex,
 methodEnabled,
 saveBlocker,
 setMethodEnabled,
 setOnlySelected,
 setTypeRuns,
 settingsPatch,
 typeRuns,
} from "./scan-selection";
import type { AuditConfigView, IssueTypeRow } from "./types.attack";

const SQLI = 0x00100200;
const XSS = 0x00200300;

function view(overrides: Partial<AuditConfigView> = {}): AuditConfigView {
 return {
  issue_types: null,
  disabled_issue_types: [],
  disabled_detection_methods: [],
  declined_detection_methods: [],
  skip_all_tests_for_parameters: null,
  skip_server_side_injection_for_parameters: [],
  ...overrides,
 } as AuditConfigView;
}

const rows: IssueTypeRow[] = [
 {
  type_index: SQLI,
  name: "SQL injection",
  typical_severity: "high",
  detection_methods: ["Error messages", "Time delays"],
  implemented_methods: ["Error messages"],
 },
 { type_index: XSS, name: "Cross-site scripting (reflected)", typical_severity: "high", detection_methods: [], implemented_methods: [] },
];

describe("draftFrom", () => {
 test("null and [] skip lists both read as empty", () => {
  const draft = draftFrom(view());
  expect(draft.skipAll).toEqual([]);
  expect(draft.skipServerSide).toEqual([]);
 });
 test("a non-empty allow list switches the mode on", () => {
  expect(draftFrom(view({ issue_types: [SQLI] })).onlySelected).toBe(true);
  expect(draftFrom(view({ issue_types: null })).onlySelected).toBe(false);
 });
});

describe("running a type", () => {
 test("without an allow list, unticking writes the deny list", () => {
  const draft = setTypeRuns(draftFrom(view()), SQLI, false);
  expect(draft.disabledTypes).toEqual([SQLI]);
  expect(typeRuns(draft, SQLI)).toBe(false);
  expect(typeRuns(setTypeRuns(draft, SQLI, true), SQLI)).toBe(true);
 });
 test("with an allow list, ticking adds to it and clears a deny entry", () => {
  const base = draftFrom(view({ issue_types: [XSS], disabled_issue_types: [SQLI] }));
  expect(typeRuns(base, SQLI)).toBe(false);
  const ticked = setTypeRuns(base, SQLI, true);
  expect(ticked.issueTypes).toEqual([XSS, SQLI]);
  expect(ticked.disabledTypes).toEqual([]);
  const unticked = setTypeRuns(ticked, XSS, false);
  expect(unticked.issueTypes).toEqual([SQLI]);
  expect(unticked.disabledTypes).toEqual([]);
 });
});

describe("saving", () => {
 test("an allow list switched on with nothing ticked is blocked, not saved as no restriction", () => {
  const draft = setOnlySelected(draftFrom(view()), true);
  expect(saveBlocker(draft)).toContain("no restriction");
  expect(saveBlocker(setTypeRuns(draft, SQLI, true))).toBeNull();
 });
 test("the patch carries only what changed", () => {
  const base = draftFrom(view({ disabled_issue_types: [XSS], skip_all_tests_for_parameters: ["csrf"] }));
  expect(settingsPatch(base, base)).toEqual({});
  const edited = setMethodEnabled(base, SQLI, "Time delays", false);
  expect(settingsPatch(base, edited)).toEqual({ disabled_detection_methods: [{ type_index: SQLI, method: "Time delays" }] });
  expect(methodEnabled(edited, SQLI, "Time delays")).toBe(false);
  expect(methodEnabled(edited, SQLI, "Error messages")).toBe(true);
 });
 test("switching the allow list off sends [] — an explicit clear", () => {
  const base = draftFrom(view({ issue_types: [SQLI] }));
  expect(settingsPatch(base, setOnlySelected(base, false))).toEqual({ issue_types: [] });
 });
 test("reordering the deny list is not a change", () => {
  const base = draftFrom(view({ disabled_issue_types: [SQLI, XSS] }));
  expect(settingsPatch(base, { ...base, disabledTypes: [XSS, SQLI] })).toEqual({});
 });
});

describe("parameter lists", () => {
 test("a blank or case-insensitive duplicate name is refused with a reason", () => {
  expect(addParameter([], "  ").error).toBeDefined();
  expect(addParameter(["CSRF"], "csrf").error).toContain("already");
  expect(addParameter(["csrf"], " id ").list).toEqual(["csrf", "id"]);
 });
});

describe("filterIssueTypes", () => {
 const draft = draftFrom(view({ disabled_issue_types: [XSS] }));
 test("searches by every word of the name, or by the type index", () => {
  expect(filterIssueTypes(rows, draft, "sql inj", "all").map((r) => r.name)).toEqual(["SQL injection"]);
  expect(filterIssueTypes(rows, draft, hexIndex(SQLI), "all").map((r) => r.name)).toEqual(["SQL injection"]);
  expect(filterIssueTypes(rows, draft, "00200300", "all").map((r) => r.name)).toEqual(["Cross-site scripting (reflected)"]);
 });
 test("filters by what the draft does to each type", () => {
  expect(filterIssueTypes(rows, draft, "", "not-running").map((r) => r.type_index)).toEqual([XSS]);
  expect(filterIssueTypes(rows, draft, "", "running").map((r) => r.type_index)).toEqual([SQLI]);
  expect(filterIssueTypes(rows, draft, "", "changed").map((r) => r.type_index)).toEqual([XSS]);
 });
});
