import { describe, expect, test } from "bun:test";
import { appliedSectionLabels, readBundleCoverage } from "./config-coverage";

// f2kr: the server computes an honest coverage report and the UI discarded it. The export carries 4
// of 15 settings, and the import confirmation said "Scope, intercept rules and session handling
// rules are affected" — naming three of the four carried, omitting uninteresting_headers entirely,
// and saying nothing about the ten settings the bundle never carried. An operator migrating a
// project read that as a complete transfer.

describe("a bundle's own coverage", () => {
 test("is read out of the file, which is where the server writes it and deliberately ignores it", () => {
  const bundle = JSON.stringify({
   version: 1,
   coverage: {
    partial: true,
    included: ["scope", "intercept", "session_rules", "uninteresting_headers"],
    omitted: ["scanner_config", "resource_pools", "scheduled_tasks"],
    note: "written by handleConfigExport",
   },
   scope: { rules: [] },
  });
  const coverage = readBundleCoverage(bundle);
  expect(coverage).toEqual({ partial: true, omitted: ["scanner_config", "resource_pools", "scheduled_tasks"] });
 });

 test("is UNKNOWN, not empty, when the file carries no coverage block", () => {
  // The distinction this whole bead turns on. A hand-written or older bundle has told us nothing
  // about its coverage, which is not the same as having told us it carries everything. Returning
  // {partial:false, omitted:[]} here would make a partial transfer read as a complete one — the
  // exact defect, reappearing inside the fix.
  expect(readBundleCoverage(JSON.stringify({ version: 1, scope: { rules: [] } }))).toBeUndefined();
 });

 test("is unknown rather than empty when the coverage block is null or not an object", () => {
  expect(readBundleCoverage(JSON.stringify({ version: 1, coverage: null }))).toBeUndefined();
  expect(readBundleCoverage(JSON.stringify({ version: 1, coverage: "everything" }))).toBeUndefined();
  expect(readBundleCoverage(JSON.stringify({ version: 1, coverage: 7 }))).toBeUndefined();
 });

 test("is unknown when the file is not JSON at all", () => {
  // The server would have refused this import, so the modal is showing a failure — but it must
  // not claim a coverage it never read on the way there.
  expect(readBundleCoverage("this is not json")).toBeUndefined();
  expect(readBundleCoverage("")).toBeUndefined();
 });

 test("treats a non-string entry in omitted as absent rather than rendering it", () => {
  // An operator can hand-write this file. A number in the list would otherwise reach the DOM as
  // text and read as a setting name.
  const coverage = readBundleCoverage(
   JSON.stringify({ coverage: { partial: true, omitted: ["scanner_config", 42, null, "proxy_options"] } }),
  );
  expect(coverage?.omitted).toEqual(["scanner_config", "proxy_options"]);
 });

 test("reads a complete bundle's coverage as partial with nothing omitted, rather than unknown", () => {
  // The two are different answers and the modal words them differently: "this is a partial
  // transfer, here is what was left out" versus "this file does not say what it can carry".
  const coverage = readBundleCoverage(JSON.stringify({ coverage: { partial: false, omitted: [] } }));
  expect(coverage).toEqual({ partial: false, omitted: [] });
  expect(coverage).not.toBeUndefined();
 });

 test("treats a coverage block with no omitted key as omitting nothing, which the file states", () => {
  // An explicit `{partial: false}` with no list is a claim of completeness. Honoured as one, and
  // distinguishable from a file that made no claim at all.
  const coverage = readBundleCoverage(JSON.stringify({ coverage: { partial: false } }));
  expect(coverage).toEqual({ partial: false, omitted: [] });
 });
});

describe("the sections an import reports applying", () => {
 test("are named from the response, including uninteresting_headers", () => {
  // uninteresting_headers IS carried by the export (configIncludedSections) and the old
  // hand-written sentence left it out. Deriving the list from the response is what stops it
  // drifting again.
  expect(appliedSectionLabels({ scope_rules: 2, intercept_dirs: 1, session_rules: 3, uninteresting_headers: true })).toEqual([
   "scope",
   "intercept rules",
   "session handling rules",
   "uninteresting headers",
  ]);
 });

 test("do not name a section that held nothing", () => {
  // "0 scope rules applied" is already in the detail line. Listing "scope" beside it would tell
  // the operator their scope was replaced when the import never touched it.
  expect(appliedSectionLabels({ scope_rules: 0, intercept_dirs: 0, session_rules: 0 })).toEqual([]);
 });

 test("name uninteresting headers when the bundle carried them and nothing else", () => {
  // The exact case the old sentence got wrong in the other direction: a bundle whose only content
  // is header lists. The old text said "Scope, intercept rules and session handling rules are
  // affected" over it — naming three sections that were untouched and missing the one that moved.
  expect(appliedSectionLabels({ scope_rules: 0, intercept_dirs: 0, session_rules: 0, uninteresting_headers: true })).toEqual([
   "uninteresting headers",
  ]);
 });

 test("survive a response that omits every field, without inventing any", () => {
  expect(appliedSectionLabels({})).toEqual([]);
 });

 test("do not treat a non-numeric count as a section that was applied", () => {
  expect(appliedSectionLabels({ scope_rules: "2", intercept_dirs: true, session_rules: null })).toEqual([]);
 });
});
