import { describe, expect, test } from "bun:test";
import { filterByIssueSource, issueSourceOf } from "./issue-source-filter";

/**
 * The source facet (burpsy-react-ui-exiu).
 *
 * An operator could not separate a manual finding from a scan's. That is not a cosmetic
 * distinction: "the scanner found this" and "a person found this" are different claims with
 * different follow-ups, and a list showing both without saying which reads as one undifferentiated
 * pile from every producer in the project.
 */

function f(id: number, source?: string) {
 return { id, source };
}

describe("the source facet", () => {
 test("keeps scan findings when the operator asks for scans", () => {
  const all = [f(1, "scan"), f(2, "manual"), f(3, "scan")];
  expect(filterByIssueSource(all, "scan").map((x) => x.id)).toEqual([1, 3]);
 });

 test("keeps manual findings when the operator asks for those", () => {
  const all = [f(1, "scan"), f(2, "manual"), f(3, "manual")];
  expect(filterByIssueSource(all, "manual").map((x) => x.id)).toEqual([2, 3]);
 });

 test("keeps EVERYTHING when no filter is chosen", () => {
  // The same "I did not choose" reading the launch body's optional fields use. A filter that
  // defaulted to one source would hide half the list on a page load.
  const all = [f(1, "scan"), f(2, "manual")];
  expect(filterByIssueSource(all, "")).toHaveLength(2);
 });

 test("treats a finding with no source as manual, because that is what no run raising it means", () => {
  // An older server, or a row from before the field existed. Dropping it instead would hide every
  // legacy row the moment an operator picked "Manual" — which reads as the tool losing data.
  const all = [f(1, "manual"), f(2), f(3, undefined)];
  expect(filterByIssueSource(all, "manual").map((x) => x.id)).toEqual([1, 2, 3]);
  expect(filterByIssueSource(all, "scan").map((x) => x.id)).toEqual([]);
 });

 test("reports a finding's provenance the same way whichever way it is asked", () => {
  expect(issueSourceOf({ source: "scan" })).toBe("scan");
  expect(issueSourceOf({ source: "manual" })).toBe("manual");
  expect(issueSourceOf({})).toBe("manual");
 });

 test("does not treat an unrecognised value as a scan", () => {
  // A server that grows a third provenance must not have its rows silently filed under "scan" by
  // a filter that only compares against "manual". Falling the other way files them as manual,
  // which is visible and correct-by-default rather than silently claiming a run raised them.
  expect(issueSourceOf({ source: "bcheck" })).toBe("manual");
 });

 test("does not mutate the caller's array, so a re-render cannot reorder the underlying cache", () => {
  const all = [f(2), f(1)];
  const kept = filterByIssueSource(all, "");
  kept.reverse();
  expect(all.map((x) => x.id)).toEqual([2, 1]);
 });
});
