import { describe, expect, test } from "bun:test";

import { availableVariants, variantMessageId } from "../ui/variant-picker";

/**
 * Burp's three message readings, as a pure mapping (burpsy-react-ui-c05, under epic mrjw).
 *
 * These two functions are the whole of the client's opinion about the feature: which comparisons to
 * offer, and which message id to fetch for the one that was chosen. Everything else is the server's
 * (`core.Exchange.VariantFor` resolves the stages) and the pane's.
 *
 * They are tested here rather than through a rendered page because both failures they guard against
 * are silent in a browser. Offering a comparison that does not exist shows the same bytes twice
 * under two labels; resolving an id to null fetches nothing and renders an empty editor. Neither
 * throws, and neither looks wrong in a screenshot of a row that happens to have a comparison.
 */

describe("the readings a row can show", () => {
 test("a row nothing modified offers only the bytes that travelled", () => {
  expect(availableVariants(null, null)).toEqual(["edited"]);
  expect(availableVariants(undefined, undefined)).toEqual(["edited"]);
 });

 test("a rule-only change offers the original and the edited bytes, but not a third reading", () => {
  // The auto-modified reading is present to the server as an id only when a manual edit followed the
  // rule; here it is null, which means "the rules' output is what travelled". Offering a tab for it
  // would show the response twice.
  expect(availableVariants(11, null)).toEqual(["original", "edited"]);
 });

 test("a manual-only change offers the pre-edit bytes under both earlier names", () => {
  // Nothing fired a rule, so the pre-edit bytes are the auto-modified reading as well as the
  // original one — two labels for one message, which is what Burp shows too.
  expect(availableVariants(null, 12)).toEqual(["auto-modified", "edited"]);
 });

 test("a row changed twice offers all three, in Burp's order", () => {
  expect(availableVariants(11, 12)).toEqual(["original", "auto-modified", "edited"]);
 });

 test("edited is always available", () => {
  for (const options of [availableVariants(null, null), availableVariants(11, null), availableVariants(11, 12)]) {
   expect(options).toContain("edited");
   expect(options[options.length - 1]).toBe("edited");
  }
 });
});

describe("the message id behind a chosen reading", () => {
 test("the edited reading is the row's own id", () => {
  expect(variantMessageId(10, 11, 12, "edited")).toBe(10);
  expect(variantMessageId(10, null, null, "edited")).toBe(10);
 });

 test("an earlier reading resolves to the id the server sent", () => {
  expect(variantMessageId(10, 11, 12, "original")).toBe(11);
  expect(variantMessageId(10, 11, 12, "auto-modified")).toBe(12);
 });

 test("a reading the row does not have falls back to the bytes that travelled", () => {
  // The null means "this reading is the edited bytes", so the pane must show those rather than fetch
  // message null. Reaching a fetcher with null is the failure this fallback exists to prevent.
  expect(variantMessageId(10, null, null, "original")).toBe(10);
  expect(variantMessageId(10, null, null, "auto-modified")).toBe(10);
  expect(variantMessageId(10, 11, null, "auto-modified")).toBe(10);
 });

 test("a response with no bytes stays null rather than inventing an id", () => {
  // An exchange whose response has not arrived has response === null, and both earlier readings null
  // too. Resolving to 0 would fetch whatever message holds id 0 — a real message, and not this one.
  expect(variantMessageId(null, null, null, "edited")).toBeNull();
  expect(variantMessageId(null, null, null, "original")).toBeNull();
  expect(variantMessageId(null, 11, 12, "original")).toBe(11);
 });
});
