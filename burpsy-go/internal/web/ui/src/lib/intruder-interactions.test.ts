import { describe, expect, test } from "bun:test";
import { hasCollaboratorAttempts, interactionsByAttempt } from "./intruder-interactions";
import type { CollaboratorInteractionRow } from "./data.collab";
import type { Attempt } from "./types.tools";

const attempt = (ordinal: number, collaborator_payloads?: string[]): Attempt => ({ ordinal, collaborator_payloads }) as unknown as Attempt;
const row = (id: number, payload: string | undefined, collapsed = false, at_ms = id): CollaboratorInteractionRow => ({
 id,
 interaction_id: `i${id}`,
 type: "dns",
 client_ip: "198.51.100.7",
 at_ms,
 payload,
 collapsed,
});

describe("interactionsByAttempt", () => {
 test("ties each callback to the attempt that sent its address", () => {
  const attempts = [attempt(1, ["bsyaa.oast.test"]), attempt(2, ["bsybb.oast.test"]), attempt(3, ["bsycc.oast.test"])];
  const second = { ...row(1, "BSYBB.oast.test", false, 10), type: "http" };
  const rows = [row(0, "bsybb.oast.test", false, 50), second, row(2, "bsyzz.oast.test"), row(3, undefined)];
  const got = interactionsByAttempt(attempts, rows);
  expect(got.get(1)).toEqual([]);
  expect(got.get(2)?.map((r) => r.id)).toEqual([1, 0]);
  expect(got.get(3)).toEqual([]);
 });

 test("a repeat of one callback counts once per attempt, and the same client counts for each attempt", () => {
  // Rows 0 and 1: one resolver reporting the same lookup twice for attempt 1. Row 2: that same
  // resolver for attempt 2, marked collapsed here to show the log's flag is not consulted — it is
  // a distinct event for a distinct payload.
  const got = interactionsByAttempt(
   [attempt(1, ["bsyaa.oast.test"]), attempt(2, ["bsybb.oast.test"])],
   [row(0, "bsyaa.oast.test"), row(1, "bsyaa.oast.test", true), row(2, "bsybb.oast.test", true)],
  );
  expect(got.get(1)?.length).toBe(1);
  expect(got.get(2)?.length).toBe(1);
 });

 test("one attempt carrying two addresses counts the same resolver once per address (vfqy)", () => {
  // Rows 0 and 2: the same resolver, protocol and query type, for the attempt's two different
  // addresses — two events. Rows 1 and 3: repeats of each, which collapse into their own address's.
  const got = interactionsByAttempt(
   [attempt(1, ["bsyaa.oast.test", "bsybb.oast.test"])],
   [row(0, "bsyaa.oast.test"), row(1, "BSYAA.oast.test"), row(2, "bsybb.oast.test"), row(3, "bsybb.oast.test")],
  );
  expect(got.get(1)?.map((r) => r.id)).toEqual([0, 2]);
 });

 test("an attempt carrying one address in two positions counts each interaction once", () => {
  const got = interactionsByAttempt([attempt(1, ["bsyaa.oast.test", "bsyaa.oast.test"])], [row(0, "bsyaa.oast.test")]);
  expect(got.get(1)?.length).toBe(1);
 });

 test("attempts without Collaborator addresses get no entry, and the column is off", () => {
  const attempts = [attempt(1), attempt(2, [])];
  expect(interactionsByAttempt(attempts, [row(0, "bsyaa.oast.test")]).size).toBe(0);
  expect(hasCollaboratorAttempts(attempts)).toBe(false);
  expect(hasCollaboratorAttempts([attempt(1, ["x"])])).toBe(true);
 });
});
