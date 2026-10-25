import { describe, expect, test } from "bun:test";
import { attentionFor, attentionSignals } from "./attention";
import type { LiveAuditState } from "./types.attack";
import type { CrawlRun } from "./types.observe";
import type { InterceptState } from "./types";

/** The minimum of InterceptState these rules read, so a field added to the wire type cannot make
 *  these tests fail for a reason unrelated to what they pin. */
function held(pending: number, enabled = true): InterceptState {
 return { enabled, wired: true, pending, held: [] };
}

describe("tool tab attention", () => {
 test("nothing needs the operator when nothing is held", () => {
  expect(attentionSignals({})).toEqual([]);
  expect(attentionSignals({ intercept: held(0) })).toEqual([]);
 });

 // The count is a fact about the queue, not about the switch. Interception can be switched off with
 // messages still held — and those requests are still parked, still worth the operator's attention,
 // and still invisible from every other tool without this. Gating on `enabled` would make the
 // indicator disappear at exactly the moment it became the only way to find out where the traffic
 // went.
 test("a held request is reported even when interception has been switched off since", () => {
  const signals = attentionSignals({ intercept: held(2, false) });
  expect(signals).toHaveLength(1);
  expect(signals[0]?.count).toBe(2);
 });

 test("the signal is addressed to the Proxy tool and says what is holding the traffic", () => {
  const [signal] = attentionSignals({ intercept: held(1) });
  expect(signal?.tool).toBe("proxy");
  expect(signal?.count).toBe(1);
  // The sentence, not just the number: a bare count beside a tab name does not say three of what,
  // or where to go. Both halves are asserted because either one alone leaves the operator guessing.
  expect(signal?.label).toContain("held request");
  expect(signal?.label).toContain("Intercept");
 });

 test("a single held request is not described in the plural", () => {
  const [one] = attentionSignals({ intercept: held(1) });
  const [many] = attentionSignals({ intercept: held(7) });
  expect(one?.label).not.toContain("requests");
  expect(one?.label).not.toContain("them");
  expect(many?.label).toContain("7 held requests");
  expect(many?.label).toContain("them");
 });

 test("a tool with no signal gets none, and a tool with one gets it", () => {
  const signals = attentionSignals({ intercept: held(3) });
  expect(attentionFor(signals, "proxy")?.count).toBe(3);
  expect(attentionFor(signals, "repeater")).toBeUndefined();
  expect(attentionFor(signals, "dashboard")).toBeUndefined();
 });
});

/** The minimum of LiveAuditState these rules read. A field added to the wire type must not make
 *  these tests fail for a reason unrelated to what they pin, so the fixture states only what the
 *  judgement looks at — and says so here rather than in each call. */
function liveAudit(skipped: number, over: Partial<LiveAuditState> = {}): LiveAuditState {
 return {
  wired: true,
  enabled: true,
  behind: 0,
  behind_for_ms: 0,
  batch_limit: 0,
  collapsed: 0,
  ledger_resets: 0,
  retried: 0,
  refused_source: 0,
  traffic_source: "proxy",
  skipped,
  ...over,
 };
}

/** One dashboard run. `state` and `finished` are the two fields the rule reads. */
function crawl(state: CrawlRun["state"], finished = true): CrawlRun {
 return {
  task_id: 1,
  seeds: ["http://app.test/"],
  state,
  started: "2026-09-24T00:00:00Z",
  ...(finished ? { finished: "2026-09-24T00:01:00Z" } : {}),
 };
}

describe("the Scanner's attention source (ve2q)", () => {
 test("a sweep that skipped exchanges is the thing that needs the operator", () => {
  const signals = attentionSignals({ liveAudit: liveAudit(3) });
  const scanner = attentionFor(signals, "scanner");
  expect(scanner?.count, "the count is the number of exchanges the sweep will not look at again").toBe(3);
  expect(scanner?.label, "the label has to name what is waiting and where to go, or the number means nothing").toContain("gave up on");
  expect(scanner?.label).toContain("Live audit");
 });

 test("a clean sweep is not a signal, even while it is working hard", () => {
  // Behind, stalled and retried are all the tool doing its job: a backlog is progress, a stall is
  // one exchange being waited on, and a retry was taken back and audited. Counting any of them
  // would train the operator to ignore a badge that is usually on.
  expect(attentionSignals({ liveAudit: liveAudit(0) })).toEqual([]);
  expect(
   attentionSignals({ liveAudit: liveAudit(0, { behind: 500, stalled_at: 42, retried: 9 }) }),
   "a busy sweep is not a sweep in trouble",
  ).toEqual([]);
 });

 test("a backlog does not borrow the skipped count when both are present", () => {
  // The two numbers are easy to swap because both mean "not audited yet", and only one means
  // "the operator has to do something". A sweep 500 behind and 0 skipped is a sweep working; a
  // sweep caught up with 3 skipped is three exchanges nothing will ever audit.
  const signals = attentionSignals({ liveAudit: liveAudit(0, { behind: 500 }) });
  expect(attentionFor(signals, "scanner"), "a backlog is progress, not a problem").toBeUndefined();
  expect(
   attentionFor(attentionSignals({ liveAudit: liveAudit(3, { behind: 0 }) }), "scanner")?.count,
   "and a skip is a problem whatever the backlog says",
  ).toBe(3);
 });

 test("a server that reports no skipped field is not read as a backlog", () => {
  // `skipped` is optional on the wire, so a server too old to report it leaves the field absent.
  // Substituting `behind` would put a number on the tab that counts something else entirely — the
  // most dangerous kind of wrong here, because it looks like a real count.
  // Built field by field rather than by deleting a key off the fixture: spreading an object that
  // simply lacks `skipped` does not remove the fixture's, and the test would pass against the very
  // mutant it exists to catch.
  const withoutSkips = {
   wired: true,
   enabled: true,
   behind: 500,
   behind_for_ms: 0,
   batch_limit: 0,
   collapsed: 0,
   ledger_resets: 0,
   retried: 0,
   refused_source: 0,
   traffic_source: "proxy",
  } as LiveAuditState;
  const signals = attentionSignals({ liveAudit: withoutSkips });
  expect(attentionFor(signals, "scanner")).toBeUndefined();
 });

 test("an unfetched source is silence, not a zero", () => {
  expect(attentionSignals({ liveAudit: undefined })).toEqual([]);
 });
});

describe("the Dashboard's attention source (ve2q)", () => {
 test("a run that did not finish is the question only this page can answer", () => {
  const signals = attentionSignals({
   crawls: [crawl("done"), crawl("failed"), crawl("running", false)],
  });
  const dashboard = attentionFor(signals, "dashboard");
  expect(dashboard?.count, "the failed run and the one still going are the same fact from any other page").toBe(2);
  expect(dashboard?.label).toContain("did not finish");
 });

 test("finished runs are not a signal, however many there are", () => {
  expect(attentionSignals({ crawls: [crawl("done"), crawl("done"), crawl("done")] })).toEqual([]);
 });

 test("a run with a finish time is done whatever its state says", () => {
  // The state and the timestamp are two reports of one fact, and a server that says "running" after
  // writing finished would otherwise park a badge forever. The timestamp is the observable.
  expect(attentionSignals({ crawls: [crawl("running")] })).toEqual([]);
 });

 test("an unfetched list is silence", () => {
  expect(attentionSignals({ crawls: undefined })).toEqual([]);
 });

 test("the dashboard does not mirror another tool's queue", () => {
  // A held request belongs to Proxy and a skip to Scanner. If the dashboard copied either, the
  // same number would sit on two tabs and the operator would have to guess which one to open.
  const signals = attentionSignals({ intercept: held(2), liveAudit: liveAudit(4), crawls: [crawl("done")] });
  expect(attentionFor(signals, "dashboard")).toBeUndefined();
  expect(attentionFor(signals, "proxy")?.count).toBe(2);
  expect(attentionFor(signals, "scanner")?.count).toBe(4);
 });

 test("all three sources can be in force at once, one per tool", () => {
  const signals = attentionSignals({
   intercept: held(1),
   liveAudit: liveAudit(5),
   crawls: [crawl("failed")],
  });
  expect(signals.map((s) => s.tool)).toEqual(["proxy", "scanner", "dashboard"]);
 });
});
