import { describe, expect, test } from "bun:test";
import { attentionFor, attentionSignals } from "./attention";
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
