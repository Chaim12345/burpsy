import { describe, expect, test } from "bun:test";
import { delayVariationFields } from "./intruder-variation";

// The page must not send a variation the operator did not ask for, and must not swallow one it
// cannot honour — the server's refusal names which half was impossible, and that reason is the
// only thing that tells the operator what to type instead (burpsy-react-ui-nn0n).

describe("the delay-variation fields an attack sends", () => {
  test("a form nobody touched sends nothing, so the attack is paced exactly as it always was", () => {
    expect(delayVariationFields("", "")).toEqual({});
    expect(delayVariationFields("   ", "  ")).toEqual({});
  });

  test("an explicit zero is off, not a variation of zero", () => {
    // Both zero would otherwise be refused server-side as "nothing to vary" — a refusal earned by
    // typing the number that means off.
    expect(delayVariationFields("0", "0")).toEqual({});
    expect(delayVariationFields("0", "50")).toEqual({ delay_increment_ms: 50 });
    expect(delayVariationFields("25", "0")).toEqual({ delay_jitter_percent: 25 });
  });

  test("each field travels on its own", () => {
    expect(delayVariationFields("25", "")).toEqual({ delay_jitter_percent: 25 });
    expect(delayVariationFields("", "50")).toEqual({ delay_increment_ms: 50 });
    expect(delayVariationFields("12.5", "5")).toEqual({ delay_jitter_percent: 12.5, delay_increment_ms: 5 });
  });

  test("an out-of-range number is sent, so the server's reason reaches the operator", () => {
    expect(delayVariationFields("150", "-10")).toEqual({ delay_jitter_percent: 150, delay_increment_ms: -10 });
  });

  test("text that is not a number is not sent as NaN", () => {
    expect(delayVariationFields("abc", "")).toEqual({});
    expect(delayVariationFields("", "Infinity")).toEqual({});
  });
});
