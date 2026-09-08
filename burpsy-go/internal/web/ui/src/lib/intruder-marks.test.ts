import { describe, expect, test } from "bun:test";
import {
  addManualSpan,
  displayText,
  displayToRaw,
  MARK_CHAR,
  selectionToRawSpan,
  type ManualSpanView,
} from "./intruder-marks";

const RAW = "GET /search?q=alpha&lang=en HTTP/1.1\r\nHost: shop.test\r\n\r\n";

function spans(items: Array<[number, number, string]>): ManualSpanView[] {
  return items.map(([start, end, text]) => ({ start, end, text }));
}

// Manual payload markers (burpsy-react-ui-mun): the positions list and the launch body speak raw
// offsets, while the editor shows the request with "§" pairs folded in. These tests pin the
// arithmetic between the two, because a marker off by one byte attacks the wrong thing silently.

describe("addManualSpan", () => {
  test("keeps spans sorted and records the marked text", () => {
    const result = addManualSpan([], 5, 10, "abcde");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.spans).toEqual([{ start: 5, end: 10, text: "abcde" }]);
  });

  test("inserts a later span after an earlier one regardless of marking order", () => {
    const first = addManualSpan([], 20, 24, "wxyz");
    if (!first.ok) throw new Error("first mark should be accepted");
    const result = addManualSpan(first.spans, 5, 10, "abcde");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.spans.map((span) => span.start)).toEqual([5, 20]);
  });

  test("refuses an empty or inverted selection", () => {
    expect(addManualSpan([], 5, 5, "").ok).toBe(false);
    expect(addManualSpan([], 10, 5, "").ok).toBe(false);
    expect(addManualSpan([], -1, 5, "").ok).toBe(false);
  });

  test("refuses a range overlapping an existing marker, allows adjacency", () => {
    const existing = spans([[5, 10, "abcde"]]);
    expect(addManualSpan(existing, 9, 12, "yz").ok).toBe(false);
    expect(addManualSpan(existing, 4, 6, "ab").ok).toBe(false);
    // Touching byte boundaries is not overlapping: byte 10 belongs to the new mark alone.
    const adjacent = addManualSpan(existing, 10, 14, "fghi");
    expect(adjacent.ok).toBe(true);
    if (!adjacent.ok) return;
    expect(adjacent.spans.map((span) => span.start)).toEqual([5, 10]);
  });
});

describe("displayText", () => {
  test("wraps each marked range in a § pair", () => {
    const marked = displayText(RAW, spans([[RAW.indexOf("alpha"), RAW.indexOf("alpha") + 5, "alpha"]]));
    expect(marked).toContain(`q=${MARK_CHAR}alpha${MARK_CHAR}&lang=en`);
    // Exactly two characters added.
    expect(marked.length).toBe(RAW.length + 2);
  });

  test("wraps several markers and stays the raw text plus two per marker", () => {
    const a = RAW.indexOf("alpha");
    const l = RAW.indexOf("lang=") + 5;
    const marked = displayText(RAW, spans([[a, a + 5, "alpha"], [l, l + 2, "en"]]));
    expect(marked.length).toBe(RAW.length + 4);
    expect(marked).toContain(`${MARK_CHAR}alpha${MARK_CHAR}`);
    expect(marked).toContain(`${MARK_CHAR}en${MARK_CHAR}`);
  });

  test("round-trips: no markers means the raw text", () => {
    expect(displayText(RAW, [])).toBe(RAW);
  });
});

describe("displayToRaw", () => {
  test("is the identity with no markers", () => {
    expect(displayToRaw([], 0)).toBe(0);
    expect(displayToRaw([], 17)).toBe(17);
  });

  test("shifts offsets past the marker by the inserted characters", () => {
    const a = RAW.indexOf("alpha");
    const one = spans([[a, a + 5, "alpha"]]);
    // Before the marker: untouched.
    expect(displayToRaw(one, a)).toBe(a);
    expect(displayToRaw(one, 3)).toBe(3);
    // The opening § itself sits between a-1's raw byte and a: display a+1 names raw a.
    expect(displayToRaw(one, a + 1)).toBe(a);
    // The first marked byte.
    expect(displayToRaw(one, a + 2)).toBe(a + 1);
    // After the closing §: two characters have been inserted.
    expect(displayToRaw(one, a + 8)).toBe(a + 6);
  });

  test("accounts for every earlier marker", () => {
    const a = RAW.indexOf("alpha");
    const l = RAW.indexOf("lang=") + 5;
    const two = spans([[a, a + 5, "alpha"], [l, l + 2, "en"]]);
    // Display offset of the "en" marker's first byte: l + 2 (the alpha pair) + 1 (its opening §).
    expect(displayToRaw(two, l + 3)).toBe(l);
    // Well past both markers.
    expect(displayToRaw(two, RAW.length + 4)).toBe(RAW.length);
  });
});

describe("selectionToRawSpan", () => {
  test("maps a display selection inside a marker back to the raw range", () => {
    const a = RAW.indexOf("alpha");
    const one = spans([[a, a + 5, "alpha"]]);
    // Select exactly the marked bytes in the display text.
    expect(selectionToRawSpan(one, a + 1, a + 6)).toEqual({ start: a, end: a + 5 });
  });

  test("maps a selection across a marker to the covering raw range", () => {
    const a = RAW.indexOf("alpha");
    const one = spans([[a, a + 5, "alpha"]]);
    // §alpha§ in display coordinates.
    expect(selectionToRawSpan(one, a, a + 7)).toEqual({ start: a, end: a + 5 });
  });
});
