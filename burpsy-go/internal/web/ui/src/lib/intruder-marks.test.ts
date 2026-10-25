import { describe, expect, test } from "bun:test";
import { EditorState } from "@codemirror/state";
import { docPosToValuePos } from "./message-views";
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
    expect(selectionToRawSpan(RAW, one, a + 1, a + 6)).toEqual({ ok: true, start: a, end: a + 5, text: "alpha" });
  });

  test("maps a selection across a marker to the covering raw range", () => {
    const a = RAW.indexOf("alpha");
    const one = spans([[a, a + 5, "alpha"]]);
    // §alpha§ in display coordinates.
    expect(selectionToRawSpan(RAW, one, a, a + 7)).toEqual({ ok: true, start: a, end: a + 5, text: "alpha" });
  });
});

// burpsy-react-ui-ngao: the editor is CodeMirror, whose document normalises every CRLF to one
// "\n". These tests drive the whole Add § chain the page runs — a real CodeMirror document of the
// displayed text, a selection in it, the editor's docPosToValuePos, then selectionToRawSpan — and
// assert on the exact wire bytes the span names, which is what the server splices.

const CRLF_REQUEST =
  "POST /login?next=%2Fhome HTTP/1.1\r\n" +
  "Host: shop.test\r\n" +
  "Cookie: session=abc123; theme=dark\r\n" +
  "Content-Type: application/x-www-form-urlencoded\r\n" +
  "Content-Length: 27\r\n" +
  "\r\n" +
  "user=alice&pass=hunter2&x=1";

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

/** The wire bytes [start, end) of `raw`, as the server would slice msg.Raw(). */
function wireSlice(raw: string, start: number, end: number): string {
  return fromUtf8.decode(utf8.encode(raw).slice(start, end));
}

/**
 * Select `needle` (its `nth` occurrence) in a CodeMirror document of the display text and run
 * Add § the way the editor + page do. Returns the stored spans.
 */
function addMarkViaEditor(raw: string, existing: ManualSpanView[], needle: string, nth = 0): ManualSpanView[] {
  const display = displayText(raw, existing);
  const doc = EditorState.create({ doc: display }).doc;
  const docText = doc.toString();
  let from = -1;
  for (let i = 0; i <= nth; i++) from = docText.indexOf(needle, from + 1);
  if (from < 0) throw new Error(`"${needle}" is not in the document`);
  const to = from + needle.length;
  // The editor's half (ui/editor.tsx payloadMarks): document → value positions.
  const start = docPosToValuePos(display, from);
  const end = docPosToValuePos(display, to);
  // The page's half (pages/intruder.tsx onAddManualSpan).
  const mapped = selectionToRawSpan(raw, existing, start, end, utf8.encode(raw).length);
  if (!mapped.ok) throw new Error(mapped.reason);
  const added = addManualSpan(existing, mapped.start, mapped.end, mapped.text);
  if (!added.ok) throw new Error(added.reason);
  return added.spans;
}

describe("Add § on a CRLF request (ngao)", () => {
  test("CodeMirror really does count each CRLF as one character (the premise of the fix)", () => {
    const doc = EditorState.create({ doc: CRLF_REQUEST }).doc;
    expect(doc.length).toBe(CRLF_REQUEST.length - CRLF_REQUEST.split("\r\n").length + 1);
    // Without the mapping, a document offset on the cookie line names bytes two to the left.
    const docFrom = doc.toString().indexOf("abc123");
    expect(wireSlice(CRLF_REQUEST, docFrom, docFrom + 6)).not.toBe("abc123");
  });

  test("marks exactly the selected bytes on every line", () => {
    for (const needle of ["%2Fhome", "shop.test", "abc123", "application/x-www-form-urlencoded", "27", "alice", "hunter2"]) {
      const span = addMarkViaEditor(CRLF_REQUEST, [], needle)[0]!;
      expect(wireSlice(CRLF_REQUEST, span.start, span.end)).toBe(needle);
      expect(span.text).toBe(needle);
      expect(span.start).toBe(CRLF_REQUEST.indexOf(needle));
    }
  });

  test("a selection spanning line breaks keeps both CRLF bytes", () => {
    const needle = "shop.test\nCookie";
    const span = addMarkViaEditor(CRLF_REQUEST, [], needle)[0]!;
    expect(wireSlice(CRLF_REQUEST, span.start, span.end)).toBe("shop.test\r\nCookie");
    expect(span.text).toBe("shop.test\r\nCookie");
  });

  test("a second marker after an existing one still names its own bytes, and both render back", () => {
    let marks = addMarkViaEditor(CRLF_REQUEST, [], "abc123");
    marks = addMarkViaEditor(CRLF_REQUEST, marks, "hunter2");
    marks = addMarkViaEditor(CRLF_REQUEST, marks, "shop.test");
    expect(marks.map((span) => wireSlice(CRLF_REQUEST, span.start, span.end))).toEqual(["shop.test", "abc123", "hunter2"]);
    // Rendering direction: the editor shows each stored byte span wrapped in its own § pair.
    const shown = EditorState.create({ doc: displayText(CRLF_REQUEST, marks) }).doc.toString();
    for (const needle of ["shop.test", "abc123", "hunter2"]) expect(shown).toContain(`${MARK_CHAR}${needle}${MARK_CHAR}`);
  });

  test("LF-only requests still mark exactly the selected bytes", () => {
    const lf = CRLF_REQUEST.replaceAll("\r\n", "\n");
    let marks = addMarkViaEditor(lf, [], "abc123");
    marks = addMarkViaEditor(lf, marks, "alice");
    expect(marks.map((span) => wireSlice(lf, span.start, span.end))).toEqual(["abc123", "alice"]);
    expect(marks[0]!.start).toBe(lf.indexOf("abc123"));
  });

  test("offsets are wire bytes past multi-byte characters, and render back in place", () => {
    const raw = "GET /caf\u00e9?q=\u{1F600} HTTP/1.1\r\nX-Name: J\u00fcrgen\r\nX-Id: 42\r\n\r\n";
    let marks = addMarkViaEditor(raw, [], "42");
    marks = addMarkViaEditor(raw, marks, "J\u00fcrgen");
    expect(marks.map((span) => wireSlice(raw, span.start, span.end))).toEqual(["J\u00fcrgen", "42"]);
    // é (2 bytes), 😀 (4 bytes, 2 UTF-16 units), ü (2 bytes): the byte offset is ahead of the index.
    expect(marks[1]!.start).toBe(utf8.encode(raw.slice(0, raw.indexOf("42"))).length);
    expect(displayText(raw, marks)).toContain(`${MARK_CHAR}42${MARK_CHAR}`);
    expect(displayText(raw, marks)).toContain(`${MARK_CHAR}J\u00fcrgen${MARK_CHAR}`);
  });

  test("refuses a mark past a byte the lossy text could not carry, allows one before it", () => {
    // One invalid byte in the body arrives in MessageView.text as U+FFFD (3 bytes) for 1 wire byte.
    const raw = "POST /x HTTP/1.1\r\nHost: a\r\n\r\nk=\uFFFD&v=1";
    const wireLength = utf8.encode(raw).length - 2;
    const display = displayText(raw, []);
    const at = (needle: string) => docPosToValuePos(display, EditorState.create({ doc: display }).doc.toString().indexOf(needle));
    const after = selectionToRawSpan(raw, [], at("v=1"), at("v=1") + 3, wireLength);
    expect(after.ok).toBe(false);
    const before = selectionToRawSpan(raw, [], at("Host"), at("Host") + 4, wireLength);
    expect(before).toEqual({ ok: true, start: raw.indexOf("Host"), end: raw.indexOf("Host") + 4, text: "Host" });
  });
});
