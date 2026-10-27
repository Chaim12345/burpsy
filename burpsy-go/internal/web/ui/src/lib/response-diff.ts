// Repeater's change highlighting between a response and the previous one in the same tab
// (burpsy-react-ui-b4gt). Burp: "Burp Repeater highlights any changes between the new and original
// responses" (testing-for-reflected-xss.html) — a one-character difference after a payload tweak
// should not have to be found by eye or by a round trip through Comparer.
//
// The diff itself is the server's /api/tools/compare (the Comparer engine, word granularity), so
// Repeater and Comparer cannot disagree about what changed. What lives here is coordinate work, and
// it is where this feature could quietly lie:
//
//  1. The engine's offsets are BYTE offsets into the UTF-8 encoding of the text it was given. The
//     editor indexes a JavaScript string in UTF-16 code units. "é" is 2 bytes and 1 unit, an emoji
//     4 bytes and 2 units — using a byte offset as a string index paints the wrong word after the
//     first multibyte character, and the error grows with every one.
//  2. CodeMirror normalises CRLF to a single line break, so a position in the message string is
//     not a position in the editor's document: every CRLF before it is one unit shorter there.
//
// Both mappings are pure and tested in response-diff.test.ts.

/** One op as /api/tools/compare returns it. Offsets are bytes into the UTF-8 of a and b. */
export interface CompareOp {
 kind: "equal" | "replace" | "insert" | "delete";
 a_offset: number;
 a_len: number;
 b_offset: number;
 b_len: number;
 uninteresting?: boolean;
}

/** A change to paint on the NEW response, in UTF-16 positions of the message string. */
export interface ChangeMark {
 from: number;
 to: number;
 /** "changed" spans text that differs or is new; "deleted" is a point where old text was removed. */
 kind: "changed" | "deleted";
}

/** The UTF-8 byte length of one UTF-16 code unit position's code point, and how many units it uses. */
function codePointAt(text: string, index: number): { bytes: number; units: number } {
 const code = text.codePointAt(index) ?? 0;
 const units = code > 0xffff ? 2 : 1;
 const bytes = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
 return { bytes, units };
}

/**
 * Map a list of ascending byte offsets into `text`'s UTF-8 encoding to UTF-16 indices, in one pass.
 * An offset that falls inside a multibyte character maps to that character's start, so a span is
 * never cut through the middle of a code point; an offset past the end maps to text.length.
 */
export function byteOffsetsToUtf16(text: string, offsets: number[]): number[] {
 const order = offsets.map((offset, at) => ({ offset, at })).sort((x, y) => x.offset - y.offset);
 const out = new Array<number>(offsets.length);
 let unit = 0;
 let byte = 0;
 for (const { offset, at } of order) {
  while (unit < text.length) {
   const next = codePointAt(text, unit);
   if (byte + next.bytes > offset) break;
   byte += next.bytes;
   unit += next.units;
  }
  out[at] = unit;
 }
 return out;
}

/** Map a position in the message string to CodeMirror's document, which counts CRLF as one. */
export function valuePosToDocPos(value: string, pos: number): number {
 let crlf = 0;
 for (let at = value.indexOf("\r\n"); at >= 0 && at + 1 < pos; at = value.indexOf("\r\n", at + 2)) crlf++;
 return pos - crlf;
}

/**
 * The marks to paint on the new response `b`: every replace/insert span on b's side, and a point
 * mark where a delete removed old text. Differences the operator marked uninteresting (the
 * Comparer's discounted headers) are left unpainted and counted, so the badge can say so.
 */
export function changeMarksFor(b: string, ops: CompareOp[]): { marks: ChangeMark[]; discounted: number } {
 const wanted = ops.filter((op) => op.kind !== "equal");
 const offsets: number[] = [];
 for (const op of wanted) offsets.push(op.b_offset, op.b_offset + op.b_len);
 const units = byteOffsetsToUtf16(b, offsets);
 const marks: ChangeMark[] = [];
 let discounted = 0;
 wanted.forEach((op, index) => {
  if (op.uninteresting) {
   discounted++;
   return;
  }
  const from = units[index * 2]!;
  const to = units[index * 2 + 1]!;
  if (op.kind === "delete" || to <= from) {
   marks.push({ from, to: from, kind: "deleted" });
  } else {
   marks.push({ from, to, kind: "changed" });
  }
 });
 return { marks, discounted };
}

/**
 * The largest response, in UTF-8 bytes, change highlighting diffs. Past it the comparison is
 * skipped and the badge says so — a word diff of two multi-megabyte bodies on every send would make
 * the Send button feel broken, and a silently absent highlight would read as "nothing changed".
 */
export const MAX_DIFF_BYTES = 512 * 1024;
