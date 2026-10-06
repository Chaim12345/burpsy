import { describe, expect, test } from "bun:test";
import {
  byteOffsetToCharIndex,
  charIndexToByteOffset,
  docPosToValuePos,
} from "./message-views";

// The audit-selection span arithmetic (burpsy-react-ui-c6oq). The server's
// insertion_spans index the raw request bytes, while the editor hands over a
// CodeMirror selection — UTF-16 positions into a document whose CRLFs CM6 has
// normalised away. A conversion that drifts one byte splices payloads into the
// byte AFTER the one the operator selected, silently, so these tests pin the
// arithmetic on the two places it can go wrong: multi-byte UTF-8 and line-break
// normalisation.

describe("charIndexToByteOffset", () => {
  test("ASCII text: byte offset equals character index", () => {
    const value = "GET /search?q=alpha HTTP/1.1";
    expect(charIndexToByteOffset(value, 0)).toBe(0);
    expect(charIndexToByteOffset(value, 5)).toBe(5);
    expect(charIndexToByteOffset(value, value.length)).toBe(value.length);
  });

  test("multi-byte characters count their UTF-8 width", () => {
    // UTF-16 indices: a=0, é=1, b=2, €=3, 🎉=4..5 (surrogate pair), z=6.
    // UTF-8 bytes: a=1, é=2, b=1, €=3, 🎉=4, z=1 — total 12.
    const value = "aéb€🎉z";
    expect(new TextEncoder().encode(value).length).toBe(12);
    expect(charIndexToByteOffset(value, 1)).toBe(1); // before é
    expect(charIndexToByteOffset(value, 2)).toBe(3); // after é: 1 + 2
    expect(charIndexToByteOffset(value, 3)).toBe(4); // before €: 3 + b's 1
    expect(charIndexToByteOffset(value, 4)).toBe(7); // before 🎉: 4 + €'s 3
    expect(charIndexToByteOffset(value, 6)).toBe(11); // before z: 7 + 🎉's 4
    expect(charIndexToByteOffset(value, 7)).toBe(12); // the end: 11 + 1
  });

  test("a position inside a surrogate pair maps past the pair — an editor can never hold it anyway", () => {
    const value = "a🎉z"; // indices: a=0, 🎉=1..2, z=3
    expect(charIndexToByteOffset(value, 1)).toBe(1); // pair start
    expect(charIndexToByteOffset(value, 2)).toBe(5); // mid-pair: after the pair's 4 bytes
    expect(charIndexToByteOffset(value, 3)).toBe(5); // z itself
  });

  test("is the inverse of byteOffsetToCharIndex at every character boundary", () => {
    const value = "héllo wörld € café 🎉 tail";
    expect(new TextEncoder().encode(value).length).toBeGreaterThan(value.length); // non-ASCII really present
    // Round-trip: char -> byte -> char must land back on the same character. A
    // mid-pair UTF-16 index is not a character boundary — skip those.
    for (let index = 0; index <= value.length; index += 1) {
      const at = value.charCodeAt(index);
      if (at >= 0xdc00 && at <= 0xdfff) continue; // low surrogate: index points inside a pair
      const roundTrip = byteOffsetToCharIndex(value, charIndexToByteOffset(value, index));
      expect(roundTrip).toBe(index);
    }
  });

  test("clamps: a non-positive index is byte 0, an index past the end is the byte length", () => {
    const value = "abc";
    expect(charIndexToByteOffset(value, -3)).toBe(0);
    expect(charIndexToByteOffset(value, 99)).toBe(3);
  });
});

describe("docPosToValuePos", () => {
  test("LF-only text: document positions map one to one", () => {
    const value = "GET / HTTP/1.1\nHost: t\n\nbody";
    expect(docPosToValuePos(value, 0)).toBe(0);
    expect(docPosToValuePos(value, 14)).toBe(14); // at the \n
    expect(docPosToValuePos(value, 16)).toBe(16); // past it
    expect(docPosToValuePos(value, value.length)).toBe(value.length);
  });

  test("CRLF text: a document position past N line breaks is N bytes further in the value", () => {
    const value = "GET /a HTTP/1.1\r\nHost: t\r\n\r\nbody";
    // CM6 document: "GET /a HTTP/1.1\nHost: t\n\nbody" — 29 chars vs the value's 32.
    const doc = value.replace(/\r\n/g, "\n");
    expect(doc.length).toBe(29);
    expect(value.length).toBe(32);
    // Document index 16 is 'H' of Host (15 + one \n); value index 17 is 'H'.
    expect(doc.indexOf("Host")).toBe(16);
    // Document index 25 is 'b' of body: three CRLFs passed, so value index 28.
    expect(doc.indexOf("body")).toBe(25);
    expect(docPosToValuePos(value, 25)).toBe(28);
    expect(docPosToValuePos(value, doc.length)).toBe(value.length);
  });

  test("a document position that falls inside a CRLF clamps to the CR", () => {
    const value = "one\r\ntwo";
    // Document: "one\ntwo". Document position 3 IS the normalised '\n'; in the value
    // it is the '\r' at index 3. Position 4 is 't', whose value index is 5.
    expect(docPosToValuePos(value, 3)).toBe(3);
    expect(docPosToValuePos(value, 4)).toBe(5);
  });

  test("bare CR line breaks map one to one: CM6 replaces the byte without changing length", () => {
    const value = "one\rtwo";
    // CM6 turns a bare \r into \n without changing the length, so every
    // document position is the value position it names.
    expect(docPosToValuePos(value, 4)).toBe(4);
  });

  test("mixed line endings keep every break's own width", () => {
    const value = "a\r\nb\rc\nd";
    // Document: "a\nb\nc\nd" — a=0, \n=1, b=2, \n=3, c=4, \n=5, d=6.
    expect(docPosToValuePos(value, 2)).toBe(3); // 'b' in value
    expect(docPosToValuePos(value, 4)).toBe(5); // 'c' in value
    expect(docPosToValuePos(value, 6)).toBe(7); // 'd' in value
  });

  test("clamps: a non-positive position is 0, a position past the document end is the value length", () => {
    expect(docPosToValuePos("abc\r\ndef", -1)).toBe(0);
    expect(docPosToValuePos("abc\r\ndef", 99)).toBe(8);
  });
});

describe("the full chain: document position to raw byte span", () => {
  test("a selection on the body of a CRLF request lands on the bytes it names, not three early", () => {
    const value = "POST /login HTTP/1.1\r\nHost: shop.test\r\n\r\nuser=admin&pw=é";
    // The document CM6 holds: every \r\n became \n, so the needle sits three
    // bytes earlier in the document than in the value.
    const doc = value.replace(/\r\n/g, "\n");
    const needle = "user=admin";
    const valueIndex = value.indexOf(needle);
    const docIndex = doc.indexOf(needle);
    expect(valueIndex - docIndex).toBe(3); // three CRLFs precede the body
    // The needle's raw byte offset, computed INDEPENDENTLY of the code under
    // test: encode the value's prefix up to the needle and take its length.
    const rawOffset = new TextEncoder().encode(value.slice(0, valueIndex)).length;
    const byteSpan = charIndexToByteOffset(value, docPosToValuePos(value, docIndex));
    expect(byteSpan).toBe(rawOffset);
    // The two bytes before the span are the blank line's CRLF in the raw bytes —
    // the exact drift a conversion that ignored \r would get wrong.
    const raw = new TextEncoder().encode(value);
    expect(Array.from(raw.slice(byteSpan - 2, byteSpan))).toEqual([13, 10]);
  });

  test("a selection over a multibyte parameter value in a CRLF request measures its exact bytes", () => {
    const value = "POST /login HTTP/1.1\r\nHost: shop.test\r\n\r\npw=café";
    const doc = value.replace(/\r\n/g, "\n");
    const needle = "café";
    const docIndex = doc.indexOf(needle);
    const rawOffset = new TextEncoder().encode(value.slice(0, value.indexOf(needle))).length;
    // The selection covers "café" in the document: [docIndex, docIndex + 5).
    const start = charIndexToByteOffset(value, docPosToValuePos(value, docIndex));
    const end = charIndexToByteOffset(value, docPosToValuePos(value, docIndex + needle.length));
    expect(start).toBe(rawOffset);
    // é is two bytes, so the span is five UTF-8 bytes even though it is four characters.
    expect(end - start).toBe(5);
  });
});
