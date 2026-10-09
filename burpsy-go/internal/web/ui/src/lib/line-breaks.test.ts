// The detail view's CR/LF codec (burpsy-react-ui-ln2a). A field cannot hold a CR — an <input> strips
// it and a <textarea> folds CRLF to LF — so the view shows glyphs and maps back on Apply. These pin
// that the mapping is exact in both directions and that the one lossy case is detectable.
import { describe, expect, test } from "bun:test";
import { CRLF_GLYPHS, hasLineBreak, hasLineBreakGlyphs, insertAt, readLineBreaks, showLineBreaks } from "./line-breaks";

describe("line-break glyphs", () => {
  test("CR and LF each become their own glyph and come back as the same octets", () => {
    const value = "a\r\nb\rc\nd";
    const shown = showLineBreaks(value);
    expect(shown).toBe("a␍␊b␍c␊d");
    expect(/[\r\n]/.test(shown), "a field must never be handed a real line break").toBe(false);
    expect(readLineBreaks(shown)).toBe(value);
  });

  test("Shift+Return inserts CR then LF at the caret, replacing a selection", () => {
    const { text, caret } = insertAt("ab", 1, 1, CRLF_GLYPHS);
    expect(readLineBreaks(text)).toBe("a\r\nb");
    expect(caret).toBe(3);
    expect(readLineBreaks(insertAt("abcd", 1, 3, CRLF_GLYPHS).text)).toBe("a\r\nd");
  });

  test("a value that already holds a glyph is detected, because mapping it back would invent a CR", () => {
    expect(hasLineBreakGlyphs("x␍y")).toBe(true);
    expect(hasLineBreakGlyphs("plain")).toBe(false);
    expect(hasLineBreak("x\ny")).toBe(true);
    expect(hasLineBreak("x y")).toBe(false);
  });
});
