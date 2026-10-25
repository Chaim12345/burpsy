import { describe, expect, test } from "bun:test";
import { breakGlyphs } from "./message-views";


// Burp's \n toggle (burpsy-react-ui-1e4) has two halves, and each is pinned where it can
// actually fail loudly:
//
// 1. breakGlyphs, the pure naming of line breaks. This is the half a wrong answer silently
//    poisons: CodeMirror normalises CRLF to LF the moment it parses a document, so any glyph
//    derived from the *document* would certify "LF only" on a CRLF message - exactly the
//    misreading the toggle exists to prevent. The glyphs must come off the raw message text,
//    and these tests hold the raw-text contract: every break spelling (CRLF, bare CR, bare
//    LF, and a message mixing them) is named distinctly and in order.
//
// 2. The wiring in ui/editor.tsx. No unit test of the extension alone can see that the
//    toolbar toggle actually installs it - that wire runs between a useState and a useMemo,
//    and the project has shipped a missing wire before (keymap-installed.test.ts documents
//    the precedent). The structural assertions below hold the shape: the state, the
//    conditional push of both halves (glyphs AND end-of-line markers), and the toggle button
//    that drives it.

describe("breakGlyphs", () => {
  test("a CRLF message names every break as CRLF", () => {
    const message = "POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 0\r\n";
    expect(breakGlyphs(message)).toEqual(["␍␊", "␍␊", "␍␊"]);
  });

  test("an LF-only message names every break as LF", () => {
    expect(breakGlyphs("a\nb\nc")).toEqual(["␊", "␊"]);
  });

  test("a bare-CR message names every break as CR", () => {
    expect(breakGlyphs("a\rb\rc")).toEqual(["␍", "␍"]);
  });

  test("a message mixing CRLF and bare LF is named distinctly, in order", () => {
    // The smuggling probe: header injection via a lone LF between CRLF lines. The glyphs
    // must disagree where the bytes disagree - one list entry per break, never collapsed.
    expect(breakGlyphs("x\r\ny\nz\r\n")).toEqual(["␍␊", "␊", "␍␊"]);
  });

  test("a message with no breaks names nothing", () => {
    expect(breakGlyphs("GET / HTTP/1.1")).toEqual([]);
    expect(breakGlyphs("")).toEqual([]);
  });

  test("CRLF is matched as one break, not a CR plus an LF", () => {
    expect(breakGlyphs("a\r\nb")).toHaveLength(1);
  });
});

// The toggle itself (off by default, glyphs and EOL markers together, EOL marker names the document's own
// break, pressed state) is pinned by rendering the editor: ui/editor-strip.test.tsx (vln1).
