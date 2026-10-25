import {
 EditorView,
 Decoration,
 ViewPlugin,
 WidgetType,
 hoverTooltip,
 highlightSpecialChars,
 type DecorationSet,
 type ViewUpdate,
} from "@codemirror/view";
import { findNext, findPrevious, getSearchQuery, openSearchPanel, searchPanelOpen, SearchCursor } from "@codemirror/search";
import { EditorState, Prec, RangeSetBuilder, Transaction, type Extension } from "@codemirror/state";
import { documentText, lineSeparatorFor, selectionText, selectionTransformSpec } from "../lib/editor-eol";
import CodeMirror, { ExternalChange } from "@uiw/react-codemirror";
import { toast } from "sonner";
import {
 ClipboardPaste,
 Copy,
 Download,
 MoreHorizontal,
 Pilcrow,
 Radar,
 RadioTower,
 Search,
 WrapText,
 Percent,
 EyeOff,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { copyToClipboard, downloadText, formatBytes } from "../lib/api";
import {
 bodyOf,
 compactMessage,
 contentTypeOf,
 hexDumpBytes,
 hideHeadersIn,
 isResponse,
 parseMessage,
 prettyMessage,
 withContentLength,
 requestTargetPath,
 cookieHeaderTokens,
} from "../lib/message";
import {
 breakGlyphs,
 bodyTokens,
 byteOffsetToCharIndex,
 charIndexToByteOffset,
 decodeHoverToken,
 detectGraphQL,
 docPosToValuePos,
 findJwts,
 paramsOf,
 type BodyToken,
 type TokenClass,
} from "../lib/message-views";
import { pairSpans } from "../lib/message";
import {
 base64Decode,
 base64Encode,
 base64UrlDecode,
 base64UrlEncode,
 constructString,
 htmlDecode,
 htmlEncodeAllCharsDecimal,
 htmlEncodeAllCharsHex,
 htmlEncodeKeyChars,
 urlDecode,
 urlEncodeAllChars,
 urlEncodeAllCharsUnicode,
 urlEncodeKeyChars,
 type ConstructDialect,
} from "../lib/transforms";

const CONSTRUCT_DIALECTS: Record<ConstructDialect, string> = {
 js_double: "JavaScript (double-quoted)",
 js_single: "JavaScript (single-quoted)",
 sql_mssql: "SQL for Microsoft SQL Server",
 sql_oracle: "SQL for Oracle",
 sql_mysql: "SQL for MySQL",
};
import { cn } from "../lib/cn";
import { registerCommand } from "../lib/commands";
import { paragraphTarget } from "../lib/editor-paragraph";
import { usePluginEditorTabs } from "../lib/plugin-editor-tabs";
import { urlEncodeAsYouTypeExtension } from "../lib/url-encode-as-you-type";
import { useApp, moveEditorTab, type OptionalEditorTab, defaultEditorTabPrefs } from "../lib/store";
import { extraEditorTabs } from "../lib/editor-extra-tabs";
import { inlineDiffExtension } from "../lib/inline-diff";
import { valuePosToDocPos, type ChangeMark } from "../lib/response-diff";
import { INTROSPECTION_QUERY, LEGACY_INTROSPECTION_QUERY, setGraphQLQuery } from "../lib/graphql-introspection";
import { AttributesTab, BodyParamsTab, CookiesTab, HeadersTab, QueryParamsTab } from "./message-sections";
import { SlidersHorizontal, ChevronDown, ChevronUp } from "lucide-react";
import { useMintPayload } from "../lib/data.collab";
import { HexEditor } from "./hex-editor";
import { ContextMenu, DropdownMenu, hasMenuActions, type MenuGroup } from "./menu";
import { Button, IconButton, Modal } from "./primitives";
import { GraphQLView, JwtView, ParamsView } from "./typed-views";
import { ProtobufView } from "./protobuf-view";

const START_LINE = Decoration.mark({ class: "cm-http-start" });
const HEADER_NAME = Decoration.mark({ class: "cm-http-header-name" });
const HEADER_VALUE = Decoration.mark({ class: "cm-http-header-value" });
const BODY_LINE = Decoration.line({ class: "cm-http-body" });

/**
 * Headers are always small, so the request/body boundary is found by scanning a
 * bounded prefix rather than stringifying a body that may be megabytes.
 */
function headerEnd(view: EditorView): number {
 const probe = view.state.doc.sliceString(0, Math.min(view.state.doc.length, 65536));
 const crlf = probe.indexOf("\r\n\r\n");
 if (crlf >= 0) return crlf + 4;
 const lf = probe.indexOf("\n\n");
 if (lf >= 0) return lf + 2;
 return view.state.doc.length;
}

const TOKEN_DECORATIONS: Record<TokenClass, Decoration> = {
 "json-key": Decoration.mark({ class: "cm-tok-json-key" }),
 "json-string": Decoration.mark({ class: "cm-tok-json-string" }),
 "json-number": Decoration.mark({ class: "cm-tok-json-number" }),
 "json-constant": Decoration.mark({ class: "cm-tok-json-constant" }),
 "html-tag": Decoration.mark({ class: "cm-tok-html-tag" }),
 "html-attr-name": Decoration.mark({ class: "cm-tok-html-attr-name" }),
 "html-attr-value": Decoration.mark({ class: "cm-tok-html-attr-value" }),
 "js-keyword": Decoration.mark({ class: "cm-tok-js-keyword" }),
 "js-string": Decoration.mark({ class: "cm-tok-js-string" }),
 "js-comment": Decoration.mark({ class: "cm-tok-js-comment" }),
 "css-property": Decoration.mark({ class: "cm-tok-css-property" }),
 "css-value": Decoration.mark({ class: "cm-tok-css-value" }),
 "url-param-name": Decoration.mark({ class: "cm-tok-url-param-name" }),
 "url-param-value": Decoration.mark({ class: "cm-tok-url-param-value" }),
 "cookie-name": Decoration.mark({ class: "cm-tok-cookie-name" }),
 "cookie-value": Decoration.mark({ class: "cm-tok-cookie-value" }),
};

/**
 * Burp's mouse-over decode (6fq): hovering an encoded syntax item shows its decoded value —
 * URL-decode in requests, HTML-decode in responses. The decoders are the transforms module's
 * own; `decodeHoverToken` returns null when the decode is a no-op, so a plain ASCII token
 * grows no popup that restates itself. Bounded to the body region: hovering a header is not
 * a decode, and the tooltip exists only where the colouring does.
 */
function hoverDecodeTooltip(messageIsResponse: boolean, boundary: () => number, queryRange: () => { from: number; to: number } | null) {
 return hoverTooltip((view, pos) => {
  // The body region, or the request line's query: both are decode targets. A header value is
  // neither — Burp decodes parameters and HTML entities, not header bytes — so the gate is a
  // range test, not a "past the headers" one (the query lives IN the headers, and its values
  // are exactly what a request's popup exists to decode).
  const inBody = pos >= boundary();
  const inQuery = (() => {
   const range = queryRange();
   return range ? pos >= range.from && pos < range.to : false;
  })();
  if (!inBody && !inQuery) return null;
  const line = view.state.doc.lineAt(pos);
  const token = tokenAt(pos, line);
  if (!token) return null;
  const contentType = contentTypeOf(view.state.doc.sliceString(0, boundary()));
  const decoded = decodeHoverToken(line.text, token.from - line.from, token.to - line.from, messageIsResponse, contentType);
  if (!decoded) return null;
  return {
   pos: token.from,
   create: () => {
    const dom = document.createElement("div");
    dom.className = "cm-hover-decode";
    dom.textContent = decoded;
    return { dom };
   },
  };
 });
}

/** The encoded token under the pointer: a URL/query parameter value, or an HTML attribute
 *  value — the spans the colouring already drew, consulted here so the popup and the colour
 *  cannot disagree about what is a decode target. */
function tokenAt(pos: number, line: { from: number; text: string }): { from: number; to: number } | null {
 // The pointer sits inside a coloured span or on plain text. The span lookup is over the
 // token shapes themselves, computed here against this line: a parameter value's bounds are
 // its own `=` and `&`, an attribute value's are its quotes.
 const rel = pos - line.from;
 const text = line.text;
 // Form/query parameter: scan pairs on this line.
 const ampersands = [-1, ...[...text.matchAll(/&/g)].map((m) => m.index ?? -1)];
 for (let i = 0; i < ampersands.length; i++) {
  const from = ampersands[i]! + 1;
  const to = i + 1 < ampersands.length ? ampersands[i + 1]! : text.length;
  if (rel < from || rel >= to) continue;
  const eq = text.indexOf("=", from);
  if (eq < 0 || eq >= to) return null;
  if (rel >= eq && rel < to) return { from: line.from + eq + 1, to: line.from + to };
  return null;
 }
 // HTML attribute value: the nearest attr="..." pair the pointer falls inside.
 const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("[^"]*"|'[^']*')/g;
 for (const m of text.matchAll(attrRe)) {
  const valueFrom = m.index! + m[0].indexOf(m[2]!);
  const valueTo = valueFrom + m[2]!.length;
  if (rel >= valueFrom && rel < valueTo) return { from: line.from + valueFrom, to: line.from + valueTo };
 }
 return null;
}

/**
 * The body's token spans, computed for decoration only. Bounded like headerEnd: the body
 * text is scanned only up to what is on screen (visibleRanges), so a megabyte body never
 * tokenises whole. An empty set is normal — a plain-text body has nothing to highlight and
 * keeps the flat body tint.
 */
function bodyTokenSpansFor(view: EditorView): BodyToken[] {
 const boundary = headerEnd(view);
 const doc = view.state.doc;
 const contentType = contentTypeOf(doc.sliceString(0, boundary));
 const out: BodyToken[] = [];
 // Query params are the REQUEST's own colouring (Burp distinguishes request parameters):
 // the start line's query is scanned here, and its spans are line-1 offsets already.
 const firstLine = doc.line(1);
 const qFrom = firstLine.text.indexOf("?");
 if (qFrom >= 0) {
  const space = firstLine.text.indexOf(" ", qFrom);
  const query = firstLine.text.slice(qFrom, space < 0 ? firstLine.text.length : space);
  for (const pair of pairSpans(query)) {
   const eq = query.indexOf("=", pair.start);
   const base = firstLine.from + qFrom;
   if (eq < 0 || eq >= pair.end) {
    out.push({ cls: "url-param-name", start: base + pair.start, end: base + pair.end });
   } else {
    out.push({ cls: "url-param-name", start: base + pair.start, end: base + eq });
    out.push({ cls: "url-param-value", start: base + eq + 1, end: base + pair.end });
   }
  }
 }
 for (const { from, to } of view.visibleRanges) {
  if (to <= boundary) continue;
  const start = Math.max(from, boundary);
  const text = doc.sliceString(start, Math.min(to, doc.length));
  for (const token of bodyTokens(text, contentType)) {
   out.push({ ...token, start: token.start + start, end: token.end + start });
  }
  if (to >= doc.length) break;
 }
 return out;
}

function buildDecorations(view: EditorView): DecorationSet {
 const builder = new RangeSetBuilder<Decoration>();
 const boundary = headerEnd(view);
 const doc = view.state.doc;
 const tokens = bodyTokenSpansFor(view);
 // Past the boundary: a tokenised body carries its own colouring, so the flat body tint is
 // applied only when the body tokenised to nothing — a plain-text body keeps the tint, a
 // colourised one does not get a second layer over it.
 const tokenised = tokens.length > 0;
 // A mark must not cross the header boundary (the token spans are body-relative already);
 // the walk below adds them in document order interleaved with the line decorations, which
 // is the order RangeSetBuilder requires.
 let tokenIndex = 0;

 for (const { from, to } of view.visibleRanges) {
  let position = from;
  while (position <= to) {
   const line = doc.lineAt(position);
   if (line.from >= boundary) {
    // Token marks falling inside this line are added before the line's own decoration.
    while (tokenIndex < tokens.length && tokens[tokenIndex]!.start < line.to) {
     const token = tokens[tokenIndex]!;
     const tFrom = Math.max(token.start, line.from);
     const tTo = Math.min(token.end, line.to);
     if (tTo > tFrom) builder.add(tFrom, tTo, TOKEN_DECORATIONS[token.cls]!);
     tokenIndex += 1;
    }
    if (!tokenised && (line.length > 0 || line.from > boundary)) builder.add(line.from, line.from, BODY_LINE);
   } else if (line.number === 1) {
    // START_LINE first: RangeSetBuilder requires additions in increasing start order, and a
    // token mark inside the line starts later than the line itself — adding the line's own
    // mark after it would throw and kill every decoration this editor has (the exact
    // regression a query-bearing Repeater request exposed in the live pass).
    if (line.length > 0) builder.add(line.from, line.to, START_LINE);
    // The query params are line-1 tokens (the request's own colouring); they are consumed
    // here, in document order, or the cursor below would be out of step for every later line.
    while (tokenIndex < tokens.length && tokens[tokenIndex]!.start < line.to) {
     const token = tokens[tokenIndex]!;
     const tFrom = Math.max(token.start, line.from);
     const tTo = Math.min(token.end, line.to);
     if (tTo > tFrom) builder.add(tFrom, tTo, TOKEN_DECORATIONS[token.cls]!);
     tokenIndex += 1;
    }
   } else if (line.length > 0) {
    const colon = line.text.indexOf(":");
    if (colon > 0) {
     builder.add(line.from, line.from + colon, HEADER_NAME);
     if (line.from + colon + 1 < line.to) builder.add(line.from + colon + 1, line.to, HEADER_VALUE);
     // Cookie / Set-Cookie pairs (burpsy-react-ui-axm9), nested inside the value mark. They start after
     // the value mark's own start and come back in increasing order, which RangeSetBuilder requires.
     for (const token of cookieHeaderTokens(line.text)) {
      if (token.end > token.start) builder.add(line.from + token.start, line.from + token.end, TOKEN_DECORATIONS[token.cls]);
     }
    }
   }
   if (line.to >= doc.length) break;
   position = line.to + 1;
  }
 }
 return builder.finish();
}

const httpHighlight = ViewPlugin.fromClass(
 class {
  decorations: DecorationSet;
  constructor(view: EditorView) {
   this.decorations = buildDecorations(view);
  }
  update(update: ViewUpdate) {
   if (update.docChanged || update.viewportChanged) this.decorations = buildDecorations(update.view);
  }
 },
 { decorations: (plugin) => plugin.decorations },
);

/**
 * Burp's \\n toggle as a CodeMirror decoration (burpsy-react-ui-1e4). Bytes below 0x20 render
 * as their Unicode Control Picture (U+2400 block: NUL -> ␀, TAB -> ␉, LF -> ␊, CR -> ␍),
 * DEL as ␡, and 0x80-0xFF keep their own glyph inside a marked span with the code point as
 * its tooltip - those bytes are only invisible in fonts that lack them, so replacing them
 * with an escape would hide what the operator came to see. The default special-char set
 * already covers the C0 controls; addSpecialChars pulls in TAB (which CodeMirror leaves
 * alone) and the high range. A decoration only: the document - and therefore anything sent
 * or saved - is untouched.
 */
const nonPrintingGlyphs = highlightSpecialChars({
 render: (code) => {
  const span = document.createElement("span");
  span.className = "cm-nonprinting";
  if (code <= 0x1f) span.textContent = String.fromCodePoint(0x2400 + code);
  else if (code === 0x7f) span.textContent = "\u2421";
  else span.textContent = String.fromCodePoint(code);
  span.title = `U+${code.toString(16).toUpperCase().padStart(4, "0")}`;
  return span;
 },
 addSpecialChars: /[\t\x7f-\xff]/,
});

/**
 * Line-ending markers, the other half of the toggle. CodeMirror treats CR and LF as
 * structural line separators rather than document content, so highlightSpecialChars can
 * never see them - a message whose every line ends CRLF would show no glyph at all.
 * These zero-width end-of-line widgets name the actual break bytes instead (␍␊ for CRLF,
 * the smuggling-relevant case). Widgets are not document text: copying, saving and
 * sending are byte-identical with the toggle on or off.
 */
/**
 * Where a deletion happened in a changed response (b4gt): the old text is gone, so there is no span
 * to paint, and a zero-width marker at the point is the honest way to show that something was there.
 */
class DeletedMarker extends WidgetType {
 override eq(): boolean {
  return true;
 }
 override toDOM(): HTMLElement {
  const span = document.createElement("span");
  span.className = "cm-diff-deleted";
  // role="img" so the name is permitted: a bare span is the generic role, where aria-label is
  // prohibited and dropped.
  span.setAttribute("role", "img");
  span.title = "Text the previous response had here is gone";
  span.setAttribute("aria-label", "deleted text");
  return span;
 }
}

/** The change marks as a CodeMirror decoration set, mapped from message positions to the document. */
function changeDecorations(value: string, docLength: number, marks: ChangeMark[]): Extension {
 const ranges = [];
 for (const mark of marks) {
  const from = Math.min(valuePosToDocPos(value, mark.from), docLength);
  const to = Math.min(valuePosToDocPos(value, mark.to), docLength);
  if (mark.kind === "deleted" || to <= from) {
   ranges.push(Decoration.widget({ widget: new DeletedMarker(), side: 1 }).range(from));
  } else {
   ranges.push(Decoration.mark({ class: "cm-diff-changed" }).range(from, to));
  }
 }
 return EditorView.decorations.of(Decoration.set(ranges, true));
}

class EOLMarker extends WidgetType {
 constructor(readonly glyph: string) {
  super();
 }
 override eq(other: EOLMarker): boolean {
  return other.glyph === this.glyph;
 }
 override toDOM(): HTMLElement {
  const span = document.createElement("span");
  span.className = "cm-nonprinting cm-eol";
  span.textContent = this.glyph;
  return span;
 }
}

function buildEOLMarkers(view: EditorView): DecorationSet {
 const builder = new RangeSetBuilder<Decoration>();
 const doc = view.state.doc;
 // Every line of this document ends in the message's separator (EditorState.lineSeparator, set in
 // markedExtensions), so naming it names every break; a break of another kind inside a line is a
 // character, drawn by nonPrintingGlyphs.
 const glyph = breakGlyphs(view.state.lineBreak)[0];
 for (let lineNo = 1; lineNo <= doc.lines; lineNo += 1) {
  const line = doc.line(lineNo);
  // The final line has no break after it (a document ending in a break grows an empty
  // final line instead), so there is nothing to name there.
  if (line.to >= doc.length) break;
  if (glyph) builder.add(line.to, line.to, Decoration.widget({ widget: new EOLMarker(glyph), side: 1 }));
 }
 return builder.finish();
}

function nonPrintingEOLPlugin() {
 return ViewPlugin.fromClass(
  class {
   decorations: DecorationSet;
   constructor(view: EditorView) {
    this.decorations = buildEOLMarkers(view);
   }
   update(update: ViewUpdate) {
    if (update.docChanged || update.viewportChanged) this.decorations = buildEOLMarkers(update.view);
   }
  },
  { decorations: (plugin) => plugin.decorations },
 );
}

/**
 * Colours come from CSS custom properties so a single stylesheet drives both
 * themes; CodeMirror's generated rules resolve them at paint time.
 */
const editorTheme = EditorView.theme(
 {
  "&": { backgroundColor: "var(--editor-bg)", color: "var(--editor-fg)", fontSize: "var(--editor-font-size, 12px)" },
  // The editor font family (burpsy-react-ui-mqrn): --editor-font-family when the operator picked a
  // family, else the stylesheet's --font-mono. The content and the gutter read the same property so
  // the line numbers and the bytes stay in one face.
  ".cm-content": { fontFamily: "var(--editor-font-family, var(--font-mono))", padding: "8px 0", caretColor: "var(--accent)" },
  ".cm-gutters": {
   backgroundColor: "var(--editor-gutter-bg)",
   color: "var(--editor-gutter-fg)",
   border: "0",
   borderRight: "1px solid var(--editor-line)",
   fontFamily: "var(--editor-font-family, var(--font-mono))",
   fontSize: "calc(var(--editor-font-size, 12px) - 1px)",
  },
  ".cm-activeLine": { backgroundColor: "var(--editor-active-line)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--editor-active-line)", color: "var(--editor-fg)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground, .cm-content ::selection": {
   backgroundColor: "var(--editor-selection)",
  },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--accent)", borderLeftWidth: "2px" },
  ".cm-http-start": { color: "var(--editor-start)", fontWeight: "700" },
  ".cm-http-header-name": { color: "var(--editor-header-name)" },
  ".cm-http-header-value": { color: "var(--editor-header-value)" },
  ".cm-http-body": { color: "var(--editor-body)" },
  ".cm-panels": { backgroundColor: "var(--editor-gutter-bg)", color: "var(--editor-fg)", borderColor: "var(--editor-line)" },
  ".cm-searchMatch": { backgroundColor: "var(--editor-match)", outline: "1px solid var(--editor-match-border)" },
  ".cm-searchMatch.cm-searchMatch-selected": { backgroundColor: "var(--editor-match-selected)" },
  ".cm-selectionMatch": { backgroundColor: "var(--editor-match)" },
  ".cm-scroller": { overflow: "auto", lineHeight: "1.55" },
  ".cm-lineNumbers .cm-gutterElement": { padding: "0 6px 0 10px" },
 },
 { dark: false },
);

/**
 * Burp's editor hotkeys, applied to the selection. Bound at high precedence so
 * they win over the default keymap, and marked handled so the browser does not
 * also act on them (ctrl+S would otherwise open "save page").
 *
 * Deliberate parity choice: Burp uses ctrl+S for the editor's search and ctrl+F
 * to forward an intercepted message, which is the opposite of the browser
 * convention. Matching Burp is the point.
 */
function transformSelection(view: EditorView, transform: (input: string) => string): boolean {
 // Reads each range as the message's real text and writes the output back verbatim
 // (burpsy-react-ui-eslt): the document has no CR bytes, so a selection across a CRLF header
 // break read through sliceDoc was converted, and written back, without them.
 const spec = selectionTransformSpec(view.state, transform);
 if (!spec) return false;
 view.dispatch({ ...spec, scrollIntoView: true });
 return true;
}

/**
 * Read the modifiers straight off the keydown event rather than going through
 * CodeMirror's key names. For letter keys CodeMirror resolves a shifted press
 * back to the unshifted binding, so both "Mod-Shift-u" as a separate entry and
 * the binding's own `shift` slot lost to "Mod-u" — ctrl+shift+U ran the encoder.
 * Testing the flag here is unambiguous.
 */
const PAIRS: Record<string, { plain: (input: string) => string; shifted: (input: string) => string }> = {
 u: { plain: urlEncodeKeyChars, shifted: urlDecode },
 h: { plain: htmlEncodeKeyChars, shifted: htmlDecode },
 b: { plain: base64Encode, shifted: base64Decode },
};

/** The editor that currently holds the EDITOR_TOGGLE_* commands (see claimEditorCommands). */
let topEditor: symbol | null = null;

/**
 * Delete the line(s) the main selection touches, newline included — Burp's EDITOR_DELETE_LINE.
 * Written here rather than imported from @codemirror/commands, which this package only has as a
 * transitive dependency of @uiw/react-codemirror.
 */
function deleteLine(view: EditorView): boolean {
 const { state } = view;
 const sel = state.selection.main;
 const first = state.doc.lineAt(sel.from);
 const last = state.doc.lineAt(sel.to);
 let from = first.from;
 let to = last.to;
 if (to < state.doc.length)
  to += 1; // take the line break after
 else if (from > 0) from -= 1; // last line: take the break before instead
 view.dispatch({
  changes: { from, to },
  selection: { anchor: Math.min(from, state.doc.length - (to - from)) },
  scrollIntoView: true,
  userEvent: "delete.line",
 });
 return true;
}

/** Move the main cursor to a paragraph boundary (lib/editor-paragraph.ts), extending with shift. */
function moveParagraph(view: EditorView, direction: "up" | "down", extend: boolean): boolean {
 const { state } = view;
 const head = state.selection.main.head;
 const fromLine = state.doc.lineAt(head).number;
 const lines: string[] = [];
 for (let n = 1; n <= state.doc.lines; n += 1) lines.push(state.doc.line(n).text);
 const target = state.doc.line(paragraphTarget(lines, fromLine, direction));
 const pos = direction === "down" && target.number === state.doc.lines && target.text.trim() !== "" ? target.to : target.from;
 view.dispatch({
  selection: extend ? { anchor: state.selection.main.anchor, head: pos } : { anchor: pos },
  scrollIntoView: true,
 });
 return true;
}

const burpEditorKeys = Prec.high(
 EditorView.domEventHandlers({
  keydown(event, view) {
   if (!(event.ctrlKey || event.metaKey)) return false;
   const key = event.key.toLowerCase();

   // Burp's EDITOR_COPY_PRETTIFIED, Ctrl+Alt+C (2czi). A selection is copied as it reads on screen
   // (Pretty's selection is already pretty); with none, the whole message is copied prettified.
   if (event.altKey && !event.shiftKey && event.code === "KeyC") {
    event.preventDefault();
    const sel = view.state.selection.main;
    // The message's own text, CR bytes included (burpsy-react-ui-elam).
    const text = sel.empty ? prettyMessage(documentText(view.state)) : selectionText(view.state);
    void copyToClipboard(text).then(() => toast.success(sel.empty ? "Copied the message, prettified" : "Copied the selection"));
    return true;
   }
   if (event.altKey) return false;

   if (key === "s") {
    event.preventDefault();
    openSearchPanel(view);
    return true;
   }

   // Burp's previous/next search match, Ctrl+Comma / Ctrl+Period. With no search yet there is
   // nothing to step through, so the search panel opens instead of the key doing nothing.
   if (event.code === "Comma" || event.code === "Period") {
    event.preventDefault();
    if (!getSearchQuery(view.state).valid) {
     openSearchPanel(view);
     return true;
    }
    return event.code === "Comma" ? findPrevious(view) : findNext(view);
   }

   // Burp's EDITOR_DELETE_LINE, Ctrl+D — only in an editable editor. A read-only pane leaves the
   // key alone, so it stays the browser's bookmark key there, as everywhere outside an editor.
   if (key === "d" && !event.shiftKey) {
    if (view.state.readOnly) return false;
    event.preventDefault();
    return deleteLine(view);
   }

   // Burp's paragraph navigation, Ctrl+Up / Ctrl+Down, Shift to extend.
   if (event.key === "ArrowUp" || event.key === "ArrowDown") {
    event.preventDefault();
    return moveParagraph(view, event.key === "ArrowUp" ? "up" : "down", event.shiftKey);
   }

   const pair = PAIRS[key];
   if (!pair) return false;
   // Only claim the key when there is a selection to act on, so an unselected
   // ctrl+B still reaches whatever the browser would normally do.
   if (view.state.selection.ranges.every((range) => range.empty)) return false;
   event.preventDefault();
   return transformSelection(view, event.shiftKey ? pair.shifted : pair.plain);
  },
 }),
);

/**
 * Raw HTTP message editor. Used for both editing (Repeater, Intercept) and
 * inspection (history detail), because operators expect the same affordances —
 * line numbers, find, wrapping — in both.
 */
// The five operator-added tabs (t94i) are part of the same union: they ride the same strip,
// the same pick()/active machinery and the same aria-selected rules as the built-ins.
type MessageView =
 | "pretty"
 | "raw"
 | "hex"
 | "render"
 | "graphql"
 | "jwt"
 | "params"
 | "protobuf"
 | "headers"
 | "queryparams"
 | "bodyparams"
 | "cookies"
 | "attributes";

// The tab bar's labels, keyed by view. Kept next to the type so a view added to the
// union fails to compile here first — a tab that renders its key instead of a label is
// exactly the kind of half-wired view this editor shipped with once already.
/** The views that take an Add in an editable context (11r8): the ones whose items an operator
 *  adds to a request — never Attributes, which are facts about the message, not a list. */
const ADDABLE_VIEWS: MessageView[] = ["headers", "queryparams", "bodyparams", "cookies"];

const VIEW_LABELS: Record<MessageView, string> = {
 pretty: "Pretty",
 raw: "Raw",
 hex: "Hex",
 render: "Render",
 graphql: "GraphQL",
 jwt: "JWT",
 params: "Params",
 protobuf: "Protobuf",
 headers: "Headers",
 queryparams: "Query params",
 bodyparams: "Body params",
 cookies: "Cookies",
 attributes: "Attributes",
};

/**
 * Raw HTTP message editor with Burp's message-editor views.
 *
 * Raw, Hex and Pretty are the editable views, for reasons that pair with what each
 * view shows: Raw is the exact bytes as text, Hex is the exact bytes as bytes, and
 * Pretty is the operator's readable window onto the body — an edit there is written
 * back through compactMessage, which inverts the prettifier so the wire bytes stay
 * what every view (and the send path) shows. Render shows the response in a
 * sandboxed iframe, and GraphQL, JWT and Params read a structure out of the message
 * without offering to write one back; those stay read-only, and the note under the
 * editor says which.
 *
 * Pretty is also the default view when the body has a formattable format — Burp
 * opens Pretty whenever it detects a supported format (tools/message-editor/
 * text-editor.html), and a migrating operator who has to click Pretty on every
 * JSON body has been told their preference does not matter (burpsy-react-ui-vet).
 *
 * Every tab past Raw is conditional. Pretty appears only when reformatting would
 * change something; Render only for an HTML response; GraphQL, JWT and Params only
 * when the message actually carries one. A tab that is present on every message and
 * empty on all but a few teaches an operator to ignore the tab strip.
 */
export function HttpEditor({
 value,
 bodyBase64,
 onChange,
 readOnly = false,
 label,
 actions,
 height = "100%",
 filename = "message.txt",
 placeholder,
 className,
 views = true,
 menuGroups,
 payloadMarks,
 changeMarks,
 compareWith,
 saveGraphQLToSiteMap,
 auditSelection,
 onBodyBytesChange,
 messageId,
 requestPath,
 onRawSelection,
}: {
 value: string;
 /** The body's exact octets, base64 (MessageView.body_base64). Given, the Render view's image
  *  data URL is built from these bytes instead of from `value`'s text — whose non-UTF-8 bytes
  *  JSON already destroyed. The other views keep reading `value`, which remains the lossy text. */
 bodyBase64?: string;
 onChange?: (value: string) => void;
 readOnly?: boolean;
 label: string;
 actions?: ReactNode;
 height?: string;
 filename?: string;
 placeholder?: string;
 className?: string;
 /** Set false for non-HTTP payloads (a WebSocket frame, a token blob). */
 views?: boolean;
 /**
  * The message's own cross-tool actions — normally `useExchangeActions().menu(exchange)`.
  *
  * Burp's message editor carries the same menu as the table row above it, reachable both by
  * right-clicking the message and from an Actions button, and reading a response then sending
  * it straight to Repeater is the highest-frequency gesture in the tool. Omit this for an
  * editor with no exchange behind it (the Decoder's pane, a token blob) — the selection codecs
  * below are offered either way, because those act on the text and need nothing else.
  */
 menuGroups?: MenuGroup[];
 /**
  * Hand-marked payload positions (Burp's Add §, burpsy-react-ui-mun). When given, the Raw view's
  * selection menu gains an "Add § payload marker" entry that reports the selection as [start, end)
  * UTF-16 positions in `value` — CRLF restored (docPosToValuePos), NOT CodeMirror's document
  * offsets, which count each CRLF as one character and would land one short per preceding line
  * (burpsy-react-ui-ngao). `text` is `value`'s own slice, line breaks as they are in the message.
  * Callers displaying a transformed value (the Intruder base request shows its marks as "§"
  * pairs) map those positions back themselves. Not offered under a charset override, where the
  * document is not `value`'s characters at all.
  */
 payloadMarks?: {
  onAdd: (span: { start: number; end: number; text: string }) => void;
 };
 /**
  * Spans to highlight as changed (b4gt — Repeater's "highlights any changes between the new and
  * original responses"), in UTF-16 positions of `value`. Painted on the Raw view only: Pretty
  * reformats the text and a charset override shows other characters, so the positions would name
  * the wrong thing there.
  */
 changeMarks?: ChangeMark[];
 /**
  * The previous response, to lay over this one as an inline diff (burpsy-react-ui-6ibj,
  * lib/inline-diff.ts). Raw view only, where the document is the message itself; Pretty and the
  * charset override show a different text, so a diff there would name the wrong lines. Replaces
  * `changeMarks` while set: the two highlight the same changes in different ways.
  */
 compareWith?: string;
 /**
  * Burp's GraphQL > "Save GraphQL queries to site map" (7v1e). Given by a surface that knows the
  * exchange behind the message (Repeater); `enabled` says whether that exchange's response is an
  * introspection answer. Absent, the item is shown disabled with the reason.
  */
 saveGraphQLToSiteMap?: { enabled: boolean; run: () => void };
 /**
  * Actively audit a selected byte range (burpsy-react-ui-c6oq). When given, the Raw view's
  * context menu gains an "Actively audit this selection" entry that converts the CodeMirror
  * selection (UTF-16 indices) to a UTF-8 byte span and hands it to the caller for posting
  * to /api/audit/{id} with insertion_spans. Only the Raw view is safe — Pretty may reformat
  * the message, and the byte offsets would name the wrong thing.
  */
 auditSelection?: (span: [number, number]) => void;
 /**
  * Persist the request body as faithful bytes when the Protobuf view re-encodes an edit
  * (burpsy-react-ui-ytkk). A binary body cannot survive the editor's `value` string on the way to
  * the server, so a surface that can resend it (Repeater) stores the base64 here and sends it as
  * request_base64. Absent on read-only panes. */
 onBodyBytesChange?: (bodyBase64: string) => void;
 /**
  * The request's path, for a response editor (burpsy-react-ui-3pco). A request editor reads its own
  * path off the request line; a response cannot, and for gRPC the path (/pkg.Service/Method) is what
  * names the response's message type in a loaded .proto. Optional: without it the operator picks.
  */
 requestPath?: string;
 /**
  * The stored-message id behind this editor's value, when there is one. This is what makes a
  * loaded plugin's editor-tab registrations real (burpsy-react-ui-ww5): `editor.render` takes
  * {message, raw} and a plugin has no route to the traffic store, so the id both identifies the
  * message on the wire and names the bytes the tab fetches. Omit it for an editor with no
  * stored message (a draft, a token blob, the Decoder's input) — a plugin tab there could only
  * render from bytes that do not exist, and the strip stays honest by not offering it.
  */
 messageId?: number;
 /**
  * The Raw view's selection, reported as it changes, as [start, end) positions in `value` — CRLF
  * restored, so they index the message string the caller holds rather than CodeMirror's normalised
  * document (docPosToValuePos). null when nothing is selected, or when the active view is not the
  * unconverted Raw text (Pretty reformats; a charset override shows other characters), because a
  * position there would name the wrong text. Intruder's "Define extract grep from response" builds
  * its rule from this (burpsy-react-ui-df8r).
  */
 onRawSelection?: (selection: { start: number; end: number } | null) => void;
}): JSX.Element {
 const [wrap, setWrap] = useState(true);
 // Burp's eye button (burpsy-react-ui-whr): hide the headers named in the Settings > Message
 // editor lists, in Pretty only — the docs scope it there ("In the Pretty tab, you have the
 // option to hide HTTP headers…") and on Raw the bytes are the bytes. Which list applies is the
 // message's own direction: a request pane reads Hide request headers, a response pane Hide
 // response headers (Burp keeps the two apart: `user_options.misc.uninteresting_headers` vs
 // `user_options.misc.uninteresting_response_headers`).
 const hideRequestHeaders = useApp((state) => state.hideRequestHeaders);
 const hideResponseHeaders = useApp((state) => state.hideResponseHeaders);
 const hideHeadersByDefault = useApp((state) => state.hideHeadersByDefault);
 // Which headers this pane's eye would hide. Derived from the message, because one editor
 // instance shows a request in one pane and a response in the pane beside it.
 const hideList = isResponse(value) ? hideResponseHeaders : hideRequestHeaders;
 // The eye's state. `null` means the operator has not pressed it in this pane, so the Settings
 // default decides — the same rule `view` follows for an operator who has not picked a view
 // (burpsy-react-ui-vet). One explicit press wins for the life of this pane, because a choice
 // made by hand outranks a default set elsewhere.
 const [hidePicked, setHidePicked] = useState<boolean | null>(null);
 // Burp's \n toggle (burpsy-react-ui-1e4): off by default, and a pure decoration - the
 // document never changes, so toggling cannot alter the bytes that get sent.
 const [showNonPrinting, setShowNonPrinting] = useState(false);
 // Pretty first when it is available: the initial state cannot read canPretty (it
 // does not exist yet on first render), so the choice is deferred to the active
 // resolution below instead of a second source of truth in useState.
 const [view, setView] = useState<MessageView>("raw");
 // Whether the codec entries can act. Tracked as state rather than read off the view when the
 // menu is built: `groups` is evaluated at render time, so a selection made after that render
 // would leave every codec row enabled and doing nothing, or disabled and refusing to.
 const [hasSelection, setHasSelection] = useState(false);
 // Burp's Convert-selection on a read-only message (burpsy-react-ui-l7xj): "If the message is not
 // editable, then the result of the conversion is shown in a dialog." The result, not a toast — a
 // toast is read once and gone, while a converted payload is exactly what an operator wants to
 // copy, which a dialog with a copy affordance serves. Cleared on close.
 const [conversionResult, setConversionResult] = useState<undefined | { label: string; output: string }>(undefined);

 // Burp's message-editor character-set control (burpsy-react-ui-p836): "Recognize automatically
 // based on message headers", "Use the platform default" (UTF-8, this editor's behaviour before
 // this control existed), "Display as raw bytes", "Use a specific character set" — and "The
 // charset encoding options only apply to the message body." State only; see charsetLabel below
 // for how each maps to an actual decode.
 const [charsetMode, setCharsetMode] = useState<"utf-8" | "auto" | "raw-bytes" | "custom">("utf-8");
 const [customCharset, setCustomCharset] = useState("windows-1252");

 const editable = !readOnly && Boolean(onChange);
 // The search spec this editor last auto-scrolled for. Outside the useMemo because the
 // listener closes over it; per-editor, so two editors do not fight over one marker.
 const lastSearchSpecRef = useRef("");
 // The text this editor last handed to onChange, and the separator its state was built with.
 const emittedRef = useRef<string | null>(null);
 const separatorRef = useRef<"\r\n" | "\r" | "\n">("\n");
 // onRawSelection's inputs, refreshed every render (below, once `active` exists) so the selection
 // listener inside the memoised extensions reads the current callback, view and text.
 const rawSelectionRef = useRef<{
  report?: (selection: { start: number; end: number } | null) => void;
  rawView: boolean;
  value: string;
 }>({ rawView: false, value: "" });
 // Paste-from-file (burpsy-react-ui-cto2): a hidden input is the only way a web page reads a
 // file the operator picked, and it must live in the DOM to be clickable. Cleared after every
 // change so choosing the same file twice still fires (the app's config import does the same).
 const fileInputRef = useRef<HTMLInputElement>(null);
 const pasteFromFile = useCallback(
  (file: File) => {
   const reader = new FileReader();
   // Text decode: the editor's value IS text — a binary file pasted as text arrives with
   // replacement characters rather than as raw bytes, and Raw shows exactly that, which is
   // the honest outcome. Burp's own paste-from-file treats the file as text in the text tabs.
   reader.readAsText(file);
   reader.onload = () => {
    const text = String(reader.result ?? "");
    // Replace, not insert: the point is loading a request/response from disk, and a
    // replace is what "paste the file into this message" means when the message is a draft.
    onChange?.(text);
   };
   reader.onerror = () => {};
  },
  [onChange],
 );
 // URL-encode as you type (burpsy-react-ui-js1): Burp's toggle — "Automatically URL-encodes
 // special characters as you type". One persisted preference for every editor surface, the
 // same class of fact as the wrapping toggle; the filter itself is built in the extensions
 // memo below, only when this is on.
 const urlEncodeAsYouType = useApp((state) => state.urlEncodeAsYouType);

 const extensions = useMemo<Extension[]>(() => {
  // CodeMirror's content element renders with role="textbox" but nothing in @uiw/react-codemirror's
  // own props reaches it — the wrapper spreads unknown props onto its outer container, not the
  // content DOM node CM6 owns internally. contentAttributes is CM6's own mechanism for setting
  // attributes on that exact element, so this is the only place `label` (already a required prop,
  // used nowhere else for accessibility) actually becomes the textbox's accessible name. Found by
  // the e2e a11y suite's first real run: every route with an HttpEditor failed "aria-label attribute
  // does not exist" on this element, because every route has at least one.
  const base: Extension[] = [
   httpHighlight,
   // The hover decode (6fq): Burp's mouse-over popups — URL-decode in requests,
   // HTML-decode in responses, nothing when the decode is a no-op. Gated on `views` like
   // Pretty: a payload blob with no head/body split has nothing for a popup to decode.
   // The boundary closure re-reads the editor's own boundary so the tooltip is only
   // offered past the headers, the same region the colouring is scoped to.
   hoverDecodeTooltip(
    isResponse(value),
    () => (cmViewRef.current ? headerEnd(cmViewRef.current) : Number.MAX_SAFE_INTEGER),
    () => {
     const cm = cmViewRef.current;
     if (!cm) return null;
     const first = cm.state.doc.line(1);
     const qFrom = first.text.indexOf("?");
     if (qFrom < 0) return null;
     const space = first.text.indexOf(" ", qFrom);
     return { from: first.from + qFrom, to: first.from + (space < 0 ? first.text.length : space) };
    },
   ),
   burpEditorKeys,
   EditorView.contentAttributes.of({ "aria-label": label }),
   // Keeps the codec menu entries honest about whether they have anything to act on.
   EditorView.updateListener.of((update) => {
    if (!update.selectionSet && !update.docChanged) return;
    setHasSelection(update.state.selection.ranges.some((range) => !range.empty));
    const raw = rawSelectionRef.current;
    if (!raw.report) return;
    const sel = update.state.selection.main;
    if (!raw.rawView || sel.empty) {
     raw.report(null);
     return;
    }
    raw.report({ start: docPosToValuePos(raw.value, sel.from), end: docPosToValuePos(raw.value, sel.to) });
   }),
   // burpsy-react-ui-czw9: when the search panel is open and the query text changes, scroll
   // to the first match immediately — Burp's message search steps through matches as the
   // text changes, while CodeMirror's own panel only moves the viewport on Enter (its
   // commit() dispatches setSearchQuery; scrolling lives in findNext/replaceNext alone).
   // The re-find runs from position 0 rather than from the caret, so what the operator sees
   // tracks the text they type: first match of the new term, not of the old selection.
   EditorView.updateListener.of((update) => {
    if (!searchPanelOpen(update.state)) return;
    const query = getSearchQuery(update.state);
    // React only when the query text changed (the panel's commit), not on every keystroke
    // in the document: a doc edit while a search is open must not yank the viewport.
    // lastSearchSpecRef lives outside the useMemo, so the closure survives re-renders.
    if (query.search === lastSearchSpecRef.current) return;
    lastSearchSpecRef.current = query.search;
    if (!query.search || !query.valid) return;
    // StringCursor only: a plain string with the query's own case sensitivity covers the
    // message search that matters (find "token", "password", a header name). Regexp and
    // whole-word queries keep CodeMirror's Enter-to-step behaviour rather than having this
    // extension reimplement their matching.
    if (query.regexp || query.wholeWord) return;
    const cursor = new SearchCursor(
     update.state.doc,
     query.search,
     0,
     update.state.doc.length,
     query.caseSensitive ? undefined : (s) => s.toLowerCase(),
    );
    cursor.next();
    if (cursor.done) return;
    update.view.dispatch({
     selection: { anchor: cursor.value.from, head: cursor.value.to },
     effects: EditorView.scrollIntoView(cursor.value.from, { y: "center" }),
    });
   }),
  ];
  if (wrap) base.push(EditorView.lineWrapping);
  if (showNonPrinting) base.push(nonPrintingGlyphs, nonPrintingEOLPlugin());
  // URL-encode as you type (burpsy-react-ui-js1). A transaction filter, added only when the
  // persisted toggle is on: it rewrites the user's typed insert through the same
  // urlEncodeKeyChars the ctrl+U chord uses, so the operator sees %26 land under their cursor
  // as they type &. "input.type" only — paste is content chosen whole, and programmatic
  // changes (reveal, sort) must not be re-encoded.
  if (urlEncodeAsYouType) {
   base.push(urlEncodeAsYouTypeExtension());
  }
  return base;
 }, [wrap, showNonPrinting, label, urlEncodeAsYouType]);

 const bytes = useMemo(() => new TextEncoder().encode(value).length, [value]);
 const response = useMemo(() => isResponse(value), [value]);
 // Render covers both of Burp's renderable shapes (tools/message-editor/index.html): HTML through
 // the sandboxed iframe, and images through a data URL over the body bytes — a CAPTCHA, a QR
 // code, an IDOR'd avatar are ordinary findings whose evidence is the stored response itself
 // (burpsy-react-ui-n7n). The body in `value` is decoded as Latin-1 text (one char per byte), so
 // round-tripping through charCodeAt recovers the exact bytes without a second fetch.
 const contentType = useMemo(() => contentTypeOf(value).toLowerCase(), [value]);
 const renderable = useMemo(() => response && (/html/i.test(contentType) || /^image\//.test(contentType)), [response, contentType]);
 const imageDataUrl = useMemo(() => {
  if (!/^image\//.test(contentType)) return null;
  if (bodyBase64) return `data:${contentType};base64,${bodyBase64}`;
  const body = bodyOf(value);
  const bytes = new Uint8Array(body.length);
  for (let i = 0; i < body.length; i++) bytes[i] = body.charCodeAt(i) & 0xff;
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
   binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return `data:${contentType};base64,${btoa(binary)}`;
 }, [contentType, value, bodyBase64, label]);

 // The body's exact octets, regardless of which branch of messageView.Body64 produced them.
 // body_base64 IS the answer for a non-UTF-8 body — the only case the server ever sends it, per
 // its own doc on why. For a UTF-8-valid body it is absent, but that absence is itself proof the
 // body round-trips exactly through `value`: text that decoded as valid UTF-8 server-side and
 // survived JSON re-encodes to identical bytes on re-encode. Either way this recovers the real
 // wire bytes without a second request — which is what makes the specific-charset control below
 // possible with no server change at all.
 const bodyBytes = useMemo(() => {
  if (!views) return null;
  let body: Uint8Array;
  if (bodyBase64) {
   try {
    const binary = atob(bodyBase64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    body = out;
   } catch {
    return null;
   }
  } else {
   body = new TextEncoder().encode(bodyOf(value));
  }
  const head = new TextEncoder().encode(value.slice(0, parseMessage(value).bodyOffset));
  const full = new Uint8Array(head.length + body.length);
  full.set(head, 0);
  full.set(body, head.length);
  return full;
 }, [views, bodyBase64, value]);

 // Whether TextDecoder recognises a label at all. An unsupported one (a typo, a legacy code page
 // nothing implements) is refused rather than silently falling back to UTF-8 — the same "refuse
 // rather than guess" rule api_toolkit.go's decodeLayer follows for an unknown encoding name.
 const supportsCharset = useCallback((label: string): boolean => {
  try {
   new TextDecoder(label);
   return true;
  } catch {
   return false;
  }
 }, []);

 // Burp's "Recognize automatically based on message headers": the `charset` parameter off
 // Content-Type, when the header names one this runtime can actually decode.
 const headerCharset = useMemo(() => {
  const match = /charset\s*=\s*"?([^;"\s]+)"?/i.exec(contentType);
  const label = match?.[1]?.toLowerCase() ?? "";
  return label && supportsCharset(label) ? label : "";
 }, [contentType, supportsCharset]);

 const charsetLabel =
  charsetMode === "utf-8"
   ? "utf-8"
   : charsetMode === "raw-bytes"
     ? // Burp calls this "ASCII", but true ASCII cannot represent a byte >= 0x80 at all. ISO-8859-1
       // maps every one of the 256 byte values to its own code point with no loss and no
       // substitution, which is what "one glyph per byte" actually requires.
       "iso-8859-1"
     : charsetMode === "auto"
       ? headerCharset || "utf-8"
       : customCharset.trim().toLowerCase();

 const charsetError =
  charsetMode === "custom" && customCharset.trim() !== "" && !supportsCharset(charsetLabel)
   ? `"${customCharset.trim()}" is not a character set this browser can decode`
   : null;

 // Active means "showing something other than what `value` already carries" — which restricts
 // the editor to a single read-only view below, so this is also the flag that keeps that
 // restriction off by default (charsetMode starts at "utf-8", today's only behaviour).
 const charsetActive = views && charsetMode !== "utf-8" && !charsetError;

 const decodedBody = useMemo(() => {
  if (!charsetActive || !bodyBytes) return null;
  try {
   return new TextDecoder(charsetLabel, { fatal: false }).decode(bodyBytes);
  } catch {
   return null;
  }
 }, [charsetActive, bodyBytes, charsetLabel]);

 // The full message re-rendered for display: the head untouched (headers are always ASCII-safe
 // wire syntax; Burp's own doc says the charset options apply to the body only) plus the body
 // reinterpreted under the chosen charset. Never fed back through onChange — see the editor's
 // forced read-only state below for why editing stays off while this is showing.
 const charsetOverride = useMemo(() => {
  if (!charsetActive || decodedBody === null) return null;
  return value.slice(0, parseMessage(value).bodyOffset) + decodedBody;
 }, [charsetActive, decodedBody, value]);

 // Pretty is only offered when it would actually change something.
 const prettied = useMemo(() => (views ? prettyMessage(value) : value), [views, value]);
 const canPretty = views && prettied !== value;

 // The typed views follow Pretty's discipline: each detector returns null unless the
 // message really carries the thing, and the tab exists only when it does. All three
 // are skipped outright for non-HTTP payloads, which is also what keeps them off the
 // per-keystroke path in the decoder and the WebSocket panes.
 const graphql = useMemo(() => (views ? detectGraphQL(value) : null), [views, value]);
 const jwt = useMemo(() => (views ? findJwts(value) : null), [views, value]);
 const params = useMemo(() => (views ? paramsOf(value) : null), [views, value]);
 // Protobuf / gRPC (burpsy-react-ui-3x2g): the Protobuf tab exists when the content type names gRPC
 // or protobuf. The body bytes go to the decoder base64-encoded; the body in `value` is Latin-1 (one
 // char per byte, see the imageDataUrl note above), so btoa over it recovers the exact wire bytes.
 const protoGrpc = useMemo(() => /application\/grpc/.test(contentType), [contentType]);
 const protoEligible = useMemo(
  () => views && (protoGrpc || /application\/(x-)?protobuf|application\/vnd\.google\.protobuf/.test(contentType)),
  [views, protoGrpc, contentType],
 );
 const protoBodyBase64 = useMemo(() => {
  if (!protoEligible) return null;
  if (bodyBase64) return bodyBase64;
  try {
   return btoa(bodyOf(value));
  } catch {
   return null;
  }
 }, [protoEligible, bodyBase64, value]);
 // Which side of the exchange this is, and the gRPC call path, so a loaded .proto can name the message
 // for each direction from the service's rpc signature (burpsy-react-ui-3pco).
 const protoDirection: "request" | "response" = /^HTTP\/\d/.test(value) ? "response" : "request";
 const protoRpcPath = useMemo(() => {
  return protoDirection === "response" ? requestPath : requestTargetPath(value);
 }, [protoDirection, requestPath, value]);

 // A loaded plugin's editor-tab registrations, when this editor has a stored message behind it
 // (burpsy-react-ui-ww5). The built-in typed views each warrant themselves by the message's
 // content; a plugin tab warrants itself by the operator having loaded the plugin, which is a
 // different fact, so the two lists are computed independently and the plugin tabs are appended
 // after the built-ins — an extension's view sits at the end of the strip in Burp too.
 const pluginTabs = usePluginEditorTabs(messageId);
 // The strip preferences this editor reads; moveEditorTab and the hidden-array edits go
 // through the store so every editor on every page moves together — one strip shape, not one
 // per surface (t94i).
 const setEditorTabs = useApp((state) => state.setEditorTabs);
 const setUrlEncodeAsYouType = useApp((state) => state.setUrlEncodeAsYouType);

 // The five operator-added tabs (t94i). Read-only, each warrants itself by the message's own
 // content — Headers and Attributes always, Query/Body params and Cookies when there is
 // something to read. Editable, a request gets every view so an item can be ADDED where none
 // exists yet (11r8: Burp's "in editable contexts … displays all views"). The prefs decide
 // which of these are hidden and their order. The rule is lib/editor-extra-tabs.ts.
 const extraTabs: OptionalEditorTab[] = extraEditorTabs(value, editable);
 // Where an add from one of those tabs is written: the same onChange Raw writes through, so
 // the raw text stays the single source of truth and the tab is a writer over it, not a copy.
 const addInto = editable ? onChange : undefined;

 // Preferences: hidden tabs leave the strip, the order array reorders it. A pref naming a
 // tab the message does not warrant is inert — the strip still only offers what it can fill.
 const editorTabs = useApp((state) => state.editorTabs) ?? defaultEditorTabPrefs;

 const orderedOptional = useMemo((): MessageView[] => {
  const optional: MessageView[] = [
   ...(renderable ? (["render"] as MessageView[]) : []),
   ...(graphql ? (["graphql"] as MessageView[]) : []),
   ...(jwt && jwt.tokens.length ? (["jwt"] as MessageView[]) : []),
   ...(params && params.rows.length ? (["params"] as MessageView[]) : []),
   ...(protoBodyBase64 ? (["protobuf"] as MessageView[]) : []),
   ...extraTabs,
  ];
  const order = editorTabs.order.length ? editorTabs.order : [];
  const rank = (tab: MessageView) => {
   const idx = order.indexOf(tab as OptionalEditorTab);
   return idx < 0 ? order.length : idx;
  };
  return optional.filter((tab) => !editorTabs.hidden.includes(tab as OptionalEditorTab)).sort((a, b) => rank(a) - rank(b));
  // extraTabs is derived from value; listing it would double-count. value covers it.
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [renderable, graphql, jwt, params, protoBodyBase64, editorTabs, value]);

 const available: MessageView[] = !views
  ? []
  : charsetActive
    ? // Pretty/Render/GraphQL/JWT/Params all assume the platform-default decoding of `value`; showing
      // them unchanged while the operator has deliberately asked to view the body under a different
      // charset would look like the charset applied everywhere when it only applies to Raw. Hex stays
      // — it is a byte-exact view the charset choice was never about. The operator-added tabs read
      // the same `value`, so they sit this out too.
      (["raw", "hex"] as MessageView[])
    : ([...(canPretty ? ["pretty"] : []), "raw", "hex", ...orderedOptional] as MessageView[]);

 // Resolve the active view. The "raw" initial state means "the operator has not
 // chosen yet", and for an unchosen editor a formattable body opens on Pretty —
 // Burp's default (burpsy-react-ui-vet): a migrating operator who has to click
 // Pretty on every JSON body has been told their preference does not matter. An
 // explicit click, including a click back to Raw, wins for the life of this
 // editor pane, which is also how Burp treats a pane once the operator has
 // expressed a preference. A message whose Pretty view disappears falls back to
 // Raw, the only view every message has.
 const pickedRef = useRef(false);
 const pick = useCallback((candidate: MessageView) => {
  pickedRef.current = true;
  setView(candidate);
 }, []);
 const active: MessageView = available.includes(view) ? view : !pickedRef.current && canPretty ? "pretty" : "raw";
 // Raw is the one view the charset override actually changes — Hex always shows the true bytes
 // (the override never reaches this variable when active is "hex"), and Pretty/Render/GraphQL/
 // JWT/Params are simply not offered while charsetActive (see `available` above).
 // Whether the eye is actually in force in this pane. An empty list hides nothing, so the
 // button is not offered at all (see the toolbar) and `hiding` stays false either way.
 const hiding = active === "pretty" && hideList.length > 0 && (hidePicked ?? hideHeadersByDefault);
 const shown =
  active === "pretty" && hiding
   ? hideHeadersIn(prettied, hideList)
   : active === "raw" && charsetActive
     ? (charsetOverride ?? value)
     : value;
 // The line separator CodeMirror splits this message on (lib/editor-eol.ts, burpsy-react-ui-elam).
 // It is fixed when the state is built, so it is re-derived only when the text changed under the
 // editor (a new message, a tab switch) and never from the operator's own typing: pasting a CRLF
 // into an LF message must not rebuild the editor and drop the caret and the undo history.
 if (shown !== emittedRef.current) separatorRef.current = lineSeparatorFor(shown);
 const separator = separatorRef.current;
 // Raw edits are the bytes; a Pretty edit is the operator editing the readable form, written back
 // through compactMessage so the wire keeps the body compacted exactly as it was
 // (burpsy-react-ui-dmf) — the same deal Burp offers ("In this tab, you can access all the same
 // functionality as in the Raw tab"), and the reason the sent request never silently grows to the
 // pretty layout. A mid-edit JSON parse failure passes the operator's text through untouched, and
 // Raw then shows precisely what they typed. Never fires while charsetActive: the document on
 // screen is the reinterpreted body, not the real bytes, and writing it back through onChange
 // would send whatever the chosen charset happened to produce as if the operator had typed it.
 //
 // CodeMirror's own string has every line ending flattened to "\n", so taking it as the message
 // turned a CRLF request into an LF one on any edit at all (burpsy-react-ui-eslt). The
 // transactions are replayed onto the real text instead (lib/editor-eol.ts reconcile); only when
 // that text no longer matches the document does the document's string stand in, as it always did.
 const writeDoc = charsetActive ? undefined : active === "pretty" && editable ? "pretty" : active === "raw" ? "raw" : undefined;
 const cmOnChange = useMemo(() => {
  if (!writeDoc || !onChange) return undefined;
  return (_doc: string, update: ViewUpdate) => {
   // sliceDoc joins lines with the state's separator, so the message comes back byte for byte;
   // the `doc` string the wrapper passes joins with "\n" whatever the separator is.
   const next = documentText(update.state);
   emittedRef.current = next;
   onChange(writeDoc === "pretty" ? compactMessage(next) : next);
  };
 }, [writeDoc, onChange]);
 rawSelectionRef.current = { report: onRawSelection, rawView: active === "raw" && !charsetActive, value };
 // What the toolbar's Copy hands over. Hex still copies a dump — that is what an
 // operator pasting into a ticket wants, and it is why message.ts's read-only
 // hexDump did not go away when the view became editable. Raw under a charset override copies
 // what is actually on screen, matching every other "what you see is what exports" surface in
 // this codebase (History and Organizer's CSV exports both follow the same rule).
 // The change marks join the extensions only on the unconverted Raw text, where `value` and the
 // document are the same characters (CRLF aside, which changeDecorations maps).
 const markedExtensions = useMemo(() => {
  const withSeparator = [...extensions, EditorState.lineSeparator.of(separator)];
  if (compareWith != null && active === "raw" && !charsetActive) return [...withSeparator, inlineDiffExtension(compareWith, separator)];
  if (!changeMarks || changeMarks.length === 0 || active !== "raw" || charsetActive) return withSeparator;
  const docLength = value.length - (separator === "\r\n" ? (value.match(/\r\n/g)?.length ?? 0) : 0);
  return [...withSeparator, changeDecorations(value, docLength, changeMarks)];
 }, [extensions, changeMarks, compareWith, active, charsetActive, value, separator]);
 const hexDumpText = useMemo(
  () => (active === "hex" ? hexDumpBytes(bodyBytes ?? new TextEncoder().encode(value)) : ""),
  [active, bodyBytes, value],
 );
 // The clipboard copies the VISIBLE document (whr): with the eye on, a Pretty copy is
 // the filtered pretty — a copy that silently restored 15 hidden headers would contradict
 // the button the operator just pressed.
 const clipboard =
  active === "pretty"
   ? hiding
    ? hideHeadersIn(prettied, hideList)
    : prettied
   : active === "hex"
     ? hexDumpText
     : active === "raw" && charsetActive
       ? (charsetOverride ?? value)
       : value;

 // A Hex selection handed to the Raw view. The byte range is mapped to a character
 // range on the way, because the two views index the same message differently.
 const cmViewRef = useRef<EditorView | null>(null);
 const [cmEpoch, setCmEpoch] = useState(0);
 const [reveal, setReveal] = useState<{ from: number; to: number } | null>(null);
 // Keeps the document equal to `shown`. Compared as the message's own text (documentText), so a
 // CRLF message is not "different" on every render, and written with ExternalChange so the
 // wrapper does not echo it back through onChange; kept out of undo history, which is the
 // operator's edits only.
 useEffect(() => {
  const cm = cmViewRef.current;
  if (!cm || documentText(cm.state) === shown) return;
  cm.dispatch({
   changes: { from: 0, to: cm.state.doc.length, insert: shown },
   annotations: [ExternalChange.of(true), Transaction.addToHistory.of(false)],
  });
 }, [shown, cmEpoch]);
 useEffect(() => {
  if (!reveal || active !== "raw") return;
  const cm = cmViewRef.current;
  // No view yet means CodeMirror has not mounted for this switch; cmEpoch bumps on
  // creation, which re-runs this effect rather than dropping the selection.
  if (!cm) return;
  const from = Math.min(reveal.from, cm.state.doc.length);
  const to = Math.min(reveal.to, cm.state.doc.length);
  cm.dispatch({ selection: { anchor: from, head: to }, scrollIntoView: true });
  cm.focus();
  setReveal(null);
 }, [reveal, active, cmEpoch]);

 /**
  * Burp's "Convert selection", as menu entries rather than keystrokes alone.
  *
  * The chords in burpEditorKeys above are the same six transforms, and they were the only way
  * to reach them: a codec an operator has to already know about is a codec most operators never
  * find. These run the identical `transformSelection` path, so the menu and the keyboard cannot
  * diverge, and each row shows its own chord so the menu also teaches them.
  *
  * Offered only on the Raw view, which is the only view CodeMirror owns and the only one whose
  * bytes are the message's real bytes — converting a selection of a reformatted body would write
  * the reformatting back into the request.
  */
 const runTransform = useCallback((transform: (input: string) => string) => {
  const cm = cmViewRef.current;
  if (cm) transformSelection(cm, transform);
 }, []);

 /** The read-only twin: same six transforms, result into the dialog instead of the document —
  * a dispatch into a read-only CodeMirror view is dropped by the editor, so the old code path
  * here was a menu row that visibly did nothing. */
 const showTransform = useCallback((label: string, transform: (input: string) => string) => {
  const cm = cmViewRef.current;
  if (!cm) return;
  const sel = cm.state.selection.main;
  if (sel.empty) return;
  // On the unconverted Raw view the input is the message's own characters, CRLF included: the
  // document holds a lone "\n" for each, and URL-encoding a selection across a header break must
  // give %0D%0A, as the bytes are (burpsy-react-ui-ngao). Pretty and charset views have no such
  // mapping and convert what is on screen.
  // selectionText maps through the real text of whichever view is showing (lib/editor-eol.ts).
  const input = selectionText(cm.state);
  setConversionResult({ label, output: transform(input) });
 }, []);

 /**
  * Burp's "Insert Collaborator payload" (burpsy-react-ui-0ax): mint one server-side and drop
  * its address at the caret, replacing any selection. Offered on Raw and Pretty alike - both
  * are the same CodeMirror document, and a Pretty insert writes back through compactMessage
  * exactly like a typed one. The mint is server-side because the address has to be a payload
  * the polling loop already knows; inventing a subdomain client-side would insert an address
  * no interaction could ever come back on.
  */
 const mint = useMintPayload();
 const insertCollaboratorPayload = useCallback(() => {
  const cm = cmViewRef.current;
  if (!cm) {
   toast.error("Open the Raw or Pretty view to insert a payload");
   return;
  }
  mint.mutate(
   { count: 1 },
   {
    onSuccess: (payload) => {
     const view = cmViewRef.current;
     if (!view) return;
     const sel = view.state.selection.main;
     view.dispatch({
      changes: { from: sel.from, to: sel.to, insert: payload.address },
      selection: { anchor: sel.from + payload.address.length },
      scrollIntoView: true,
     });
     view.focus();
     toast.success(`Inserted Collaborator payload ${payload.address}`);
    },
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Minting a Collaborator payload failed"),
   },
  );
 }, [mint]);

 const selectionGroups = useMemo<MenuGroup[]>(() => {
  const groups: MenuGroup[] = [];
  if (editable && (active === "raw" || active === "pretty")) {
   groups.push({
    id: "collaborator",
    actions: [
     {
      id: "insert-payload",
      label: "Insert Collaborator payload",
      icon: RadioTower,
      disabled: mint.isPending,
      onSelect: insertCollaboratorPayload,
     },
    ],
   });
  }
  // Burp's GraphQL submenu (7v1e, burp.Zu6): the two introspection documents replace the query of
  // an editable REQUEST — on a response they carry Burp's own " [Request only]" and stay disabled —
  // and Save GraphQL queries to site map acts on an introspection answer the surface can name.
  if (views) {
   const requestOnly = isResponse(value) ? " [Request only]" : "";
   const canSet = editable && !isResponse(value) && Boolean(onChange);
   const setQuery = (query: string, label: string) => () => {
    if (!canSet) return;
    onChange?.(setGraphQLQuery(value, query));
    toast.success(`${label}: the request now carries it`);
   };
   groups.push({
    id: "graphql",
    actions: [
     {
      id: "graphql",
      label: "GraphQL",
      onSelect: () => {},
      submenu: [
       {
        id: "graphql-introspection",
        actions: [
         {
          id: "set-introspection",
          label: `Set introspection query${requestOnly}`,
          disabled: !canSet,
          onSelect: setQuery(INTROSPECTION_QUERY, "Introspection query set"),
         },
         {
          id: "set-legacy-introspection",
          label: `Set legacy introspection query${requestOnly}`,
          disabled: !canSet,
          onSelect: setQuery(LEGACY_INTROSPECTION_QUERY, "Legacy introspection query set"),
         },
        ],
       },
       {
        id: "graphql-sitemap",
        actions: [
         {
          id: "save-to-sitemap",
          label: saveGraphQLToSiteMap
           ? saveGraphQLToSiteMap.enabled
            ? "Save GraphQL queries to site map"
            : "Save GraphQL queries to site map (send an introspection query first)"
           : "Save GraphQL queries to site map (not available here — use Repeater)",
          disabled: !saveGraphQLToSiteMap?.enabled,
          onSelect: () => saveGraphQLToSiteMap?.run(),
         },
        ],
       },
      ],
     },
    ],
   });
  }
  if (active !== "raw") return groups;
  if (payloadMarks && !charsetActive) {
   groups.push({
    id: "payload-marks",
    actions: [
     {
      id: "add-payload-mark",
      label: "Add \u00a7 payload marker",
      disabled: !hasSelection,
      onSelect: () => {
       const cm = cmViewRef.current;
       if (!cm) return;
       const sel = cm.state.selection.main;
       // The document normalises CRLF to one "\n"; the caller's offsets index `value`, where it is
       // two characters (and two bytes on the wire). Map before reporting (burpsy-react-ui-ngao).
       const start = docPosToValuePos(value, sel.from);
       const end = docPosToValuePos(value, sel.to);
       payloadMarks.onAdd({ start, end, text: value.slice(start, end) });
      },
     },
    ],
   });
  }
  if (auditSelection && !charsetActive) {
   groups.push({
    id: "audit-selection",
    actions: [
     {
      id: "audit-this-selection",
      label: "Actively audit this selection",
      icon: Radar,
      disabled: !hasSelection,
      onSelect: () => {
       const cm = cmViewRef.current;
       if (!cm) return;
       const sel = cm.state.selection.main;
       if (sel.empty) return;
       // The span must index the raw bytes the server stored, and the selection indexes
       // the CodeMirror document — which has CRLF normalised away and (under a charset
       // override, excluded above) is not the wire text at all. Map the document position
       // back to the raw string first, then to its UTF-8 bytes: Go stores the message as
       // []byte(text), so the byte offset is the cumulative UTF-8 width of the characters
       // before the position.
       const start = charIndexToByteOffset(value, docPosToValuePos(value, sel.from));
       const end = charIndexToByteOffset(value, docPosToValuePos(value, sel.to));
       auditSelection([start, end]);
      },
     },
    ],
   });
  }
  const codec = (id: string, label: string, shortcut: string, transform: (input: string) => string) => ({
   id,
   label,
   shortcut,
   disabled: !hasSelection,
   // Editable: in-place, Burp's editable half of the contract. Read-only: the dialog half —
   // same transform, shown instead of written.
   onSelect: () => (editable ? runTransform(transform) : showTransform(label, transform)),
  });
  groups.push(
   {
    id: "convert-selection",
    title: hasSelection ? "Convert selection" : "Convert selection (select text first)",
    actions: [
     codec("url-encode", "URL-encode", "Ctrl+U", urlEncodeKeyChars),
     codec("url-encode-all", "URL-encode all characters", "", urlEncodeAllChars),
     codec("url-encode-unicode", "URL-encode all characters (Unicode %uXXXX)", "", urlEncodeAllCharsUnicode),
     codec("url-decode", "URL-decode", "Ctrl+Shift+U", urlDecode),
     codec("html-encode", "HTML-encode", "Ctrl+H", htmlEncodeKeyChars),
     codec("html-encode-decimal", "HTML-encode all characters (numeric)", "", htmlEncodeAllCharsDecimal),
     codec("html-encode-hex", "HTML-encode all characters (hex)", "", htmlEncodeAllCharsHex),
     codec("html-decode", "HTML-decode", "Ctrl+Shift+H", htmlDecode),
     codec("b64-encode", "Base64-encode", "Ctrl+B", base64Encode),
     codec("b64-decode", "Base64-decode", "Ctrl+Shift+B", base64Decode),
     codec("b64url-encode", "Base64-URL-encode", "", base64UrlEncode),
     codec("b64url-decode", "Base64-URL-decode", "", base64UrlDecode),
    ],
   },
   {
    id: "construct-string",
    title: "Construct string",
    actions: (Object.entries(CONSTRUCT_DIALECTS) as [ConstructDialect, string][]).map(([dialect, label]) =>
     codec(`construct-${dialect}`, label, "", (input: string) => constructString(input, dialect)),
    ),
   },
   {
    id: "editor-find",
    actions: [
     {
      id: "find",
      label: "Find in this message",
      icon: Search,
      shortcut: "Ctrl+S",
      onSelect: () => {
       const cm = cmViewRef.current;
       if (!cm) return;
       openSearchPanel(cm);
       cm.focus();
      },
     },
    ],
   },
  );
  return groups;
 }, [
  active,
  editable,
  hasSelection,
  charsetActive,
  runTransform,
  showTransform,
  insertCollaboratorPayload,
  mint.isPending,
  payloadMarks,
  auditSelection,
  value,
  views,
  onChange,
  saveGraphQLToSiteMap,
 ]);

 const allGroups = useMemo<MenuGroup[]>(() => [...(menuGroups ?? []), ...selectionGroups], [menuGroups, selectionGroups]);

 // Burp's EDITOR_TOGGLE_* actions and Insert Collaborator payload (2czi), for whichever message
 // editor the operator used last: an editor takes the commands when focus enters it and holds them
 // until another editor does or it unmounts (lib/commands.ts stacks them). The handlers are read
 // through a ref so a re-render never re-registers — only a focus change does.
 const editorCommands = useRef<Record<string, () => void>>({});
 editorCommands.current = {
  "editor.togglePretty": () => {
   if (!canPretty) {
    toast.info(`${label}: Pretty would show the same bytes as Raw for this message`);
    return;
   }
   pick(active === "pretty" ? "raw" : "pretty");
  },
  "editor.toggleWrap": () => setWrap((on) => !on),
  "editor.toggleNonPrinting": () => setShowNonPrinting((on) => !on),
  "editor.toggleHideHeaders": () => {
   if (hideList.length === 0) {
    toast.info("No headers are listed to hide — add them under Settings › Message editor");
    return;
   }
   if (active !== "pretty") pick("pretty");
   setHidePicked(!(hidePicked ?? hideHeadersByDefault));
  },
  "editor.insertCollaborator": () => {
   if (!editable) {
    toast.info(`${label} is read-only; a Collaborator payload can only be inserted into an editable message`);
    return;
   }
   insertCollaboratorPayload();
  },
 };
 const commandRegistrations = useRef<(() => void)[]>([]);
 const editorToken = useRef<symbol>(Symbol("editor"));
 const claimEditorCommands = useCallback(() => {
  if (topEditor === editorToken.current) return;
  for (const off of commandRegistrations.current) off();
  topEditor = editorToken.current;
  commandRegistrations.current = Object.keys(editorCommands.current).map((id) => registerCommand(id, () => editorCommands.current[id]?.()));
 }, []);
 useEffect(
  () => () => {
   for (const off of commandRegistrations.current) off();
   if (topEditor === editorToken.current) topEditor = null;
  },
  [],
 );

 return (
  <div className={cn("editor-shell", className)} onFocusCapture={claimEditorCommands}>
   <div className="editor-bar">
    <span className="editor-label-inline">{label}</span>
    {available.length || pluginTabs.entries.length ? (
     <div className="editor-views" role="tablist" aria-label={`${label} view`}>
      {available.map((candidate) => (
       <button
        key={candidate}
        type="button"
        role="tab"
        // A plugin tab open means the built-in views are deselected, including the one
        // `active` still names: `active` is the fallback the view returns to when the
        // plugin tab closes, and a tablist with two selected tabs is a broken tablist.
        aria-selected={candidate === active && pluginTabs.openKey === null}
        className={candidate === active && pluginTabs.openKey === null ? "editor-view editor-view-active" : "editor-view"}
        onClick={() => {
         pluginTabs.close();
         pick(candidate);
        }}
       >
        {VIEW_LABELS[candidate]}
       </button>
      ))}
      {pluginTabs.entries.map((entry) => (
       <button
        key={`plugin-${entry.key}`}
        type="button"
        role="tab"
        aria-selected={pluginTabs.openKey === entry.key}
        className={pluginTabs.openKey === entry.key ? "editor-view editor-view-active" : "editor-view"}
        title={entry.invocation.registration.hint ?? `View rendered by the ${entry.invocation.plugin} plugin`}
        onClick={() => {
         // Toggling, like every built-in tab: clicking the open plugin tab closes it, and
         // the view falls back to Raw — the one view every message has.
         if (pluginTabs.openKey === entry.key) {
          pluginTabs.close();
         } else {
          pluginTabs.open(entry.key);
         }
        }}
       >
        {entry.invocation.registration.label}
       </button>
      ))}
     </div>
    ) : null}
    <span className="editor-meta">{formatBytes(bytes)}</span>
    <div className="editor-bar-actions">
     {actions}
     {/* Burp's Actions button: the same menu the right-click opens, for an operator who has
              not learned that the message pane has one. Hidden rather than disabled when there is
              nothing in it — an editor with no exchange behind it and no Raw view (a close frame,
              a rendered response) genuinely has no actions, and a dead button says otherwise. */}
     {hasMenuActions(allGroups) ? (
      <DropdownMenu
       groups={allGroups}
       trigger={
        // A plain button, not IconButton: IconButton wraps its <button> in a Tooltip,
        // which is a second Radix `asChild` layer, and stacking two of them on one node
        // means two sets of merged handlers on the same element. app.tsx's menu bar uses
        // a bare button as its trigger for the same reason. `title` carries the hover
        // text the Tooltip would have.
        <button type="button" className="icon-button icon-button-sm" aria-label={`Actions for ${label}`} title={`Actions for ${label}`}>
         <MoreHorizontal size={13} />
        </button>
       }
      />
     ) : null}
     {/* Burp's message-editor character-set control (burpsy-react-ui-p836), settings/ui/message-
              editor.html: "The charset encoding options only apply to the message body." Gated on
              `views` like Pretty/GraphQL/JWT/Params — a payload blob with no head/body split has
              nothing for this control to mean. */}
     {views ? (
      <select
       className="input select"
       aria-label={`${label} character set`}
       title="How the message body is decoded for display. Headers are always shown as captured."
       value={charsetMode}
       onChange={(event) => setCharsetMode(event.target.value as typeof charsetMode)}
       style={{ maxWidth: "11ch" }}
      >
       <option value="utf-8">Platform default</option>
       <option value="auto">Recognize automatically</option>
       <option value="raw-bytes">Raw bytes</option>
       <option value="custom">Specific charset…</option>
      </select>
     ) : null}
     {views && charsetMode === "custom" ? (
      <input
       className="input"
       aria-label="Specific character set"
       title="A charset name your browser's TextDecoder recognises, e.g. windows-1252, shift_jis, iso-8859-15"
       value={customCharset}
       onChange={(event) => setCustomCharset(event.target.value)}
       style={{ maxWidth: "14ch" }}
      />
     ) : null}
     {views ? (
      // The tab-strip settings (t94i): Burp's settings/ui/message-editor "Show" checkboxes
      // and Up/Down reorder, on the editor itself so the strip being edited is the one on
      // screen. A details/summary rather than a Radix popover: the strip is already dense
      // with portaled triggers, and a native disclosure cannot z-fight them.
      <details className="editor-tabs-settings">
       <summary
        className="icon-button icon-button-sm"
        aria-label="Message editor tabs settings"
        title="Show, hide and reorder this editor's tabs"
       >
        <SlidersHorizontal size={13} />
       </summary>
       <div className="editor-tabs-settings-panel" role="group" aria-label="Optional tabs">
        <p className="field-hint">Pretty and Raw are always shown — Raw is the bytes themselves.</p>
        {(
         [
          "render",
          "graphql",
          "jwt",
          "params",
          "protobuf",
          "headers",
          "queryparams",
          "bodyparams",
          "cookies",
          "attributes",
         ] as OptionalEditorTab[]
        ).map((tab) => {
         const hidden = editorTabs.hidden.includes(tab);
         const order = editorTabs.order.length
          ? editorTabs.order
          : ([
             "render",
             "graphql",
             "jwt",
             "params",
             "protobuf",
             "headers",
             "queryparams",
             "bodyparams",
             "cookies",
             "attributes",
            ] as OptionalEditorTab[]);
         const at = order.indexOf(tab);
         return (
          <div key={tab} className="editor-tabs-settings-row">
           <label>
            <input
             type="checkbox"
             checked={!hidden}
             onChange={(event) => {
              const next = event.target.checked ? editorTabs.hidden.filter((t) => t !== tab) : [...editorTabs.hidden, tab];
              setEditorTabs({ ...editorTabs, hidden: next });
             }}
            />{" "}
            {VIEW_LABELS[tab]}
           </label>
           <span className="editor-tabs-settings-move">
            <IconButton
             label={`Move ${VIEW_LABELS[tab]} tab up`}
             size="small"
             disabled={at <= 0}
             onClick={() => setEditorTabs(moveEditorTab(editorTabs, tab, -1))}
            >
             <ChevronUp size={12} />
            </IconButton>
            <IconButton
             label={`Move ${VIEW_LABELS[tab]} tab down`}
             size="small"
             disabled={at < 0 || at >= order.length - 1}
             onClick={() => setEditorTabs(moveEditorTab(editorTabs, tab, 1))}
            >
             <ChevronDown size={12} />
            </IconButton>
           </span>
          </div>
         );
        })}
       </div>
      </details>
     ) : null}
     {/* Wrapping is a CodeMirror setting, so the toggle is offered only on the two
              views CodeMirror renders. It used to be hidden for Render alone, which left
              a dead control on Hex. */}
     {/* Burp's eye button (whr), on Burp's own labels ("Show / Hide specified headers",
         messageAnalyserToggleHideUninterestingHeaders) — "specified" rather than
         "uninteresting", which is the Comparer's word for a different list. Offered only when
         the direction's list is non-empty: an eye with nothing to hide is a control that can
         never act, and its presence would tell an operator the setting is in force when it is
         empty. `editable` is deliberately not part of this test — see the note below, which
         turns editing off while the eye is on rather than hiding the button from editable
         panes, because the response pane in Repeater is read-only while the request pane is
         not and Burp offers the eye on both. */}
     {active === "pretty" && hideList.length > 0 ? (
      <IconButton
       label={hiding ? "Show specified headers" : "Hide specified headers"}
       title={`Hide the headers named in Settings › Message editor (${hideList.length} listed for ${isResponse(value) ? "responses" : "requests"}). Pretty view only — the bytes and anything sent are untouched.`}
       size="small"
       aria-pressed={hiding}
       onClick={() => setHidePicked(!hiding)}
      >
       <EyeOff size={13} />
      </IconButton>
     ) : null}
     {active === "pretty" || active === "raw" ? (
      <IconButton
       label={wrap ? "Disable wrapping" : "Enable wrapping"}
       size="small"
       aria-pressed={wrap}
       onClick={() => setWrap((current) => !current)}
      >
       <WrapText size={13} />
      </IconButton>
     ) : null}
     {active === "pretty" || active === "raw" ? (
      <IconButton
       label={showNonPrinting ? "Hide non-printing characters" : "Show non-printing characters"}
       title="Render bytes below 0x20 and 0x7F-0xFF as visible glyphs (Burp's \n)"
       size="small"
       aria-pressed={showNonPrinting}
       onClick={() => setShowNonPrinting((current) => !current)}
      >
       <Pilcrow size={13} />
      </IconButton>
     ) : null}
     {/* URL-encode as you type (burpsy-react-ui-js1): Burp's context-menu toggle —
         "Automatically URL-encodes special characters as you type". A pressed-state toggle on
         the text views, persisted for every editor surface through the workspace store. Hidden
         when the editor is read-only: encoding what cannot be typed is a control that can
         never act. */}
     {active === "pretty" || active === "raw" ? (
      <IconButton
       label={urlEncodeAsYouType ? "Stop URL-encoding as you type" : "URL-encode as you type"}
       title="Special characters typed into this editor are URL-encoded automatically, the same key-character set as the ctrl+U selection command"
       size="small"
       aria-pressed={urlEncodeAsYouType}
       disabled={!editable}
       onClick={() => setUrlEncodeAsYouType(!urlEncodeAsYouType)}
      >
       <Percent size={13} />
      </IconButton>
     ) : null}
     {editable ? (
      <IconButton
       label="Paste from file"
       size="small"
       title="Load a message body from a file on your machine"
       onClick={() => fileInputRef.current?.click()}
      >
       <ClipboardPaste size={13} />
      </IconButton>
     ) : null}
     <IconButton label="Copy message" size="small" onClick={() => void copyToClipboard(clipboard)}>
      <Copy size={13} />
     </IconButton>
     <IconButton label="Save to file" size="small" onClick={() => downloadText(filename, value)}>
      <Download size={13} />
     </IconButton>
    </div>
   </div>
   {/* The right-click surface is the message body, not the whole shell: the toolbar's own
          controls keep the browser's menu, and the Render view keeps it too — that iframe is
          sandboxed attacker-controlled HTML, and putting a Radix trigger over it would replace
          the browser's own "open image in new tab" affordances on rendered content for no gain. */}
   <ContextMenu groups={active === "render" ? [] : allGroups} docTopic="message-editor">
    <div className="editor-body" style={{ height }}>
     {pluginTabs.openKey !== null && pluginTabs.content ? (
      // A plugin's editor tab: read-only by contract (KindEditorTab is the read-only half of
      // registerHttpRequestEditorProvider — the caret half a JSON round trip cannot carry, see
      // protocol.go). The content is the plugin's own words; the editor wraps it in the same
      // pre-scroll the typed views use, so every tab in the strip reads like the same control.
      // Loading and failure are in-tab rather than toasts: an operator who clicks a tab and
      // sees a blank body reads the plugin as having rendered nothing.
      <div className="editor-plugin-tab" role="tabpanel">
       {pluginTabs.content.loading ? (
        <p className="editor-plugin-note">Rendering…</p>
       ) : pluginTabs.content.error ? (
        <div className="notice notice-warn" role="status">
         <span>{pluginTabs.content.error}</span>
        </div>
       ) : (
        <pre className="editor-plugin-text">{pluginTabs.content.text}</pre>
       )}
      </div>
     ) : active === "render" && imageDataUrl ? (
      // An image response: render the stored bytes as the browser would show them. Same
      // attacker-controlled caution as the iframe — the data URL renders pixels and runs
      // nothing; it is an <img>, not an <object> or <embed>.
      <div className="render-frame render-image" role="img" aria-label={`${label} rendered`}>
       <img src={imageDataUrl} alt={`${label} rendered response body`} />
      </div>
     ) : active === "render" ? (
      // No scripts, no same-origin, no forms: a captured response is attacker
      // controlled and must never run inside the console's own origin.
      <iframe className="render-frame" title={`${label} rendered`} sandbox="" srcDoc={bodyOf(value)} />
     ) : active === "hex" ? (
      <HexEditor
       value={shown}
       bytes={bodyBytes ?? undefined}
       onChange={editable ? onChange : undefined}
       label={label}
       onRevealInRaw={
        views
         ? (selection) => {
            // Hex indexes bytes; Raw indexes UTF-16 code units over the same
            // message. The reveal maps the selected byte range to the character
            // range Raw will scroll to, which is what byteOffsetToCharIndex
            // exists for — without it a selection past a multibyte character
            // lands one or more characters off.
            // Then to CodeMirror's document, which holds one "\n" per CRLF: dispatching the
            // string index as-is selected one character further right per preceding line
            // (burpsy-react-ui-ngao).
            setReveal({
             from: valuePosToDocPos(value, byteOffsetToCharIndex(value, selection.from)),
             to: valuePosToDocPos(value, byteOffsetToCharIndex(value, selection.to)),
            });
            pick("raw");
           }
         : undefined
       }
      />
     ) : active === "graphql" && graphql ? (
      <GraphQLView document={graphql} />
     ) : active === "jwt" && jwt ? (
      <JwtView report={jwt} />
     ) : active === "params" && params ? (
      <ParamsView report={params} />
     ) : active === "protobuf" && protoBodyBase64 ? (
      <ProtobufView
       bodyBase64={protoBodyBase64}
       grpc={protoGrpc}
       direction={protoDirection}
       rpcPath={protoRpcPath}
       onApply={
        readOnly || (!onChange && !onBodyBytesChange)
         ? undefined
         : (newBodyBase64) => {
            // The body in `value` is Latin-1, so atob's output (one char per byte) is the exact wire
            // body; splice it back and correct Content-Length (burpsy-react-ui-3x2g). The faithful
            // bytes also go to onBodyBytesChange so Repeater can resend them without the lossy string
            // (burpsy-react-ui-ytkk).
            const newBody = atob(newBodyBase64);
            const offset = parseMessage(value).bodyOffset;
            const head = withContentLength(value.slice(0, offset), newBody.length);
            // Order matters: onChange rewrites the request body, which the store reads as a stale
            // faithful body and clears (burpsy-react-ui-ytkk); onBodyBytesChange then restores it to
            // the just-encoded bytes. Swapping them would clear what we just set.
            onChange?.(head + newBody);
            onBodyBytesChange?.(newBodyBase64);
           }
       }
      />
     ) : active === "headers" ? (
      <HeadersTab raw={value} onAdd={addInto} />
     ) : active === "queryparams" ? (
      <QueryParamsTab raw={value} onAdd={addInto} />
     ) : active === "bodyparams" ? (
      <BodyParamsTab raw={value} onAdd={addInto} />
     ) : active === "cookies" ? (
      <CookiesTab raw={value} onAdd={addInto} />
     ) : active === "attributes" ? (
      <AttributesTab raw={value} />
     ) : (
      <CodeMirror
       // The separator is baked into the state, so a different one means a new editor.
       key={JSON.stringify(separator)}
       // No `value`: the wrapper compares it with doc.toString(), which joins lines with "\n" whatever
       // the separator, so a CRLF message would look changed on every render. The document is synced
       // from `shown` by the effect above, comparing real text (documentText) instead.
       onChange={cmOnChange}
       editable={editable && !charsetActive && !hiding && (active === "raw" || active === "pretty")}
       readOnly={!(editable && !charsetActive && !hiding && (active === "raw" || active === "pretty"))}
       height="100%"
       theme={editorTheme}
       extensions={markedExtensions}
       placeholder={placeholder}
       onCreateEditor={(view) => {
        // The reveal effect below needs the mounted view to exist; the epoch bump
        // re-runs it when the editor mounts after the reveal was already set — the
        // hex-selection-then-switch-tabs path hits exactly that order.
        cmViewRef.current = view;
        setCmEpoch((epoch) => epoch + 1);
       }}
       basicSetup={{
        lineNumbers: true,
        foldGutter: false,
        autocompletion: false,
        bracketMatching: false,
        closeBrackets: false,
        highlightActiveLine: editable && (active === "raw" || active === "pretty"),
        highlightActiveLineGutter: editable && (active === "raw" || active === "pretty"),
        searchKeymap: true,
        indentOnInput: false,
       }}
      />
     )}
    </div>
   </ContextMenu>
   <input
    ref={fileInputRef}
    type="file"
    className="sr-only"
    aria-hidden="true"
    tabIndex={-1}
    onChange={(event) => {
     const file = event.target.files?.[0];
     if (file) pasteFromFile(file);
     event.target.value = "";
    }}
   />
   <Modal
    open={conversionResult !== undefined}
    onOpenChange={(open) => {
     if (!open) setConversionResult(undefined);
    }}
    title={conversionResult ? `Conversion result — ${conversionResult.label}` : ""}
    description="The message is read-only, so the conversion is shown here instead of written in place."
   >
    <pre className="conversion-result">{conversionResult?.output}</pre>
    <div className="detail-actions">
     <Button
      variant="outline"
      onClick={() => {
       if (conversionResult) void copyToClipboard(conversionResult.output);
       setConversionResult(undefined);
      }}
     >
      Copy and close
     </Button>
     <Button variant="primary" onClick={() => setConversionResult(undefined)}>
      Close
     </Button>
    </div>
   </Modal>
   {editable && active !== "raw" && active !== "hex" && active !== "pretty" ? (
    <div className="editor-note">
     {ADDABLE_VIEWS.includes(active) && addInto
      ? "Add an item here and it is written into the message. Edit, remove or reorder existing items in Raw or the Inspector."
      : "Editing happens on the Raw, Hex and Pretty views — this one reads the message without writing one back."}
    </div>
   ) : null}
   {charsetError ? (
    <div className="editor-note">{charsetError} — showing the platform default instead.</div>
   ) : hiding ? (
    <div className="editor-note">
     The eye is on: {hideList.length} header name{hideList.length === 1 ? "" : "s"} listed under Settings › Message editor{" "}
     {hideList.length === 1 ? "is" : "are"} hidden here in Pretty. The message itself is unchanged — Raw and everything sent still carry
     them — but editing is off while they are hidden, because an edit here would be written back against a head missing those lines. Press
     the eye again to edit.
    </div>
   ) : charsetActive ? (
    <div className="editor-note">
     Raw is showing the body decoded as {charsetLabel}. Hex still shows the true bytes, but editing and the Pretty/Render/GraphQL/JWT/Params
     views are off while a character set override is active — switch back to "Platform default" to use them again.
    </div>
   ) : null}
  </div>
 );
}
