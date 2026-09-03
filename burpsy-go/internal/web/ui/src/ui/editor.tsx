import { EditorView, Decoration, ViewPlugin, WidgetType, highlightSpecialChars, type DecorationSet, type ViewUpdate } from "@codemirror/view";
import { getSearchQuery, openSearchPanel, searchPanelOpen, SearchCursor } from "@codemirror/search";
import { Prec, RangeSetBuilder, type Extension } from "@codemirror/state";
import CodeMirror from "@uiw/react-codemirror";
import { ClipboardPaste, Copy, Download, MoreHorizontal, Pilcrow, Search, WrapText } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { copyToClipboard, downloadText, formatBytes } from "../lib/api";
import { bodyOf, compactMessage, contentTypeOf, hexDump, isResponse, prettyMessage } from "../lib/message";
import { byteOffsetToCharIndex, detectGraphQL, findJwts, paramsOf } from "../lib/message-views";
import {
  base64Decode,
  base64Encode,
  htmlDecode,
  htmlEncodeKeyChars,
  urlDecode,
  urlEncodeKeyChars,
} from "../lib/transforms";
import { cn } from "../lib/cn";
import { HexEditor } from "./hex-editor";
import { ContextMenu, DropdownMenu, hasMenuActions, type MenuGroup } from "./menu";
import { IconButton } from "./primitives";
import { GraphQLView, JwtView, ParamsView } from "./typed-views";

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

function buildDecorations(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  const boundary = headerEnd(view);
  const doc = view.state.doc;

  for (const { from, to } of view.visibleRanges) {
    let position = from;
    while (position <= to) {
      const line = doc.lineAt(position);
      if (line.from >= boundary) {
        if (line.length > 0 || line.from > boundary) builder.add(line.from, line.from, BODY_LINE);
      } else if (line.number === 1) {
        if (line.length > 0) builder.add(line.from, line.to, START_LINE);
      } else if (line.length > 0) {
        const colon = line.text.indexOf(":");
        if (colon > 0) {
          builder.add(line.from, line.from + colon, HEADER_NAME);
          if (line.from + colon + 1 < line.to) builder.add(line.from + colon + 1, line.to, HEADER_VALUE);
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

/**
 * The break bytes behind each rendered line, read off the raw message rather than the
 * CodeMirror document: CM6 normalises CRLF to LF when it parses the doc, so the document
 * itself can no longer tell a CRLF message from an LF one - and certifying "LF only" on a
 * CRLF message is the one wrong answer this toggle must never give. The raw text and the
 * document agree line-for-line (every break spelling still breaks exactly one line), so the
 * nth break in the raw text is the break after the nth rendered line.
 */
function breakGlyphs(text: string): string[] {
  const glyphs: string[] = [];
  for (const match of text.matchAll(/\r\n|\r|\n/g)) {
    glyphs.push(match[0] === "\r\n" ? "␍␊" : match[0] === "\n" ? "␊" : "␍");
  }
  return glyphs;
}

function buildEOLMarkers(view: EditorView, raw: string): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  const doc = view.state.doc;
  const glyphs = breakGlyphs(raw);
  for (let lineNo = 1; lineNo <= doc.lines; lineNo += 1) {
    const line = doc.line(lineNo);
    // The final line has no break after it (a document ending in a break grows an empty
    // final line instead), so there is nothing to name there.
    if (line.to >= doc.length) break;
    const glyph = glyphs[lineNo - 1];
    if (glyph) builder.add(line.to, line.to, Decoration.widget({ widget: new EOLMarker(glyph), side: 1 }));
  }
  return builder.finish();
}

function nonPrintingEOLPlugin(rawRef: { current: string }) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet;
      constructor(view: EditorView) {
        this.decorations = buildEOLMarkers(view, rawRef.current);
      }
      update(update: ViewUpdate) {
        if (update.docChanged || update.viewportChanged) this.decorations = buildEOLMarkers(update.view, rawRef.current);
      }
    },
    { decorations: (plugin) => plugin.decorations },
  );
}

/**
 * Colours come from CSS custom properties so a single stylesheet drives both
 * themes; CodeMirror's generated rules resolve them at paint time.
 */
const editorTheme = EditorView.theme({
  "&": { backgroundColor: "var(--editor-bg)", color: "var(--editor-fg)", fontSize: "12px" },
  ".cm-content": { fontFamily: "var(--font-mono)", padding: "8px 0", caretColor: "var(--accent)" },
  ".cm-gutters": {
    backgroundColor: "var(--editor-gutter-bg)",
    color: "var(--editor-gutter-fg)",
    border: "0",
    borderRight: "1px solid var(--editor-line)",
    fontFamily: "var(--font-mono)",
    fontSize: "11px",
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
}, { dark: false });

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
  const changes = view.state.selection.ranges
    .filter((range) => !range.empty)
    .map((range) => ({
      from: range.from,
      to: range.to,
      insert: transform(view.state.sliceDoc(range.from, range.to)),
    }));
  if (!changes.length) return false;
  view.dispatch({ changes, scrollIntoView: true });
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

const burpEditorKeys = Prec.high(
  EditorView.domEventHandlers({
    keydown(event, view) {
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return false;
      const key = event.key.toLowerCase();

      if (key === "s") {
        event.preventDefault();
        openSearchPanel(view);
        return true;
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
type MessageView = "pretty" | "raw" | "hex" | "render" | "graphql" | "jwt" | "params";

// The tab bar's labels, keyed by view. Kept next to the type so a view added to the
// union fails to compile here first — a tab that renders its key instead of a label is
// exactly the kind of half-wired view this editor shipped with once already.
const VIEW_LABELS: Record<MessageView, string> = {
  pretty: "Pretty",
  raw: "Raw",
  hex: "Hex",
  render: "Render",
  graphql: "GraphQL",
  jwt: "JWT",
  params: "Params",
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
}: {
  value: string;
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
}): JSX.Element {
  const [wrap, setWrap] = useState(true);
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

  const editable = !readOnly && Boolean(onChange);
  // The search spec this editor last auto-scrolled for. Outside the useMemo because the
  // listener closes over it; per-editor, so two editors do not fight over one marker.
  const lastSearchSpecRef = useRef("");
  const rawTextRef = useRef("");
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
      burpEditorKeys,
      EditorView.contentAttributes.of({ "aria-label": label }),
      // Keeps the codec menu entries honest about whether they have anything to act on.
      EditorView.updateListener.of((update) => {
        if (!update.selectionSet && !update.docChanged) return;
        setHasSelection(update.state.selection.ranges.some((range) => !range.empty));
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
    if (showNonPrinting) base.push(nonPrintingGlyphs, nonPrintingEOLPlugin(rawTextRef));
    return base;
  }, [wrap, showNonPrinting, label]);

  const bytes = useMemo(() => new TextEncoder().encode(value).length, [value]);
  const response = useMemo(() => isResponse(value), [value]);
  const renderable = useMemo(() => response && /html/i.test(contentTypeOf(value)), [response, value]);

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

  const available: MessageView[] = views
    ? ([
        ...(canPretty ? ["pretty"] : []),
        "raw",
        "hex",
        ...(renderable ? ["render"] : []),
        ...(graphql ? ["graphql"] : []),
        ...(jwt && jwt.tokens.length ? ["jwt"] : []),
        ...(params && params.rows.length ? ["params"] : []),
      ] as MessageView[])
    : [];

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
  const active: MessageView = available.includes(view)
    ? view
    : !pickedRef.current && canPretty
      ? "pretty"
      : "raw";
  const shown = active === "pretty" ? prettied : value;
  // Refreshed every render, before any plugin constructor or update can run: the EOL plugin
  // names breaks off the raw text (CM6 normalises CRLF away in the document), and reading it
  // here keeps `value` out of the extensions useMemo deps - which would otherwise rebuild the
  // whole extension set on every keystroke. This must stay outside that useMemo: its factory
  // runs on mount, before this line exists, which is a first-render TDZ crash.
  rawTextRef.current = shown;
  // What the toolbar's Copy hands over. Hex still copies a dump — that is what an
  // operator pasting into a ticket wants, and it is why message.ts's read-only
  // hexDump did not go away when the view became editable.
  const clipboard = active === "pretty" ? prettied : active === "hex" ? hexDump(value) : value;

  // A Hex selection handed to the Raw view. The byte range is mapped to a character
  // range on the way, because the two views index the same message differently.
  const cmViewRef = useRef<EditorView | null>(null);
  const [cmEpoch, setCmEpoch] = useState(0);
  const [reveal, setReveal] = useState<{ from: number; to: number } | null>(null);
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

  const selectionGroups = useMemo<MenuGroup[]>(() => {
    if (active !== "raw") return [];
    const codec = (id: string, label: string, shortcut: string, transform: (input: string) => string) => ({
      id,
      label,
      shortcut,
      disabled: !hasSelection,
      onSelect: () => runTransform(transform),
    });
    return [
      {
        id: "convert-selection",
        title: hasSelection ? "Convert selection" : "Convert selection (select text first)",
        actions: [
          codec("url-encode", "URL-encode", "Ctrl+U", urlEncodeKeyChars),
          codec("url-decode", "URL-decode", "Ctrl+Shift+U", urlDecode),
          codec("html-encode", "HTML-encode", "Ctrl+H", htmlEncodeKeyChars),
          codec("html-decode", "HTML-decode", "Ctrl+Shift+H", htmlDecode),
          codec("b64-encode", "Base64-encode", "Ctrl+B", base64Encode),
          codec("b64-decode", "Base64-decode", "Ctrl+Shift+B", base64Decode),
        ],
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
    ];
  }, [active, hasSelection, runTransform]);

  const allGroups = useMemo<MenuGroup[]>(
    () => [...(menuGroups ?? []), ...selectionGroups],
    [menuGroups, selectionGroups],
  );

  return (
    <div className={cn("editor-shell", className)}>
      <div className="editor-bar">
        <span className="editor-label-inline">{label}</span>
        {available.length ? (
          <div className="editor-views" role="tablist" aria-label={`${label} view`}>
            {available.map((candidate) => (
              <button
                key={candidate}
                type="button"
                role="tab"
                aria-selected={candidate === active}
                className={candidate === active ? "editor-view editor-view-active" : "editor-view"}
                onClick={() => pick(candidate)}
              >
                {VIEW_LABELS[candidate]}
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
                <button
                  type="button"
                  className="icon-button icon-button-sm"
                  aria-label={`Actions for ${label}`}
                  title={`Actions for ${label}`}
                >
                  <MoreHorizontal size={13} />
                </button>
              }
            />
          ) : null}
          {/* Wrapping is a CodeMirror setting, so the toggle is offered only on the two
              views CodeMirror renders. It used to be hidden for Render alone, which left
              a dead control on Hex. */}
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
      <ContextMenu groups={active === "render" ? [] : allGroups}>
      <div className="editor-body" style={{ height }}>
        {active === "render" ? (
          // No scripts, no same-origin, no forms: a captured response is attacker
          // controlled and must never run inside the console's own origin.
          <iframe
            className="render-frame"
            title={`${label} rendered`}
            sandbox=""
            srcDoc={bodyOf(value)}
          />
        ) : active === "hex" ? (
          <HexEditor
            value={shown}
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
                    setReveal({
                      from: byteOffsetToCharIndex(value, selection.from),
                      to: byteOffsetToCharIndex(value, selection.to),
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
        ) : (
          <CodeMirror
            value={shown}
            onChange={
              // Raw edits are the bytes; a Pretty edit is the operator editing the
              // readable form, written back through compactMessage so the wire keeps
              // the body compacted exactly as it was (burpsy-react-ui-dmf) — the same
              // deal Burp offers ("In this tab, you can access all the same
              // functionality as in the Raw tab"), and the reason the sent request
              // never silently grows to the pretty layout. A mid-edit JSON parse
              // failure passes the operator's text through untouched, and Raw then
              // shows precisely what they typed.
              active === "pretty" && editable
                ? (next) => onChange?.(compactMessage(next))
                : active === "raw"
                  ? onChange
                  : undefined
            }
            editable={editable && (active === "raw" || active === "pretty")}
            readOnly={!(editable && (active === "raw" || active === "pretty"))}
            height="100%"
            theme={editorTheme}
            extensions={extensions}
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
      {editable && active !== "raw" && active !== "hex" && active !== "pretty" ? (
        <div className="editor-note">
          Editing happens on the Raw, Hex and Pretty views — this one reads the message without writing one back.
        </div>
      ) : null}
    </div>
  );
}
