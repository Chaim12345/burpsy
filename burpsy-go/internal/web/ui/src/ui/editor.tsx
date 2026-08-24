import { EditorView, Decoration, ViewPlugin, type DecorationSet, type ViewUpdate } from "@codemirror/view";
import { openSearchPanel } from "@codemirror/search";
import { Prec, RangeSetBuilder, type Extension } from "@codemirror/state";
import CodeMirror from "@uiw/react-codemirror";
import { Copy, Download, WrapText } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { copyToClipboard, downloadText, formatBytes } from "../lib/api";
import { bodyOf, contentTypeOf, hexDump, isResponse, prettyMessage } from "../lib/message";
import {
  base64Decode,
  base64Encode,
  htmlDecode,
  htmlEncodeKeyChars,
  urlDecode,
  urlEncodeKeyChars,
} from "../lib/transforms";
import { cn } from "../lib/cn";
import { IconButton } from "./primitives";

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
type MessageView = "pretty" | "raw" | "hex" | "render";

/**
 * Raw HTTP message editor with Burp's message-editor views.
 *
 * Raw is the only editable view — it is the exact bytes. Pretty reformats the body
 * only, Hex is a read-only dump, and Render shows the response in a sandboxed
 * iframe. Editing stays on Raw deliberately: a reformatted body is not the bytes
 * that were sent, and silently sending the reformatted version would be a lie.
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
}): JSX.Element {
  const [wrap, setWrap] = useState(true);
  const [view, setView] = useState<MessageView>("raw");

  const editable = !readOnly && Boolean(onChange);
  const extensions = useMemo<Extension[]>(() => {
    // CodeMirror's content element renders with role="textbox" but nothing in @uiw/react-codemirror's
    // own props reaches it — the wrapper spreads unknown props onto its outer container, not the
    // content DOM node CM6 owns internally. contentAttributes is CM6's own mechanism for setting
    // attributes on that exact element, so this is the only place `label` (already a required prop,
    // used nowhere else for accessibility) actually becomes the textbox's accessible name. Found by
    // the e2e a11y suite's first real run: every route with an HttpEditor failed "aria-label attribute
    // does not exist" on this element, because every route has at least one.
    const base: Extension[] = [httpHighlight, burpEditorKeys, EditorView.contentAttributes.of({ "aria-label": label })];
    if (wrap) base.push(EditorView.lineWrapping);
    return base;
  }, [wrap, label]);

  const bytes = useMemo(() => new TextEncoder().encode(value).length, [value]);
  const response = useMemo(() => isResponse(value), [value]);
  const renderable = useMemo(() => response && /html/i.test(contentTypeOf(value)), [response, value]);

  // Pretty is only offered when it would actually change something.
  const prettied = useMemo(() => (views ? prettyMessage(value) : value), [views, value]);
  const canPretty = views && prettied !== value;

  const available: MessageView[] = views
    ? (["pretty", "raw", "hex", ...(renderable ? (["render"] as MessageView[]) : [])] as MessageView[]).filter(
        (candidate) => candidate !== "pretty" || canPretty,
      )
    : [];

  // Fall back to Raw if the current view stops being available for a new message.
  const active: MessageView = available.length === 0 || available.includes(view) ? view : "raw";
  const shown = active === "pretty" ? prettied : active === "hex" ? hexDump(value) : value;

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
                onClick={() => setView(candidate)}
              >
                {candidate}
              </button>
            ))}
          </div>
        ) : null}
        <span className="editor-meta">{formatBytes(bytes)}</span>
        <div className="editor-bar-actions">
          {actions}
          {active !== "render" ? (
            <IconButton
              label={wrap ? "Disable wrapping" : "Enable wrapping"}
              size="small"
              aria-pressed={wrap}
              onClick={() => setWrap((current) => !current)}
            >
              <WrapText size={13} />
            </IconButton>
          ) : null}
          <IconButton
            label="Copy message"
            size="small"
            onClick={() => {
              void copyToClipboard(shown);
              toast.success(`${label} copied to clipboard`);
            }}
          >
            <Copy size={13} />
          </IconButton>
          <IconButton label="Save to file" size="small" onClick={() => downloadText(filename, value)}>
            <Download size={13} />
          </IconButton>
        </div>
      </div>
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
        ) : (
          <CodeMirror
            value={shown}
            onChange={active === "raw" ? onChange : undefined}
            editable={editable && active === "raw"}
            readOnly={!(editable && active === "raw")}
            height="100%"
            theme={editorTheme}
            extensions={extensions}
            placeholder={placeholder}
            basicSetup={{
              lineNumbers: true,
              foldGutter: false,
              autocompletion: false,
              bracketMatching: false,
              closeBrackets: false,
              highlightActiveLine: editable && active === "raw",
              highlightActiveLineGutter: editable && active === "raw",
              searchKeymap: true,
              indentOnInput: false,
            }}
          />
        )}
      </div>
      {editable && active !== "raw" ? (
        <div className="editor-note">Editing happens on the Raw view, which is the exact bytes.</div>
      ) : null}
    </div>
  );
}
