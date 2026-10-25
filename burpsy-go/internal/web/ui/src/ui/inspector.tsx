import { ArrowDown, ArrowUp, ChevronDown, ChevronRight, ChevronsDownUp, ChevronsRight, ChevronsUpDown, Copy, Plus, Settings2, Trash2, Wand2, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { copyToClipboard, formatBytes } from "../lib/api";
import {
  addBodyParam,
  addCookie,
  addHeader,
  addQueryParam,
  bodyParamSpans,
  bodyParamsEditable,
  cookieSpans,
  cookiesOf,
  headerSpans,
  headerValue,
  isResponse,
  moveItem,
  parseMessage,
  parseRequestLine,
  parseStatusLine,
  querySpans,
  removeBodyParamAt,
  removeCookieAt,
  removeHeaderAt,
  removeQueryParamAt,
  setBodyParamAt,
  setCookieAt,
  setHeaderAt,
  setQueryParamAt,
  setStartLineTail,
  setStartLineToken,
  type ReorderDomain,
} from "../lib/message";
import { base64Decode, base64Encode, htmlDecode, htmlEncodeKeyChars, urlDecode, urlEncodeKeyChars } from "../lib/transforms";
import { CRLF_GLYPHS, hasLineBreak, hasLineBreakGlyphs, insertAt, readLineBreaks, showLineBreaks } from "../lib/line-breaks";
import { ContextMenu, type MenuGroup } from "./menu";
import { kettleHeaderEdit, type H2Field } from "../lib/kettle";
import { useApp } from "../lib/store";
import { cn } from "../lib/cn";
import { Badge, Button, IconButton, Input } from "./primitives";
import { confirmDialog } from "../lib/dialogs";

/* ==== the model ============================================================
 *
 * A row knows how to WRITE ITSELF, as a closure over the index it came from.
 * That is the whole design: the alternative — a section-wide switch on a row
 * "kind" — has to re-derive which writer applies at commit time, and the one
 * bug that costs is the worst one available here, an edit landing on the wrong
 * header of a request that is about to be sent.
 */

interface Row {
  name: string;
  value: string;
  /** Position within this row's own writer domain, for ordering removals. */
  index: number;
  /** Whether the NAME is a real name (a header, a parameter) or a fixed label ("Method"). */
  renamable: boolean;
  /** Absent for a derived row — a body's size is a fact about the message, not a field in it. */
  set?: (raw: string, name: string, value: string) => string;
  remove?: (raw: string) => string;
}

interface SectionModel {
  id: string;
  title: string;
  rows: Row[];
  add?: (raw: string, name: string, value: string) => string;
  /**
   * Why this section cannot be written, when it cannot. Rendered instead of
   * silently showing fields that would do nothing — the same rule the editor
   * follows for its Pretty view.
   */
  note?: string;
  /** Extra controls in the section head; the attributes section's HTTP/1 and HTTP/2. */
  extra?: JSX.Element;
  /**
   * Which item list the arrow buttons reorder (burpsy-react-ui-ybmd), absent where order is not
   * the operator's to change — the start line's attributes, or a body the writers cannot parse.
   */
  reorder?: ReorderDomain;
  /**
   * Whether an item here is a header field, the one thing Burp's Shift+Return injection targets
   * (burpsy-react-ui-ln2a). Every other section refuses a CR/LF by name.
   */
  headerFields?: boolean;
  /**
   * The section's own writer target, when it is not the message text: a kettled request's header
   * section edits the HTTP/2 field list (jae5). Its rows' `set`/`remove`, `add` and `move` then work on
   * that list's JSON form, and this commits the result — so the generic row machinery (drafts, Apply,
   * removal order, reordering) is the same code for both, and only where the result goes differs.
   */
  commit?: (apply: (state: string) => string, summary: string) => void;
  /** Reorder for a section whose state is not the message text; see `commit`. */
  move?: (state: string, index: number, direction: -1 | 1) => string;
}

/** "3 rows", "1 row" — the count an assistive reader hears. Pluralised because a tool whose
 *  differentiator is careful counting cannot afford to say "1 rows". */
function countLabel(count: number): string {
  return `${count} ${count === 1 ? "row" : "rows"}`;
}

/* ==== the decoder ==========================================================
 *
 * Burp's Inspector carries a stack of decoders you apply to one selected value.
 * These run against the local codecs rather than /api/tools/decode: the point of
 * the widget is to try four decodings in four seconds and see which one turns
 * into something, and a round trip per stage turns that into a chore.
 */

type Codec = "url-decode" | "url-encode" | "html-decode" | "html-encode" | "base64-decode" | "base64-encode";

const CODECS: { value: Codec; label: string; apply: (input: string) => string }[] = [
  { value: "url-decode", label: "URL decode", apply: urlDecode },
  { value: "url-encode", label: "URL encode", apply: urlEncodeKeyChars },
  { value: "html-decode", label: "HTML decode", apply: htmlDecode },
  { value: "html-encode", label: "HTML encode", apply: htmlEncodeKeyChars },
  { value: "base64-decode", label: "Base64 decode", apply: base64Decode },
  { value: "base64-encode", label: "Base64 encode", apply: base64Encode },
];

const codecOf = (value: Codec) => CODECS.find((entry) => entry.value === value)!;

/* ==== code point (burpsy-react-ui-luu3) ====================================
 *
 * Burp's message-editor docs: select a character in the Inspector and "an entry will appear ...
 * that indicates the decimal and hex code points for the character. In editable contexts ... you
 * can edit this value to overwrite the selected character" — the way to type a byte with no
 * keyboard representation (NUL, ESC, a raw 0x81) into a request.
 *
 * This reads the native input's own selection (selectionStart/End), which is UTF-16 code-unit
 * offsets — the same unit String.prototype.slice already uses everywhere else in this file, so a
 * codepoint above U+FFFF (a surrogate pair, two code units) is out of scope here exactly as it
 * would be for the rest of the Selection section's string handling, not a new limitation.
 */

/** A control character renders as nothing at all; showing its Unicode Control Picture glyph (the
 *  ␀-␟ block, plus ␡ for DEL) is what makes "which byte did I select" answerable at a glance. */
function displayChar(char: string): string {
  const codePoint = char.codePointAt(0) ?? 0;
  if (codePoint <= 0x1f) return String.fromCodePoint(0x2400 + codePoint);
  if (codePoint === 0x7f) return "␡";
  return char;
}

function CodePointEditor({
  char,
  writable,
  onOverwrite,
}: {
  char: string;
  writable: boolean;
  onOverwrite: (nextChar: string) => void;
}): JSX.Element {
  const codePoint = char.codePointAt(0) ?? 0;
  const [decimal, setDecimal] = useState(String(codePoint));
  const [hex, setHex] = useState(codePoint.toString(16).toUpperCase());

  // An edit that does not parse, or names a value outside the Unicode range, reverts to the
  // current code point rather than writing anything — the same "refuse rather than guess" rule
  // this codebase's own decoders follow (see api_toolkit.go's decodeLayer).
  const commit = (parsed: number) => {
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0x10ffff) {
      setDecimal(String(codePoint));
      setHex(codePoint.toString(16).toUpperCase());
      return;
    }
    if (parsed !== codePoint) onOverwrite(String.fromCodePoint(parsed));
  };

  return (
    <div className="inspector-decoder">
      <span className="cell-dim" title={`Selected character (U+${codePoint.toString(16).toUpperCase().padStart(4, "0")})`}>
        {displayChar(char)}
      </span>
      <Input
        className="inspector-input"
        aria-label="Selected character's code point, decimal"
        title="Decimal code point"
        value={decimal}
        readOnly={!writable}
        inputMode="numeric"
        onChange={(event) => setDecimal(event.target.value)}
        onBlur={() => commit(Number.parseInt(decimal, 10))}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            commit(Number.parseInt(decimal, 10));
          }
        }}
      />
      <Input
        className="inspector-input"
        aria-label="Selected character's code point, hex"
        title="Hex code point"
        value={hex}
        readOnly={!writable}
        onChange={(event) => setHex(event.target.value)}
        onBlur={() => commit(Number.parseInt(hex, 16))}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            commit(Number.parseInt(hex, 16));
          }
        }}
      />
    </div>
  );
}

/** The value the Selection section is working on, and where Apply writes it back to. */
interface Selection {
  /** Section and row, for the label and for the write-back. */
  sectionId: string;
  rowIndex: number;
  label: string;
  original: string;
  /** The decoder stack, applied in order. */
  stages: Codec[];
}

/** Every stage applied in order, so the field shows the end of the chain. */
function decoded(selection: Selection): string {
  return selection.stages.reduce((text, stage) => codecOf(stage).apply(text), selection.original);
}

/* ==== sections =============================================================== */

function SectionHead({
  title,
  count,
  open,
  onToggle,
  id,
  extra,
}: {
  title: string;
  count: number;
  open: boolean;
  onToggle: () => void;
  id: string;
  extra?: JSX.Element;
}): JSX.Element {
  return (
    <div className="inspector-head-row">
      <button
        type="button"
        className="inspector-head"
        aria-expanded={open}
        // Only while the panel exists. A dangling aria-controls is a broken promise
        // to assistive tech, and axe flags it as an invalid attribute value.
        aria-controls={open ? `${id}-rows` : undefined}
        onClick={onToggle}
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <span>{title}</span>
        {/* The bare number is for the eye, so it is hidden from the accessible name and
            the pluralised text carries it instead — "1 row", never "1 rows". aria-label
            cannot do this job: on a <span>, which maps to the generic role, naming is
            prohibited and the label is dropped. */}
        <Badge aria-hidden="true">{count}</Badge>
        <span className="sr-only">{countLabel(count)}</span>
      </button>
      {open && extra ? <div className="inspector-head-extra">{extra}</div> : null}
    </div>
  );
}

interface Draft {
  name: string;
  value: string;
}

function SectionBlock({
  section,
  open,
  onToggle,
  editable,
  onCommit: onCommitText,
  onSelect,
  onDetail,
  onAnnounce,
}: {
  section: SectionModel;
  open: boolean;
  onToggle: () => void;
  editable: boolean;
  onCommit: (apply: (raw: string) => string, summary: string) => void;
  onSelect: (sectionId: string, rowIndex: number, label: string, value: string) => void;
  onDetail: (sectionId: string, rowIndex: number) => void;
  onAnnounce: (text: string) => void;
}): JSX.Element {
  /** Edits buffered until Apply. Keyed by the row's position in the rendered list. */
  const [drafts, setDrafts] = useState<Record<number, Draft>>({});
  const [removing, setRemoving] = useState<number[]>([]);
  const [adding, setAdding] = useState<Draft | null>(null);
  /**
   * The row the arrow buttons move — Burp's "select the item and use the arrow buttons at the
   * bottom of the list". Kept out of `reset` on purpose: a move changes the row fingerprint, and
   * the selection has to follow the moved row to its new place rather than vanish, so a header
   * can be walked several places with repeated clicks.
   */
  const [selected, setSelected] = useState<number | null>(null);

  const reset = () => {
    setDrafts({});
    setRemoving([]);
    setAdding(null);
  };

  // A new message means the buffered edits describe rows that no longer exist.
  // Dropping them is the honest move: keeping them would apply an edit meant for
  // one request to a different one.
  // The delimiters are written as escapes, never as literal control bytes. They used to be the
  // raw characters, and a single NUL byte in the source made grep classify this whole 826-line
  // file as binary and silently report zero matches in it -- which is how the parity audit
  // concluded that inspectorPanelState had "zero readers, zero writers" and filed W6 #12 as its
  // flagship unwired finding, while lines 468 and 543 below had been reading it all along.
  // U+0000 and U+0001 cannot occur in a header name or value, which is the property being relied
  // on here; the escapes produce exactly the same two code units.
  const rowFingerprint = section.rows.map((row) => `${row.name}\u0000${row.value}`).join("\u0001");
  useEffect(reset, [rowFingerprint]);

  const dirty = Object.keys(drafts).length > 0 || removing.length > 0 || adding !== null;

  const apply = () => {
    const sets = Object.entries(drafts).map(([key, draft]) => ({ row: section.rows[Number(key)]!, draft }));
    const removals = removing
      .map((key) => section.rows[key]!)
      // Descending, so removing row 3 cannot invalidate the index row 1 was found at.
      // Ascending would silently delete the wrong row on the second removal.
      .sort((a, b) => b.index - a.index);
    const newRow = adding;

    onCommit((raw) => {
      let next = raw;
      // Sets first: replacing a row's text never changes the row COUNT, so every
      // index stays valid however many are written.
      for (const { row, draft } of sets) if (row.set) next = row.set(next, draft.name, draft.value);
      for (const row of removals) if (row.remove) next = row.remove(next);
      if (newRow && section.add) next = section.add(next, newRow.name, newRow.value);
      return next;
    }, `${section.title} updated`);
    reset();
  };

  const draftFor = (index: number, row: Row): Draft => drafts[index] ?? { name: row.name, value: row.value };
  const editRow = (index: number, row: Row, patch: Partial<Draft>) =>
    setDrafts((current) => ({ ...current, [index]: { ...draftFor(index, row), ...patch } }));

  // A section with a writer target of its own commits there (jae5); every other section writes the text.
  const onCommit = section.commit ?? onCommitText;
  const canEdit = editable && !section.note;
  const canReorder = canEdit && section.reorder !== undefined && section.rows.length > 1;
  const selectedRow = selected !== null && selected < section.rows.length ? selected : null;

  /**
   * Move the selected row one place. Refused while edits are buffered: a move rewrites the
   * message, the fingerprint change resets the section, and an operator's half-typed value would
   * be silently thrown away by a click on an arrow. Applying or cancelling first is one click.
   */
  const move = (direction: -1 | 1) => {
    if (selectedRow === null || !section.reorder || dirty) return;
    const to = selectedRow + direction;
    if (to < 0 || to >= section.rows.length) return;
    const domain = section.reorder;
    const row = section.rows[selectedRow]!;
    onCommit(
      (raw) => (section.move ? section.move(raw, selectedRow, direction) : moveItem(raw, domain, selectedRow, direction)),
      `${row.name} moved ${direction < 0 ? "up" : "down"}`,
    );
    setSelected(to);
  };

  return (
    <div className="inspector-section">
      <SectionHead
        id={`inspector-${section.id}`}
        title={section.title}
        count={section.rows.length}
        open={open}
        onToggle={onToggle}
        extra={section.extra}
      />
      {open ? (
        <div id={`inspector-${section.id}-rows`}>
          {section.note ? <p className="inspector-note">{section.note}</p> : null}
          {section.rows.length === 0 && !adding ? <p className="inspector-empty">none</p> : null}
          {section.rows.length > 0 || adding ? (
            <dl className="inspector-rows">
              {section.rows.map((row, index) => {
                const draft = draftFor(index, row);
                const gone = removing.includes(index);
                // A kettled field may hold CR/LF (jae5). An inline <input> would strip it on the next
                // keystroke, so such a row shows its line breaks as ␍␊ and is edited in the detail view.
                const breaks = hasLineBreak(row.name) || hasLineBreak(row.value);
                const rowEditable = canEdit && Boolean(row.set) && !breaks;
                // Burp's item context menu: "Copy name or Copy value from the context menu". Offered on
                // every mount, read-only ones included — copying changes nothing. The value is the
                // item's own text, CR/LF and all, never the glyph form a field shows.
                const copyMenu: MenuGroup[] = [
                  {
                    id: "copy",
                    actions: [
                      {
                        id: "copy-name",
                        label: "Copy name",
                        icon: Copy,
                        onSelect: () => void copyToClipboard(row.name).then(() => onAnnounce(`Copied the name ${row.name}`)),
                      },
                      {
                        id: "copy-value",
                        label: "Copy value",
                        icon: Copy,
                        onSelect: () => void copyToClipboard(row.value).then(() => onAnnounce(`Copied the value of ${row.name}`)),
                      },
                    ],
                  },
                  {
                    id: "detail",
                    actions: [{ id: "open-detail", label: "Open in detail view", icon: ChevronsRight, onSelect: () => onDetail(section.id, index) }],
                  },
                ];
                return (
                  <ContextMenu key={`${row.name}-${index}`} groups={copyMenu} docTopic="message-editor">
                  <div
                    className={cn(gone && "inspector-row-removed", canReorder && selectedRow === index && "inspector-row-selected")}
                    // Focus anywhere in the row selects it for the arrow buttons, so a keyboard
                    // operator selects by tabbing in exactly as a mouse operator does by clicking.
                    onFocus={canReorder ? () => setSelected(index) : undefined}
                    onClick={canReorder ? () => setSelected(index) : undefined}
                    onKeyDown={(event) => {
                      // The context menu from the keyboard: the Menu key and Shift+F10 are what a
                      // desktop tool answers, and a browser does not reliably turn either into a
                      // contextmenu event on a focused field, so the row raises one itself.
                      if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
                        event.preventDefault();
                        const rect = event.currentTarget.getBoundingClientRect();
                        event.currentTarget.dispatchEvent(
                          new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: rect.left + 8, clientY: rect.bottom }),
                        );
                        return;
                      }
                      if (!canReorder || !event.altKey || (event.key !== "ArrowUp" && event.key !== "ArrowDown")) return;
                      event.preventDefault();
                      move(event.key === "ArrowUp" ? -1 : 1);
                    }}
                  >
                    <dt title={row.name}>
                      {rowEditable && row.renamable ? (
                        <Input
                          className="inspector-input"
                          aria-label={`${section.title} name ${index + 1}`}
                          value={draft.name}
                          disabled={gone}
                          onChange={(event) => editRow(index, row, { name: event.target.value })}
                        />
                      ) : (
                        showLineBreaks(row.name)
                      )}
                    </dt>
                    <dd title={row.value}>
                      <div className="inspector-cell">
                        {rowEditable ? (
                          <Input
                            className="inspector-input"
                            aria-label={`${section.title} value for ${row.name}`}
                            value={draft.value}
                            disabled={gone}
                            onChange={(event) => editRow(index, row, { value: event.target.value })}
                          />
                        ) : (
                          <button
                            type="button"
                            className="inspector-value"
                            onClick={() => void copyToClipboard(row.value)}
                            title="Copy value"
                          >
                            {row.value === "" ? <span className="cell-dim">(empty)</span> : showLineBreaks(row.value)}
                          </button>
                        )}
                        <IconButton
                          label={`Open ${row.name} in the detail view`}
                          size="small"
                          className="inspector-row-action"
                          onClick={() => onDetail(section.id, index)}
                        >
                          <ChevronsRight size={12} />
                        </IconButton>
                        <IconButton
                          label={`Decode ${row.name}`}
                          size="small"
                          className="inspector-row-action"
                          onClick={() => onSelect(section.id, index, `${section.title} · ${row.name}`, draft.value)}
                        >
                          <Wand2 size={12} />
                        </IconButton>
                        {canEdit && row.remove ? (
                          <IconButton
                            label={gone ? `Keep ${row.name}` : `Remove ${row.name}`}
                            size="small"
                            className="inspector-row-action"
                            onClick={() =>
                              setRemoving((current) => (current.includes(index) ? current.filter((k) => k !== index) : [...current, index]))
                            }
                          >
                            {gone ? <X size={12} /> : <Trash2 size={12} />}
                          </IconButton>
                        ) : null}
                      </div>
                    </dd>
                  </div>
                  </ContextMenu>
                );
              })}
              {adding ? (
                <div>
                  <dt>
                    <Input
                      className="inspector-input"
                      aria-label={`New ${section.title} name`}
                      value={adding.name}
                      placeholder="name"
                      autoFocus
                      onChange={(event) => setAdding({ ...adding, name: event.target.value })}
                    />
                  </dt>
                  <dd>
                    <Input
                      className="inspector-input"
                      aria-label={`New ${section.title} value`}
                      value={adding.value}
                      placeholder="value"
                      onChange={(event) => setAdding({ ...adding, value: event.target.value })}
                    />
                  </dd>
                </div>
              ) : null}
            </dl>
          ) : null}
          {canEdit ? (
            <div className="inspector-actions">
              {section.add && !adding ? (
                <Button variant="quiet" size="small" onClick={() => setAdding({ name: "", value: "" })}>
                  <Plus size={12} />
                  Add
                </Button>
              ) : null}
              {canReorder ? (
                <>
                  <IconButton
                    label={
                      dirty
                        ? "Apply or cancel the pending edits before reordering"
                        : selectedRow === null
                          ? `Select a ${section.title.toLowerCase()} row to move it up`
                          : `Move ${section.rows[selectedRow]!.name} up (Alt+Up)`
                    }
                    size="small"
                    disabled={dirty || selectedRow === null || selectedRow === 0}
                    onClick={() => move(-1)}
                  >
                    <ArrowUp size={12} />
                  </IconButton>
                  <IconButton
                    label={
                      dirty
                        ? "Apply or cancel the pending edits before reordering"
                        : selectedRow === null
                          ? `Select a ${section.title.toLowerCase()} row to move it down`
                          : `Move ${section.rows[selectedRow]!.name} down (Alt+Down)`
                    }
                    size="small"
                    disabled={dirty || selectedRow === null || selectedRow === section.rows.length - 1}
                    onClick={() => move(1)}
                  >
                    <ArrowDown size={12} />
                  </IconButton>
                </>
              ) : null}
              <span style={{ flex: 1 }} />
              {dirty ? (
                <>
                  <Button variant="quiet" size="small" onClick={reset}>
                    Cancel
                  </Button>
                  <Button size="small" onClick={apply}>
                    Apply
                  </Button>
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

/* ==== the Selection section — Burp's inspectorSelectionSection ============== */

function SelectionSection({
  selection,
  onChangeSelection,
  onApply,
  onClear,
  writable,
}: {
  selection: Selection;
  onChangeSelection: (next: Selection) => void;
  onApply: (text: string) => void;
  onClear: () => void;
  writable: boolean;
}): JSX.Element {
  const result = decoded(selection);
  // Which one character (if exactly one) is selected in the field below — not the section's own
  // `selection.stages`, which is the decoder stack, a different "selection" than the one this
  // tracks (a highlighted range of text within `result`).
  const [charRange, setCharRange] = useState<{ start: number; end: number } | null>(null);
  const captureCharRange = (event: React.SyntheticEvent<HTMLInputElement>) => {
    const el = event.currentTarget;
    const { selectionStart, selectionEnd } = el;
    // Burp shows this for exactly one selected character, not a cursor position and not a longer
    // run — a wider selection has no single code point to report.
    setCharRange(
      selectionStart !== null && selectionEnd !== null && selectionEnd - selectionStart === 1
        ? { start: selectionStart, end: selectionEnd }
        : null,
    );
  };
  const selectedChar = charRange ? result[charRange.start] : undefined;
  return (
    <div className="inspector-section inspector-selection">
      <div className="inspector-head-row">
        <div className="inspector-head inspector-head-static">
          <span />
          <span>Selection</span>
          <Badge aria-hidden="true">{selection.stages.length}</Badge>
          <span className="sr-only">
            {selection.stages.length === 1 ? "1 decoder" : `${selection.stages.length} decoders`}
          </span>
        </div>
        <div className="inspector-head-extra">
          <IconButton label="Close selection" size="small" onClick={onClear}>
            <X size={12} />
          </IconButton>
        </div>
      </div>
      <div className="inspector-selection-body">
        <p className="inspector-selection-origin" title={selection.label}>
          {selection.label}
        </p>
        {selection.stages.map((stage, index) => (
          <div key={index} className="inspector-decoder">
            {/* A native select rather than the Select primitive: it sits in a dense
                stack where a visible label would cost the row height that makes the
                stack readable, so it carries an aria-label instead. */}
            <select
              className="input select inspector-decoder-select"
              aria-label={`Decoder ${index + 1} encoding`}
              value={stage}
              onChange={(event) =>
                onChangeSelection({
                  ...selection,
                  stages: selection.stages.map((entry, i) => (i === index ? (event.target.value as Codec) : entry)),
                })
              }
            >
              {CODECS.map((codec) => (
                <option key={codec.value} value={codec.value}>
                  {codec.label}
                </option>
              ))}
            </select>
            <IconButton
              label={`Remove decoder ${index + 1}`}
              size="small"
              onClick={() => onChangeSelection({ ...selection, stages: selection.stages.filter((_, i) => i !== index) })}
            >
              <Trash2 size={12} />
            </IconButton>
          </div>
        ))}
        <Input
          className="inspector-input inspector-selection-field"
          aria-label="Selection text"
          value={result}
          readOnly={selection.stages.length > 0}
          onChange={(event) => onChangeSelection({ ...selection, original: event.target.value, stages: [] })}
          onSelect={captureCharRange}
          onClick={captureCharRange}
          onKeyUp={captureCharRange}
        />
        {selection.stages.length > 0 ? (
          <p className="inspector-note">
            Showing the decoder output. Remove the decoders to type into it directly.
          </p>
        ) : null}
        {selectedChar !== undefined && charRange ? (
          <CodePointEditor
            // Remounts on a new selection (or once the char it names has itself changed), so the
            // decimal/hex drafts inside always start from what is actually selected rather than
            // carrying over a stale edit from the previous character.
            key={`${charRange.start}-${selectedChar}`}
            char={selectedChar}
            writable={writable && selection.stages.length === 0}
            onOverwrite={(nextChar) => {
              const { start, end } = charRange;
              onChangeSelection({
                ...selection,
                original: result.slice(0, start) + nextChar + result.slice(end),
                stages: [],
              });
            }}
          />
        ) : null}
        <div className="inspector-actions">
          <Button
            variant="quiet"
            size="small"
            onClick={() => onChangeSelection({ ...selection, stages: [...selection.stages, "url-decode"] })}
          >
            <Plus size={12} />
            Add decoder
          </Button>
          <IconButton label="Copy selection" size="small" onClick={() => void copyToClipboard(result)}>
            <Copy size={12} />
          </IconButton>
          <span style={{ flex: 1 }} />
          <Button variant="quiet" size="small" onClick={onClear}>
            Cancel
          </Button>
          {writable ? (
            <Button size="small" onClick={() => onApply(result)}>
              Apply
            </Button>
          ) : null}
        </div>
        {writable ? null : (
          <p className="inspector-note">This message is read-only here, so the decoded value can be copied but not written back.</p>
        )}
      </div>
    </div>
  );
}

/* ==== the detail view (burpsy-react-ui-ln2a) ================================
 *
 * Burp: "drill down into the header by clicking the chevron to the right of its entry in the
 * Inspector. From this view, you can select either the Name or Value field and press the Shift +
 * Return keys to enter the sequence \r\n." The fields show CR and LF as glyphs (lib/line-breaks.ts
 * says why a real line break cannot live in a form field) and Apply maps them back.
 *
 * Whether a CR/LF may be written at all is the caller's decision, passed as `crlfRefusal`: HTTP/1
 * text cannot carry one inside a header, so on an HTTP/1 request — or anywhere that cannot send an
 * HTTP/2 header list as written — Shift+Return is refused with the reason instead of quietly doing
 * nothing, and an Apply that would put one into the text is refused the same way.
 */

interface DetailTarget {
  sectionId: string;
  rowIndex: number;
}

function DetailSection({
  sectionTitle,
  row,
  writable,
  crlfRefusal,
  onApply,
  onClose,
  onAnnounce,
}: {
  sectionTitle: string;
  row: Row;
  writable: boolean;
  /** Why CR/LF cannot be written here, or null when it can. */
  crlfRefusal: string | null;
  onApply: (name: string, value: string) => void;
  onClose: () => void;
  onAnnounce: (text: string) => void;
}): JSX.Element {
  // A value already holding ␍ or ␊ cannot round-trip through the glyph form: Apply would turn a
  // literal glyph into a CR the message never had. Such a row is shown, never written.
  const lossy = hasLineBreakGlyphs(row.name) || hasLineBreakGlyphs(row.value);
  const canWrite = writable && !lossy;
  const [name, setName] = useState(showLineBreaks(row.name));
  const [value, setValue] = useState(showLineBreaks(row.value));
  const [refusal, setRefusal] = useState<string | null>(null);

  const refuse = (text: string) => {
    setRefusal(text);
    onAnnounce(text);
  };

  const apply = () => {
    if (!canWrite) return;
    const nextName = readLineBreaks(name);
    const nextValue = readLineBreaks(value);
    if ((hasLineBreak(nextName) || hasLineBreak(nextValue)) && crlfRefusal) {
      refuse(crlfRefusal);
      return;
    }
    onApply(nextName, nextValue);
  };

  const keys = (set: (next: string) => void) => (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    if (!event.shiftKey) {
      apply();
      return;
    }
    if (!canWrite) return;
    if (crlfRefusal) {
      refuse(crlfRefusal);
      return;
    }
    const field = event.currentTarget;
    const { text, caret } = insertAt(field.value, field.selectionStart ?? field.value.length, field.selectionEnd ?? field.value.length, CRLF_GLYPHS);
    set(text);
    setRefusal(null);
    // After React has written the new value, put the caret where typing would have left it.
    requestAnimationFrame(() => field.setSelectionRange(caret, caret));
  };

  return (
    <div className="inspector-section inspector-selection inspector-detail">
      <div className="inspector-head-row">
        <div className="inspector-head inspector-head-static">
          <span />
          <span>Detail</span>
        </div>
        <div className="inspector-head-extra">
          <IconButton label="Close the detail view" size="small" onClick={onClose}>
            <X size={12} />
          </IconButton>
        </div>
      </div>
      <div className="inspector-selection-body">
        <p className="inspector-selection-origin" title={`${sectionTitle} · ${row.name}`}>
          {sectionTitle} · {showLineBreaks(row.name)}
        </p>
        <label className="inspector-detail-field">
          <span>Name</span>
          <Input
            className="inspector-input"
            aria-label="Detail name"
            value={name}
            readOnly={!canWrite || !row.renamable}
            onChange={(event) => setName(event.target.value)}
            onKeyDown={keys(setName)}
          />
        </label>
        <label className="inspector-detail-field">
          <span>Value</span>
          <Input
            className="inspector-input"
            aria-label="Detail value"
            value={value}
            readOnly={!canWrite}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={keys(setValue)}
          />
        </label>
        {canWrite ? (
          <p className="inspector-note">Shift+Return inserts CR LF, shown as ␍␊. Return applies.</p>
        ) : null}
        {lossy ? (
          <p className="inspector-note">
            This item already contains the ␍ or ␊ character the detail view uses to show CR and LF, so it is shown here and not
            written back — edit it in the Raw view.
          </p>
        ) : null}
        {refusal ? (
          <p className="inspector-note inspector-refusal" role="status">
            {refusal}
          </p>
        ) : null}
        <div className="inspector-actions">
          <IconButton label="Copy name" size="small" onClick={() => void copyToClipboard(row.name).then(() => onAnnounce("Copied the name"))}>
            <Copy size={12} />
          </IconButton>
          <span style={{ flex: 1 }} />
          <Button variant="quiet" size="small" onClick={onClose}>
            {canWrite ? "Cancel" : "Close"}
          </Button>
          {canWrite ? (
            <Button size="small" onClick={apply}>
              Apply
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

/* ==== settings =============================================================== */

function SettingsPanel(): JSX.Element {
  const dock = useApp((state) => state.inspectorDock);
  const panelState = useApp((state) => state.inspectorPanelState);
  const setDock = useApp((state) => state.setInspectorDock);
  const setPanelState = useApp((state) => state.setInspectorPanelState);

  return (
    <div className="inspector-settings">
      <fieldset>
        <legend>Sections open by default</legend>
        <label>
          <input
            type="radio"
            name="inspector-panel-state"
            checked={panelState === "auto"}
            onChange={() => setPanelState("auto")}
          />
          <span>Auto-expand the ones with rows</span>
        </label>
        <label>
          <input
            type="radio"
            name="inspector-panel-state"
            checked={panelState === "collapsed"}
            onChange={() => setPanelState("collapsed")}
          />
          <span>Start collapsed</span>
        </label>
      </fieldset>
      <fieldset>
        <legend>Dock</legend>
        <label>
          <input type="radio" name="inspector-dock" checked={dock === "left"} onChange={() => setDock("left")} />
          <span>Left</span>
        </label>
        <label>
          <input type="radio" name="inspector-dock" checked={dock === "right"} onChange={() => setDock("right")} />
          <span>Right</span>
        </label>
      </fieldset>
    </div>
  );
}

/**
 * The sections of a kettled request (jae5): the attributes read from the field list, Request headers
 * editing the list itself (every pseudo-header included, as Burp's Inspector shows them), and the
 * parameter and cookie sections read-only with the reason — they are views of HTTP/1 text, which no
 * longer describes the request's headers.
 */
function kettledSections(
  list: SectionModel[],
  fields: H2Field[],
  kettle: InspectorKettle,
  editable: boolean,
  bodySize: string,
  announce: (text: string) => void,
  downgrade: () => void,
): SectionModel[] {
  const first = (name: string) => fields.find((field) => field.name.toLowerCase() === name)?.value;
  const parse = (state: string) => JSON.parse(state) as H2Field[];
  const write = (next: H2Field[]) => JSON.stringify(next);
  const commitFields = (apply: (state: string) => string, summary: string) => {
    const before = write(fields);
    const after = apply(before);
    if (after === before) {
      announce("No change");
      return;
    }
    kettle.onFields(parse(after));
    announce(summary);
  };
  const readOnly = "This request is kettled: its headers are an HTTP/2 field list now, edited under Request headers, and its body is edited in the request editor.";
  return list.map((section): SectionModel => {
    if (section.id === "attributes") {
      return {
        id: "attributes",
        title: "Request attributes",
        rows: [
          { name: "Method", value: first(":method") ?? "—", index: 0, renamable: false },
          { name: "Path", value: first(":path") ?? "—", index: 1, renamable: false },
          { name: "Version", value: "HTTP/2 (kettled)", index: 2, renamable: false },
          { name: "Authority", value: first(":authority") ?? "—", index: 3, renamable: false },
          { name: "Body", value: bodySize, index: 4, renamable: false },
        ],
        extra: editable ? (
          <Button variant="quiet" size="small" onClick={downgrade}>
            HTTP/1
          </Button>
        ) : undefined,
      };
    }
    if (section.id === "headers") {
      return {
        id: "headers",
        title: "Request headers",
        headerFields: true,
        rows: fields.map((field, index) => ({
          name: field.name,
          value: field.value,
          index,
          renamable: true,
          set: (state, name, value) => write(parse(state).map((entry, i) => (i === index ? { name, value } : entry))),
          remove: (state) => write(parse(state).filter((_, i) => i !== index)),
        })),
        add: (state, name, value) => write([...parse(state), { name, value }]),
        reorder: "header",
        move: (state, index, direction) => {
          const next = parse(state);
          const to = index + direction;
          if (to < 0 || to >= next.length) return state;
          [next[index], next[to]] = [next[to]!, next[index]!];
          return write(next);
        },
        commit: commitFields,
      };
    }
    return {
      ...section,
      rows: section.rows.map(({ set: _set, remove: _remove, ...row }) => row),
      add: undefined,
      reorder: undefined,
      note: readOnly,
    };
  });
}

/* ==== the Inspector ========================================================== */

/**
 * A kettled request's header list and where its edits go (jae5). `fields` is null while the request is
 * plain text; a header edit that HTTP/1 cannot carry then seeds the list from the text and hands it to
 * `onFields`. While it is non-null the Inspector's Request headers section edits the list itself, and
 * `onFields(null)` is the downgrade: the list is dropped and the text — kept as its normalised
 * rendering by the caller — is the request again.
 */
export interface InspectorKettle {
  /** Whether the target is TLS: Repeater speaks HTTP/2 only over TLS, so a plain-HTTP tab cannot kettle. */
  tls: boolean;
  fields: H2Field[] | null;
  onFields: (fields: H2Field[] | null) => void;
}

/**
 * Burp's Inspector: the same message broken into its addressable parts, so an
 * operator can read — and change — a cookie or a query parameter without counting
 * bytes in the raw view.
 *
 * Editing is offered only when `onChange` is given, and every write goes through
 * message.ts's splicing writers, so an edit here produces the same bytes as the
 * equivalent edit typed into the Raw view, Content-Length included. Where a
 * surface genuinely cannot be edited — a response that has already arrived, a
 * captured exchange from history — the caller passes `readOnlyNote` and the pane
 * SAYS SO rather than rendering fields that swallow keystrokes.
 */
export function Inspector({
  raw,
  label = "Inspector",
  onChange,
  readOnlyNote,
  onSwitch,
  switchLabel,
  kettle,
}: {
  raw: string;
  label?: string;
  onChange?: (next: string) => void;
  readOnlyNote?: string;
  /** Point the pane at the other half of the exchange, where the caller has one. */
  onSwitch?: () => void;
  switchLabel?: string;
  /**
   * Where an HTTP/2 header list that HTTP/1 text cannot carry can go (jae5) — given only by a mount that
   * can send one, which is a Repeater draft. Absent, a CR/LF in a header is refused with the reason.
   */
  kettle?: InspectorKettle;
}): JSX.Element {
  const parsed = useMemo(() => parseMessage(raw), [raw]);
  const response = useMemo(() => isResponse(raw), [raw]);
  const editable = Boolean(onChange);
  const kettled = kettle?.fields ?? null;
  const panelState = useApp((state) => state.inspectorPanelState);
  const dock = useApp((state) => state.inspectorDock);

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [detail, setDetail] = useState<DetailTarget | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const settingsRef = useRef<HTMLDivElement>(null);

  // Escape closes the settings popover, and a click outside it does too — a panel
  // that can only be dismissed by hitting the same small button again is a trap
  // for anyone driving this from the keyboard.
  useEffect(() => {
    if (!settingsOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSettingsOpen(false);
    };
    const onDown = (event: MouseEvent) => {
      if (!settingsRef.current?.contains(event.target as Node)) setSettingsOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
    };
  }, [settingsOpen]);

  const commit = (apply: (raw: string) => string, summary: string) => {
    if (!onChange) return;
    const next = apply(raw);
    if (next === raw) {
      setAnnouncement("No change");
      return;
    }
    onChange(next);
    setAnnouncement(summary);
  };

  const sections = useMemo<SectionModel[]>(() => {
    const request = response ? null : parseRequestLine(parsed.startLine);
    const status = response ? parseStatusLine(parsed.startLine) : null;
    const contentType = headerValue(parsed.headers, "content-type");
    const headers = headerSpans(raw);
    const hostIndex = headers.findIndex((header) => header.name.toLowerCase() === "host");
    const bodyBytes = new TextEncoder().encode(parsed.body).length;

    const attributes: Row[] = response
      ? [
          {
            name: "Version",
            value: status?.version ?? "—",
            index: 0,
            renamable: false,
            set: (current, _name, value) => setStartLineToken(current, 0, value),
          },
          {
            name: "Status",
            value: status ? String(status.status) : parsed.startLine,
            index: 1,
            renamable: false,
            set: (current, _name, value) => setStartLineToken(current, 1, value),
          },
          {
            name: "Reason",
            value: status?.reason ?? "",
            index: 2,
            renamable: false,
            // The reason phrase is the one start-line field allowed to contain spaces,
            // so it takes the rest of the line rather than a single token.
            set: (current, _name, value) => setStartLineTail(current, 2, value),
          },
          { name: "Content type", value: contentType ?? "—", index: 3, renamable: false },
          { name: "Body", value: formatBytes(bodyBytes), index: 4, renamable: false },
        ]
      : [
          {
            name: "Method",
            value: request?.method ?? "—",
            index: 0,
            renamable: false,
            set: (current, _name, value) => setStartLineToken(current, 0, value),
          },
          {
            name: "Target",
            value: request?.target ?? parsed.startLine,
            index: 1,
            renamable: false,
            set: (current, _name, value) => setStartLineToken(current, 1, value),
          },
          {
            name: "Version",
            value: request?.version ?? "—",
            index: 2,
            renamable: false,
            set: (current, _name, value) => setStartLineToken(current, 2, value),
          },
          {
            name: "Host",
            value: headerValue(parsed.headers, "host") ?? "—",
            index: 3,
            renamable: false,
            // Host is a header, so it writes as one. Absent from the message, there is
            // nothing to splice and the row reports "—" rather than inventing a header.
            set: hostIndex < 0 ? undefined : (current, _name, value) => setHeaderAt(current, hostIndex, "Host", value),
          },
          { name: "Body", value: formatBytes(bodyBytes), index: 4, renamable: false },
        ];

    const list: SectionModel[] = [
      {
        id: "attributes",
        title: response ? "Response attributes" : "Request attributes",
        rows: attributes,
        // Burp's HTTP/1 and HTTP/2 buttons: the version is the one attribute an
        // operator flips repeatedly, and two buttons beat retyping "HTTP/1.1".
        extra:
          response || !editable ? undefined : (
            <>
              <Button variant="quiet" size="small" onClick={() => commit((current) => setStartLineToken(current, 2, "HTTP/1.1"), "Version set to HTTP/1.1")}>
                HTTP/1
              </Button>
              <Button variant="quiet" size="small" onClick={() => commit((current) => setStartLineToken(current, 2, "HTTP/2"), "Version set to HTTP/2")}>
                HTTP/2
              </Button>
            </>
          ),
      },
    ];

    if (!response) {
      const query = querySpans(raw);
      list.push({
        id: "query",
        title: "Query parameters",
        rows: query.map((pair, index) => ({
          name: pair.name,
          value: pair.value,
          index,
          renamable: true,
          set: (current, name, value) => setQueryParamAt(current, index, name, value),
          remove: (current) => removeQueryParamAt(current, index),
        })),
        add: (current, name, value) => addQueryParam(current, name, value),
        reorder: "query",
      });
    }

    if (response) {
      // Each Set-Cookie is a whole header with attributes — Path, Expires, HttpOnly.
      // Writing back just the name=value pair would drop them, so this section reads
      // and the Headers section below is where a Set-Cookie is actually edited.
      list.push({
        id: "setcookie",
        title: "Set-Cookie",
        rows: cookiesOf(parsed.headers, true).map(([name, value], index) => ({ name, value, index, renamable: false })),
        note: "Editing a Set-Cookie means editing the whole header, attributes included — do it in Response headers below.",
      });
    } else {
      const cookies = cookieSpans(raw);
      list.push({
        id: "cookies",
        title: "Cookies",
        rows: cookies.map((cookie, index) => ({
          name: cookie.name,
          value: cookie.value,
          index,
          renamable: true,
          set: (current, name, value) => setCookieAt(current, index, name, value),
          remove: (current) => removeCookieAt(current, index),
        })),
        add: (current, name, value) => addCookie(current, name, value),
        reorder: "cookie",
      });
    }

    if (!response) {
      const params = bodyParamSpans(raw);
      const writable = bodyParamsEditable(raw);
      list.push({
        id: "body",
        title: "Body parameters",
        rows: params.map((param, index) => ({
          name: param.name,
          value: param.value,
          index,
          renamable: true,
          set: writable ? (current, name, value) => setBodyParamAt(current, index, name, value) : undefined,
          remove: writable ? (current) => removeBodyParamAt(current, index) : undefined,
        })),
        add: writable ? (current, name, value) => addBodyParam(current, name, value) : undefined,
        reorder: writable ? "body" : undefined,
        // Named rather than generic: an operator who sees "not editable" wants to know
        // which content type put them there.
        note: writable
          ? undefined
          : `Only urlencoded and JSON bodies break into parameters${contentType ? ` — this one is ${contentType}` : ""}. Edit it in the Raw view.`,
      });
    }

    list.push({
      id: "headers",
      title: response ? "Response headers" : "Request headers",
      rows: headers.map((header, index) => ({
        name: header.name,
        value: header.value,
        index,
        renamable: true,
        set: (current, name, value) => setHeaderAt(current, index, name, value),
        remove: (current) => removeHeaderAt(current, index),
      })),
      add: (current, name, value) => addHeader(current, name, value),
      // Header order is a smuggling and desync variable; this is the one place it can be changed
      // without retyping lines in Raw.
      reorder: "header",
      headerFields: !response,
    });

    if (!response && kettled && kettle) {
      return kettledSections(list, kettled, kettle, editable, formatBytes(bodyBytes), setAnnouncement, async () => {
        // Burp's downgrade warning: the HTTP/2-only edits are lost, and the request is normalised.
        const ok = await confirmDialog({
          title: "Downgrade this kettled request to HTTP/1?",
          description:
            "Burp calls this normalising: every change HTTP/1 cannot carry — CR/LF in a header, an uppercase name, extra pseudo-headers — is discarded.",
          confirmLabel: "Downgrade",
          danger: true,
        });
        if (!ok) return;
        kettle.onFields(null);
        commit((current) => setStartLineToken(current, 2, "HTTP/1.1"), "Downgraded to HTTP/1.1; the kettled edits were discarded");
      });
    }
    return list;
    // `commit` closes over `raw`, which is already a dependency; listing it would
    // rebuild every section on each render for no gain.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [parsed, response, raw, editable, kettled, kettle]);

  /** Explicit toggles win; otherwise the persisted default decides. */
  const [toggled, setToggled] = useState<Record<string, boolean>>({});
  const isOpen = (section: SectionModel) =>
    section.id in toggled ? toggled[section.id]! : panelState === "auto" && section.rows.length > 0;

  const detailSection = detail ? sections.find((entry) => entry.id === detail.sectionId) : undefined;
  const detailRow = detail ? detailSection?.rows[detail.rowIndex] : undefined;
  const http2 = !response && parseRequestLine(parsed.startLine)?.version === "HTTP/2";

  /**
   * Why a CR/LF cannot be written into an item of this section, or null when it can (ln2a). HTTP/1
   * text ends a header at its line break, so the only place one can live is an HTTP/2 header list
   * sent as written — a kettled request — and only a Repeater tab sends one.
   */
  const crlfRefusal = (section: SectionModel): string | null => {
    if (!section.headerFields) {
      return `Only a header can carry CR/LF; a ${section.title.toLowerCase()} item would split the message instead.`;
    }
    if (!http2) {
      return "This would split the header: only HTTP/2 can carry CR/LF inside a header. Switch the request to HTTP/2 under Request attributes first.";
    }
    if (!kettle) {
      return "This editor cannot send an HTTP/2 header list as written, so CR/LF in a header has nowhere to go here. Send the request to Repeater and inject it there.";
    }
    if (!kettle.tls) {
      return "This would split the header: only HTTP/2 can carry CR/LF inside a header, and Repeater speaks HTTP/2 only to an https:// target.";
    }
    return null;
  };

  /**
   * Apply a detail-view edit. A CR/LF reaching a header of a request that is still text is the moment it
   * kettles: the text is seeded into a field list with this one field changed, and the list takes over.
   */
  const applyDetail = (section: SectionModel, row: Row, name: string, value: string) => {
    const breaks = hasLineBreak(name) || hasLineBreak(value);
    // Burp's other name triggers, from the same view: renaming a header to something with an uppercase
    // letter or a colon in it, on an HTTP/2 request, is a name HTTP/2 text would lowercase or misread.
    const h2OnlyName = http2 && name !== row.name && /[A-Z:]/.test(name);
    if ((breaks || h2OnlyName) && !kettled && kettle && kettle.tls && section.headerFields && !section.commit) {
      kettle.onFields(kettleHeaderEdit(raw, kettle.tls, row.index, row.name, name, value));
      setAnnouncement(`${row.name} changed in a way HTTP/1 text cannot carry: the request is kettled and its headers are an HTTP/2 field list`);
      return;
    }
    (section.commit ?? commit)((current) => row.set!(current, name, value), `${section.title} · ${name} updated`);
  };

  const applySelection = (text: string) => {
    if (!selection) return;
    const section = sections.find((entry) => entry.id === selection.sectionId);
    const row = section?.rows[selection.rowIndex];
    if (!section || !row?.set) {
      setAnnouncement("That value cannot be written back");
      return;
    }
    (section.commit ?? commit)((current) => row.set!(current, row.name, text), `${section.title} · ${row.name} updated`);
    setSelection(null);
  };

  return (
    <div className={`inspector inspector-dock-${dock}`}>
      <div className="inspector-bar">
        <span className="editor-label-inline">{label}</span>
        <span style={{ flex: 1 }} />
        {onSwitch && switchLabel ? (
          <Button variant="quiet" size="small" onClick={onSwitch}>
            {switchLabel}
          </Button>
        ) : null}
        {/* Burp's Inspector "Expand all" / "Collapse all" (BurpClass9725, 9744; txnw). Explicit
            toggles for every section, so they win over the panel's Start-collapsed default the
            same way a click on one section does. */}
        <IconButton
          label="Expand all sections"
          size="small"
          onClick={() => setToggled(Object.fromEntries(sections.map((section) => [section.id, true])))}
        >
          <ChevronsUpDown size={13} />
        </IconButton>
        <IconButton
          label="Collapse all sections"
          size="small"
          onClick={() => setToggled(Object.fromEntries(sections.map((section) => [section.id, false])))}
        >
          <ChevronsDownUp size={13} />
        </IconButton>
        <div className="inspector-settings-anchor" ref={settingsRef}>
          <IconButton label="Inspector settings" size="small" aria-expanded={settingsOpen} onClick={() => setSettingsOpen((open) => !open)}>
            <Settings2 size={13} />
          </IconButton>
          {settingsOpen ? <SettingsPanel /> : null}
        </div>
      </div>
      <div className="inspector-body">
        {readOnlyNote && !editable ? <p className="inspector-note inspector-note-top">{readOnlyNote}</p> : null}
        {sections.map((section) => (
          <SectionBlock
            key={section.id}
            section={section}
            open={isOpen(section)}
            onToggle={() => setToggled((current) => ({ ...current, [section.id]: !isOpen(section) }))}
            editable={editable}
            onCommit={commit}
            onSelect={(sectionId, rowIndex, rowLabel, value) =>
              setSelection({ sectionId, rowIndex, label: rowLabel, original: value, stages: [] })
            }
            onDetail={(sectionId, rowIndex) => setDetail({ sectionId, rowIndex })}
            onAnnounce={setAnnouncement}
          />
        ))}
        {detailSection && detailRow ? (
          <DetailSection
            // Remounts per item, so the drafts start from the item opened rather than the last one.
            key={`${detail!.sectionId}-${detail!.rowIndex}-${detailRow.name}\u0000${detailRow.value}`}
            sectionTitle={detailSection.title}
            row={detailRow}
            writable={editable && !detailSection.note && Boolean(detailRow.set)}
            crlfRefusal={crlfRefusal(detailSection)}
            onApply={(name, value) => {
              applyDetail(detailSection, detailRow, name, value);
              setDetail(null);
            }}
            onClose={() => setDetail(null)}
            onAnnounce={setAnnouncement}
          />
        ) : null}
        {selection ? (
          <SelectionSection
            selection={selection}
            onChangeSelection={setSelection}
            onApply={applySelection}
            onClear={() => setSelection(null)}
            writable={editable}
          />
        ) : null}
      </div>
      {/* Every commit says what it did. An edit that silently changes bytes about to go
          over the wire is exactly the thing an operator needs confirmation of. */}
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>
    </div>
  );
}
