import { ChevronDown, ChevronRight, ChevronsDownUp, ChevronsUpDown, Copy, Plus, Settings2, Trash2, Wand2, X } from "lucide-react";
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
} from "../lib/message";
import { base64Decode, base64Encode, htmlDecode, htmlEncodeKeyChars, urlDecode, urlEncodeKeyChars } from "../lib/transforms";
import { useApp } from "../lib/store";
import { Badge, Button, IconButton, Input } from "./primitives";

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
  onCommit,
  onSelect,
}: {
  section: SectionModel;
  open: boolean;
  onToggle: () => void;
  editable: boolean;
  onCommit: (apply: (raw: string) => string, summary: string) => void;
  onSelect: (sectionId: string, rowIndex: number, label: string, value: string) => void;
}): JSX.Element {
  /** Edits buffered until Apply. Keyed by the row's position in the rendered list. */
  const [drafts, setDrafts] = useState<Record<number, Draft>>({});
  const [removing, setRemoving] = useState<number[]>([]);
  const [adding, setAdding] = useState<Draft | null>(null);

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

  const canEdit = editable && !section.note;

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
                const rowEditable = canEdit && Boolean(row.set);
                return (
                  <div key={`${row.name}-${index}`} className={gone ? "inspector-row-removed" : undefined}>
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
                        row.name
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
                            {row.value === "" ? <span className="cell-dim">(empty)</span> : row.value}
                          </button>
                        )}
                        <IconButton
                          label={`Decode ${row.name}`}
                          size="small"
                          className="inspector-row-action"
                          onClick={() => onSelect(section.id, index, `${section.title} · ${row.name}`, draft.value)}
                        >
                          <Wand2 size={12} />
                        </IconButton>
                        {rowEditable ? (
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

/* ==== the Inspector ========================================================== */

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
}: {
  raw: string;
  label?: string;
  onChange?: (next: string) => void;
  readOnlyNote?: string;
  /** Point the pane at the other half of the exchange, where the caller has one. */
  onSwitch?: () => void;
  switchLabel?: string;
}): JSX.Element {
  const parsed = useMemo(() => parseMessage(raw), [raw]);
  const response = useMemo(() => isResponse(raw), [raw]);
  const editable = Boolean(onChange);
  const panelState = useApp((state) => state.inspectorPanelState);
  const dock = useApp((state) => state.inspectorDock);

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selection, setSelection] = useState<Selection | null>(null);
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
    });

    return list;
    // `commit` closes over `raw`, which is already a dependency; listing it would
    // rebuild every section on each render for no gain.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [parsed, response, raw, editable]);

  /** Explicit toggles win; otherwise the persisted default decides. */
  const [toggled, setToggled] = useState<Record<string, boolean>>({});
  const isOpen = (section: SectionModel) =>
    section.id in toggled ? toggled[section.id]! : panelState === "auto" && section.rows.length > 0;

  const applySelection = (text: string) => {
    if (!selection) return;
    const section = sections.find((entry) => entry.id === selection.sectionId);
    const row = section?.rows[selection.rowIndex];
    if (!section || !row?.set) {
      setAnnouncement("That value cannot be written back");
      return;
    }
    commit((current) => row.set!(current, row.name, text), `${section.title} · ${row.name} updated`);
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
          />
        ))}
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
