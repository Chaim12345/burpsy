import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import { bytesToMessage, messageBytes } from "../lib/message-views";
import { Button, Field, Input, Modal } from "./primitives";
import { ContextMenu, type MenuGroup } from "./menu";

/**
 * The editable Hex view.
 *
 * It replaces a read-only `hexDump` string, and the reason it had to stop being a
 * string is the one thing this view exists for: an operator opens Hex to craft
 * bytes no text editor will let them type — a header with a bare LF, a body one
 * byte shorter than its Content-Length, a NUL in the middle of a cookie. A dump
 * you cannot type into is a viewer, not an editor.
 *
 * Three deliberate refusals:
 *
 *  * Content-Length is never adjusted. Every other message editor in this console
 *    could reasonably offer to fix it; this one must not, because sending a wrong
 *    Content-Length on purpose is a request-smuggling test and silently correcting
 *    it would delete the test.
 *  * Nothing is re-encoded or normalised. The bytes committed are the bytes typed,
 *    checked by re-encoding and comparing rather than assumed.
 *  * An edit the transport cannot carry is refused out loud. The console moves
 *    messages as JSON strings and the Go side turns them back into bytes with
 *    []byte(s), so a byte sequence that is not valid UTF-8 has no representation
 *    anywhere in this pipeline — the Raw view cannot hold one either. Rather than
 *    write U+FFFD's three bytes and report success, the edit is held locally, the
 *    message is left alone, and the offset is named.
 */

/** Must match `.hex-row` in styles.css: the virtualiser and the CSS have to agree. */
const ROW_HEIGHT = 18;
const COLUMNS = 16;

function hex2(byte: number): string {
  return byte.toString(16).padStart(2, "0");
}

function printable(byte: number): string {
  return byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
}

function offsetLabel(offset: number): string {
  return offset.toString(16).padStart(8, "0");
}

const HEX_DIGITS = "0123456789abcdef";

export interface HexSelection {
  /** First byte, inclusive. */
  from: number;
  /** Last byte, exclusive. */
  to: number;
}

export function HexEditor({
  value,
  bytes: bytesProp,
  onChange,
  label,
  onRevealInRaw,
}: {
  value: string;
  /** The true wire bytes, when the caller has them (MessageView.body_base64, burpsy-react-ui-p836).
   *  `value` is a JSON string, and JSON replaced every byte >= 0x80 of a non-UTF-8 body with U+FFFD —
   *  encoding that string back shows EF BF BD triplets in the dump where the wire bytes belong. Given,
   *  the dump shows these bytes instead; absent, `value` is encoded as before (valid for every
   *  UTF-8-clean message, which was the only case before p836). */
  bytes?: Uint8Array;
  /** Absent means read-only — a captured response, a sequencer token. */
  onChange?: (value: string) => void;
  label: string;
  /** Hand a byte range to the Raw view. Absent when there is no Raw view to hand it to. */
  onRevealInRaw?: (selection: HexSelection) => void;
}): JSX.Element {
  const editable = Boolean(onChange);

  // An edit that cannot be carried is held here instead of being written to the
  // message. `value` is untouched while a draft exists, so the draft cannot drift:
  // the effect below drops it the moment the message changes under us, whether
  // that was our own commit or an edit on the Raw view.
  const [draft, setDraft] = useState<Uint8Array | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [caret, setCaret] = useState(0);
  const [anchor, setAnchor] = useState<number | null>(null);
  // Structured-insertion dialogs (burpsy-react-ui-297r): which prompt is open, and its draft.
  const [insertOpen, setInsertOpen] = useState<null | "bytes" | "string">(null);
  const [insertCount, setInsertCount] = useState("4");
  const [insertText, setInsertText] = useState("");
  const [column, setColumn] = useState<"hex" | "ascii">("hex");
  const [nibble, setNibble] = useState<0 | 1>(0);

  useEffect(() => {
    setDraft(null);
    setRefusal(null);
  }, [value]);

  const encoded = useMemo(() => bytesProp ?? messageBytes(value), [bytesProp, value]);
  const bytes = draft ?? encoded;
  const length = bytes.length;

  // Caret and anchor are clamped on read rather than corrected in state: a delete
  // that shortens the buffer would otherwise leave a caret past the end for one
  // render, which is exactly long enough to index undefined.
  const caretAt = Math.min(Math.max(caret, 0), length);
  const anchorAt = anchor === null ? null : Math.min(Math.max(anchor, 0), Math.max(0, length - 1));
  const selection: HexSelection | null =
    anchorAt === null
      ? null
      : { from: Math.min(anchorAt, caretAt), to: Math.min(length, Math.max(anchorAt, caretAt) + 1) };

  const rowCount = Math.ceil(length / COLUMNS);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const tableRef = useRef<HTMLTableElement | null>(null);
  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });
  const virtualRows = virtualizer.getVirtualItems();
  const totalSize = virtualizer.getTotalSize();
  const paddingTop = virtualRows.length ? (virtualRows[0]?.start ?? 0) : 0;
  const paddingBottom = virtualRows.length ? totalSize - (virtualRows.at(-1)?.end ?? 0) : 0;

  // Keep the caret on screen when it moves by keyboard.
  useEffect(() => {
    if (rowCount === 0) return;
    virtualizer.scrollToIndex(Math.min(rowCount - 1, Math.floor(caretAt / COLUMNS)), { align: "auto" });
    // virtualizer identity is stable for a given scroll element; depending on it loops.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caretAt, rowCount]);

  /**
   * Write a new byte array back to the message.
   *
   * The exactness check is a measurement, not a claim: the candidate string is
   * re-encoded and compared with the bytes that were asked for. Only an identical
   * result reaches `onChange`.
   */
  function commit(next: Uint8Array): void {
    if (!onChange) return;
    const { text, exact, badOffset } = bytesToMessage(next);
    if (exact) {
      setDraft(null);
      setRefusal(null);
      onChange(text);
      return;
    }
    const bad = badOffset >= 0 && badOffset < next.length ? next[badOffset]! : undefined;
    setDraft(next);
    setRefusal(
      bad === undefined
        ? "Those bytes are not valid UTF-8, and the console carries messages as text — the message was left unchanged."
        : `0x${hex2(bad)} at offset ${badOffset} (0x${offsetLabel(badOffset)}) is not valid UTF-8 here. ` +
            "The console carries messages as text, so this byte cannot be sent by any view — the message was left " +
            "unchanged and the edit is shown below only so you can see it. Finish the sequence (a lead byte needs " +
            "its continuation bytes) and it will be written.",
    );
  }

  function moveCaret(to: number, extend: boolean): void {
    const clamped = Math.min(Math.max(to, 0), Math.max(0, length === 0 ? 0 : length - 1));
    if (extend) {
      if (anchor === null) setAnchor(caretAt);
    } else {
      setAnchor(null);
    }
    setCaret(clamped);
    setNibble(0);
  }

  function writeByte(offset: number, byte: number): Uint8Array {
    const next = new Uint8Array(Math.max(bytes.length, offset + 1));
    next.set(bytes);
    next[offset] = byte;
    return next;
  }

  function deleteRange(from: number, to: number): void {
    if (from >= to || from < 0) return;
    const next = new Uint8Array(bytes.length - (to - from));
    next.set(bytes.subarray(0, from), 0);
    next.set(bytes.subarray(to), from);
    setAnchor(null);
    setCaret(from);
    setNibble(0);
    commit(next);
  }

  /**
   * Splice bytes in at the caret (burpsy-react-ui-297r). `insertByte` is this with one
   * zero byte; the count and string menu entries are this with N zeroes and with a
   * UTF-8 encoding. All three commit through the same exactness check, so an insertion
   * the transport cannot carry is refused the same loud way as a typed one.
   */
  function insertBytes(data: Uint8Array): void {
    const at = Math.min(caretAt, length);
    const next = new Uint8Array(bytes.length + data.length);
    next.set(bytes.subarray(0, at), 0);
    next.set(data, at);
    next.set(bytes.subarray(at), at + data.length);
    setAnchor(null);
    setCaret(at);
    setNibble(0);
    commit(next);
  }

  function insertByte(): void {
    insertBytes(new Uint8Array([0]));
  }

  function typeHexDigit(digit: number): void {
    const at = caretAt;
    const existing = at < length ? bytes[at]! : 0;
    if (nibble === 0) {
      commit(writeByte(at, (digit << 4) | (existing & 0x0f)));
      setNibble(1);
      // Typing past the end appends, so the caret must be able to sit on the new byte.
      if (at >= length) setCaret(at);
    } else {
      commit(writeByte(at, (existing & 0xf0) | digit));
      setNibble(0);
      setCaret(at + 1);
    }
    setAnchor(null);
  }

  function typeAsciiChar(character: string): void {
    const code = character.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) {
      setRefusal(
        `The ASCII column writes one byte per character, so it only accepts 0x20–0x7E. "${character}" is not one ` +
          "byte — use the hex column, where every byte value can be typed.",
      );
      return;
    }
    commit(writeByte(caretAt, code));
    setAnchor(null);
    setCaret(caretAt + 1);
    setNibble(0);
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLTableElement>): void {
    const perPage = COLUMNS * 16;
    switch (event.key) {
      case "ArrowLeft":
        event.preventDefault();
        moveCaret(caretAt - 1, event.shiftKey);
        return;
      case "ArrowRight":
        event.preventDefault();
        moveCaret(caretAt + 1, event.shiftKey);
        return;
      case "ArrowUp":
        event.preventDefault();
        moveCaret(caretAt - COLUMNS, event.shiftKey);
        return;
      case "ArrowDown":
        event.preventDefault();
        moveCaret(caretAt + COLUMNS, event.shiftKey);
        return;
      case "Home":
        event.preventDefault();
        moveCaret(event.ctrlKey || event.metaKey ? 0 : caretAt - (caretAt % COLUMNS), event.shiftKey);
        return;
      case "End":
        event.preventDefault();
        moveCaret(
          event.ctrlKey || event.metaKey ? length - 1 : caretAt - (caretAt % COLUMNS) + COLUMNS - 1,
          event.shiftKey,
        );
        return;
      case "PageUp":
        event.preventDefault();
        moveCaret(caretAt - perPage, event.shiftKey);
        return;
      case "PageDown":
        event.preventDefault();
        moveCaret(caretAt + perPage, event.shiftKey);
        return;
      case "Tab":
        // Tab keeps its job of leaving the grid. The hex and ASCII columns are
        // switched with the keys below, and by clicking.
        return;
      default:
        break;
    }

    if (!editable) return;

    if (event.key === "Backspace") {
      event.preventDefault();
      if (selection) deleteRange(selection.from, selection.to);
      else if (caretAt > 0) deleteRange(caretAt - 1, caretAt);
      return;
    }
    if (event.key === "Delete") {
      event.preventDefault();
      if (selection) deleteRange(selection.from, selection.to);
      else if (caretAt < length) deleteRange(caretAt, caretAt + 1);
      return;
    }
    if (event.key === "Insert") {
      event.preventDefault();
      insertByte();
      return;
    }
    // Modified keys belong to the browser and to the editor's own hotkeys.
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key.length !== 1) return;

    if (column === "hex") {
      const digit = HEX_DIGITS.indexOf(event.key.toLowerCase());
      if (digit < 0) return;
      event.preventDefault();
      typeHexDigit(digit);
      return;
    }
    event.preventDefault();
    typeAsciiChar(event.key);
  }

  /**
   * One delegated click handler rather than 32 per row. A hex pane can hold tens of
   * thousands of cells and a closure on each is the difference between a view that
   * scrolls and one that hitches.
   */
  function onCellMouseDown(event: ReactMouseEvent<HTMLTableElement>): void {
    const target = (event.target as HTMLElement).closest<HTMLElement>("[data-offset]");
    if (!target) return;
    const offset = Number(target.dataset["offset"]);
    if (!Number.isInteger(offset)) return;
    event.preventDefault();
    tableRef.current?.focus();
    setColumn(target.dataset["col"] === "ascii" ? "ascii" : "hex");
    moveCaret(offset, event.shiftKey);
  }

  const caretByte = caretAt < length ? bytes[caretAt] : undefined;
  const status =
    length === 0
      ? "0 bytes."
      : `Offset ${offsetLabel(caretAt)} (${caretAt})` +
        (caretByte === undefined
          ? " — past the last byte"
          : ` · 0x${hex2(caretByte)} · ${caretByte} · "${printable(caretByte)}"`) +
        (selection
          ? ` · selected ${selection.to - selection.from} bytes, ${offsetLabel(selection.from)}–${offsetLabel(selection.to - 1)}`
          : "") +
        ` · ${column === "hex" ? "hex" : "ASCII"} column` +
        (editable && column === "hex" && nibble === 1 ? ", low nibble next" : "");

  const selectedCount = selection ? selection.to - selection.from : 0;
  const menuGroups: MenuGroup[] = editable
    ? [
        {
          id: "hex-insert",
          actions: [
            { id: "insert-byte", label: "Insert byte", onSelect: insertByte },
            { id: "insert-bytes", label: "Insert bytes…", onSelect: () => setInsertOpen("bytes") },
            { id: "insert-string", label: "Insert string…", onSelect: () => setInsertOpen("string") },
          ],
        },
        {
          id: "hex-delete",
          actions: [
            {
              id: "delete-selection",
              label: selectedCount > 1 ? `Delete ${selectedCount} selected bytes` : "Delete selected byte",
              danger: true,
              disabled: !selection,
              onSelect: () => {
                if (selection) deleteRange(selection.from, selection.to);
              },
            },
          ],
        },
      ]
    : [];

  const insertCountValid = /^\d+$/.test(insertCount.trim()) && Number(insertCount) >= 1 && Number(insertCount) <= 65535;

  return (
    <div className="hex-view">
      <div className="hex-toolbar">
        {editable ? (
          <Button variant="outline" size="small" onClick={insertByte} disabled={!editable}>
            Insert 00
          </Button>
        ) : null}
        {editable ? (
          <Button
            variant="outline"
            size="small"
            disabled={!selection}
            onClick={() => {
              if (selection) deleteRange(selection.from, selection.to);
            }}
          >
            Delete selection
          </Button>
        ) : null}
        {onRevealInRaw ? (
          <Button
            variant="outline"
            size="small"
            disabled={!selection}
            onClick={() => {
              if (selection) onRevealInRaw(selection);
            }}
          >
            Show in Raw
          </Button>
        ) : null}
        <span className="hex-count">
          {length} {length === 1 ? "byte" : "bytes"}
        </span>
      </div>

      <ContextMenu groups={menuGroups} docTopic="message-editor">
      <div className="hex-scroll" ref={scrollRef}>
        <table
          className="hex-table"
          ref={tableRef}
          tabIndex={0}
          aria-label={`${label} hex${editable ? " editor" : ", read-only"}`}
          onKeyDown={onKeyDown}
          onMouseDown={onCellMouseDown}
        >
          <thead>
            <tr>
              <th scope="col" className="hex-offset">
                offset
              </th>
              <th scope="col" className="hex-bytes">
                {Array.from({ length: COLUMNS }, (_unused, index) => (
                  <span key={index} className="hex-ruler">
                    {hex2(index)}
                  </span>
                ))}
              </th>
              <th scope="col" className="hex-ascii">
                ascii
              </th>
            </tr>
          </thead>
          <tbody>
            {paddingTop > 0 ? (
              <tr aria-hidden="true" style={{ height: paddingTop }}>
                <td colSpan={3} />
              </tr>
            ) : null}
            {virtualRows.map((virtual) => {
              const base = virtual.index * COLUMNS;
              const cells = Array.from({ length: COLUMNS }, (_unused, index) => base + index).filter(
                (offset) => offset < length,
              );
              return (
                <tr key={virtual.index} style={{ height: ROW_HEIGHT }}>
                  <th scope="row" className="hex-offset">
                    {offsetLabel(base)}
                  </th>
                  <td className="hex-bytes">
                    {cells.map((offset) => (
                      <span
                        key={offset}
                        data-offset={offset}
                        data-col="hex"
                        className={cellClass(offset, caretAt, column === "hex", selection, nibble, editable)}
                      >
                        {hex2(bytes[offset]!)}
                      </span>
                    ))}
                  </td>
                  <td className="hex-ascii">
                    {cells.map((offset) => (
                      <span
                        key={offset}
                        data-offset={offset}
                        data-col="ascii"
                        className={cellClass(offset, caretAt, column === "ascii", selection, 0, editable)}
                      >
                        {printable(bytes[offset]!)}
                      </span>
                    ))}
                  </td>
                </tr>
              );
            })}
            {paddingBottom > 0 ? (
              <tr aria-hidden="true" style={{ height: paddingBottom }}>
                <td colSpan={3} />
              </tr>
            ) : null}
            {rowCount === 0 ? (
              <tr style={{ height: ROW_HEIGHT }}>
                <td colSpan={3} className="hex-empty">
                  no bytes{editable ? " — press Insert, or use Insert 00 above, to start one" : ""}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      </ContextMenu>

      <Modal
        open={insertOpen === "bytes"}
        onOpenChange={(open) => {
          if (!open) setInsertOpen(null);
        }}
        title="Insert bytes"
        description="Zero bytes at the caret. The same commit path as typing, so unrepresentable results are refused, not written."
      >
        <div className="stack">
          <Field label="How many bytes (1-65535)">
            {(id) => (
              <Input
                id={id}
                inputMode="numeric"
                value={insertCount}
                onChange={(event) => setInsertCount(event.target.value)}
              />
            )}
          </Field>
          <div className="toolbar-end">
            <Button variant="outline" size="small" onClick={() => setInsertOpen(null)}>
              Cancel
            </Button>
            <Button
              size="small"
              disabled={!insertCountValid}
              onClick={() => {
                insertBytes(new Uint8Array(Number(insertCount)));
                setInsertOpen(null);
              }}
            >
              Insert
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        open={insertOpen === "string"}
        onOpenChange={(open) => {
          if (!open) setInsertOpen(null);
        }}
        title="Insert string"
        description="The text as UTF-8 bytes at the caret."
      >
        <div className="stack">
          <Field label="Text to insert">
            {(id) => <Input id={id} value={insertText} onChange={(event) => setInsertText(event.target.value)} />}
          </Field>
          <div className="toolbar-end">
            <Button variant="outline" size="small" onClick={() => setInsertOpen(null)}>
              Cancel
            </Button>
            <Button
              size="small"
              disabled={!insertText}
              onClick={() => {
                insertBytes(new TextEncoder().encode(insertText));
                setInsertText("");
                setInsertOpen(null);
              }}
            >
              Insert
            </Button>
          </div>
        </div>
      </Modal>

      {/* One region for position and for refusals, so a screen reader hears the caret
          move and hears why an edit did not land, without two competing live regions. */}
      <div className="hex-status" role="status" aria-live="polite">
        {refusal ? <span className="hex-refusal">{refusal}</span> : <span>{status}</span>}
      </div>
    </div>
  );
}

function cellClass(
  offset: number,
  caret: number,
  columnActive: boolean,
  selection: HexSelection | null,
  nibble: 0 | 1,
  editable: boolean,
): string {
  const classes = ["hex-cell"];
  if (selection && offset >= selection.from && offset < selection.to) classes.push("hex-cell-selected");
  if (offset === caret) {
    classes.push("hex-cell-caret");
    if (columnActive) classes.push("hex-cell-caret-active");
    if (editable && columnActive && nibble === 1) classes.push("hex-cell-low-nibble");
  }
  return classes.join(" ");
}
