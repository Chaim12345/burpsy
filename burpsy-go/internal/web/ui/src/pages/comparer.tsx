import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftRight, Braces, ChevronLeft, ChevronRight, Download, GitCompare, Hash, Network, Type , Trash2 } from "lucide-react";
import { toast } from "sonner";
import { formatBytes } from "../lib/api";
import { useCompare, useLoadMessage } from "../lib/data.workbench";
import { useCrawls } from "../lib/data.observe";
import { useCompareSitemaps } from "../lib/data.observe";
import { comparableRuns, sideLabel, type SitemapDiffResponse } from "../lib/sitemap-diff";
import { useApp , newComparerItem } from "../lib/store";
import type { CompareOp } from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { PageHeader, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, IconButton, Input, Metric, Select, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/** Ops carry byte offsets, so slicing has to go through the same byte view the server used. */
function byteSlice(text: string, offset: number, length: number): string {
  const bytes = new TextEncoder().encode(text);
  return new TextDecoder().decode(bytes.slice(offset, offset + length));
}

/** Aligned run drawn in both panes. `hunk` is null for unchanged text. */
interface Segment {
  key: string;
  kind: string;
  hunk: number | null;
  mark: string;
  a: string;
  b: string;
  /** Carried through from the op so the pane can dim a discounted header difference. */
  uninteresting?: boolean;
}

/**
 * Filler drawn opposite an insertion or deletion. Padding to the other side's
 * length is what keeps the two panes aligned rather than drifting apart.
 */
const GAP_CHAR = "·";

/** A hand-off's provenance label when the sender did not name one: the message's first
 * line — the request line or status line — which is exactly what an operator scanning two
 * item tables reads to tell one candidate from another (yy2). */
function labelOf(value: string): string {
 const first = value.split(/\r?\n/, 1)[0] ?? "";
 return first.length > 72 ? `${first.slice(0, 69)}...` : first || "(no content)";
}

/** Ops drawn before the view stops. A pathological diff must not hang the tab. */
const MAX_SEGMENTS = 2_000;

function buildSegments(ops: CompareOp[], aText: string, bText: string): { segments: Segment[]; hunks: number; omitted: number } {
  const segments: Segment[] = [];
  let hunks = 0;
  const drawn = ops.slice(0, MAX_SEGMENTS);
  for (const [index, op] of drawn.entries()) {
    const key = `${index}-${op.kind}`;
    if (op.kind === "equal") {
      const text = byteSlice(aText, op.a_offset, op.a_len);
      segments.push({ key, kind: "equal", hunk: null, mark: "", a: text, b: text });
      continue;
    }
    const hunk = hunks++;
    if (op.kind === "insert") {
      const text = op.text ?? byteSlice(bText, op.b_offset, op.b_len);
      segments.push({ key, kind: "insert", hunk, mark: "+", a: GAP_CHAR.repeat([...text].length), b: text, uninteresting: op.uninteresting });
      continue;
    }
    if (op.kind === "delete") {
      const text = op.text ?? byteSlice(aText, op.a_offset, op.a_len);
      segments.push({ key, kind: "delete", hunk, mark: "−", a: text, b: GAP_CHAR.repeat([...text].length), uninteresting: op.uninteresting });
      continue;
    }
    // "replace": both sides carry bytes; the shorter one is padded so the panes stay level.
    const left = op.text ?? byteSlice(aText, op.a_offset, op.a_len);
    const right = byteSlice(bText, op.b_offset, op.b_len);
    const width = Math.max([...left].length, [...right].length);
    segments.push({
      key,
      kind: "replace",
      hunk,
      mark: "~",
      a: left + GAP_CHAR.repeat(width - [...left].length),
      b: right + GAP_CHAR.repeat(width - [...right].length),
      uninteresting: op.uninteresting,
    });
  }
  return { segments, hunks, omitted: ops.length - drawn.length };
}

function Pane({
  label,
  side,
  segments,
  currentHunk,
}: {
  label: string;
  side: "a" | "b";
  segments: Segment[];
  currentHunk: number;
}): JSX.Element {
  return (
    <div className="diff-pane">
      <div className="editor-bar">
        <span className="editor-label-inline">{label}</span>
      </div>
      <div className="diff-pane-body">
        {segments.map((segment) => {
          const text = side === "a" ? segment.a : segment.b;
          if (segment.kind === "equal") return <span key={segment.key}>{text}</span>;
          return (
            <span
              key={segment.key}
              data-hunk={segment.hunk}
              className={`diff-${segment.kind}${segment.hunk === currentHunk ? " diff-hunk-current" : ""}${segment.uninteresting ? " diff-uninteresting" : ""}`}
              title={`${segment.kind} at byte ${side === "a" ? "A" : "B"} offset`}
            >
              <span className="diff-mark">{segment.mark}</span>
              {text}
            </span>
          );
        })}
      </div>
    </div>
  );
}

const HEX_COLS = 16;

/**
 * Cap on the hex dump per side, mirroring Decoder's MAX_HEX_BYTES/hexDump (pages/decoder.tsx):
 * a hex row costs roughly five times its bytes in markup, so an inflated response that renders
 * fine as text would stall the tab as hex. Not shared code — the two pages don't share a hex
 * module — but the same value and the same reasoning, since the trade-off is identical.
 */
export const MAX_HEX_BYTES = 8192;

/** A run of consecutive same-kind/same-hunk bytes within one hex row — the hex view's analogue
 *  of a Segment, sized down to what fits in 16 columns. */
export interface HexGroup {
  key: string;
  kind: string;
  hunk: number | null;
  uninteresting?: boolean;
  hex: string;
  ascii: string;
}

export interface HexRow {
  offset: number;
  groups: HexGroup[];
  /** Missing columns on a short final row, so the ascii column still lines up under it. */
  padCells: number;
}

/**
 * One side's byte-tagged hex grid, built straight from the diff ops and the side's own encoded
 * bytes — not from the GAP_CHAR-padded Segment strings buildSegments produces for the text pane.
 * GAP_CHAR is itself a real character that can appear in the data (see buildSegments' comment),
 * so reusing the padded text here would draw a padding glyph indistinguishable from an actual
 * byte in the one view whose job is to tell that difference apart. The trade-off: unlike the
 * text pane, the two sides are not padded to the same row count, so a hunk can land at different
 * row offsets in A and B. Hunk numbering matches buildSegments' exactly (one increment per
 * non-equal op, same op order), so highlighting a hunk and jumping to it via data-hunk still
 * lines the two panes up on the region that matters, even when the rows around it do not match.
 */
export function buildHexRows(ops: CompareOp[], sideBytes: Uint8Array, side: "a" | "b"): { rows: HexRow[]; shown: number; total: number } {
  const drawn = ops.slice(0, MAX_SEGMENTS);
  let hunks = 0;
  let shown = 0;
  let total = 0;
  const rows: HexRow[] = [];
  let row: { kind: string; hunk: number | null; uninteresting?: boolean; hex: string[]; ascii: string[] }[] = [];
  let rowLen = 0;
  let offset = 0;

  const flushRow = () => {
    rows.push({
      offset,
      groups: row.map((g, index) => ({
        key: `${offset}-${index}`,
        kind: g.kind,
        hunk: g.hunk,
        uninteresting: g.uninteresting,
        hex: g.hex.join(" "),
        ascii: g.ascii.join(""),
      })),
      padCells: HEX_COLS - rowLen,
    });
    offset += HEX_COLS;
    row = [];
    rowLen = 0;
  };

  for (const op of drawn) {
    const hunk = op.kind === "equal" ? null : hunks++;
    const opOffset = side === "a" ? op.a_offset : op.b_offset;
    const opLen = side === "a" ? op.a_len : op.b_len;
    total += opLen;
    for (let i = 0; i < opLen; i++) {
      if (shown >= MAX_HEX_BYTES) continue;
      const byte = sideBytes[opOffset + i]!;
      const hexByte = byte.toString(16).padStart(2, "0");
      const asciiByte = byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
      const last = row[row.length - 1];
      if (last && last.kind === op.kind && last.hunk === hunk && last.uninteresting === op.uninteresting) {
        last.hex.push(hexByte);
        last.ascii.push(asciiByte);
      } else {
        row.push({ kind: op.kind, hunk, uninteresting: op.uninteresting, hex: [hexByte], ascii: [asciiByte] });
      }
      shown++;
      rowLen++;
      if (rowLen === HEX_COLS) flushRow();
    }
  }
  if (rowLen > 0) flushRow();
  return { rows, shown, total };
}

function hexGroupClass(group: HexGroup, currentHunk: number): string {
  return `diff-${group.kind}${group.hunk === currentHunk ? " diff-hunk-current" : ""}${group.uninteresting ? " diff-uninteresting" : ""}`;
}

function HexPane({
  label,
  hexView,
  currentHunk,
}: {
  label: string;
  hexView: { rows: HexRow[]; shown: number; total: number };
  currentHunk: number;
}): JSX.Element {
  return (
    <div className="diff-pane">
      <div className="editor-bar">
        <span className="editor-label-inline">{label}</span>
      </div>
      <div className="diff-pane-body">
        {hexView.rows.length === 0 ? (
          <div>(0 bytes)</div>
        ) : (
          hexView.rows.map((row) => (
            <div key={row.offset}>
              <span className="cell-dim">{row.offset.toString(16).padStart(8, "0")}</span>
              {"  "}
              {row.groups.map((group) =>
                group.kind === "equal" ? (
                  <span key={group.key}>{group.hex} </span>
                ) : (
                  <span key={group.key} data-hunk={group.hunk} className={hexGroupClass(group, currentHunk)}>
                    {group.hex}{" "}
                  </span>
                ),
              )}
              {"   ".repeat(row.padCells)}
              {"  |"}
              {row.groups.map((group) =>
                group.kind === "equal" ? (
                  <span key={`${group.key}-a`}>{group.ascii}</span>
                ) : (
                  <span key={`${group.key}-a`} className={hexGroupClass(group, currentHunk)}>
                    {group.ascii}
                  </span>
                ),
              )}
              <span>|</span>
            </div>
          ))
        )}
        {hexView.total > hexView.shown ? (
          <div className="cell-dim">
            … {hexView.total - hexView.shown} more byte(s) not dumped; switch back to text for the whole output
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function ComparerPage(): JSX.Element {
  const slots = useApp((state) => state.comparerSlots);
  const setComparerSlot = useApp((state) => state.setComparerSlot);
  // Burp's item tables (burpsy-react-ui-yy2): each side is a LIST of what was sent, the
  // comparison runs on the selected item from each, and send-to appends instead of destroying.
  const items = useApp((state) => state.comparerItems);
  const addComparerItem = useApp((state) => state.addComparerItem);
  const removeComparerItem = useApp((state) => state.removeComparerItem);
  const clearComparerItems = useApp((state) => state.clearComparerItems);
  const [selectedA, setSelectedA] = useState<number | null>(null);
  const [selectedB, setSelectedB] = useState<number | null>(null);

  // Burp's two Comparer subjects: two buffers (the page this file was before k3a7), and two
  // site maps (burpsy-react-ui-k3a7). One page, because Burp also offers them from one tool —
  // "Send to Comparer" on a message and "Compare site maps" on two crawls land in the same place.
  const [mode, setMode] = useState<"buffers" | "sitemaps">("buffers");

  // --- the site-maps half -------------------------------------------------
  const crawls = useCrawls();
  const compareSitemaps = useCompareSitemaps();
  const finished = comparableRuns(crawls.data?.crawls);
  const [taskA, setTaskA] = useState<number | null>(null);
  const [taskB, setTaskB] = useState<number | null>(null);
  // Auto-picked once, when the list first answers: the two most recent finished runs — the two
  // crawls an operator just ran are the pair they meant, and making them re-select ids the
  // dashboard already showed them is a round trip that serves nothing.
  useEffect(() => {
    if (taskA !== null || finished.length < 2) return;
    const [first, second] = finished;
    if (!first || !second) return;
    setTaskA(first.task_id);
    setTaskB(second.task_id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished.length > 0]);

  const runSitemapDiff = () => {
    if (taskA === null || taskB === null) return;
    compareSitemaps.mutate(
      { taskA, taskB },
      {
        onSuccess: (r) =>
          r.only_a + r.only_b === 0
            ? toast.success(`The two runs reached the same ${r.both} path(s)`)
            : toast.success(`${r.only_a} path(s) only in run ${r.task_a}, ${r.only_b} only in run ${r.task_b}`),
        onError: (cause) => toast.error(`Site-map comparison failed: ${cause.message}`),
      },
    );
  };
  const sitemapResult = compareSitemaps.data;

  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [msgA, setMsgA] = useState("");
  const [msgB, setMsgB] = useState("");
  const [currentHunk, setCurrentHunk] = useState(-1);
  /**
   * Which uninteresting-header list to apply (W6 #81/#82). Defaults to the response list because
   * comparing two responses is what the Comparer is overwhelmingly used for, and because the
   * response list is the one with defaults — leaving this at "request" would apply an empty list and
   * make the whole setting look inert on the surface it exists to serve.
   */
  const [side, setSide] = useState<"response" | "request">("response");
  const [view, setView] = useState<"text" | "hex">("text");
  /**
   * Burp's two compare modes. Bytes is the default because that is what this page did before the
   * modes existed, so an operator who never touches the control gets the same answer as yesterday —
   * and the result always says which mode produced it, so the control cannot be mistaken for a
   * label.
   */
  const [granularity, setGranularity] = useState<"bytes" | "words">("bytes");
  const paneRef = useRef<HTMLDivElement>(null);

  const compare = useCompare();
  const loadMessage = useLoadMessage();
  const result = compare.data;

  // "Send to Comparer (A/B)" elsewhere in the app writes the raw bytes into the
  // store; consume them so a second hand-off of the same text still lands.
  // The hand-off still lands as a pending slot; the page consumes it into the LIST (yy2), so
  // the third send-to a side adds a row instead of destroying what was there. The label names
  // the provenance because the item tables' visible column is "which exchange is this".
  useEffect(() => {
    if (!slots.a) return;
    const item = newComparerItem(labelOf(slots.a), slots.a);
    addComparerItem("a", item);
    setSelectedA(item.id);
    setComparerSlot("a", "");
  }, [slots.a, setComparerSlot, addComparerItem]);

  useEffect(() => {
    if (!slots.b) return;
    const item = newComparerItem(labelOf(slots.b), slots.b);
    addComparerItem("b", item);
    setSelectedB(item.id);
    setComparerSlot("b", "");
  }, [slots.b, setComparerSlot, addComparerItem]);

  const { segments, hunks, omitted } = useMemo(
    () => (result ? buildSegments(result.ops, a, b) : { segments: [], hunks: 0, omitted: 0 }),
    [result, a, b],
  );

  // Encoded once per side rather than per op the way byteSlice does, since the hex view walks
  // every op's byte range instead of just the ones a text render touches.
  const aBytes = useMemo(() => new TextEncoder().encode(a), [a]);
  const bBytes = useMemo(() => new TextEncoder().encode(b), [b]);
  const emptyHexView = useMemo(() => ({ rows: [], shown: 0, total: 0 }), []);
  // Deferred until the operator actually asks for hex: building it costs a pass over every op's
  // real bytes, which the memory-lean ethos this console holds to says not to pay for a mode
  // nobody is looking at.
  const aHex = useMemo(() => (view === "hex" && result ? buildHexRows(result.ops, aBytes, "a") : emptyHexView), [view, result, aBytes, emptyHexView]);
  const bHex = useMemo(() => (view === "hex" && result ? buildHexRows(result.ops, bBytes, "b") : emptyHexView), [view, result, bBytes, emptyHexView]);

  // Replaces are in neither of the server's deleted/inserted totals, so they are
  // counted here instead of being left out of the summary.
  const replacedBytes = useMemo(
    () => (result ? result.ops.filter((op) => op.kind === "replace").reduce((total, op) => total + op.a_len, 0) : 0),
    [result],
  );

  const jump = (delta: number) => {
    if (hunks === 0) return;
    const next = currentHunk === -1 ? (delta > 0 ? 0 : hunks - 1) : (currentHunk + delta + hunks) % hunks;
    setCurrentHunk(next);
    paneRef.current?.querySelector(`[data-hunk="${next}"]`)?.scrollIntoView({ block: "center", behavior: "smooth" });
  };

  const loadSlot = (slot: "a" | "b") => {
    const raw = slot === "a" ? msgA : msgB;
    const id = Number(raw);
    // Message ids count from zero too, so message 0 — the first request body ever stored — is real
    // and loadable. `<= 0` refused it.
    if (!Number.isInteger(id) || id < 0) {
      toast.error("Give a stored message id — a whole number, counting from 0");
      return;
    }
    loadMessage.mutate(id, {
      onSuccess: (message) => {
        if (slot === "a") setA(message.text ?? "");
        else setB(message.text ?? "");
        toast.success(`Message ${id} loaded into slot ${slot.toUpperCase()}`);
      },
      onError: (cause) => toast.error(`Could not load message ${id}: ${cause.message}`),
    });
  };

  // formatCount renders a counter in the unit the comparison produced: bytes for a byte comparison,
  // words for a word comparison. One function rather than a ternary at each site, so a future metric
  // cannot pick the wrong unit by forgetting which mode it is in.
  const formatCount = (n: number, mode: "bytes" | "words") =>
    mode === "words" ? `${n} ${n === 1 ? "word" : "words"}` : formatBytes(n);

  const run = () => {
    setCurrentHunk(-1);
    compare.mutate(
      { a, b, response: side === "response", granularity },
      {
        onSuccess: (response) =>
          response.identical
            ? toast.success("The two inputs are byte-for-byte identical")
            : response.identical_ignoring_uninteresting
              ? toast.success(
                  `Differences only in discounted header(s): ${response.uninteresting_headers_applied.join(", ")}`,
                )
              : toast.success(`${response.ops.filter((op) => op.kind !== "equal").length} difference(s) found`),
        onError: (cause) => toast.error(`Comparison failed: ${cause.message}`),
      },
    );
  };

  const swap = () => {
    setA(b);
    setB(a);
    setCurrentHunk(-1);
    compare.reset();
  };

  const slotCard = (slot: "a" | "b") => {
    const value = slot === "a" ? a : b;
    const msg = slot === "a" ? msgA : msgB;
    const setMsg = slot === "a" ? setMsgA : setMsgB;
    // Burp's item table for this side (yy2): every message SENT to this slot, listed; the
    // comparison runs on the selected row. Selecting an item loads its bytes into the editor,
    // where they stay editable as before — the list is the memory, the editor is the working
    // copy, and an edit does not rewrite the stored item (the same deal Burp's tables offer).
    const list = slot === "a" ? items.a : items.b;
    const selected = slot === "a" ? selectedA : selectedB;
    const setSelected = slot === "a" ? setSelectedA : setSelectedB;
    return (
      <Card className="card-flush">
        <Toolbar>
          <Badge tone={slot === "a" ? "info" : "accent"}>slot {slot.toUpperCase()}</Badge>
          <Input
            aria-label={`Stored message id for slot ${slot.toUpperCase()}`}
            title={`Stored message id for slot ${slot.toUpperCase()}`}
            value={msg}
            inputMode="numeric"
            onChange={(event) => setMsg(event.target.value)}
            placeholder="message id"
            style={{ maxWidth: "var(--w-xs)" }}
          />
          <Button variant="outline" size="small" disabled={loadMessage.isPending} onClick={() => loadSlot(slot)}>
            <Download size={13} />
            Load
          </Button>
          <Badge>{formatBytes(new TextEncoder().encode(value).length)}</Badge>
        </Toolbar>
        {list.length > 0 ? (
          <div className="stack-tight" style={{ marginBottom: 8 }}>
            <SimpleTable headers={["Sent to " + slot.toUpperCase(), `${list.length} item${list.length === 1 ? "" : "s"}`, ""]}>
              {list.map((entry) => (
                <tr key={entry.id}>
                  <td>
                    <button
                      type="button"
                      className={entry.id === selected ? "comparer-item comparer-item-selected" : "comparer-item"}
                      aria-pressed={entry.id === selected}
                      aria-label={`Select ${entry.label} for slot ${slot.toUpperCase()}`}
                      onClick={() => {
                        setSelected(entry.id);
                        if (slot === "a") setA(entry.value);
                        else setB(entry.value);
                      }}
                      style={{ textAlign: "left" }}
                    >
                      {entry.label}
                    </button>
                  </td>
                  <td>
                    <span className="cell-dim">{formatBytes(new TextEncoder().encode(entry.value).length)}</span>
                  </td>
                  <td>
                    <IconButton
                      label={`Remove ${entry.label} from slot ${slot.toUpperCase()}`}
                      size="small"
                      onClick={() => {
                        if (entry.id === selected) {
                          setSelected(null);
                          if (slot === "a") setA("");
                          else setB("");
                        }
                        removeComparerItem(slot, entry.id);
                      }}
                    >
                      <Trash2 size={13} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </SimpleTable>
            {/* Burp's Clear: "Delete all items in the list." */}
            <Button variant="outline" size="small" onClick={() => {
              clearComparerItems(slot);
              setSelected(null);
              if (slot === "a") setA("");
              else setB("");
            }}>
              <Trash2 size={13} />
              Clear list
            </Button>
          </div>
        ) : null}
        <HttpEditor
          label={`Side ${slot.toUpperCase()}`}
          value={value}
          onChange={slot === "a" ? setA : setB}
          height="200px"
          filename={`comparer-${slot}.txt`}
          placeholder="paste text, or send an exchange here from HTTP history"
        />
      </Card>
    );
  };

  return (
    <div className="page">
      <PageHeader
        title="Comparer"
        actions={
          <>
            {/* Burp's two Comparer subjects as two modes: two buffers, or two site maps
                (k3a7). The active mode is pressed-state, not a highlight, so the control
                answers "which comparison am I in" the same way Bytes/Words does. */}
            <Button variant={mode === "buffers" ? "primary" : "outline"} size="small" aria-pressed={mode === "buffers"} onClick={() => setMode("buffers")}>
              <GitCompare size={13} />
              Buffers
            </Button>
            <Button variant={mode === "sitemaps" ? "primary" : "outline"} size="small" aria-pressed={mode === "sitemaps"} onClick={() => setMode("sitemaps")}>
              <Network size={13} />
              Site maps
            </Button>
            {/* The mode that ran, taken from the response rather than from the control: a control
                that can disagree with what the endpoint actually did is the defect this label
                exists to avoid. Before the first run there is nothing to label, so it says which
                mode the next run will use. */}
            <Badge>{result ? `${result.granularity}-level` : `${granularity}-level`}</Badge>
            <Button variant={granularity === "bytes" ? "primary" : "outline"} size="small" aria-pressed={granularity === "bytes"} onClick={() => setGranularity("bytes")}>
              <Braces size={13} />
              Bytes
            </Button>
            <Button variant={granularity === "words" ? "primary" : "outline"} size="small" aria-pressed={granularity === "words"} onClick={() => setGranularity("words")}>
              <Type size={13} />
              Words
            </Button>
            <Button variant={view === "text" ? "primary" : "outline"} size="small" aria-pressed={view === "text"} onClick={() => setView("text")}>
              <Braces size={13} />
              Text
            </Button>
            <Button variant={view === "hex" ? "primary" : "outline"} size="small" aria-pressed={view === "hex"} onClick={() => setView("hex")}>
              <Hash size={13} />
              Hex
            </Button>
            <Button variant="outline" onClick={swap} disabled={!a && !b}>
              <ArrowLeftRight size={14} />
              Swap
            </Button>
            <Button onClick={run} disabled={(!a && !b) || compare.isPending}>
              <GitCompare size={14} />
              {compare.isPending ? "Comparing…" : "Compare"}
            </Button>
          </>
        }
      />

      {mode === "sitemaps" ? (
        <Card className="card-flush">
          <SectionHeading
            title="Compare site maps"
            detail="The path-set diff between two runs — what one crawl reached that the other did not. The access-control view: an anonymous crawl's map against an authenticated one's."
          />
          {finished.length < 2 ? (
            <Empty
              title="Not two finished runs yet"
              detail="Comparing site maps takes two finished crawls or API scans. Start them from the Dashboard's New scan, wait for both to finish, and come back."
            />
          ) : (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <label htmlFor="sitemap-run-a" style={{ fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>
                  Run A
                </label>
                <Select
                  id="sitemap-run-a"
                  aria-label="Run A for the site-map comparison"
                  value={taskA ?? ""}
                  onChange={(e) => setTaskA(Number(e.target.value))}
                  style={{ width: "auto" }}
                >
                  {finished.map((run) => (
                    <option key={run.task_id} value={run.task_id}>
                      #{run.task_id} · {(run.seeds ?? []).join(", ") || run.kind || "crawl"} · {run.state}
                    </option>
                  ))}
                </Select>
                <label htmlFor="sitemap-run-b" style={{ fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>
                  Run B
                </label>
                <Select
                  id="sitemap-run-b"
                  aria-label="Run B for the site-map comparison"
                  value={taskB ?? ""}
                  onChange={(e) => setTaskB(Number(e.target.value))}
                  style={{ width: "auto" }}
                >
                  {finished.map((run) => (
                    <option key={run.task_id} value={run.task_id}>
                      #{run.task_id} · {(run.seeds ?? []).join(", ") || run.kind || "crawl"} · {run.state}
                    </option>
                  ))}
                </Select>
                <Button onClick={runSitemapDiff} disabled={taskA === null || taskB === null || taskA === taskB || compareSitemaps.isPending}>
                  <GitCompare size={14} />
                  {compareSitemaps.isPending ? "Comparing…" : "Compare site maps"}
                </Button>
                {taskA !== null && taskB !== null && taskA === taskB ? (
                  <span className="field-hint">choose two different runs</span>
                ) : null}
              </div>
              {compareSitemaps.error ? (
                <ErrorNotice error={compareSitemaps.error} onRetry={runSitemapDiff} />
              ) : sitemapResult ? (
                <SitemapDiffPanel result={sitemapResult} />
              ) : (
                <Empty
                  title="Nothing compared yet"
                  detail="Pick two finished runs and compare their site maps. Paths only one run reached are the areas to inspect for access control."
                />
              )}
            </>
          )}
        </Card>
      ) : (
      <>
      {/* The old wording said only that this build compares BYTES rather than words, which was true
          about granularity and silent about something worse: the diff had no alignment at all, so one
          inserted byte reported the whole remainder as changed. Now it aligns, both modes exist, and
          the notice says what each mode is for and what the remaining limit is. */}
      <div className="notice">
        Aligned, in the mode you choose. <strong>Bytes</strong> aligns character by character, so a
        one-character change reads as a one-character change. <strong>Words</strong> aligns whole
        words, so a changed word in a page of markup reads as that word rather than as the bytes a
        character-level match happened to leave out of it — the counts beside the diff are words in
        that mode and bytes in the other.
        {result?.truncated ? (
          <>
            {" "}
            <strong>
              These two inputs differ too extensively to align, so the differing region is shown as one
              block rather than matched up.
            </strong>
          </>
        ) : null}
      </div>

      {/* Which discount list applies. A control rather than a guess: burpsy cannot reliably tell a
          pasted request from a pasted response, and picking wrong would apply the wrong list
          silently. */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <label htmlFor="compare-side" style={{ fontSize: "var(--fs-sm)", color: "var(--fg-dim)" }}>
          Discount headers as:
        </label>
        <Select
          id="compare-side"
          aria-label="Which uninteresting-header list to apply"
          value={side}
          onChange={(event) => setSide(event.target.value as "response" | "request")}
          style={{ width: "auto" }}
        >
          <option value="response">Responses</option>
          <option value="request">Requests</option>
        </Select>
      </div>

      <div className="two-col">
        {slotCard("a")}
        {slotCard("b")}
      </div>

      {compare.error ? <ErrorNotice error={compare.error} onRetry={run} /> : null}

      {result ? (
        <>
          <div className="metric-grid">
            {/* Three verdicts, not two. "identical" stays byte-exact; the middle case — the bytes
                differ but only inside headers the operator chose to discount (W6 #81/#82) — is the
                one they usually care about, and collapsing it into either neighbour would be a
                false statement. */}
            <Metric
              label="Verdict"
              value={
                result.identical
                  ? "identical"
                  : result.identical_ignoring_uninteresting
                    ? "same but for discounted headers"
                    : "different"
              }
              tone={result.identical || result.identical_ignoring_uninteresting ? "good" : "warn"}
              accent
              detail={`${result.ops.length} aligned run(s)`}
            />
            <Metric label="Changed" value={formatBytes(replacedBytes)} detail="bytes differing in place" />
            {/* The deleted/inserted counters are in the unit of the mode that ran, so they are
                labelled in that unit: rendering a word count through formatBytes would print
                "1 B" for one deleted word, which is a number nobody can act on. "Changed" stays
                bytes in both modes because it is a byte count of the differing regions. */}
            <Metric label="Deleted" value={formatCount(result.deleted_tokens, result.granularity)} detail="only in A" />
            <Metric label="Inserted" value={formatCount(result.inserted_tokens, result.granularity)} detail="only in B" />
          </div>

          {result.uninteresting_ops > 0 ? (
            <div className="notice">
              {result.uninteresting_ops} difference(s) fall inside header(s) you have discounted
              {result.uninteresting_headers_applied.length > 0
                ? `: ${result.uninteresting_headers_applied.join(", ")}`
                : ""}
              . They are dimmed below rather than removed — the bytes really do differ. Edit the list
              in Settings → Uninteresting headers.
            </div>
          ) : null}

          {result.truncated || result.ops_omitted > 0 || omitted > 0 ? (
            <div className="notice notice-warn">
              {result.truncated ? "The server truncated the comparison. " : ""}
              {result.ops_omitted > 0 ? `${result.ops_omitted} run(s) were omitted server-side. ` : ""}
              {omitted > 0 ? `${omitted} run(s) past the first ${MAX_SEGMENTS} are not drawn here.` : ""}
            </div>
          ) : null}

          <Card className="card-flush">
            <Toolbar>
              <Badge tone={hunks ? "warn" : "good"}>
                {hunks} hunk{hunks === 1 ? "" : "s"}
              </Badge>
              <span className="field-hint">
                {currentHunk === -1 ? "no hunk focused" : `hunk ${currentHunk + 1} of ${hunks}`}
              </span>
              <Button variant="outline" size="small" disabled={hunks === 0} onClick={() => jump(-1)}>
                <ChevronLeft size={13} />
                Previous
              </Button>
              <Button variant="outline" size="small" disabled={hunks === 0} onClick={() => jump(1)}>
                Next
                <ChevronRight size={13} />
              </Button>
              <span className="field-hint">− only in A · + only in B · ~ changed · {GAP_CHAR} padding</span>
            </Toolbar>
            {result.identical ? (
              <Empty title="No differences" detail="Every byte matches, so there is no diff to draw." />
            ) : (
              <div className="diff-panes" ref={paneRef}>
                {view === "text" ? (
                  <>
                    <Pane label="A" side="a" segments={segments} currentHunk={currentHunk} />
                    <Pane label="B" side="b" segments={segments} currentHunk={currentHunk} />
                  </>
                ) : (
                  <>
                    <HexPane label="A" hexView={aHex} currentHunk={currentHunk} />
                    <HexPane label="B" hexView={bHex} currentHunk={currentHunk} />
                  </>
                )}
              </div>
            )}
          </Card>
        </>
      ) : (
        <Empty
          title="Nothing compared yet"
          detail="Paste both sides, load them by stored message id, or use “Send to Comparer” from HTTP history, then compare."
        />
      )}
      </>
      )}
    </div>
  );
}

/** The path-set diff table: one row per path, its verdict named in runs. */
function SitemapDiffPanel({ result }: { result: SitemapDiffResponse }): JSX.Element {
  // The interesting rows are the asymmetric ones, but hiding the shared surface would hide the
  // "same" verdict the comparison also answers — a diff that cannot say "identical" cannot
  // clear a control either. Both are shown; the asymmetric ones badge.
  return (
    <>
      <div className="metric-grid">
        <Metric label={`Only in run ${result.task_a}`} value={result.only_a} tone={result.only_a > 0 ? "warn" : "good"} accent />
        <Metric label={`Only in run ${result.task_b}`} value={result.only_b} tone={result.only_b > 0 ? "warn" : "good"} accent />
        <Metric label="Both runs" value={result.both} detail="paths the two maps share" />
      </div>
      <Card className="card-flush">
        <SimpleTable headers={["Authority", "Path", "Side", "Status A", "Status B"]}>
          {result.rows.map((row) => (
            <tr key={`${row.host}:${row.port}:${row.tls}:${row.path}`}>
              <td>
                {row.host}:{row.port}
                {row.tls ? <span className="cell-dim"> · https</span> : null}
              </td>
              <td>
                <code>{row.path}</code>
              </td>
              <td>
                <Badge tone={row.side === "both" ? "neutral" : "warn"}>{sideLabel(row.side, result.task_a, result.task_b)}</Badge>
              </td>
              <td>{row.status_a || "—"}</td>
              <td>{row.status_b || "—"}</td>
            </tr>
          ))}
        </SimpleTable>
      </Card>
      <p className="field-hint">
        The rows each side is missing are the access-control surface: jump to HTTP history and
        filter by <code>task = {result.task_a}</code> or <code>task = {result.task_b}</code> for
        the bytes behind any row.
      </p>
    </>
  );
}
