import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftRight, Braces, ChevronLeft, ChevronRight, Download, GitCompare, Hash } from "lucide-react";
import { toast } from "sonner";
import { formatBytes } from "../lib/api";
import { useCompare, useLoadMessage } from "../lib/data.workbench";
import { useApp } from "../lib/store";
import type { CompareOp } from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { PageHeader } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Input, Metric, Select, Toolbar } from "../ui/primitives";

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
  const paneRef = useRef<HTMLDivElement>(null);

  const compare = useCompare();
  const loadMessage = useLoadMessage();
  const result = compare.data;

  // "Send to Comparer (A/B)" elsewhere in the app writes the raw bytes into the
  // store; consume them so a second hand-off of the same text still lands.
  useEffect(() => {
    if (!slots.a) return;
    setA(slots.a);
    setComparerSlot("a", "");
  }, [slots.a, setComparerSlot]);

  useEffect(() => {
    if (!slots.b) return;
    setB(slots.b);
    setComparerSlot("b", "");
  }, [slots.b, setComparerSlot]);

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

  const run = () => {
    setCurrentHunk(-1);
    compare.mutate(
      { a, b, response: side === "response" },
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
            <Badge>byte-level</Badge>
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

      {/* The handler reads two flat strings and has no granularity parameter, so a
          word-level option here would be a control that changes nothing. */}
      {/* The old wording said only that this build compares BYTES rather than words. That was true
          about granularity and silent about something worse: the diff had no alignment at all, so one
          inserted byte reported the whole remainder as changed. Now it aligns, and the notice says
          what the actual remaining limit is. */}
      <div className="notice">
        Byte-level, aligned. Differences are matched up across insertions and deletions, so a
        one-character change reads as a one-character change. There is no word-level mode, and none is
        offered rather than a control that silently did the same thing.
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
            <Metric label="Deleted" value={formatBytes(result.deleted_tokens)} detail="only in A" />
            <Metric label="Inserted" value={formatBytes(result.inserted_tokens)} detail="only in B" />
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
    </div>
  );
}
