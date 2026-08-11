import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftRight, ChevronLeft, ChevronRight, Download, GitCompare } from "lucide-react";
import { toast } from "sonner";
import { formatBytes } from "../lib/api";
import { useCompare, useLoadMessage } from "../lib/data.workbench";
import { useApp } from "../lib/store";
import type { CompareOp } from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { PageHeader } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Input, Metric, Toolbar } from "../ui/primitives";

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
      segments.push({ key, kind: "insert", hunk, mark: "+", a: GAP_CHAR.repeat([...text].length), b: text });
      continue;
    }
    if (op.kind === "delete") {
      const text = op.text ?? byteSlice(aText, op.a_offset, op.a_len);
      segments.push({ key, kind: "delete", hunk, mark: "−", a: text, b: GAP_CHAR.repeat([...text].length) });
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
              className={`diff-${segment.kind}${segment.hunk === currentHunk ? " diff-hunk-current" : ""}`}
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

export function ComparerPage(): JSX.Element {
  const slots = useApp((state) => state.comparerSlots);
  const setComparerSlot = useApp((state) => state.setComparerSlot);

  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [msgA, setMsgA] = useState("");
  const [msgB, setMsgB] = useState("");
  const [currentHunk, setCurrentHunk] = useState(-1);
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
      { a, b },
      {
        onSuccess: (response) =>
          response.identical
            ? toast.success("The two inputs are byte-for-byte identical")
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
      <div className="notice">
        This build compares bytes. The server exposes no word-level mode, so no granularity control is offered rather
        than one that silently does the same thing.
      </div>

      <div className="two-col">
        {slotCard("a")}
        {slotCard("b")}
      </div>

      {compare.error ? <ErrorNotice error={compare.error} onRetry={run} /> : null}

      {result ? (
        <>
          <div className="metric-grid">
            <Metric
              label="Verdict"
              value={result.identical ? "identical" : "different"}
              tone={result.identical ? "good" : "warn"}
              accent
              detail={`${result.ops.length} aligned run(s)`}
            />
            <Metric label="Changed" value={formatBytes(replacedBytes)} detail="bytes differing in place" />
            <Metric label="Deleted" value={formatBytes(result.deleted_tokens)} detail="only in A" />
            <Metric label="Inserted" value={formatBytes(result.inserted_tokens)} detail="only in B" />
          </div>

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
                <Pane label="A" side="a" segments={segments} currentHunk={currentHunk} />
                <Pane label="B" side="b" segments={segments} currentHunk={currentHunk} />
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
