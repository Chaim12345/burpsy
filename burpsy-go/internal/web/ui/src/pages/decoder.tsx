import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Braces, Copy, Hash, Play, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard, formatBytes } from "../lib/api";
import {
  DECODE_LAYERS,
  ENCODE_ENCODINGS,
  HASH_ALGORITHMS,
  newTransformStep,
  useTransformPipeline,
} from "../lib/data.workbench";
import type { TransformKind, TransformResult, TransformStep } from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { PageHeader, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, IconButton, Select, Toolbar } from "../ui/primitives";

const KIND_LABEL: Record<TransformKind, string> = { decode: "Decode", encode: "Encode", hash: "Hash" };

/** The values each kind accepts, taken from the handlers rather than from Burp's menu. */
function valuesFor(kind: TransformKind): readonly string[] {
  if (kind === "decode") return ["auto", ...DECODE_LAYERS];
  if (kind === "encode") return ENCODE_ENCODINGS;
  return HASH_ALGORITHMS;
}

function defaultValue(kind: TransformKind): string {
  return valuesFor(kind)[0] ?? "auto";
}

const HEX_COLS = 16;

/**
 * Cap on the hex dump. A hex row costs roughly five times its bytes in markup,
 * so an inflated response that renders fine as text would stall the tab as hex.
 */
const MAX_HEX_BYTES = 8192;

function hexDump(text: string): string {
  const bytes = new TextEncoder().encode(text);
  const shown = bytes.subarray(0, MAX_HEX_BYTES);
  const lines: string[] = [];
  for (let offset = 0; offset < shown.length; offset += HEX_COLS) {
    const chunk = shown.subarray(offset, offset + HEX_COLS);
    const cells = Array.from(chunk, (byte) => byte.toString(16).padStart(2, "0"));
    const ascii = Array.from(chunk, (byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".")).join("");
    const pad = "   ".repeat(HEX_COLS - cells.length);
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${cells.join(" ")}${pad}  |${ascii}|`);
  }
  if (!lines.length) return "(0 bytes)";
  if (bytes.length > shown.length) {
    lines.push(`… ${bytes.length - shown.length} more bytes not dumped; switch back to text for the whole output`);
  }
  return lines.join("\n");
}

function StepRow({
  step,
  index,
  total,
  onChange,
  onMove,
  onRemove,
}: {
  step: TransformStep;
  index: number;
  total: number;
  onChange: (patch: Partial<Omit<TransformStep, "id">>) => void;
  onMove: (delta: number) => void;
  onRemove: () => void;
}): JSX.Element {
  return (
    <Toolbar>
      <Badge tone="info">step {index + 1}</Badge>
      <Select
        aria-label={`Step ${index + 1} operation`}
        value={step.kind}
        onChange={(event) => {
          const kind = event.target.value as TransformKind;
          onChange({ kind, value: defaultValue(kind) });
        }}
        style={{ maxWidth: "var(--w-xs)" }}
      >
        {(["decode", "encode", "hash"] as const).map((kind) => (
          <option key={kind} value={kind}>
            {KIND_LABEL[kind]}
          </option>
        ))}
      </Select>
      <Select
        aria-label={`Step ${index + 1} ${step.kind === "hash" ? "algorithm" : "encoding"}`}
        value={step.value}
        onChange={(event) => onChange({ value: event.target.value })}
        style={{ maxWidth: "var(--w-sm)" }}
      >
        {valuesFor(step.kind).map((value) => (
          <option key={value} value={value}>
            {value === "auto" ? "smart detect" : value}
          </option>
        ))}
      </Select>
      {step.kind === "decode" && step.value === "auto" ? (
        <Checkbox
          checked={step.guess}
          onCheckedChange={(guess) => onChange({ guess })}
          label="guess base64 / hex alphabets"
        />
      ) : null}
      <div className="page-actions">
        <IconButton label={`Move step ${index + 1} earlier`} size="small" disabled={index === 0} onClick={() => onMove(-1)}>
          <ArrowUp size={13} />
        </IconButton>
        <IconButton
          label={`Move step ${index + 1} later`}
          size="small"
          disabled={index === total - 1}
          onClick={() => onMove(1)}
        >
          <ArrowDown size={13} />
        </IconButton>
        <IconButton label={`Remove step ${index + 1}`} size="small" onClick={onRemove}>
          <Trash2 size={13} />
        </IconButton>
      </div>
    </Toolbar>
  );
}

function ResultCard({
  result,
  index,
  view,
}: {
  result: TransformResult;
  index: number;
  view: "text" | "hex";
}): JSX.Element {
  const label = `${KIND_LABEL[result.kind]} · ${result.value === "auto" ? "smart detect" : result.value}`;
  const smart = result.kind === "decode" && result.value === "auto";
  return (
    <Card>
      <div className="detail-head">
        <div className="detail-head-title">
          <span className="eyebrow">step {index + 1}</span>
          <strong>{label}</strong>
        </div>
        <div className="detail-actions">
          <Badge>{formatBytes(result.len)}</Badge>
          {result.utf8 ? null : <Badge tone="warn">not utf-8</Badge>}
          {result.truncated ? <Badge tone="warn">truncated</Badge> : null}
          <IconButton
            label={`Copy step ${index + 1} output`}
            size="small"
            onClick={() => {
              void copyToClipboard(result.output);
              toast.success(`Step ${index + 1} output copied`);
            }}
          >
            <Copy size={13} />
          </IconButton>
        </div>
      </div>

      {/* Smart detect must say what it found: the server reports only the layer
          chain, and an empty chain means it decoded nothing at all. */}
      {smart ? (
        result.layers && result.layers.length ? (
          <div className="chip-row">
            <span className="eyebrow">detected</span>
            {result.layers.map((layer, position) => (
              <Badge tone="accent" key={`${layer}-${position}`}>
                {layer}
              </Badge>
            ))}
          </div>
        ) : (
          <div className="notice notice-warn">
            Nothing was detected: no layer decoded cleanly, so this step passed the input through unchanged.
          </div>
        )
      ) : null}

      {/* A partly-decompressed stream is a prefix, not the plaintext. Saying so is the
          difference between "the string is absent" and "the string is not in what we got". */}
      {result.partial ? (
        <div className="notice notice-warn">
          This stream only partly decompressed, so the output below is a prefix of the plaintext, not all of it. A
          search that finds nothing here has not ruled the string out.
        </div>
      ) : null}

      {!result.utf8 && view === "hex" ? (
        <div className="notice notice-warn">
          The server sends a lossy text rendering, not raw bytes, so this dump is of the replacement characters that
          reached the browser — {new TextEncoder().encode(result.output).length} B here against {result.len} B decoded.
        </div>
      ) : null}

      {/* `prose` alone still reads correctly if tool-output is not merged; the extra
          class only adds the monospace column alignment a hex dump needs. */}
      <div className="prose tool-output">{view === "hex" ? hexDump(result.output) : result.output || "(empty output)"}</div>
    </Card>
  );
}

export function DecoderPage(): JSX.Element {
  const [input, setInput] = useState("");
  const [steps, setSteps] = useState<TransformStep[]>(() => [newTransformStep("decode", "auto")]);
  const [view, setView] = useState<"text" | "hex">("text");
  const pipeline = useTransformPipeline();

  const run = pipeline.data;
  const inputBytes = useMemo(() => new TextEncoder().encode(input).length, [input]);

  const addStep = (kind: TransformKind) => setSteps((current) => [...current, newTransformStep(kind, defaultValue(kind))]);

  const patchStep = (id: string, patch: Partial<Omit<TransformStep, "id">>) =>
    setSteps((current) => current.map((step) => (step.id === id ? { ...step, ...patch } : step)));

  const moveStep = (index: number, delta: number) =>
    setSteps((current) => {
      const next = [...current];
      const target = index + delta;
      const moving = next[index];
      const displaced = next[target];
      if (!moving || !displaced) return current;
      next[index] = displaced;
      next[target] = moving;
      return next;
    });

  const removeStep = (id: string) => setSteps((current) => current.filter((step) => step.id !== id));

  const execute = () =>
    pipeline.mutate(
      { input, steps },
      {
        onSuccess: (result) => {
          if (result.failedAt === null) {
            toast.success(`${result.results.length} step(s) ran`);
            return;
          }
          toast.error(`Step ${result.failedAt + 1} failed: ${result.message ?? "unknown error"}`);
        },
        onError: (cause) => toast.error(`Pipeline could not run: ${cause.message}`),
      },
    );

  // A hash is one-way, so anything chained after it transforms a digest rather
  // than the operator's data. Worth saying once, not blocking.
  const hashIndex = steps.findIndex((step) => step.kind === "hash");
  const hashNotLast = hashIndex >= 0 && hashIndex < steps.length - 1;

  return (
    <div className="page">
      <PageHeader
        title="Decoder"
        actions={
          <>
            <Badge>{formatBytes(inputBytes)} in</Badge>
            <Button
              variant={view === "text" ? "primary" : "outline"}
              size="small"
              aria-pressed={view === "text"}
              onClick={() => setView("text")}
            >
              <Braces size={13} />
              Text
            </Button>
            <Button
              variant={view === "hex" ? "primary" : "outline"}
              size="small"
              aria-pressed={view === "hex"}
              onClick={() => setView("hex")}
            >
              <Hash size={13} />
              Hex
            </Button>
            <Button onClick={execute} disabled={!input || steps.length === 0 || pipeline.isPending}>
              <Play size={14} />
              {pipeline.isPending ? "Running…" : "Run pipeline"}
            </Button>
          </>
        }
      />

      <HttpEditor
          views={false}
        label="Input"
        value={input}
        onChange={setInput}
        height="160px"
        filename="decoder-input.txt"
        placeholder="paste a cookie, a JWT, a URL-encoded parameter…"
      />

      <Card>
        <SectionHeading
          title="Transform pipeline"
          detail="Each step is fed the previous step's output, and every intermediate result stays on screen."
          actions={
            <>
              <Button variant="outline" size="small" onClick={() => addStep("decode")}>
                <Plus size={13} />
                Decode
              </Button>
              <Button variant="outline" size="small" onClick={() => addStep("encode")}>
                <Plus size={13} />
                Encode
              </Button>
              <Button variant="outline" size="small" onClick={() => addStep("hash")}>
                <Plus size={13} />
                Hash
              </Button>
            </>
          }
        />
        {steps.length ? (
          steps.map((step, index) => (
            <StepRow
              key={step.id}
              step={step}
              index={index}
              total={steps.length}
              onChange={(patch) => patchStep(step.id, patch)}
              onMove={(delta) => moveStep(index, delta)}
              onRemove={() => removeStep(step.id)}
            />
          ))
        ) : (
          <Empty title="No steps" detail="Add a decode, encode or hash step to build a chain." />
        )}
        {hashNotLast ? (
          <div className="notice notice-warn">
            A hash is one-way: step {hashIndex + 1} onwards operates on the hex digest, not on the original bytes.
          </div>
        ) : null}
      </Card>

      {pipeline.error ? <ErrorNotice error={pipeline.error} onRetry={execute} /> : null}

      {run ? (
        <>
          {run.failedAt !== null ? (
            <div className="notice notice-warn">
              Step {run.failedAt + 1} failed and the chain stopped there: {run.message ?? "no detail was returned"}. The
              steps below are the ones that did run.
            </div>
          ) : null}
          {run.results.length ? (
            run.results.map((result, index) => (
              <ResultCard key={result.stepId} result={result} index={index} view={view} />
            ))
          ) : (
            <Empty title="No output" detail="The first step failed, so nothing was produced." />
          )}
        </>
      ) : (
        <Empty
          title="Nothing run yet"
          detail="Paste an input, arrange the steps, then run the pipeline to see each layer come off in turn."
        />
      )}
    </div>
  );
}
