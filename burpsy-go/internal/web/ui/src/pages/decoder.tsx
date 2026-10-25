import { useEffect, useMemo, useRef, useState } from "react";
import { EditorView } from "@codemirror/view";
import { ArrowDown, ArrowUp, Braces, Copy, Eraser, Hash, Play, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard, formatBytes } from "../lib/api";
import { useApp } from "../lib/store";
import {
 DECODE_LAYERS,
 ENCODE_ENCODINGS,
 HASH_ALGORITHMS,
 HASH_KEY_ENCODINGS,
 HASH_OUTPUTS,
 hashNeedsKey,
 newTransformStep,
 useTransformPipeline,
} from "../lib/data.workbench";
import { encodingFamily, familyForValue } from "../lib/decoder-colours";
import { resolveSelection, splitInput } from "../lib/decoder-span";
import { docPosToValuePos } from "../lib/message-views";
import type { TransformKind, TransformResult, TransformStep } from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { PageHeader, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, IconButton, Input, Select, Toolbar } from "../ui/primitives";

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
    title={`Step ${index + 1} operation`}
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
    title={`Step ${index + 1} ${step.kind === "hash" ? "algorithm" : "encoding"}`}
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
   {step.kind === "hash" && hashNeedsKey(step.value) ? (
    <>
     <Input
      aria-label={`Step ${index + 1} HMAC key`}
      title="HMAC key — required by the hmac-* algorithms"
      placeholder="HMAC key"
      value={step.key ?? ""}
      onChange={(event) => onChange({ key: event.target.value })}
      style={{ maxWidth: "var(--w-sm)" }}
     />
     <Select
      aria-label={`Step ${index + 1} key encoding`}
      title="How the key is written"
      value={step.keyEncoding ?? "utf8"}
      onChange={(event) => onChange({ keyEncoding: event.target.value })}
      style={{ maxWidth: "var(--w-xs)" }}
     >
      {HASH_KEY_ENCODINGS.map((value) => (
       <option key={value} value={value}>
        key: {value}
       </option>
      ))}
     </Select>
    </>
   ) : null}
   {step.kind === "hash" ? (
    <Select
     aria-label={`Step ${index + 1} digest output`}
     title="How the digest is written — base64url is unpadded, the JWS signature form"
     value={step.output ?? "hex"}
     onChange={(event) => onChange({ output: event.target.value })}
     style={{ maxWidth: "var(--w-xs)" }}
    >
     {HASH_OUTPUTS.map((value) => (
      <option key={value} value={value}>
       out: {value}
      </option>
     ))}
    </Select>
   ) : null}
   {step.kind === "decode" && step.value === "auto" ? (
    <Checkbox checked={step.guess} onCheckedChange={(guess) => onChange({ guess })} label="guess base64 / hex alphabets" />
   ) : null}
   <div className="page-actions">
    <IconButton label={`Move step ${index + 1} earlier`} size="small" disabled={index === 0} onClick={() => onMove(-1)}>
     <ArrowUp size={13} />
    </IconButton>
    <IconButton label={`Move step ${index + 1} later`} size="small" disabled={index === total - 1} onClick={() => onMove(1)}>
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
 before,
 after,
 isSelection,
}: {
 result: TransformResult;
 index: number;
 view: "text" | "hex";
 /** Untouched text before the transformed span; empty in whole-input mode. */
 before: string;
 /** Untouched text after the transformed span; empty in whole-input mode. */
 after: string;
 /** True when only a selected span was transformed, so len/utf-8 describe the span. */
 isSelection: boolean;
}): JSX.Element {
 const label = `${KIND_LABEL[result.kind]} · ${result.value === "auto" ? "smart detect" : result.value}`;
 const smart = result.kind === "decode" && result.value === "auto";
 // The colour is the encoding this step actually applied — the step's value, or, for a smart
 // decode, the last layer the server reported it peeled. Null means no tint (nothing detected).
 const family = encodingFamily(result.kind, result.value, result.layers);
 // Empty output only reads as "(empty output)" when there is no surrounding text to show.
 const emptyWhole = !before && !after && !result.output;
 return (
  <Card>
   <div className="detail-head">
    <div className="detail-head-title">
     <span className="eyebrow">step {index + 1}</span>
     <strong>{label}</strong>
    </div>
    <div className="detail-actions">
     {isSelection ? (
      <Badge
       tone="info"
       title="Only the selected span was transformed; the rest of the input is shown unchanged around it. The byte count and UTF-8 flag describe the span."
      >
       selection
      </Badge>
     ) : null}
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
      {result.layers.map((layer, position) => {
       const layerFamily = familyForValue(layer);
       return (
        <Badge tone="accent" className="enc-badge" data-encoding={layerFamily ?? undefined} key={`${layer}-${position}`}>
         {layerFamily ? <span className="enc-dot" data-encoding={layerFamily} aria-hidden="true" /> : null}
         {layer}
        </Badge>
       );
      })}
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
     This stream only partly decompressed, so the output below is a prefix of the plaintext, not all of it. A search that finds nothing here
     has not ruled the string out.
    </div>
   ) : null}

   {!result.utf8 && view === "hex" ? (
    <div className="notice notice-warn">
     The server sends a lossy text rendering, not raw bytes, so this dump is of the replacement characters that reached the browser —{" "}
     {new TextEncoder().encode(result.output).length} B here against {result.len} B decoded.
    </div>
   ) : null}

   {/* `prose` alone still reads correctly if tool-output is not merged; the extra
          class only adds the monospace column alignment a hex dump needs.

          Text view colour-codes the transformed span by the encoding actually applied and
          shows any untouched prefix/suffix around it plain — Burp's "The data is color-coded
          to indicate the type of encoding or decoding that is applied." Hex view dumps the
          reconstructed whole (before + span + after), since a byte grid has no colour to carry. */}
   <div className="prose tool-output">
    {view === "hex" ? (
     hexDump(before + result.output + after)
    ) : emptyWhole ? (
     "(empty output)"
    ) : (
     <>
      {before}
      <span className="enc-span" data-encoding={family ?? undefined} title={family ? `${label} applied to this span` : undefined}>
       {result.output}
      </span>
      {after}
     </>
    )}
   </div>
  </Card>
 );
}

export function DecoderPage(): JSX.Element {
 const [input, setInput] = useState("");
 const [steps, setSteps] = useState<TransformStep[]>(() => [newTransformStep("decode", "auto")]);
 const [view, setView] = useState<"text" | "hex">("text");
 const pipeline = useTransformPipeline();

 // The input is the shared CodeMirror editor. Its selection is read through the DOM at run time
 // (EditorView.findFromDOM) rather than pushed up through a prop, because src/ui/editor.tsx is
 // owned by another agent and exposes no onSelectionChange — this is the read that would become
 // that prop. `views={false}` keeps the editor on the Raw view with no charset override, so its
 // document is byte-identical to `input` and its char offsets index `input` directly.
 const editorWrapRef = useRef<HTMLDivElement>(null);

 // The selection context of the last run, snapshotted at execute time so the result cards render
 // the prefix/suffix that belong to the results on screen even as the live selection moves on.
 const [runSplit, setRunSplit] = useState<{ before: string; after: string; whole: boolean } | null>(null);

 // A hand-off from another surface (History's "Send to Decoder") lands as a seed rather than a
 // URL param, because the input is arbitrary bytes no router should carry. Consumed once and
 // cleared: leaving it set would re-overwrite the operator's edits on every remount.
 const decoderSeed = useApp((state) => state.decoderSeed);
 const setDecoderSeed = useApp((state) => state.setDecoderSeed);
 useEffect(() => {
  if (!decoderSeed) return;
  setInput(decoderSeed.input);
  setDecoderSeed(null);
  toast.info(`Loaded ${decoderSeed.label} into Decoder`);
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [decoderSeed]);

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

 const execute = () => {
  // Burp: "The transformation applies to the whole data set. To apply the transformation to only
  // a portion of the data, select the relevant section before you choose an operation." A real
  // selection in the input feeds only that span through the pipeline; the surrounding text is
  // held aside and shown unchanged around each step's output. No selection → whole input, as before.
  const view = editorWrapRef.current ? EditorView.findFromDOM(editorWrapRef.current) : null;
  const main = view?.state.selection.main;
  // The selection indexes CodeMirror's document, which holds one "\n" for each CRLF; `input`
  // keeps the CRLF (a message sent here from Proxy or Repeater does), so map back before
  // slicing it, or the span shifts left a character per preceding line (burpsy-react-ui-ngao).
  const selection = resolveSelection(
   input.length,
   main ? docPosToValuePos(input, main.from) : null,
   main ? docPosToValuePos(input, main.to) : null,
  );
  const parts = splitInput(input, selection);
  setRunSplit({ before: parts.before, after: parts.after, whole: selection.whole });
  pipeline.mutate(
   { input: parts.span, steps },
   {
    onSuccess: (result) => {
     if (result.failedAt === null) {
      toast.success(selection.whole ? `${result.results.length} step(s) ran` : `${result.results.length} step(s) ran on the selection`);
      return;
     }
     toast.error(`Step ${result.failedAt + 1} failed: ${result.message ?? "unknown error"}`);
    },
    onError: (cause) => toast.error(`Pipeline could not run: ${cause.message}`),
   },
  );
 };

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
      <Button variant={view === "text" ? "primary" : "outline"} size="small" aria-pressed={view === "text"} onClick={() => setView("text")}>
       <Braces size={13} />
       Text
      </Button>
      <Button variant={view === "hex" ? "primary" : "outline"} size="small" aria-pressed={view === "hex"} onClick={() => setView("hex")}>
       <Hash size={13} />
       Hex
      </Button>
      {/* Input and output are cleared together. The editor's own controls and a fresh run
                each clear only one of the two, which left a stale output sitting under a new
                input — output that still looked like the answer to what was now on screen. */}
      <Button
       variant="outline"
       size="small"
       disabled={!input && !run && !pipeline.error}
       onClick={() => {
        setInput("");
        pipeline.reset();
        setRunSplit(null);
        toast.success("Input and output cleared");
       }}
      >
       <Eraser size={13} />
       Clear all
      </Button>
      <Button onClick={execute} disabled={!input || steps.length === 0 || pipeline.isPending}>
       <Play size={14} />
       {pipeline.isPending ? "Running…" : "Run pipeline"}
      </Button>
     </>
    }
   />

   {/* Wrapped so the run handler can find this editor's CodeMirror view by DOM and read its
          selection — see execute(). */}
   <div ref={editorWrapRef}>
    <HttpEditor
     views={false}
     label="Input"
     value={input}
     onChange={setInput}
     height="160px"
     filename="decoder-input.txt"
     placeholder="paste a cookie, a JWT, a URL-encoded parameter…"
    />
   </div>

   <Card>
    <SectionHeading
     title="Transform pipeline"
     detail="Each step is fed the previous step's output, and every intermediate result stays on screen. Select a span in the input to transform only that part; with nothing selected the whole input is transformed."
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

   {/* One live region around the whole result pane, always mounted — a live region has to
          already be in the document when its contents change, so announcing the results by
          marking up each card as it appears would not work. Running the pipeline replaces what
          is in here without moving focus, which is exactly the change a screen reader would
          otherwise never mention. Polite, not assertive: an operator mid-sentence in the input
          should not be interrupted by their own decode landing. */}
   <div className="stack" aria-live="polite">
    {pipeline.error ? <ErrorNotice error={pipeline.error} onRetry={execute} /> : null}

    {run ? (
     <>
      {run.failedAt !== null ? (
       <div className="notice notice-warn">
        Step {run.failedAt + 1} failed and the chain stopped there: {run.message ?? "no detail was returned"}. The steps below are the ones
        that did run.
       </div>
      ) : null}
      {run.results.length ? (
       run.results.map((result, index) => (
        <ResultCard
         key={result.stepId}
         result={result}
         index={index}
         view={view}
         before={runSplit && !runSplit.whole ? runSplit.before : ""}
         after={runSplit && !runSplit.whole ? runSplit.after : ""}
         isSelection={Boolean(runSplit && !runSplit.whole)}
        />
       ))
      ) : (
       <Empty title="No output" detail="The first step failed, so nothing was produced." />
      )}
     </>
    ) : (
     <Empty title="Nothing run yet" detail="Paste an input, arrange the steps, then run the pipeline to see each layer come off in turn." />
    )}
   </div>
  </div>
 );
}
