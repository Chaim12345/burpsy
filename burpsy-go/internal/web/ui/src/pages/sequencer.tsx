import { useEffect, useMemo, useRef, useState } from "react";
import { CircleStop, Copy, Download, Pause, Play, Radio } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard, downloadText } from "../lib/api";
import {
 SEQUENCER_ENCODINGS,
 usePauseSequencerCapture,
 useSequencerAnalyse,
 useSequencerAnalyseTokens,
 useSequencerCapture,
 useStartSequencerCapture,
 useStopSequencerCapture,
} from "../lib/data.workbench";
import type {
 CharacterAnalysis,
 SequencerAnalysis,
 SequencerCapture,
 TokenLocation,
 TokenLocationKind,
} from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { DetailList } from "../ui/json";
import { PageHeader, SectionHeading } from "../ui/layout";
import {
 Badge,
 Button,
 Checkbox,
 Card,
 Empty,
 ErrorNotice,
 Field,
 Input,
 Metric,
 Select,
 Tabs,
 TabsContent,
 TabsList,
 TabsTrigger,
 Toolbar,
} from "../ui/primitives";
import { SimpleTable } from "../ui/table";

const GRADE_LABEL: Record<string, string> = { pass: "PASS", fail: "FAIL", insufficient: "NOT TESTED" };
const GRADE_CLASS: Record<string, string> = { pass: "good-text", fail: "bad-text", insufficient: "warn-text" };

/** Positions drawn before the operator asks for the rest. Enough to see a fixed prefix. */
const POSITIONS_SHOWN = 24;

/** Characters listed per position. A wide alphabet would otherwise fill the row. */
const COUNTS_SHOWN = 6;

function lengthLabel(characters: CharacterAnalysis): string {
 return characters.min_len === characters.max_len
  ? String(characters.max_len)
  : `${characters.min_len}–${characters.max_len}`;
}

function Warnings({ warnings, grade }: { warnings: string[]; grade: string }): JSX.Element | null {
 if (!warnings.length) return null;
 return (
  <Card>
   <SectionHeading
    title={grade === "insufficient" ? "This sample does not support a verdict" : "Caveats on this verdict"}
    detail="Read these before quoting the grade: they are what the sample cannot show."
   />
   {warnings.map((warning) => (
    <div className="warning-line" key={warning}>
     {warning}
    </div>
   ))}
  </Card>
 );
}

function Fips({ report }: { report: SequencerAnalysis }): JSX.Element {
 const fips = report.fips;
 const coverage =
  `${fips.bits_supplied.toLocaleString()} bit(s) supplied · ${fips.blocks_tested} whole ${fips.block_bits}-bit block(s) tested` +
  (fips.bits_untested > 0 ? ` · ${fips.bits_untested.toLocaleString()} bit(s) not tested` : "");

 return (
  <Card>
   <SectionHeading title="FIPS 140-2 bit-level tests" detail={coverage} />
   {fips.tests === null ? (
    <div className="notice notice-warn">
     Not run. Every FIPS 140-2 threshold is defined on a {fips.block_bits}-bit sample, so running them against a
     shorter one would produce a confident answer that means nothing. Capture more tokens.
    </div>
   ) : (
    <SimpleTable headers={["Test", "Result", "Observed", "Requirement", "Blocks"]}>
     {fips.tests.map((test) => (
      <tr key={test.id}>
       <td title={test.spec}>{test.name}</td>
       <td>
        <Badge tone={test.passed ? "good" : "bad"}>{test.passed ? "pass" : "fail"}</Badge>
       </td>
       <td className="cell-num">{test.observed}</td>
       <td className="cell-dim">{test.requirement}</td>
       <td className="cell-num">
        {test.blocks_passed} / {test.blocks_passed + test.blocks_failed}
       </td>
      </tr>
     ))}
    </SimpleTable>
   )}
   <DetailList
    rows={[
     { label: "Bits", value: report.bits.bits.toLocaleString() },
     {
      label: "Ones / zeros",
      value: `${report.bits.ones.toLocaleString()} / ${report.bits.zeros.toLocaleString()}`,
     },
     { label: "Bit entropy", value: `${(report.bits.bit_entropy * 100).toFixed(2)}% of a perfect split` },
     { label: "Longest run", value: `${report.bits.longest_run} bit(s)` },
     { label: "Runs of zeros", value: report.bits.runs_zeros.join(" · ") || "—" },
     { label: "Runs of ones", value: report.bits.runs_ones.join(" · ") || "—" },
    ]}
   />
  </Card>
 );
}

function Positions({ characters }: { characters: CharacterAnalysis }): JSX.Element {
 const [showAll, setShowAll] = useState(false);
 const shown = showAll ? characters.positions : characters.positions.slice(0, POSITIONS_SHOWN);
 const hidden = characters.positions.length - shown.length;

 if (!characters.positions.length) {
  return (
   <Card>
    <SectionHeading title="Character positions" detail="No tokens to analyse." />
    <Empty title="Nothing to show" detail="Analyse a token sample to get a per-position breakdown." />
   </Card>
  );
 }

 return (
  <Card>
   <SectionHeading
    title="Character positions"
    detail={`alphabet (${characters.alphabet_size}): ${characters.alphabet.join("")}`}
    actions={
     characters.positions.length > POSITIONS_SHOWN ? (
      <Button variant="outline" size="small" aria-pressed={showAll} onClick={() => setShowAll((current) => !current)}>
       {showAll ? `Show first ${POSITIONS_SHOWN}` : `Show all ${characters.positions.length}`}
      </Button>
     ) : null
    }
   />
   {characters.positions_truncated ? (
    <div className="notice notice-warn">
     Only the first {characters.positions.length} of {characters.max_len} positions are reported by the server.
    </div>
   ) : null}
   <SimpleTable headers={["#", "Entropy", "Distinct", "Samples", "Distribution", "Flag"]}>
    {shown.map((position) => {
     // A position that never varies is the finding, so it is called out rather
     // than left to be spotted in a column of numbers.
     const dead = position.distinct <= 1;
     const top = position.counts.slice(0, COUNTS_SHOWN);
     return (
      <tr key={position.index} className={dead ? "row-flag-bad" : undefined}>
       <td className="cell-num">{position.index}</td>
       <td className="cell-num">{position.entropy_bits.toFixed(2)} b</td>
       <td className="cell-num">{position.distinct}</td>
       <td className="cell-num">{position.samples}</td>
       <td>
        <div className="chip-row">
         {top.map((count) => (
          <Badge key={count.byte} title={`${count.count} of ${position.samples}`}>
           {count.label} {(count.fraction * 100).toFixed(0)}%
          </Badge>
         ))}
         {position.counts.length > top.length ? (
          <span className="cell-dim">+{position.counts.length - top.length} more</span>
         ) : null}
        </div>
       </td>
       <td>{dead ? <Badge tone="bad">never varies</Badge> : <span className="cell-dim">—</span>}</td>
      </tr>
     );
    })}
   </SimpleTable>
   {hidden > 0 ? <p className="field-hint">{hidden} more position(s) not shown.</p> : null}
  </Card>
 );
}

function Report({ report }: { report: SequencerAnalysis }): JSX.Element {
 const characters = report.characters;
 const warnings = report.warnings ?? [];
 return (
  <>
   <Warnings warnings={warnings} grade={report.grade} />
   <div className="grade">
    <span>GRADE</span>
    <strong className={GRADE_CLASS[report.grade] ?? "warn-text"}>{GRADE_LABEL[report.grade] ?? report.grade}</strong>
    <p>{report.verdict}</p>
   </div>
   <div className="metric-grid wide">
    <Metric accent label="Tokens" value={report.tokens.toLocaleString()} detail={`length ${lengthLabel(characters)}`} />
    <Metric label="Alphabet" value={characters.alphabet_size} detail="distinct characters" />
    <Metric
     label="Entropy / token"
     value={`${characters.total_entropy_bits.toFixed(1)} b`}
     detail={`ceiling ${characters.max_possible_bits.toFixed(1)} b`}
    />
    <Metric
     label="Entropy / character"
     value={`${characters.entropy_bits_per_char.toFixed(2)} b`}
     detail={`per-position cap ${characters.entropy_ceiling_bits.toFixed(1)} b`}
    />
    <Metric
     label="Bits read as"
     value={report.encoding}
     detail={report.encoding_detected ? "detected" : "your choice"}
    />
   </div>
   <p className="field-hint">
    Entropy per token is the sum of the per-position figures, which assumes the positions are independent
    {characters.assumes_positional_independence ? "" : " (the server reports otherwise for this sample)"} — an upper
    estimate, not a measurement. This alphabet and length could carry at most{" "}
    {characters.max_possible_bits.toFixed(1)} bits, and {report.tokens.toLocaleString()} sample(s) cap any single
    position at {characters.entropy_ceiling_bits.toFixed(1)} bits however good the generator is.
   </p>
   <ExtraStats report={report} />
   <Fips report={report} />
   <Positions characters={characters} />
  </>
 );
}

/**
 * The uniformity and duplicate group (burpsy-react-ui-3sq): the numbers the CLI
 * has always printed from the same engine, now on the page. Chi-square is
 * labelled as "larger = less uniform" because it is a raw statistic, not a
 * p-value with a verdict attached; serial correlation carries the server's own
 * caveat that it is NOT Burp's bit-position correlation test; the duplicate
 * count leads because an exact repeat in a session-token sample is a finding
 * on its own.
 */
function ExtraStats({ report }: { report: SequencerAnalysis }): JSX.Element {
 const extra = report.extra_stats;
 if (!extra) return <></>;
 return (
  <Card>
   <SectionHeading
    title="Uniformity & duplicates"
    detail="The character-uniformity and duplicate statistics the CLI reports from the same engine. Chi-square is a raw statistic — larger means the alphabet is used less uniformly; it is not a pass/fail p-value."
   />
   <div className="metric-grid wide">
    <Metric
     label="Repeated tokens"
     value={extra.repeated_tokens.toLocaleString()}
     detail={extra.repeated_tokens > 0 ? "an exact repeat is a finding on its own" : "no token appeared twice"}
     {...(extra.repeated_tokens > 0 ? { tone: "warn" as const, accent: true } : {})}
    />
    <Metric label="Chi-square (chars)" value={extra.chi_square.toFixed(1)} detail="larger = less uniform" />
    <Metric
     label="Serial correlation"
     value={extra.serial_correlation.toFixed(3)}
     detail={extra.serial_correlation_label}
    />
    <Metric
     label="Monte-Carlo π"
     value={extra.monte_carlo_pi.toFixed(2)}
     detail={`deviation ${extra.monte_carlo_deviation.toFixed(2)}`}
    />
   </div>
   {extra.repeated_list?.length ? (
    <div className="notice notice-warn">
     {extra.repeated_tokens.toLocaleString()} token(s) appear more than once:{" "}
     {extra.repeated_list.slice(0, 5).map((t) => t.slice(0, 32)).join(", ")}
     {extra.repeated_list.length > 5 ? ` …and ${(extra.repeated_list.length - 5).toLocaleString()} more` : ""}
    </div>
   ) : null}
  </Card>
 );
}

/**
 * A capture in flight, or the one that just ended.
 *
 * Every number here is on screen because leaving it off made two situations look the same.
 * `attempts` against `requested` says how far a capture got; `total` against `attempts` says how
 * many of those sends yielded a token; `misses` with its reasons is what distinguishes a token the
 * application only sets sometimes from a location name that is simply wrong. The old surface showed
 * one number — the token count — and a count of zero read as a verdict about the application.
 */
function CaptureProgress({ capture }: { capture: SequencerCapture }): JSX.Element {
 const shortfall = capture.requested - capture.total;
 return (
  <Card>
   <SectionHeading
    title={capture.capturing ? `Capture ${capture.id} running` : `Capture ${capture.id} finished`}
    detail={`${capture.target} · ${capture.location}`}
   />
   <div className="metric-grid">
    <Metric label="Tokens" value={capture.total.toLocaleString()} />
    <Metric label="Requests sent" value={`${capture.attempts.toLocaleString()} of ${capture.requested.toLocaleString()}`} />
    {/* tone only when there is something to flag: `metric-neutral` has no rule behind it, so
            passing it would emit a class that styles nothing. */}
    <Metric label="No token" value={capture.misses.toLocaleString()} {...(capture.misses > 0 ? { tone: "warn" as const } : {})} />
   </div>
   {/* Said out loud rather than left to be inferred from two numbers: an entropy verdict over 40
          tokens is a different claim from one over the 200 that were asked for, and the grade alone
          does not carry the difference. */}
   {!capture.capturing && shortfall > 0 ? (
    <div className="notice notice-warn">
     This sample is {capture.total.toLocaleString()} of the {capture.requested.toLocaleString()} tokens asked for.
     {capture.stop_reason ? ` ${capture.stop_reason}.` : ""} Any verdict below describes these tokens only.
    </div>
   ) : null}
   {capture.miss_examples?.length ? (
    <SimpleTable headers={["Attempt", "Why no token"]}>
     {capture.miss_examples.map((miss) => (
      <tr key={`${miss.attempt}-${miss.reason}`}>
       <td className="cell-num">{miss.attempt}</td>
       <td className="cell-dim">{miss.reason}</td>
      </tr>
     ))}
     {capture.misses_truncated ? (
      <tr>
       <td className="cell-dim" colSpan={2}>
        …and {(capture.misses - capture.miss_examples.length).toLocaleString()} more. The count is exact; the
        examples are a sample.
       </td>
      </tr>
     ) : null}
    </SimpleTable>
   ) : null}
  </Card>
 );
}

export function SequencerPage(): JSX.Element {
 const [source, setSource] = useState("paste");
 const [encoding, setEncoding] = useState("");
 const [tokens, setTokens] = useState("");
 // Burp's Manual load offers Paste AND Load (burpsy-react-ui-ts3v): the hidden input is the
 // file affordance, the same pattern app.tsx uses for configuration import. Read as text —
 // the editor's value is text, and a binary file shows its replacement characters honestly.
 const loadInputRef = useRef<HTMLInputElement | null>(null);
 const [captureId, setCaptureId] = useState("");
 const [attached, setAttached] = useState("");

 const [captureTarget, setCaptureTarget] = useState("");
 const [captureRequest, setCaptureRequest] = useState("");
 const [captureCount, setCaptureCount] = useState("100");
 const [captureDelay, setCaptureDelay] = useState("0");
 // Burp's "Number of threads" (burpsy-react-ui-9t1). Empty means sequential — the historical
 // capture, and still the honest default, because concurrency changes what the capture
 // measures: per-request pacing becomes a bound shared across the pool.
 const [captureThreads, setCaptureThreads] = useState("");
 const [locationKind, setLocationKind] = useState<TokenLocationKind>("cookie");
 const [locationName, setLocationName] = useState("");
 const [locationPattern, setLocationPattern] = useState("");

 const analysePaste = useSequencerAnalyse();
 const analyseTokens = useSequencerAnalyseTokens();
 const capture = useSequencerCapture(attached);
 const startCapture = useStartSequencerCapture();
 const stopCapture = useStopSequencerCapture();

 // Both mutations write the same report; whichever ran last is what is on screen.
 const report = source === "paste" ? analysePaste.data : analyseTokens.data;
 const error = source === "paste" ? analysePaste.error : analyseTokens.error;
 const pending = analysePaste.isPending || analyseTokens.isPending;

 const pastedCount = useMemo(() => tokens.split("\n").filter((line) => line.trim() !== "").length, [tokens]);
 const captured = capture.data?.tokens ?? [];

 const runPaste = () =>
  analysePaste.mutate(
   { text: tokens, encoding },
   {
    onSuccess: (result) => toast.success(`${result.tokens.toLocaleString()} token(s) analysed`),
    onError: (cause) => toast.error(`Analysis failed: ${cause.message}`),
   },
  );

 const startCaptureRun = () => {
  const target = captureTarget.trim();
  if (!target) {
   toast.error("Give the target the request goes to");
   return;
  }
  if (!captureRequest.trim()) {
   toast.error("Give the request to repeat");
   return;
  }
  // Validated here as well as server-side so the operator is told before a request is sent, not
  // after: the server refuses an unusable location with a 400 rather than guessing, and being told
  // "give the cookie name" is more useful than a round trip that ends in the same sentence.
  const location: TokenLocation =
   locationKind === "body_regex" ? { kind: locationKind, pattern: locationPattern } : { kind: locationKind, name: locationName };
  if (locationKind === "body_regex" ? !locationPattern.trim() : !locationName.trim()) {
   toast.error(locationKind === "body_regex" ? "Give the pattern the token matches" : "Give the name to read the token from");
   return;
  }
  const count = Number.parseInt(captureCount, 10);
  const delay = Number.parseInt(captureDelay, 10);
  const threads = Number.parseInt(captureThreads, 10);
  startCapture.mutate(
   {
    target,
    request: captureRequest,
    location,
    ...(Number.isFinite(count) && count > 0 ? { count } : {}),
    ...(Number.isFinite(delay) && delay > 0 ? { delay_ms: delay } : {}),
    ...(Number.isFinite(threads) && threads > 1 ? { threads } : {}),
   },
   {
    onSuccess: (started) => {
     // Follow the capture that was just started, so progress appears without the operator
     // having to copy an id back into the attach field.
     setAttached(String(started.id));
     setCaptureId(String(started.id));
     toast.success(`Capture ${started.id} started: ${started.requested.toLocaleString()} requests`);
    },
    onError: (cause) => toast.error(`Could not start the capture: ${cause.message}`),
   },
  );
 };

 const runCaptured = () =>
  analyseTokens.mutate(
   { tokens: captured, encoding },
   {
    onSuccess: (result) => toast.success(`${result.tokens.toLocaleString()} captured token(s) analysed`),
    onError: (cause) => toast.error(`Analysis failed: ${cause.message}`),
   },
  );

 // Burp's Auto-analyze (burpsy-react-ui-qpl): the battery re-runs periodically while a live
 // capture is running, so the verdict converges as the sample grows instead of only after
 // the operator stops and clicks. Period 30s, and only when the sample has actually grown
 // since the last run — re-running the battery over an unchanged sample burns the server's
 // CPU to produce the same verdict. The toast stays silent for auto-runs: a success every
 // 30 seconds is a notification nobody needs, and failures still surface.
 const [autoAnalyse, setAutoAnalyse] = useState(false);
 const lastAnalysedCount = useRef(0);
 useEffect(() => {
  if (!autoAnalyse || !(capture.data?.capturing ?? false)) return;
  const timer = window.setInterval(() => {
   if (captured.length === 0 || captured.length === lastAnalysedCount.current) return;
   if (analyseTokens.isPending) return;
   lastAnalysedCount.current = captured.length;
   analyseTokens.mutate(
    { tokens: captured, encoding },
    {
     onSuccess: (result) => toast.message(`Auto-analysis over ${result.tokens.toLocaleString()} token(s)`),
     onError: (cause) => toast.error(`Auto-analysis failed: ${cause.message}`),
    },
   );
  }, 30_000);
  return () => window.clearInterval(timer);
  // analyseTokens identity changes with its internals; the interval only needs the trigger.
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [autoAnalyse, capture.data?.capturing, captured.length, encoding]);

 // Pause/resume the live capture (burpsy-react-ui-5kx). The gate is between sends server-side,
 // so the sample is never half-recorded; the capture keeps polling and shows the pause state.
 const pauseCapture = usePauseSequencerCapture(!(capture.data?.paused ?? false));
 const togglePause = () =>
  pauseCapture.mutate(undefined, {
   onSuccess: (result) => toast.message(result.note),
   onError: (cause) => toast.error(`Could not ${capture.data?.paused ? "resume" : "pause"}: ${cause.message}`),
  });

 // Copy and save the sample (Burp's Copy tokens / Save tokens): the tokens are the capture's
 // output, and handing them to Intruder or a later analysis is the point of keeping them.
 const copyCaptured = () => {
  if (captured.length === 0) {
   toast.error("No tokens captured yet");
   return;
  }
  void copyToClipboard(captured.join("\n"));
  toast.success(`Copied ${captured.length.toLocaleString()} token(s)`);
 };
 const saveCaptured = () => {
  if (captured.length === 0) {
   toast.error("No tokens captured yet");
   return;
  }
  downloadText(`sequencer-tokens-${capture.data?.id ?? "sample"}.txt`, captured.join("\n") + "\n");
  toast.success(`Saved ${captured.length.toLocaleString()} token(s)`);
 };

 return (
  <div className="page">
   <PageHeader
    title="Sequencer"
    actions={
     <>
      <Badge tone="info">{source === "paste" ? `${pastedCount} pasted` : `${captured.length} captured`}</Badge>
      <Select
       aria-label="Read token bits as"
       title="Read token bits as"
       value={encoding}
       onChange={(event) => setEncoding(event.target.value)}
       style={{ maxWidth: "var(--w-sm)" }}
      >
       <option value="">detect encoding</option>
       {SEQUENCER_ENCODINGS.map((name) => (
        <option key={name} value={name}>
         {name === "raw" ? "raw bytes" : name}
        </option>
       ))}
      </Select>
      <Button
       onClick={source === "paste" ? runPaste : runCaptured}
       disabled={pending || (source === "paste" ? pastedCount === 0 : captured.length === 0)}
      >
       <Play size={14} />
       {pending ? "Analysing…" : "Analyse"}
      </Button>
     </>
    }
   />

   <Tabs value={source} onValueChange={setSource}>
    <TabsList aria-label="Token source">
     <TabsTrigger value="paste">Paste a list</TabsTrigger>
     <TabsTrigger value="live">Capture from a live exchange</TabsTrigger>
    </TabsList>
    <TabsContent value="paste">
     <div className="toolbar" style={{ marginBottom: 8 }}>
      <Button
       variant="outline"
       size="small"
       onClick={() => loadInputRef.current?.click()}
      >
       Load from file…
      </Button>
      <input
       ref={loadInputRef}
       type="file"
       className="sr-only"
       aria-hidden="true"
       tabIndex={-1}
       onChange={(event) => {
        const file = event.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
         setTokens(String(reader.result ?? ""));
         toast.success(`Loaded ${file.name} — ${String(reader.result ?? "").split(/\r?\n/).filter(Boolean).length.toLocaleString()} line(s)`);
        };
        reader.readAsText(file);
        event.target.value = "";
       }}
      />
     </div>
     <HttpEditor
      views={false}
      label="Tokens, one per line"
      value={tokens}
      onChange={setTokens}
      height="190px"
      filename="sequencer-tokens.txt"
      placeholder={"a1b2c3d4\ne5f60718\n…"}
     />
    </TabsContent>
    <TabsContent value="live">
     <div className="field-hint" style={{ marginBottom: 8 }}>
      Send one request repeatedly and pull a token out of every response. The token location is declared, not
      guessed: a heuristic that picked the wrong cookie would produce a confident verdict about the wrong string.
     </div>

     <div className="two-col">
      <HttpEditor
       views={false}
       label="Request to repeat"
       value={captureRequest}
       onChange={setCaptureRequest}
       height="170px"
       filename="sequencer-capture-request.txt"
       placeholder={"GET /login HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n"}
      />
      <div>
       <Field label="Target">
        {(id) => (
         <Input
          id={id}
          value={captureTarget}
          onChange={(event) => setCaptureTarget(event.target.value)}
          placeholder="https://app.example:443"
         />
        )}
       </Field>
       <Field label="Token location">
        {(id) => (
         <Select id={id} value={locationKind} onChange={(event) => setLocationKind(event.target.value as TokenLocationKind)}>
          <option value="cookie">Set-Cookie value</option>
          <option value="header">Response header value</option>
          <option value="body_regex">Body, by pattern</option>
         </Select>
        )}
       </Field>
       {locationKind === "body_regex" ? (
        <Field label="Pattern" hint="RE2. Capture group 1 is the token when the pattern has one.">
         {(id) => (
          <Input
           id={id}
           value={locationPattern}
           onChange={(event) => setLocationPattern(event.target.value)}
           placeholder={'csrf"\\s*:\\s*"([^"]+)"'}
          />
         )}
        </Field>
       ) : (
        <Field label={locationKind === "cookie" ? "Cookie name" : "Header name"}>
         {(id) => (
          <Input
           id={id}
           value={locationName}
           onChange={(event) => setLocationName(event.target.value)}
           placeholder={locationKind === "cookie" ? "SESSIONID" : "X-Csrf-Token"}
          />
         )}
        </Field>
       )}
       <Toolbar>
        <Field label="Requests" style={{ maxWidth: "var(--w-xs)" }}>
         {(id) => (
          <Input
           id={id}
           value={captureCount}
           inputMode="numeric"
           onChange={(event) => setCaptureCount(event.target.value)}
           placeholder="100"
          />
         )}
        </Field>
        <Field label="Delay (ms)" style={{ maxWidth: "var(--w-xs)" }}>
         {(id) => (
          <Input
           id={id}
           value={captureDelay}
           inputMode="numeric"
           onChange={(event) => setCaptureDelay(event.target.value)}
           placeholder="0"
          />
         )}
        </Field>
        <Field
         label="Threads"
         hint="Concurrent requests. Empty = sequential; concurrency makes the delay a bound shared across the pool."
         style={{ maxWidth: "var(--w-xs)" }}
        >
         {(id) => (
          <Input
           id={id}
           value={captureThreads}
           inputMode="numeric"
           onChange={(event) => setCaptureThreads(event.target.value)}
           placeholder="1"
          />
         )}
        </Field>
        <span title="Re-run the randomness battery every 30 seconds while the capture runs, when the sample has grown — the verdict converges live.">
         <Checkbox label="Auto-analyse" checked={autoAnalyse} onCheckedChange={setAutoAnalyse} />
        </span>
        <Button onClick={startCaptureRun} disabled={startCapture.isPending}>
         <Radio size={14} />
         {startCapture.isPending ? "Starting…" : "Start capture"}
        </Button>
        <Button onClick={togglePause} disabled={!capture.data?.capturing || pauseCapture.isPending}>
         {(capture.data?.paused ?? false) ? <Play size={14} /> : <Pause size={14} />}
         {(capture.data?.paused ?? false) ? "Resume" : "Pause"}
        </Button>
        <Button
         variant="danger"
         disabled={stopCapture.isPending || !capture.data?.capturing}
         onClick={() =>
          stopCapture.mutate(undefined, {
           // The reply says whether anything was actually stopped, so the toast says so
           // too. It used to report success unconditionally, for a loop that did not exist.
           onSuccess: (result) =>
            result.stopped
             ? toast.success(`Stopped ${result.signalled} capture(s)`)
             : toast.message(result.note),
           onError: (cause) => toast.error(`Could not stop the capture: ${cause.message}`),
          })
         }
        >
         <CircleStop size={14} />
         Stop capture
        </Button>
        <Button onClick={copyCaptured} disabled={captured.length === 0}>
         <Copy size={14} />
         Copy tokens
        </Button>
        <Button onClick={saveCaptured} disabled={captured.length === 0}>
         <Download size={14} />
         Save tokens
        </Button>
       </Toolbar>
      </div>
     </div>

     {startCapture.error ? <ErrorNotice error={startCapture.error} onRetry={startCaptureRun} /> : null}

     <Toolbar>
      <Input
       aria-label="Follow an existing capture by id"
       title="Follow an existing capture by id"
       value={captureId}
       inputMode="numeric"
       onChange={(event) => setCaptureId(event.target.value)}
       placeholder="or follow capture id"
       style={{ maxWidth: "var(--w-sm)" }}
      />
      <Button
       variant="outline"
       onClick={() => {
        const next = captureId.trim();
        if (!next) {
         toast.error("Give the capture id to attach to");
         return;
        }
        setAttached(next);
        toast.success(`Following capture ${next}`);
       }}
      >
       <Radio size={14} />
       {attached ? "Re-attach" : "Attach"}
      </Button>
     </Toolbar>

     {capture.error ? <ErrorNotice error={capture.error} onRetry={() => void capture.refetch()} /> : null}
     {capture.data ? <CaptureProgress capture={capture.data} /> : null}
     {attached && !capture.data && !capture.isLoading && !capture.error ? (
      <Empty title="Nothing to follow" detail={`No capture ${attached} is known to this session.`} />
     ) : null}
     {!attached && !capture.data ? (
      <Empty
       title="No capture running"
       detail="Start one above, or paste a sample into the other tab. A hundred tokens is the conventional floor for a verdict."
      />
     ) : null}
    </TabsContent>
   </Tabs>

   {error ? <ErrorNotice error={error} onRetry={source === "paste" ? runPaste : runCaptured} /> : null}

   {
    report ? (
     <Report report={report} />
    ) : (
     <Empty
      title="No analysis yet"
      detail="Paste a representative sample of session ids or CSRF tokens — a hundred is the conventional floor — then analyse it."
     />
    )
   }
  </div >
 );
}
