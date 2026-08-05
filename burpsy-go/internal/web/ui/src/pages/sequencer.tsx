import { useMemo, useState } from "react";
import { CircleStop, Play, Radio } from "lucide-react";
import { toast } from "sonner";
import {
  SEQUENCER_ENCODINGS,
  useSequencerAnalyse,
  useSequencerAnalyseTokens,
  useSequencerCapture,
  useStopSequencerCapture,
} from "../lib/data.workbench";
import type { CharacterAnalysis, SequencerAnalysis } from "../lib/types.workbench";
import { HttpEditor } from "../ui/editor";
import { DetailList } from "../ui/json";
import { PageHeader, SectionHeading } from "../ui/layout";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorNotice,
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
      <Fips report={report} />
      <Positions characters={characters} />
    </>
  );
}

export function SequencerPage(): JSX.Element {
  const [source, setSource] = useState("paste");
  const [encoding, setEncoding] = useState("");
  const [tokens, setTokens] = useState("");
  const [captureId, setCaptureId] = useState("");
  const [attached, setAttached] = useState("");

  const analysePaste = useSequencerAnalyse();
  const analyseTokens = useSequencerAnalyseTokens();
  const capture = useSequencerCapture(attached);
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

  const runCaptured = () =>
    analyseTokens.mutate(
      { tokens: captured, encoding },
      {
        onSuccess: (result) => toast.success(`${result.tokens.toLocaleString()} captured token(s) analysed`),
        onError: (cause) => toast.error(`Analysis failed: ${cause.message}`),
      },
    );

  return (
    <div className="page">
      <PageHeader
        title="Sequencer"
        actions={
          <>
            <Badge tone="info">{source === "paste" ? `${pastedCount} pasted` : `${captured.length} captured`}</Badge>
            <Select
              aria-label="Read token bits as"
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
          {/* Honest state of the backend: the Go port serves the capture accumulator
              (GET /api/sequencer/capture/{id}) but has no loop that fills it, and no
              route to start one, so attaching reports an empty list. */}
          <div className="notice notice-warn">
            This build has no capture loop. The server answers the accumulator for a capture id and accepts a stop, but
            nothing fills it yet, so attaching will honestly report zero tokens until the backend grows a capture phase.
            Until then, drive the tokens out with Repeater or Intruder and paste them into the other tab.
          </div>
          <Toolbar>
            <Input
              aria-label="Capture id to attach to"
              value={captureId}
              inputMode="numeric"
              onChange={(event) => setCaptureId(event.target.value)}
              placeholder="capture id"
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
            <Button
              variant="danger"
              disabled={captured.length === 0 || stopCapture.isPending}
              onClick={() =>
                stopCapture.mutate(undefined, {
                  onSuccess: () => toast.success("Capture stopped"),
                  onError: (cause) => toast.error(`Could not stop the capture: ${cause.message}`),
                })
              }
            >
              <CircleStop size={14} />
              Stop capture
            </Button>
            {attached ? (
              <>
                <Badge tone={capture.isFetching ? "info" : "neutral"}>
                  {capture.isFetching ? "polling" : "idle"}
                </Badge>
                <Badge>{(capture.data?.total ?? 0).toLocaleString()} accumulated</Badge>
              </>
            ) : (
              <span className="field-hint">Not following a capture.</span>
            )}
          </Toolbar>
          {capture.error ? <ErrorNotice error={capture.error} onRetry={() => void capture.refetch()} /> : null}
          {attached && captured.length === 0 && !capture.isLoading ? (
            <Empty
              title="No tokens accumulated"
              detail={`Capture ${attached} is being polled once a second and has produced nothing yet.`}
            />
          ) : null}
        </TabsContent>
      </Tabs>

      {error ? <ErrorNotice error={error} onRetry={source === "paste" ? runPaste : runCaptured} /> : null}

      {report ? (
        <Report report={report} />
      ) : (
        <Empty
          title="No analysis yet"
          detail="Paste a representative sample of session ids or CSRF tokens — a hundred is the conventional floor — then analyse it."
        />
      )}
    </div>
  );
}
