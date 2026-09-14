import { useEffect, useMemo, useRef, useState } from "react";
import { CircleStop, Copy, Download, Pause, Play, Radio } from "lucide-react";
import { toast } from "sonner";
import { useApp } from "../lib/store";
import { cookieOptions, formFieldOptions, headerOptions, type TokenOption } from "../lib/sequencer-token-options";
import { copyToClipboard, downloadText } from "../lib/api";
import {
 buildEffectiveEntropyChart,
 runPolyline,
 significanceLabel,
 spreadExceedsChance,
 SIGNIFICANCE_LEVELS,
 type EffectiveEntropyReport,
} from "../lib/sequencer-significance";
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
 SequencerCapture,
 TokenLocation,
 TokenLocationKind,
} from "../lib/types.workbench";
import type { SequencerAnalysisWithEntropy } from "../lib/data.workbench";
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

/** The analyse report as this page reads it, with the effective-entropy curve
 *  (burpsy-react-ui-boq). The field is intersected on in data.workbench.ts rather
 *  than declared on `SequencerAnalysis` itself; see the note there. */
type SequencerAnalysis = SequencerAnalysisWithEntropy;

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
   {/* 3f3: the disclosure the issue requires. Burp's docs describe its FIPS battery as running
       "at each bit position", and its results tab names the failing bits — an operator who knows
       Burp reads this heading the same way. It is not: the thresholds are defined on a 20,000-bit
       SAMPLE, so the stream is cut into blocks and each verdict describes a block — the whole
       stream when the sample spans one. The honest per-position answer lives in Character
       positions above, which IS per bit position (per character position of the token). Saying
       so here is the difference between a caveat an operator can act on and one they discover
       after trusting the verdict. */}
   <div className="notice notice-warn">
    These verdicts describe the <strong>whole bit stream</strong>, not individual bit positions.
    Every FIPS 140-2 threshold is defined on a {fips.block_bits}-bit sample, so the stream is cut
    into {fips.block_bits}-bit blocks and each row reports over those blocks — it cannot name
    which bit positions of the token are weak. For the per-position answer (a fixed prefix, a
    low-entropy counter field), read the Character positions section: it breaks the token down
    at each position explicitly.
   </div>
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

/**
 * The extended battery (burpsy-react-ui-d2g): Burp's four further randomness
 * tests beside the FIPS four. Each row is either a statistic or the reason the
 * sample could not support the test — the same two states the FIPS table uses —
 * and the section says out loud that the grade above is the FIPS battery's, so
 * nobody reads a flagged compression position as a grade change.
 */
function Advanced({ report }: { report: SequencerAnalysis }): JSX.Element | null {
 const advanced = report.advanced;
 if (!advanced?.tests?.length) return null;
 return (
  <Card>
   <SectionHeading title="Extended tests" detail={advanced.summary} />
   <SimpleTable headers={["Test", "Result", "Observed", "Requirement", "Flagged"]}>
    {advanced.tests.map((test) =>
     test.tested ? (
      <tr key={test.id}>
       <td title={test.basis}>{test.name}</td>
       <td>
        <Badge tone={test.passed ? "good" : "bad"}>{test.passed ? "pass" : "fail"}</Badge>
       </td>
       <td className="cell-num">{test.observed}</td>
       <td className="cell-dim">{test.requirement}</td>
       <td className="cell-num">
        {test.flagged} / {test.examined}
       </td>
      </tr>
     ) : (
      <tr key={test.id}>
       <td title={test.basis}>{test.name}</td>
       <td>
        <Badge tone="warn">not tested</Badge>
       </td>
       <td className="cell-dim" colSpan={3}>
        {test.reason}
       </td>
      </tr>
     ),
    )}
   </SimpleTable>
   {advanced.tests.map((test) =>
    test.tested && test.notices?.length ? (
     <div className="field-hint" key={`${test.id}-notices`}>
      <strong>{test.name}:</strong> {test.notices.join(" ")}
     </div>
    ) : null,
   )}
   <div className="field-hint">
    These four do not change the grade above, which is the FIPS 140-2 battery's. A flagged row here is a
    finding about the sample; how far it moves the verdict is a judgement the operator makes.
   </div>
  </Card>
 );
}

/** The plot box, in SVG user units. Scaled by the viewBox, so these are ratios, not pixels. */
const CHART_W = 640;
const CHART_H = 160;

/**
 * The effective-entropy chart (burpsy-react-ui-boq) — Burp's headline Sequencer
 * output, which this page reported as one number and a grade until this section
 * existed.
 *
 * Burp: "The Effective entropy chart shows the number of bits that pass the
 * randomness tests at various significance levels, ranging from > 0.001% to 10%.
 * In most cases, the Effective entropy chart shows that the choice of
 * significance level is not important."
 *
 * Three rules this drawing keeps, each of which is the difference between a chart
 * and a misleading picture:
 *
 *  1. A level the sample cannot answer is a GAP. It is not a point at zero, and
 *     the line is not drawn through it — `buildEffectiveEntropyChart` splits the
 *     curve into runs at every such level, and `sequencer-significance.test.ts`
 *     asserts that it does. A zero there would tell the operator the generator
 *     produced no entropy at that level, which is the opposite of "this sample
 *     cannot say".
 *  2. The y axis tops out at the bit positions EXAMINED, not at the largest count
 *     plotted, so a sample that loses everything renders as a floor rather than a
 *     full chart.
 *  3. The numbers are in a table as well as in the picture. The SVG is decorative
 *     — `aria-hidden` — and the table is the accessible representation, because a
 *     line drawn from fourteen points is not something a screen reader can be
 *     asked to describe, and the reasons behind the absent points only exist in
 *     words anyway.
 */
function EffectiveEntropy({ effective }: { effective: EffectiveEntropyReport }): JSX.Element | null {
 const [showAll, setShowAll] = useState(false);
 const chart = useMemo(() => buildEffectiveEntropyChart(effective?.curve ?? []), [effective]);
 if (!effective || !effective.curve?.length) return null;

 const chosen = effective.chosen;
 const headline = chosen?.computed && chosen.bits !== null ? `${chosen.bits} of ${chosen.bits_examined} bit(s)` : "no answer";
 const rows = showAll ? effective.curve : effective.curve.filter((point) => point.chosen || isLadderHighlight(point.significance_percent));

 return (
  <Card>
   <SectionHeading
    title="Effective entropy by significance level"
    detail={`${effective.tokens_used.toLocaleString()} token(s) · ${effective.bit_positions_examined} bit position(s) examined · at ${significanceLabel(effective.significance_percent)}${effective.significance_defaulted ? " (default)" : ""}: ${headline}`}
    actions={
     <Button variant="outline" size="small" aria-pressed={showAll} onClick={() => setShowAll((current) => !current)}>
      {showAll ? "Key levels only" : `All ${effective.curve.length} levels`}
     </Button>
    }
   />

   {chart.marks.length > 0 ? (
    <figure style={{ margin: 0 }}>
     <svg
      viewBox={`0 0 ${CHART_W + 48} ${CHART_H + 28}`}
      width="100%"
      height="200"
      aria-hidden="true"
      focusable="false"
      style={{ display: "block", overflow: "visible" }}
     >
      <g transform="translate(40, 8)">
       {/* The ceiling and the floor: the chart is read against bit positions
           examined, so both are drawn and labelled rather than implied. */}
       <line x1={0} y1={0} x2={CHART_W} y2={0} stroke="var(--line)" strokeDasharray="3 3" />
       <line x1={0} y1={CHART_H} x2={CHART_W} y2={CHART_H} stroke="var(--line-strong)" />
       <line x1={0} y1={0} x2={0} y2={CHART_H} stroke="var(--line-strong)" />
       <text x={-6} y={4} textAnchor="end" fontSize="10" fill="var(--muted)">
        {chart.maxBits}
       </text>
       <text x={-6} y={CHART_H} textAnchor="end" fontSize="10" fill="var(--muted)">
        0
       </text>
       {/* A level with no answer: a dashed column, not a data point. */}
       {chart.gaps.map((gap) => (
        <line
         key={`gap-${gap.percent}`}
         x1={gap.x * CHART_W}
         y1={0}
         x2={gap.x * CHART_W}
         y2={CHART_H}
         stroke="var(--muted)"
         strokeDasharray="2 4"
         opacity={0.5}
        />
       ))}
       {chart.runs.map((run, index) => (
        <polyline
         key={`run-${index}`}
         points={runPolyline(run, CHART_W, CHART_H)}
         fill="none"
         stroke="var(--accent)"
         strokeWidth={2}
        />
       ))}
       {chart.marks.map((mark) => (
        <circle
         key={`mark-${mark.percent}`}
         cx={mark.x * CHART_W}
         cy={(1 - mark.y) * CHART_H}
         r={mark.chosen ? 5 : 3}
         fill={mark.chosen ? "var(--accent-bright)" : "var(--accent)"}
         stroke={mark.chosen ? "var(--ink)" : "none"}
        />
       ))}
       {[...chart.marks, ...chart.gaps].map((point) =>
        isLadderHighlight(point.percent) || point.chosen ? (
         <text
          key={`tick-${point.percent}`}
          x={point.x * CHART_W}
          y={CHART_H + 16}
          textAnchor="middle"
          fontSize="10"
          fill="var(--muted)"
         >
          {significanceLabel(point.percent)}
         </text>
        ) : null,
       )}
      </g>
     </svg>
     <figcaption className="field-hint">
      Significance level, logarithmic, from {significanceLabel(effective.curve[0]?.significance_percent ?? 0.001)} on the
      left to {significanceLabel(effective.curve[effective.curve.length - 1]?.significance_percent ?? 10)} on the right.
      A dashed column is a level this sample cannot answer — the line breaks there rather than being drawn through a
      value that does not exist. The table below carries every number in the picture.
     </figcaption>
    </figure>
   ) : (
    <div className="notice notice-warn">
     No level in the chart&apos;s range could be answered by this sample, so there is nothing to draw. That is an absence,
     not a curve at zero — the table below says why for each level.
    </div>
   )}

   <SimpleTable headers={["Level", "Effective entropy", "Rejected", "Expected by chance", "Note"]}>
    {rows.map((point) => (
     <tr key={point.significance_percent}>
      <td className="cell-num">
       {significanceLabel(point.significance_percent)}
       {point.chosen ? <Badge tone="info">chosen</Badge> : null}
      </td>
      <td className="cell-num">
       {point.computed && point.bits !== null ? (
        <>
         {point.bits} / {point.bits_examined} bit(s)
        </>
       ) : (
        <Badge tone="warn">insufficient sample</Badge>
       )}
      </td>
      <td className="cell-num">{point.computed && point.bits_rejected !== null ? point.bits_rejected : "—"}</td>
      <td className="cell-num">
       {point.computed && point.expected_chance_rejections !== null
        ? point.expected_chance_rejections.toFixed(2)
        : "—"}
      </td>
      <td className="cell-dim">{point.computed ? "" : point.reason}</td>
     </tr>
    ))}
   </SimpleTable>
   {!showAll && rows.length < effective.curve.length ? (
    <p className="field-hint">
     {effective.curve.length - rows.length} more level(s) not shown. The chart above draws all of them.
    </p>
   ) : null}

   {/* `robust` on the server is strict equality, which is the honest reading of "the
       choice of level does not change this verdict". It is not the right thing to style
       as a warning: a healthy sample loses a position or two at 5% and 10% to the
       level's own false-positive rate, and colouring that red would call an artefact a
       defect. The warn styling is reserved for movement larger than chance explains. */}
   <div className={spreadExceedsChance(effective.curve) ? "notice notice-warn" : "notice"}>
    {effective.robustness_note}
   </div>

   <div className="field-hint">
    <strong>What this number is.</strong> {effective.definition} Tests run at each bit position:{" "}
    {effective.tests.join("; ")}. No multiple-comparison correction is applied — correcting would flatten the slope this
    chart exists to show — so read every loss against the &quot;expected by chance&quot; column beside it.
   </div>
   {effective.bit_positions_skipped_variable_length > 0 ? (
    <div className="field-hint">
     {effective.bit_positions_skipped_variable_length} bit position(s) present in the longest token but not the shortest
     were excluded: they have a smaller sample than the rest, and testing them against this sample size would
     manufacture a rejection.
    </div>
   ) : null}
   {effective.positions_truncated ? (
    <div className="notice notice-warn">
     Only the first {effective.bit_positions_examined} bit positions were examined. The counts above are out of that
     number, not out of the whole token.
    </div>
   ) : null}
   <div className="field-hint">
    <strong>Against the FIPS grade.</strong> {effective.fips_agreement}
   </div>
  </Card>
 );
}

/** The levels labelled on the axis and listed by default: the ends of Burp's range and
 *  the ends of the two bands it names, which is as many labels as fit without overlapping. */
function isLadderHighlight(percent: number): boolean {
 return percent === 0.001 || percent === 0.002 || percent === 0.03 || percent === 0.1 || percent === 1 || percent === 5 || percent === 10;
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
   <EffectiveEntropy effective={report.effective_entropy} />
   <ExtraStats report={report} />
   <Fips report={report} />
   <Advanced report={report} />
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
 // The operator's significance level (burpsy-react-ui-boq). "" means "the server's
 // default", the same idiom the encoding select uses for "detect" — and the report
 // says `significance_defaulted` back, so the page can label it as the default
 // rather than implying a choice was made.
 const [significancePercent, setSignificancePercent] = useState("");
 const [tokens, setTokens] = useState("");
 // Burp's Manual load offers Paste AND Load (burpsy-react-ui-ts3v): the hidden input is the
 // file affordance, the same pattern app.tsx uses for configuration import. Read as text —
 // the editor's value is text, and a binary file shows its replacement characters honestly.
 const loadInputRef = useRef<HTMLInputElement | null>(null);
 // Length-deviation filter (burpsy-react-ui-rcs): empty string is off, a number enables it.
 const [deviates, setDeviates] = useState("");
 const [captureId, setCaptureId] = useState("");
 const [attached, setAttached] = useState("");

 const [captureTarget, setCaptureTarget] = useState("");
 const [captureRequest, setCaptureRequest] = useState("");
 // Send to Sequencer (fhp): a hand-off from the row context menu lands here once and is
 // consumed immediately — the seed is session-only, and a second visit to the page must not
 // re-offer yesterday's request.
 const sequencerSeed = useApp((state) => state.sequencerSeed);
 const setSequencerSeed = useApp((state) => state.setSequencerSeed);
 useEffect(() => {
  if (!sequencerSeed) return;
  setCaptureRequest(sequencerSeed.request);
  setCaptureTarget(sequencerSeed.target);
  setSequencerSeed(null);
  toast.success(`Loaded ${sequencerSeed.label} — pick the token location, then Start live capture`);
 }, [sequencerSeed, setSequencerSeed]);

 // The picker's contents (6t8): the cookies, headers and form fields actually present in the
 // response that arrived with the hand-off. Empty when the seed carried no response — the
 // typed inputs remain the path then, exactly as before.
 const [seedResponse, setSeedResponse] = useState<string | null>(null);
 useEffect(() => {
  setSeedResponse(sequencerSeed?.response ?? null);
 }, [sequencerSeed]);
 const locationOptions = useMemo(
  () => ({
   cookie: seedResponse ? cookieOptions(seedResponse) : [],
   header: seedResponse ? headerOptions(seedResponse) : [],
   form_field: seedResponse ? formFieldOptions(seedResponse) : [],
  }),
  [seedResponse],
 );

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
   { text: tokens, encoding, significancePercent },
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
    ...(Number.isFinite(Number(deviates)) && Number(deviates) > 0
     ? { length_deviates: { enable: true, chars: Number(deviates) } }
     : {}),
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
   { tokens: captured, encoding, significancePercent },
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
    { tokens: captured, encoding, significancePercent },
    {
     onSuccess: (result) => toast.message(`Auto-analysis over ${result.tokens.toLocaleString()} token(s)`),
     onError: (cause) => toast.error(`Auto-analysis failed: ${cause.message}`),
    },
   );
  }, 30_000);
  return () => window.clearInterval(timer);
  // analyseTokens identity changes with its internals; the interval only needs the trigger.
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [autoAnalyse, capture.data?.capturing, captured.length, encoding, significancePercent]);

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
      {/* The significance level is the operator's input to the whole analysis, not a
          display option — Burp: "you can choose the probability you use to interpret
          the randomness of your findings". It sits beside the encoding because both
          are decisions the analysis is run UNDER, and both are echoed back in the
          report so a quoted finding carries them. The two bands are the ones Burp
          names; the analysis still draws the whole curve whatever is picked here. */}
      <Select
       aria-label="Significance level"
       title="Significance level: the probability below which a bit position is judged non-random"
       value={significancePercent}
       onChange={(event) => setSignificancePercent(event.target.value)}
       style={{ maxWidth: "var(--w-sm)" }}
      >
       <option value="">significance: default (1%)</option>
       {SIGNIFICANCE_LEVELS.map((level) => (
        <option key={level.percent} value={String(level.percent)}>
         {level.label}
         {level.band ? ` — ${level.band}` : ""}
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
       <Field
        label="Token location"
        hint={
         seedResponse
          ? "The lists below are what the handed-off response actually contains — you pick; nothing is auto-selected."
          : "No response arrived with this capture, so the names are typed: run the request once (or Send to Sequencer from history) to populate the pickers."
        }
       >
        {(id) => (
         <Select id={id} value={locationKind} onChange={(event) => setLocationKind(event.target.value as TokenLocationKind)}>
          <option value="cookie">Set-Cookie value</option>
          <option value="header">Response header value</option>
          <option value="form_field">Form field value</option>
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
        <Field
         label={locationKind === "cookie" ? "Cookie name" : locationKind === "form_field" ? "Form field name" : "Header name"}
         hint={
          seedResponse
           ? "Pick from what the response carries, or switch to free text."
           : "Typed: no response arrived with this capture to pick from."
         }
        >
         {(id) =>
          locationOptions[locationKind].length > 0 ? (
           <Select id={id} value={locationName} onChange={(event) => setLocationName(event.target.value)}>
            <option value="" disabled>
             {locationOptions[locationKind].length} found in the response — pick one
            </option>
            {locationOptions[locationKind].map((option: TokenOption) => (
             <option key={option.name.toLowerCase()} value={option.name}>
              {option.name} — {option.excerpt}
             </option>
            ))}
           </Select>
          ) : (
           <Input
            id={id}
            value={locationName}
            onChange={(event) => setLocationName(event.target.value)}
            placeholder={locationKind === "cookie" ? "SESSIONID" : "X-Csrf-Token"}
           />
          )
         }
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
        {/* Burp's "Ignore token whose length deviates by X characters" (burpsy-react-ui-rcs).
            Empty = off. The deviation is measured against the running average of accepted tokens. */}
        <Field label="Ignore length deviates ±" style={{ maxWidth: "var(--w-xs)" }}>
         {(id) => (
          <Input
           id={id}
           value={deviates}
           inputMode="numeric"
           onChange={(event) => setDeviates(event.target.value)}
           placeholder="off"
           title="Drop tokens whose length differs from the running average by more than this many characters. The application occasionally returns a different item where the token normally appears — this keeps it out of the sample."
          />
         )}
        </Field>
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
