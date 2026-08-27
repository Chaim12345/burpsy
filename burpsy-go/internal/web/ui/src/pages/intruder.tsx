import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Crosshair, Plus, Search, Trash2, Zap } from "lucide-react";
import { toast } from "sonner";
import { formatBytes, formatCount, formatDuration, statusTone } from "../lib/api";
import { useIntruderPoints, useIntruderRun } from "../lib/data.tools";
import { useMessage } from "../lib/data";
import { useApp } from "../lib/store";
import {
  ATTACK_MODES,
  HASH_ALGORITHMS,
  PAYLOAD_LAYERS,
  PAYLOAD_RULES,
  emptyRule,
  estimateRequests,
  type AttackMode,
  type PayloadRuleName,
  type PayloadRuleSpec,
  type PointView,
  type RunView,
} from "../lib/types.tools";
import { HttpEditor } from "../ui/editor";
import { PageHeader, SectionHeading } from "../ui/layout";
import { JsonView } from "../ui/json";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Empty,
  ErrorNotice,
  Field,
  IconButton,
  Input,
  Select,
  Switch,
  Textarea,
  Tooltip,
} from "../ui/primitives";
import { SimpleTable } from "../ui/table";

const DEFAULT_PAYLOADS = "admin\nroot\ntest\n' OR 1=1--\n../../etc/passwd";

function countPayloads(text: string): number {
  return text.split("\n").filter((line) => line.trim() !== "").length;
}

function payloadList(text: string): string[] {
  return text.split("\n").filter((line) => line.trim() !== "");
}

/** Editor for one payload processing rule; the visible fields depend on the rule. */
function RuleRow({
  rule,
  index,
  onChange,
  onRemove,
}: {
  rule: PayloadRuleSpec;
  index: number;
  onChange: (next: PayloadRuleSpec) => void;
  onRemove: () => void;
}): JSX.Element {
  const spec = PAYLOAD_RULES.find((entry) => entry.value === rule.rule);
  const uses = spec?.uses ?? [];
  return (
    <div className="rule-row">
      <span className="cell-dim">{index + 1}</span>
      <Select
        aria-label={`Rule ${index + 1} operation`}
        value={rule.rule}
        onChange={(event) => onChange({ ...emptyRule(event.target.value as PayloadRuleName) })}
      >
        {PAYLOAD_RULES.map((entry) => (
          <option key={entry.value} value={entry.value}>
            {entry.label}
          </option>
        ))}
      </Select>
      {uses.includes("text") ? (
        <Input
          aria-label={`Rule ${index + 1} text`}
          placeholder="text"
          value={rule.text}
          onChange={(event) => onChange({ ...rule, text: event.target.value })}
        />
      ) : null}
      {uses.includes("pattern") ? (
        <Input
          aria-label={`Rule ${index + 1} pattern`}
          placeholder="regex pattern"
          value={rule.pattern}
          onChange={(event) => onChange({ ...rule, pattern: event.target.value })}
        />
      ) : null}
      {uses.includes("replace") ? (
        <Input
          aria-label={`Rule ${index + 1} replacement`}
          placeholder="replacement ($1 for a group)"
          value={rule.replace}
          onChange={(event) => onChange({ ...rule, replace: event.target.value })}
        />
      ) : null}
      {uses.includes("layer") ? (
        <Select
          aria-label={`Rule ${index + 1} codec`}
          value={rule.layer}
          onChange={(event) => onChange({ ...rule, layer: event.target.value })}
        >
          {PAYLOAD_LAYERS.map((layer) => (
            <option key={layer} value={layer}>
              {layer}
            </option>
          ))}
        </Select>
      ) : null}
      {uses.includes("algorithm") ? (
        <Select
          aria-label={`Rule ${index + 1} algorithm`}
          value={rule.algorithm}
          onChange={(event) => onChange({ ...rule, algorithm: event.target.value })}
        >
          {HASH_ALGORITHMS.map((algorithm) => (
            <option key={algorithm} value={algorithm}>
              {algorithm}
            </option>
          ))}
        </Select>
      ) : null}
      {uses.includes("all") ? (
        <Checkbox checked={rule.all} onCheckedChange={(all) => onChange({ ...rule, all })} label="every match" />
      ) : null}
      <IconButton label={`Remove rule ${index + 1}`} size="small" onClick={onRemove}>
        <Trash2 size={13} />
      </IconButton>
    </div>
  );
}

/**
 * The attack report, presented as accounting rather than a payload dump: every
 * bound the engine applied (capped, truncated, skipped, unbucketed) is shown, so
 * a small result set is never mistaken for a complete one.
 */
function AttackResult({ view, examples }: { view: RunView; examples: Map<number, string[]> }): JSX.Element {
  const { report, payload_sets: sets } = view;
  const caveats = [
    report.truncated ? `Capped at ${formatCount(report.max_requests)} requests` : null,
    !report.combinations_exact ? "Combination count is a floor, not an exact total" : null,
    report.buckets_truncated ? "Result buckets were truncated" : null,
    report.unbucketed ? `${formatCount(report.unbucketed)} results outside the shown buckets` : null,
    report.attempts.length < report.sent ? `Per-attempt detail limited to ${formatCount(report.detail_limit)} rows` : null,
    report.auto_throttle_engaged ? `Auto-throttle engaged ${report.auto_throttle_engaged}×` : null,
  ].filter((value): value is string => value !== null);

  return (
    <>
      <div className="metric-grid">
        <Badge tone="neutral" className="sr-only">
          report
        </Badge>
        <div className="card metric metric-accent">
          <span>Sent</span>
          <strong>{formatCount(report.sent)}</strong>
          <small>of {formatCount(report.planned)} planned</small>
        </div>
        <div className="card metric">
          <span>Combinations</span>
          <strong>
            {formatCount(report.combinations)}
            {report.combinations_exact ? "" : "+"}
          </strong>
          <small>{report.combinations_exact ? "exact" : "floor — saturated"}</small>
        </div>
        <div className={report.failed ? "card metric metric-bad" : "card metric"}>
          <span>Failed</span>
          <strong>{formatCount(report.failed)}</strong>
          <small>{report.errors.length} distinct errors</small>
        </div>
        <div className="card metric">
          <span>Elapsed</span>
          <strong>{formatDuration(report.elapsed_ms)}</strong>
          <small>{report.grep_matched ? `${formatCount(report.grep_matched)} grep matches` : "mode " + report.kind}</small>
        </div>
      </div>

      {caveats.length ? (
        <div className="notice notice-warn">
          <AlertTriangle size={15} />
          <div>
            <strong>Bounds applied to this attack.</strong>
            <ul style={{ margin: "4px 0 0", paddingLeft: 16 }}>
              {caveats.map((caveat) => (
                <li key={caveat}>{caveat}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      <Card>
        <SectionHeading
          title="Result buckets"
          detail="Responses grouped by status, length and reflection. Interesting rows are the ones that differ from the crowd."
        />
        {report.buckets.length ? (
          <SimpleTable headers={["Status", "Length", "Reflected", "Count", "Grep", "First payload"]}>
            {report.buckets.map((bucket) => (
              <tr key={`${bucket.status}-${bucket.response_len}-${bucket.first_ordinal}`}>
                <td>
                  {bucket.status === null ? <Badge tone="bad">error</Badge> : <Badge tone={statusTone(bucket.status)}>{bucket.status}</Badge>}
                </td>
                <td>
                  <span className="cell-num">{formatBytes(bucket.response_len)}</span>
                </td>
                <td>{bucket.reflected ? <Badge tone="warn">reflected</Badge> : <span className="cell-dim">no</span>}</td>
                <td>
                  <span className="cell-num">{formatCount(bucket.count)}</span>
                </td>
                <td>
                  {bucket.grep_matches ? <Badge tone="info">{bucket.grep_matches}</Badge> : <span className="cell-dim">—</span>}
                  {bucket.grep_extract ? <code title={bucket.grep_extract}> {bucket.grep_extract}</code> : null}
                </td>
                <td>
                  <code title={(examples.get(bucket.first_ordinal) ?? []).join(" | ")}>
                    {(examples.get(bucket.first_ordinal) ?? [`#${bucket.first_ordinal}`]).join(" | ")}
                  </code>
                </td>
              </tr>
            ))}
          </SimpleTable>
        ) : (
          <Empty title="No buckets" detail="The attack produced no grouped responses." />
        )}
      </Card>

      {report.errors.length ? (
        <Card>
          <SectionHeading title="Errors" detail="Grouped by message, with the first attempt that hit each." />
          <SimpleTable headers={["Error", "Count", "First ordinal"]}>
            {report.errors.map((bucket) => (
              <tr key={bucket.error} className="row-flag-bad">
                <td title={bucket.error}>{bucket.error}</td>
                <td>
                  <span className="cell-num">{formatCount(bucket.count)}</span>
                </td>
                <td>
                  <span className="cell-num">{bucket.first_ordinal ?? "—"}</span>
                </td>
              </tr>
            ))}
          </SimpleTable>
        </Card>
      ) : null}

      <Card>
        <SectionHeading title="Payload set accounting" detail="What each set produced, and what was bounded away." />
        {sets.length ? (
          <SimpleTable headers={["Set", "Kind", "Used", "Described", "Truncated", "Skipped", "Dropped because"]}>
            {sets.map((set, index) => (
              <tr key={`${set.kind}-${index}`}>
                <td>{index + 1}</td>
                <td>
                  <Badge>{set.kind}</Badge>
                </td>
                <td>
                  <span className="cell-num">{formatCount(set.count)}</span>
                </td>
                <td>
                  <span className="cell-num">
                    {formatCount(set.total)}
                    {set.total_exact ? "" : "+"}
                  </span>
                </td>
                <td>{set.truncated ? <Badge tone="warn">at {formatCount(set.max_count)}</Badge> : <span className="cell-dim">no</span>}</td>
                <td>
                  <span className="cell-num">{formatCount(set.skipped)}</span>
                </td>
                <td>
                  {set.dropped.length ? (
                    set.dropped.map((reason) => (
                      <Badge tone="warn" key={reason.reason}>
                        {reason.reason} ×{reason.count}
                      </Badge>
                    ))
                  ) : (
                    <span className="cell-dim">—</span>
                  )}
                </td>
              </tr>
            ))}
          </SimpleTable>
        ) : (
          <Empty title="No set accounting" detail="The server reported no per-set breakdown." />
        )}
      </Card>

      {report.attempts.length ? (
        <Card>
          <SectionHeading
            title="Attempts"
            detail={`Per-request detail, capped by the server at ${formatCount(report.detail_limit)} rows.`}
          />
          <SimpleTable headers={["#", "Status", "Length", "Time", "Reflected", "Grep", "Error"]}>
            {report.attempts.map((attempt) => (
              <tr key={attempt.ordinal} className={attempt.error ? "row-flag-bad" : undefined}>
                <td>
                  <span className="cell-num">{attempt.ordinal}</span>
                </td>
                <td>
                  {attempt.status === null ? <Badge tone="bad">—</Badge> : <Badge tone={statusTone(attempt.status)}>{attempt.status}</Badge>}
                </td>
                <td>
                  <span className="cell-num">{formatBytes(attempt.response_len)}</span>
                </td>
                <td>
                  <span className="cell-num">{formatDuration(attempt.duration_ms)}</span>
                </td>
                <td>{attempt.reflected ? <Badge tone="warn">yes</Badge> : <span className="cell-dim">no</span>}</td>
                <td>{attempt.grep_matched ? <Badge tone="info">match</Badge> : <span className="cell-dim">—</span>}</td>
                <td title={attempt.error ?? ""}>{attempt.error ?? <span className="cell-dim">—</span>}</td>
              </tr>
            ))}
          </SimpleTable>
        </Card>
      ) : null}
    </>
  );
}

export function IntruderPage(): JSX.Element {
  const seed = useApp((state) => state.intruderSeed);
  const setIntruderSeed = useApp((state) => state.setIntruderSeed);

  const [msgId, setMsgId] = useState("");
  const [target, setTarget] = useState("");
  const [label, setLabel] = useState("");
  const [mode, setMode] = useState<AttackMode>("sniper");
  const [allPoints, setAllPoints] = useState(false);
  const [points, setPoints] = useState<PointView[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [payloadTexts, setPayloadTexts] = useState<string[]>([DEFAULT_PAYLOADS]);
  const [payloadTypes, setPayloadTypes] = useState<("list" | "numbers" | "file")[]>(["list"]);
  const [payloadNumbers, setPayloadNumbers] = useState<{ from: string; to: string; step: string }[]>([{ from: "1", to: "100", step: "1" }]);
  const [payloadFiles, setPayloadFiles] = useState<string[]>([""]);
  const [rules, setRules] = useState<PayloadRuleSpec[]>([]);
  const [grepMatch, setGrepMatch] = useState("");
  const [grepExtract, setGrepExtract] = useState("");
  const [maxRequests, setMaxRequests] = useState(1000);
  const [maxInFlight, setMaxInFlight] = useState(8);
  const [rps, setRps] = useState("");
  const [result, setResult] = useState<RunView | null>(null);
  const [legacyResult, setLegacyResult] = useState<unknown>(null);
  const [tab, setTab] = useState("positions");

  const discover = useIntruderPoints();
  const run = useIntruderRun();
  const baseMessage = useMessage(msgId ? Number(msgId) : null);

  // A send-to handoff from History or Repeater arrives through the store.
  useEffect(() => {
    if (!seed) return;
    if (seed.msgId !== null) setMsgId(String(seed.msgId));
    setTarget(seed.target);
    setLabel(seed.label);
    setPoints([]);
    setSelected([]);
    setResult(null);
    setIntruderSeed(null);
  }, [seed, setIntruderSeed]);

  const setsNeeded = mode === "sniper" || mode === "battering_ram" ? 1 : Math.max(1, selected.length);

  // Keep the payload-set count in step with the mode and the chosen positions.
  useEffect(() => {
    setPayloadTexts((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => "")];
    });
    setPayloadTypes((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => "list" as const)];
    });
    setPayloadNumbers((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => ({ from: "1", to: "100", step: "1" }))];
    });
    setPayloadFiles((current) => {
      if (current.length === setsNeeded) return current;
      if (current.length > setsNeeded) return current.slice(0, setsNeeded);
      return [...current, ...Array.from({ length: setsNeeded - current.length }, () => "")];
    });
  }, [setsNeeded]);

  const setSizes = useMemo(() => {
    return payloadTypes.map((t, i) => {
      if (t === "numbers") {
        const n = payloadNumbers[i];
        if (!n) return 0;
        const from = Number(n.from), to = Number(n.to), step = Number(n.step) || 1;
        if (!Number.isFinite(from) || !Number.isFinite(to) || step === 0) return 0;
        return Math.floor(Math.abs(to - from) / Math.abs(step)) + 1;
      }
      if (t === "file") return 1; // unknown until resolved server-side; 1 keeps canRun true
      return countPayloads(payloadTexts[i] ?? "");
    });
  }, [payloadTypes, payloadTexts, payloadNumbers, payloadFiles]);
  const estimate = useMemo(() => estimateRequests(mode, selected.length, setSizes), [mode, selected.length, setSizes]);
  const examples = useMemo(
    () => new Map((result?.examples ?? []).map((example) => [example.first_ordinal, example.payloads])),
    [result],
  );

  // `>= 0` and an integer check: message ids count from zero, so message 0 is a real base request —
  // `> 0` disabled Discover for it, and a decimal typed by accident passed.
  const canDiscover = msgId.trim() !== "" && Number.isInteger(Number(msgId)) && Number(msgId) >= 0;
  const canRun =
    canDiscover && target.trim() !== "" && selected.length > 0 && setSizes.every((size) => size > 0) && !run.isPending;

  const onDiscover = () => {
    setSelected([]);
    setPoints([]);
    discover.mutate(
      { msg_id: Number(msgId), all: allPoints },
      {
        onSuccess: (found) => {
          setPoints(found);
          if (!found.length) toast.error("No insertion points were found in that message");
          else toast.success(`${found.length} insertion ${found.length === 1 ? "point" : "points"} found`);
        },
        onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
      },
    );
  };

  const onRun = () => {
    setResult(null);
    setLegacyResult(null);
    const useSources = payloadTypes.some((t) => t !== "list");
    const body: Record<string, unknown> = {
      msg_id: Number(msgId),
      target: target.trim(),
      all: allPoints,
      mode,
      points: selected,
      max_requests: maxRequests,
      max_in_flight: maxInFlight,
      ...(rules.length ? { payload_rules: rules } : {}),
      ...(grepMatch.trim() ? { grep_match: grepMatch.trim() } : {}),
      ...(grepExtract.trim() ? { grep_extract: grepExtract.trim() } : {}),
      ...(rps.trim() ? { rps: Number(rps) } : {}),
    };
    if (useSources) {
      body.payload_sources = payloadTypes.map((t, i) => {
        if (t === "numbers") {
          const n = payloadNumbers[i] ?? { from: "1", to: "100", step: "1" };
          return { type: "numbers", from: Number(n.from), to: Number(n.to), step: Number(n.step) || 1 };
        }
        if (t === "file") {
          return { type: "file", filename: (payloadFiles[i] ?? "").trim() };
        }
        return { type: "list", items: payloadList(payloadTexts[i] ?? "") };
      });
    } else {
      body.payload_sets = payloadTexts.map(payloadList);
    }
    run.mutate(body as unknown as Parameters<typeof run.mutate>[0], {
      onSuccess: (payload) => {
        // Naming a mode always selects the full report shape, but stay defensive:
        // an older server could still answer with the flat legacy array.
        if (payload && typeof payload === "object" && "report" in payload) {
          const view = payload as RunView;
          setResult(view);
          setTab("results");
          toast.success(`${formatCount(view.report.sent)} requests sent in ${formatDuration(view.report.elapsed_ms)}`);
        } else {
          setLegacyResult(payload);
          setTab("results");
          toast.success("Attack finished");
        }
      },
      onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
    });
  };

  const overBudget = estimate.count > maxRequests;

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Intruder"
          description={label || "Payload-driven attacks with explicit bounds and honest result accounting."}
          actions={
            <>
              <Badge tone={overBudget ? "warn" : "neutral"}>
                {formatCount(estimate.count)} request{estimate.count === 1 ? "" : "s"}
              </Badge>
              <Tooltip content={canRun ? "Run the attack" : "Choose a message, target, positions and payloads first"}>
                <button type="button" className="button button-primary" onClick={onRun} disabled={!canRun}>
                  <Zap size={14} />
                  {run.isPending ? "Attacking…" : "Launch attack"}
                </button>
              </Tooltip>
            </>
          }
        />

        {overBudget ? (
          <div className="notice notice-warn" style={{ marginTop: "var(--s2)" }}>
            <AlertTriangle size={15} />
            <div>
              This configuration implies {formatCount(estimate.count)} requests but the cap is{" "}
              {formatCount(maxRequests)}. The server will stop at the cap and mark the report truncated. Raise the cap or
              narrow the payload sets.
            </div>
          </div>
        ) : null}
      </div>

      {/* Burp splits Intruder across Positions / Payloads / Resource pool / Settings.
          Same split here, so the muscle memory carries over. */}
      <Tabs value={tab} onValueChange={setTab} className="tool-panel">
        <TabsList aria-label="Intruder configuration">
          <TabsTrigger value="positions">Positions</TabsTrigger>
          <TabsTrigger value="payloads">Payloads</TabsTrigger>
          <TabsTrigger value="pool">Resource pool</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="results">
            Results{result ? ` (${formatCount(result.report.sent)})` : ""}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="positions" className="tool-pane">
          <Card>
            <SectionHeading
              title="Base request"
              detail="A stored message id supplies the request that payloads are spliced into."
            />
            <div className="form-grid">
              <Field label="Stored message id">
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={1}
                    value={msgId}
                    onChange={(event) => {
                      setMsgId(event.target.value);
                      setPoints([]);
                      setSelected([]);
                    }}
                    placeholder="e.g. 42"
                  />
                )}
              </Field>
              <Field label="Target authority">
                {(id) => <Input id={id} value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://host:443" />}
              </Field>
              <Field label="Attack type">
                {(id) => (
                  <Select id={id} value={mode} onChange={(event) => setMode(event.target.value as AttackMode)}>
                    {ATTACK_MODES.map((entry) => (
                      <option key={entry.value} value={entry.value}>
                        {entry.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
            <p className="field-hint">{ATTACK_MODES.find((entry) => entry.value === mode)?.detail}</p>

            <div className="toolbar">
              <label className="check-row">
                <Switch
                  checked={allPoints}
                  onCheckedChange={(next) => {
                    setAllPoints(next);
                    setPoints([]);
                    setSelected([]);
                  }}
                  label="Include every candidate position"
                />
                <span>Every candidate position</span>
              </label>
              <Button variant="outline" onClick={onDiscover} disabled={!canDiscover || discover.isPending}>
                <Search size={14} />
                {discover.isPending ? "Scanning…" : "Find positions"}
              </Button>
            </div>

            {discover.error ? <ErrorNotice error={discover.error} onRetry={onDiscover} /> : null}

            {points.length ? (
              <div className="row-list point-list">
                {points.map((point) => {
                  const on = selected.includes(point.index);
                  const order = selected.indexOf(point.index);
                  return (
                    <label className="point-row" key={point.index}>
                      <input
                        type="checkbox"
                        checked={on}
                        aria-label={`Use position ${point.label}`}
                        onChange={(event) =>
                          setSelected((current) =>
                            event.target.checked
                              ? [...current, point.index]
                              : current.filter((index) => index !== point.index),
                          )
                        }
                      />
                      <span>
                        <strong>{point.label}</strong>
                        <small>
                          {point.kind} · offset {point.offset} · {point.current || "(empty)"}
                        </small>
                      </span>
                      {on && (mode === "pitchfork" || mode === "cluster_bomb") ? (
                        <Badge tone="accent">set {order + 1}</Badge>
                      ) : null}
                    </label>
                  );
                })}
              </div>
            ) : canDiscover ? (
              <Empty title="No positions loaded" detail="Find positions before launching an attack." />
            ) : (
              <Empty
                title="No base request"
                detail="Enter a stored message id, or right-click a row in HTTP history and choose “Send to Intruder”."
              />
            )}
          </Card>

          {/* Rendered as soon as a message id exists, not once the fetch resolves, so
              the form never jumps out from under the pointer mid-click. */}
          {msgId ? (
            <Card className="card-flush tool-pane-fill">
              <HttpEditor
                label={`Base request · message ${msgId}`}
                readOnly
                value={
                  baseMessage.data?.text ??
                  (baseMessage.isFetching
                    ? "Loading the base request…"
                    : baseMessage.error
                      ? `Could not load message ${msgId}.`
                      : "No bytes stored for this message.")
                }
                filename={`intruder-base-${msgId}.txt`}
              />
            </Card>
          ) : null}
        </TabsContent>

        <TabsContent value="payloads" className="tool-pane">
          <Card className="card-flush">
            <div className="card-pad">
              <SectionHeading
                title="Payload sets"
                detail={
                  setsNeeded === 1
                    ? "One payload per line."
                    : `${setsNeeded} sets — one per selected position, in selection order.`
                }
              />
            </div>
            <div className="card-pad stack">
              {Array.from({ length: setsNeeded }, (_, index) => {
                const t = payloadTypes[index] ?? "list";
                return (
                  <Card key={index} className="card-pad" style={{ border: "1px solid var(--line)" }}>
                    <div className="toolbar" style={{ marginBottom: 8 }}>
                      <Field label={setsNeeded === 1 ? `Set (${setSizes[index] ?? 0})` : `Set ${index + 1} (${setSizes[index] ?? 0})`}>
                        {(id) => (
                          <Select
                            id={id}
                            value={t}
                            onChange={(e) =>
                              setPayloadTypes((cur) => cur.map((v, i) => (i === index ? (e.target.value as typeof t) : v)))
                            }
                          >
                            <option value="list">Simple list</option>
                            <option value="numbers">Numbers</option>
                            <option value="file">File (server path)</option>
                          </Select>
                        )}
                      </Field>
                      <Badge tone={t === "list" ? "neutral" : "accent"}>{t}</Badge>
                    </div>
                    {t === "list" ? (
                      <Field label="One payload per line">
                        {(id) => (
                          <Textarea
                            id={id}
                            value={payloadTexts[index] ?? ""}
                            onChange={(event) =>
                              setPayloadTexts((current) =>
                                current.map((value, position) => (position === index ? event.target.value : value)),
                              )
                            }
                            placeholder={index === 0 ? DEFAULT_PAYLOADS : "one payload per line"}
                          />
                        )}
                      </Field>
                    ) : t === "numbers" ? (
                      <div className="form-grid">
                        <Field label="From">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadNumbers[index]?.from ?? "1"}
                              onChange={(e) =>
                                setPayloadNumbers((cur) => cur.map((v, i) => (i === index ? { ...v, from: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="To">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadNumbers[index]?.to ?? "100"}
                              onChange={(e) =>
                                setPayloadNumbers((cur) => cur.map((v, i) => (i === index ? { ...v, to: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                        <Field label="Step">
                          {(id) => (
                            <Input
                              id={id}
                              type="number"
                              value={payloadNumbers[index]?.step ?? "1"}
                              onChange={(e) =>
                                setPayloadNumbers((cur) => cur.map((v, i) => (i === index ? { ...v, step: e.target.value } : v)))
                              }
                            />
                          )}
                        </Field>
                      </div>
                    ) : (
                      <Field label="Server file path" hint="File must exist on server; blank lines skipped">
                        {(id) => (
                          <Input
                            id={id}
                            value={payloadFiles[index] ?? ""}
                            onChange={(e) =>
                              setPayloadFiles((cur) => cur.map((v, i) => (i === index ? e.target.value : v)))
                            }
                            placeholder="/tmp/payloads.txt or ./wordlists/sqli.txt"
                          />
                        )}
                      </Field>
                    )}
                  </Card>
                );
              })}
            </div>
          </Card>

          <Card>
            <SectionHeading
              title="Payload processing"
              detail="Rules run in order on every payload before it is sent."
              actions={
                <Button
                  variant="outline"
                  size="small"
                  onClick={() => setRules((current) => [...current, emptyRule("add_prefix")])}
                >
                  <Plus size={13} />
                  Add rule
                </Button>
              }
            />
            {rules.length ? (
              rules.map((rule, index) => (
                <RuleRow
                  key={index}
                  rule={rule}
                  index={index}
                  onChange={(next) =>
                    setRules((current) => current.map((value, position) => (position === index ? next : value)))
                  }
                  onRemove={() => setRules((current) => current.filter((_, position) => position !== index))}
                />
              ))
            ) : (
              <p className="field-hint">No processing rules. Payloads are sent exactly as written.</p>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="pool" className="tool-pane">
          <Card>
            <SectionHeading
              title="Resource pool"
              detail="An attack is always bounded; these are the limits the engine enforces."
            />
            <div className="form-grid">
              <Field label="Max requests">
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={1}
                    value={maxRequests}
                    onChange={(event) => setMaxRequests(Number(event.target.value) || 1)}
                  />
                )}
              </Field>
              <Field label="Max concurrent requests">
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={1}
                    value={maxInFlight}
                    onChange={(event) => setMaxInFlight(Number(event.target.value) || 1)}
                  />
                )}
              </Field>
              <Field label="Requests per second" hint="Blank leaves it unthrottled.">
                {(id) => (
                  <Input
                    id={id}
                    type="number"
                    min={0}
                    step="0.5"
                    value={rps}
                    onChange={(event) => setRps(event.target.value)}
                    placeholder="unlimited"
                  />
                )}
              </Field>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="tool-pane">
          <Card>
            <SectionHeading
              title="Grep — match and extract"
              detail="Count responses containing a marker, or capture a value out of each response."
            />
            <div className="form-grid">
              <Field label="Grep match" hint="Counts responses containing this string.">
                {(id) => (
                  <Input
                    id={id}
                    value={grepMatch}
                    onChange={(event) => setGrepMatch(event.target.value)}
                    placeholder="error, root:, welcome"
                  />
                )}
              </Field>
              <Field label="Grep extract" hint="Captures the text after this marker.">
                {(id) => <Input id={id} value={grepExtract} onChange={(event) => setGrepExtract(event.target.value)} placeholder="token=" />}
              </Field>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="results" className="tool-pane">
          {run.error ? <ErrorNotice error={run.error} onRetry={onRun} /> : null}

          {result ? <AttackResult view={result} examples={examples} /> : null}

          {legacyResult ? (
            <Card>
              <SectionHeading title="Attack result" detail="This server answered with the legacy per-attempt form." />
              <JsonView value={legacyResult} label="attempts" />
            </Card>
          ) : null}

          {!result && !legacyResult && !run.isPending && !run.error ? (
            <Empty
              title="No attack run yet"
              detail="Pick a base request, choose positions and payloads, then launch. The report shows what was sent and what was bounded away."
              action={
                <Badge tone="info">
                  <Crosshair size={11} />
                  {formatCount(estimate.count)} requests planned
                </Badge>
              }
            />
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}
