import { useState } from "react";
import { toast } from "sonner";
import {
  HIDDEN_INPUT_KINDS,
  useHiddenInputRun,
  useStartHiddenInputs,
  type HiddenInputKind,
  type HiddenInputRun,
} from "../lib/data.hiddeninputs";
import { useApp } from "../lib/store";
import type { Exchange } from "../lib/types";
import { Badge, Button, Checkbox, ErrorNotice, Field, Input, Modal, Spinner, Toolbar } from "./primitives";
import { SimpleTable } from "./table";

/**
 * "Guess hidden inputs…" — Burp's Param Miner "Guess params" dialog, built in (burpsy-react-ui-wlz8).
 *
 * Opened from the shared exchange row menu, so it lives once at app level and reads its target from
 * the store. The operator picks which kinds to guess, as Burp's submenu makes them pick between
 * GET parameters, cookies, headers and "everything"; nothing is preselected away from them, and an
 * empty selection cannot be started, because the server refuses an empty list rather than reading it
 * as "all".
 *
 * After the start the dialog shows the run itself — its state, the server's one-line summary with
 * every caveat, and what was confirmed — and says plainly that a running run is not a result yet.
 * Confirmed inputs are also filed as "Secret input" issues, and the run is a task on the dashboard.
 */
export function HiddenInputsDialog(): JSX.Element {
  const target = useApp((state) => state.hiddenInputsTarget);
  const setTarget = useApp((state) => state.setHiddenInputsTarget);
  return (
    <Modal
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) setTarget(null);
      }}
      wide
      title={target ? `Guess hidden inputs — #${target.id} ${target.method} ${target.host}${target.path}` : "Guess hidden inputs"}
      description={
        "Sends the request with names from a built-in wordlist added, in batches, and reports a name only " +
        "when the response changes with it and returns to normal without it. Every request is checked " +
        "against the engagement scope. Confirmed inputs are filed as \"Secret input\" issues."
      }
    >
      {/* Keyed by exchange: a new target is a new form, so a previous run's result or error is never
          shown against a different exchange. */}
      {target ? <HiddenInputsForm key={target.id} target={target} /> : null}
    </Modal>
  );
}

function HiddenInputsForm({ target }: { target: Exchange }): JSX.Element {
  const [kinds, setKinds] = useState<Record<HiddenInputKind, boolean>>({ query: true, cookie: true, header: true });
  const [budget, setBudget] = useState("500");
  const [cacheBuster, setCacheBuster] = useState(true);
  const [taskId, setTaskId] = useState<number | null>(null);
  const start = useStartHiddenInputs();
  const run = useHiddenInputRun(taskId);

  const chosen = HIDDEN_INPUT_KINDS.filter((k) => kinds[k.kind]).map((k) => k.kind);
  const budgetNumber = Number(budget);
  const budgetValid = Number.isInteger(budgetNumber) && budgetNumber >= 1 && budgetNumber <= 5000;

  const submit = () => {
    start.mutate(
      { exchange_id: target.id, kinds: chosen, max_requests: budgetNumber, cache_buster: cacheBuster },
      {
        onSuccess: (started) => {
          setTaskId(started.task_id);
          toast.success(`Guessing hidden inputs on #${target.id} — task ${started.task_id} on the dashboard`);
        },
      },
    );
  };

  if (taskId !== null) {
    return (
      <div className="stack">
        <RunView run={run.data} loading={run.isPending} error={run.error} onRetry={() => void run.refetch()} />
      </div>
    );
  }
  return (
    <div className="stack">
      {HIDDEN_INPUT_KINDS.map((k) => (
        <Checkbox
          key={k.kind}
          checked={kinds[k.kind]}
          onCheckedChange={(checked) => setKinds((current) => ({ ...current, [k.kind]: checked }))}
          label={`${k.label} (${k.hint})`}
        />
      ))}
      <Checkbox
        checked={cacheBuster}
        onCheckedChange={setCacheBuster}
        label="Add a cache buster to every request (recommended: keeps guessed headers out of a shared cache)"
      />
      <Field label="Request budget" hint="The run stops here and says how many names it never sent (1–5000).">
        {(id) => <Input id={id} inputMode="numeric" value={budget} onChange={(event) => setBudget(event.target.value)} />}
      </Field>
      {start.error ? <ErrorNotice error={start.error} title="Could not start guessing" /> : null}
      <Toolbar>
        <Button onClick={submit} disabled={chosen.length === 0 || !budgetValid || start.isPending}>
          {start.isPending ? "Starting…" : "Start guessing"}
        </Button>
        {chosen.length === 0 ? <span className="cell-dim">Pick at least one kind to guess.</span> : null}
        {!budgetValid ? <span className="cell-dim">The budget must be a whole number from 1 to 5000.</span> : null}
      </Toolbar>
    </div>
  );
}

const STATE_TONE: Record<string, "neutral" | "good" | "warn" | "bad" | "info"> = {
  running: "info",
  done: "good",
  unstable: "warn",
  budget: "warn",
  stopped: "warn",
  failed: "bad",
};

function RunView({
  run,
  loading,
  error,
  onRetry,
}: {
  run: HiddenInputRun | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}): JSX.Element {
  if (error) return <ErrorNotice error={error} title="Could not read the run" onRetry={onRetry} />;
  if (loading || !run) return <Spinner label="Loading the run" />;
  const result = run.result;
  const neverSent = result ? result.kinds.reduce((sum, k) => sum + k.untested, 0) : 0;
  return (
    <>
      <Toolbar>
        <Badge tone={STATE_TONE[run.state] ?? "neutral"}>{run.state}</Badge>
        {/* A finished run that never sent some names is a floor, not a clean result: say so beside
            the state rather than leaving "done" to stand alone. */}
        {result && neverSent > 0 ? <Badge tone="warn">{neverSent} name(s) never sent</Badge> : null}
        <span>task {run.task_id}</span>
        {result ? (
          <span className="cell-dim">
            {result.requests_sent} of {result.request_budget} requests sent
          </span>
        ) : null}
      </Toolbar>
      <p>{run.state === "running" ? "Running — nothing below is a result yet." : run.summary}</p>
      {result ? (
        result.inputs.length === 0 ? (
          <p className="cell-dim">No hidden input was confirmed. Read the summary above for what was not tested.</p>
        ) : (
          <SimpleTable headers={["Kind", "Name", "Confidence", "Evidence"]}>
            {result.inputs.map((input) => (
              <tr key={`${input.kind}:${input.name}`}>
                <td>{input.kind}</td>
                <td>
                  <code>{input.name}</code>
                  {input.reflected ? <span className="cell-dim"> (reflected)</span> : null}
                </td>
                <td>{input.confidence}</td>
                <td title={input.evidence}>{input.evidence}</td>
              </tr>
            ))}
          </SimpleTable>
        )
      ) : null}
      {result ? (
        <SimpleTable headers={["Kind", "State", "Settled", "Already present", "Unresolved", "Unconfirmed", "Never sent"]}>
          {result.kinds.map((k) => (
            <tr key={k.kind}>
              <td>{k.kind}</td>
              <td title={k.reason}>{k.state}</td>
              <td>
                {k.settled} of {k.candidates}
              </td>
              <td>{k.present}</td>
              <td>{k.unresolved}</td>
              <td>{k.unconfirmed.length}</td>
              <td>{k.untested}</td>
            </tr>
          ))}
        </SimpleTable>
      ) : null}
    </>
  );
}
