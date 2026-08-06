import { Bug, Play } from "lucide-react";
import { useState } from "react";
import { useCrawls, useStartCrawl } from "../lib/data.observe";
import type { CrawlRun } from "../lib/types.observe";
import { Badge, Button, Field, Input, Modal, Switch } from "./primitives";

/**
 * Crawl launcher and coverage report.
 *
 * A crawl is bounded before it starts, and the bounds are part of the form rather than buried in a
 * settings pane, because the honest question an operator is answering here is "how much of this
 * application am I willing to touch, and how hard". The engine enforces every bound and reports what
 * it did with them; this only collects them.
 *
 * Form submission is off by default and says why. That is a requirement, not a default: a crawl that
 * submits forms writes to the application under test.
 */
export function CrawlLauncher(): JSX.Element {
  const [open, setOpen] = useState(false);
  const [seeds, setSeeds] = useState("");
  const [maxRequests, setMaxRequests] = useState("200");
  const [maxDepth, setMaxDepth] = useState("6");
  const [rps, setRps] = useState("5");
  const [submitForms, setSubmitForms] = useState(false);
  const start = useStartCrawl();
  const { data, running } = useCrawls();

  const seedList = seeds
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const launch = () => {
    start.mutate(
      {
        seeds: seedList,
        max_requests: Number(maxRequests) || undefined,
        max_depth: Number(maxDepth) || undefined,
        requests_per_second: Number(rps) || undefined,
        submit_forms: submitForms,
      },
      { onSuccess: () => setOpen(false) },
    );
  };

  const crawls = data?.crawls ?? [];

  return (
    <>
      <Button variant="outline" size="small" onClick={() => setOpen(true)}>
        <Bug size={13} />
        Crawl
        {running ? <Badge tone="info">running</Badge> : null}
      </Button>

      <Modal open={open} onOpenChange={setOpen} title="Crawl" description="Discover content from a seed URL, bounded by the limits you set here.">
        <div className="stack">
          <Field
            label="Seed URLs"
            hint="One per line, or comma separated. Each must be an absolute http or https URL. Only hosts in scope will be fetched."
          >
            <Input
              value={seeds}
              placeholder="https://target.test/"
              onChange={(event) => setSeeds(event.target.value)}
            />
          </Field>

          <div className="form-grid">
            <Field label="Max requests" hint="The bound that actually governs cost.">
              <Input type="number" min={1} value={maxRequests} onChange={(event) => setMaxRequests(event.target.value)} />
            </Field>
            <Field label="Max depth" hint="Links from a seed. A seed is depth 0.">
              <Input type="number" min={1} value={maxDepth} onChange={(event) => setMaxDepth(event.target.value)} />
            </Field>
            <Field label="Requests per second" hint="Blank or 0 takes the engine default.">
              <Input type="number" min={0} step="0.5" value={rps} onChange={(event) => setRps(event.target.value)} />
            </Field>
          </div>

          <Field label="Submit forms" hint="Off by default on purpose: a crawl that submits forms writes to the application under test.">
            <Switch checked={submitForms} onCheckedChange={setSubmitForms} label="Submit discovered forms" />
          </Field>

          {start.error ? <div className="notice notice-warn">{String((start.error as Error).message ?? start.error)}</div> : null}

          <div className="page-actions">
            <Button onClick={launch} disabled={seedList.length === 0 || start.isPending}>
              <Play size={13} />
              {start.isPending ? "Starting…" : "Start crawl"}
            </Button>
          </div>

          {crawls.length ? (
            <>
              <div className="eyebrow">Recent crawls</div>
              <div className="stack-tight">
                {crawls.map((run) => (
                  <CrawlRunRow key={run.task_id} run={run} />
                ))}
              </div>
            </>
          ) : null}
        </div>
      </Modal>
    </>
  );
}

/**
 * One crawl's outcome. Shows the partition — fetched, refused, failed — rather than just the
 * successes, and names the non-zero skip categories, because "what did it not reach, and why" is the
 * half of a coverage report that a highlight reel leaves out.
 */
function CrawlRunRow({ run }: { run: CrawlRun }): JSX.Element {
  const rep = run.report;
  const skips = (rep?.skips?.counts ?? []).filter((c) => c.count > 0);
  const tone = run.state === "failed" ? "bad" : run.state === "running" ? "info" : "good";
  return (
    <div className="ex-row">
      <Badge tone={tone}>{run.state}</Badge>
      <span className="cell-dim" title={run.seeds.join(", ")}>
        {run.seeds.join(", ")}
      </span>
      {rep ? (
        <span className="cell-num">
          {rep.fetched} fetched · {rep.refused} refused · {rep.failed} failed
        </span>
      ) : null}
      {run.error ? <span className="cell-dim">{run.error}</span> : null}
      {skips.length ? (
        <span className="cell-dim" title={skips.map((s) => `${s.name}: ${s.count}`).join("\n")}>
          {skips.length} skip {skips.length === 1 ? "category" : "categories"}
        </span>
      ) : null}
    </div>
  );
}
