import { Bug, Play } from "lucide-react";
import { parseSeeds } from "../lib/parse-seeds";
import { crawlBound } from "../lib/crawl-bounds";
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
  // The eight bounds added in burpsy-react-ui-qzzy. Blank means the engine default; 0 is a real
  // answer (zero locations, zero links per page) and is sent as 0.
  //
  // The distinction is why these are strings rather than numbers: a numeric field cannot tell "the
  // operator left this blank" from "the operator typed 0", and `Number(x) || undefined` — the shape
  // the three older fields use — answers 0 as undefined, so asking for no locations at all would
  // silently start a 300-location crawl.
  const [maxLocations, setMaxLocations] = useState("");
  const [maxFrontier, setMaxFrontier] = useState("");
  const [maxLinksPerPage, setMaxLinksPerPage] = useState("");
  const [maxParseBytes, setMaxParseBytes] = useState("");
  const [maxTemplateVisits, setMaxTemplateVisits] = useState("");
  const [maxCaptureBytes, setMaxCaptureBytes] = useState("");
  const [maxFingerprints, setMaxFingerprints] = useState("");
  const [maxRelogins, setMaxRelogins] = useState("");
  const start = useStartCrawl();
  const { data, running } = useCrawls();
  // The engine's own defaults, from the server. The first version of this row carried a hard-coded
  // table and got MaxRelogins wrong (10 there, 5 in the engine), which showed an operator a bound
  // they had never set as one they had. A second copy of eleven numbers is a defect waiting for the
  // first default to change, and it cannot be tested against the thing it describes.
  const defaults = data?.default_limits ?? {};

  const seedList = parseSeeds(seeds);

  const launch = () => {
    start.mutate(
      {
        seeds: seedList,
        max_requests: Number(maxRequests) || undefined,
        max_depth: Number(maxDepth) || undefined,
        requests_per_second: Number(rps) || undefined,
        submit_forms: submitForms,
        ...crawlBound("max_locations", maxLocations),
        ...crawlBound("max_frontier", maxFrontier),
        ...crawlBound("max_links_per_page", maxLinksPerPage),
        ...crawlBound("max_parse_bytes", maxParseBytes),
        ...crawlBound("max_template_visits", maxTemplateVisits),
        ...crawlBound("max_capture_bytes", maxCaptureBytes),
        ...crawlBound("max_fingerprints", maxFingerprints),
        ...crawlBound("max_relogins", maxRelogins),
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
            {(id) => (
              <Input
                id={id}
                value={seeds}
                placeholder="https://target.test/"
                onChange={(event) => setSeeds(event.target.value)}
              />
            )}
          </Field>

          <div className="form-grid">
            <Field label="Max requests" hint="The bound that actually governs cost.">
              {(id) => <Input id={id} type="number" min={1} value={maxRequests} onChange={(event) => setMaxRequests(event.target.value)} />}
            </Field>
            <Field label="Max depth" hint="Links from a seed. A seed is depth 0.">
              {(id) => <Input id={id} type="number" min={1} value={maxDepth} onChange={(event) => setMaxDepth(event.target.value)} />}
            </Field>
            <Field label="Requests per second" hint="Blank or 0 takes the engine default.">
              {(id) => <Input id={id} type="number" min={0} step="0.5" value={rps} onChange={(event) => setRps(event.target.value)} />}
            </Field>
          </div>

          <div className="eyebrow">Bounds the engine would otherwise choose</div>
          <div className="form-grid">
            <Field label="Max locations" hint="Distinct pages. Blank takes the default; 0 admits none. Stops an application whose URLs are unbounded but whose pages are not.">
              {(id) => <Input id={id} type="number" min={0} value={maxLocations} onChange={(event) => setMaxLocations(event.target.value)} placeholder="default" />}
            </Field>
            <Field label="Max frontier" hint="URLs queued but not yet fetched. Bounds the queue's memory; links arriving at a full frontier are dropped and counted.">
              {(id) => <Input id={id} type="number" min={0} value={maxFrontier} onChange={(event) => setMaxFrontier(event.target.value)} placeholder="default" />}
            </Field>
            <Field label="Max links per page" hint="Links and forms taken from one response. A generated index page can carry a hundred thousand.">
              {(id) => <Input id={id} type="number" min={0} value={maxLinksPerPage} onChange={(event) => setMaxLinksPerPage(event.target.value)} placeholder="default" />}
            </Field>
            <Field label="Max template visits" hint="Fetches of one URL shape, ids replaced. The honest cutoff for the infinite-application crawl.">
              {(id) => <Input id={id} type="number" min={0} value={maxTemplateVisits} onChange={(event) => setMaxTemplateVisits(event.target.value)} placeholder="default" />}
            </Field>
            <Field label="Max parse bytes" hint="Bytes of a response body examined for links. The body is still stored and scanned in full.">
              {(id) => <Input id={id} type="number" min={0} step={1024} value={maxParseBytes} onChange={(event) => setMaxParseBytes(event.target.value)} placeholder="default" />}
            </Field>
            <Field label="Max capture bytes" hint="Size of a response stored and scanned at all. Past it the response is neither.">
              {(id) => <Input id={id} type="number" min={0} step={1024} value={maxCaptureBytes} onChange={(event) => setMaxCaptureBytes(event.target.value)} placeholder="default" />}
            </Field>
            <Field label="Max fingerprints" hint="Entries in each request-identity table. Reached, further unseen URLs are refused admission and the crawl says so.">
              {(id) => <Input id={id} type="number" min={0} value={maxFingerprints} onChange={(event) => setMaxFingerprints(event.target.value)} placeholder="default" />}
            </Field>
            <Field label="Max re-logins" hint="Session-recovery attempts. Each costs a login round trip, so a target whose session keeps expiring spends the crawl on logins.">
              {(id) => <Input id={id} type="number" min={0} value={maxRelogins} onChange={(event) => setMaxRelogins(event.target.value)} placeholder="default" />}
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
                  <CrawlRunRow key={run.task_id} run={run} defaults={defaults} />
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
 * The bounds a run was launched with, in one line, in the form an operator reads them in.
 *
 * Only the bounds that are NOT the engine's default are named, because a row that lists all eleven
 * says nothing. That requires the defaults here, which is a copy rather than a fetch on purpose: the
 * point of the row is to answer "what did I change", and a defaults table that silently drifts from
 * the server's would make it answer "nothing changed" for a crawl that did.
 *
 * The zero case is the one this exists for. A run bounded to zero locations names it, because "0
 * locations" and "the default 300" are the same number in a table that only prints the default.
 */
function describeBounds(limits: NonNullable<CrawlRun["limits"]>, defaults: NonNullable<CrawlRun["limits"]>): string {
  const names: Record<string, string> = {
    max_requests: "requests", max_depth: "depth", max_duration_secs: "duration",
    max_locations: "locations", max_frontier: "frontier", max_links_per_page: "links/page",
    max_parse_bytes: "parse bytes", max_template_visits: "template visits",
    max_capture_bytes: "capture bytes", max_fingerprints: "fingerprints", max_relogins: "re-logins",
  };
  const parts = Object.entries(limits)
    .filter(([key, value]) => typeof value === "number" && value !== defaults[key])
    .map(([key, value]) => `${names[key] ?? key} ${value}`);
  return parts.length ? parts.join(" · ") : "default bounds";
}

/**
 * One crawl's outcome. Shows the partition — fetched, refused, failed — rather than just the
 * successes, and names the non-zero skip categories, because "what did it not reach, and why" is the
 * half of a coverage report that a highlight reel leaves out.
 */
function CrawlRunRow({ run, defaults }: { run: CrawlRun; defaults: NonNullable<CrawlRun["limits"]> }): JSX.Element {
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
      {run.limits ? <span className="cell-dim">{describeBounds(run.limits, defaults)}</span> : null}
      {run.error ? <span className="cell-dim">{run.error}</span> : null}
      {skips.length ? (
        <span className="cell-dim" title={skips.map((s) => `${s.name}: ${s.count}`).join("\n")}>
          {skips.length} skip {skips.length === 1 ? "category" : "categories"}
        </span>
      ) : null}
    </div>
  );
}
