import { Bug, Play } from "lucide-react";
import { parseSeeds } from "../lib/parse-seeds";
import { crawlBound } from "../lib/crawl-bounds";
import { useState } from "react";
import { useCrawls, useStartCrawl } from "../lib/data.observe";
import type { CrawlRun } from "../lib/types.observe";
import { crawlOutcome, crawlStopLabel, crawlStops, isPolicyPause } from "../lib/crawl-stops";
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
  // Browser-driven interaction (burpsy-react-ui-spa1). Off by default: it navigates and fires the
  // application's own handlers, and with the form-fill switch below it writes. The two are separate
  // because reading a SPA's routes is a much smaller act than submitting its forms.
  const [interact, setInteract] = useState(false);
  const [fillInteractionForms, setFillInteractionForms] = useState(false);
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
  // Burp's "Reuse the site map" (z8qf). Off by default: a seeded crawl does not re-fetch what the site
  // map holds, so a page only ever browsed through the proxy contributes its links only if its stored
  // response is parsed — the trade the hint states.
  const [seedFromSiteMap, setSeedFromSiteMap] = useState(false);
  // Burp's crawler.error_handling (o0c5), blank = the engine default, 0 = never/off/no retries.
  const [pauseTimeoutCount, setPauseTimeoutCount] = useState("");
  const [pauseTimeoutPercent, setPauseTimeoutPercent] = useState("");
  const [pauseAuthFailures, setPauseAuthFailures] = useState("");
  const [followUpPasses, setFollowUpPasses] = useState("");
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
        interact,
        fill_interaction_forms: interact && fillInteractionForms,
        ...crawlBound("max_locations", maxLocations),
        ...crawlBound("max_frontier", maxFrontier),
        ...crawlBound("max_links_per_page", maxLinksPerPage),
        ...crawlBound("max_parse_bytes", maxParseBytes),
        ...crawlBound("max_template_visits", maxTemplateVisits),
        ...crawlBound("max_capture_bytes", maxCaptureBytes),
        ...crawlBound("max_fingerprints", maxFingerprints),
        ...crawlBound("max_relogins", maxRelogins),
        ...(seedFromSiteMap ? { seed_from_site_map: true } : {}),
        ...crawlBound("pause_task_requests_timed_out_count", pauseTimeoutCount),
        ...crawlBound("pause_task_requests_timed_out_percentage", pauseTimeoutPercent),
        ...crawlBound("consecutive_authentication_failures_before_pausing_task", pauseAuthFailures),
        ...crawlBound("number_of_follow_up_passes", followUpPasses),
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

          <div className="eyebrow">Error handling</div>
          <div className="form-grid">
            <Field label="Pause after timeouts in a row" hint="Consecutive timed-out requests before the crawl pauses itself. Blank takes the default (15); 0 never pauses.">
              {(id) => <Input id={id} type="number" min={0} value={pauseTimeoutCount} onChange={(event) => setPauseTimeoutCount(event.target.value)} placeholder="default (15)" />}
            </Field>
            <Field label="Pause at timeout percentage" hint="Share of the crawl's requests that may time out before it pauses, 0–100. Blank or 0 is off.">
              {(id) => <Input id={id} type="number" min={0} max={100} value={pauseTimeoutPercent} onChange={(event) => setPauseTimeoutPercent(event.target.value)} placeholder="default (off)" />}
            </Field>
            <Field label="Pause after auth failures in a row" hint="Consecutive authentication failures before the crawl pauses, at most 10. Blank takes the default (2); 0 never pauses.">
              {(id) => <Input id={id} type="number" min={0} max={10} value={pauseAuthFailures} onChange={(event) => setPauseAuthFailures(event.target.value)} placeholder="default (2)" />}
            </Field>
            <Field label="Follow-up passes" hint="Passes that retry requests which failed. Blank takes the default (1); 0 retries nothing. Retries spend the same request budget.">
              {(id) => <Input id={id} type="number" min={0} value={followUpPasses} onChange={(event) => setFollowUpPasses(event.target.value)} placeholder="default (1)" />}
            </Field>
          </div>

          <Field label="Reuse the site map" hint="Skips requests the site map already holds for the seeds' origins. Best for a re-crawl: pages only browsed through the proxy may link to pages a seeded crawl will not discover.">
            <Switch checked={seedFromSiteMap} onCheckedChange={setSeedFromSiteMap} label="Skip requests already in the site map" />
          </Field>

          <Field label="Submit forms" hint="Off by default on purpose: a crawl that submits forms writes to the application under test.">
            <Switch checked={submitForms} onCheckedChange={setSubmitForms} label="Submit discovered forms" />
          </Field>

          <Field
            label="Drive pages in a browser"
            hint="Clicks each rendered page's navigational controls in a real browser and crawls the routes they reveal — the only way a single-page app's script-built navigation is found at all. Off by default: it navigates and fires the application's own handlers. Needs a browser (start burpsy with -dom)."
          >
            <Switch checked={interact} onCheckedChange={setInteract} label="Click controls and follow the routes they reveal" />
          </Field>

          {interact ? (
            <Field
              label="Fill and submit forms while driving"
              hint="Types a default into each visible field and submits each form the pass finds. State-changing: this writes to the application under test."
            >
              <Switch checked={fillInteractionForms} onCheckedChange={setFillInteractionForms} label="Fill and submit discovered forms in the browser" />
            </Field>
          ) : null}

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
  // "done" only for a crawl that exhausted its frontier (j5j7): a run that hit any bound says so in
  // the badge, and names each stop below — the counts beside it are then counts of a partial crawl.
  const outcome = crawlOutcome(run);
  const stops = crawlStops(run);
  return (
    <div className="ex-row">
      <Badge tone={outcome.tone}>{outcome.label}</Badge>
      <span className="cell-dim" title={run.seeds.join(", ")}>
        {run.seeds.join(", ")}
      </span>
      {rep ? (
        <span className="cell-num">
          {rep.fetched} fetched · {rep.refused} refused · {rep.failed} failed
        </span>
      ) : null}
      {rep && (rep.sitemap_seeded ?? 0) > 0 ? (
        <span className="cell-dim">
          {rep.sitemap_seeded} {rep.sitemap_seeded === 1 ? "request" : "requests"} reused from the site map
        </span>
      ) : null}
      {rep && (rep.follow_up_recovered ?? 0) > 0 ? (
        <span className="cell-dim">
          {rep.follow_up_recovered} recovered by a follow-up pass
        </span>
      ) : null}
      {run.limits ? <span className="cell-dim">{describeBounds(run.limits, defaults)}</span> : null}
      {run.error ? <span className="cell-dim">{run.error}</span> : null}
      {stops.length ? (
        <ul className="crawl-stops">
          {stops.map((stop) => (
            <li key={stop} className={isPolicyPause(stop) ? "crawl-stop crawl-stop-policy" : "crawl-stop"}>
              {crawlStopLabel(stop)}
            </li>
          ))}
        </ul>
      ) : null}
      {skips.length ? (
        <span className="cell-dim" title={skips.map((s) => `${s.name}: ${s.count}`).join("\n")}>
          {skips.length} skip {skips.length === 1 ? "category" : "categories"}
        </span>
      ) : null}
    </div>
  );
}
