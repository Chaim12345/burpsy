import type { CrawlRun } from "./types.observe";
import type { LiveAuditState } from "./types.attack";
import type { InterceptState } from "./types";

/**
 * One thing that needs the operator's attention, addressed to the tool that owns it.
 *
 * Burp's shell is built on this contract per tool: every tool module exposes a
 * `ToolTabProvider` and a `ToolTabFlasher` (spec 1.1, and 4.1-4.12 name one flasher per tool), which
 * makes an attention indicator a shell-wide mechanism rather than a Proxy special case. The failure
 * it fixes is the one reason it has to live in the shell at all: with interception holding a
 * request, the operator's *browser* hangs and nothing outside the Proxy page said why
 * (burpsy-react-ui-xvo). An indicator that only rendered on its own page would be a decoration; the
 * value is that it is visible from every other tool.
 *
 * `count` is what the badge shows, and `label` is the sentence assistive tech announces and the
 * tab's tooltip carries. They travel together rather than being rebuilt per call site because the
 * number alone is not a statement — "3" beside a tab name means nothing until something says three
 * of *what*, and a caller left to compose that would eventually ship the bare number.
 */
export interface AttentionSignal {
  /** The tool id from nav.ts's TOOLS this signal belongs to. */
  tool: string;
  count: number;
  /** A sentence: what is waiting, and where to go to deal with it. */
  label: string;
}

/**
 * Everything the shell can currently see that needs the operator.
 *
 * The sources are parameters rather than reads inside this function so the decision "does this need
 * attention" is a pure one that a test can pin without a server or a query cache — which is the only
 * way the *rule* stays honest. The shell owns the fetching; this owns the judgement.
 */
export interface AttentionSources {
  intercept?: InterceptState | undefined;
  /**
   * The live active-audit sweep's own state (ve2q). Carried whole rather than a pre-counted number so
   * the judgement stays in this file, which is the only place a test can pin the rule without a query
   * cache.
   */
  liveAudit?: LiveAuditState | undefined;
  /**
   * The dashboard's crawl runs, for the task-level signal (ve2q). Same reason: a run's own state is
   * the fact, and this file decides what about it needs the operator.
   */
  crawls?: CrawlRun[] | undefined;
}

/**
 * The signals in force right now, in tool order.
 *
 * A count of zero is not a signal, and neither is an un-fetched source: a tab that showed "0" would
 * be reporting that something needs the operator and that nothing does, in the same mark.
 *
 * The intercept signal deliberately does not consult `enabled`. A held request is a fact about the
 * queue, and interception can be switched off with messages still parked in it; those requests are
 * still going nowhere, and the tab is then the only way to find out. Gating on the switch would make
 * the indicator vanish at the exact moment it became load-bearing.
 */
export function attentionSignals(sources: AttentionSources): AttentionSignal[] {
  const signals: AttentionSignal[] = [];
  const held = sources.intercept?.pending ?? 0;
  if (held > 0) {
    signals.push({
      tool: "proxy",
      count: held,
      label: `${held} held ${held === 1 ? "request" : "requests"} — interception is holding traffic; open Proxy, then Intercept, to release ${
        held === 1 ? "it" : "them"
      }`,
    });
  }
  signals.push(...scannerSignals(sources.liveAudit));
  signals.push(...dashboardSignals(sources.crawls));
  return signals;
}

/**
 * The Scanner's signal: exchanges the live sweep gave up on (ve2q).
 *
 * `skipped` is the one number on that state that means the operator is needed rather than that the
 * tool is busy. A sweep that is `behind` is working; a sweep that is `stalled_at` is working on one
 * exchange. A skip is the sweep saying it will not look at these again, which is precisely a thing
 * only an operator can resolve — by releasing the exchange, widening the source, or accepting the
 * coverage gap on the record.
 *
 * `retried` is deliberately NOT counted: a retried exchange was taken back and audited, so it is the
 * opposite of something waiting. `behind` is not counted either — a backlog is the tool doing its job.
 */
function scannerSignals(live: LiveAuditState | undefined): AttentionSignal[] {
 // `?? 0`, not a fallback to `behind`: an absent `skipped` is a server too old to report skips, and
 // answering with the backlog would put a number on the tab that counts something else entirely.
 const skipped = live?.skipped ?? 0;
 if (skipped <= 0) {
  return [];
 }
 return [{
  tool: "scanner",
  count: skipped,
  label: `${skipped} ${skipped === 1 ? "exchange" : "exchanges"} the live audit gave up on — open Scanner, then Live audit, to see what it skipped and why`,
 }];
}

/**
 * The Dashboard's signal: runs that did not finish (ve2q).
 *
 * A dashboard is an aggregation of other tools, so it has no state of its own to count — but it does
 * have the one question only it can answer: which of the things the operator started did not
 * complete. A failed run and an unfinished one are counted together because from any page but this one
 * they are the same fact — something was started here and its result is not on the page it belongs
 * on. A run that is merely `running` is NOT counted: the operator knows they started it, and the
 * dashboard is the page they are already looking at.
 *
 * Deliberately not derived from the other tools' attention signals: a held request belongs to Proxy
 * and a skipped exchange to Scanner, and mirroring either here would put the same number on two tabs
 * and make the operator wonder which one to open. A run that failed is a fact about the run, not a
 * duplicate of a tool's queue.
 */
function dashboardSignals(crawls: CrawlRun[] | undefined): AttentionSignal[] {
 if (!crawls) {
  return [];
 }
 let unfinished = 0;
 for (const run of crawls) {
  if (run.state === "failed" || (!run.finished && run.state === "running")) {
   unfinished += 1;
  }
 }
 if (unfinished === 0) {
  return [];
 }
 return [{
  tool: "dashboard",
  count: unfinished,
  label: `${unfinished} ${unfinished === 1 ? "task" : "tasks"} did not finish — open Dashboard to see which`,
 }];
}

/** The signal for one tool, or undefined when that tool needs nothing. */
export function attentionFor(signals: AttentionSignal[], toolId: string): AttentionSignal | undefined {
  return signals.find((signal) => signal.tool === toolId);
}
