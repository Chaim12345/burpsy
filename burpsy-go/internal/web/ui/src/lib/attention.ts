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
  return signals;
}

/** The signal for one tool, or undefined when that tool needs nothing. */
export function attentionFor(signals: AttentionSignal[], toolId: string): AttentionSignal | undefined {
  return signals.find((signal) => signal.tool === toolId);
}
