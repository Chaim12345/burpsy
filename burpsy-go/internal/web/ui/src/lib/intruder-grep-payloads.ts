import type { IntruderConfig } from "./store";
import type { AttackReport, GrepPayloadsSettings } from "./types.tools";

/**
 * Burp's Grep - Payloads (burpsy-react-ui-7qc3): "flag result items containing reflections of the
 * submitted payload", with Case sensitive match, Exclude HTTP headers and Match against pre-URL-encoded
 * payloads, and a results column per payload set counting the payload's occurrences.
 */

export type GrepPayloadsConfig = Pick<
 IntruderConfig,
 "grepPayloadsEnabled" | "grepPayloadsCaseSensitive" | "grepPayloadsExcludeHeaders" | "grepPayloadsMatchPreEncoded"
>;

/**
 * The run request's grep_payloads object. Always sent, all four fields: the server's answer to an
 * absent object is the check every attack ran before the settings existed (on, case-sensitive, headers
 * included, matched as sent), and the page's defaults are Burp's case-insensitive, pre-encoded ones, so
 * leaving it out would launch an attack the settings on screen do not describe.
 */
export function grepPayloadsField(config: GrepPayloadsConfig): { grep_payloads: GrepPayloadsSettings } {
 return {
  grep_payloads: {
   enabled: config.grepPayloadsEnabled !== false,
   case_sensitive: config.grepPayloadsCaseSensitive === true,
   exclude_headers: config.grepPayloadsExcludeHeaders === true,
   match_pre_url_encoded: config.grepPayloadsMatchPreEncoded !== false,
  },
 };
}

/**
 * The per-set count columns a report has, as header labels: none when Grep - Payloads was off (or the
 * server predates it), one "Payload reflections" column for a one-set attack, "Set N reflections"
 * otherwise — Burp: "If more than one payload set is used, a separate column is added for each".
 */
export function reflectionColumnLabels(report: Pick<AttackReport, "grep_payloads">, setCount: number): string[] {
 if (!report.grep_payloads?.enabled || setCount < 1) return [];
 if (setCount === 1) return ["Payload reflections"];
 return Array.from({ length: setCount }, (_, i) => `Set ${i + 1} reflections`);
}
