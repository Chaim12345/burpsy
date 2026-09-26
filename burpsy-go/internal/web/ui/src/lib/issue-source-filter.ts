/**
 * Which findings a source filter keeps (burpsy-react-ui-exiu).
 *
 * Two values, and only two, because only two are knowable without inventing provenance the store
 * does not record. Burp splits this further into BCheck / Scan check / Extension / manually
 * generated; this deliberately does not, and a filter that guessed from a check name would put an
 * unverifiable claim in front of an operator deciding what to chase next.
 *
 * An empty filter keeps everything, which is the same "I did not choose" reading the launch body's
 * optional fields use.
 */
export type IssueSourceFilter = "" | "scan" | "manual";

export const ISSUE_SOURCE_FILTERS: { value: IssueSourceFilter; label: string }[] = [
 { value: "", label: "All sources" },
 { value: "scan", label: "Scan only" },
 { value: "manual", label: "Manual only" },
];

/**
 * Keeps the findings a source filter admits.
 *
 * A finding with no `source` — an older server, or a row from before the field existed — counts as
 * manual, because that is what "no run raised it" means. Dropping it instead would silently hide
 * every legacy row the moment an operator picked "Manual", which reads as the tool losing data.
 */
export function filterByIssueSource<T extends { source?: string }>(
 findings: readonly T[],
 filter: IssueSourceFilter,
): T[] {
 if (!filter) return [...findings];
 return findings.filter((f) => issueSourceOf(f) === filter);
}

/** The finding's provenance, defaulting the absent case to manual. */
export function issueSourceOf(finding: { source?: string }): "scan" | "manual" {
 return finding.source === "scan" ? "scan" : "manual";
}
