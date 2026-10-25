import { useMemo, useState } from "react";
import { useAdvisories, useAdvisory } from "../lib/data.advisory";
import { useDebounced } from "../lib/data";
import type { AdvisoryIndexRow } from "../lib/types.advisory";
import { LoadingPanel, PageHeader, RefreshButton, SplitPane } from "../ui/layout";
import { Badge, Empty, ErrorNotice, Input, Select, Toolbar } from "../ui/primitives";
import { AdvisoryReader } from "../ui/advisory";
import { severityTone } from "../lib/severity";

/**
 * Target › Issue definitions: the issue-definition catalogue, browsable on its own.
 *
 * Burp's Target tool carries this sub-tab for a reason the Issues tab cannot serve. Issues answers
 * "what did we find"; a finding that does not exist has no row to hang a definition off. This screen
 * is the reference work an operator reads *before* there is a finding — to decide what to look for, to
 * lift remediation text into a report, or to check what a CWE maps to.
 *
 * # What this screen is careful not to claim
 *
 * A definition existing says nothing about whether burpsy runs a check for it, and nothing about
 * whether such a check has ever been shown to work. Those are separate facts counted separately in
 * docs/SCANNER-COVERAGE.md — 183 catalog rows registered, 145 with an end-to-end runtime
 * demonstration — and neither number is published here, because the only one this screen could
 * compute is the catalogue size, and a catalogue size shown next to the word "coverage" would be read
 * as the second figure. So the header says what a definition is instead, and the numbers stay where
 * the test that pins them lives.
 *
 * The other distinction the screen preserves is the one internal/web/AGENTS.md records for
 * /api/issues: a nil catalogue is a supported state, and "no catalogue is loaded" must never render
 * as "this catalogue is empty". `loaded`, `count` and `matched` are three separate wire fields and
 * this page reads all three.
 */

/** Severities the catalogue uses, worst first. Its own vocabulary — HIGH/MEDIUM/LOW/INFO — rather
 * than a finding's Critical…Informational scale, because these are different scales measuring
 * different things: an issue class's typical severity against one occurrence's rating. */
const CATALOGUE_SEVERITIES = ["HIGH", "MEDIUM", "LOW", "INFO"] as const;

const SEVERITY_LABEL: Record<string, string> = {
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

function DefinitionRow({
  row,
  selected,
  onSelect,
}: {
  row: AdvisoryIndexRow;
  selected: boolean;
  onSelect: () => void;
}): JSX.Element {
  return (
    <button type="button" className={selected ? "list-row active" : "list-row"} onClick={onSelect}>
      <div className="list-row-text">
        <strong title={row.name}>{row.name}</strong>
        {/* Burp's own hexadecimal type index, in the mono slot the row's `small` already renders as an
            identifier. It is what an operator cross-checks against Burp, and the key the reader is
            fetched by. */}
        <small>{row.type_index}</small>
      </div>
      <Badge tone={severityTone(row.typical_severity)} title={`Typically ${SEVERITY_LABEL[row.typical_severity] ?? row.typical_severity} severity`}>
        {row.typical_severity}
      </Badge>
    </button>
  );
}

export function IssueDefinitionsPage(): JSX.Element {
  const [severity, setSeverity] = useState("all");
  const [term, setTerm] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  // The search runs server-side (it covers the description, which is the half too expensive to ship),
  // so this is one request per settled keystroke rather than per keystroke.
  const debouncedTerm = useDebounced(term, 260);
  const catalogue = useAdvisories(debouncedTerm.trim(), severity);
  // Selection is keyed on the composite row key, because type_index alone cannot address a row
  // (two pairs share one). The DETAIL fetch still goes by type_index -- that is the only thing
  // /api/advisories/{index} can look up, and the backend's byIndex map holds one per index -- so
  // for a shared index the reader is told whose definition it is actually looking at.
  const selectedIndex = selected === null ? null : selected.slice(0, selected.indexOf(":"));
  const detail = useAdvisory(selectedIndex);

  const rows = catalogue.data?.advisories ?? [];
  const counts = catalogue.data?.severity_counts ?? {};
  const filtered = severity !== "all" || debouncedTerm.trim() !== "";

  // The selected row's index entry, so the reader's head can show the name and severity immediately
  // rather than blanking while the detail request is in flight.
  const selectedRow = useMemo(
    () => rows.find((row) => `${row.type_index}:${row.name}` === selected) ?? null,
    [rows, selected],
  );
  // Other catalogue rows sharing this row's index. Non-empty means the definition below is
  // addressed by an index that does not identify it uniquely, which the reader has to know.
  const indexTwins = useMemo(
    () =>
      selectedRow === null
        ? []
        : rows.filter((row) => row.type_index === selectedRow.type_index && row.name !== selectedRow.name),
    [rows, selectedRow],
  );

  const listPane = (
    <div className="pane">
      <Toolbar className="pane-toolbar">
        <Input
          aria-label="Search issue definitions"
          title="Search issue definitions"
          value={term}
          onChange={(event) => setTerm(event.target.value)}
          placeholder="Search name and description"
        />
      </Toolbar>
      {catalogue.isFetching && !catalogue.data ? (
        <LoadingPanel label="Loading the issue-definition catalogue" />
      ) : catalogue.data && !catalogue.data.loaded ? (
        // Not the same state as "your filter matched nothing", and said differently on purpose: this
        // is a server without a catalogue, which is a supported state an operator can act on.
        <Empty
          title="No issue-definition catalogue is loaded"
          detail={
            catalogue.data.hint ??
            "This build carries no issue definitions, so no finding can show one either. Findings still render their check's own description and remediation."
          }
        />
      ) : rows.length === 0 ? (
        <Empty
          title={filtered ? "No definition matches this filter" : "The catalogue loaded no definitions"}
          detail={
            filtered
              ? `The catalogue holds ${catalogue.data?.count ?? 0} definition(s); none of them matches. The search covers each definition's name and description.`
              : "A catalogue is present but carries no entries. That is a load problem rather than an empty result."
          }
        />
      ) : (
        <div className="row-list">
          {/*
            type_index is NOT unique: the shipped catalogue has 183 definitions across 181
            distinct indices. "Perl code injection" shares 00100e00 with the React2Shell RCE
            row, and "BCheck generated issue" shares 09000000 with "Bambda generated issue".
            Keying on it alone made React drop one row of each pair, so the list silently
            showed 181 of 183 definitions -- exactly the undercount this project treats as a
            defect. The name disambiguates and is unique across the catalogue.
          */}
          {rows.map((row) => (
            <DefinitionRow
              key={`${row.type_index}:${row.name}`}
              row={row}
              selected={`${row.type_index}:${row.name}` === selected}
              onSelect={() => setSelected(`${row.type_index}:${row.name}`)}
            />
          ))}
        </div>
      )}
    </div>
  );

  const readerPane =
    selected === null ? (
      <Empty
        title="Select an issue definition"
        detail="Choose a definition to read its description, remediation, references and CWE classifications."
      />
    ) : (
      <div className="pane">
        <div className="detail-head">
          <div className="detail-head-title">
            <span className="eyebrow">Issue definition · {selectedIndex}</span>
            <h2>
              <strong>{selectedRow?.name ?? detail.data?.name ?? selectedIndex}</strong>
            </h2>
          </div>
          <div className="detail-actions">
            {selectedRow ? (
              <Badge tone={severityTone(selectedRow.typical_severity)}>{selectedRow.typical_severity}</Badge>
            ) : null}
          </div>
        </div>
        <div className="advisory-body">
          {indexTwins.length > 0 ? (
            <p className="cell-dim">
              The catalogue gives type index {selectedIndex} to{" "}
              {indexTwins.length === 1 ? "another definition" : `${indexTwins.length} other definitions`} —{" "}
              {indexTwins.map((twin) => twin.name).join(", ")}. The index does not identify a definition on its own,
              and the reader below is whichever one the catalogue resolves that index to, which may not be the row
              selected.
            </p>
          ) : null}
          {detail.error ? <ErrorNotice error={detail.error} onRetry={() => void detail.refetch()} /> : null}
          {detail.isFetching && !detail.data ? <LoadingPanel label="Loading definition" /> : null}
          {/* heading="Description" because the pane head above already names the definition; the
              default heading names it too, which would say it twice on one screen. */}
          {detail.data ? <AdvisoryReader advisory={detail.data} heading="Description" /> : null}
        </div>
      </div>
    );

  return (
    <div className="page-fill">
      <div>
        <PageHeader
          title="Issue definitions"
          description="Every issue class the catalogue describes, found or not. A definition here is reference text, not a claim that a check for it runs."
          actions={<RefreshButton onClick={() => void catalogue.refetch()} loading={catalogue.isFetching} />}
        />
        <Toolbar style={{ marginTop: 8 }}>
          <Select
            aria-label="Typical severity filter"
            title="Typical severity filter"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            style={{ maxWidth: "var(--w-sm)" }}
          >
            <option value="all">All severities</option>
            {CATALOGUE_SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {/* The count is the catalogue's own partition, not the current result: it says what
                    picking this option would find. Omitted rather than shown as 0 when the catalogue
                    has not answered yet, so an option never claims a number it does not have. */}
                {SEVERITY_LABEL[s]}
                {counts[s] === undefined ? "" : ` (${counts[s]})`}
              </option>
            ))}
          </Select>
          {/* Two numbers, never one. Unfiltered they agree and only the total is worth the space;
              filtered, "N of M" is the only honest way to show a short list — a bare count would read
              as the size of the catalogue. */}
          <Badge title="definitions in the loaded catalogue">
            {filtered
              ? `${(catalogue.data?.matched ?? 0).toLocaleString()} of ${(catalogue.data?.count ?? 0).toLocaleString()} definition(s)`
              : `${(catalogue.data?.count ?? 0).toLocaleString()} definition(s)`}
          </Badge>
        </Toolbar>
        {catalogue.error ? <ErrorNotice error={catalogue.error} onRetry={() => void catalogue.refetch()} /> : null}
        {catalogue.data && !catalogue.data.loaded ? (
          <div className="notice notice-warn">{catalogue.data.hint ?? "no issue-definition catalogue is loaded"}</div>
        ) : null}
      </div>

      <SplitPane
        storageId="advisories"
        orientation="horizontal"
        defaultMasterSize="34"
        minMasterSize="20"
        master={listPane}
        detail={readerPane}
      />
    </div>
  );
}
