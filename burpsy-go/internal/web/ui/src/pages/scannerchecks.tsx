import { useCorpusChecks, useSetCorpusCheckEnabled } from "../lib/data.attack";
import type { CorpusCheckView } from "../lib/types.attack";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Card, Empty, ErrorNotice, Switch } from "../ui/primitives";
import { SimpleTable } from "../ui/table";

/**
 * Extender > Custom scan checks (burpsy-react-ui-kdqj).
 *
 * Burp's fifth Extender sub-tab is the list of custom checks a user has loaded: which are registered,
 * whether each compiled, and whether each is enabled. burpsy had the corpus and the classification
 * (LoadDir, LoadReport, the coverage tracker) but no surface that gathered them, so an operator could
 * read counts on two other routes and could not tell which checks were loaded, could not see whether
 * one compiled, and could not switch one off.
 *
 * The per-row switch is the part that had to be real rather than decorative: it writes to the same
 * disabled set the audit engine filters its dispatch set by (internal/scanner/check_enable.go), so a
 * row switched off here is a check the next audit does not run. The columns the wire cannot fill
 * honestly are omitted rather than faked: `run_count` is the passive coverage counter and reads 0 for
 * an active check, because the active engine keeps a per-session ledger rather than a counter.
 *
 * There is no Bambda library sub-tab, and that is deliberate rather than pending: importBambda takes
 * Java source and this tool refuses it by design (see lib/reference.ts), so a leaf that offered to
 * import one would be offering a capability the server will not honour.
 */

/** One row's bucket, in words. A check is active or passive, never both, so the cell is a label
 * rather than two booleans an operator has to combine. */
function bucketOf(row: CorpusCheckView): { label: string; tone: "info" | "neutral" } {
 if (row.passive) return { label: "passive", tone: "neutral" };
 return { label: "active", tone: "info" };
}

function CheckRow({ row, onToggle }: { row: CorpusCheckView; onToggle: (next: boolean) => void }): JSX.Element {
 const bucket = bucketOf(row);
 return (
  <tr key={row.name}>
   <td title={row.description || undefined}>{row.name}</td>
   <td>
    <Badge tone={bucket.tone}>{bucket.label}</Badge>
   </td>
   <td>
    {/* Compile status: a check the loader kept is one that parsed, so "loaded" is the honest
            statement. A check the parser refused never reaches this list — the loader counts it in
            LoadReport.Errors, which this route does not carry — so claiming "compiled" here would
            overstate what the row knows. */}
    <Badge tone="good">loaded</Badge>
   </td>
   <td className="cell-num">{(row.run_count ?? 0).toLocaleString()}</td>
   <td>{row.severity || "—"}</td>
   <td>
    <Switch
     checked={!row.disabled}
     label={`${row.disabled ? "Enable" : "Disable"} ${row.name}`}
     onCheckedChange={(next) => onToggle(next)}
    />
   </td>
  </tr>
 );
}

export function ScannerChecksPage(): JSX.Element {
 const corpus = useCorpusChecks();
 const { data, error, isFetching } = corpus;
 const setEnabled = useSetCorpusCheckEnabled();

 const toggle = (row: CorpusCheckView, next: boolean) => {
  setEnabled.mutate({ name: row.name, enabled: next });
 };

 return (
  <div className="page">
   <PageHeader
    title="Custom scan checks"
    description="The BCheck corpus this process loaded, both buckets, and a per-row switch the audit engine reads."
    actions={<RefreshButton onClick={() => void corpus.refetch()} loading={corpus.isFetching} />}
   />
   {error ? <ErrorNotice error={error} /> : null}
   {!data && isFetching ? <LoadingPanel /> : null}

   {data && !data.enabled ? (
    <div className="notice notice-warn">
     No BCheck corpus is loaded. Start burpsy with <code>--bchecks DIR</code> to load one; the
     scanner then audits with the built-in checks alone.
    </div>
   ) : null}

   {data?.enabled ? (
    <Card>
     <SectionHeading
      title="Loaded corpus"
      detail={`${data.active_count ?? 0} active, ${data.passive_count ?? 0} passive — counted from the corpus loader, the same set the audit engine dispatches.`}
     />
     {(data.checks ?? []).length === 0 ? (
      <Empty title="No checks" detail="The loader classified no checks; see the server log for parse errors." />
     ) : (
      <SimpleTable headers={["Check", "Bucket", "Status", "Run count", "Severity", "Enabled"]}>
       {(data.checks ?? []).map((row: CorpusCheckView) => (
        <CheckRow key={row.name} row={row} onToggle={(next) => toggle(row, next)} />
       ))}
      </SimpleTable>
     )}
    </Card>
   ) : null}
  </div>
 );
}
