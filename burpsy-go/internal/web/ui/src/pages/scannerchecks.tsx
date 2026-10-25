import { useRef, useState } from "react";
import { toast } from "sonner";
import { useCorpusChecks, useSetCorpusCheckEnabled } from "../lib/data.attack";
import { downloadText } from "../lib/api";
import { confirmDialog } from "../lib/dialogs";
import { CHECK_TEMPLATES, fetchCheckSource, useDeleteCheck, useReloadChecks } from "../lib/data.customchecks";
import { CustomCheckEditor, type EditorTarget } from "../ui/custom-check-editor";
import { DropdownMenu } from "../ui/menu";
import type { CorpusCheckView } from "../lib/types.attack";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Empty, ErrorNotice, Switch } from "../ui/primitives";
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

function CheckRow({
 row,
 onToggle,
 onOpen,
 onExport,
 onDelete,
}: {
 row: CorpusCheckView;
 onToggle: (next: boolean) => void;
 onOpen: () => void;
 onExport: () => void;
 onDelete: () => void;
}): JSX.Element {
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
   <td>{row.origin === "console" ? <Badge tone="info">console</Badge> : <span title={row.file}>{row.file ?? "file"}</span>}</td>
   <td>
    <Switch
     checked={!row.disabled}
     label={`${row.disabled ? "Enable" : "Disable"} ${row.name}`}
     onCheckedChange={(next) => onToggle(next)}
    />
   </td>
   <td>
    <div className="toolbar" style={{ gap: 4 }}>
     <Button variant="outline" size="small" onClick={onOpen} aria-label={`${row.origin === "console" ? "Edit" : "View"} ${row.name}`}>
      {row.origin === "console" ? "Edit" : "View"}
     </Button>
     <Button variant="outline" size="small" onClick={onExport} aria-label={`Export ${row.name}`}>
      Export
     </Button>
     {row.origin === "console" ? (
      <Button variant="outline" size="small" onClick={onDelete} aria-label={`Delete ${row.name}`}>
       Delete
      </Button>
     ) : null}
    </div>
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
 // Authoring (kbu1): the editor, Import, Export, Delete and Reload.
 const [editor, setEditor] = useState<EditorTarget | null>(null);
 const fileInput = useRef<HTMLInputElement>(null);
 const del = useDeleteCheck();
 const reload = useReloadChecks();
 const failed = (error: unknown) => toast.error(error instanceof Error ? error.message : String(error));
 const open = (row: CorpusCheckView) =>
  void fetchCheckSource(row.name).then(
   (src) =>
    setEditor({
     source: src.source,
     editing: src.origin === "console" ? src.name : null,
     readOnly: src.origin === "file",
     title: src.origin === "console" ? `Edit custom scan check — ${src.name}` : `View custom scan check — ${src.file ?? src.name}`,
    }),
   failed,
  );
 const exportRow = (row: CorpusCheckView) =>
  void fetchCheckSource(row.name).then((src) => {
   const file = (src.file ?? `${src.name.replace(/[^A-Za-z0-9._-]+/g, "_")}.bcheck`).replace(/\.bcheck$/i, "") + ".bcheck";
   downloadText(file, src.source);
  }, failed);
 const deleteRow = async (row: CorpusCheckView) => {
  const ok = await confirmDialog({
   title: `Delete the custom scan check "${row.name}"?`,
   description: "It is removed from the corpus and the project.",
   confirmLabel: "Delete",
   danger: true,
  });
  if (!ok) return;
  del.mutate(row.name, { onSuccess: () => toast.success(`Deleted "${row.name}"`), onError: failed });
 };
 const onReload = () =>
  reload.mutate(undefined, {
   onSuccess: (out) => {
    toast.success(`Reloaded: ${out.summary}`);
    if (out.shadowed.length) toast.warning(`A file now provides ${out.shadowed.join(", ")}; the console version was dropped`);
    if (out.errors.length) toast.error(`${out.errors.length} file(s) did not parse: ${out.errors.map((e) => e.file).join(", ")}`);
   },
   onError: failed,
  });
 const onImportFile = (file: File) =>
  void file.text().then((text) => setEditor({ source: text, editing: null, title: `Import custom scan check — ${file.name}` }), failed);
 const toolbar = (
  <div className="toolbar" style={{ gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
   <DropdownMenu
    groups={[
     {
      id: "templates",
      actions: CHECK_TEMPLATES.map((t) => ({
       id: t.id,
       label: t.label,
       onSelect: () => setEditor({ source: t.source, editing: null, title: `New custom scan check — ${t.label}` }),
      })),
     },
    ]}
    trigger={<Button>New check</Button>}
   />
   <Button variant="outline" onClick={() => fileInput.current?.click()}>
    Import .bcheck…
   </Button>
   <input
    ref={fileInput}
    type="file"
    accept=".bcheck,text/plain"
    hidden
    aria-label="Import a BCheck file"
    onChange={(event) => {
     const file = event.target.files?.[0];
     if (file) onImportFile(file);
     event.target.value = "";
    }}
   />
   <Button variant="outline" onClick={onReload} disabled={reload.isPending}>
    {reload.isPending ? "Reloading…" : "Reload --bchecks directory"}
   </Button>
  </div>
 );

 return (
  <div className="page">
   <PageHeader
    title="Custom scan checks"
    description="The BCheck corpus this process loaded, both buckets, and a per-row switch the audit engine reads."
    actions={<RefreshButton onClick={() => void corpus.refetch()} loading={corpus.isFetching} />}
   />
   {error ? <ErrorNotice error={error} /> : null}
   {!data && isFetching ? <LoadingPanel /> : null}

   {toolbar}
   <CustomCheckEditor target={editor} onClose={() => setEditor(null)} />

   {data && !data.enabled ? (
    <div className="notice notice-warn">
     No BCheck corpus is loaded. Write or import a check here, or start burpsy with <code>--bchecks DIR</code>; until then the scanner
     audits with the built-in checks alone.
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
      <SimpleTable headers={["Check", "Bucket", "Status", "Run count", "Severity", "Source", "Enabled", "Actions"]}>
       {(data.checks ?? []).map((row: CorpusCheckView) => (
        <CheckRow
         key={`${row.name}-${row.passive ? "p" : "a"}`}
         row={row}
         onToggle={(next) => toggle(row, next)}
         onOpen={() => open(row)}
         onExport={() => exportRow(row)}
         onDelete={() => deleteRow(row)}
        />
       ))}
      </SimpleTable>
     )}
    </Card>
   ) : null}
  </div>
 );
}
