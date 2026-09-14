import { useMemo, useRef, useState } from "react";
import { Plus, Trash2, Pencil, ClipboardPaste, FolderOpen } from "lucide-react";
import { toast } from "sonner";
import { useScopeView, useUpdateScope } from "../lib/data.policy";
import { describeScopeRule, parseScopePaste, type ScopeRuleArms } from "../lib/scope-paste";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, Input, Modal, Select, Textarea, Toolbar } from "../ui/primitives";
import { VirtualTable, type Column } from "../ui/table";

/** One row of the rules table: the exact tuple the wire reports, keyed for selection. */
interface ScopeRow {
 kind: "Include" | "Exclude";
 host: string;
 port: number | null;
 path: string | null;
 protocol: string | null;
 enabled: boolean;
}

const rowKey = (row: ScopeRow) =>
 `${row.kind}|${row.host}|${row.port ?? ""}|${row.path ?? ""}|${row.protocol ?? ""}`;

/**
 * Scope sits under Target, where Burp puts it. The editor is a full Burp-style rule table rather
 * than the host-pattern-only form Settings grew from: the Go API has carried port and path arms
 * since ScopeRequest grew Path/Port, and remove matches the whole tuple, so the UI finally offers
 * both instead of pretending the API ends at the host.
 *
 * # Paste URL and Load from file (dao)
 *
 * Burp carries both on every scope-entry surface, because scoping a 40-host engagement through a
 * five-field form is 40 decompositions done by hand. The paste box does the decomposition
 * (lib/scope-paste.ts) and Load from file fills the same box, so the file format is one entry per
 * line rather than a second format to agree on — which is the question the issue parked. Both are
 * previewed before anything is written, and the lines that are not rules are named with their
 * reasons, because the failure this feature has to avoid is a host that quietly never became a
 * rule: the scan then touches something the operator did not authorise, or skips something they
 * did, and nothing afterwards says which.
 */
export function ScopePage(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useScopeView();
 const update = useUpdateScope();

 const [kind, setKind] = useState<"include" | "exclude">("include");
 const [pattern, setPattern] = useState("");
 const [port, setPort] = useState("");
 const [path, setPath] = useState("");
 const [protocol, setProtocol] = useState<"" | "http" | "https">("");
 const [selected, setSelected] = useState<ScopeRow | null>(null);

 // The paste dialog's own box. Kept out of the five Add fields deliberately: a pasted entry is
 // decomposition *into* those fields' arms, and writing a URL into the Host field would be a rule
 // named after a URL — the one shape Burp's Paste URL exists to prevent.
 const [pasting, setPasting] = useState(false);
 const [pasteText, setPasteText] = useState("");
 // A hidden input is the only way a page reads a file the operator picked, and it has to be in
 // the DOM to be clicked — the same shape the message editor's paste-from-file uses.
 const pasteFileRef = useRef<HTMLInputElement>(null);

 const run = (body: Parameters<typeof update.mutate>[0], message: string) =>
  update.mutate(body, {
   onSuccess: () => toast.success(message),
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Scope change failed"),
  });

 const setDropOutOfScope = (on: boolean) =>
  run({ action: "drop_out_of_scope", enabled: on }, on
   ? "Out-of-scope requests will be dropped"
   : "Out-of-scope requests will be forwarded");

 const addRule = () => {
  if (!pattern.trim()) {
   toast.error("A host pattern is required.");
   return;
  }
  const trimmedPort = port.trim();
  const parsedPort = trimmedPort === "" ? undefined : Number(trimmedPort);
  if (parsedPort !== undefined && (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535)) {
   toast.error("Port must be an integer between 1 and 65535.");
   return;
  }
  run(
   {
    action: kind,
    pattern: pattern.trim(),
    ...(parsedPort !== undefined ? { port: parsedPort } : {}),
    ...(path.trim() ? { path: path.trim() } : {}),
    ...(protocol ? { protocol } : {}),
   },
   `${kind === "include" ? "Included" : "Excluded"} ${pattern.trim()}`,
  );
  setPattern("");
  setPort("");
  setPath("");
  setProtocol("");
 };

 // The edit affordance (k5l): Burp's "Edit the selected item" button. The dialog pre-fills from
 // the selected row, and saving sends old_* (what the table showed) plus the replacement arms.
 const [editing, setEditing] = useState(false);
 const [editKind, setEditKind] = useState<"include" | "exclude">("include");
 const [editPattern, setEditPattern] = useState("");
 const [editPort, setEditPort] = useState("");
 const [editPath, setEditPath] = useState("");
 const [editProtocol, setEditProtocol] = useState<"" | "http" | "https">("");

 const openEdit = () => {
  if (!selected) return;
  setEditKind(selected.kind.toLowerCase() as "include" | "exclude");
  setEditPattern(selected.host);
  setEditPort(selected.port !== null ? String(selected.port) : "");
  setEditPath(selected.path ?? "");
  setEditProtocol((selected.protocol as "http" | "https" | null) ?? "");
  setEditing(true);
 };

 const saveEdit = () => {
  if (!selected) return;
  if (!editPattern.trim()) {
   toast.error("Host is required");
   return;
  }
  run(
   {
    action: "edit",
    old_pattern: selected.host,
    old_kind: selected.kind.toLowerCase() as "include" | "exclude",
    ...(selected.port !== null ? { old_port: selected.port } : {}),
    ...(selected.path !== null ? { old_path: selected.path } : {}),
    ...(selected.protocol !== null ? { old_protocol: selected.protocol as "http" | "https" } : {}),
    kind: editKind,
    pattern: editPattern.trim(),
    ...(editPort.trim() ? { port: Number(editPort) } : {}),
    ...(editPath.trim() ? { path: editPath.trim() } : {}),
    ...(editProtocol ? { protocol: editProtocol } : {}),
   },
   `Edited rule: ${selected.host} → ${editPattern.trim()}`,
  );
  setEditing(false);
  setSelected(null);
 };

 const removeSelected = () => {
  if (!selected) return;
  run(
   {
    action: "remove",
    kind: selected.kind.toLowerCase() as "include" | "exclude",
    pattern: selected.host,
    ...(selected.port !== null ? { port: selected.port } : {}),
    ...(selected.path !== null ? { path: selected.path } : {}),
    ...(selected.protocol !== null ? { protocol: selected.protocol as "http" | "https" } : {}),
   },
   `Removed ${selected.host}`,
  );
  setSelected(null);
 };

 const rows = useMemo<ScopeRow[]>(
  () =>
   (data?.rules ?? []).map((rule) => ({
    kind: rule.kind,
    host: rule.host ?? "",
    port: rule.port ?? null,
    path: rule.path ?? null,
    protocol: rule.protocol ?? null,
    enabled: rule.enabled,
   })),
  [data],
 );

 /**
  * What the box currently parses to, previewed before anything is written and recomputed as the
  * operator types. The existing rules are handed in so a re-pasted list is reported as already in
  * scope rather than doubling it — the parser treats "already there" as a refusal with a reason,
  * because it is the same class of line: readable, and deliberately not added.
  */
 const pastePreview = useMemo(() => {
  const existing: ScopeRuleArms[] = rows.map((row) => ({
   pattern: row.host,
   ...(row.port !== null ? { port: row.port } : {}),
   ...(row.path !== null ? { path: row.path } : {}),
   ...(row.protocol !== null ? { protocol: row.protocol as "http" | "https" } : {}),
  }));
  return parseScopePaste(pasteText, existing);
 }, [pasteText, rows]);

 /**
  * Add every parsed rule under the kind the form is showing, and report what actually happened.
  *
  * A partial failure is stated as a partial failure and the box is left alone so the rest can be
  * sent again: the alternative — a single "added" toast over a loop that stopped at line 12 — is the
  * one outcome an operator cannot recover from, because the rules that did land are invisible until
  * they read the table.
  */
 const addPasted = async () => {
  const { rules: accepted, refused, duplicates } = pastePreview;
  if (accepted.length === 0) {
   toast.error("Nothing to add: no line in the box is a scope rule.");
   return;
  }
  let added = 0;
  let failure: unknown = null;
  for (const rule of accepted) {
   try {
    await update.mutateAsync({
     action: kind,
     pattern: rule.pattern,
     ...(rule.port !== undefined ? { port: rule.port } : {}),
     ...(rule.path ? { path: rule.path } : {}),
     ...(rule.protocol ? { protocol: rule.protocol } : {}),
    });
    added += 1;
   } catch (problem) {
    failure = problem;
    break;
   }
  }
  const skipped: string[] = [];
  if (duplicates.length > 0) skipped.push(`${duplicates.length} already in scope`);
  if (refused.length > 0) skipped.push(`${refused.length} unreadable`);
  const tail = skipped.length > 0 ? ` (skipped ${skipped.join(", ")})` : "";
  if (failure) {
   const reason = failure instanceof Error ? failure.message : "the server refused it";
   toast.error(`Added ${added} of ${accepted.length} rules, then the server refused the next one: ${reason}. The box is unchanged, so the rest can be added again.`);
   return;
  }
  toast.success(`Added ${added} scope rule${added === 1 ? "" : "s"}${tail}`);
  setPasteText("");
  setPasting(false);
 };

 /** Load from file fills the box; the operator still sees and edits it before Add. */
 const loadPasteFile = async (file: File) => {
  const contents = await file.text();
  setPasteText((current) => (current.trim() === "" ? contents : `${current.replace(/\n+$/, "")}\n${contents}`));
 };

 const columns = useMemo<Column<ScopeRow>[]>(
  () => [
   {
    accessorKey: "enabled",
    header: "Enabled",
    size: 80,
    cell: (info) => {
     const value = info.getValue<boolean>();
     return (
      <Checkbox
       label={<span className="sr-only">{`Toggle rule ${info.row.original.host}`}</span>}
       checked={value}
       onCheckedChange={(on) =>
        run(
         {
          action: "toggle",
          kind: info.row.original.kind.toLowerCase() as "include" | "exclude",
          pattern: info.row.original.host,
          ...(info.row.original.path !== null ? { path: info.row.original.path } : {}),
          ...(info.row.original.port !== null ? { port: info.row.original.port } : {}),
          ...(info.row.original.protocol !== null
           ? { protocol: info.row.original.protocol as "http" | "https" }
           : {}),
          enabled: on,
         },
         `${info.row.original.host} ${on ? "enabled" : "disabled"}`,
        )
       }
      />
     );
    },
   },
   { accessorKey: "kind", header: "Kind", size: 90 },
   { accessorKey: "host", header: "Host", size: 260 },
   {
    accessorKey: "port",
    header: "Port",
    size: 90,
    cell: (info) => {
     const value = info.getValue<number | null>();
     return value === null ? <span className="cell-dim">any</span> : <span className="cell-num">{value}</span>;
    },
   },
   {
    accessorKey: "protocol",
    header: "Protocol",
    size: 100,
    cell: (info) => {
     const value = info.getValue<string | null>();
     return value === null ? <span className="cell-dim">any</span> : <code>{value}</code>;
    },
   },
   {
    accessorKey: "path",
    header: "Path prefix",
    cell: (info) => {
     const value = info.getValue<string | null>();
     return value === null ? <span className="cell-dim">any</span> : <code>{value}</code>;
    },
   },
  ],
  [],
 );

 return (
  <div className="page-fill">
   <div>
    <PageHeader
     title="Scope"
     description="What the proxy, scanner and crawler are allowed to touch. Changes persist immediately."
     actions={
      <>
       {data ? <Badge tone={data.allow_all ? "warn" : "good"}>{data.allow_all ? "everything in scope" : "restricted"}</Badge> : null}
       <Button
        variant="outline"
        size="small"
        onClick={() => {
         setSelected(null);
         run({ action: "clear" }, "Scope cleared");
        }}
        disabled={!data || data.empty}
       >
        <Trash2 size={13} />
        Clear scope
       </Button>
       <RefreshButton onClick={() => void refetch()} loading={isFetching} />
      </>
     }
    />
   </div>

   <Card>
    <SectionHeading title="Add scope rule" detail="Port and path are optional arms; a rule without them covers the whole host." />
    {error ? <ErrorNotice error={error} onRetry={() => void refetch()} /> : null}
    {isLoading ? <LoadingPanel label="Loading scope" /> : null}
    <Toolbar>
     <Field label="Rule kind" hint="Excludes win over includes.">
      {(id) => (
       <Select id={id} value={kind} onChange={(event) => setKind(event.target.value === "exclude" ? "exclude" : "include")} style={{ maxWidth: "var(--w-sm)" }}>
        <option value="include">Include</option>
        <option value="exclude">Exclude</option>
       </Select>
      )}
     </Field>
     <Field label="Host pattern" hint="For example api.example.com or *.example.com.">
      {(id) => <Input id={id} value={pattern} onChange={(event) => setPattern(event.target.value)} placeholder="api.example.com" />}
     </Field>
     <Field label="Port" hint="Optional; blank means any port.">
      {(id) => <Input id={id} value={port} onChange={(event) => setPort(event.target.value)} placeholder="8443" inputMode="numeric" style={{ maxWidth: "var(--w-xs)" }} />}
     </Field>
     <Field label="Path prefix" hint="Optional; must start with /.">
      {(id) => <Input id={id} value={path} onChange={(event) => setPath(event.target.value)} placeholder="/v2" style={{ maxWidth: "var(--w-sm)" }} />}
     </Field>
     <Field label="Protocol" hint="Optional; blank means either scheme.">
      {(id) => (
       <Select id={id} value={protocol} onChange={(event) => setProtocol(event.target.value === "http" ? "http" : event.target.value === "https" ? "https" : "")} style={{ maxWidth: "var(--w-xs)" }}>
        <option value="">Any</option>
        <option value="http">HTTP</option>
        <option value="https">HTTPS</option>
       </Select>
      )}
     </Field>
     <Button variant="primary" onClick={addRule}>
      <Plus size={14} />
      Add rule
     </Button>
     {/* Burp's second entry point, beside the form: a list of URLs into a list of rules. */}
     <Button variant="outline" onClick={() => setPasting(true)}>
      <ClipboardPaste size={14} />
      Paste URL
     </Button>
    </Toolbar>
   </Card>

   <Card>
    <SectionHeading
     title="Out-of-scope request handling"
     detail="Drop all out-of-scope requests: requests to hosts the scope excludes are not issued at all — the guardrail that stops burpsy touching hosts you have no permission to test. Off, out-of-scope traffic is forwarded (and kept or dropped per the proxy's logging switch)."
    />
    <Toolbar>
     <Checkbox
      label="Drop all out-of-scope requests"
      checked={data?.drop_out_of_scope ?? false}
      onCheckedChange={setDropOutOfScope}
     />
    </Toolbar>
   </Card>

   <Card className="card-fill">
    <SectionHeading
     title="Rules"
     detail="Select a row to remove exactly that tuple — two rules on one host differing only in path are removed separately."
     actions={
      <>
       <Button variant="outline" size="small" onClick={openEdit} disabled={!selected}>
        <Pencil size={13} />
        Edit rule
       </Button>
       <Button variant="outline" size="small" onClick={removeSelected} disabled={!selected}>
        <Trash2 size={13} />
        Remove rule
       </Button>
      </>
     }
    />
    <VirtualTable
     ariaLabel="Scope rules"
     data={rows}
     columns={columns}
     getRowId={rowKey}
     selectedId={selected ? rowKey(selected) : null}
     onSelect={setSelected}
     empty={<Empty title="No scope rules" detail="An empty scope means everything is in scope. Add a rule to restrict what burpsy touches." />}
    />

   <Modal
    open={pasting}
    onOpenChange={setPasting}
    title="Paste URLs"
    description="One entry per line: a full URL, or a bare host pattern like the Host field takes. Blank lines and lines starting with # are ignored. Each entry is decomposed into the rule's arms under the kind selected above."
    wide
   >
    <div className="stack">
     <Field
      label={`Entries to add as ${kind === "include" ? "inclusions" : "exclusions"}`}
      hint="Load from file reads the same format: one entry per line. Nothing is added until you press Add, and the lines that are not rules are listed below with the reason."
     >
      {(id) => (
       <Textarea
        id={id}
        value={pasteText}
        onChange={(event) => setPasteText(event.target.value)}
        placeholder={"https://api.example.com:8443/v2\n*.example.com\n10.0.0.1:8080"}
        rows={8}
        aria-describedby="scope-paste-preview"
       />
      )}
     </Field>
     <Toolbar>
      <Button variant="outline" size="small" onClick={() => pasteFileRef.current?.click()}>
       <FolderOpen size={14} />
       Load from file
      </Button>
      <Button
       variant="outline"
       size="small"
       onClick={() => setPasteText("")}
       disabled={pasteText.trim() === ""}
      >
       Clear
      </Button>
     </Toolbar>
     {/*
      * The preview is the whole point of a paste box: what each line becomes, and what each line
      * that becomes nothing was refused for. Counts first, then the lines themselves, because the
      * count is what the operator checks after fixing a list and the lines are what they fix.
      */}
     <div id="scope-paste-preview" className="stack">
      <p>
       {pastePreview.rules.length} rule{pastePreview.rules.length === 1 ? "" : "s"} to add
       {pastePreview.duplicates.length > 0 ? `, ${pastePreview.duplicates.length} already in scope` : ""}
       {pastePreview.refused.length > 0 ? `, ${pastePreview.refused.length} unreadable` : ""}
      </p>
      {pastePreview.rules.slice(0, 8).map((rule, index) => (
       <p key={`rule-${index}`}>
        <code>{describeScopeRule(rule)}</code>
       </p>
      ))}
      {pastePreview.rules.length > 8 ? <p className="cell-dim">…and {pastePreview.rules.length - 8} more.</p> : null}
      {[...pastePreview.duplicates, ...pastePreview.refused].map((line) => (
       <p key={`line-${line.line}`} className="cell-dim">
        Line {line.line}: <code>{line.text}</code> — {line.reason}.
       </p>
      ))}
     </div>
     <div className="page-actions">
      <Button variant="outline" onClick={() => setPasting(false)}>
       Cancel
      </Button>
      {/* The count is on the button in every state, including zero: the click that adds nothing is
          the one worth disabling by name, and "Add rules" beside "0 rules to add" reads as if the
          count were an accident. */}
      <Button
       disabled={update.isPending || pastePreview.rules.length === 0}
       onClick={() => void addPasted()}
      >
       Add {pastePreview.rules.length} rule{pastePreview.rules.length === 1 ? "" : "s"}
      </Button>
     </div>
     <input
      ref={pasteFileRef}
      type="file"
      accept=".txt,.list,text/plain"
      className="sr-only"
      aria-hidden="true"
      tabIndex={-1}
      onChange={(event) => {
       const file = event.target.files?.[0];
       // Cleared so re-picking the same file fires change again: a file edited on disk and loaded
       // twice is an ordinary way to fix a line the preview refused.
       event.target.value = "";
       if (file) void loadPasteFile(file);
      }}
     />
    </div>
   </Modal>

   <Modal
    open={editing}
    onOpenChange={setEditing}
    title="Edit scope rule"
    description={`Replacing ${selected ? `${selected.kind.toLowerCase()} ${selected.host}` : ""} in place — the replacement takes its position in the list.`}
   >
    <div className="stack">
     <Field label="Type">
      {(id) => (
       <Select id={id} value={editKind} onChange={(e) => setEditKind(e.target.value as "include" | "exclude")}>
        <option value="include">Include in scope</option>
        <option value="exclude">Exclude from scope</option>
       </Select>
      )}
     </Field>
     <Field label="Host">
      {(id) => <Input id={id} value={editPattern} onChange={(e) => setEditPattern(e.target.value)} placeholder="*.example.com" />}
     </Field>
     <Field label="Port" hint="Blank matches any port.">
      {(id) => <Input id={id} value={editPort} onChange={(e) => setEditPort(e.target.value)} placeholder="443" />}
     </Field>
     <Field label="Path prefix" hint="Blank covers the whole host.">
      {(id) => <Input id={id} value={editPath} onChange={(e) => setEditPath(e.target.value)} placeholder="/api" />}
     </Field>
     <Field label="Protocol" hint="Blank matches either scheme.">
      {(id) => (
       <Select id={id} value={editProtocol} onChange={(e) => setEditProtocol(e.target.value as "" | "http" | "https")}>
        <option value="">Any</option>
        <option value="http">http</option>
        <option value="https">https</option>
       </Select>
      )}
     </Field>
     <div className="page-actions">
      <Button variant="outline" onClick={() => setEditing(false)}>
       Cancel
      </Button>
      <Button disabled={update.isPending || !editPattern.trim()} onClick={saveEdit}>
       Save
      </Button>
     </div>
    </div>
   </Modal>
   </Card>
  </div>
 );
}
