import { useMemo, useState } from "react";
import { Plus, Trash2, Pencil } from "lucide-react";
import { toast } from "sonner";
import { useScopeView, useUpdateScope } from "../lib/data.policy";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, Input, Modal, Select, Toolbar } from "../ui/primitives";
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
