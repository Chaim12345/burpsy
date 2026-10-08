import { useMemo, useRef, useState } from "react";
import { Plus, Trash2, Pencil, ClipboardPaste, FolderOpen, BookMarked, Library } from "lucide-react";
import { toast } from "sonner";
import { useScopeView, useUpdateScope, useUpdateScopeLibrary, type ScopeLibraryEntry } from "../lib/data.policy";
import {
 describeScopeLibraryAge,
 describeScopeLibraryDelete,
 describeScopeLibraryLoad,
 describeScopeLibraryLoaded,
 describeScopeLibrarySaved,
 isScopeLibraryDamaged,
 scopeRuleCount,
} from "../lib/scope-library";
import { describeScopeRule, parseScopePaste, type ScopeRuleArms } from "../lib/scope-paste";
import { dropRulesFrom, dropRulesInclude } from "../lib/drop-scope";
import type { DropScopeRule } from "../lib/types.policy";
import {
 decodeHostArm,
 decodePathArm,
 encodeHostArm,
 encodePathArm,
 hostArmLabel,
 hostArmProblem,
 pathArmProblem,
 type HostArmMode,
 type PathArmMode,
} from "../lib/scope-arms";
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
 *
 * # Host and path arms (c09)
 *
 * Burp reads each URL component as a regular expression, and the host field as a regex *or* an IP
 * range. burpsy read the host as a glob and the path as a literal prefix and nothing else. Both new
 * arms are here as a mode selector beside the field they change, because one field read three ways
 * with no visible statement of which is exactly how an operator ends up believing a restriction is
 * in force when it is not. The mode is not a new wire field: it is encoded into the same pattern and
 * path strings the rule has always carried (lib/scope-arms.ts, and core/scope.go for why).
 *
 * # Simple and advanced (c09)
 *
 * Burp ships both — "enable advanced scope control" — where simple mode is a flat list of URL
 * prefixes and advanced is the rule table. burpsy has only ever had the middle: more than prefixes,
 * less than regex. The toggle below offers Burp's simple entry form, which turns one pasted URL into
 * the arms it decomposes to, and it is *only* an entry form: it is component state, it never reaches
 * the wire, the rules table is the same table in both modes, and no stored rule changes meaning when
 * it is flipped. Advanced is the default, because that is what this page has always shown and
 * hiding working controls behind a toggle nobody knew to look for is its own regression.
 */
export function ScopePage(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useScopeView();
 const update = useUpdateScope();

 const [kind, setKind] = useState<"include" | "exclude">("include");
 const [pattern, setPattern] = useState("");
 const [port, setPort] = useState("");
 const [path, setPath] = useState("");
 const [protocol, setProtocol] = useState<"" | "http" | "https">("");
 const [hostMode, setHostMode] = useState<HostArmMode>("wildcard");
 const [pathMode, setPathMode] = useState<PathArmMode>("prefix");
 // Burp's "enable advanced scope control", defaulting the other way round: see the header note.
 const [advanced, setAdvanced] = useState(true);
 // Simple mode's only field: one URL whose prefix is the scope, decomposed by the same parser the
 // paste box uses, so the two entry points cannot disagree about what a URL means.
 const [simpleURL, setSimpleURL] = useState("");
 const [selected, setSelected] = useState<ScopeRow | null>(null);

 // The paste dialog's own box. Kept out of the five Add fields deliberately: a pasted entry is
 // decomposition *into* those fields' arms, and writing a URL into the Host field would be a rule
 // named after a URL — the one shape Burp's Paste URL exists to prevent.
 const [pasting, setPasting] = useState(false);
 const [pasteText, setPasteText] = useState("");
 // A hidden input is the only way a page reads a file the operator picked, and it has to be in
 // the DOM to be clicked — the same shape the message editor's paste-from-file uses.
 const pasteFileRef = useRef<HTMLInputElement>(null);

 // Burp's "Save to library" (burpsy-react-ui-e365): a rule set is named, stored and brought back
 // later. The dialogs are state here rather than routes because a library is an operation on this
 // page's rules, and the operator has to be able to see the table they are about to replace.
 const updateLibrary = useUpdateScopeLibrary();
 const [saving, setSaving] = useState(false);
 const [libraryName, setLibraryName] = useState("");
 const [browsing, setBrowsing] = useState(false);
 // The second step of a load or a delete: the entry the operator picked, held so the dialog can
 // state what the click is about to do *before* it does it. A load replaces the live rule list and
 // a delete destroys the only copy of a rule set, and neither is a thing to learn from a toast.
 const [pendingLoad, setPendingLoad] = useState<ScopeLibraryEntry | null>(null);
 const [pendingDelete, setPendingDelete] = useState<ScopeLibraryEntry | null>(null);

 const run = (body: Parameters<typeof update.mutate>[0], message: string) =>
  update.mutate(body, {
   onSuccess: () => toast.success(message),
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Scope change failed"),
  });

 // How many rules the load is about to replace. Read from the same response the table renders, so
 // the sentence in the dialog and the rows on the page can never disagree about what is in scope.
 const liveRuleCount = data?.rules.length ?? 0;
 // The libraries ride the same GET as the rules, so the picker and the table can never disagree
 // about which scope the sentences below are describing.
 const savedLibraries = data?.libraries ?? [];
 const existingLibrary = savedLibraries.find((entry) => entry.name === libraryName.trim());

 const saveLibrary = () => {
  const name = libraryName.trim();
  // Refused here and at the server both: a blank name cannot be picked out of the list again, and
  // the next blank save would replace it with nothing to tell the two apart.
  if (name === "") {
   toast.error("Give the library a name, so you can find it again");
   return;
  }
  updateLibrary.mutate(
   { action: "library_save", name },
   {
    onSuccess: (result) => {
     toast.success(describeScopeLibrarySaved(name, result));
     setSaving(false);
     setLibraryName("");
    },
    onError: (failure: unknown) =>
     toast.error(failure instanceof Error ? failure.message : "The scope library could not be saved"),
   },
  );
 };

 const loadLibrary = (entry: ScopeLibraryEntry) => {
  updateLibrary.mutate(
   { action: "library_load", name: entry.name },
   {
    onSuccess: (result) => {
     toast.success(describeScopeLibraryLoaded(entry.name, result));
     setPendingLoad(null);
     setBrowsing(false);
     // The selected row belonged to the rule list that has just been replaced.
     setSelected(null);
    },
    onError: (failure: unknown) =>
     // The server refuses a library it cannot read rather than installing it as an empty rule
     // list, and its refusal names the library — so it is shown as it arrived.
     toast.error(failure instanceof Error ? failure.message : "The scope library could not be loaded"),
   },
  );
 };

 const deleteLibrary = (entry: ScopeLibraryEntry) => {
  updateLibrary.mutate(
   { action: "library_delete", name: entry.name },
   {
    onSuccess: () => {
     toast.success(`Deleted the scope library “${entry.name}”`);
     setPendingDelete(null);
    },
    onError: (failure: unknown) =>
     toast.error(failure instanceof Error ? failure.message : "The scope library could not be deleted"),
   },
  );
 };

 // Burp's "Use suite scope" / "Use custom scope" for the drop switch (47ed). The custom rules are
 // re-sent whole on every change, with each rule's arms as the server reported them.
 const dropMode = data?.drop_scope?.mode ?? "suite";
 const dropRules = dropRulesFrom(data?.drop_scope?.rules ?? []);
 const [dropHost, setDropHost] = useState("");
 const [dropKind, setDropKind] = useState<"include" | "exclude">("include");
 const sendDropScope = (rules: DropScopeRule[], message: string) => {
  if (!dropRulesInclude(rules)) {
   toast.error("A custom drop scope needs at least one enabled include rule: without one it would admit every request and drop nothing.");
   return false;
  }
  run({ action: "drop_scope", mode: "custom", drop_rules: rules }, message);
  return true;
 };
 const chooseSuiteDropScope = () =>
  run({ action: "drop_scope", mode: "suite" }, "Out-of-scope requests are judged by the suite scope");
 const addDropRule = () => {
  const host = dropHost.trim();
  if (!host) return;
  if (sendDropScope([...dropRules, { action: dropKind, pattern: host, enabled: true }], `Custom drop scope: ${dropKind} ${host}`)) {
   setDropHost("");
  }
 };
 const removeDropRule = (index: number) => {
  const next = dropRules.filter((_, i) => i !== index);
  if (next.length === 0 || !dropRulesInclude(next)) {
   toast.error("That would leave the custom drop scope with no include rule. Add another include first, or switch to the suite scope.");
   return;
  }
  sendDropScope(next, "Custom drop scope rule removed");
 };

 const setDropOutOfScope = (on: boolean) =>
  run({ action: "drop_out_of_scope", enabled: on }, on
   ? "Out-of-scope requests will be dropped"
   : "Out-of-scope requests will be forwarded");

 const addRule = () => {
  // The arm checks run before the port check and before anything is sent, and they are the same
  // checks the server makes: a rule refused here is refused there, so the round trip only exists to
  // tell the operator something this page could have told them at the keystroke.
  const hostProblem = hostArmProblem(hostMode, pattern);
  if (hostProblem) {
   toast.error(hostProblem);
   return;
  }
  const pathProblem = pathArmProblem(pathMode, path);
  if (pathProblem) {
   toast.error(pathProblem);
   return;
  }
  const trimmedPort = port.trim();
  const parsedPort = trimmedPort === "" ? undefined : Number(trimmedPort);
  if (parsedPort !== undefined && (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535)) {
   toast.error("Port must be an integer between 1 and 65535.");
   return;
  }
  const encodedHost = encodeHostArm(hostMode, pattern);
  const encodedPath = encodePathArm(pathMode, path);
  run(
   {
    action: kind,
    pattern: encodedHost,
    ...(parsedPort !== undefined ? { port: parsedPort } : {}),
    ...(encodedPath ? { path: encodedPath } : {}),
    ...(protocol ? { protocol } : {}),
   },
   `${kind === "include" ? "Included" : "Excluded"} ${encodedHost}`,
  );
  setPattern("");
  setPort("");
  setPath("");
  setProtocol("");
 };

 /**
  * Simple mode's Add: one URL prefix becomes one rule.
  *
  * It goes through parseScopePaste rather than a second decomposition, because "what does this URL
  * mean as a rule" is a question this page must answer the same way everywhere — the paste box, the
  * file loader and this field are three doors into one answer. A line that is not a rule is reported
  * with the parser's own reason rather than a generic failure.
  */
 const addSimpleRule = () => {
  const parsed = parseScopePaste(simpleURL);
  const refusal = parsed.refused[0];
  if (refusal) {
   toast.error(`${refusal.text} is not a URL or host pattern: ${refusal.reason}.`);
   return;
  }
  const rule = parsed.rules[0];
  if (!rule) {
   toast.error("Write a URL such as https://example.com/app, or a host pattern such as *.example.com.");
   return;
  }
  if (parsed.rules.length > 1) {
   toast.error("One entry per rule here. Use Paste URL for a list.");
   return;
  }
  run(
   {
    action: kind,
    pattern: rule.pattern,
    ...(rule.port !== undefined ? { port: rule.port } : {}),
    ...(rule.path ? { path: rule.path } : {}),
    ...(rule.protocol ? { protocol: rule.protocol } : {}),
   },
   `${kind === "include" ? "Included" : "Excluded"} ${describeScopeRule(rule)}`,
  );
  setSimpleURL("");
 };

 // The edit affordance (k5l): Burp's "Edit the selected item" button. The dialog pre-fills from
 // the selected row, and saving sends old_* (what the table showed) plus the replacement arms.
 const [editing, setEditing] = useState(false);
 const [editKind, setEditKind] = useState<"include" | "exclude">("include");
 const [editPattern, setEditPattern] = useState("");
 const [editPort, setEditPort] = useState("");
 const [editPath, setEditPath] = useState("");
 const [editProtocol, setEditProtocol] = useState<"" | "http" | "https">("");
 const [editHostMode, setEditHostMode] = useState<HostArmMode>("wildcard");
 const [editPathMode, setEditPathMode] = useState<PathArmMode>("prefix");

 const openEdit = () => {
  if (!selected) return;
  setEditKind(selected.kind.toLowerCase() as "include" | "exclude");
  // The dialog shows the arm the rule actually carries, not the string it is stored as: an operator
  // editing a regex rule must see a regex field, or their next save turns it into a glob named after
  // an expression — a rule that matches nothing and looks like it matches something.
  const host = decodeHostArm(selected.host);
  setEditHostMode(host.mode);
  setEditPattern(host.value);
  const rulePath = decodePathArm(selected.path);
  setEditPathMode(rulePath.mode);
  setEditPath(rulePath.value);
  setEditPort(selected.port !== null ? String(selected.port) : "");
  setEditProtocol((selected.protocol as "http" | "https" | null) ?? "");
  setEditing(true);
 };

 const saveEdit = () => {
  if (!selected) return;
  const hostProblem = hostArmProblem(editHostMode, editPattern);
  if (hostProblem) {
   toast.error(hostProblem);
   return;
  }
  const pathProblem = pathArmProblem(editPathMode, editPath);
  if (pathProblem) {
   toast.error(pathProblem);
   return;
  }
  // old_* is the row exactly as the table showed it — the stored strings, tags and all — because
  // that tuple is the rule's identity on the server. Decoding it for display and sending the decoded
  // form back would name a rule that does not exist, and the edit would 404.
  const encodedHost = encodeHostArm(editHostMode, editPattern);
  const encodedPath = encodePathArm(editPathMode, editPath);
  run(
   {
    action: "edit",
    old_pattern: selected.host,
    old_kind: selected.kind.toLowerCase() as "include" | "exclude",
    ...(selected.port !== null ? { old_port: selected.port } : {}),
    ...(selected.path !== null ? { old_path: selected.path } : {}),
    ...(selected.protocol !== null ? { old_protocol: selected.protocol as "http" | "https" } : {}),
    kind: editKind,
    pattern: encodedHost,
    ...(editPort.trim() ? { port: Number(editPort) } : {}),
    ...(encodedPath ? { path: encodedPath } : {}),
    ...(editProtocol ? { protocol: editProtocol } : {}),
   },
   `Edited rule: ${selected.host} → ${encodedHost}`,
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
   {
    accessorKey: "host",
    header: "Host",
    size: 260,
    // The arm is named beside the value, not left for the reader to infer from the tag. A regex and
    // a glob that happen to read alike authorise very different sets of hosts, and the column is
    // where an operator checks what they wrote.
    cell: (info) => {
     const arm = decodeHostArm(info.getValue<string>());
     return arm.mode === "wildcard" ? (
      <span>{arm.value}</span>
     ) : (
      <span>
       <code>{arm.value}</code> <span className="cell-dim">{hostArmLabel(arm.mode)}</span>
      </span>
     );
    },
   },
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
    // "Path", not "Path prefix": a prefix is now one of the two things this column can hold, and a
    // header naming only one of them would misdescribe every regex rule under it.
    accessorKey: "path",
    header: "Path",
    cell: (info) => {
     const value = info.getValue<string | null>();
     if (value === null) return <span className="cell-dim">any</span>;
     const arm = decodePathArm(value);
     return arm.mode === "prefix" ? (
      <code>{arm.value}</code>
     ) : (
      <span>
       <code>{arm.value}</code> <span className="cell-dim">regex</span>
      </span>
     );
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
       {/* Burp's "Save to library" and its counterpart, beside Clear scope because those three are
           the operations on the rule set as a whole. Save is disabled with nothing to save: a
           library holding no rules is an empty scope, which allows every host, and storing one
           under a name is a trap to load later. */}
       <Button variant="outline" size="small" onClick={() => setSaving(true)} disabled={!data || data.empty}>
        <BookMarked size={13} />
        Save to library
       </Button>
       <Button variant="outline" size="small" onClick={() => setBrowsing(true)}>
        <Library size={13} />
        Load…
       </Button>
       <RefreshButton onClick={() => void refetch()} loading={isFetching} />
      </>
     }
    />
   </div>

   <Card>
    <SectionHeading
     title="Add scope rule"
     detail={
      advanced
       ? "Port and path are optional arms; a rule without them covers the whole host. The host can be a wildcard pattern, a regular expression or an IP range."
       : "Simple mode takes one URL and scopes what sits under it, the way Burp's simple scope does. Everything already in the table keeps working exactly as it is — this changes the form, not the rules."
     }
     actions={
      <Checkbox
       label="Advanced scope control"
       checked={advanced}
       onCheckedChange={setAdvanced}
      />
     }
    />
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
     {advanced ? (
      <>
       <Field label="Host match" hint="How the host field below is read.">
        {(id) => (
         <Select
          id={id}
          value={hostMode}
          onChange={(event) => setHostMode(event.target.value as HostArmMode)}
          style={{ maxWidth: "var(--w-sm)" }}
         >
          <option value="wildcard">Wildcard</option>
          <option value="regex">Regular expression</option>
          <option value="range">IP range</option>
         </Select>
        )}
       </Field>
       <Field
        label="Host"
        hint={
         hostMode === "regex"
          ? "Matches the whole host: write .* for anything either side, as in .*\\.example\\.com."
          : hostMode === "range"
            ? "A CIDR block such as 10.0.0.0/8, or one address. Only IP literals match it — a hostname is never resolved to decide scope."
            : "For example api.example.com or *.example.com."
        }
       >
        {(id) => (
         <Input
          id={id}
          value={pattern}
          onChange={(event) => setPattern(event.target.value)}
          placeholder={hostMode === "regex" ? "api[0-9]+\\.example\\.com" : hostMode === "range" ? "10.0.0.0/8" : "api.example.com"}
         />
        )}
       </Field>
       <Field label="Port" hint="Optional; blank means any port.">
        {(id) => <Input id={id} value={port} onChange={(event) => setPort(event.target.value)} placeholder="8443" inputMode="numeric" style={{ maxWidth: "var(--w-xs)" }} />}
       </Field>
       <Field label="Path match" hint="How the path field below is read.">
        {(id) => (
         <Select
          id={id}
          value={pathMode}
          onChange={(event) => setPathMode(event.target.value as PathArmMode)}
          style={{ maxWidth: "var(--w-sm)" }}
         >
          <option value="prefix">Prefix</option>
          <option value="regex">Regular expression</option>
         </Select>
        )}
       </Field>
       <Field
        label="Path"
        hint={
         pathMode === "regex"
          ? "Optional; matches the whole path, so /admin.* is needed to cover what is under /admin."
          : "Optional; must start with /."
        }
       >
        {(id) => (
         <Input
          id={id}
          value={path}
          onChange={(event) => setPath(event.target.value)}
          placeholder={pathMode === "regex" ? "/v[0-9]+/orders.*" : "/v2"}
          style={{ maxWidth: "var(--w-sm)" }}
         />
        )}
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
      </>
     ) : (
      <>
       <Field
        label={kind === "include" ? "Prefix for in-scope URLs" : "Prefix for out-of-scope URLs"}
        hint="One URL, such as https://example.com/app. Its host, port, scheme and path become the rule's arms — the table below shows exactly what was created."
       >
        {(id) => (
         <Input
          id={id}
          value={simpleURL}
          onChange={(event) => setSimpleURL(event.target.value)}
          placeholder="https://example.com/app"
         />
        )}
       </Field>
       <Button variant="primary" onClick={addSimpleRule}>
        <Plus size={14} />
        Add rule
       </Button>
      </>
     )}
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
    <div role="radiogroup" aria-label="Which scope decides what is dropped" className="stack">
     <label style={{ display: "flex", alignItems: "center", gap: "var(--s1)" }}>
      <input type="radio" name="drop-scope-mode" checked={dropMode === "suite"} onChange={chooseSuiteDropScope} />
      <span>
       Use suite scope <span className="field-hint">— drop what the rules below leave out</span>
      </span>
     </label>
     <label style={{ display: "flex", alignItems: "center", gap: "var(--s1)" }}>
      <input
       type="radio"
       name="drop-scope-mode"
       checked={dropMode === "custom"}
       onChange={() => {
        if (dropRules.length === 0) {
         toast.info("Add an include rule for the custom scope below; it takes effect with the first one.");
        } else {
         run({ action: "drop_scope", mode: "custom" }, "Out-of-scope requests are judged by the custom scope");
        }
       }}
      />
      <span>
       Use custom scope <span className="field-hint">— drop by a separate set of rules</span>
      </span>
     </label>
    </div>
    {dropMode === "suite" && dropRules.length > 0 && (
     <p className="field-hint">The custom scope's rules are kept, not in force, until Use custom scope is chosen again.</p>
    )}
    {dropRules.length > 0 && (
     <ul className="stack" aria-label="Custom drop scope rules" style={{ listStyle: "none", padding: 0 }}>
      {dropRules.map((rule, index) => (
       <li key={`${rule.action}-${rule.pattern}-${rule.path ?? ""}-${rule.port ?? ""}-${index}`} style={{ display: "flex", alignItems: "center", gap: "var(--s2)" }}>
        <Badge>{rule.action === "include" ? "Include" : "Exclude"}</Badge>
        <span className="mono">
         {rule.protocol ? `${rule.protocol}://` : ""}
         {rule.pattern}
         {rule.port ? `:${rule.port}` : ""}
         {rule.path ?? ""}
        </span>
        {rule.enabled === false && <span className="field-hint">disabled</span>}
        <Button variant="outline" size="small" onClick={() => removeDropRule(index)} aria-label={`Remove custom drop rule ${rule.pattern}`}>
         <Trash2 size={13} />
        </Button>
       </li>
      ))}
     </ul>
    )}
    <Toolbar>
     <Field label="Custom scope rule" hint="Saving switches the drop gate to the custom scope">
      {(id) => (
       <Select id={id} value={dropKind} onChange={(event) => setDropKind(event.target.value as "include" | "exclude")} style={{ maxWidth: "var(--w-xs)" }}>
        <option value="include">Include</option>
        <option value="exclude">Exclude</option>
       </Select>
      )}
     </Field>
     <Field label="Host" hint="Same patterns as the suite scope">
      {(id) => (
       <Input
        id={id}
        value={dropHost}
        placeholder="*.client.example"
        onChange={(event) => setDropHost(event.target.value)}
        onKeyDown={(event) => {
         if (event.key === "Enter") addDropRule();
        }}
       />
      )}
     </Field>
     <Button variant="outline" onClick={addDropRule} disabled={!dropHost.trim()}>
      <Plus size={14} />
      Add to custom scope
     </Button>
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

   {/*
     * Save to library (burpsy-react-ui-e365). A name and nothing else: what gets stored is the rule
     * list the table is showing, so a second field describing it would be a second thing to keep
     * true. An existing name is allowed and called out — the ordinary second save is "the same
     * engagement, after I fixed a rule", and making that an error would push operators into
     * inventing names they will not recognise tomorrow.
     */}
   <Modal
    open={saving}
    onOpenChange={(open) => {
     setSaving(open);
     if (!open) setLibraryName("");
    }}
    title="Save scope to library"
    description={`Stores the ${scopeRuleCount(liveRuleCount)} in scope now under a name, so this rule set can be loaded back later — including in another project.`}
   >
    <div className="stack">
     <Field
      label="Library name"
      hint="What you will look for when you want these rules back: the engagement, the target, the phase."
     >
      {(id) => (
       <Input
        id={id}
        value={libraryName}
        onChange={(event) => setLibraryName(event.target.value)}
        placeholder="acme-external-q3"
        onKeyDown={(event) => {
         if (event.key === "Enter") saveLibrary();
        }}
       />
      )}
     </Field>
     {existingLibrary ? (
      <p>
       A library called “{existingLibrary.name}” already exists, saved {describeScopeLibraryAge(existingLibrary.saved_at)}
       {isScopeLibraryDamaged(existingLibrary) ? "" : ` with ${scopeRuleCount(existingLibrary.rules)}`}. Saving replaces it.
      </p>
     ) : null}
     <div className="page-actions">
      <Button variant="outline" onClick={() => setSaving(false)}>
       Cancel
      </Button>
      <Button disabled={updateLibrary.isPending || libraryName.trim() === ""} onClick={saveLibrary}>
       {existingLibrary ? "Replace library" : "Save library"}
      </Button>
     </div>
    </div>
   </Modal>

   {/*
     * Load… — the picker, and the page's statement of what loading means. Nothing loads from this
     * list directly: picking one opens the sentence that says how many rules it will take away and
     * how many it will put back, because a load REPLACES the rule list and the rules it removes are
     * the ones the operator cannot see from a button labelled "Load".
     */}
   <Modal
    open={browsing}
    onOpenChange={(open) => {
     setBrowsing(open);
     if (!open) {
      setPendingLoad(null);
      setPendingDelete(null);
     }
    }}
    title="Scope libraries"
    description="Saved rule sets. Loading one replaces every rule in your scope with the rules it holds — it is not merged into what is there."
    wide
   >
    <div className="stack">
     {data?.libraries_error ? (
      // The server could not read the saved libraries. Shown rather than drawn as an empty picker:
      // "nothing is saved" and "I could not find out what is saved" are different things to tell
      // someone who is about to re-create a rule set.
      <ErrorNotice
       title="The saved libraries could not be read"
       error={new Error(data.libraries_error)}
       onRetry={() => void refetch()}
      />
     ) : isLoading ? (
      <p>Reading the saved libraries…</p>
     ) : savedLibraries.length === 0 ? (
      <Empty
       title="No scope libraries saved"
       detail="Save to library stores the rules you have now under a name. They stay available after a restart and in other projects."
      />
     ) : (
      savedLibraries.map((entry) => (
       <div key={entry.name} className="stack">
        <p>
         <strong>{entry.name}</strong>{" "}
         <span className="cell-dim">
          {isScopeLibraryDamaged(entry) ? "unreadable" : scopeRuleCount(entry.rules)} · saved{" "}
          {describeScopeLibraryAge(entry.saved_at)}
         </span>
        </p>
        <Toolbar>
         <Button
          variant="outline"
          size="small"
          disabled={isScopeLibraryDamaged(entry) || updateLibrary.isPending}
          onClick={() => {
           setPendingDelete(null);
           setPendingLoad(entry);
          }}
         >
          <Library size={13} />
          Load…
         </Button>
         <Button
          variant="outline"
          size="small"
          disabled={updateLibrary.isPending}
          onClick={() => {
           setPendingLoad(null);
           setPendingDelete(entry);
          }}
         >
          <Trash2 size={13} />
          Delete
         </Button>
        </Toolbar>
        {pendingLoad?.name === entry.name ? (
         <div className="stack">
          <p>{describeScopeLibraryLoad(entry, liveRuleCount)}</p>
          <Toolbar>
           <Button variant="outline" size="small" onClick={() => setPendingLoad(null)}>
            Keep my rules
           </Button>
           <Button size="small" disabled={updateLibrary.isPending} onClick={() => loadLibrary(entry)}>
            Replace {scopeRuleCount(liveRuleCount)} with “{entry.name}”
           </Button>
          </Toolbar>
         </div>
        ) : null}
        {pendingDelete?.name === entry.name ? (
         <div className="stack">
          <p>{describeScopeLibraryDelete(entry)}</p>
          <Toolbar>
           <Button variant="outline" size="small" onClick={() => setPendingDelete(null)}>
            Keep it
           </Button>
           <Button size="small" disabled={updateLibrary.isPending} onClick={() => deleteLibrary(entry)}>
            Delete “{entry.name}”
           </Button>
          </Toolbar>
         </div>
        ) : null}
       </div>
      ))
     )}
     <div className="page-actions">
      <Button variant="outline" onClick={() => setBrowsing(false)}>
       Close
      </Button>
     </div>
    </div>
   </Modal>

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
     <Field label="Host match" hint="How the host below is read.">
      {(id) => (
       <Select id={id} value={editHostMode} onChange={(e) => setEditHostMode(e.target.value as HostArmMode)}>
        <option value="wildcard">Wildcard</option>
        <option value="regex">Regular expression</option>
        <option value="range">IP range</option>
       </Select>
      )}
     </Field>
     <Field
      label="Host"
      hint={
       editHostMode === "regex"
        ? "Matches the whole host."
        : editHostMode === "range"
          ? "A CIDR block or one address; only IP literals match it."
          : "A wildcard pattern, such as *.example.com."
      }
     >
      {(id) => <Input id={id} value={editPattern} onChange={(e) => setEditPattern(e.target.value)} placeholder="*.example.com" />}
     </Field>
     <Field label="Port" hint="Blank matches any port.">
      {(id) => <Input id={id} value={editPort} onChange={(e) => setEditPort(e.target.value)} placeholder="443" />}
     </Field>
     <Field label="Path match" hint="How the path below is read.">
      {(id) => (
       <Select id={id} value={editPathMode} onChange={(e) => setEditPathMode(e.target.value as PathArmMode)}>
        <option value="prefix">Prefix</option>
        <option value="regex">Regular expression</option>
       </Select>
      )}
     </Field>
     <Field label="Path" hint={editPathMode === "regex" ? "Blank covers the whole host; otherwise matches the whole path." : "Blank covers the whole host."}>
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
