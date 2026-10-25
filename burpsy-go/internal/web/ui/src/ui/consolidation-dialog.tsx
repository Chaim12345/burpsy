import { useEffect, useState } from "react";
import { Plus, Save, X } from "lucide-react";
import { toast } from "sonner";
import { formatCount } from "../lib/api";
import {
 CONSOLIDATION_ACTIONS,
 useIssueConsolidation,
 useSetIssueConsolidation,
 type ConsolidationAction,
} from "../lib/data.consolidation";
import { Button, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Toolbar } from "./primitives";
import { SimpleTable } from "./table";

/**
 * The issue consolidation policy (burpsy-react-ui-oorl): Burp's merge choice — keep existing, keep
 * both, keep new — applied to every issue type, with per-type exceptions, plus what consolidation has
 * done this session. A scan does not stop to ask per collision, so "apply to all" is the default
 * action and the exceptions are the per-type answers.
 *
 * `issueNames` feeds the override picker with the issue types already reported, which are the ones
 * an operator has evidence about; any catalog name can still be typed.
 */
export function ConsolidationDialog({
 open,
 onOpenChange,
 issueNames,
}: {
 open: boolean;
 onOpenChange: (open: boolean) => void;
 issueNames: readonly string[];
}): JSX.Element {
 const query = useIssueConsolidation();
 const save = useSetIssueConsolidation();
 const [def, setDef] = useState<ConsolidationAction>("keep_existing");
 const [rows, setRows] = useState<{ name: string; action: ConsolidationAction }[]>([]);
 const [newName, setNewName] = useState("");

 // Start from what is saved each time the dialog opens, so a cancelled edit does not linger.
 useEffect(() => {
  if (!open || !query.data) return;
  setDef(query.data.default);
  setRows(Object.entries(query.data.per_row).map(([name, action]) => ({ name, action })).sort((a, b) => a.name.localeCompare(b.name)));
  setNewName("");
 }, [open, query.data]);

 const neverMerge = new Set(query.data?.never_merge ?? []);
 const tally = query.data?.tally;

 const addRow = () => {
  const name = newName.trim();
  if (!name || rows.some((row) => row.name === name)) return;
  setRows((current) => [...current, { name, action: def === "keep_both" ? "keep_existing" : "keep_both" }]);
  setNewName("");
 };

 const submit = () =>
  save.mutate(
   { default: def, per_row: Object.fromEntries(rows.map((row) => [row.name, row.action])) },
   {
    onSuccess: () => {
     toast.success("Consolidation policy saved — it applies to issues reported from now on");
     onOpenChange(false);
    },
    onError: (cause) => toast.error(`Could not save the consolidation policy: ${cause.message}`),
   },
  );

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   wide
   title="Issue consolidation"
   description="What happens when a scan reports an issue that is already reported at the same place. A change applies to issues reported after it; a merge already made is not undone."
  >
   {query.error ? <ErrorNotice error={query.error} onRetry={() => void query.refetch()} /> : null}
   {query.data ? (
    <div className="stack">
     <Field label="For every issue type" hint={CONSOLIDATION_ACTIONS.find((a) => a.value === def)?.hint}>
      {(id) => (
       <Select id={id} value={def} onChange={(event) => setDef(event.target.value as ConsolidationAction)}>
        {CONSOLIDATION_ACTIONS.map((a) => (
         <option key={a.value} value={a.value}>
          {a.label}
         </option>
        ))}
       </Select>
      )}
     </Field>

     <div>
      <h3>Exceptions by issue type</h3>
      {rows.length === 0 ? (
       <Empty title="No exceptions" detail="Every issue type uses the action above." />
      ) : (
       <SimpleTable headers={["Issue type", "Action", ""]}>
        {rows.map((row, index) => (
         <tr key={row.name}>
          <td>
           {row.name}
           {neverMerge.has(row.name) ? <span className="cell-dim"> — never merged, so this has no effect</span> : null}
          </td>
          <td>
           <Select
            aria-label={`Action for ${row.name}`}
            value={row.action}
            onChange={(event) =>
             setRows((current) => current.map((r, i) => (i === index ? { ...r, action: event.target.value as ConsolidationAction } : r)))
            }
           >
            {CONSOLIDATION_ACTIONS.map((a) => (
             <option key={a.value} value={a.value}>
              {a.label}
             </option>
            ))}
           </Select>
          </td>
          <td>
           <IconButton label={`Remove the exception for ${row.name}`} size="small" onClick={() => setRows((current) => current.filter((_, i) => i !== index))}>
            <X size={13} />
           </IconButton>
          </td>
         </tr>
        ))}
       </SimpleTable>
      )}
      <Toolbar>
       <Field label="Exception for issue type">
        {(id) => (
         <>
          <Input
           id={id}
           list="consolidation-issue-names"
           value={newName}
           placeholder="e.g. Strict transport security not enforced"
           onChange={(event) => setNewName(event.target.value)}
           onKeyDown={(event) => {
            if (event.key === "Enter") addRow();
           }}
          />
          <datalist id="consolidation-issue-names">
           {issueNames.filter((name) => !neverMerge.has(name)).map((name) => (
            <option key={name} value={name} />
           ))}
          </datalist>
         </>
        )}
       </Field>
       <Button variant="outline" size="small" disabled={!newName.trim()} onClick={addRow}>
        <Plus size={13} />
        Add exception
       </Button>
      </Toolbar>
     </div>

     <div>
      <h3>What consolidation has done</h3>
      {tally && tally.collisions > 0 ? (
       <>
        <p className="cell-dim">
         {formatCount(tally.collisions)} duplicate report(s) this session: {formatCount(tally.merged)} merged, {formatCount(tally.kept_both)} kept as
         separate issues, {formatCount(tally.replaced)} replaced the issue they duplicated.
        </p>
        <SimpleTable headers={["Run", "Duplicates", "Merged", "Kept both", "Replaced"]}>
         {query.data.by_task.map((task) => (
          <tr key={task.task_id}>
           <td>{task.task_id === 0 ? "untracked (proxy, imports)" : `task ${task.task_id}`}</td>
           <td><span className="cell-num">{formatCount(task.collisions)}</span></td>
           <td><span className="cell-num">{formatCount(task.merged)}</span></td>
           <td><span className="cell-num">{formatCount(task.kept_both)}</span></td>
           <td><span className="cell-num">{formatCount(task.replaced)}</span></td>
          </tr>
         ))}
        </SimpleTable>
       </>
      ) : (
       <p className="cell-dim">No duplicate has been reported this session, so nothing has been consolidated yet.</p>
      )}
      {neverMerge.size > 0 ? (
       <p className="cell-dim">Never merged, whatever the action: {[...neverMerge].join(", ")}.</p>
      ) : null}
     </div>

     <Toolbar>
      <Button onClick={submit} disabled={save.isPending}>
       <Save size={13} />
       Save
      </Button>
      <Button variant="quiet" onClick={() => onOpenChange(false)}>
       Cancel
      </Button>
     </Toolbar>
    </div>
   ) : null}
  </Modal>
 );
}
