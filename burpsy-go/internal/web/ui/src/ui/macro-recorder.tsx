import { useMemo, useState } from "react";
import { toast } from "sonner";
import { exchangeUrl } from "../lib/actions";
import { useHistory } from "../lib/data";
import { useRecordMacroSteps } from "../lib/data.policy";
import type { Exchange } from "../lib/types";
import type { SessionMacroStep } from "../lib/types.policy";
import { Empty, ErrorNotice, Button, Checkbox, Field, Input, Modal, Select } from "./primitives";
import { SimpleTable } from "./table";

/**
 * Burp's Macro Recorder (burpsy-react-ui-escl).
 *
 * Burp's own copy is the specification: "Macros are made up of requests taken from the Proxy history
 * […] Select the items you need from the Proxy history list." So this dialog is a selection over
 * history, not a form — the operator picks rows and gets back the steps those rows describe.
 *
 * # Why the conversion is not done here
 *
 * The stored request is origin-form and its authority lives on the exchange row, so turning a row
 * into a step is a join with rules — which port is omitted, how an IPv6 literal is bracketed, what
 * happens to a repeated header. Those rules are the session package's, and the validator that
 * decides whether a saved rule is usable reads the same ones. Re-implementing them in TypeScript
 * would put a second copy beside the first, and the copy is what drifts: a recorder that builds a
 * step the server then refuses, or worse accepts spelled differently from what the operator picked.
 * The server does the join; this dialog only chooses the rows.
 *
 * # The second answer is shown, not swallowed
 *
 * The server reports rows it could not convert in `skipped`. This dialog surfaces that count and the
 * reasons instead of discarding them, because a recorder that returns three steps from four selected
 * rows is how a login macro ends up one request short — and the failure surfaces at the next login,
 * with nothing on screen having ever said a row was dropped.
 *
 * # Selection is by order of clicking
 *
 * A macro replays its steps in order, so the order the operator selected in is preserved and shown
 * by number. Sorting the selection by history position instead would silently reorder a login
 * sequence whenever the history list was re-sorted.
 */
export function MacroRecorder({
 open,
 onOpenChange,
 onRecord,
}: {
 open: boolean;
 onOpenChange: (open: boolean) => void;
 onRecord: (steps: SessionMacroStep[]) => void;
}): JSX.Element {
 // The same read the History page uses. A generous limit because the recorder is a picker over
 // recent traffic and pagination would be worse than a long list here.
 const history = useHistory("", 500);
 const record = useRecordMacroSteps();
 const [term, setTerm] = useState("");
 const [picked, setPicked] = useState<number[]>([]);
 const [variant, setVariant] = useState<"edited" | "original" | "auto-modified">("edited");

 const rows = useMemo(() => {
  const all = history.data ?? [];
  const needle = term.trim().toLowerCase();
  if (needle === "") return all;
  return all.filter(
   (row) =>
    row.host.toLowerCase().includes(needle) ||
    row.path.toLowerCase().includes(needle) ||
    row.method.toLowerCase().includes(needle),
  );
 }, [history.data, term]);

 const toggle = (id: number, on: boolean) =>
  setPicked((current) => (on ? [...current, id] : current.filter((existing) => existing !== id)));

 const close = () => {
  onOpenChange(false);
  // Cleared on close so reopening the dialog does not resurrect a selection the operator made,
  // thought better of, and dismissed — a stale tick is how a request gets into a macro twice.
  setPicked([]);
  setTerm("");
 };

 const submit = () => {
  record.mutate(
   { exchanges: picked, variant },
   {
    onSuccess: (result) => {
     if (result.steps.length > 0) {
      onRecord(result.steps);
      toast.success(
       result.steps.length === 1
        ? "Recorded 1 step from history"
        : `Recorded ${result.steps.length} steps from history`,
      );
     }
     // Reported rather than hidden, and reported even when some steps succeeded: the operator has
     // to know which rows did not make it before they save the rule.
     if (result.skipped.length > 0) {
      const first = result.skipped[0];
      toast.warning(
       `${result.skipped.length} selected row(s) could not be recorded` +
        (first ? ` — e.g. exchange ${first.exchange}: ${first.reason}` : ""),
      );
     }
     if (result.steps.length > 0) close();
    },
    onError: (failure: unknown) =>
     toast.error(failure instanceof Error ? failure.message : "Could not record a macro from history"),
   },
  );
 };

 return (
  <Modal
   open={open}
   onOpenChange={(next) => (next ? onOpenChange(true) : close())}
   title="Record a macro from HTTP history"
   description="Select the requests to replay, in order. The proxy captured them, so each step keeps the method, target, headers and body it sent."
   wide
  >
   <Field label="Filter history" hint="Matches host, path and method.">
    {(id) => (
     <Input id={id} value={term} placeholder="shop.test" onChange={(event) => setTerm(event.target.value)} />
    )}
   </Field>

   <Field label="Request to record" hint="A macro replays what actually travelled. The other readings are for diagnosing a Match & Replace rule.">
    {(id) => (
     <Select
      id={id}
      value={variant}
      onChange={(event) => setVariant(event.target.value as "edited" | "original" | "auto-modified")}
     >
      <option value="edited">As sent (after edits)</option>
      <option value="auto-modified">Before manual edit (after rules)</option>
      <option value="original">Original (before rules)</option>
     </Select>
    )}
   </Field>

   {history.error ? <ErrorNotice error={history.error} /> : null}

   {rows.length === 0 ? (
    <Empty
     title={history.isLoading ? "Reading history…" : "No matching requests"}
     detail={
      history.isLoading
       ? "The recorder reads the proxy's stored exchanges."
       : "Send the login flow through the proxy first, then record it."
     }
    />
   ) : (
    <SimpleTable headers={["", "Order", "Method", "URL", "Status"]} density="compact">
     {rows.map((row: Exchange) => {
      const position = picked.indexOf(row.id);
      return (
       <tr key={row.id}>
        <td>
         <Checkbox
          label={`Select exchange ${row.id}`}
          checked={position >= 0}
          onCheckedChange={(on) => toggle(row.id, on)}
         />
        </td>
        <td>{position >= 0 ? position + 1 : ""}</td>
        <td>{row.method}</td>
        {/* The shared exchange URL helper, not a local one: it already omits the scheme's default
            port, which is exactly how the recorded step's URL is spelled, so the picker and the
            step that lands in the rule show the same address. */}
        <td>{exchangeUrl(row)}</td>
        <td>{row.status ?? "—"}</td>
       </tr>
      );
     })}
    </SimpleTable>
   )}

   <div className="page-actions">
    <Button variant="outline" onClick={close}>
     Cancel
    </Button>
    <Button disabled={picked.length === 0 || record.isPending} onClick={submit}>
     {/* "Record 0 steps" is what a bare template produces here, and it reads as an offer rather
         than as the disabled state it is. Naming the action without a count is honest about there
         being nothing selected yet. */}
     {record.isPending
      ? "Recording…"
      : picked.length === 0
        ? "Record steps"
        : picked.length === 1
          ? "Record 1 step"
          : `Record ${picked.length} steps`}
    </Button>
   </div>
  </Modal>
 );
}
