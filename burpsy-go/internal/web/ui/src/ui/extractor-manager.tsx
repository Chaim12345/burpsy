import { useEffect, useState } from "react";
import { Plus, Save, X } from "lucide-react";
import { toast } from "sonner";
import { ApiError } from "../lib/api";
import {
 draftToExtractor,
 emptyExtractorDraft,
 extractorToDraft,
 MAX_HISTORY_EXTRACTORS,
 validateDrafts,
 type ExtractorDraft,
 type HistoryExtractor,
} from "../lib/extractors";
import { Button, IconButton, Input, Modal, Select, Toolbar } from "./primitives";

/**
 * The custom extractor column manager (burpsy-react-ui-28n8).
 *
 * Edits the saved set as a list of flat drafts — the same controls the session-rule editor uses for
 * an extraction (name; source Body or Header+name; method Regex+group / JSON path / Whole value) —
 * and PUTs the whole set. Client-side validation is deliberately light: it catches the obvious
 * mistakes (empty name, duplicate name, too many) for an instant answer, and leaves the real refusal
 * — a bad regex, an unsupported JSON-path construct — to the server, whose 400 message is shown
 * inline here rather than as a toast that vanishes, because the operator needs it beside the field
 * they must fix. The drafts are KEPT on a failed save so nothing an operator typed is lost.
 *
 * # Column ORDER is not edited here
 *
 * The left-to-right order of the columns is owned by the table's own drag-to-reorder (bead mem3),
 * which persists per table and works on these derived columns exactly as on the built-in ones. A
 * reorder control in this manager would fight that persisted order and lose — the table would keep
 * showing the dragged order — so it would be a dead control. The saved definition order sets where a
 * newly added column first appears; after that, the operator reorders by dragging the header. Adding
 * a manager reorder that actually drives the table is a follow-up that belongs in table.tsx.
 */
export function ExtractorManager({
 open,
 onOpenChange,
 extractors,
 onSave,
 saving,
}: {
 open: boolean;
 onOpenChange: (open: boolean) => void;
 extractors: readonly HistoryExtractor[];
 onSave: (extractors: HistoryExtractor[]) => Promise<HistoryExtractor[]>;
 saving: boolean;
}): JSX.Element {
 const [drafts, setDrafts] = useState<ExtractorDraft[]>([]);
 const [serverError, setServerError] = useState<string | null>(null);

 // Reload the drafts from the saved set each time the modal opens, so a cancelled edit does not
 // linger into the next open and the form always starts from what is actually saved.
 useEffect(() => {
  if (!open) return;
  setDrafts(extractors.map(extractorToDraft));
  setServerError(null);
 }, [open, extractors]);

 const patch = (index: number, changes: Partial<ExtractorDraft>) =>
  setDrafts((current) => current.map((draft, i) => (i === index ? { ...draft, ...changes } : draft)));

 const clientError = validateDrafts(drafts);

 const save = async () => {
  setServerError(null);
  if (clientError) {
   setServerError(clientError);
   return;
  }
  try {
   await onSave(drafts.map(draftToExtractor));
   toast.success(
    drafts.length === 0 ? "Cleared the extractor columns" : `Saved ${drafts.length} extractor column${drafts.length === 1 ? "" : "s"}`,
   );
   onOpenChange(false);
  } catch (cause) {
   // The server's own message — a bad regex, an unsupported JSON path, a duplicate it caught — shown
   // inline so it sits beside the rows that produced it rather than disappearing as a toast.
   setServerError(
    cause instanceof ApiError ? cause.message : cause instanceof Error ? cause.message : "The server refused the extractors.",
   );
  }
 };

 return (
  <Modal
   open={open}
   onOpenChange={onOpenChange}
   wide
   title="Extractor columns"
   description="Each extractor is rendered as a column in HTTP history: every visible row runs it against its stored response and shows the captured value. Saved with the project."
  >
   <div className="stack">
    {drafts.length === 0 ? (
     <p className="field-hint">
      No extractor columns yet. Add one to pull a field — a CSRF token, a user id, a rate-limit header — out of every response and read it
      as a column.
     </p>
    ) : (
     <div className="stack-tight" role="list" aria-label="Extractor columns">
      {drafts.map((draft, index) => (
       <div className="extractor-row" role="listitem" key={index}>
        <Input
         aria-label={`Extractor ${index + 1} column name`}
         title={`Extractor ${index + 1} column name`}
         value={draft.name}
         placeholder="csrf"
         onChange={(event) => patch(index, { name: event.target.value })}
        />
        <Select
         aria-label={`Extractor ${index + 1} source`}
         title={`Extractor ${index + 1} source`}
         value={draft.fromKind}
         onChange={(event) => patch(index, { fromKind: event.target.value === "header" ? "header" : "body" })}
        >
         <option value="body">From body</option>
         <option value="header">From header</option>
        </Select>
        <Input
         aria-label={`Extractor ${index + 1} header name`}
         title={`Extractor ${index + 1} header name`}
         value={draft.header}
         placeholder="X-Token"
         disabled={draft.fromKind !== "header"}
         onChange={(event) => patch(index, { header: event.target.value })}
        />
        <Select
         aria-label={`Extractor ${index + 1} method`}
         title={`Extractor ${index + 1} method`}
         value={draft.how}
         onChange={(event) => {
          const value = event.target.value;
          patch(index, { how: value === "json_path" ? "json_path" : value === "whole" ? "whole" : "regex" });
         }}
        >
         <option value="regex">Regex</option>
         <option value="json_path">JSON path</option>
         <option value="whole">Whole value</option>
        </Select>
        <Input
         aria-label={`Extractor ${index + 1} pattern`}
         title={`Extractor ${index + 1} pattern`}
         value={draft.pattern}
         placeholder={draft.how === "json_path" ? "data.token" : 'name="csrf" value="([^"]+)"'}
         disabled={draft.how === "whole"}
         onChange={(event) => patch(index, { pattern: event.target.value })}
        />
        <Input
         aria-label={`Extractor ${index + 1} capture group`}
         title={`Extractor ${index + 1} capture group`}
         value={draft.group}
         placeholder="1"
         disabled={draft.how !== "regex"}
         onChange={(event) => patch(index, { group: event.target.value })}
        />
        <div className="extractor-row-actions">
         <IconButton
          label={`Remove extractor ${index + 1}`}
          size="small"
          onClick={() => setDrafts((current) => current.filter((_, i) => i !== index))}
         >
          <X size={13} />
         </IconButton>
        </div>
       </div>
      ))}
     </div>
    )}

    <div>
     <Button
      variant="outline"
      size="small"
      disabled={drafts.length >= MAX_HISTORY_EXTRACTORS}
      title={drafts.length >= MAX_HISTORY_EXTRACTORS ? `At most ${MAX_HISTORY_EXTRACTORS} columns` : undefined}
      onClick={() => setDrafts((current) => [...current, emptyExtractorDraft()])}
     >
      <Plus size={13} />
      Add extractor
     </Button>
     {drafts.length > 1 ? <small className="field-hint">Reorder the columns by dragging their headers in the table.</small> : null}
    </div>

    {/* The one place an error lives: a client-side mistake until the operator saves, then the
        server's own words if it refused. role=alert so a screen reader hears it on save. */}
    {serverError ? (
     <div className="error-notice" role="alert">
      <span className="error-notice-icon" aria-hidden="true">
       ⚠
      </span>
      <div>
       <strong>The extractors were not saved</strong>
       <span>{serverError}</span>
      </div>
     </div>
    ) : null}

    <Toolbar>
     <Button variant="primary" size="small" disabled={saving} onClick={() => void save()}>
      <Save size={13} />
      {saving ? "Saving…" : "Save columns"}
     </Button>
     <Button variant="quiet" size="small" onClick={() => onOpenChange(false)}>
      Cancel
     </Button>
    </Toolbar>
   </div>
  </Modal>
 );
}

/**
 * One cell of a derived extractor column (burpsy-react-ui-28n8). The five states are deliberately
 * distinct — the house rule that empty, failed and loading must not read alike:
 *
 *  - a captured value: shown, with the full text as a title since the column is narrow;
 *  - "" the extractor really captured: an empty-string marker, NOT a blank cell, so "matched empty"
 *    is visibly different from "did not match";
 *  - null (the response had no such field): an em dash;
 *  - no value in the answer: a dash, with the reason the row has none — either it has no stored
 *    response, or the run is still loading, or the run failed (the notice above the table carries the
 *    failure; a per-cell error notice across every row would be noise);
 */
export function ExtractorCell({
 value,
 hasResponse,
 loading,
 failed,
 noResponseTitle = "No response was captured for this row",
}: {
 value: string | null | undefined;
 hasResponse: boolean;
 loading: boolean;
 failed: boolean;
 /** Why a row with no stored response has no value — the reason differs between tables. */
 noResponseTitle?: string;
}): JSX.Element {
 if (value === undefined) {
  if (!hasResponse)
   return (
    <span className="cell-dim" title={noResponseTitle}>
     —
    </span>
   );
  if (loading)
   return (
    <span className="cell-dim" title="Running the extractors…">
     …
    </span>
   );
  if (failed)
   return (
    <span className="cell-dim" title="The extractor run failed — see the notice above the table">
     —
    </span>
   );
  return (
   <span className="cell-dim" title="No value for this row">
    —
   </span>
  );
 }
 if (value === null)
  return (
   <span className="cell-dim" title="No match in the response">
    —
   </span>
  );
 if (value === "")
  return (
   <span className="cell-dim" title="Captured an empty string">
    &quot;&quot;
   </span>
  );
 return <span title={value}>{value}</span>;
}
