import { useEffect, useMemo, useState } from "react";
import { ExternalLink, Plus, RotateCcw, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useOrganizer, useOrganizerMutations } from "../lib/data";
import { useApp } from "../lib/store";
import { HIGHLIGHTS, HIGHLIGHT_TONE, type OrganizerEdit, type OrganizerItem } from "../lib/types";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Textarea, Toolbar } from "../ui/primitives";
import { SimpleTable } from "../ui/table";
interface Draft {
 title: string;
 note: string;
 highlight: string;
}

function draftOf(item: OrganizerItem): Draft {
 return { title: item.title, note: item.note, highlight: item.highlight || "none" };
}

/* --- filters (burpsy-react-ui-k4r) -----------------------------------------
 *
 * Burp filters the Organizer by in-scope, status class and MIME type. burpsy could not, and the
 * missing piece was data rather than controls: an organizer item is `{id, exchange, title, note,
 * highlight}` and none of the three is in it. The list endpoint now resolves each item against the
 * traffic store and the scope, so these filters run over fields that are actually on the wire.
 *
 * # The rule every filter here obeys
 *
 * An item whose exchange has been evicted cannot be judged — no status, no MIME, no scope answer.
 * Such a row is *exempt* from every filter rather than failing it, because the alternative hides a
 * note the operator deliberately wrote, and hides it precisely when they are searching. The row
 * carries an "unresolved" badge so its exemption is visible rather than mysterious, and the count
 * line says how many rows are being shown for that reason instead of on merit.
 *
 * That is a deliberate false-positive bias: a filtered view here may show rows that do not match.
 * The opposite bias loses evidence, and on this page evidence is the entire product.
 */

/**
 * Status code to badge tone.
 *
 * 401 and 403 are `warn` rather than `bad`: a saved 403 is usually saved *because* it is interesting
 * — something is there and refusing you — and colouring it as a failure buries the reason the
 * operator kept it.
 */
function statusTone(status: number): "neutral" | "good" | "warn" | "bad" | "info" {
 if (status >= 500) return "bad";
 if (status === 401 || status === 403) return "warn";
 if (status >= 400) return "neutral";
 if (status >= 300) return "info";
 return "good";
}

/** Status classes, as Burp groups them. */
const STATUS_CLASSES = [
 { value: "all", label: "Any status" },
 { value: "2xx", label: "2xx success" },
 { value: "3xx", label: "3xx redirect" },
 { value: "4xx", label: "4xx client error" },
 { value: "5xx", label: "5xx server error" },
 // Its own option rather than folded into "any": an exchange with no response is a state an
 // operator looks for on purpose, and no status class contains it.
 { value: "none", label: "No response" },
] as const;

type StatusClass = (typeof STATUS_CLASSES)[number]["value"];

function matchesStatusClass(item: OrganizerItem, want: StatusClass): boolean {
 if (want === "all") return true;
 if (want === "none") return !item.has_response;
 if (item.status === undefined) return false;
 const hundreds = Math.floor(item.status / 100);
 return want === `${hundreds}xx`;
}

/**
 * The MIME options offered, derived from what is actually saved rather than from a fixed list.
 *
 * A hardcoded vocabulary would offer types nothing in the organizer has, and would silently omit
 * whatever the target actually serves. `has_response` separates the two empty cases: a response
 * with no usable Content-Type is offered as its own option, a pending one is not a MIME at all and
 * belongs to the status filter's "No response".
 */
function mimeOptions(items: OrganizerItem[]): string[] {
 const seen = new Set<string>();
 for (const item of items) {
  if (!item.resolved || !item.has_response) continue;
  seen.add(item.mime && item.mime !== "" ? item.mime : "(none declared)");
 }
 return [...seen].sort((a, b) => a.localeCompare(b));
}

function matchesMime(item: OrganizerItem, want: string): boolean {
 if (want === "all") return true;
 if (!item.has_response) return false;
 const mime = item.mime && item.mime !== "" ? item.mime : "(none declared)";
 return mime === want;
}

export function OrganizerPage(): JSX.Element {
 const { data, error, isFetching, isLoading, refetch } = useOrganizer();
 const mutations = useOrganizerMutations();
 const focusExchange = useApp((state) => state.focusExchange);
 const setRoute = useApp((state) => state.setRoute);

 /** Selection is by item id: a refetch reorders or replaces objects, ids survive it. */
 const [selectedId, setSelectedId] = useState<number | null>(null);
 const [draft, setDraft] = useState<Draft | null>(null);
 const [baseline, setBaseline] = useState("");
 const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
 const [exchangeId, setExchangeId] = useState("");

 const [inScopeOnly, setInScopeOnly] = useState(false);
 const [statusClass, setStatusClass] = useState<StatusClass>("all");
 const [mimeFilter, setMimeFilter] = useState("all");

 const items = useMemo(() => data?.items ?? [], [data]);
 const mimes = useMemo(() => mimeOptions(items), [items]);

 const filtering = inScopeOnly || statusClass !== "all" || mimeFilter !== "all";

 /**
  * The filtered rows, plus how many were kept only because they could not be judged.
  *
  * `unjudged` is reported rather than hidden: it is the difference between "three of your saved
  * exchanges are 4xx" and "three matched and two are unknowable", and on a page whose output is
  * read as evidence those are not the same statement.
  */
 const { visible, unjudged } = useMemo(() => {
  if (!filtering) return { visible: items, unjudged: 0 };
  const kept: OrganizerItem[] = [];
  let exempt = 0;
  for (const item of items) {
   if (!item.resolved) {
    // Cannot be judged, so it is not judged. See the filter note above.
    kept.push(item);
    exempt++;
    continue;
   }
   if (inScopeOnly && item.in_scope !== true) continue;
   if (!matchesStatusClass(item, statusClass)) continue;
   if (!matchesMime(item, mimeFilter)) continue;
   kept.push(item);
  }
  return { visible: kept, unjudged: exempt };
 }, [items, filtering, inScopeOnly, statusClass, mimeFilter]);

 // A MIME option can disappear when the rows behind it are removed, which would leave the filter
 // pinned to a value nothing can match — an empty table with no visible reason. Fall back to "all".
 useEffect(() => {
  if (mimeFilter !== "all" && !mimes.includes(mimeFilter)) setMimeFilter("all");
 }, [mimes, mimeFilter]);

 const selected = useMemo(() => items.find((item) => item.id === selectedId) ?? null, [items, selectedId]);
 const dirty = draft !== null && JSON.stringify(draft) !== baseline;

 // Adopt the server's copy only while the note has no unsaved edits, so a refetch
 // triggered by another pane cannot throw away what the operator is typing.
 useEffect(() => {
  if (!selected) {
   if (draft !== null) {
    setDraft(null);
    setBaseline("");
   }
   return;
  }
  const next = JSON.stringify(draftOf(selected));
  if (next === baseline) return;
  if (draft !== null && JSON.stringify(draft) !== baseline) return;
  setDraft(draftOf(selected));
  setBaseline(next);
 }, [selected, draft, baseline]);

 const select = (item: OrganizerItem) => {
  setSelectedId(item.id);
  setDraft(draftOf(item));
  setBaseline(JSON.stringify(draftOf(item)));
 };

 const add = () => {
  const exchange = Number(exchangeId.trim());
  // `< 0`, not `<= 0`. Exchange ids count from zero, so exchange 0 is the first request captured in
  // a session — the one most likely to be reached for first, and the one this guard used to refuse.
  if (!Number.isInteger(exchange) || exchange < 0) {
   toast.error("Enter an exchange id — a whole number, counting from 0");
   return;
  }
  mutations.add.mutate(exchange, {
   onSuccess: (item) => {
    setExchangeId("");
    select(item);
    toast.success(`Saved exchange #${exchange}`);
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not save that exchange"),
  });
 };

 const save = () => {
  if (!selected || !draft) return;
  // OrganizerEdit, not OrganizerItem: the read shape now carries status, MIME and scope, which
  // the server derives and a client has no business restating. Typing the payload as the read
  // shape would let a save claim to know an exchange's status.
  const payload: OrganizerEdit = {
   id: selected.id,
   title: draft.title,
   note: draft.note,
   highlight: draft.highlight === "none" ? "" : draft.highlight,
  };
  mutations.save.mutate(payload, {
   onSuccess: () => {
    setBaseline(JSON.stringify(draft));
    toast.success("Note saved");
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Save failed"),
  });
 };

 const remove = (id: number) => {
  mutations.remove.mutate(id, {
   onSuccess: () => {
    if (selectedId === id) {
     setSelectedId(null);
     setDraft(null);
     setBaseline("");
    }
    toast.success("Removed from the organizer");
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Delete failed"),
  });
  setConfirmDelete(null);
 };

 /** Reveal the underlying exchange in HTTP history rather than copying its bytes here. */
 const openInHistory = (exchange: number) => {
  focusExchange(exchange);
  setRoute("history");
 };

 if (error) {
  return (
   <div className="page">
    <PageHeader title="Organizer" />
    <ErrorNotice error={error} onRetry={() => void refetch()} />
   </div>
  );
 }

 return (
  <div className="page">
   <PageHeader
    title="Organizer"
    description="A shortlist of exchanges worth coming back to, with the note that says why."
    actions={
     <>
      <Badge>{items.length} saved</Badge>
      <RefreshButton onClick={() => void refetch()} loading={isFetching} />
     </>
    }
   />

   <Card>
    <SectionHeading
     title="Saved exchanges"
     detail="Usually added from HTTP history's save action; an exchange id works too."
    />
    <Toolbar>
     <div className="inline-add">
      <Input
       aria-label="Exchange id to save"
       title="Exchange id to save"
       value={exchangeId}
       inputMode="numeric"
       placeholder="exchange id"
       onChange={(event) => setExchangeId(event.target.value)}
       onKeyDown={(event) => {
        if (event.key === "Enter") add();
       }}
       style={{ maxWidth: "var(--w-sm)" }}
      />
      <Button variant="outline" size="small" onClick={add} disabled={!exchangeId.trim() || mutations.add.isPending}>
       <Plus size={13} />
       Save exchange
      </Button>
     </div>
    </Toolbar>

    <Toolbar>
     <Checkbox
      label="In scope only"
      checked={inScopeOnly}
      onCheckedChange={(next) => setInScopeOnly(next === true)}
     />
     <Field label="Status" className="field-inline">
      {(id) => (
       <Select id={id} value={statusClass} onChange={(event) => setStatusClass(event.target.value as StatusClass)}>
        {STATUS_CLASSES.map((option) => (
         <option key={option.value} value={option.value}>
          {option.label}
         </option>
        ))}
       </Select>
      )}
     </Field>
     <Field label="MIME type" className="field-inline">
      {(id) => (
       <Select id={id} value={mimeFilter} onChange={(event) => setMimeFilter(event.target.value)} disabled={mimes.length === 0}>
        <option value="all">Any type</option>
        {mimes.map((mime) => (
         <option key={mime} value={mime}>
          {mime}
         </option>
        ))}
       </Select>
      )}
     </Field>
     {filtering ? (
      <>
       <Button
        variant="outline"
        size="small"
        onClick={() => {
         setInScopeOnly(false);
         setStatusClass("all");
         setMimeFilter("all");
        }}
       >
        <RotateCcw size={13} />
        Clear filters
       </Button>
       {/* Both numbers, always. "5 of 12" alone would let a filtered view be mistaken for the
                  whole organizer, which is the mistake this page can least afford. */}
       <span className="cell-dim">
        showing {visible.length} of {items.length}
       </span>
       {unjudged > 0 ? (
        <Badge tone="warn" title="Their exchange is no longer in the traffic store, so no filter can judge them">
         {unjudged} shown unjudged
        </Badge>
       ) : null}
      </>
     ) : null}
    </Toolbar>
    {isLoading ? (
     <LoadingPanel label="Loading saved exchanges" />
    ) : items.length === 0 ? (
     <Empty
      title="Nothing saved yet"
      detail="Save an exchange from HTTP history, or add one by id above, to start an investigation note."
     />
    ) : visible.length === 0 ? (
     /* Distinct from the empty-organizer panel above: nothing was lost, the filters are simply
        narrower than the contents, and saying so is what tells the operator which to change. */
     <Empty
      title="No saved exchange matches these filters"
      detail={`All ${items.length} are still here. Widen or clear the filters to see them.`}
     />
    ) : (
     <SimpleTable headers={["#", "Exchange", "Request", "Status", "Type", "Title", "Highlight", "Note", ""]}>
      {visible.map((item) => (
       <tr
        key={item.id}
        className={item.id === selectedId ? "data-row clickable selected-row" : "data-row clickable"}
        onClick={() => select(item)}
       >
        <td>
         <span className="cell-num">{item.id}</span>
        </td>
        <td>
         <span className="cell-num">#{item.exchange}</span>
        </td>
        {/* The three resolved columns. An unresolved row says so once, spanning them, rather
                    than showing three em-dashes that would read as "no status, no type, no host" —
                    which is a claim about the exchange instead of an admission about the store. */}
        {item.resolved ? (
         <>
          <td>
           <span className="cell-dim" title={`${item.method ?? ""} ${item.host ?? ""}${item.path ?? ""}`}>
            {item.method ? `${item.method} ` : ""}
            {item.path || "/"}
           </span>
           {item.in_scope === false ? (
            <Badge tone="neutral" title="Outside the current engagement scope">
             out of scope
            </Badge>
           ) : null}
          </td>
          <td>
           {item.status !== undefined ? (
            <Badge tone={statusTone(item.status)}>{item.status}</Badge>
           ) : (
            <span className="cell-dim" title="No response was recorded for this exchange">
             no response
            </span>
           )}
          </td>
          <td>
           <span className="cell-dim">
            {!item.has_response ? "—" : item.mime && item.mime !== "" ? item.mime : "none declared"}
           </span>
          </td>
         </>
        ) : (
         <td colSpan={3}>
          <Badge tone="warn" title="The exchange is no longer in the traffic store; the note survives it">
           exchange no longer retained
          </Badge>
         </td>
        )}
        <td>{item.title || <span className="cell-dim">untitled</span>}</td>
        <td>
         {item.highlight ? (
          <Badge tone={HIGHLIGHT_TONE[item.highlight] ?? "neutral"}>{item.highlight}</Badge>
         ) : (
          <span className="cell-dim">—</span>
         )}
        </td>
        <td>
         <span className="cell-dim">{item.note ? item.note.split("\n")[0] : "no note"}</span>
        </td>
        <td>
         <div className="chip-row">
          <IconButton
           label={`Open exchange #${item.exchange} in HTTP history`}
           size="small"
           onClick={(event) => {
            event.stopPropagation();
            openInHistory(item.exchange);
           }}
          >
           <ExternalLink size={13} />
          </IconButton>
          <IconButton
           label={`Remove item ${item.id}`}
           size="small"
           onClick={(event) => {
            event.stopPropagation();
            setConfirmDelete(item.id);
           }}
          >
           <Trash2 size={13} />
          </IconButton>
         </div>
        </td>
       </tr>
      ))}
     </SimpleTable>
    )}
   </Card>

   <Card>
    {selected && draft ? (
     <>
      <SectionHeading
       title={`Exchange #${selected.exchange}`}
       detail="The note stays attached to the exchange, not to a copy of its bytes."
       actions={
        <>
         {dirty ? <Badge tone="warn">unsaved changes</Badge> : <Badge tone="good">saved</Badge>}
         <Button variant="outline" size="small" onClick={() => openInHistory(selected.exchange)}>
          <ExternalLink size={13} />
          Show in history
         </Button>
         <Button
          variant="outline"
          size="small"
          disabled={!dirty}
          onClick={() => {
           setDraft(JSON.parse(baseline) as Draft);
           toast.success("Reverted to the saved note");
          }}
         >
          <RotateCcw size={13} />
          Revert
         </Button>
         <Button size="small" onClick={save} disabled={!dirty || mutations.save.isPending}>
          <Save size={13} />
          {mutations.save.isPending ? "Saving…" : "Save"}
         </Button>
         <Button variant="danger" size="small" onClick={() => setConfirmDelete(selected.id)}>
          <Trash2 size={13} />
          Remove
         </Button>
        </>
       }
      />
      <div className="stack">
       <div className="form-grid">
        <Field label="Title" hint="What this exchange is, in a few words.">
         {(id) => (
          <Input
           id={id}
           value={draft.title}
           placeholder="admin panel exposes user list"
           onChange={(event) => setDraft({ ...draft, title: event.target.value })}
          />
         )}
        </Field>
        <Field label="Highlight" hint="Tap a colour to assign it.">
         {(_id) => (
          <div className="swatch-row" role="radiogroup" aria-label="Highlight colour">
           {HIGHLIGHTS.map((colour) => (
            <button
             key={colour}
             type="button"
             role="radio"
             aria-checked={draft.highlight === colour}
             className={draft.highlight === colour ? "swatch-button swatch-active" : "swatch-button"}
             style={{ "--swatch-color": "var(--highlight-" + colour + ")" } as React.CSSProperties}
             title={colour}
             onClick={() => setDraft({ ...draft, highlight: colour })}
            />
           ))}
          </div>
         )}
        </Field>
       </div>
       <Field label="Investigation note" hint="Saved explicitly; a background refresh will not overwrite an edit in progress.">
        {(id) => (
         <Textarea
          id={id}
          value={draft.note}
          rows={8}
          placeholder="What was observed, what to try next, and which request reproduces it."
          onChange={(event) => setDraft({ ...draft, note: event.target.value })}
         />
        )}
       </Field>
      </div>
     </>
    ) : (
     <Empty title="No item selected" detail="Choose a saved exchange to read or edit its note." />
    )}
   </Card>

   <Modal
    open={confirmDelete !== null}
    onOpenChange={(open) => {
     if (!open) setConfirmDelete(null);
    }}
    title="Remove this item?"
    description="The note is deleted. The exchange itself stays in HTTP history."
   >
    <div className="page-actions">
     <Button variant="outline" onClick={() => setConfirmDelete(null)}>
      Keep it
     </Button>
     <Button
      variant="danger"
      disabled={mutations.remove.isPending}
      onClick={() => (confirmDelete === null ? undefined : remove(confirmDelete))}
     >
      <Trash2 size={13} />
      Remove item
     </Button>
    </div>
   </Modal>
  </div>
 );
}
