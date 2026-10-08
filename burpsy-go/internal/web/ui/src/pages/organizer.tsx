import { useEffect, useMemo, useState } from "react";
import { Copy, ExternalLink, FolderInput, FolderPlus, Highlighter, ListTodo, Pencil, Plus, RotateCcw, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { copyToClipboard, downloadText, organizerToCSV } from "../lib/api";
import { useMessage, useOrganizer, useOrganizerMutations } from "../lib/data";
import { useApp } from "../lib/store";
import { promptDialog } from "../lib/dialogs";
import { FILTER_DEFAULTS, sanitizeSettings, type FilterSettings } from "../lib/filter-presets";
import { FilterPresetsMenu } from "../ui/filter-presets";
import {
 HIGHLIGHTS,
 HIGHLIGHT_TONE,
 WORKFLOW_STATUSES,
 WORKFLOW_STATUS_LABEL,
 WORKFLOW_STATUS_TONE,
 type OrganizerCollection,
 type OrganizerEdit,
 type OrganizerItem,
 type WorkflowStatus,
} from "../lib/types";
import { LoadingPanel, PageHeader, RefreshButton, SectionHeading } from "../ui/layout";
import { Badge, Button, Card, Checkbox, Empty, ErrorNotice, Field, IconButton, Input, Modal, Select, Tabs, TabsContent, TabsList, TabsTrigger, Textarea, Toolbar } from "../ui/primitives";
import { HttpEditor } from "../ui/editor";
import { MenuRow, SimpleTable } from "../ui/table";
import { HIGHLIGHT_ICONS } from "../ui/highlight-icons";
import type { MenuGroup } from "../ui/menu";
interface Draft {
 title: string;
 note: string;
 highlight: string;
}

/** The inbox is collection 0; the UI names it rather than minting a numeric id for what is not a collection. */
const INBOX = "inbox" as const;

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

/** The organizer filter selects' closed option sets, for saved presets (mntt). */
const ORGANIZER_FILTER_ALLOWED = {
 statusClass: STATUS_CLASSES.map((entry) => entry.value),
 workflowFilter: ["all", ...WORKFLOW_STATUSES],
};

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

/**
 * The text a search term runs over: the row's own title and note, plus the resolved exchange's
 * host, path and method — the fields an operator names when describing what they saved. An
 * unresolved row contributes only its note and title, because that is all it has.
 */
function rowText(item: OrganizerItem): string {
 const parts = [item.title, item.note, item.host ?? "", item.path ?? "", item.method ?? ""];
 return parts.join("\n");
}

/**
 * The file extension of the saved response's path, lowercased, empty when there is no path or no
 * extension. The extension is the last dot-segment of the path; a trailing dot or a dotless final
 * segment yields "" so it cannot match a real extension filter.
 */
function rowExtension(item: OrganizerItem): string {
 const path = item.path ?? "";
 const slash = path.lastIndexOf("/");
 const last = slash >= 0 ? path.slice(slash + 1) : path;
 const dot = last.lastIndexOf(".");
 if (dot <= 0) return "";
 const ext = last.slice(dot + 1).toLowerCase();
 return /^[a-z0-9]{1,10}$/.test(ext) ? ext : "";
}

function matchesTerm(item: OrganizerItem, raw: string, regex: boolean, caseSensitive: boolean, negative: boolean): boolean {
 if (raw.trim() === "") return true;
 const haystack = rowText(item);
 // An uncompileable regex matches nothing rather than everything: a broken filter that silently
 // passes would read as "no rows matched" on the negative side and hide the breakage.
 const hit = regex
  ? safeRegexTest(raw, caseSensitive, haystack)
  : caseSensitive
    ? haystack.includes(raw)
    : haystack.toLowerCase().includes(raw.toLowerCase());
 return negative ? !hit : hit;
}

function safeRegexTest(pattern: string, caseSensitive: boolean, haystack: string): boolean {
 try {
  return new RegExp(pattern, caseSensitive ? "" : "i").test(haystack);
 } catch {
  return false;
 }
}

/** The distinct file extensions present on resolved rows, sorted. The option list only ever
 * offers what the rows carry, so a filter value that nothing matches cannot be selected. */
function extensionOptions(items: OrganizerItem[]): string[] {
 const seen = new Set<string>();
 for (const item of items) {
  if (!item.resolved) continue;
  const ext = rowExtension(item);
  if (ext !== "") seen.add(ext);
 }
 return [...seen].sort((a, b) => a.localeCompare(b));
}

function matchesMime(item: OrganizerItem, want: string): boolean {
 if (want === "all") return true;
 if (!item.has_response) return false;
 const mime = item.mime && item.mime !== "" ? item.mime : "(none declared)";
 return mime === want;
}

/**
 * The tool options offered (burpsy-react-ui-ldfk), derived from what the saved rows actually carry
 * — same reasoning as mimeOptions above: a fixed list would offer tools nothing here used, and
 * would omit one the server starts naming later without this page changing.
 */
function toolOptions(items: OrganizerItem[]): string[] {
 const seen = new Set<string>();
 for (const item of items) {
  if (!item.resolved || !item.tool) continue;
  seen.add(item.tool);
 }
 return [...seen].sort((a, b) => a.localeCompare(b));
}

function matchesTool(item: OrganizerItem, want: string): boolean {
 if (want === "all") return true;
 return item.tool === want;
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
 /** Burp's "Filter by tool" (tools/organizer/filter.html: "Show or hide items that were sent to
  *  Organizer from different tools"), burpsy-react-ui-ldfk. */
 const [toolFilter, setToolFilter] = useState("all");
 /** The user-applied workflow status to filter on — Burp's "Filter by status", a different axis from the HTTP status class above. */
 const [workflowFilter, setWorkflowFilter] = useState<WorkflowStatus | "all">("all");
 // Burp's remaining filter axes (burpsy-react-ui-6a2l): a search term over the row's own text,
 // with regex / case-sensitive / negative modes; the response's file extension; and the
 // annotation axes (has a note / has a highlight).
 const [term, setTerm] = useState("");
 const [debouncedTerm, setDebouncedTerm] = useState("");
 const [termRegex, setTermRegex] = useState(false);
 const [termCase, setTermCase] = useState(false);
 const [termNegative, setTermNegative] = useState(false);
 const [extensionFilter, setExtensionFilter] = useState("all");
 const [annotatedOnly, setAnnotatedOnly] = useState(false);

 const items = useMemo(() => data?.items ?? [], [data]);
 const collections = useMemo(() => data?.collections ?? [], [data]);
 const mimes = useMemo(() => mimeOptions(items), [items]);
 const tools = useMemo(() => toolOptions(items), [items]);

 useEffect(() => {
  const timer = setTimeout(() => setDebouncedTerm(term), 250);
  return () => clearTimeout(timer);
 }, [term]);

 /**
  * The collection being viewed: "all" is the whole organizer, 0 the inbox, an id one group. This
  * is Burp's organizer frame — the inbox first, collections as where work goes — implemented as a
  * view over one flat store rather than as the store's shape, so a collection cannot strand an
  * item from the operator's single list.
  */
 const [collectionView, setCollectionView] = useState<"all" | number>("all");

 /** The collection delete dialog: its choice is the items' fate, so it is asked, never defaulted silently. */
 const [confirmDeleteCollection, setConfirmDeleteCollection] = useState<OrganizerCollection | null>(null);
 const [newCollectionName, setNewCollectionName] = useState("");

 // Saved filters (mntt): the filter row as it stands, and the one function that puts a preset —
 // or the defaults, for Clear filters — back.
 const filterSnapshot: FilterSettings = {
  term,
  termRegex,
  termCase,
  termNegative,
  inScopeOnly,
  statusClass,
  mimeFilter,
  toolFilter,
  workflowFilter,
  extensionFilter,
  annotatedOnly,
 };
 const applyFilterSettings = (next: FilterSettings) => {
  const v = sanitizeSettings("organizer", next, ORGANIZER_FILTER_ALLOWED).settings;
  setTerm(v.term as string);
  setTermRegex(v.termRegex as boolean);
  setTermCase(v.termCase as boolean);
  setTermNegative(v.termNegative as boolean);
  setInScopeOnly(v.inScopeOnly as boolean);
  setStatusClass(v.statusClass as StatusClass);
  setMimeFilter(v.mimeFilter as string);
  setToolFilter(v.toolFilter as string);
  setWorkflowFilter(v.workflowFilter as WorkflowStatus | "all");
  setExtensionFilter(v.extensionFilter as string);
  setAnnotatedOnly(v.annotatedOnly as boolean);
 };

 const filtering =
  inScopeOnly ||
  statusClass !== "all" ||
  mimeFilter !== "all" ||
  toolFilter !== "all" ||
  workflowFilter !== "all" ||
  debouncedTerm.trim() !== "" ||
  extensionFilter !== "all" ||
  annotatedOnly;

 /**
  * The filtered rows, plus how many were kept only because they could not be judged.
  *
  * `unjudged` is reported rather than hidden: it is the difference between "three of your saved
  * exchanges are 4xx" and "three matched and two are unknowable", and on a page whose output is
  * read as evidence those are not the same statement.
  */
 const { visible, unjudged } = useMemo(() => {
  if (!filtering && collectionView === "all") return { visible: items, unjudged: 0 };
  const kept: OrganizerItem[] = [];
  let exempt = 0;
  for (const item of items) {
   // The collection view is not a judgement about the row, so an unresolved row is still grouped:
   // its collection id is stored state, not derived, and a filter must not scatter it.
   if (collectionView !== "all" && (item.collection ?? 0) !== collectionView) continue;
   if (!item.resolved) {
    // Cannot be judged, so it is not judged. See the filter note above.
    kept.push(item);
    exempt++;
    continue;
   }
   if (inScopeOnly && item.in_scope !== true) continue;
   if (!matchesStatusClass(item, statusClass)) continue;
   if (!matchesMime(item, mimeFilter)) continue;
   if (!matchesTool(item, toolFilter)) continue;
   // An item with no status on the wire predates the field; it reads as "new" (the same fallback
   // the Go load path applies), so the filter matches it against "new" rather than hiding it.
   if (workflowFilter !== "all" && (item.workflow_status ?? "new") !== workflowFilter) continue;
   if (!matchesTerm(item, debouncedTerm, termRegex, termCase, termNegative)) continue;
   if (extensionFilter !== "all" && rowExtension(item) !== extensionFilter) continue;
   // "none" is the highlight picker's no-colour value, not an annotation — a row carrying it
   // has no highlight, whatever the string's length says.
   const annotated = item.note.trim() !== "" || ((item.highlight ?? "").trim() !== "" && item.highlight !== "none");
   if (annotatedOnly && !annotated) continue;
   kept.push(item);
  }
  return { visible: kept, unjudged: exempt };
 }, [items, filtering, inScopeOnly, statusClass, mimeFilter, toolFilter, workflowFilter, collectionView, debouncedTerm, termRegex, termCase, termNegative, extensionFilter, annotatedOnly]);

 // A MIME option can disappear when the rows behind it are removed, which would leave the filter
 // pinned to a value nothing can match — an empty table with no visible reason. Fall back to "all".
 useEffect(() => {
  if (mimeFilter !== "all" && !mimes.includes(mimeFilter)) setMimeFilter("all");
 }, [mimes, mimeFilter]);

 // Same failure shape as the MIME select, for the same reason: the tool filter's options are the
 // tools actually present, so removing the last intruder-sourced item must not leave the filter
 // pinned to "intruder" with nothing left to show.
 useEffect(() => {
  if (toolFilter !== "all" && !tools.includes(toolFilter)) setToolFilter("all");
 }, [tools, toolFilter]);

 // The extension select has the same failure shape — its options derive from the current rows —
 // so it gets the same fallback. Without it, deleting the last .rss row leaves the filter on
 // .rss forever, showing an empty list that no visible control explains.
 const extensions = useMemo(() => extensionOptions(items), [items]);
 useEffect(() => {
  if (extensionFilter !== "all" && !extensions.includes(extensionFilter)) setExtensionFilter("all");
 }, [extensions, extensionFilter]);

 const selected = useMemo(() => items.find((item) => item.id === selectedId) ?? null, [items, selectedId]);
 const dirty = draft !== null && JSON.stringify(draft) !== baseline;

 // The read-only request/response pane (burpsy-react-ui-i3l): resolved from the traffic store by
 // the same message-store ids History reads through useMessage, rather than a snapshot taken at
 // save time — see the design-choice note beside the detail card below. Both hooks no-op (disabled
 // query, no request) when the row is unresolved or the id is absent, which useMessage already
 // handles for a missing exchange id.
 const savedRequest = useMessage(selected?.request);
 const savedResponse = useMessage(selected?.response);

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

 /**
  * Write one field of a saved item without going through the detail pane's draft.
  *
  * The save endpoint takes the whole `OrganizerEdit`, so a menu that only means to change the
  * colour still has to send the title and the note. They are read off `item` — the row the pointer
  * is on — and never off `draft`, which belongs to whatever is selected. Sending the selected
  * row's note under another row's id would silently overwrite a note the operator wrote.
  */
 const patchItem = (item: OrganizerItem, change: Partial<Draft>, message: string) => {
  const payload: OrganizerEdit = {
   id: item.id,
   title: change.title ?? item.title,
   note: change.note ?? item.note,
   highlight: change.highlight ?? item.highlight,
  };
  mutations.save.mutate(payload, {
   onSuccess: () => {
    // Keep the open draft in step when the row being patched is the one on screen; otherwise the
    // pane would keep showing the old value and report itself "saved".
    if (selectedId === item.id) select({ ...item, ...payload });
    toast.success(message);
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not save that change"),
  });
 };

 /** Create a collection from the toolbar input; the server refuses a duplicate name with 400. */
 const createCollection = () => {
  const name = newCollectionName.trim();
  if (!name) return;
  mutations.createCollection.mutate(name, {
   onSuccess: (collection) => {
    setNewCollectionName("");
    toast.success(`Collection ${collection.name} created`);
   },
   onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not create the collection"),
  });
 };

 /**
  * Move (or copy) one item into a collection, or back to the inbox. The wire route is the same
  * one the multi-select uses; a copy arrives under a fresh id, so the table grows rather than
  * the original relocating.
  */
 const moveItems = (item: OrganizerItem, collection: number | typeof INBOX, copy = false) => {
  mutations.moveItems.mutate(
   { collection, itemIds: [item.id], copy },
   {
    onSuccess: () => toast.success(copy ? `Copied item ${item.id}` : `Moved item ${item.id}`),
    onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not move that item"),
   },
  );
 };

 /**
  * The saved-item context menu — Burp's Organiser row actions.
  *
  * Rename and Highlight are here because they are the two things an operator does to a shortlist
  * while triaging it, and both previously required selecting the row, editing the detail pane and
  * pressing Save. The note stays in the pane: it is multi-line prose, and a prompt is the wrong
  * surface for it.
  *
  * Status and the collection Move/Copy submenus are Burp's remaining row actions
  * (tools/organizer/annotate.html "Statuses", collections.html "Move to…"). A status change goes
  * through setStatus — one deliberate decision about the item itself — and never through the
  * title/note save, the same separation the Go store draws between SetStatus and Update.
  */
 const menuFor = (item: OrganizerItem): MenuGroup[] => [
  {
   id: "edit",
   actions: [
    {
     id: "rename",
     label: item.title ? "Rename" : "Add a title",
     icon: Pencil,
     onSelect: () => {
      void promptDialog({
       title: item.title ? `Rename saved item ${item.id}` : `Add a title to saved item ${item.id}`,
       description: `Exchange #${item.exchange}. An empty title clears it.`,
       label: "Title",
       initial: item.title,
       confirmLabel: "Save title",
       allowEmpty: true,
      }).then((next) => {
       if (next === null || next.trim() === item.title) return;
       patchItem(item, { title: next.trim() }, `Item ${item.id} renamed`);
      });
     },
    },
    {
     id: "status",
     label: "Status",
     icon: ListTodo,
     submenu: [
      {
       id: "statuses",
       actions: WORKFLOW_STATUSES.map((status) => ({
        id: status,
        label: WORKFLOW_STATUS_LABEL[status],
        disabled: (item.workflow_status ?? "new") === status,
        onSelect: () => {
         mutations.setStatus.mutate(
          { id: item.id, status },
          {
           onSuccess: () => toast.success(`Item ${item.id} marked ${WORKFLOW_STATUS_LABEL[status]}`),
           onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not set the status"),
          },
         );
        },
       })),
      },
     ],
     onSelect: () => { },
    },
    {
     id: "highlight",
     label: "Highlight",
     icon: Highlighter,
     submenu: [
      {
       id: "colours",
       actions: HIGHLIGHTS.map((name) => {
        // "none" is the picker's sentinel and "" is the wire's value for no highlight, the same
        // translation the detail pane's Select does.
        const wire = name === "none" ? "" : name;
        return {
         id: name,
         label: name === "none" ? "Clear highlight" : name.charAt(0).toUpperCase() + name.slice(1),
         icon: HIGHLIGHT_ICONS[name],
         disabled: (item.highlight || "") === wire,
         onSelect: () => patchItem(item, { highlight: wire }, wire === "" ? `Highlight cleared on ${item.id}` : `Item ${item.id} highlighted ${wire}`),
        };
       }),
      },
     ],
     onSelect: () => { },
    },
   ],
  },
  {
   id: "goto",
   actions: [
    {
     id: "open",
     label: `Show exchange #${item.exchange} in HTTP history`,
     icon: ExternalLink,
     onSelect: () => openInHistory(item.exchange),
    },
    {
     id: "copy-exchange",
     label: `Copy exchange id (#${item.exchange})`,
     icon: Copy,
     onSelect: () => void copyToClipboard(String(item.exchange)),
    },
    {
     id: "copy-note",
     label: "Copy note",
     icon: Copy,
     disabled: !item.note,
     onSelect: () => {
      void copyToClipboard(item.note);
      toast.success("Note copied");
     },
    },
   ],
  },
  {
   /**
    * Move to… / Copy to… — Burp's collections.html: "In Organizer, select one or more messages.
    * Right-click and select Move to…". The inbox is offered as a destination, which is Unlink.
    * Copy duplicates the item under a fresh id (the Copy Link analogue) rather than aliasing it.
    */
   id: "collect",
   actions: [
    {
     id: "move-to",
     label: "Move to…",
     icon: FolderInput,
     submenu: [
      {
       id: "destinations",
       actions: [
        { id: "inbox", label: "Inbox", disabled: (item.collection ?? 0) === 0, onSelect: () => moveItems(item, INBOX) },
        ...collections.map((collection) => ({
         id: `collection-${collection.id}`,
         label: collection.name,
         disabled: (item.collection ?? 0) === collection.id,
         onSelect: () => moveItems(item, collection.id),
        })),
       ],
      },
     ],
     onSelect: () => { },
    },
    {
     id: "copy-to",
     label: "Copy to…",
     icon: FolderPlus,
     submenu: [
      {
       id: "copy-destinations",
       actions: collections.map((collection) => ({
        id: `copy-${collection.id}`,
        label: collection.name,
        onSelect: () => moveItems(item, collection.id, true),
       })),
      },
     ],
     onSelect: () => { },
    },
   ],
  },
  {
   id: "remove",
   actions: [
    {
     id: "delete",
     label: `Remove item ${item.id}`,
     icon: Trash2,
     danger: true,
     // Routed through the same confirmation the row button uses: removing a saved item destroys
     // the note, which is the only thing here that is not recoverable from the traffic store.
     onSelect: () => setConfirmDelete(item.id),
    },
   ],
  },
 ];

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
      <Button
       variant="outline"
       size="small"
       onClick={() => {
        // Burp exports the selection, or the whole table when nothing is selected. The page
        // has no multi-select, so the whole filtered view is exported — the same "what you
        // see is what exports" rule History's button follows.
        if (visible.length === 0) {
         toast.error("No organizer items to export");
         return;
        }
        downloadText(
         "organizer.csv",
         organizerToCSV(
          visible.map((item) => ({
           id: item.id,
           title: item.title,
           note: item.note,
           highlight: item.highlight,
           workflow_status: item.workflow_status ?? "new",
           exchange: item.exchange,
          })),
         ),
         "text/csv",
        );
        toast.success(`Exported ${visible.length} organizer items to CSV`);
       }}
      >
       Export CSV
      </Button>
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
     {/* Burp's "Filter by tool" (tools/organizer/filter.html), burpsy-react-ui-ldfk. */}
     <Field label="Tool" className="field-inline">
      {(id) => (
       <Select id={id} value={toolFilter} onChange={(event) => setToolFilter(event.target.value)} disabled={tools.length === 0}>
        <option value="all">Any tool</option>
        {tools.map((tool) => (
         <option key={tool} value={tool}>
          {tool.charAt(0).toUpperCase() + tool.slice(1)}
         </option>
        ))}
       </Select>
      )}
     </Field>
     {/* Burp's "Filter by status" (filter.html) — the user-applied status, distinct from the
         Status-class filter above. An item with no status on the wire reads as "new". */}
     <Field label="Workflow" className="field-inline">
      {(id) => (
       <Select id={id} value={workflowFilter} onChange={(event) => setWorkflowFilter(event.target.value as WorkflowStatus | "all")}>
        <option value="all">Any workflow status</option>
        {WORKFLOW_STATUSES.map((status) => (
         <option key={status} value={status}>
          {WORKFLOW_STATUS_LABEL[status]}
         </option>
        ))}
       </Select>
      )}
     </Field>
     <Field label="Search term" hint={termRegex ? "Regular expression over title, note, host, path and method" : "Text over title, note, host, path and method"}>
      {(id) => <Input id={id} value={term} onChange={(event) => setTerm(event.target.value)} placeholder="search saved exchanges…" style={{ maxWidth: "var(--w-md)" }} />}
     </Field>
     <Checkbox label="Regex" checked={termRegex} onCheckedChange={setTermRegex} />
     <Checkbox label="Case sensitive" checked={termCase} onCheckedChange={setTermCase} />
     <Checkbox label="Negative" checked={termNegative} onCheckedChange={setTermNegative} />
     <Field label="Extension">
      {(id) => (
       <Select id={id} value={extensionFilter} onChange={(event) => setExtensionFilter(event.target.value)} style={{ maxWidth: "var(--w-xs)" }}>
        <option value="all">Any</option>
        {extensionOptions(items).map((ext) => (
         <option key={ext} value={ext}>
          .{ext}
         </option>
        ))}
       </Select>
      )}
     </Field>
     <Checkbox label="Annotated only" checked={annotatedOnly} onCheckedChange={setAnnotatedOnly} />
     <FilterPresetsMenu table="organizer" current={filterSnapshot} apply={applyFilterSettings} allowed={ORGANIZER_FILTER_ALLOWED} />
     {filtering ? (
      <>
       <Button
        variant="outline"
        size="small"
        onClick={() => applyFilterSettings(structuredClone(FILTER_DEFAULTS.organizer))}
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

    {/* --- Collections (dcr) ---------------------------------------------------------------
     * Burp's organizer collections: the inbox is where messages appear, collections are where
     * work goes (tools/organizer/collections.html). The panel manages the groups; membership is
     * the row menu's Move to…/Copy to…. Creating, renaming, duplicating and deleting a group are
     * server refusals when they are wrong (duplicate name, delete of an unknown id), so the UI
     * surfaces the server's message rather than pre-validating a second opinion.
     */}
    <Card>
     <SectionHeading
      title="Collections"
      detail="Groups of saved exchanges. New items land in the inbox; move them from a row's menu."
     />
     <Toolbar>
      <div className="inline-add">
       <Input
        aria-label="New collection name"
        title="New collection name"
        value={newCollectionName}
        placeholder="new collection name"
        onChange={(event) => setNewCollectionName(event.target.value)}
        onKeyDown={(event) => {
         if (event.key === "Enter") createCollection();
        }}
        style={{ maxWidth: "var(--w-sm)" }}
       />
       <Button
        variant="outline"
        size="small"
        onClick={createCollection}
        disabled={!newCollectionName.trim() || mutations.createCollection.isPending}
       >
        <FolderPlus size={13} />
        New collection
       </Button>
      </div>
      {/* The view switcher: the whole list, the inbox, or one group. Counted so an empty view
          reads as "this group is empty", not as "data is missing". */}
      <Field label="View" className="field-inline">
       {(id) => (
        <Select id={id} value={String(collectionView)} onChange={(event) => setCollectionView(event.target.value === "all" ? "all" : Number(event.target.value))}>
         <option value="all">All saved exchanges</option>
         <option value="0">{`Inbox (${items.filter((item) => (item.collection ?? 0) === 0).length})`}</option>
         {collections.map((collection) => (
          <option key={collection.id} value={String(collection.id)}>
           {`${collection.name} (${items.filter((item) => (item.collection ?? 0) === collection.id).length})`}
          </option>
         ))}
        </Select>
       )}
      </Field>
     </Toolbar>
     {collections.length > 0 ? (
      <SimpleTable headers={["Collection", "Items", "Note", ""]}>
       {collections.map((collection) => (
        <tr key={collection.id} className={collectionView === collection.id ? "data-row selected-row" : "data-row"}>
         <td>
          <button type="button" className="text-button" onClick={() => setCollectionView(collectionView === collection.id ? "all" : collection.id)}>
           {collection.name}
          </button>
         </td>
         <td>
          <span className="cell-num">{items.filter((item) => (item.collection ?? 0) === collection.id).length}</span>
         </td>
         <td>
          <span className="cell-dim">{collection.note || "no note"}</span>
         </td>
         <td>
          <div className="chip-row">
           <IconButton
            label={`Rename ${collection.name}`}
            size="small"
            onClick={async () => {
             const next = await promptDialog({
              title: `Rename collection ${collection.name}`,
              label: "Collection name",
              initial: collection.name,
              confirmLabel: "Rename",
             });
             if (next === null || next.trim() === collection.name) return;
             mutations.updateCollection.mutate(
              { id: collection.id, name: next.trim() },
              {
               onSuccess: () => toast.success(`Collection renamed to ${next.trim()}`),
               onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Rename failed"),
              },
             );
            }}
           >
            <Pencil size={13} />
           </IconButton>
           <IconButton
            label={`Edit note on ${collection.name}`}
            size="small"
            onClick={async () => {
             const next = await promptDialog({
              title: `Note for collection ${collection.name}`,
              description: "Shown on the collection's About tab. An empty note clears it.",
              label: "Note",
              initial: collection.note,
              confirmLabel: "Save note",
              multiline: true,
              allowEmpty: true,
             });
             if (next === null) return;
             mutations.updateCollection.mutate(
              { id: collection.id, note: next },
              {
               onSuccess: () => toast.success("Collection note saved"),
               onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Could not save the note"),
              },
             );
            }}
           >
            <ListTodo size={13} />
           </IconButton>
           <IconButton
            label={`Duplicate ${collection.name}`}
            size="small"
            onClick={() =>
             mutations.duplicateCollection.mutate(collection.id, {
              onSuccess: (out) => toast.success(`Duplicated into ${out.collection.name} with ${out.items_copied} item(s)`),
              onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Duplicate failed"),
             })
            }
           >
            <Copy size={13} />
           </IconButton>
           <IconButton
            label={`Delete ${collection.name}`}
            size="small"
            onClick={() => setConfirmDeleteCollection(collection)}
           >
            <Trash2 size={13} />
           </IconButton>
          </div>
         </td>
        </tr>
       ))}
      </SimpleTable>
     ) : (
      <Empty
       title="No collections yet"
       detail="Create one above, then move saved exchanges into it from a row's Move to… menu."
      />
     )}
    </Card>

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
     <SimpleTable headers={["#", "Exchange", "Tool", "Request", "Status", "Workflow", "Type", "Title", "Highlight", "Note", ""]}>
      {visible.map((item) => (
       <MenuRow
        key={item.id}
        groups={menuFor(item)}
        className={item.id === selectedId ? "data-row clickable selected-row" : "data-row clickable"}
        onClick={() => select(item)}
        // Right-clicking a row should act on that row, matching VirtualTable and every desktop tool.
        onContextMenu={() => select(item)}
       >
        <td>
         <span className="cell-num">{item.id}</span>
        </td>
        <td>
         <span className="cell-num">#{item.exchange}</span>
        </td>
        {/* Burp's Organizer "Tool" column (burpsy-react-ui-ldfk): "The Burp tool that originally
            generated the request. This always reflects the request's origin, even if the message
            is later sent from Burp Logger or from within Organizer." A standalone cell rather than
            folded into the three-column resolved/unresolved block below: it comes from
            core.Exchange.Source the same way workflow_status comes from the item itself, not from
            re-deriving anything the block below already handles. */}
        <td>
         {item.tool ? (
          <Badge tone="neutral">{item.tool.charAt(0).toUpperCase() + item.tool.slice(1)}</Badge>
         ) : (
          <span className="cell-dim">—</span>
         )}
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
         <td colSpan={4}>
          <Badge tone="warn" title="The exchange is no longer in the traffic store; the note survives it">
           exchange no longer retained
          </Badge>
         </td>
        )}
        {/* The operator's decision, not the server's — the Status column above is the HTTP code.
            Both are shown because both are answered per row, and merging them is exactly the
            collision the wire avoids by naming this field workflow_status. */}
        <td>
         {(() => {
          const status = item.workflow_status ?? "new";
          return <Badge tone={WORKFLOW_STATUS_TONE[status]}>{WORKFLOW_STATUS_LABEL[status]}</Badge>;
         })()}
        </td>
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
       </MenuRow>
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

      {/*
       * Read-only request/response (burpsy-react-ui-i3l): Burp's own docs describe this as the
       * point of Organizer — "Messages appear in the Organizer inbox as read-only copies of the
       * original request and response" — and burpsy had nothing here at all; the only way to read
       * a saved item's bytes was to leave the page for HTTP history and come back.
       *
       * # The design choice this makes, and what it costs
       *
       * Burp copies the bytes into the item at save time, so a saved message outlives the tab it
       * came from. This resolves them on demand from the traffic store instead, through the same
       * message-store ids and useMessage hook History already uses — the smaller change, given
       * organizer.Item only ever stored `Exchange int`, and it inherits the eviction handling this
       * page already had rather than adding a second one. The cost is real: once the exchange is
       * evicted these bytes are gone with it, same as every other resolved field on this row. If
       * Organizer is meant to survive that the way Burp's does, the fix is a byte snapshot taken at
       * save time — a bigger change, deliberately not made here.
       */}
      {!selected.resolved ? (
       <div className="notice notice-warn">
        This exchange is no longer in the traffic store, so its request and response cannot be
        shown — only the note below survives it.
       </div>
      ) : (
       <Tabs defaultValue="request" className="editor-combined">
        <TabsList>
         <TabsTrigger value="request">Request</TabsTrigger>
         <TabsTrigger value="response">Response</TabsTrigger>
        </TabsList>
        <TabsContent value="request" className="tabs-fill">
         <HttpEditor
          label="Request"
          readOnly
          value={savedRequest.data?.text ?? (savedRequest.isFetching ? "Loading request bytes…" : "No request bytes captured.")}
          bodyBase64={savedRequest.data?.body_base64}
          filename={`organizer-${selected.id}-request.txt`}
         />
        </TabsContent>
        <TabsContent value="response" className="tabs-fill">
         <HttpEditor
          label="Response"
          readOnly
          value={
           !selected.has_response
            ? "No response was captured for this exchange."
            : (savedResponse.data?.text ?? (savedResponse.isFetching ? "Loading response bytes…" : "No response bytes captured."))
          }
          bodyBase64={savedResponse.data?.body_base64}
          requestPath={selected.path}
          filename={`organizer-${selected.id}-response.txt`}
         />
        </TabsContent>
       </Tabs>
      )}

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

   {/* The collection delete dialog, with the acceptance criteria's two options spelled out:
       unlink (the default, losing nothing) or delete the items with the group. Refusing to
       hide this choice is the point — a silent "delete" of a group would take saved notes
       with it, and a note is the only thing here that is not recoverable. */}
   <Modal
    open={confirmDeleteCollection !== null}
    onOpenChange={(open) => {
     if (!open) setConfirmDeleteCollection(null);
    }}
    title={confirmDeleteCollection ? `Delete collection ${confirmDeleteCollection.name}?` : "Delete collection?"}
    description="Its items can be moved back to the inbox, or deleted with the collection."
   >
    <div className="page-actions">
     <Button variant="outline" onClick={() => setConfirmDeleteCollection(null)}>
      Cancel
     </Button>
     <Button
      variant="outline"
      disabled={mutations.deleteCollection.isPending}
      onClick={() => {
       if (!confirmDeleteCollection) return;
       mutations.deleteCollection.mutate(
        { id: confirmDeleteCollection.id },
        {
         onSuccess: (out) => {
          if (collectionView === confirmDeleteCollection.id) setCollectionView("all");
          setConfirmDeleteCollection(null);
          toast.success(`Collection deleted${out.unlinked ? `, ${out.unlinked} item(s) back in the inbox` : ""}`);
         },
         onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Delete failed"),
        },
       );
      }}
     >
      <FolderInput size={13} />
      Delete, keep items (inbox)
     </Button>
     <Button
      variant="danger"
      disabled={mutations.deleteCollection.isPending}
      onClick={() => {
       if (!confirmDeleteCollection) return;
       mutations.deleteCollection.mutate(
        { id: confirmDeleteCollection.id, items: "delete" },
        {
         onSuccess: () => {
          if (collectionView === confirmDeleteCollection.id) setCollectionView("all");
          setConfirmDeleteCollection(null);
          toast.success("Collection and its items deleted");
         },
         onError: (failure: unknown) => toast.error(failure instanceof Error ? failure.message : "Delete failed"),
        },
       );
      }}
     >
      <Trash2 size={13} />
      Delete with items
     </Button>
    </div>
   </Modal>
  </div>
 );
}
