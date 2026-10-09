// The Organizer table's column layout, kept in one place so the header and the row cells cannot
// drift apart again (burpsy-react-ui-tni8): the row once rendered Type before Workflow under a
// header that read Workflow then Type, and an unresolved row's colSpan={4} plus its Workflow cell
// made five columns where the header has four — every later cell sat one column to the right.

/** Every column the Organizer table shows, in header order. */
export const ORGANIZER_COLUMNS = [
 { key: "id", header: "#" },
 { key: "exchange", header: "Exchange" },
 { key: "tool", header: "Tool" },
 { key: "request", header: "Request" },
 { key: "status", header: "Status" },
 { key: "workflow", header: "Workflow" },
 { key: "type", header: "Type" },
 { key: "title", header: "Title" },
 { key: "highlight", header: "Highlight" },
 { key: "note", header: "Note" },
 { key: "actions", header: "" },
] as const;

export type OrganizerColumnKey = (typeof ORGANIZER_COLUMNS)[number]["key"];

/** A rendered cell: one column, or the "exchange no longer retained" notice spanning several. */
export type OrganizerCell = { key: OrganizerColumnKey; span: 1 } | { key: "unresolved"; span: number };

export const ORGANIZER_HEADERS: string[] = ORGANIZER_COLUMNS.map((column) => column.header);

// The columns whose values come from the stored exchange (request line and HTTP status). When the
// exchange has aged out of the traffic store these are unknown, and the row says so once across
// them. Workflow and Type are deliberately NOT spanned: the workflow badge is the operator's own
// decision, stored on the organizer item, and survives the exchange; Type gets its own cell so it
// stays under its header.
const SPANNED_WHEN_UNRESOLVED: ReadonlySet<OrganizerColumnKey> = new Set<OrganizerColumnKey>(["request", "status"]);

/** The cells one row renders, in order. Their spans always sum to ORGANIZER_COLUMNS.length. */
export function organizerRowCells(resolved: boolean): OrganizerCell[] {
 const cells: OrganizerCell[] = [];
 let spanned = 0;
 for (const column of ORGANIZER_COLUMNS) {
  if (!resolved && SPANNED_WHEN_UNRESOLVED.has(column.key)) {
   if (spanned === 0) cells.push({ key: "unresolved", span: SPANNED_WHEN_UNRESOLVED.size });
   spanned++;
   continue;
  }
  cells.push({ key: column.key, span: 1 });
 }
 return cells;
}
