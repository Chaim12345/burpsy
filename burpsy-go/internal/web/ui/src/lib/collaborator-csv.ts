/**
 * Collaborator interactions as CSV (burpsy-react-ui-aw2y): Burp's "Export as CSV". Burp formats date
 * times as yyyy-MMM-dd HH:mm:ss.SSS and represents DNS queries and HTTP interactions, requests and
 * responses, as Base64 strings (desktop/tools/collaborator/index.html). Comments are this console's
 * own annotations, which live in the workspace store rather than on the server, so the CSV is built
 * here where both are in hand.
 *
 * Every cell goes through csvCell, including the Base64 ones. A Base64 string can begin with "+",
 * which Excel would run as a formula, so the guard's leading apostrophe can appear there too and
 * must be stripped before decoding. A security tool's export does not get to be the injection vector.
 */
import { csvCell } from "./api";
import type { CollaboratorInteractionRow } from "./data.collab";

export interface CollaboratorExportRow extends CollaboratorInteractionRow {
  raw_request_b64?: string;
  raw_response_b64?: string;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** Burp's yyyy-MMM-dd HH:mm:ss.SSS, in local time as Java's SimpleDateFormat renders it. */
export function burpDateTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${d.getFullYear()}-${MONTHS[d.getMonth()]}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export const COLLABORATOR_CSV_HEADERS = [
  "#",
  "Time",
  "Type",
  "Payload",
  "Source IP address",
  "Query type",
  "Interaction ID",
  "Comment",
  "Request (Base64)",
  "Response (Base64)",
];

export function collaboratorToCSV(rows: CollaboratorExportRow[], comments: Record<number, string | undefined>): string {
  const lines = [COLLABORATOR_CSV_HEADERS.map(csvCell).join(",")];
  for (const row of rows) {
    lines.push(
      [
        row.id,
        burpDateTime(row.at_ms),
        row.type.toUpperCase(),
        row.payload ?? "",
        row.client_ip,
        row.q_type ?? "",
        row.interaction_id,
        comments[row.id] ?? "",
        row.raw_request_b64 ?? "",
        row.raw_response_b64 ?? "",
      ]
        .map(csvCell)
        .join(","),
    );
  }
  return lines.join("\r\n") + "\r\n";
}
