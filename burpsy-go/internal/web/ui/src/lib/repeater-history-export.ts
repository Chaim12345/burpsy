// The request body for Repeater's "Save entire history" (burpsy-react-ui-pznm).
//
// Ids, never text: a tab's history lives in the page's state, and each HTTP entry carries the
// message ids its send stored. The server exports the stored bytes by id, so a binary body
// round-trips exactly — the `response` string here already lost any non-UTF-8 byte. Every entry is
// sent, a WebSocket one included, so the server can count what it could not export instead of the
// browser silently leaving it out.
import type { RepeaterHistoryEntry, RepeaterWsHistoryEntry } from "./types";

export interface HistoryExportEntryBody {
 kind: "http" | "ws";
 request_msg_id?: number;
 response_msg_id?: number;
 exchange_id?: number;
}

export function historyExportBody(
 tab: { name: string; target: string; note?: string },
 entries: (RepeaterHistoryEntry | RepeaterWsHistoryEntry)[],
): { tab: string; target: string; note?: string; entries: HistoryExportEntryBody[] } {
 return {
  tab: tab.name,
  target: tab.target,
  ...(tab.note && tab.note.trim() !== "" ? { note: tab.note } : {}),
  entries: entries.map((entry): HistoryExportEntryBody => {
   if ("ws" in entry) return { kind: "ws" };
   return {
    kind: "http",
    ...(entry.request_msg_id != null ? { request_msg_id: entry.request_msg_id } : {}),
    ...(entry.response_msg_id != null ? { response_msg_id: entry.response_msg_id } : {}),
    ...(entry.exchange_id != null ? { exchange_id: entry.exchange_id } : {}),
   };
  }),
 };
}
