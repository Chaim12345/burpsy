import { describe, expect, test } from "bun:test";
import { historyExportBody } from "./repeater-history-export";
import type { RepeaterHistoryEntry, RepeaterWsHistoryEntry } from "./types";

describe("Save entire history's request body (burpsy-react-ui-pznm)", () => {
 const http = (over: Partial<RepeaterHistoryEntry>): RepeaterHistoryEntry => ({
  status: 200,
  duration_ms: 1,
  response: "HTTP/1.1 200 OK\r\n\r\n",
  exchange_id: 4,
  request: "GET / HTTP/1.1\r\n\r\n",
  ...over,
 });
 const ws = { request: "hi", ws: { handshake: "101", messages: [], elapsed_ms: 1 } } as unknown as RepeaterWsHistoryEntry;

 test("HTTP entries go by id, never by text; message 0 is a real id", () => {
  const body = historyExportBody({ name: "t", target: "https://h:443" }, [http({ request_msg_id: 0, response_msg_id: 1 })]);
  expect(body.entries).toEqual([{ kind: "http", request_msg_id: 0, response_msg_id: 1, exchange_id: 4 }]);
  expect(JSON.stringify(body)).not.toContain("HTTP/1.1 200 OK");
 });

 test("a WebSocket entry is sent as ws so the server counts it, not dropped here", () => {
  const body = historyExportBody({ name: "t", target: "ws://h" }, [ws, http({ request_msg_id: 2, response_msg_id: 3 })]);
  expect(body.entries.map((entry) => entry.kind)).toEqual(["ws", "http"]);
 });

 test("an entry with no stored ids still goes, so its gap is reported", () => {
  const body = historyExportBody({ name: "t", target: "h" }, [http({})]);
  expect(body.entries).toEqual([{ kind: "http", exchange_id: 4 }]);
 });

 test("the tab note rides along; a blank one does not", () => {
  expect(historyExportBody({ name: "t", target: "h", note: "n" }, []).note).toBe("n");
  expect("note" in historyExportBody({ name: "t", target: "h", note: "  " }, [])).toBe(false);
 });
});
