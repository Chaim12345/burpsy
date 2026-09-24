import { describe, expect, test } from "bun:test";
import { appendGroupResultsToHistory, followNewestAfterGroupSend } from "./repeater-group";
import type { RepeaterGroupItemResult, RepeaterGroupSendResult, RepeaterHistoryEntry, RepeaterWsHistoryEntry } from "./types";

/** One group-send item result, with the boring fields filled in. */
function item(tabID: string, over: Partial<RepeaterGroupItemResult> = {}): RepeaterGroupItemResult {
  return {
    tab_id: tabID,
    result: { status: 200, duration_ms: 12, response: `HTTP/1.1 200 OK\r\n\r\n${tabID}`, exchange_id: 1 },
    duration_measured: true,
    ...over,
  };
}

function outcome(items: RepeaterGroupItemResult[], over: Partial<RepeaterGroupSendResult> = {}): RepeaterGroupSendResult {
  return {
    mode: "sequence_single_conn",
    items,
    batch_duration_ms: 40,
    followed_redirects: false,
    ...over,
  };
}

/**
 * Narrow a history entry to the HTTP one. A tab's history is a union since the WebSocket tab type
 * landed (burpsy-react-ui-6ex): an HTTP entry carries a response, a WS entry carries a frame result,
 * and the assertions in this file are about the HTTP fold, so they ask for the HTTP shape by name
 * rather than casting. `asHttp(undefined)` is null, which is what an entry-less tab should read as.
 */
const asHttp = (entry: RepeaterHistoryEntry | RepeaterWsHistoryEntry | undefined): RepeaterHistoryEntry | null =>
  entry && "status" in entry ? entry : null;

describe("appendGroupResultsToHistory", () => {
  test("each tab's result lands in that tab's own history, not the active one's", () => {
    const sent = new Map([
      ["tab-a", "GET /a HTTP/1.1\r\n\r\n"],
      ["tab-b", "GET /b HTTP/1.1\r\n\r\n"],
    ]);
    const next = appendGroupResultsToHistory({}, outcome([item("tab-a"), item("tab-b")]), sent);
    expect(Object.keys(next).sort()).toEqual(["tab-a", "tab-b"]);
    expect(next["tab-a"]).toHaveLength(1);
    expect(next["tab-b"]).toHaveLength(1);
    // The pair is the point: each entry carries the draft that produced it, not its neighbour's.
    expect(next["tab-a"]?.[0]?.request).toBe("GET /a HTTP/1.1\r\n\r\n");
    expect(next["tab-b"]?.[0]?.request).toBe("GET /b HTTP/1.1\r\n\r\n");
    // Through the HTTP narrowing helper, because a tab's history is now a union (burpsy-react-ui-6ex
    // added the WebSocket entry) and these assertions are about the HTTP fold specifically.
    expect(asHttp(next["tab-a"]?.[0])?.response).toContain("tab-a");
    expect(asHttp(next["tab-b"]?.[0])?.response).toContain("tab-b");
  });

  test("appends to a tab's existing history rather than replacing it", () => {
    const existing: Record<string, RepeaterHistoryEntry[]> = {
      "tab-a": [{ status: 404, duration_ms: 3, response: "old", exchange_id: 0, request: "GET /old HTTP/1.1\r\n\r\n" }],
    };
    const next = appendGroupResultsToHistory(existing, outcome([item("tab-a")]), new Map([["tab-a", "GET /new HTTP/1.1\r\n\r\n"]]));
    expect(next["tab-a"]).toHaveLength(2);
    expect(asHttp(next["tab-a"]?.[0])?.response).toBe("old");
    expect(next["tab-a"]?.[1]?.request).toBe("GET /new HTTP/1.1\r\n\r\n");
    // The input is not mutated: the page hands this straight to a setState updater.
    expect(existing["tab-a"]).toHaveLength(1);
  });

  test("an item with no response appends nothing at all", () => {
    const next = appendGroupResultsToHistory(
      {},
      outcome([item("tab-a"), item("tab-b", { result: undefined, error: "connection closed before answering" })]),
      new Map([
        ["tab-a", "GET /a HTTP/1.1\r\n\r\n"],
        ["tab-b", "GET /b HTTP/1.1\r\n\r\n"],
      ]),
    );
    expect(Object.keys(next)).toEqual(["tab-a"]);
    expect(next["tab-b"]).toBeUndefined();
  });

  test("a partial response is kept, with its incomplete read recorded rather than smoothed over", () => {
    const next = appendGroupResultsToHistory(
      {},
      outcome([
        item("tab-a", {
          result: { status: 200, duration_ms: 0, response: "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort", exchange_id: 7 },
          error: "body read failed before the deadline",
          framing: "content-length",
          response_complete: false,
          duration_measured: false,
        }),
      ]),
      new Map([["tab-a", "POST / HTTP/1.1\r\n\r\n"]]),
    );
    // Narrowed, because this entry is the HTTP one and the tab's history is a union.
    const entry = asHttp(next["tab-a"]?.[0]);
    expect(entry?.response).toContain("short");
    expect(entry?.framing).toBe("content-length");
    expect(entry?.response_complete).toBe(false);
    // The shared socket reports no per-request timing, so the entry must not claim its 0 is measured.
    expect(entry?.duration_measured).toBe(false);
    expect(entry?.group_mode).toBe("sequence_single_conn");
  });

  test("the separate-connection modes carry a measured duration and no framing claim", () => {
    const next = appendGroupResultsToHistory(
      {},
      outcome([item("tab-a")], { mode: "parallel", followed_redirects: true }),
      new Map([["tab-a", "GET /a HTTP/1.1\r\n\r\n"]]),
    );
    const entry = asHttp(next["tab-a"]?.[0]);
    expect(entry?.group_mode).toBe("parallel");
    expect(entry?.duration_measured).toBe(true);
    expect(entry?.framing).toBeUndefined();
    expect(entry?.response_complete).toBeUndefined();
  });

  test("a result for a tab nobody captured a draft for is skipped, not paired with a guess", () => {
    const next = appendGroupResultsToHistory({}, outcome([item("tab-gone")]), new Map());
    expect(next).toEqual({});
  });
});

describe("followNewestAfterGroupSend", () => {
  test("tabs that got an answer follow the newest entry again", () => {
    const next = followNewestAfterGroupSend({ "tab-a": 0, "tab-b": 2 }, outcome([item("tab-a"), item("tab-b")]));
    expect(next["tab-a"]).toBeNull();
    expect(next["tab-b"]).toBeNull();
  });

  test("a tab whose request failed keeps the entry the operator was looking at", () => {
    const next = followNewestAfterGroupSend(
      { "tab-a": 0, "tab-b": 2 },
      outcome([item("tab-a"), item("tab-b", { result: undefined, error: "not sent" })]),
    );
    expect(next["tab-a"]).toBeNull();
    expect(next["tab-b"]).toBe(2);
  });

  test("tabs outside the group are untouched", () => {
    const next = followNewestAfterGroupSend({ "tab-z": 4 }, outcome([item("tab-a")]));
    expect(next["tab-z"]).toBe(4);
  });
});
