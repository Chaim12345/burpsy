// Repeater's WebSocket connection modes (burpsy-react-ui-wuwf): attach, clone, new.
import { describe, expect, test } from "bun:test";
import {
 defaultWsMode,
 effectiveWsMode,
 planWsSend,
 toClientRuns,
 wsModeOptions,
 wsTabSeedFromFrame,
 wsTargetOf,
} from "./repeater-ws-connection";

describe("the mode a tab opened from a frame starts in", () => {
 test("attach while the proxy holds the connection, clone once it has closed, new with no connection", () => {
  expect(defaultWsMode(7, true)).toBe("attach");
  expect(defaultWsMode(7, false)).toBe("clone");
  expect(defaultWsMode(undefined, true)).toBe("new");
 });
 test("WebSocket ID 0 is a real connection, not an absent one", () => {
  expect(defaultWsMode(0, true)).toBe("attach");
  expect(effectiveWsMode({ target: "", wsSocket: 0, wsMode: "clone" })).toBe("clone");
 });
 test("a tab persisted before modes existed sends on a new connection", () => {
  expect(effectiveWsMode({ target: "ws://a:80" })).toBe("new");
  expect(effectiveWsMode({ target: "ws://a:80", wsMode: "attach" })).toBe("new");
 });
});

describe("the connection chooser", () => {
 test("lists every mode and says why one cannot run instead of hiding it", () => {
  const closed = wsModeOptions(3, false);
  expect(closed.map((o) => o.value)).toEqual(["new", "clone", "attach"]);
  expect(closed.find((o) => o.value === "attach")?.disabledReason).toContain("no longer open");
  expect(closed.find((o) => o.value === "clone")?.disabledReason).toBeUndefined();
  const live = wsModeOptions(3, true);
  expect(live.find((o) => o.value === "attach")?.disabledReason).toBeUndefined();
  const handMade = wsModeOptions(undefined, false);
  expect(handMade.filter((o) => o.disabledReason).map((o) => o.value)).toEqual(["clone", "attach"]);
 });
});

describe("what Send posts", () => {
 const base = { target: "wss://chat.test:443", wsPayload: "hi", wsOpcode: "text", wsSocket: 12, wsPath: "/chat" };
 test("attach writes into the live connection by its WebSocket ID, with the direction", () => {
  expect(planWsSend({ ...base, wsMode: "attach", wsDirection: "client" })).toEqual({
   route: "/api/repeater/ws-attach",
   body: { socket: 12, opcode: "text", payload: "hi", to_client: true },
  });
 });
 test("clone replays the captured handshake and names no target", () => {
  const plan = planWsSend({ ...base, wsMode: "clone" });
  expect(plan.route).toBe("/api/repeater/ws-send");
  expect(plan.body).toEqual({ clone: true, socket: 12, opcode: "text", payload: "hi" });
 });
 test("new dials the tab's Target at the connection's path, and never claims a message id", () => {
  const plan = planWsSend({ ...base, wsMode: "new" });
  expect(plan.body).toEqual({ target: "wss://chat.test:443", path: "/chat", opcode: "text", payload: "hi" });
  expect("message" in plan.body).toBe(false);
 });
 test("to-client is a real direction only when attached", () => {
  expect(toClientRuns("attach")).toBe(true);
  expect(toClientRuns("clone")).toBe(false);
  expect(toClientRuns("new")).toBe(false);
 });
});

test("a connection's target uses the ws spelling and brackets an IPv6 literal", () => {
 expect(wsTargetOf({ host: "chat.test", port: 443, tls: true })).toBe("wss://chat.test:443");
 expect(wsTargetOf({ host: "::1", port: 8080 })).toBe("ws://[::1]:8080");
});

describe("Send to Repeater from a WebSockets-history frame", () => {
 const row = { id: 41, exchange: 9, opcode: "text", url: "https://chat.test/socket?x=1", tls: true };
 test("opens a ws tab on the frame's connection, attached while it is live", () => {
  const seed = wsTabSeedFromFrame(row, { exchange: 9, host: "chat.test", port: 443, tls: true, path: "/socket", live: true }, "hello");
  expect(seed).toMatchObject({
   kind: "ws",
   wsPayload: "hello",
   wsOpcode: "text",
   wsSocket: 9,
   wsPath: "/socket",
   wsMode: "attach",
   target: "wss://chat.test:443",
  });
 });
 test("a closed connection opens cloned, and a missing connection row falls back to the frame's URL", () => {
  const seed = wsTabSeedFromFrame(row, null, null);
  expect(seed.wsMode).toBe("clone");
  expect(seed.target).toBe("wss://chat.test:443");
  expect(seed.wsPath).toBe("/socket?x=1");
  expect(seed.wsPayload).toBe("");
 });
});
