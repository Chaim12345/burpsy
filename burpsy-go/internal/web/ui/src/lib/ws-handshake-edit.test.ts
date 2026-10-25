import { describe, expect, test, beforeEach } from "bun:test";
import { useApp } from "./store";
import { planWsSend } from "./repeater-ws-connection";

// burpsy-react-ui-ws3e review: the edited negotiation request belongs to one authority - the
// captured connection or explicit target it was previewed against. Re-aiming the tab (mode,
// socket, target or path) must drop the stored edit, or a retargeted send dials yesterday's
// bytes. And a cleared editor ("") must stay distinct from no edit (undefined): the server
// refuses present-but-empty with its reason, while absent sends the captured or synthetic head.

function reset() {
 useApp.setState({ repeaterTabs: [], closedRepeaterTabs: [], activeRepeaterTab: null });
}

function openWsTab(): string {
 return useApp.getState().openRepeaterTab({
  name: "ws",
  kind: "ws",
  target: "ws://example.test",
  request: "",
  wsMode: "clone",
  wsSocket: 7,
 });
}

function tab(id: string) {
 const t = useApp.getState().repeaterTabs.find((t) => t.id === id);
 if (!t) throw new Error("tab gone");
 return t;
}

describe("a stored handshake edit does not survive a retarget", () => {
 beforeEach(reset);

 test("changing the target clears the edit", () => {
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /x HTTP/1.1\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, { target: "ws://other.test" });
  expect(tab(id).wsHandshake).toBeUndefined();
 });

 test("switching mode or socket clears the edit", () => {
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /x HTTP/1.1\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, { wsMode: "new", wsSocket: undefined });
  expect(tab(id).wsHandshake).toBeUndefined();
 });

 test("clearing the socket alone clears the edit", () => {
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /x HTTP/1.1\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, { wsSocket: undefined });
  expect(tab(id).wsHandshake).toBeUndefined();
 });

 test("changing the path clears the edit", () => {
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /x HTTP/1.1\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, { wsPath: "/elsewhere" });
  expect(tab(id).wsHandshake).toBeUndefined();
 });

 test("an edit keystroke is not mistaken for a retarget", () => {
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /a HTTP/1.1\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /ab HTTP/1.1\r\n\r\n" });
  expect(tab(id).wsHandshake).toBe("GET /ab HTTP/1.1\r\n\r\n");
 });

 test("a patch restating the current aim keeps a legitimate edit", () => {
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /x HTTP/1.1\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, { target: "ws://example.test", wsMode: "clone", wsSocket: 7 });
  expect(tab(id).wsHandshake).toBe("GET /x HTTP/1.1\r\n\r\n");
 });

 test("an atomic target+fresh-edit patch keeps the new edit for the new target", () => {
  // Atomic-pair semantics: the operator supplying a NEW handshake in the same patch as the new
  // target means it for that target. What the rule forbids is the STALE edit riding the retarget
  // - so the seed below (an edit written against the old target) is the load-bearing part: the
  // atomic patch must replace it, not preserve it and not clear to the synthetic head.
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "GET /stale HTTP/1.1\r\n\r\n" });
  useApp.getState().updateRepeaterTab(id, {
   target: "ws://other.test",
   wsHandshake: "GET /fresh HTTP/1.1\r\n\r\n",
  });
  expect(tab(id).wsHandshake).toBe("GET /fresh HTTP/1.1\r\n\r\n");
 });
});

describe("an emptied editor stays distinct from no edit", () => {
 beforeEach(reset);

 test("planWsSend posts handshake:\"\" so the server can refuse it by name", () => {
  const id = openWsTab();
  useApp.getState().updateRepeaterTab(id, { wsHandshake: "" });
  const plan = planWsSend(tab(id));
  expect(plan.route).toBe("/api/repeater/ws-send");
  expect((plan.body as { handshake?: string }).handshake).toBe("");
 });

 test("no edit sends no handshake field at all", () => {
  const id = openWsTab();
  const plan = planWsSend(tab(id));
  expect("handshake" in (plan.body as object)).toBe(false);
 });
});
