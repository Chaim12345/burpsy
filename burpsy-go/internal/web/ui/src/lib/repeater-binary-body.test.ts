import { describe, expect, test, beforeEach } from "bun:test";
import { useApp } from "./store";

// burpsy-react-ui-ytkk: a Repeater tab holds a binary request body faithfully as requestBodyBase64,
// which the send prefers over the lossy `request` text. That makes the base64 a shadow of the body —
// so every path that edits the body text must invalidate it, or the send resends stale bytes and the
// operator's edit is silently dropped. The rule lives in the store's updateRepeaterTab (the one
// chokepoint every request edit funnels through); these drive the committed store so a version with
// the rule deleted, or the body/header test inverted, fails here — which a helper-only test cannot see.

const HEAD = "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\n\r\n";
const B = btoa("BODY"); // the faithful body the tab was opened with
const N = btoa("NEW!"); // a freshly re-encoded body

function reset() {
 useApp.setState({ repeaterTabs: [], closedRepeaterTabs: [], activeRepeaterTab: null });
}

function openBinaryTab(): string {
 return useApp.getState().openRepeaterTab({
  name: "proto",
  target: "example.test",
  request: `${HEAD}BODY`,
  requestBodyBase64: B,
 });
}

function bodyBase64Of(id: string): string | undefined {
 return useApp.getState().repeaterTabs.find((t) => t.id === id)?.requestBodyBase64;
}

describe("a stale faithful binary body is dropped when the body text is edited", () => {
 beforeEach(reset);

 test("the tab opens holding the faithful body", () => {
  const id = openBinaryTab();
  expect(bodyBase64Of(id)).toBe(B);
 });

 test("a body edit through the request text clears it, so the send cannot resend stale bytes", () => {
  const id = openBinaryTab();
  useApp.getState().updateRepeaterTab(id, { request: `${HEAD}NEW!` });
  expect(bodyBase64Of(id)).toBeUndefined();
 });

 test("a header-only edit keeps it, so editing headers around a binary body still resends exactly", () => {
  const id = openBinaryTab();
  // The header line grows (the offset shifts) but the body slice is unchanged.
  useApp.getState().updateRepeaterTab(id, { request: `POST /x HTTP/1.1\r\nHost: target.example\r\nContent-Length: 4\r\n\r\nBODY` });
  expect(bodyBase64Of(id)).toBe(B);
 });

 test("the Protobuf Apply sequence — request then base64 — leaves the new body", () => {
  const id = openBinaryTab();
  // onChange rewrites the body (clears), then onBodyBytesChange restores the just-encoded bytes.
  useApp.getState().updateRepeaterTab(id, { request: `${HEAD}NEW!` });
  useApp.getState().updateRepeaterTab(id, { requestBodyBase64: N });
  expect(bodyBase64Of(id)).toBe(N);
 });

 test("the reversed order would lose the body — pinning why editor.tsx sets request first", () => {
  const id = openBinaryTab();
  useApp.getState().updateRepeaterTab(id, { requestBodyBase64: N });
  useApp.getState().updateRepeaterTab(id, { request: `${HEAD}NEW!` });
  expect(bodyBase64Of(id)).toBeUndefined();
 });

 test("setting the base64 together with the request in one patch is honoured, not cleared", () => {
  const id = openBinaryTab();
  useApp.getState().updateRepeaterTab(id, { request: `${HEAD}NEW!`, requestBodyBase64: N });
  expect(bodyBase64Of(id)).toBe(N);
 });
});
