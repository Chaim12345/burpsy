// The Repeater tab note (burpsy-react-ui-jva5): Burp's per-tab Notes panel. The store half is pinned
// here (persistence is in pages/repeater.notes.test.tsx) — the note is opened with a tab, survives duplicate and reopen, is persisted, and a text edit
// to the request never touches it. The wire half (the note becomes the sent exchange's comment and
// Organizer copies it) is pinned in Go by repeater_tab_note_test.go through the real routes.
import { beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { useApp } from "./store";

function reset() {
 useApp.setState({ repeaterTabs: [], closedRepeaterTabs: [], activeRepeaterTab: null });
}

const request = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";

describe("a Repeater tab's note", () => {
 beforeEach(reset);

 test("a tab opened with a note (an exchange's comment) carries it", () => {
  const id = useApp.getState().openRepeaterTab({ name: "a", target: "example.test", request, note: "seen in history" });
  expect(useApp.getState().repeaterTabs.find((tab) => tab.id === id)?.note).toBe("seen in history");
 });

 test("a tab opened without one has no note field at all, not an empty one", () => {
  const id = useApp.getState().openRepeaterTab({ name: "a", target: "example.test", request });
  expect("note" in (useApp.getState().repeaterTabs.find((tab) => tab.id === id) ?? {})).toBe(false);
 });

 test("duplicate and reopen keep the note", () => {
  const id = useApp.getState().openRepeaterTab({ name: "a", target: "example.test", request });
  useApp.getState().updateRepeaterTab(id, { note: "try the encoded variant" });
  useApp.getState().duplicateRepeaterTab(id);
  const copy = useApp.getState().repeaterTabs.find((tab) => tab.id !== id);
  expect(copy?.note, "a duplicated tab is a fork of the work, notes included").toBe("try the encoded variant");
  useApp.getState().closeRepeaterTab(id);
  useApp.getState().reopenClosedRepeaterTab();
  expect(useApp.getState().repeaterTabs.find((tab) => tab.id === id)?.note).toBe("try the encoded variant");
 });

 test("editing the request text never touches the note", () => {
  const id = useApp.getState().openRepeaterTab({ name: "a", target: "example.test", request, note: "keep me" });
  useApp.getState().updateRepeaterTab(id, { request: request.replace("/", "/x") });
  expect(useApp.getState().repeaterTabs.find((tab) => tab.id === id)?.note).toBe("keep me");
 });

 // The single send, blank-note omission and persistence are pinned by rendering the page
 // (pages/repeater.notes.test.tsx, vln1). This source pin remains only for the group send and the
 // hand-off's own send, which that test does not drive yet.
 test("every send path carries the note (single, group, and the hand-off's own send)", () => {
  const page = readFileSync(join(import.meta.dir, "..", "pages", "repeater.tsx"), "utf8");
  expect(page.match(/\.\.\.noteFor\(tab\)/g)?.length, "submit, submitGroup and handOffToIntruder").toBe(3);
 });
});
