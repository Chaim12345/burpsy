/**
 * burpsy-react-ui-vln1 (replaces two source-text pins in lib/repeater-notes.test.ts): the Repeater
 * tab note (jva5) as the page and the store behave. The wire half is pinned in Go.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup } from "@testing-library/react";
import { type FakeRepeater, fakeRepeaterApi, openOnlyTab, pressSend, renderRepeater } from "../../test/repeater-fake";

let fake: FakeRepeater;
beforeEach(() => {
 fake = fakeRepeaterApi();
});
afterEach(() => {
 cleanup();
 fake.restore();
});

describe("Repeater tab note", () => {
 test("a send carries the tab's note", async () => {
  openOnlyTab("https://target.test:443", { note: "try the encoded variant" });
  renderRepeater();
  await pressSend(fake);
  expect(fake.sends[0]?.note).toBe("try the encoded variant");
 });

 test("a blank note records no comment: it is omitted, not sent empty", async () => {
  openOnlyTab("https://target.test:443", { note: "   " });
  renderRepeater();
  await pressSend(fake);
  expect("note" in (fake.sends[0] ?? {})).toBe(false);
 });

 test("the note survives a reload: it is in the persisted workspace", () => {
  openOnlyTab("https://target.test:443", { note: "keep me" });
  const saved = JSON.parse(window.localStorage.getItem("burpsy.workspace") ?? "{}") as {
   state?: { repeaterTabs?: { note?: string }[] };
  };
  expect(saved.state?.repeaterTabs?.[0]?.note).toBe("keep me");
 });
});
