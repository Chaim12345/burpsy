/**
 * burpsy-react-ui-vln1: the group send and the hand-off's own send carry a tab's Override SNI and
 * note too, rendered. Replaces the count-the-spread source pins in lib/repeater-sni.test.ts and
 * lib/repeater-notes.test.ts.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { type FakeRepeater, fakeRepeaterApi, renderRepeater } from "../../test/repeater-fake";
import { useApp } from "../lib/store";

let fake: FakeRepeater;
beforeEach(() => {
 fake = fakeRepeaterApi();
 useApp.setState({ repeaterTabs: [], activeRepeaterTab: "", repeaterGroups: [], intruderSeed: null } as never);
});
afterEach(() => {
 cleanup();
 fake.restore();
});

const request = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

function tab(target: string, patch: Record<string, unknown>): string {
 const id = useApp.getState().openRepeaterTab({ name: "t", target, request });
 useApp.getState().updateRepeaterTab(id, patch);
 return id;
}

describe("the group send", () => {
 test("each item carries its tab's SNI (TLS only, never blank) and note (never blank)", async () => {
  const a = tab("https://a.test:443", { sni: " oast.example ", note: "first" });
  const b = tab("http://b.test:80", { sni: "ignored.example", note: "  " });
  const groupId = useApp.getState().createRepeaterGroup();
  useApp.getState().setRepeaterTabGroup(a, groupId);
  useApp.getState().setRepeaterTabGroup(b, groupId);
  useApp.getState().setActiveRepeaterTab(a);
  renderRepeater();
  fireEvent.keyDown(await screen.findByRole("button", { name: /^Send group/ }), { key: "Enter" });
  const modes = await screen.findAllByRole("menuitem");
  fireEvent.click(modes[0] as HTMLElement);
  await waitFor(() => expect(fake.groupSends.length).toBe(1));
  const items = fake.groupSends[0]?.items as Record<string, unknown>[];
  expect(items.length).toBe(2);
  expect(items[0]).toMatchObject({ sni: "oast.example", note: "first" });
  expect("sni" in (items[1] ?? {})).toBe(false);
  expect("note" in (items[1] ?? {})).toBe(false);
 });
});

describe("the hand-off to Intruder", () => {
 test("a tab that has not been sent is sent first, carrying its SNI and note, then seeds Intruder", async () => {
  const id = tab("https://a.test:443", { sni: "oast.example", note: "seen" });
  useApp.getState().setActiveRepeaterTab(id);
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: "To Intruder" }));
  await waitFor(() => expect(fake.sends.length).toBe(1));
  expect(fake.sends[0]).toMatchObject({ sni: "oast.example", note: "seen" });
  await waitFor(() => expect(useApp.getState().route).toBe("intruder"));
  expect(useApp.getState().intruderSeed).toMatchObject({ msgId: 9 });
 });

 test("for a plain-HTTP tab the hand-off's send carries no SNI", async () => {
  const id = tab("http://a.test:80", { sni: "oast.example" });
  useApp.getState().setActiveRepeaterTab(id);
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: "To Intruder" }));
  await waitFor(() => expect(fake.sends.length).toBe(1));
  expect("sni" in (fake.sends[0] ?? {})).toBe(false);
 });
});
