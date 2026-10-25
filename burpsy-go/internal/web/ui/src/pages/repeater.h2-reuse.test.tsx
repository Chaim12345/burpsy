/**
 * burpsy-react-ui-vln1 (replaces the source-text pins in lib/repeater-h2-reuse.test.ts): HTTP/2
 * connection reuse (adkx) as the page behaves. The wire half is pinned in Go.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { cleanup, fireEvent, screen } from "@testing-library/react";
import { type FakeRepeater, fakeRepeaterApi, openOnlyTab, pressSend, renderRepeater } from "../../test/repeater-fake";
import { useApp } from "../lib/store";

let fake: FakeRepeater;
beforeEach(() => {
 fake = fakeRepeaterApi();
});
afterEach(() => {
 cleanup();
 fake.restore();
});

describe("Repeater HTTP/2 connection reuse", () => {
 test("a send names its tab, which is what keys the tab's reused connection", async () => {
  const id = openOnlyTab("https://target.test:443");
  renderRepeater();
  await pressSend(fake);
  expect(fake.sends[0]?.tab_id).toBe(id);
 });

 test("the Config panel offers both switches, and turning one on is what the next send carries", async () => {
  openOnlyTab("https://target.test:443");
  renderRepeater();
  fireEvent.click(await screen.findByRole("button", { name: /Config/ }));
  fireEvent.click(await screen.findByLabelText("HTTP/2 connection reuse"));
  fireEvent.click(screen.getByLabelText("Use selected protocol for cross-domain redirects"));
  await pressSend(fake);
  expect(fake.sends[0]?.options).toMatchObject({ h2_connection_reuse: true, enforce_protocol_cross_domain: true });
  expect(useApp.getState().repeaterTabs[0]?.options).toMatchObject({ h2_connection_reuse: true });
 });
});
