/**
 * The component tests share one process, so one module-level store and one localStorage. A test that
 * leaves a preference on (editor-url-encode did: urlEncodeAsYouType stayed true) changes what every
 * later test in the run types, and showed up as a failure in an unrelated file. test/dom-preload.ts
 * resets both after each test; these two tests fail if it stops.
 */
import { describe, expect, test } from "bun:test";
import { useApp } from "../lib/store";

describe("component tests do not leak state into each other", () => {
 test("first test leaves store and storage dirty", () => {
  useApp.setState({ urlEncodeAsYouType: true, hideHeadersByDefault: true });
  window.localStorage.setItem("burpsy.leak-probe", "1");
  expect(useApp.getState().urlEncodeAsYouType).toBe(true);
 });
 test("the next test starts from the initial store and an empty storage", () => {
  expect(useApp.getState().urlEncodeAsYouType).toBe(useApp.getInitialState().urlEncodeAsYouType);
  expect(useApp.getState().hideHeadersByDefault).toBe(useApp.getInitialState().hideHeadersByDefault);
  expect(window.localStorage.getItem("burpsy.leak-probe")).toBeNull();
 });
});
