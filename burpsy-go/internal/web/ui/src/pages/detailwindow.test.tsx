/**
 * burpsy-react-ui-vln1 (replaces the source-line pin in lib/detail-window-route.test.ts): the URL
 * "Show details in new window" opens, observed through window.open (burpsy-react-ui-76ea).
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { findLeaf } from "../nav";
import type { Exchange } from "../lib/types";
import { openDetailWindow } from "./detailwindow";

const originalOpen = window.open;
let opened: { url: string; target: string | undefined; features: string | undefined }[] = [];

beforeEach(() => {
 opened = [];
 window.open = ((url?: string | URL, target?: string, features?: string) => {
  opened.push({ url: String(url), target, features });
  return {} as Window;
 }) as typeof window.open;
});
afterEach(() => {
 window.open = originalOpen;
});

describe("openDetailWindow", () => {
 test("opens the detail leaf's route carrying the exchange id, so the new window lands on the detail page", () => {
  expect(openDetailWindow({ id: 42 } as Exchange)).toBe(true);
  const url = opened[0]?.url ?? "";
  expect(url).toContain("exchange=42");
  const hash = url.slice(url.indexOf("#") + 1);
  // The hash is the route: it must resolve to the hidden detail leaf, not the history table.
  expect(findLeaf(hash).id).toBe("exchange-detail");
  expect(url.endsWith("#exchange-detail")).toBe(true);
 });

 test("a second exchange opens its own window", () => {
  openDetailWindow({ id: 1 } as Exchange);
  openDetailWindow({ id: 2 } as Exchange);
  expect(new Set(opened.map((call) => call.target)).size).toBe(2);
 });
});
