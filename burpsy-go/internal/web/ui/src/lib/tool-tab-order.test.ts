/** burpsy-react-ui-sk29: top-level tool tabs can be reordered, and the order is remembered. */
import { afterEach, describe, expect, test } from "bun:test";
import { TOOL_TAB_ORDER_STORAGE_KEY, moveToolTab, orderToolTabs, readToolTabOrder, writeToolTabOrder } from "./tool-tabs";

const store = new Map<string, string>();
const fakeStorage = {
 getItem: (key: string) => store.get(key) ?? null,
 setItem: (key: string, value: string) => void store.set(key, value),
 removeItem: (key: string) => void store.delete(key),
 clear: () => store.clear(),
};
const existingWindow = (globalThis as Record<string, unknown>).window as
 | (Record<string, unknown> & { localStorage?: Storage })
 | undefined;
if (existingWindow) {
 existingWindow.localStorage = fakeStorage as unknown as Storage;
} else {
 (globalThis as Record<string, unknown>).window = {
  localStorage: fakeStorage,
  addEventListener: () => {},
  removeEventListener: () => {},
 };
}

afterEach(() => store.clear());

const tabs = ["dashboard", "target", "proxy", "intruder", "repeater"].map((id) => ({ id }));
const ids = (list: { id: string }[]) => list.map((tab) => tab.id);

describe("orderToolTabs", () => {
 test("no saved order is the default order", () => {
  expect(ids(orderToolTabs(tabs, []))).toEqual(ids(tabs));
 });
 test("saved ids come first in saved order", () => {
  expect(ids(orderToolTabs(tabs, ["repeater", "proxy"]))).toEqual(["repeater", "proxy", "dashboard", "target", "intruder"]);
 });
 test("unknown saved ids are ignored and a tab missing from the saved order keeps its default place after the saved ones", () => {
  expect(ids(orderToolTabs(tabs, ["gone", "intruder", "gone"]))).toEqual(["intruder", "dashboard", "target", "proxy", "repeater"]);
 });
 test("never loses or duplicates a tab", () => {
  const out = ids(orderToolTabs(tabs, ["proxy", "proxy", "dashboard"]));
  expect([...out].sort()).toEqual(ids(tabs).sort());
 });
});

describe("moveToolTab", () => {
 const order = ids(tabs);
 test("dragging forward drops the tab after the target", () => {
  expect(moveToolTab(order, "dashboard", "proxy")).toEqual(["target", "proxy", "dashboard", "intruder", "repeater"]);
 });
 test("dragging backward drops the tab before the target", () => {
  expect(moveToolTab(order, "repeater", "target")).toEqual(["dashboard", "repeater", "target", "proxy", "intruder"]);
 });
 test("dropping on itself or an unknown id changes nothing", () => {
  expect(moveToolTab(order, "proxy", "proxy")).toEqual(order);
  expect(moveToolTab(order, "proxy", "nope")).toEqual(order);
  expect(moveToolTab(order, "nope", "proxy")).toEqual(order);
 });
});

describe("persistence", () => {
 test("round trips", () => {
  writeToolTabOrder(["b", "a"]);
  expect(readToolTabOrder()).toEqual(["b", "a"]);
  expect(store.has(TOOL_TAB_ORDER_STORAGE_KEY)).toBe(true);
 });
 test("garbage reads as the default order", () => {
  store.set(TOOL_TAB_ORDER_STORAGE_KEY, "{not json");
  expect(readToolTabOrder()).toEqual([]);
  store.set(TOOL_TAB_ORDER_STORAGE_KEY, JSON.stringify({ a: 1 }));
  expect(readToolTabOrder()).toEqual([]);
  store.set(TOOL_TAB_ORDER_STORAGE_KEY, JSON.stringify(["a", 3, "", "b"]));
  expect(readToolTabOrder()).toEqual(["a", "b"]);
 });
});
