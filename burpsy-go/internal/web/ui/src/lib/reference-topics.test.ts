// The trailing "<Tool> documentation" entry (u9zz): every topic a menu can name resolves to a
// panel Discover renders, and the entry is added last, only to menus that have entries.
import { describe, expect, test } from "bun:test";
import { DOC_TOPICS, docEntryLabel, type DocTopic } from "./docs";
import { referencePanels, TOOL_PANELS } from "./reference";
import { withDocs } from "../ui/menu";

describe("documentation topics", () => {
 test("every topic resolves to a panel Discover renders", () => {
  const rendered = new Set(referencePanels({}).map((panel) => panel.id));
  for (const [topic, { panelId }] of Object.entries(DOC_TOPICS)) {
   expect(rendered.has(panelId), `${topic} → ${panelId}`).toBe(true);
  }
 });

 test("every tool panel is some topic's, and each has rows", () => {
  const targets = new Set(Object.values(DOC_TOPICS).map((entry) => entry.panelId));
  for (const panel of TOOL_PANELS) {
   expect(targets.has(panel.id), panel.id).toBe(true);
   expect(panel.rows.length, panel.id).toBeGreaterThan(0);
  }
 });

 test("the entry reads as Burp's does", () => {
  expect(docEntryLabel("proxy-history")).toBe("Proxy history documentation");
  expect(docEntryLabel("repeater")).toBe("Repeater documentation");
 });
});

describe("withDocs", () => {
 const own = [{ id: "send", actions: [{ id: "repeater", label: "Send to Repeater", onSelect: () => undefined }] }];

 test("appends the entry as the last group", () => {
  const groups = withDocs(own, "proxy-history");
  expect(groups.length).toBe(2);
  expect(groups.at(-1)!.actions.map((action) => action.label)).toEqual(["Proxy history documentation"]);
 });

 test("a menu with no entries of its own gets no documentation-only menu", () => {
  expect(withDocs([], "tables")).toEqual([]);
  expect(withDocs([{ id: "empty", actions: [] }], "tables")).toEqual([{ id: "empty", actions: [] }]);
 });

 test("null opts out", () => {
  expect(withDocs(own, null as DocTopic | null)).toBe(own);
 });
});
