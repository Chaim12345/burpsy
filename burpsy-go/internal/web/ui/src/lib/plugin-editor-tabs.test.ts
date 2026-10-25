// Which plugin editor-tab registrations reach the message editor's strip, and what opening
// one does (burpsy-react-ui-ww5).
//
// The DOM half — the tab buttons in the strip, the pre-formatted body, the toggle-on-click —
// needs a mounted console and is covered by the live pass. What is worth pinning without a
// DOM is the rule that decides whether a control exists at all, because a tab built from an
// unloaded plugin is a control that can only fail, and the invoke route refuses it. The
// precedent is plugin-registrations.test.ts, which pins the same rule for the menu surfaces.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pluginInvocations, pluginTabKey } from "./plugin-registrations";
import type { ExtensionList } from "./types.extensions";
import type { Registration } from "./types.extensions";

/** One registration, minimal: the fields pluginInvocations and pluginTabKey read. */
function registration(id: string, kind: Registration["kind"], label: string): Registration {
 return { id, kind, label };
}

/** An ExtensionList with one plugin, minimal: state and registrations are all the walk reads. */
function extensionList(state: "loaded" | "unloaded", registrations: Registration[]): ExtensionList {
 return {
  allowlisted: 1,
  policy: { admission: "allowlist", max_output_bytes: 4096, call_timeout_ms: 5000 },
  extensions: [{ name: "demo", path: "/tmp/demo", state, registrations }],
 } as unknown as ExtensionList;
}

describe("which editor-tab registrations reach the tab strip", () => {
 test("a loaded plugin's editor-tab registrations are offered, in the order they were declared", () => {
  const list = extensionList("loaded", [
   registration("zeta", "editor-tab", "Zeta view"),
   registration("alpha", "editor-tab", "Alpha view"),
  ]);
  expect(
   pluginInvocations(list, "editor-tab").map((invocation) => invocation.registration.id),
   "the served order is the plugin's own order; sorting by name would reorder a strip the operator cannot re-learn",
  ).toEqual(["zeta", "alpha"]);
 });

 test("an unloaded plugin contributes nothing, because the invoke route would refuse it", () => {
  const list = extensionList("unloaded", [registration("tab", "editor-tab", "Derived view")]);
  expect(pluginInvocations(list, "editor-tab"), "a tab built from an unloaded plugin is a control that can only fail when clicked").toEqual(
   [],
  );
 });

 test("a plugin that registered no editor tab contributes nothing to the strip", () => {
  const list = extensionList("loaded", [
   registration("act", "menu", "Run the demo scan"),
   registration("ctx", "context-menu", "Inspect this exchange"),
  ]);
  expect(
   pluginInvocations(list, "editor-tab"),
   "the strip shows editor-tab registrations only — the menu and context-menu kinds have their own surfaces",
  ).toEqual([]);
 });
});

describe("pluginTabKey", () => {
 test("the key names the message, the plugin and the registration, so two messages never share a tab's content", () => {
  expect(pluginTabKey(1, { plugin: "alpha", registration: registration("tab", "editor-tab", "Derived view") })).not.toBe(
   pluginTabKey(2, { plugin: "alpha", registration: registration("tab", "editor-tab", "Derived view") }),
  );
  expect(pluginTabKey(1, { plugin: "alpha", registration: registration("tab", "editor-tab", "Derived view") })).not.toBe(
   pluginTabKey(1, { plugin: "beta", registration: registration("tab", "editor-tab", "Derived view") }),
  );
 });

 test("the same message, plugin and registration always produce the same key, because the key is the content cache's identity", () => {
  const invocation = { plugin: "alpha", registration: registration("tab", "editor-tab", "Derived view") };
  expect(pluginTabKey(7, invocation)).toBe(pluginTabKey(7, invocation));
 });
});

// The strip, the tab body (text, loading, in-tab error) and the messageId hand-off are pinned by
// rendering the editor: ui/plugin-editor-tabs.test.tsx (vln1). What stays a source pin is that History
// passes its stored-message ids to its editors: rendering the History page for it is a separate, larger
// piece of work.
describe("history hands its editors the stored-message ids", () => {
 test("so the tabs render from the bytes on screen", () => {
  const history = readFileSync(join(import.meta.dir, "..", "pages", "history.tsx"), "utf8");
  expect(history).toMatch(/messageId=\{requestId \?\? undefined\}/);
  expect(history).toMatch(/messageId=\{selected\.response === null \? undefined/);
 });
});
