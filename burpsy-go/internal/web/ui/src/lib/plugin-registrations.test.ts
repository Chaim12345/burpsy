// The context-menu half of burpsy-react-ui-ww5.
//
// These rules are testable without a DOM and are the ones that decide whether the control is real:
// which registrations reach the menu, what each row runs, and — the claim burpsy-react-ui-d3gj turns
// on — that the order the server served the plugins in is the order the menu offers them in.
import { describe, expect, test } from "bun:test";
import { PLUGIN_MENU_ID, pluginInvocations, pluginMenuGroup, pluginMenuItems, pluginTabKey } from "./plugin-registrations";
import type { ExtensionList, ExtensionView, Registration } from "./types.extensions";

const noop = () => {};

/** An extension list with only the fields these rules read; the rest of the wire shape is noise here. */
function extensionList(extensions: Partial<ExtensionView>[]): ExtensionList {
  return { extensions: extensions as ExtensionView[] } as ExtensionList;
}

function registration(id: string, kind: Registration["kind"], label: string): Registration {
  return { id, kind, label };
}

/** A loaded plugin with one context-menu registration, which is the shape every test here needs. */
function loaded(name: string, registrations: Registration[]): Partial<ExtensionView> {
  return { name, state: "loaded", registrations };
}

describe("the Extensions group in an exchange context menu", () => {
  test("a loaded plugin's context-menu registration becomes a row that invokes it with the exchange", () => {
    const calls: { plugin: string; registration: string; exchange?: number }[] = [];
    const list = extensionList([loaded("jwt", [registration("decode", "context-menu", "Decode the token")])]);

    const group = pluginMenuGroup(list, 77, (call, target) =>
      calls.push({ plugin: call.plugin, registration: call.registration.id, exchange: target.exchange }),
    );
    expect(group, "a loaded plugin with a context-menu registration must produce a group; without one the registration is a row on the Extender page and nothing else").not.toBeNull();

    const submenu = group?.actions[0]?.submenu?.[0]?.actions ?? [];
    expect(submenu.map((row) => row.label), "the row's label is the plugin's own words — renaming it here would be a second implementation of a fact the host published").toEqual([
      "Decode the token",
    ]);

    expect(calls, "building the group must be free of side effects: a menu that invoked every plugin as it rendered would run code the operator never chose").toEqual([]);
    submenu[0]?.onSelect();
    expect(calls, "selecting the row must invoke that plugin's registration against the exchange the menu was opened on — an item that cannot carry the selected exchange cannot do the one thing its kind name means").toEqual([
      { plugin: "jwt", registration: "decode", exchange: 77 },
    ]);
  });

  test("a plugin that is not loaded contributes nothing, because the invoke route would refuse it", () => {
    const list = extensionList([
      { name: "asleep", state: "unloaded", registrations: [registration("decode", "context-menu", "Decode")] },
      { name: "gone", state: "crashed", registrations: [registration("decode", "context-menu", "Decode")] },
    ]);
    expect(
      pluginMenuGroup(list, 1, noop),
      "an unloaded plugin's row could only fail: POST /api/extensions/invoke answers 409 for a plugin that is not running, so offering it would be a control that does nothing real",
    ).toBeNull();
  });

  test("no loaded plugin declaring a context-menu item leaves the menu exactly as it was", () => {
    const empty = extensionList([]);
    expect(pluginMenuGroup(empty, 1, noop), "an empty allowlist is the stock build's state and must be an absence, not an empty heading").toBeNull();
    expect(pluginMenuItems(empty, 1, noop), "pluginMenuItems is what a menu spreads, so the empty case has to be a spread of nothing rather than a group with no rows").toEqual([]);
    expect(pluginMenuItems(undefined, 1, noop), "the list is undefined while /api/extensions is still in flight; a menu opened then must not carry a heading that fills in later").toEqual([]);
  });

  test("only context-menu registrations reach the context menu", () => {
    const list = extensionList([
      loaded("mixed", [
        registration("act", "menu", "A menu action"),
        registration("tab", "editor-tab", "A derived view"),
        registration("ctx", "context-menu", "The only one that belongs here"),
      ]),
    ]);
    const rows = pluginMenuGroup(list, 1, noop)?.actions[0]?.submenu?.[0]?.actions ?? [];
    expect(rows.map((row) => row.label), "a menu action has no selection behind it and an editor tab is a view, not a command; offering either here would put a row in the menu that means something else when clicked").toEqual([
      "The only one that belongs here",
    ]);
  });

  test("two plugins are two rows, so the menu names which code is about to run", () => {
    const list = extensionList([
      loaded("jwt", [registration("decode", "context-menu", "Decode")]),
      loaded("proto", [registration("decode", "context-menu", "Decode")]),
    ]);
    const group = pluginMenuGroup(list, 1, noop);
    expect(group?.actions.map((row) => row.label), "two plugins offering 'Decode' are two different pieces of code; a flat list would hide which one the operator is about to invoke").toEqual([
      "jwt",
      "proto",
    ]);
    expect(group?.id, "the group id is stable so a caller can find the group it contributed").toBe(PLUGIN_MENU_ID);
  });

  test("the menu follows the order the server served the plugins in", () => {
    // The d3gj claim, from the menu's side: POST /api/extensions/order permutes the served list, and
    // this is what makes that permutation visible and dispatchable. If the menu sorted by name, an
    // operator could move a plugin to the top of the Extender table and find it still second here.
    const served = extensionList([
      loaded("zeta", [registration("z", "context-menu", "Zeta's action")]),
      loaded("alpha", [registration("a", "context-menu", "Alpha's action")]),
    ]);
    expect(
      pluginMenuGroup(served, 1, noop)?.actions.map((row) => row.label),
      "the group must follow the served order and never re-sort it: reordering is the operator's control over which plugin sees a message first, and a menu that sorted by name would silently discard it",
    ).toEqual(["zeta", "alpha"]);
    expect(
      pluginInvocations(served, "context-menu").map((call) => call.plugin),
      "pluginInvocations is the single walk every surface uses — palette group, context menu, editor tabs — so the order has to live here and not be re-derived per surface",
    ).toEqual(["zeta", "alpha"]);
  });
});

describe("a plugin tab's identity", () => {
  test("the same registration over two messages is two keys", () => {
    const [invocation] = pluginInvocations(
      extensionList([loaded("jwt", [registration("view", "editor-tab", "Decoded")])]),
      "editor-tab",
    );
    expect(invocation, "the fixture must yield one editor-tab invocation or the rest of this test proves nothing").toBeDefined();
    expect(
      pluginTabKey(1, invocation!),
      "keying on the registration alone would keep showing a stale render when the operator selects another row",
    ).not.toBe(pluginTabKey(2, invocation!));
  });
});
