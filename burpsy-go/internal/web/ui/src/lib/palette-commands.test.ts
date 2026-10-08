// The three palette groups that are built from data rather than written out (burpsy-react-ui-1wrb).
//
// Each group exists because Burp's palette has it (tools/command-palette.html: recently used
// commands at the top, encoding data as a core command, extension-created commands), and each is
// an enumeration of something the console already holds. The claims worth pinning are therefore
// about *fidelity to the source*: a Recents row is the same command it summarises, a codec row
// runs the codec it names, and an extension row exists only for a plugin that could answer it.
import { describe, expect, test } from "bun:test";
import { RECENTS_GROUP, codecCommands, extensionCommands, recentCommands } from "./palette-commands";
import { SELECTION_CODECS } from "./selection-codecs";
import type { ExtensionList, ExtensionView, Registration } from "./types.extensions";
import { catalogueCommands } from "./palette-commands";
import { SHORTCUT_ACTIONS } from "./shortcuts";

const noop = () => {};

function action(id: string) {
  return { id, label: id, group: "Go to", run: noop };
}

/** An extension list with only the fields these rules read; the rest of the wire shape is noise here. */
function extensionList(extensions: Partial<ExtensionView>[]): ExtensionList {
  return { extensions: extensions as ExtensionView[] } as ExtensionList;
}

function registration(id: string, kind: Registration["kind"], label: string): Registration {
  return { id, kind, label };
}

describe("the Recently used group", () => {
  test("the most recently run command is listed first, which is the whole point of the group", () => {
    const actions = [action("nav.history"), action("nav.repeater"), action("cmd:theme")];
    const recent = recentCommands(actions, { "nav.history": 1, "cmd:theme": 2, "nav.repeater": 3 });
    expect(
      recent.map((entry) => entry.id),
      "a Recents group in ledger order rather than recency order is just the command list again, and an operator repeating a command would still have to hunt for it",
    ).toEqual(["nav.repeater", "cmd:theme", "nav.history"]);
  });

  test("a Recents row is the same object as the command it summarises, not a copy of it", () => {
    const actions = [action("nav.history")];
    const [recent] = recentCommands(actions, { "nav.history": 5 });
    expect(
      recent,
      "a copied row would run a copied `run` and record a copied id: the ledger would start ranking a second, parallel notion of 'recent' that drifts from the one the palette sorts by",
    ).toBe(actions[0]);
  });

  test("a command the ledger remembers but the palette no longer offers is dropped", () => {
    const recent = recentCommands([action("nav.history")], { "nav.retired": 9, "nav.history": 1 });
    expect(
      recent.map((entry) => entry.id),
      "the ledger outlives the build that wrote it, so a removed command is still in an operator's storage — listing it would be a Recents row with nothing behind it to run",
    ).toEqual(["nav.history"]);
  });

  test("the group is bounded, so Recents stays a shortcut past the list instead of a second copy of it", () => {
    const actions = Array.from({ length: 20 }, (_, index) => action(`a${index}`));
    const ledger = Object.fromEntries(actions.map((entry, index) => [entry.id, index]));
    expect(
      recentCommands(actions, ledger).length,
      "an unbounded Recents block pushes the rest of the palette off the screen, which costs the operator the list they opened it to see",
    ).toBe(6);
  });

  test("an empty ledger produces no group at all", () => {
    expect(
      recentCommands([action("nav.history")], {}),
      "an empty 'Recently used' heading would advertise a feature with nothing under it on every first run",
    ).toEqual([]);
  });

  test("the group has a heading the palette can print", () => {
    expect(RECENTS_GROUP, "the heading is what tells an operator why these rows are above the rest").toBe("Recently used");
  });
});

describe("the encode/decode commands", () => {
  test("the palette offers one entry per transform the editor's menu offers", () => {
    const commands = codecCommands(noop, { runnable: true });
    expect(
      commands.map((command) => command.id),
      "a codec missing from this list is a transform an operator can reach from the context menu and not from mod+K, which is the gap the group exists to close",
    ).toEqual(SELECTION_CODECS.map((codec) => `convert:${codec.id}`));
  });

  test("running an entry runs the codec it names, not the first one in the table", () => {
    const ran: string[] = [];
    const commands = codecCommands((codec) => ran.push(codec.id), { runnable: true });
    commands[3]?.run();
    expect(
      ran,
      "an entry that runs the wrong transform silently rewrites a selection into the wrong encoding, which looks like a codec bug rather than a wiring bug",
    ).toEqual([SELECTION_CODECS[3]?.id ?? "(none)"]);
  });

  test("with nothing selected every entry is disabled rather than merely unhelpful", () => {
    const commands = codecCommands(noop, { runnable: false, note: "select text in a message editor first" });
    expect(
      commands.filter((command) => !command.disabled).map((command) => command.id),
      "an enabled codec with no selection is an entry that closes the palette and does nothing, which is exactly the failure this group must not ship",
    ).toEqual([]);
  });

  test("the reason a codec cannot run is printed on its group heading, as the editor's menu prints it", () => {
    const commands = codecCommands(noop, { runnable: false, note: "select text in a message editor first" });
    expect(
      commands[0]?.group,
      "a disabled row with no stated condition reads as broken; the editor's own menu answers this by putting the condition in the heading",
    ).toBe("Convert selection (select text in a message editor first)");
  });

  test("a disabled entry carries its reason on the row, because Recents prints it away from its heading", () => {
    const commands = codecCommands(noop, { runnable: false, note: "select text in a message editor first" });
    expect(
      commands[0]?.disabledReason,
      "the Recently used group lifts a row out from under the heading that states the condition: with nothing on the row itself, a recently-run codec would sit among the recents looking ordinary and do nothing when chosen",
    ).toBe("select text in a message editor first");
  });

  test("a runnable entry carries no reason, so the ordinary row prints no caveat under its label", () => {
    expect(
      codecCommands(noop, { runnable: true })[0]?.disabledReason,
      "a reason left on a runnable row would print a condition that is already met",
    ).toBeUndefined();
  });

  test("with a usable selection the headings are the editor's plain group titles", () => {
    const groups = new Set(codecCommands(noop, { runnable: true }).map((command) => command.group));
    expect(
      [...groups].sort(),
      "the ordinary case must not carry a caveat, or the palette would warn about a condition that is already met",
    ).toEqual(["Construct string", "Convert selection"]);
  });

  test("every entry is findable by the word Burp uses for the whole family", () => {
    const missing = codecCommands(noop, { runnable: true }).filter(
      (command) => !`${command.label} ${command.keywords ?? ""}`.toLowerCase().includes("encod"),
    );
    expect(
      missing.map((command) => command.id),
      "an operator typing 'encode' is asking for this group by the name Burp gives it; a row that does not answer that word is a row they will not find",
    ).toEqual([]);
  });
});

describe("the extension-registered commands", () => {
  test("a loaded plugin's menu registration becomes a palette entry", () => {
    const list = extensionList([
      { name: "demo", state: "loaded", registrations: [registration("scan", "menu", "Run the demo scan")] },
    ]);
    const commands = extensionCommands(list, noop);
    expect(
      commands.map((command) => ({ id: command.id, label: command.label, group: command.group })),
      "a registration the host reports and the palette does not list is a command an extension author registered and no operator can reach",
    ).toEqual([{ id: "extension:demo:scan", label: "Run the demo scan", group: "Extensions" }]);
  });

  test("an unloaded plugin contributes nothing, because the invoke route would refuse it", () => {
    const list = extensionList([
      { name: "demo", state: "unloaded", registrations: [registration("scan", "menu", "Run the demo scan")] },
    ]);
    expect(
      extensionCommands(list, noop),
      "an entry for a plugin that is not running can only fail when selected, and an entry that cannot run is worse than an absent one",
    ).toEqual([]);
  });

  test("a context-menu registration is not offered, because the palette has no exchange to invoke it about", () => {
    const list = extensionList([
      { name: "demo", state: "loaded", registrations: [registration("decode", "context-menu", "Decode this")] },
    ]);
    expect(
      extensionCommands(list, noop),
      "a context-menu handler is called about the row the operator right-clicked; run from the palette it would be invoked against nothing",
    ).toEqual([]);
  });

  test("selecting an entry invokes that plugin's registration, named so the host can dispatch it", () => {
    const invoked: string[] = [];
    const list = extensionList([
      { name: "alpha", state: "loaded", registrations: [registration("go", "menu", "Go")] },
      { name: "beta", state: "loaded", registrations: [registration("go", "menu", "Go")] },
    ]);
    const commands = extensionCommands(list, (call) => invoked.push(`${call.plugin}/${call.registration.id}`));
    commands[1]?.run();
    expect(
      invoked,
      "two plugins may register the same id and the same label; invoking the wrong one runs a different piece of code than the row the operator chose",
    ).toEqual(["beta/go"]);
  });

  test("a console with no extensions offers no group, rather than an empty heading", () => {
    expect(
      extensionCommands(undefined, noop),
      "an 'Extensions' heading with nothing under it claims a registry this console does not have",
    ).toEqual([]);
  });

  test("an entry says which plugin it came from, because two plugins can register the same label", () => {
    const list = extensionList([
      { name: "demo", state: "loaded", registrations: [registration("scan", "menu", "Scan")] },
    ]);
    expect(
      extensionCommands(list, noop)[0]?.hint,
      "without the plugin's name the row is an unattributed command, and an operator cannot tell which extension is about to run",
    ).toBe("registered by demo");
  });
});

describe("catalogueCommands (2czi)", () => {
  const build = catalogueCommands;

  test("every catalogue action named in the acceptance criteria is a palette row", () => {
    const rows = build(SHORTCUT_ACTIONS, {}, () => false, () => undefined);
    const ids = new Set(rows.map((row) => row.id.replace(/^action:/, "")));
    for (const id of [
      "tab.close", "tab.reopen", "tab.duplicate", "tab.next", "tab.prev", "tab.rename",
      "repeater.historyBack", "repeater.historyForward",
      "proxy.forwardAll", "proxy.dropAll", "proxy.interceptResponse",
      "intruder.startAttack",
      "editor.togglePretty", "editor.toggleWrap", "editor.toggleNonPrinting", "editor.toggleHideHeaders",
      "editor.toggleSidebar", "editor.cycleLayout", "editor.insertCollaborator",
      "nav.search", "nav.settings", "tasks.toggle",
    ]) {
      expect(ids.has(id), id).toBe(true);
    }
    // Every row flagged `palette` is emitted, and only those.
    expect(rows.length).toBe(SHORTCUT_ACTIONS.filter((action) => action.palette).length);
  });

  test("a row with no mounted handler is disabled with where it lives; one with a handler runs it", () => {
    const ran: string[] = [];
    const rows = build(SHORTCUT_ACTIONS, {}, (id) => id === "tab.close", (id) => ran.push(id));
    const close = rows.find((row) => row.id === "action:tab.close")!;
    const dropAll = rows.find((row) => row.id === "action:proxy.dropAll")!;
    expect(close.disabled).toBe(false);
    close.run();
    expect(ran).toEqual(["tab.close"]);
    expect(dropAll.disabled).toBe(true);
    expect(dropAll.disabledReason).toBe("Available in Proxy › Intercept");
  });

  test("the shortcut column shows the operator's binding, not the default", () => {
    const rows = build(SHORTCUT_ACTIONS, { "tab.close": "alt+w" }, () => true, () => undefined);
    expect(rows.find((row) => row.id === "action:tab.close")!.shortcut).toBe("alt+w");
    expect(rows.find((row) => row.id === "action:tab.reopen")!.shortcut).toBeUndefined();
  });
});
