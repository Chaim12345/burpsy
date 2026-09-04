import { beforeEach, describe, expect, test } from "bun:test";
import { emptyIntruderConfig, persistedWorkspace, useApp, type IntruderRun } from "./store";

// ---- an Intruder attack must survive leaving the page -----------------------------------------
//
// All Intruder state used to live in the page's `useState`, and app.tsx mounts one page at a time
// (`const ActivePage = leaf.page` … `<ActivePage />`). Clicking any other nav entry therefore
// destroyed the base request, the positions, all seven payload forms, the processing rules and the
// finished report — no warning, and no way to re-run the attack because its configuration went with
// it (burpsy-react-ui-rby). A 5,000-request report was lost by clicking "Repeater" to check a
// header value.
//
// These pin the two halves of the fix: the state is in the store, and the store persists it.

function reset() {
  useApp.setState({ intruder: emptyIntruderConfig(), intruderRun: null, intruderTab: "positions" });
}

describe("the Intruder attack lives in the shared store", () => {
  beforeEach(reset);

  test("a configuration patch keeps the rest of the attack", () => {
    useApp.getState().setIntruder((current) => ({ ...current, msgId: "42", target: "https://host:443" }));
    useApp.getState().setIntruder((current) => ({ ...current, selected: [0, 2] }));
    const config = useApp.getState().intruder;
    expect(config.msgId).toBe("42");
    expect(config.target).toBe("https://host:443");
    expect(config.selected).toEqual([0, 2]);
    // Untouched fields survive a patch — the field setters in the page compose this way.
    expect(config.mode).toBe("sniper");
    expect(config.payloadTypes).toEqual(["list"]);
  });

  test("a finished report is state, not a render artefact", () => {
    const run: IntruderRun = {
      view: null,
      legacy: [{ payload: "admin", status: 200 }],
      snapshot: { mode: "sniper", points: 1, sets: [["admin"]] },
    };
    useApp.getState().setIntruderRun(run);
    expect(useApp.getState().intruderRun).toEqual(run);
    useApp.getState().setIntruderRun(null);
    expect(useApp.getState().intruderRun).toBeNull();
  });

  test("the open sub-tab is remembered, so returning lands where it was left", () => {
    useApp.getState().setIntruderTab("results");
    expect(useApp.getState().intruderTab).toBe("results");
  });
});

describe("the attack is persisted, like Repeater's drafts", () => {
  beforeEach(reset);

  test("partialize carries the configuration, the report and the open tab", () => {
    useApp.getState().setIntruder((current) => ({ ...current, msgId: "7" }));
    useApp.getState().setIntruderRun({ view: null, legacy: null, snapshot: null });

    const persisted = persistedWorkspace(useApp.getState());

    expect(Object.keys(persisted)).toContain("intruder");
    expect(Object.keys(persisted)).toContain("intruderRun");
    expect(Object.keys(persisted)).toContain("intruderTab");
    expect(persisted.intruder.msgId).toBe("7");
    expect(persisted.intruderRun).not.toBeNull();
    // Repeater's drafts are the precedent this follows; both must stay in.
    expect(Object.keys(persisted)).toContain("repeaterTabs");
  });

  test("the one-shot send-to handoff is still NOT persisted", () => {
    // intruderSeed is a transient coordination flag, cleared on arrival. Persisting it would
    // re-seed the page on every reload and overwrite the attack this change exists to protect.
    useApp.getState().setIntruderSeed({ msgId: 3, target: "https://host", label: "GET /" });
    const persisted = persistedWorkspace(useApp.getState());
    expect(Object.keys(persisted)).not.toContain("intruderSeed");
    // And the reopen-closed stack stays out, as its own comment in the store promises.
    expect(Object.keys(persisted)).not.toContain("closedRepeaterTabs");
  });
});
