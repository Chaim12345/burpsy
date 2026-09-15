import { beforeEach, describe, expect, test } from "bun:test";
import { emptyIntruderConfig, intruderLaunchBlocker, persistedWorkspace, useApp } from "./store";

// ---- the menubar asks; the Intruder page decides ------------------------------------------------
//
// The Intruder menu in the menubar (burp.Zcur mainIntruderMenu) has to start and stop an attack
// whose entire launch sequence lives in pages/intruder.tsx — the pre-launch snapshot of running
// attacks, the payload snapshot the report is read through, the payload-source encoding. Copying
// that into app.tsx would be a second attack launcher. So the menu writes an intention and the page
// performs it, and the page publishes back what it will currently permit.
//
// These pin the two halves that can go wrong silently: an instruction that does not re-fire, and an
// instruction that survives a reload and launches an attack nobody clicked for.

function reset() {
  useApp.setState({
    intruder: emptyIntruderConfig(),
    intruderRun: null,
    intruderCommand: null,
    intruderStatus: null,
  });
}

describe("the menubar's instruction reaches the Intruder page", () => {
  beforeEach(reset);

  test("clicking Start twice is two instructions, not one", () => {
    // A bare "start" string would be equal to itself, so the page's effect would not re-fire and
    // the second click would do nothing at all — a menu row that works once and then lies.
    useApp.getState().requestIntruderCommand("start");
    const first = useApp.getState().intruderCommand;
    useApp.getState().requestIntruderCommand("start");
    const second = useApp.getState().intruderCommand;
    expect(first?.kind).toBe("start");
    expect(second?.kind).toBe("start");
    expect(second?.nonce).toBeGreaterThan(first!.nonce);
  });

  test("the page consumes the instruction, so it cannot be performed twice", () => {
    useApp.getState().requestIntruderCommand("stop");
    expect(useApp.getState().intruderCommand?.kind).toBe("stop");
    useApp.getState().clearIntruderCommand();
    expect(useApp.getState().intruderCommand).toBeNull();
  });

  test("neither the instruction nor the page's status survives a reload", () => {
    // A persisted "start" would launch an attack against a live target on every page load with no
    // click behind it. A persisted status would tell the menubar an attack is running when the
    // process that was running it is gone, so Stop would offer to stop nothing.
    useApp.getState().requestIntruderCommand("start");
    useApp.getState().setIntruderStatus({ refusal: null, running: true, controllable: true });
    const persisted = persistedWorkspace(useApp.getState());
    expect(Object.keys(persisted)).not.toContain("intruderCommand");
    expect(Object.keys(persisted)).not.toContain("intruderStatus");
    // The attack itself still persists — that is the property this must not break.
    expect(Object.keys(persisted)).toContain("intruder");
  });

  test("leaving the Intruder page takes its status with it", () => {
    useApp.getState().setIntruderStatus({ refusal: null, running: true, controllable: true });
    useApp.getState().setIntruderStatus(null);
    expect(useApp.getState().intruderStatus).toBeNull();
  });
});

describe("the menu can say why Start attack is grey without the page mounted", () => {
  beforeEach(reset);

  test("an untouched attack names the first thing missing", () => {
    expect(intruderLaunchBlocker(emptyIntruderConfig())).toContain("stored message id");
  });

  test("a non-numeric message id is named, not silently treated as absent", () => {
    const blocker = intruderLaunchBlocker({ ...emptyIntruderConfig(), msgId: "twelve" });
    expect(blocker).toContain("twelve");
  });

  test("message 0 is a real base request, so it is not the obstacle", () => {
    // Stored ids count from zero. A `> 0` check here would make the very first captured request the
    // one request whose attack could never be started from the menu.
    const blocker = intruderLaunchBlocker({
      ...emptyIntruderConfig(),
      msgId: "0",
      target: "https://host:443",
      selected: [0],
    });
    expect(blocker).toBeNull();
  });

  test("a missing target and unselected positions are each named in turn", () => {
    expect(intruderLaunchBlocker({ ...emptyIntruderConfig(), msgId: "7" })).toContain("target");
    expect(
      intruderLaunchBlocker({ ...emptyIntruderConfig(), msgId: "7", target: "https://host:443" }),
    ).toContain("insertion points");
  });

  test("the blocker is a necessary condition only, never a licence to skip the page's own guard", () => {
    // It passes an attack whose only payload set is empty, because sizing seven payload forms is the
    // page's arithmetic. The page refuses that one on arrival, by name. Pinned so nobody "fixes" the
    // menu by teaching it to size payloads and ends up with two guards that disagree.
    const blocker = intruderLaunchBlocker({
      ...emptyIntruderConfig(),
      msgId: "7",
      target: "https://host:443",
      selected: [0],
      payloadTexts: [""],
    });
    expect(blocker).toBeNull();
  });
});
