// The command bridge (2czi): a palette row runs exactly when something mounted registered it, and
// the most recent registration wins until it unregisters.
import { describe, expect, test } from "bun:test";
import { hasCommand, registerCommand, registerUnavailable, runCommand, unavailableReason } from "./commands";

describe("lib/commands", () => {
 test("nothing registered: not available, and running it does nothing", () => {
  expect(hasCommand("t.none")).toBe(false);
  expect(runCommand("t.none")).toBe(false);
 });

 test("the latest registration wins; unregistering exposes the previous one", () => {
  const calls: string[] = [];
  const offA = registerCommand("t.stack", () => calls.push("a"));
  const offB = registerCommand("t.stack", () => calls.push("b"));
  runCommand("t.stack");
  offB();
  runCommand("t.stack");
  offA();
  expect(runCommand("t.stack")).toBe(false);
  expect(calls).toEqual(["b", "a"]);
  expect(hasCommand("t.stack")).toBe(false);
 });

 test("unregistering an older entry leaves the newer one on top", () => {
  const calls: string[] = [];
  const offA = registerCommand("t.order", () => calls.push("a"));
  const offB = registerCommand("t.order", () => calls.push("b"));
  offA();
  runCommand("t.order");
  offA(); // idempotent
  offB();
  expect(calls).toEqual(["b"]);
 });
});

describe("unavailable reasons", () => {
 test("an owner that cannot run says why, and is not runnable", () => {
  const off = registerUnavailable("t.reason", "Nothing is held");
  expect(hasCommand("t.reason")).toBe(false);
  expect(unavailableReason("t.reason")).toBe("Nothing is held");
  expect(runCommand("t.reason")).toBe(false);
  const offHandler = registerCommand("t.reason", () => undefined);
  expect(hasCommand("t.reason")).toBe(true);
  expect(unavailableReason("t.reason")).toBeUndefined();
  offHandler();
  off();
  expect(unavailableReason("t.reason")).toBeUndefined();
 });
});
