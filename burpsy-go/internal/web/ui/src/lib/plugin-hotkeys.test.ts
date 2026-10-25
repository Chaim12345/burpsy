// The hotkey installer (burpsy-react-ui-wsu4). The host's NormaliseChord is the single
// source of truth — it computes the binding at load time and sets Registration.Binding.
// The UI installs that field verbatim. These tests pin the properties that keep the
// installer honest:
//
//   1. The installer reads the host's Binding field, not the raw Chord.
//   2. A registration with no Binding (the host refused it) does not install.
//   3. An unloaded plugin's hotkey installs nothing.
import { describe, expect, test } from "bun:test";
import { installedPluginHotkeys } from "./plugin-hotkeys";
import type { ExtensionList } from "./types.extensions";

describe("installedPluginHotkeys installs the host's binding verbatim", () => {
 const hotkey = (id: string, binding: string) => ({
  id,
  kind: "hotkey" as const,
  label: `action ${id}`,
  chord: "Ctrl+Shift+K",
  binding,
 });

 test("a loaded plugin's hotkey registrations arrive with the host's binding", () => {
  const list: ExtensionList = {
   allowlisted: 1,
   policy: { admission: "allowlist", max_output_bytes: 1, call_timeout_ms: 1 },
   extensions: [
    {
     name: "probe",
     state: "loaded",
     registrations: [hotkey("key", "mod+shift+k"), hotkey("plain", "mod+p")],
     registrations_refused: 0,
    },
   ],
  } as unknown as ExtensionList;
  const bindings = installedPluginHotkeys(list);
  expect(bindings).toEqual([
   { chord: "mod+shift+k", plugin: "probe", registration: "key", label: "action key" },
   { chord: "mod+p", plugin: "probe", registration: "plain", label: "action plain" },
  ]);
 });

 test("a registration with no binding (host refused it) does not install", () => {
  const list: ExtensionList = {
   allowlisted: 1,
   policy: { admission: "allowlist", max_output_bytes: 1, call_timeout_ms: 1 },
   extensions: [
    {
     name: "probe",
     state: "loaded",
     registrations: [hotkey("refused", "")],
     registrations_refused: 1,
    },
   ],
  } as unknown as ExtensionList;
  expect(installedPluginHotkeys(list)).toEqual([]);
 });

 test("an unloaded plugin's hotkey installs nothing", () => {
  const list: ExtensionList = {
   allowlisted: 1,
   policy: { admission: "allowlist", max_output_bytes: 1, call_timeout_ms: 1 },
   extensions: [
    {
     name: "probe",
     state: "unloaded",
     registrations: [hotkey("key", "mod+k")],
     registrations_refused: 0,
    },
   ],
  } as unknown as ExtensionList;
  expect(installedPluginHotkeys(list)).toEqual([]);
 });
});
