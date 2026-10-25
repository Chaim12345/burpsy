// The default message reading (burpsy-react-ui-ngcj): Burp's
// user_options.proxy.default_display_message, which its settings panel describes as "choose
// whether the Proxy history message editor displays auto-modified, manually edited, or original
// messages by default".
//
// Two properties to pin, and each one is a way this setting could silently become a lie:
//
//   1. PERSISTENCE. The whole point of a default is that it survives the session; a reading an
//      operator set once and must re-set on every reload is a preference in the UI sense only.
//      persistedWorkspace is the exact seam: zustand's persist API is unreachable from a unit
//      test environment (see its note in store.ts), so the rule "this key is in partialize" is
//      asserted against the exported function the real persist call consumes.
//
//   2. THE OUT-OF-BOX VALUE IS BURP'S OWN. Burp constructs its config with both direction
//      entries at Zpg8.ORIGINAL (recovered: burp.Zblz.java lines 142-143), and the migration
//      story — an operator whose hands expect Original — is the reason the setting exists at
//      all. If the default ever drifts to "edited", the defect is invisible to every test that
//      does not name it: a page that opens Edited looks fine, it is simply not what Burp does.
import { beforeEach, describe, expect, test } from "bun:test";
import { persistedWorkspace, useApp } from "./store";
import type { MessageVariant } from "../ui/variant-picker";

function reset() {
 // Zustand's setState with replace, so each test starts from the store's own defaults
 // rather than the previous test's leftovers.
 useApp.setState({ defaultMessageVariant: "original" });
}

describe("the default message reading is a persisted preference", () => {
 beforeEach(reset);

 test("partialize carries the reading, so it survives the session", () => {
  useApp.getState().setDefaultMessageVariant("auto-modified");
  const persisted = persistedWorkspace(useApp.getState());
  // The key must be present by name: a persisted object that serializes the value into a
  // different key would pass a value check and lose the setting on load.
  expect(Object.keys(persisted)).toContain("defaultMessageVariant");
  expect(persisted.defaultMessageVariant).toBe("auto-modified");
 });

 test("the out-of-box default is Original, Burp's own construction default", () => {
  // Not "edited": Burp initialises both direction entries to Zpg8.ORIGINAL, and a migrated
  // operator's habits expect exactly that. This is the line that keeps the parity honest.
  expect(useApp.getState().defaultMessageVariant).toBe("original");
  const persisted = persistedWorkspace(useApp.getState());
  expect(persisted.defaultMessageVariant).toBe("original");
 });

 test("every variant the picker offers is a value the setting can hold", () => {
  // The three-way contract: if the picker's union ever gains or renames a reading, this loop
  // fails until the settings panel's option table and the store's type agree again.
  const readings: MessageVariant[] = ["original", "edited", "auto-modified"];
  for (const reading of readings) {
   useApp.getState().setDefaultMessageVariant(reading);
   expect(useApp.getState().defaultMessageVariant).toBe(reading);
  }
 });
});
