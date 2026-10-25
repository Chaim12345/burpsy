import { describe, expect, test } from "bun:test";
import { describePoint, placementFields } from "./intruder-placement";
import { emptyIntruderConfig, mergePersistedWorkspace } from "./store";

describe("automatic payload placement (1krs)", () => {
 test("append is sent; replace and a missing field are omitted", () => {
  expect(placementFields("append")).toEqual({ payload_placement: "append" });
  expect(placementFields("replace")).toEqual({});
  expect(placementFields(undefined)).toEqual({});
 });

 test("a new attack replaces, and an attack persisted before the field existed hydrates to replace", () => {
  expect(emptyIntruderConfig().payloadPlacement).toBe("replace");
  const { payloadPlacement: _dropped, ...older } = emptyIntruderConfig();
  const merged = mergePersistedWorkspace({ intruder: { ...older, msgId: "7" } }, { intruder: emptyIntruderConfig() });
  expect(merged.intruder.payloadPlacement).toBe("replace");
  expect(merged.intruder.msgId).toBe("7");
 });

 test("an appended position names the value it is added to, not the empty span it occupies", () => {
  expect(describePoint({ kind: "url_param_value", offset: 19, current: "alpha", placement: "append" })).toBe(
   "url_param_value · offset 19 · appends to alpha",
  );
  expect(describePoint({ kind: "url_param_value", offset: 14, current: "alpha", placement: "replace" })).toBe(
   "url_param_value · offset 14 · alpha",
  );
  expect(describePoint({ kind: "cookie_value", offset: 3, current: "", placement: "append" })).toBe(
   "cookie_value · offset 3 · appends to (empty)",
  );
 });
});
