// Column visibility rules (burpsy-react-ui-bae7): when "Hide column" is allowed, and what a stored
// map is trusted to restore.
import { describe, expect, test } from "bun:test";
import { canHideColumn, reconcileVisibility, visibilityStorageKey, visibleColumnIds } from "./table-columns";

const IDS = ["id", "method", "host", "path"];

describe("canHideColumn", () => {
  test("any visible column may be hidden while another stays visible", () => {
    expect(canHideColumn(IDS, {}, "host")).toBe(true);
    expect(canHideColumn(IDS, { method: false, host: false }, "path")).toBe(true);
  });

  test("the last visible column may not be hidden", () => {
    expect(canHideColumn(IDS, { id: false, method: false, host: false }, "path")).toBe(false);
  });

  test("an already hidden column is not offered again", () => {
    expect(canHideColumn(IDS, { host: false }, "host")).toBe(false);
  });

  test("visibleColumnIds treats absent and true as shown", () => {
    expect(visibleColumnIds(IDS, { method: true, host: false })).toEqual(["id", "method", "path"]);
  });
});

describe("reconcileVisibility", () => {
  test("keeps known booleans, drops unknown ids and junk values", () => {
    expect(reconcileVisibility({ host: false, gone: false, path: "no" }, IDS)).toEqual({ host: false });
  });

  test("a stored map that would hide every column is discarded whole", () => {
    expect(reconcileVisibility({ id: false, method: false, host: false, path: false }, IDS)).toEqual({});
  });

  test("non-object storage restores nothing", () => {
    expect(reconcileVisibility(null, IDS)).toEqual({});
    expect(reconcileVisibility(["host"], IDS)).toEqual({});
    expect(reconcileVisibility("host", IDS)).toEqual({});
  });
});

test("the storage key fingerprints the column set, not its order", () => {
  expect(visibilityStorageKey(["b", "a"])).toBe(visibilityStorageKey(["a", "b"]));
  expect(visibilityStorageKey(["a", "b"])).not.toBe(visibilityStorageKey(["a", "c"]));
});
